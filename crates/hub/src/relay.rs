// Hub side of the reverse tunnel, over plain HTTP long-poll on the hub's own
// port (so it deploys behind a single HTTPS endpoint / PaaS bypass path — no
// raw TCP, no WebSocket). Agents:
//   POST /relay/hello   — register + heartbeat (sysinfo, relay_id)
//   GET  /relay/poll    — long-poll for the next queued request
//   POST /relay/reply   — stream a response back (chunked body)
// We register each agent like a normal one (transport = "relay") and dispatch
// device actions through its queue, multiplexed by request id.
use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;

use crate::{Agent, Agents};

enum Msg {
    Head(u16, String),
    Chunk(Vec<u8>),
    End,
}

/// A request queued for delivery to the agent via /relay/poll.
struct Outgoing {
    id: u32,
    m: String,
    p: String,
    ct: String,
    b: String,
}

pub struct Tunnel {
    queue: Mutex<VecDeque<Outgoing>>,
    qcv: Condvar,
    pending: Mutex<HashMap<u32, Sender<Msg>>>,
    next_id: AtomicU32,
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Tunnel>>> {
    static R: OnceLock<Mutex<HashMap<String, Arc<Tunnel>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

fn upsert_agent(agents: &Agents, key: &str, agent_id: &str, data: &serde_json::Value) {
    let mut d = data.clone();
    let owner = d.get("owner").and_then(|x| x.as_str()).map(crate::canon_owner);
    if let Some(o) = d.as_object_mut() {
        o.insert("scheme".into(), serde_json::json!("relay"));
        o.insert("ip".into(), serde_json::json!(agent_id));
        o.insert("port".into(), serde_json::json!(0));
        o.insert("relay".into(), serde_json::json!(true));
        if let Some(own) = owner {
            o.insert("owner".into(), serde_json::json!(own));
        }
    }
    agents.lock().unwrap().insert(key.to_string(), Agent { data: d, last: std::time::SystemTime::now() });
}

/// POST /relay/hello — register (or heartbeat) a relay agent.
pub fn hello(agents: &Agents, data: serde_json::Value) {
    let agent_id = match data.get("relay_id").and_then(|x| x.as_str()) {
        Some(s) => s.to_string(),
        None => return,
    };
    let mut reg = registry().lock().unwrap();
    let fresh = !reg.contains_key(&agent_id);
    reg.entry(agent_id.clone()).or_insert_with(|| {
        Arc::new(Tunnel {
            queue: Mutex::new(VecDeque::new()),
            qcv: Condvar::new(),
            pending: Mutex::new(HashMap::new()),
            next_id: AtomicU32::new(1),
        })
    });
    drop(reg);
    upsert_agent(agents, &format!("relay:{agent_id}"), &agent_id, &data);
    if fresh {
        println!("relay: {agent_id} connected");
    }
    // Dissolve-on-next-connect: if this device was queued to dissolve while
    // offline, deliver it now. Claim it atomically (clear returns true only for
    // the first heartbeat) and dispatch on a separate thread — the dissolve reply
    // can take up to 65s and must not block this heartbeat handler. Re-queue if
    // the dispatch fails so a later heartbeat retries.
    let key = format!("relay:{agent_id}");
    if crate::clear_pending_dissolve(&key) {
        let id = agent_id.clone();
        std::thread::spawn(move || {
            if request(&id, "POST", "/dissolve", None).is_some() {
                println!("relay: {id} dissolved (queued while offline)");
            } else {
                crate::queue_dissolve(&format!("relay:{id}"));
            }
        });
    }
}

/// GET /relay/poll — block up to `timeout` for the next request; JSON or None.
pub fn poll(agent_id: &str, timeout: Duration) -> Option<String> {
    let t = registry().lock().unwrap().get(agent_id)?.clone();
    let mut q = t.queue.lock().unwrap();
    if q.is_empty() {
        let (g, _) = t.qcv.wait_timeout(q, timeout).unwrap();
        q = g;
    }
    let o = q.pop_front()?;
    Some(serde_json::json!({"id": o.id, "m": o.m, "p": o.p, "ct": o.ct, "b": o.b}).to_string())
}

/// POST /relay/reply — feed a streamed response body into the waiting request.
pub fn reply_stream(agent_id: &str, req_id: u32, status: u16, ctype: String, reader: &mut dyn Read) {
    let tx = match registry().lock().unwrap().get(agent_id).cloned() {
        Some(t) => match t.pending.lock().unwrap().get(&req_id).cloned() {
            Some(tx) => tx,
            None => return,
        },
        None => return,
    };
    if tx.send(Msg::Head(status, ctype)).is_err() {
        return;
    }
    let mut buf = [0u8; 65536];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            // send fails once the browser side (Receiver) is gone → stop reading,
            // which fails the agent's upload and stops it streaming.
            Ok(n) => {
                if tx.send(Msg::Chunk(buf[..n].to_vec())).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = tx.send(Msg::End);
    if let Some(t) = registry().lock().unwrap().get(agent_id) {
        t.pending.lock().unwrap().remove(&req_id);
    }
}

/// Dispatch a request to a relay agent and return a streaming response handle.
pub fn request(agent_id: &str, method: &str, path: &str, body: Option<(String, Vec<u8>)>) -> Option<RelayResponse> {
    let tunnel = registry().lock().unwrap().get(agent_id)?.clone();
    let id = tunnel.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = std::sync::mpsc::channel();
    tunnel.pending.lock().unwrap().insert(id, tx);

    let (ct, b) = match body {
        Some((ct, bytes)) => (ct, base64::engine::general_purpose::STANDARD.encode(bytes)),
        None => (String::new(), String::new()),
    };
    tunnel.queue.lock().unwrap().push_back(Outgoing { id, m: method.to_string(), p: path.to_string(), ct, b });
    tunnel.qcv.notify_one();

    // Wait longer than the agent's own 60s exec cap: slow reports (e.g. Windows
    // `systeminfo`) don't reply until the command finishes, so a 20s wait gave up
    // on them and surfaced "(device unreachable)".
    match rx.recv_timeout(Duration::from_secs(65)) {
        Ok(Msg::Head(status, ctype)) => Some(RelayResponse { status, ctype, rx, tunnel, id, buf: Vec::new(), pos: 0, done: false }),
        _ => {
            tunnel.pending.lock().unwrap().remove(&id);
            None
        }
    }
}

pub struct RelayResponse {
    pub status: u16,
    pub ctype: String,
    rx: Receiver<Msg>,
    tunnel: Arc<Tunnel>,
    id: u32,
    buf: Vec<u8>,
    pos: usize,
    done: bool,
}

impl RelayResponse {
    /// Drain the whole body (for unary responses).
    pub fn read_all(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while !self.done {
            match self.rx.recv_timeout(Duration::from_secs(30)) {
                Ok(Msg::Chunk(c)) => out.extend_from_slice(&c),
                _ => self.done = true,
            }
        }
        out
    }
}

impl Read for RelayResponse {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            if self.done {
                return Ok(0);
            }
            match self.rx.recv_timeout(Duration::from_secs(60)) {
                Ok(Msg::Chunk(c)) => {
                    self.buf = c;
                    self.pos = 0;
                }
                _ => {
                    self.done = true;
                    return Ok(0);
                }
            }
        }
        let n = (self.buf.len() - self.pos).min(out.len());
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

impl Drop for RelayResponse {
    fn drop(&mut self) {
        // Dropping `rx` makes the agent's reply upload fail (reply_stream's
        // send errors), which stops it streaming; just free the slot here.
        self.tunnel.pending.lock().unwrap().remove(&self.id);
    }
}
