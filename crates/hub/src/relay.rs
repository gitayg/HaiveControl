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
    /// sha256(enrollment token) of the agent that registered this tunnel. Every
    /// subsequent poll/reply/heartbeat for this id must present the SAME token —
    /// so a holder of merely *a* valid token (the shared RELAY_TOKEN, or another
    /// owner's htok_) cannot poll/forge an arbitrary device's tunnel by id.
    auth: String,
}

fn registry() -> &'static Mutex<HashMap<String, Arc<Tunnel>>> {
    static R: OnceLock<Mutex<HashMap<String, Arc<Tunnel>>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}

/// sha256-hex of the caller's enrollment token — what we bind a tunnel to. Empty
/// token → empty string (an unauthenticated hub where every tunnel shares "").
pub fn auth_hash(tok: &str) -> String {
    if tok.is_empty() {
        return String::new();
    }
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(tok.as_bytes()))
}

/// Constant-time string equality — avoids a timing oracle on the tunnel secret.
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn upsert_agent(agents: &Agents, key: &str, agent_id: &str, data: &serde_json::Value) {
    let mut d = data.clone();
    // A manual owner assignment (dashboard "Claim") wins over the agent's report.
    let owner = crate::owner_override(key).or_else(|| d.get("owner").and_then(|x| x.as_str()).map(crate::canon_owner));
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

/// Drop stale old-scheme rows for `hostname` once the machine reports under its
/// stable hc-<machine-id> key. "Stale" = no heartbeat in 45s, so a genuinely
/// separate but live machine with the same hostname is never removed.
fn retire_superseded(agents: &Agents, keep_key: &str, hostname: &str) {
    if hostname.is_empty() {
        return;
    }
    let stale: Vec<String> = {
        let map = agents.lock().unwrap();
        map.iter()
            .filter(|(k, a)| {
                k.as_str() != keep_key
                    && !k.starts_with("relay:hc-")
                    && a.data.get("hostname").and_then(|x| x.as_str()) == Some(hostname)
                    && a.last.elapsed().map(|e| e.as_secs() >= 45).unwrap_or(true)
            })
            .map(|(k, _)| k.clone())
            .collect()
    };
    for k in &stale {
        agents.lock().unwrap().remove(k);
        crate::clear_pending_dissolve(k);
        println!("relay: retired superseded row {k} (now {keep_key})");
    }
}

/// Registry-wide dedup, run on a timer (and once at startup): for every hostname
/// that has a stable hc-<machine-id> row, drop stale pre-2.27 (name-hash) rows for
/// that same hostname — even when the hc- agent itself is offline (asleep). The
/// hc- hello handler already does this at check-in; this widens *when* it fires so
/// a machine that reported once under hc- and then went to sleep still gets its
/// leftover old row cleared. retire_superseded's 45s guard still protects a live
/// separate machine that happens to share the hostname.
pub fn dedup_sweep(agents: &Agents) {
    let hc: Vec<(String, String)> = {
        let map = agents.lock().unwrap();
        map.iter()
            .filter(|(k, _)| k.starts_with("relay:hc-"))
            .filter_map(|(k, a)| {
                a.data
                    .get("hostname")
                    .and_then(|x| x.as_str())
                    .map(|h| (k.clone(), h.to_string()))
            })
            .collect()
    };
    for (keep_key, host) in hc {
        retire_superseded(agents, &keep_key, &host);
    }
    dedup_hostnames(agents);
}

/// General duplicate cleanup: for any hostname with more than one row (a machine
/// re-installed under a new relay id — common on old agents that used name-hash keys
/// and never got an `hc-<machine-id>` row), keep the MOST-recently-seen row and retire
/// the others that are stale (no heartbeat in 45s). A genuinely separate live machine
/// that happens to share a hostname keeps a recent heartbeat and is never retired.
pub fn dedup_hostnames(agents: &Agents) {
    let retire: Vec<String> = {
        let map = agents.lock().unwrap();
        let mut by_host: HashMap<String, Vec<(String, u64)>> = HashMap::new();
        for (k, a) in map.iter() {
            if let Some(h) = a.data.get("hostname").and_then(|x| x.as_str()) {
                if h.is_empty() {
                    continue;
                }
                let age = a.last.elapsed().map(|e| e.as_secs()).unwrap_or(u64::MAX);
                by_host.entry(h.to_string()).or_default().push((k.clone(), age));
            }
        }
        let mut out = Vec::new();
        for (_host, mut rows) in by_host {
            if rows.len() < 2 {
                continue;
            }
            rows.sort_by_key(|(_, age)| *age); // freshest first
            for (k, age) in rows.into_iter().skip(1) {
                if age >= 45 {
                    out.push(k);
                }
            }
        }
        out
    };
    for k in &retire {
        agents.lock().unwrap().remove(k);
        crate::clear_pending_dissolve(k);
        println!("relay: retired duplicate row {k}");
    }
}

/// POST /relay/hello — register (or heartbeat) a relay agent. `auth` is
/// sha256(enrollment token) (see `auth_hash`); it binds the tunnel to its enroller.
/// Returns false if an EXISTING tunnel is heartbeat'd with a different token — i.e.
/// someone other than the original agent is trying to take over the id.
pub fn hello(agents: &Agents, data: serde_json::Value, auth: &str) -> bool {
    let agent_id = match data.get("relay_id").and_then(|x| x.as_str()) {
        Some(s) => s.to_string(),
        None => return false,
    };
    let mut reg = registry().lock().unwrap();
    let fresh = match reg.get(&agent_id) {
        // Existing tunnel: only its original enroller (same token) may heartbeat it.
        Some(t) => {
            if !ct_eq(&t.auth, auth) {
                return false;
            }
            false
        }
        None => {
            reg.insert(
                agent_id.clone(),
                Arc::new(Tunnel {
                    queue: Mutex::new(VecDeque::new()),
                    qcv: Condvar::new(),
                    pending: Mutex::new(HashMap::new()),
                    next_id: AtomicU32::new(1),
                    auth: auth.to_string(),
                }),
            );
            true
        }
    };
    drop(reg);
    upsert_agent(agents, &format!("relay:{agent_id}"), &agent_id, &data);
    if fresh {
        println!("relay: {agent_id} connected");
    }
    // Auto-dedup: a machine now reporting under its stable machine-ID key (hc-…)
    // supersedes any leftover pre-2.27 row (name-hash key) for the same hostname.
    // Only retire ones that have gone stale — a *different* live machine that
    // happens to share a hostname keeps a recent heartbeat and is left alone.
    if agent_id.starts_with("hc-") {
        if let Some(host) = data.get("hostname").and_then(|x| x.as_str()) {
            retire_superseded(agents, &format!("relay:{agent_id}"), host);
        }
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
        // A queued dissolve is now being delivered — drop the device from inventory
        // too (it just re-registered on this heartbeat). If the dispatch above fails
        // it re-queues, the agent re-hellos, and this repeats until it sticks.
        crate::forget_device(agents, &format!("relay://{agent_id}"));
    }
    // #50: dispatch any canned actions queued while this device was offline.
    let qid = agent_id.clone();
    std::thread::spawn(move || crate::run_queued_actions(&qid));
    true
}

/// GET /relay/poll — block up to `timeout` for the next request; JSON or None.
/// `auth` must match the token the tunnel was registered with (see `hello`), so a
/// caller can only dequeue commands destined for a device it actually enrolled.
pub fn poll(agent_id: &str, auth: &str, timeout: Duration) -> Option<String> {
    let t = registry().lock().unwrap().get(agent_id)?.clone();
    if !ct_eq(&t.auth, auth) {
        return None;
    }
    let mut q = t.queue.lock().unwrap();
    if q.is_empty() {
        let (g, _) = t.qcv.wait_timeout(q, timeout).unwrap();
        q = g;
    }
    let o = q.pop_front()?;
    Some(serde_json::json!({"id": o.id, "m": o.m, "p": o.p, "ct": o.ct, "b": o.b}).to_string())
}

/// POST /relay/reply — feed a streamed response body into the waiting request.
/// `auth` must match the tunnel's registering token, so a caller can't forge a
/// response for another device's in-flight request by guessing (agent_id, req_id).
pub fn reply_stream(agent_id: &str, auth: &str, req_id: u32, status: u16, ctype: String, reader: &mut dyn Read) {
    let tx = match registry().lock().unwrap().get(agent_id).cloned() {
        Some(t) if ct_eq(&t.auth, auth) => match t.pending.lock().unwrap().get(&req_id).cloned() {
            Some(tx) => tx,
            None => return,
        },
        _ => return,
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

/// True once the agent has an active tunnel (dialed in via /relay/hello).
pub fn is_connected(agent_id: &str) -> bool {
    registry().lock().unwrap().contains_key(agent_id)
}

/// Wait up to `budget` for the agent's tunnel to (re)appear, returning it if so.
/// Covers the brief dark window after a dropped long-poll or a hub redeploy —
/// the device reloads as "online" from disk but its in-memory tunnel is gone
/// until it re-sends /relay/hello (within a heartbeat). Beats failing instantly.
fn wait_for_tunnel(agent_id: &str, budget: Duration) -> Option<Arc<Tunnel>> {
    let step = Duration::from_millis(150);
    let mut waited = Duration::ZERO;
    loop {
        if let Some(t) = registry().lock().unwrap().get(agent_id).cloned() {
            return Some(t);
        }
        if waited >= budget {
            return None;
        }
        std::thread::sleep(step);
        waited += step;
    }
}

/// Dispatch a request to a relay agent and return a streaming response handle.
pub fn request(agent_id: &str, method: &str, path: &str, body: Option<(String, Vec<u8>)>) -> Option<RelayResponse> {
    // Tolerate a reconnecting agent (redeploy / dropped poll) instead of an
    // instant "unreachable" — it re-hellos within a heartbeat.
    let tunnel = wait_for_tunnel(agent_id, Duration::from_secs(4))?;
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
