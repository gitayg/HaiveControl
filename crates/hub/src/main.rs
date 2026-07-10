// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// HaiveHub — runs on the Mac. Advertises a Mac ID over Bonjour, collects agent
// registrations, and serves a dashboard + JSON list of registered devices.
use std::collections::HashMap;
use std::net::UdpSocket;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::Parser;
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

mod relay;

const VERSION: &str = "2.3.0";
const HUB_SERVICE: &str = "_rmtscrn._tcp.local.";
const STALE: Duration = Duration::from_secs(40);

type Resp = Response<std::io::Cursor<Vec<u8>>>;
type Agents = Mutex<HashMap<String, Agent>>;

struct Agent {
    data: serde_json::Value,
    last: Instant,
}

#[derive(Parser)]
#[command(name = "HaiveHub", version = VERSION,
    about = "HaiveControl hub — advertises a Mac ID, collects agent registrations, serves a dashboard.\n\nenv: HUB_PORT (default 8770), MAC_ID (override advertised id)")]
struct Args {}

fn main() {
    Args::parse();
    // PORT is what PaaS platforms (AppCrane) inject; HUB_PORT is the local name.
    let port: u16 = std::env::var("PORT")
        .or_else(|_| std::env::var("HUB_PORT"))
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8770);
    let mid = mac_id();
    let ip = local_ip();
    let _mdns = advertise(&mid, port, &ip);

    println!("HaiveControl hub {VERSION}");
    println!("   Mac ID:  {mid}");
    println!("   Dashboard: http://localhost:{port}/  (or http://{ip}:{port}/)");
    println!("   On a device run:  HaiveControl {mid}");

    let agents: Arc<Agents> = Arc::new(Mutex::new(HashMap::new()));

    // Reverse tunnel: agents behind NAT dial in over HTTP long-poll on THIS port
    // (/relay/hello, /relay/poll, /relay/reply — see relay.rs), so it works
    // behind a single HTTPS endpoint. `HaiveControl --relay http://<hub-host>:<port>`.

    let server = Arc::new(Server::http(format!("0.0.0.0:{port}")).expect("bind hub port"));
    let mut handles = Vec::new();
    // Generous pool: long-poll and streaming handlers each hold a thread a while.
    for _ in 0..64 {
        let (s, a, m, hip) = (server.clone(), agents.clone(), mid.clone(), ip.clone());
        handles.push(std::thread::spawn(move || loop {
            match s.recv() {
                Ok(req) => handle(req, &a, &m, &hip, port),
                Err(_) => break,
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn handle(mut req: Request, agents: &Agents, mac_id: &str, hub_ip: &str, hub_port: u16) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    // On a multi-user hub, AppCrane forwards the authenticated user; a device
    // belongs to an owner and you can only see/drive your own. No owner header
    // (LAN / dev) = full access. exec carries its target in the body, so it's
    // checked inside proxy_exec instead of here.
    // Empty owner = no scope (see all), never "owner equals empty string" — an
    // unset HIVE_OWNER on the MCP must not silently hide every device.
    let user = req_header(&req, "X-AppCrane-User-Email")
        .or_else(|| req_header(&req, "X-AppCrane-User"))
        .filter(|s| !s.is_empty())
        .map(|e| canon_owner(&e));
    if path.starts_with("/x/") && path != "/x/exec" {
        if let Some(t) = query_param(&url, "target") {
            if !may_control(user.as_deref(), agents, &t) {
                let _ = req.respond(Response::from_string("forbidden").with_status_code(403));
                return;
            }
            if auditable(&path) {
                audit(user.as_deref().unwrap_or(""), "browser", action_label(&path), &device_name(agents, &t), "");
            }
        }
    }
    // /m/* is the token-authed MCP API (a headless MCP can't pass SSO either, so
    // it's SSO-bypassed and carries ?mtok=<MCP_TOKEN>&owner=<user>). Ownership is
    // scoped by the caller-supplied owner; exec/input carry their target in the body.
    // MCP owner: the client's owner param, else a server-configured MCP_OWNER
    // (so a single token "is" that owner), else none (unscoped — the token is
    // the auth; owner is only a per-user filter).
    let mowner = query_param(&url, "owner")
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("MCP_OWNER").ok().filter(|s| !s.is_empty()))
        .map(|o| canon_owner(&o));
    if path.starts_with("/m/") {
        if !mcp_ok(&url) {
            let _ = req.respond(Response::from_string("unauthorized").with_status_code(401));
            return;
        }
        if !matches!(path.as_str(), "/m/agents" | "/m/exec" | "/m/input" | "/m/sys") {
            if let Some(t) = query_param(&url, "target") {
                if !may_control(mowner.as_deref(), agents, &t) {
                    let _ = req.respond(Response::from_string("forbidden").with_status_code(403));
                    return;
                }
                record_mcp_access(&t, mcp_action(&path), mowner.as_deref().unwrap_or(""), "");
                if auditable(&path) {
                    audit(mowner.as_deref().unwrap_or(""), "mcp", action_label(&path), &device_name(agents, &t), "");
                }
            }
        }
    }
    // Live MJPEG streams pipe an endless reqwest body straight through tiny_http,
    // so they bypass the `Resp` match below (which expects a finite Cursor body).
    if method == Method::Get && (path == "/x/stream" || path == "/x/camstream") {
        proxy_stream(req, &url, &path);
        return;
    }
    // Agents can't pass the PaaS SSO (headless), so /relay is SSO-bypassed — which
    // means the hub must authenticate them itself. If RELAY_TOKEN is set, every
    // /relay call must carry ?tok=<token>. Unset = open (trusted LAN / dev).
    if path.starts_with("/relay/") && !relay_ok(&url) {
        let _ = req.respond(Response::from_string("unauthorized").with_status_code(401));
        return;
    }
    let resp = match (&method, path.as_str()) {
        (Method::Post, "/register") => {
            register(&mut req, agents);
            Response::from_string("").with_status_code(204)
        }
        (Method::Get, "/agents") => json_agents(agents, user.as_deref()),
        (Method::Get, "/audit") => json_audit(user.as_deref()),
        (Method::Get, "/api/health") => json_resp(&serde_json::json!({"status": "ok", "version": VERSION})),
        (Method::Post, "/relay/hello") => {
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            relay::hello(agents, serde_json::from_str(&body).unwrap_or_default());
            Response::from_string("").with_status_code(204)
        }
        (Method::Get, "/relay/poll") => {
            let id = query_param(&url, "id").unwrap_or_default();
            match relay::poll(&id, std::time::Duration::from_secs(25)) {
                Some(js) => Response::from_string(js).with_header(hdr("Content-Type", "application/json")),
                None => Response::from_string("").with_status_code(204),
            }
        }
        (Method::Post, "/relay/reply") => {
            let id = query_param(&url, "id").unwrap_or_default();
            let req_id = query_param(&url, "req").and_then(|v| v.parse().ok()).unwrap_or(0);
            let st = query_param(&url, "st").and_then(|v| v.parse().ok()).unwrap_or(200);
            let ct = query_param(&url, "ct").unwrap_or_default();
            relay::reply_stream(&id, req_id, st, ct, req.as_reader());
            Response::from_string("").with_status_code(204)
        }
        (Method::Get, "/install.ps1") => text_resp(install_ps1(hub_ip, hub_port, mac_id), "text/plain; charset=utf-8"),
        (Method::Get, "/install.sh") => text_resp(install_sh(hub_ip, hub_port, mac_id), "text/plain; charset=utf-8"),
        (Method::Get, p) if p.starts_with("/bin/") => serve_bin(&p[5..]),
        (Method::Get, "/x/frame") => proxy_frame(&url),
        (Method::Get, "/x/camera") => proxy_camera(&url),
        (Method::Get, "/x/update") => proxy_update(&url, agents, hub_ip, hub_port),
        (Method::Get, "/x/dissolve") => proxy_dissolve(&url),
        (Method::Post, "/x/exec") => proxy_exec(&mut req, agents, user.as_deref(), false),
        (Method::Post, "/x/shell/open") => proxy_shell_open(&url),
        (Method::Get, "/x/shell/read") => proxy_shell_read(&url),
        (Method::Post, "/x/shell/input") => proxy_shell_input(&mut req, &url),
        (Method::Post, "/x/shell/resize") => proxy_shell_resize(&url),
        (Method::Post, "/x/shell/close") => proxy_shell_close(&url),
        (Method::Get, "/assets/xterm.js") => asset(XTERM_JS, "text/javascript; charset=utf-8"),
        (Method::Get, "/assets/xterm.css") => asset(XTERM_CSS, "text/css; charset=utf-8"),
        (Method::Get, "/assets/addon-fit.js") => asset(ADDON_FIT, "text/javascript; charset=utf-8"),
        (Method::Get, "/x/download") => proxy_download(&url),
        (Method::Get, "/x/list") => proxy_list(&url),
        (Method::Post, "/x/upload") => proxy_upload(&mut req, &url),
        (Method::Get, "/live") => live_page(&url),
        // MCP API (token-authed, owner-scoped) — mirrors the device actions the
        // haive-mcp server needs, routed through the hub so it works over relay.
        (Method::Get, "/m/agents") => json_agents(agents, mowner.as_deref()),
        (Method::Get, "/m/frame") => proxy_frame(&url),
        (Method::Get, "/m/camera") => proxy_camera(&url),
        (Method::Post, "/m/exec") => proxy_exec(&mut req, agents, mowner.as_deref(), true),
        (Method::Post, "/m/input") => proxy_input(&mut req, agents, mowner.as_deref()),
        (Method::Get, "/m/sys") => proxy_sys(&url, agents, mowner.as_deref(), true),
        (Method::Get, "/m/fleet") => proxy_fleet(&url, agents, mowner.as_deref(), true),
        (Method::Get, "/x/sys") => proxy_sys(&url, agents, user.as_deref(), false),
        (Method::Get, "/x/fleet") => proxy_fleet(&url, agents, user.as_deref(), false),
        (Method::Get, "/m/download") => proxy_download(&url),
        (Method::Post, "/m/upload") => proxy_upload(&mut req, &url),
        (Method::Get, "/m/update") => proxy_update(&url, agents, hub_ip, hub_port),
        (Method::Get, "/m/dissolve") => proxy_dissolve(&url),
        (Method::Get, "/") => dashboard(agents, mac_id, hub_ip, hub_port, user.as_deref()),
        _ => Response::from_string("not found").with_status_code(404),
    };
    let _ = req.respond(resp);
}

fn text_resp(body: String, ct: &str) -> Resp {
    Response::from_string(body).with_header(hdr("Content-Type", ct))
}

fn req_header(req: &Request, name: &'static str) -> Option<String> {
    req.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str().to_string())
}

/// Stable, deterministic owner id from an email (UUIDv5) — same email always
/// yields the same id, across redeploys and hub instances, no persistence and
/// no dependence on any churning machine identity (MAC/hostname). It's a *scope*
/// key, not the auth boundary — the MCP token is the credential.
fn owner_id(email: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_URL, email.trim().to_lowercase().as_bytes()).to_string()
}

/// Canonicalize any owner value: an email → its UUIDv5, anything else unchanged.
/// Applied at every entry (SSO header, MCP ?owner=, device --owner) so emails and
/// pre-hashed ids interoperate and all resolve to one stable key.
pub(crate) fn canon_owner(s: &str) -> String {
    let t = s.trim();
    if t.contains('@') {
        owner_id(t)
    } else {
        t.to_string()
    }
}

/// The agents-map key for a proxy target: `relay:id` or the LAN ip.
fn device_key(target: &str) -> String {
    match target.strip_prefix("relay://") {
        Some(id) => format!("relay:{}", id.trim_end_matches('/')),
        None => target.split("://").nth(1).and_then(|s| s.split(':').next()).unwrap_or("").to_string(),
    }
}

/// The `owner` a device registered under.
fn device_owner(agents: &Agents, target: &str) -> Option<String> {
    agents.lock().unwrap().get(&device_key(target)).and_then(|a| a.data.get("owner").and_then(|o| o.as_str()).map(String::from))
}

type AccessEvent = (Instant, String, String, String); // (when, action, owner, detail)

/// Recent MCP (/m) accesses per device, newest first — drives the dashboard's
/// live "agent accessing" indicator + activity log.
fn access_log() -> &'static Mutex<HashMap<String, std::collections::VecDeque<AccessEvent>>> {
    static A: std::sync::OnceLock<Mutex<HashMap<String, std::collections::VecDeque<AccessEvent>>>> = std::sync::OnceLock::new();
    A.get_or_init(|| Mutex::new(HashMap::new()))
}

fn record_mcp_access(target: &str, action: &str, owner: &str, detail: &str) {
    let key = device_key(target);
    if key.is_empty() {
        return;
    }
    let mut m = access_log().lock().unwrap();
    let dq = m.entry(key).or_default();
    dq.push_front((Instant::now(), action.to_string(), owner.to_string(), detail.chars().take(180).collect()));
    dq.truncate(8);
}

fn mcp_action(path: &str) -> &'static str {
    match path {
        "/m/frame" => "screenshot",
        "/m/camera" => "camera",
        "/m/download" => "download",
        "/m/upload" => "upload",
        "/m/update" => "update agent",
        "/m/dissolve" => "dissolve",
        "/m/exec" => "run command",
        "/m/input" => "input",
        _ => "access",
    }
}

/// The registered `name` for a proxy target (falls back to its key).
fn device_name(agents: &Agents, target: &str) -> String {
    let key = device_key(target);
    agents
        .lock()
        .unwrap()
        .get(&key)
        .and_then(|a| a.data.get("name").and_then(|n| n.as_str()).map(String::from))
        .unwrap_or(key)
}

// Audit log: (when, actor, source, action, device, detail), newest first.
type AuditEvent = (Instant, String, String, String, String, String);

fn audit_log() -> &'static Mutex<std::collections::VecDeque<AuditEvent>> {
    static A: std::sync::OnceLock<Mutex<std::collections::VecDeque<AuditEvent>>> = std::sync::OnceLock::new();
    A.get_or_init(|| Mutex::new(std::collections::VecDeque::new()))
}

fn audit(actor: &str, source: &str, action: &str, device: &str, detail: &str) {
    let mut m = audit_log().lock().unwrap();
    m.push_front((
        Instant::now(),
        actor.to_string(),
        source.to_string(),
        action.to_string(),
        device.to_string(),
        detail.chars().take(180).collect(),
    ));
    m.truncate(500);
}

/// Human label for an auditable action path (`/x/*` or `/m/*`).
fn action_label(path: &str) -> &'static str {
    let p = path.strip_prefix("/x").or_else(|| path.strip_prefix("/m")).unwrap_or(path);
    match p {
        "/frame" => "screenshot",
        "/camera" => "camera photo",
        "/stream" => "live screen",
        "/camstream" => "live camera",
        "/exec" => "run command",
        "/input" => "input",
        "/download" => "download file",
        "/upload" => "upload file",
        "/update" => "update agent",
        "/dissolve" => "dissolve agent",
        "/shell/open" => "open shell",
        _ => "access",
    }
}

/// Whether a device-action path is worth an audit entry (skips noisy polls).
fn auditable(path: &str) -> bool {
    let p = path.strip_prefix("/x").or_else(|| path.strip_prefix("/m")).unwrap_or(path);
    matches!(p, "/frame" | "/camera" | "/stream" | "/camstream" | "/download" | "/upload" | "/update" | "/dissolve" | "/shell/open")
}

/// A user may drive a device only if it's theirs. No user context (LAN/dev) = allowed.
fn may_control(user: Option<&str>, agents: &Agents, target: &str) -> bool {
    match user {
        None => true,
        Some(u) => device_owner(agents, target).as_deref() == Some(u),
    }
}

/// Agent auth for the SSO-bypassed /relay paths. Open when RELAY_TOKEN is unset.
fn relay_ok(url: &str) -> bool {
    match std::env::var("RELAY_TOKEN") {
        Ok(t) if !t.is_empty() => query_param(url, "tok").as_deref() == Some(t.as_str()),
        _ => true,
    }
}

/// MCP-client auth for the SSO-bypassed /m paths. Open when MCP_TOKEN is unset.
fn mcp_ok(url: &str) -> bool {
    match std::env::var("MCP_TOKEN") {
        Ok(t) if !t.is_empty() => query_param(url, "mtok").as_deref() == Some(t.as_str()),
        _ => true,
    }
}

// xterm.js terminal, bundled into the binary and served same-origin (no CDN).
const XTERM_JS: &[u8] = include_bytes!("../assets/xterm.js");
const XTERM_CSS: &[u8] = include_bytes!("../assets/xterm.css");
const ADDON_FIT: &[u8] = include_bytes!("../assets/addon-fit.js");

fn asset(bytes: &'static [u8], ct: &str) -> Resp {
    Response::from_data(bytes.to_vec())
        .with_header(hdr("Content-Type", ct))
        .with_header(hdr("Cache-Control", "max-age=86400"))
}

fn serve_bin(name: &str) -> Resp {
    if name.is_empty() || name.contains('/') || name.contains("..") {
        return Response::from_string("bad name").with_status_code(400);
    }
    let dir = std::env::var("HUB_DIST").unwrap_or_else(|_| "dist".to_string());
    match std::fs::read(std::path::Path::new(&dir).join(name)) {
        Ok(bytes) => Response::from_data(bytes).with_header(hdr("Content-Type", "application/octet-stream")),
        Err(_) => Response::from_string("not found").with_status_code(404),
    }
}

fn http() -> &'static reqwest::blocking::Client {
    static HTTP: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    HTTP.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(std::time::Duration::from_secs(65))
            .build()
            .expect("http client")
    })
}

/// A separate client with NO read timeout — live MJPEG streams never end, so the
/// 65s cap on `http()` would kill them mid-view.
fn http_stream() -> &'static reqwest::blocking::Client {
    static HTTP: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    HTTP.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .expect("stream client")
    })
}

/// Pipe an endless stream from the agent straight to the browser. `path` is
/// `/x/stream` (screen), `/x/camstream` (camera), or `/x/shell/stream` (terminal);
/// the agent path drops the `/x` and carries every query param except `target`.
fn proxy_stream(req: Request, url: &str, path: &str) {
    let target = match query_param(url, "target") {
        Some(t) => t,
        None => {
            let _ = req.respond(Response::from_string("no target").with_status_code(400));
            return;
        }
    };
    let sub = &path[2..]; // "/stream" | "/camstream" | "/shell/stream"
    let q = query_without(url, "target");
    let agent_path = if q.is_empty() { sub.to_string() } else { format!("{sub}?{q}") };
    if let Some(id) = relay_target(&target) {
        match relay::request(&id, "GET", &agent_path, None) {
            Some(r) => {
                let ct = r.ctype.clone();
                let resp = Response::new(StatusCode(200), vec![hdr("Content-Type", &ct)], r, None, None);
                let _ = req.respond(resp);
            }
            None => {
                let _ = req.respond(Response::from_string("relay stream unreachable").with_status_code(502));
            }
        }
        return;
    }
    match http_stream().get(format!("{target}{agent_path}")).send() {
        Ok(r) if r.status().is_success() => {
            let ct = r
                .headers()
                .get("content-type")
                .and_then(|h| h.to_str().ok())
                .unwrap_or("multipart/x-mixed-replace; boundary=frame")
                .to_string();
            let resp = Response::new(StatusCode(200), vec![hdr("Content-Type", &ct)], r, None, None);
            let _ = req.respond(resp);
        }
        Ok(r) => {
            let _ = req.respond(Response::from_string(r.text().unwrap_or_default()).with_status_code(502));
        }
        Err(_) => {
            let _ = req.respond(Response::from_string("stream unreachable").with_status_code(502));
        }
    }
}

/// A fullscreen viewer page that renders the live MJPEG stream as an <img>.
fn live_page(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let src = match query_param(url, "src").as_deref() {
        Some("camstream") => "camstream",
        _ => "stream",
    };
    let index = query_param(url, "index").unwrap_or_default();
    let label = if src == "camstream" { "Camera" } else { "Screen" };
    let mut stream_url = format!("/x/{src}?target={}", urlencode(&target));
    if src == "camstream" && !index.is_empty() {
        stream_url = format!("{stream_url}&index={}", urlencode(&index));
    }
    let html = format!(
        "<!doctype html><meta charset=utf-8><title>{label} — live</title>\
<style>html,body{{margin:0;background:#000;height:100%}}\
img{{width:100%;height:100%;object-fit:contain;display:block}}</style>\
<img src=\"{stream_url}\" alt=\"{label} live stream\">"
    );
    Response::from_string(html).with_header(hdr("Content-Type", "text/html; charset=utf-8"))
}

/// If `target` is a relay device (`relay://<id>`), return its agent id.
fn relay_target(target: &str) -> Option<String> {
    target.strip_prefix("relay://").map(|s| s.trim_end_matches('/').to_string())
}

/// One request to a device by either transport → (status, content-type, body).
/// For relay devices it tunnels; otherwise it's a normal reqwest call.
fn dev_unary(target: &str, method: &str, path: &str, body: Option<(String, Vec<u8>)>) -> Option<(u16, String, Vec<u8>)> {
    if let Some(id) = relay_target(target) {
        let r = relay::request(&id, method, path, body)?;
        let (st, ct) = (r.status, r.ctype.clone());
        return Some((st, ct, r.read_all()));
    }
    let full = format!("{target}{path}");
    let rb = if method == "POST" { http().post(full) } else { http().get(full) };
    let rb = match body {
        Some((ct, b)) => rb.header("Content-Type", ct).body(b),
        None => rb,
    };
    let resp = rb.send().ok()?;
    let st = resp.status().as_u16();
    let ct = resp.headers().get("content-type").and_then(|h| h.to_str().ok()).unwrap_or("application/octet-stream").to_string();
    let bytes = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
    Some((st, ct, bytes))
}

/// The query string with the `drop` param removed (no leading `?`).
fn query_without(url: &str, drop: &str) -> String {
    let q = match url.split('?').nth(1) {
        Some(q) => q,
        None => return String::new(),
    };
    let prefix = format!("{drop}=");
    q.split('&').filter(|kv| !kv.starts_with(&prefix) && !kv.is_empty()).collect::<Vec<_>>().join("&")
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split('?').nth(1)?;
    let prefix = format!("{key}=");
    for kv in q.split('&') {
        if let Some(v) = kv.strip_prefix(&prefix) {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(n) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(n);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn proxy_frame(url: &str) -> Resp {
    let target = match query_param(url, "target") {
        Some(t) => t,
        None => return Response::from_string("no target").with_status_code(400),
    };
    match dev_unary(&target, "GET", "/frame", None) {
        Some((_st, ct, body)) => Response::from_data(body).with_header(hdr("Content-Type", &ct)),
        None => Response::from_string("frame failed").with_status_code(502),
    }
}

fn proxy_update(url: &str, agents: &Agents, hub_ip: &str, hub_port: u16) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let key = match relay_target(&target) {
        Some(id) => format!("relay:{id}"),
        None => target.split("://").nth(1).and_then(|s| s.split(':').next()).unwrap_or("").to_string(),
    };
    let platform = agents
        .lock()
        .unwrap()
        .get(&key)
        .and_then(|a| a.data.get("platform").and_then(|p| p.as_str()).map(String::from))
        .unwrap_or_default();
    let asset = match platform.as_str() {
        "windows" => "HaiveControl-windows.exe",
        "macos" => "HaiveControl-macos",
        "linux" => "HaiveControl-linux",
        _ => return Response::from_string("unknown platform for device").with_status_code(400),
    };
    let dl = format!("http://{hub_ip}:{hub_port}/bin/{asset}");
    let payload = serde_json::json!({ "url": dl }).to_string().into_bytes();
    match dev_unary(&target, "POST", "/update", Some(("application/json".into(), payload))) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "text/plain")),
        None => Response::from_string("update failed").with_status_code(502),
    }
}

fn proxy_dissolve(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    match dev_unary(&target, "POST", "/dissolve", None) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "text/plain")),
        None => Response::from_string("dissolve failed").with_status_code(502),
    }
}

fn proxy_camera(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let index = query_param(url, "index").unwrap_or_default();
    let path = if index.is_empty() { "/camera".to_string() } else { format!("/camera?index={index}") };
    match dev_unary(&target, "GET", &path, None) {
        Some((st, ct, body)) if st < 400 => Response::from_data(body).with_header(hdr("Content-Type", &ct)),
        Some((_st, _ct, body)) => Response::from_data(body).with_status_code(502),
        None => Response::from_string("camera unreachable").with_status_code(502),
    }
}

fn device_platform(agents: &Agents, target: &str) -> String {
    agents
        .lock()
        .unwrap()
        .get(&device_key(target))
        .and_then(|a| a.data.get("platform").and_then(|p| p.as_str()).map(String::from))
        .unwrap_or_default()
}

fn shell_arg(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || "._+-:/@".contains(*c)).collect()
}

/// The OS-appropriate shell command for a canned management action, or None if
/// unsupported on that platform. `arg` = message text / package id where used.
fn os_command(platform: &str, kind: &str, arg: &str) -> Option<String> {
    let cmd: String = match (kind, platform) {
        ("hardware", "windows") => "systeminfo".into(),
        ("hardware", "macos") => "system_profiler SPHardwareDataType".into(),
        ("hardware", "linux") => "lscpu; echo; free -h; echo; lsblk".into(),
        ("av", "windows") => "powershell -NoProfile -Command \"Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AMRunningMode | Format-List\"".into(),
        ("av", "macos") => "echo 'Gatekeeper:'; spctl --status; echo 'XProtect present:'; ls /Library/Apple/System/Library/CoreServices/XProtect.bundle >/dev/null 2>&1 && echo yes || echo no".into(),
        ("av", "linux") => "clamscan --version 2>/dev/null || echo 'no clamav installed'".into(),
        ("encryption", "windows") => "manage-bde -status C:".into(),
        ("encryption", "macos") => "fdesetup status".into(),
        ("encryption", "linux") => "lsblk -o NAME,FSTYPE,MOUNTPOINT | grep -i crypt || echo 'no LUKS volumes detected'".into(),
        ("firewall", "windows") => "netsh advfirewall show allprofiles state".into(),
        ("firewall", "macos") => "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate".into(),
        ("firewall", "linux") => "ufw status 2>/dev/null || echo 'ufw not present'".into(),
        ("firewall_on", "windows") => "netsh advfirewall set allprofiles state on".into(),
        ("firewall_on", "macos") => "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on".into(),
        ("firewall_on", "linux") => "sudo ufw enable".into(),
        ("firewall_off", "windows") => "netsh advfirewall set allprofiles state off".into(),
        ("firewall_off", "macos") => "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate off".into(),
        ("firewall_off", "linux") => "sudo ufw disable".into(),
        ("processes", "windows") => "tasklist".into(),
        ("processes", _) => "ps aux 2>/dev/null | sort -rk3 | head -25".into(),
        ("services", "windows") => "powershell -NoProfile -Command \"Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 40 Name,DisplayName | Format-Table -Auto\"".into(),
        ("services", "macos") => "launchctl list | head -40".into(),
        ("services", "linux") => "systemctl list-units --type=service --state=running --no-pager | head -40".into(),
        ("network", _) => "arp -a".into(),
        ("packages", "windows") => "winget list".into(),
        ("packages", "macos") => "brew list --versions 2>/dev/null || ls /Applications".into(),
        ("packages", "linux") => "apt list --installed 2>/dev/null | head -60 || dpkg -l | head -60".into(),
        ("reboot", "windows") => "shutdown /r /t 5".into(),
        ("reboot", _) => "sudo shutdown -r +1 2>/dev/null || shutdown -r +1".into(),
        ("shutdown", "windows") => "shutdown /s /t 5".into(),
        ("shutdown", _) => "sudo shutdown -h +1 2>/dev/null || shutdown -h +1".into(),
        ("sleep", "windows") => "rundll32.exe powrprof.dll,SetSuspendState 0,1,0".into(),
        ("sleep", "macos") => "pmset sleepnow".into(),
        ("sleep", "linux") => "systemctl suspend".into(),
        ("logoff", "windows") => "shutdown /l".into(),
        ("logoff", "macos") => "osascript -e 'tell application \"System Events\" to log out'".into(),
        ("logoff", "linux") => "loginctl terminate-user \"$USER\"".into(),
        ("usb_lock", "windows") => "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\" /v Start /t REG_DWORD /d 4 /f".into(),
        ("usb_unlock", "windows") => "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR\" /v Start /t REG_DWORD /d 3 /f".into(),
        ("message", "windows") => format!("msg * \"{}\"", arg.replace('"', "'")),
        ("message", "macos") => format!("osascript -e 'display dialog \"{}\" buttons {{\"OK\"}} with title \"HaiveControl\"'", arg.replace('"', "'").replace('\'', "’")),
        ("message", "linux") => format!("notify-send \"HaiveControl\" \"{}\"", arg.replace('"', "'")),
        ("install", "windows") => format!("winget install --silent --accept-package-agreements --accept-source-agreements {}", shell_arg(arg)),
        ("install", "macos") => format!("brew install {}", shell_arg(arg)),
        ("install", "linux") => format!("sudo apt-get install -y {}", shell_arg(arg)),
        ("uninstall", "windows") => format!("winget uninstall --silent {}", shell_arg(arg)),
        ("uninstall", "macos") => format!("brew uninstall {}", shell_arg(arg)),
        ("uninstall", "linux") => format!("sudo apt-get remove -y {}", shell_arg(arg)),
        ("updates", "windows") => "winget upgrade".into(),
        ("updates", "macos") => "softwareupdate -l".into(),
        ("updates", "linux") => "apt list --upgradable 2>/dev/null".into(),
        ("update_all", "windows") => "winget upgrade --all --silent --accept-package-agreements --accept-source-agreements".into(),
        ("update_all", "macos") => "softwareupdate -ia".into(),
        ("update_all", "linux") => "sudo apt-get update && sudo apt-get upgrade -y".into(),
        ("power_report", "windows") => "powercfg /getactivescheme & powercfg /batteryreport /output %TEMP%\\haive-battery.html & echo saved to %TEMP%\\haive-battery.html".into(),
        ("power_report", "macos") => "pmset -g custom | head -25".into(),
        ("power_report", "linux") => "upower -d 2>/dev/null | head -30 || echo 'upower not present'".into(),
        _ => return None,
    };
    Some(cmd)
}

/// (name, proxy-target, platform) for every device owned by `user`.
fn owned_targets(agents: &Agents, user: Option<&str>) -> Vec<(String, String, String)> {
    live(agents, user)
        .iter()
        .filter_map(|d| {
            let name = d.get("name").and_then(|x| x.as_str())?.to_string();
            let scheme = d.get("scheme").and_then(|x| x.as_str())?;
            let ip = d.get("ip").and_then(|x| x.as_str())?;
            let port = d.get("port").and_then(|x| x.as_u64()).unwrap_or(0);
            let platform = d.get("platform").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let target = if scheme == "relay" { format!("relay://{ip}") } else { format!("{scheme}://{ip}:{port}") };
            Some((name, target, platform))
        })
        .collect()
}

fn exec_output(target: &str, cmd: &str) -> String {
    let payload = serde_json::json!({ "cmd": cmd }).to_string().into_bytes();
    match dev_unary(target, "POST", "/exec", Some(("application/json".into(), payload))) {
        Some((_, _, b)) => {
            let v: serde_json::Value = serde_json::from_slice(&b).unwrap_or_default();
            let s = format!("{}{}", v.get("stdout").and_then(|x| x.as_str()).unwrap_or(""), v.get("stderr").and_then(|x| x.as_str()).unwrap_or(""));
            if s.trim().is_empty() { format!("(exit {})", v.get("code").and_then(|x| x.as_i64()).unwrap_or(0)) } else { s }
        }
        None => "(device unreachable)".to_string(),
    }
}

/// Heuristic pass/fail from a check's command output (best-effort across OSes).
fn posture_pass(kind: &str, out: &str) -> bool {
    let o = out.to_lowercase();
    match kind {
        "encryption" => o.contains("filevault is on") || o.contains("protection on") || o.contains("percentage encrypted: 100") || o.contains("crypt"),
        "firewall" => o.contains("state = 1") || o.contains("state on") || o.contains("firewall is enabled") || o.contains("status: active"),
        "av" => o.contains("antivirusenabled  : true") || o.contains("realtimeprotectionenabled : true") || o.contains("assessments enabled"),
        "updates" => o.contains("no new software") || o.contains("no applicable") || o.contains("no installed package") || out.lines().count() <= 2,
        _ => false,
    }
}

fn grade(score: i64) -> &'static str {
    match score {
        s if s >= 90 => "A",
        s if s >= 75 => "B",
        s if s >= 50 => "C",
        s if s >= 25 => "D",
        _ => "F",
    }
}

/// One canned management action on one device.
fn proxy_sys(url: &str, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let kind = query_param(url, "kind").unwrap_or_default();
    let arg = query_param(url, "arg").unwrap_or_default();
    if !may_control(user, agents, &target) {
        return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}));
    }
    let platform = device_platform(agents, &target);
    // Compliance posture (63): run the security checks and score them.
    if kind == "posture" {
        let dev = device_name(agents, &target);
        record_mcp_access(&target, "posture", user.unwrap_or(""), "compliance check");
        audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, "posture", &dev, "compliance check");
        let checks = [("disk encryption", "encryption"), ("firewall", "firewall"), ("antivirus", "av"), ("OS updates", "updates")];
        let mut items = Vec::new();
        let mut pass_n = 0;
        for (label, k) in checks {
            let out = os_command(&platform, k, "").map(|c| exec_output(&target, &c)).unwrap_or_else(|| "n/a".into());
            let pass = posture_pass(k, &out);
            if pass {
                pass_n += 1;
            }
            items.push(serde_json::json!({"check": label, "pass": pass, "output": out.chars().take(240).collect::<String>()}));
        }
        let score = (pass_n as f64 / checks.len() as f64 * 100.0).round() as i64;
        return json_resp(&serde_json::json!({"ok": true, "device": dev, "score": score, "grade": grade(score), "checks": items}));
    }
    let cmd = match os_command(&platform, &kind, &arg) {
        Some(c) => c,
        None => return json_resp(&serde_json::json!({"ok": false, "error": format!("'{kind}' not supported on {platform}")})),
    };
    let dev = device_name(agents, &target);
    let detail = if arg.is_empty() { cmd.clone() } else { format!("{kind} {arg}") };
    record_mcp_access(&target, &kind, user.unwrap_or(""), &detail);
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, &kind, &dev, &detail);
    let out = exec_output(&target, &cmd);
    json_resp(&serde_json::json!({"ok": true, "device": dev, "kind": kind, "output": out}))
}

/// Run a command (kind=exec, cmd=…) or a canned action (kind=…, arg=…) on ALL of
/// the user's devices, concurrently, and return per-device results.
fn proxy_fleet(url: &str, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let kind = query_param(url, "kind").unwrap_or_else(|| "exec".into());
    let cmd = query_param(url, "cmd").unwrap_or_default();
    let arg = query_param(url, "arg").unwrap_or_default();
    let targets = owned_targets(agents, user);
    audit(
        user.unwrap_or(""),
        if via_mcp { "mcp" } else { "browser" },
        "fleet",
        &format!("all ({})", targets.len()),
        &if kind == "exec" { cmd.clone() } else { format!("{kind} {arg}") },
    );
    let out = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let mut handles = Vec::new();
    for (name, target, platform) in targets {
        let (out, kind, cmd, arg) = (out.clone(), kind.clone(), cmd.clone(), arg.clone());
        handles.push(std::thread::spawn(move || {
            let command = if kind == "exec" { cmd } else { os_command(&platform, &kind, &arg).unwrap_or_default() };
            let text = if command.is_empty() {
                format!("(unsupported on {platform})")
            } else {
                exec_output(&target, &command)
            };
            out.lock().unwrap().push(serde_json::json!({"device": name, "output": text}));
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut results = std::sync::Arc::try_unwrap(out).unwrap().into_inner().unwrap();
    results.sort_by(|a, b| a["device"].as_str().unwrap_or("").cmp(b["device"].as_str().unwrap_or("")));
    json_resp(&serde_json::json!({"ok": true, "count": results.len(), "results": results}))
}

fn proxy_exec(req: &mut Request, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
    if !may_control(user, agents, target) {
        return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}));
    }
    let cmd = v.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
    if via_mcp {
        record_mcp_access(target, "run command", user.unwrap_or(""), cmd);
    }
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, "run command", &device_name(agents, target), cmd);
    let payload = serde_json::json!({ "cmd": cmd }).to_string().into_bytes();
    match dev_unary(target, "POST", "/exec", Some(("application/json".into(), payload))) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "application/json")),
        None => json_resp(&serde_json::json!({"ok": false, "error": "device unreachable"})),
    }
}

fn proxy_input(req: &mut Request, agents: &Agents, user: Option<&str>) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
    if !may_control(user, agents, target) {
        return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}));
    }
    let ev = v.get("ev").cloned().unwrap_or_else(|| serde_json::json!({}));
    let ev_kind = ev.get("type").and_then(|x| x.as_str()).unwrap_or("input");
    record_mcp_access(target, "input", user.unwrap_or(""), ev_kind);
    audit(user.unwrap_or(""), "mcp", "input", &device_name(agents, target), ev_kind);
    match dev_unary(target, "POST", "/input", Some(("application/json".into(), ev.to_string().into_bytes()))) {
        Some(_) => Response::from_string("").with_status_code(204),
        None => json_resp(&serde_json::json!({"ok": false, "error": "device unreachable"})),
    }
}

fn proxy_shell_open(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    match dev_unary(&target, "POST", "/shell/open", None) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "application/json")),
        None => json_resp(&serde_json::json!({"ok": false, "error": "device unreachable"})),
    }
}

fn proxy_shell_read(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let sid = query_param(url, "sid").unwrap_or_default();
    let from = query_param(url, "from").unwrap_or_else(|| "0".into());
    let path = format!("/shell/read?sid={}&from={}", urlencode(&sid), urlencode(&from));
    match dev_unary(&target, "GET", &path, None) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "text/plain; charset=utf-8")),
        None => Response::from_string("").with_status_code(502),
    }
}

fn proxy_shell_input(req: &mut Request, url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let sid = query_param(url, "sid").unwrap_or_default();
    let mut body = Vec::new();
    let _ = req.as_reader().read_to_end(&mut body);
    let path = format!("/shell/input?sid={}", urlencode(&sid));
    match dev_unary(&target, "POST", &path, Some(("text/plain".into(), body))) {
        Some(_) => Response::from_string("").with_status_code(204),
        None => Response::from_string("no session").with_status_code(502),
    }
}

fn proxy_shell_resize(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let sid = query_param(url, "sid").unwrap_or_default();
    let cols = query_param(url, "cols").unwrap_or_default();
    let rows = query_param(url, "rows").unwrap_or_default();
    let path = format!("/shell/resize?sid={}&cols={}&rows={}", urlencode(&sid), urlencode(&cols), urlencode(&rows));
    let _ = dev_unary(&target, "POST", &path, None);
    Response::from_string("").with_status_code(204)
}

fn proxy_shell_close(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let sid = query_param(url, "sid").unwrap_or_default();
    let path = format!("/shell/close?sid={}", urlencode(&sid));
    let _ = dev_unary(&target, "POST", &path, None);
    Response::from_string("closed")
}

fn proxy_download(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let path = query_param(url, "path").unwrap_or_default();
    let apath = format!("/download?path={}", urlencode(&path));
    match dev_unary(&target, "GET", &apath, None) {
        Some((_st, _ct, bytes)) => {
            let fname = path.rsplit(['/', '\\']).find(|s| !s.is_empty()).unwrap_or("download");
            Response::from_data(bytes)
                .with_header(hdr("Content-Type", "application/octet-stream"))
                .with_header(hdr("Content-Disposition", &format!("attachment; filename=\"{fname}\"")))
        }
        None => Response::from_string("download failed").with_status_code(502),
    }
}

fn proxy_list(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let path = query_param(url, "path").unwrap_or_default();
    let apath = format!("/list?path={}", urlencode(&path));
    match dev_unary(&target, "GET", &apath, None) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "application/json")),
        None => Response::from_string("{\"ok\":false,\"error\":\"list failed\"}").with_header(hdr("Content-Type", "application/json")),
    }
}

fn proxy_upload(req: &mut Request, url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let ct = req.headers().iter().find(|h| h.field.equiv("Content-Type")).map(|h| h.value.as_str().to_string()).unwrap_or_default();
    let mut body = Vec::new();
    let _ = req.as_reader().read_to_end(&mut body);
    match dev_unary(&target, "POST", "/upload", Some((ct, body))) {
        Some((_st, _ct, b)) => Response::from_data(b).with_header(hdr("Content-Type", "application/json")),
        None => json_resp(&serde_json::json!({"ok": false, "error": "upload failed"})),
    }
}

fn install_ps1(ip: &str, port: u16, mac_id: &str) -> String {
    const T: &str = r#"param([Parameter(Position=0)][string]$Password = $env:HIVE_PW)
$ErrorActionPreference = "Stop"
$hub = "__HUB__"
$id  = "__ID__"
$dir = Join-Path $env:LOCALAPPDATA "airm"
$dest = Join-Path $dir "airm.exe"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Write-Host "Downloading airm from $hub ..."
Invoke-WebRequest -Uri "http://$hub/bin/HaiveControl-windows.exe" -OutFile $dest
Write-Host "Registering to hub $hub (fallback id $id) ..."
if ($Password) { & $dest $hub --id $id $Password } else { & $dest $hub --id $id }
"#;
    T.replace("__HUB__", &format!("{ip}:{port}")).replace("__ID__", mac_id)
}

fn install_sh(ip: &str, port: u16, mac_id: &str) -> String {
    const T: &str = r#"#!/bin/sh
set -e
HUB="__HUB__"
ID="__ID__"
PASSWORD="${1:-$HIVE_PW}"
case "$(uname -s)" in
  Darwin) ASSET="HaiveControl-macos" ;;
  Linux)  ASSET="HaiveControl-linux" ;;
  *) echo "unsupported OS: $(uname -s)"; exit 1 ;;
esac
DEST="$HOME/.airm/airm"; mkdir -p "$HOME/.airm"
echo "Downloading airm ($ASSET) from $HUB ..."
curl -fsSL "http://$HUB/bin/$ASSET" -o "$DEST"
chmod +x "$DEST"
echo "Registering to hub $HUB (fallback id $ID) ..."
exec "$DEST" "$HUB" --id "$ID" $PASSWORD
"#;
    T.replace("__HUB__", &format!("{ip}:{port}")).replace("__ID__", mac_id)
}

fn register(req: &mut Request, agents: &Agents) {
    let remote_ip = req.remote_addr().map(|a| a.ip().to_string());
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&body) {
        let ip = v
            .get("ip")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or(remote_ip)
            .unwrap_or_default();
        if let Some(o) = v.get("owner").and_then(|x| x.as_str()).map(canon_owner) {
            v.as_object_mut().unwrap().insert("owner".to_string(), serde_json::json!(o));
        }
        if let Some(obj) = v.as_object_mut() {
            obj.insert("ip".to_string(), serde_json::Value::String(ip.clone()));
        }
        agents.lock().unwrap().insert(ip, Agent { data: v, last: Instant::now() });
    }
}

fn live(agents: &Agents, user: Option<&str>) -> Vec<serde_json::Value> {
    let now = Instant::now();
    let guard = agents.lock().unwrap();
    let alog = access_log().lock().unwrap();
    guard
        .iter()
        .filter(|(_, a)| now.duration_since(a.last) < STALE)
        .filter(|(_, a)| match user {
            None => true,
            Some(u) => a.data.get("owner").and_then(|o| o.as_str()) == Some(u),
        })
        .map(|(key, a)| {
            let mut d = a.data.clone();
            if let Some(o) = d.as_object_mut() {
                o.insert("last_seen_secs".to_string(), serde_json::json!(now.duration_since(a.last).as_secs()));
                if let Some(events) = alog.get(key) {
                    // Only surface accesses within the last 5 minutes.
                    let recent: Vec<serde_json::Value> = events
                        .iter()
                        .map(|(at, act, own, det)| (now.duration_since(*at).as_secs(), act, own, det))
                        .filter(|(secs, ..)| *secs < 300)
                        .map(|(secs, act, own, det)| serde_json::json!({"action": act, "owner": own, "secs": secs, "detail": det}))
                        .collect();
                    let active = events.front().map(|(at, ..)| now.duration_since(*at).as_secs() < 10).unwrap_or(false);
                    o.insert("mcp_active".to_string(), serde_json::json!(active));
                    o.insert("mcp_log".to_string(), serde_json::json!(recent));
                }
            }
            d
        })
        .collect()
}

fn json_agents(agents: &Agents, user: Option<&str>) -> Resp {
    json_resp(&serde_json::json!({"agents": live(agents, user)}))
}

/// Audit events, scoped to the requesting user (all when no user context).
fn json_audit(user: Option<&str>) -> Resp {
    let now = Instant::now();
    let events: Vec<serde_json::Value> = audit_log()
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, actor, ..)| match user {
            None => true,
            Some(u) => actor == u,
        })
        .map(|(at, actor, source, action, device, detail)| {
            serde_json::json!({
                "secs": now.duration_since(*at).as_secs(),
                "actor": actor, "source": source, "action": action, "device": device, "detail": detail
            })
        })
        .collect();
    json_resp(&serde_json::json!({"audit": events}))
}

fn dashboard(_agents: &Agents, mac_id: &str, hub_ip: &str, hub_port: u16, user: Option<&str>) -> Resp {
    // When the hub is reachable at a public URL (a cloud deploy), show relay-mode
    // install commands (device dials out); otherwise LAN-mode (hub reaches in).
    let (win, mac, lin) = match std::env::var("HUB_PUBLIC_URL").ok().filter(|s| !s.is_empty()) {
        Some(pub_url) => {
            let b = pub_url.trim_end_matches('/').to_string();
            let tok = match std::env::var("RELAY_TOKEN") {
                Ok(t) if !t.is_empty() => format!(" --relay-token {t}"),
                _ => String::new(),
            };
            // Tag the device with the logged-in user so it lists only for them.
            let own = user.map(|u| format!(" --owner {u}")).unwrap_or_default();
            let ex = format!("{tok}{own}");
            (
                cmd_block("Windows (PowerShell or cmd)", &format!("curl.exe -L -o airm.exe {b}/bin/HaiveControl-windows.exe\n.\\airm.exe --relay {b}{ex} --name my-pc")),
                cmd_block("macOS", &format!("curl -L -o airm {b}/bin/HaiveControl-macos && chmod +x airm\n./airm --relay {b}{ex} --name my-mac")),
                cmd_block("Linux", &format!("curl -L -o airm {b}/bin/HaiveControl-linux && chmod +x airm\n./airm --relay {b}{ex} --name my-box")),
            )
        }
        None => {
            let hub = format!("{hub_ip}:{hub_port}");
            (
                cmd_block("Windows (PowerShell or cmd)", &format!("curl.exe -L -o airm.exe http://{hub}/bin/HaiveControl-windows.exe\n.\\airm.exe {hub} --id {mac_id}")),
                cmd_block("macOS", &format!("curl -L -o airm http://{hub}/bin/HaiveControl-macos && chmod +x airm\n./airm {hub} --id {mac_id}")),
                cmd_block("Linux", &format!("curl -L -o airm http://{hub}/bin/HaiveControl-linux && chmod +x airm\n./airm {hub} --id {mac_id}")),
            )
        }
    };
    // Values the dashboard bakes into the per-device "copy agent setup" action.
    // Behind SSO, so showing the viewer their own MCP token + owner is fine.
    let hb_base = std::env::var("HUB_PUBLIC_URL").ok().filter(|s| !s.is_empty()).unwrap_or_else(|| format!("http://{hub_ip}:{hub_port}"));
    let hb_mtok = std::env::var("MCP_TOKEN").ok().filter(|s| !s.is_empty()).unwrap_or_default();
    let hb = format!(
        "<script>window.HB={{base:\"{}\",mtok:\"{}\",owner:\"{}\"}}</script>",
        hb_base.replace('"', ""),
        hb_mtok.replace('"', ""),
        user.unwrap_or("").replace('"', "")
    );
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>HaiveControl hub</title>\n<link rel=\"stylesheet\" href=\"/assets/xterm.css\"><style>{cp_css}</style></head>\n<body>\
<div class=\"app\">\
<aside class=\"side\">\
<div class=\"side-head\"><div><h1>HaiveControl <span class=\"dim2\">hub</span></h1><code>{mac_id}</code></div><span class=\"pill\" id=\"count\">…</span></div>\
<div class=\"legend\"><span><span class=\"dot on\"></span>online</span><span><span class=\"dot idle\"></span>idle</span><span><span class=\"dot off\"></span>stale</span></div>\
<input id=\"devsearch\" class=\"devsearch\" type=\"search\" placeholder=\"Search devices…\" autocomplete=\"off\" oninput=\"SEARCH=this.value.toLowerCase();renderSide(LAST);\">\
<ul id=\"devlist\" class=\"devlist\"></ul>\
<button class=\"addbtn\" onclick=\"showFleet()\">⚡ Fleet run</button>\
<button class=\"addbtn\" onclick=\"showAudit()\">📋 Audit log</button>\
<button class=\"addbtn\" onclick=\"toggleReg()\">+ Register a device</button>\
<div id=\"reg\" class=\"reg\" style=\"display:none\"><p class=\"reg-hint\">Download the agent, then run it:</p>{win}{mac}{lin}</div>\
</aside>\
<main class=\"stage\">\
<div class=\"stage-empty\" id=\"stage-empty\">Select a device from the left to control it.</div>\
<div id=\"audit-view\" style=\"display:none\"><div class=\"aud-head\">Audit log <span class=\"dim2\">— device actions on your account</span></div><div class=\"aud-cols\"><span>when</span><span>via</span><span>action</span><span>device</span><span>who</span><span>detail</span></div><div id=\"audit-rows\"></div></div>\
<div id=\"fleet-view\" style=\"display:none\"><div class=\"aud-head\">Fleet run <span class=\"dim2\">— run on all your devices, in parallel</span></div><div class=\"fleet-bar\"><input id=\"fleet-cmd\" class=\"devsearch\" placeholder=\"shell command to run on every device…\" autocomplete=\"off\"><button class=\"b\" onclick=\"runFleet()\">Run on all</button></div><div id=\"fleet-results\"></div></div>\
<div id=\"detail\" style=\"display:none\">\
<div class=\"detail-head\"><div class=\"dh-id\"><span class=\"dot\" id=\"d-dot\"></span><div><div class=\"dh-name\" id=\"d-name\"></div><div class=\"dh-sub\" id=\"d-sub\"></div></div></div>\
<a class=\"dh-open\" id=\"d-open\" target=\"_blank\">Open agent&nbsp;↗</a></div>\
<div class=\"specs\" id=\"d-specs\"></div>\
<div id=\"d-activity\"></div>\
<div class=\"controls\" id=\"d-controls\"></div>\
<div class=\"viewport\" id=\"viewport\"><div class=\"vp-hint\" id=\"vp-hint\">Press <b>Live screen</b>, <b>Screenshot</b>, or a <b>Camera</b> action — it renders here.</div><img id=\"view\" alt=\"\" style=\"display:none\"><div class=\"vp-tools\" id=\"vp-tools\" style=\"display:none\"><button class=\"b\" onclick=\"stopView()\">Stop</button><button class=\"b\" onclick=\"openTab()\">Open in tab&nbsp;↗</button></div></div>\
<div class=\"term\" id=\"terminal\" style=\"display:none\"><div class=\"term-head\"><span>interactive shell</span><button class=\"b\" onclick=\"closeShell()\">Close shell</button></div><div id=\"xterm\" class=\"xterm-host\"></div></div>\
<pre class=\"output\" id=\"out\" style=\"display:none\"></pre>\
</div>\
</main>\
</div>{fb}{hb}<script src=\"/assets/xterm.js\"></script><script src=\"/assets/addon-fit.js\"></script>{script}</body></html>",
        cp_css = CP_CSS, script = COPY_SCRIPT, fb = FB_HTML
    );
    Response::from_string(html).with_header(hdr("Content-Type", "text/html"))
}

const CP_CSS: &str = r#"
:root{--bg:#0d0f14;--surface:#151823;--surface2:#1b1f2b;--line:#232838;--line2:#2c3245;--text:#e6e9f2;--muted:#8b93a7;--muted2:#646c7e;--accent:#5b9dff;--on:#35d07f;--idle:#f5a623;--off:#5b6472;--danger:#ff6b6b}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;background:var(--bg);color:var(--text);max-width:1340px;margin:24px auto;padding:0 20px}
h1{font-size:16px;font-weight:700;letter-spacing:-.2px;margin:0}
h2{font-size:14px;font-weight:600;margin:0 0 4px}
code{background:var(--surface2);border:1px solid var(--line);padding:3px 8px;border-radius:6px;font-size:11px;color:#c7ccda}
pre{margin:0}
.dim2{color:var(--muted);font-weight:400}
.pill{background:rgba(91,157,255,.14);color:var(--accent);border:1px solid rgba(91,157,255,.32);border-radius:999px;padding:3px 10px;font-size:11px;font-weight:600;white-space:nowrap}
.legend{display:flex;align-items:center;gap:14px;color:var(--muted);font-size:11px;margin:0}
.legend>span{display:inline-flex;align-items:center}
.reg-hint{font-size:12px;color:var(--muted);margin:0 0 10px}
.app{display:flex;align-items:stretch;min-height:calc(100vh - 60px);border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--surface)}
.side{width:288px;flex:none;border-right:1px solid var(--line);display:flex;flex-direction:column;background:#11141d}
.side-head{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;padding:15px 15px 6px}
.side-head code{display:inline-block;margin-top:7px}
.side .legend{padding:6px 15px 12px}
.devlist{list-style:none;margin:0;padding:7px;overflow-y:auto;flex:1;display:flex;flex-direction:column;gap:3px}
.dev-li{display:flex;align-items:center;gap:10px;padding:9px 11px;border-radius:9px;cursor:pointer;border:1px solid transparent;transition:background .12s,border-color .12s}
.dev-li:hover{background:var(--surface2)}
.dev-li.sel{background:rgba(91,157,255,.13);border-color:rgba(91,157,255,.38)}
.dl-txt{display:flex;flex-direction:column;min-width:0;flex:1}
.dl-name{font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dl-meta{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dl-load{flex:none;font-size:11px;font-weight:600;color:var(--muted);font-variant-numeric:tabular-nums}
.agi{flex:none;background:none;border:0;cursor:pointer;font-size:14px;line-height:1;opacity:.55;padding:2px 3px;border-radius:6px;transition:opacity .12s,background .12s}
.agi:hover{opacity:1;background:var(--surface2)}
@keyframes mcppulse{0%,100%{opacity:.4}50%{opacity:1}}
.mcp-live{flex:none;font-size:11px;color:var(--accent);white-space:nowrap;animation:mcppulse 1s ease-in-out infinite}
.activity{background:rgba(91,157,255,.06);border:1px solid var(--line);border-radius:10px;padding:9px 12px;margin-top:2px}
.act-head{display:flex;align-items:center;font-size:12px;font-weight:600;color:var(--muted);margin-bottom:4px}
.act-dot{width:8px;height:8px;border-radius:50%;background:var(--muted2);display:inline-block;margin-right:8px;flex:none}
.act-head.live{color:var(--accent)}
.act-head.live .act-dot{background:var(--on);box-shadow:0 0 8px var(--on);animation:mcppulse 1s ease-in-out infinite}
.act-row{display:flex;gap:12px;font-size:12px;color:var(--muted);padding:3px 0;cursor:default}
.act-act{color:#c3c9d8;min-width:110px;flex:none}
.act-det{flex:1;min-width:0;font-family:ui-monospace,Menlo,monospace;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.act-by{flex:none;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.act-ago{font-variant-numeric:tabular-nums;flex:none}
.aud-head{font-size:16px;font-weight:700;margin-bottom:12px}
.aud-cols,.aud-row{display:grid;grid-template-columns:78px 62px 130px 130px 150px 1fr;gap:12px;align-items:center;padding:7px 8px}
.aud-cols{color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.5px;border-bottom:1px solid var(--line2)}
.aud-row{font-size:12px;border-bottom:1px solid var(--line)}
.aud-row:hover{background:var(--surface2)}
.aud-when,.aud-actor{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.aud-src{font-size:9px;text-transform:uppercase;font-weight:700;padding:2px 0;border-radius:5px;text-align:center}
.aud-src.mcp{background:rgba(91,157,255,.16);color:var(--accent)}
.aud-src.browser{background:var(--surface2);color:var(--muted)}
.aud-act{color:#d7dbe6;font-weight:600}
.aud-dev{color:#c3c9d8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.aud-detail{color:var(--muted);font-family:ui-monospace,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.aud-empty{color:var(--muted2);padding:18px 8px;font-size:13px}
.devsearch{width:100%;margin:0 0 8px;background:var(--surface2);border:1px solid var(--line2);color:#d7dbe6;border-radius:8px;padding:8px 11px;font-size:13px;outline:none}
.devsearch:focus{border-color:var(--accent)}
.fleet-bar{display:flex;gap:8px;margin-bottom:14px}
.fleet-bar .devsearch{margin:0;flex:1}
.fleet-card{border:1px solid var(--line);border-radius:10px;margin-bottom:10px;overflow:hidden}
.fleet-dev{background:var(--surface2);padding:7px 12px;font-weight:600;font-size:12px;color:#d7dbe6}
.fleet-out{margin:0;padding:10px 12px;font-family:ui-monospace,Menlo,monospace;font-size:11px;line-height:1.5;color:#c3c9d8;white-space:pre-wrap;max-height:200px;overflow:auto}
.dl-load.warn{color:var(--idle)}
.dl-load.hot{color:var(--danger)}
.empty-li{color:var(--muted);font-size:12px;padding:14px 11px}
.addbtn{margin:9px;padding:9px;border-radius:9px;background:var(--surface2);border:1px solid var(--line2);color:#d7dbe6;cursor:pointer;font-size:12px;transition:background .15s}
.addbtn:hover{background:#252b3a}
.reg{padding:10px 14px 14px;border-top:1px solid var(--line)}
.stage{flex:1;min-width:0;display:flex;flex-direction:column;padding:18px 20px;gap:14px}
.stage-empty{margin:auto;color:var(--muted2);font-size:13px}
.detail-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}
.dh-id{display:flex;align-items:center;gap:12px;min-width:0}
.dh-id .dot{margin:0}
.dh-name{font-size:18px;font-weight:700;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dh-sub{font-size:12px;color:var(--muted);font-family:ui-monospace,Menlo,monospace;margin-top:2px}
.dh-open{color:var(--accent);font-size:12px;text-decoration:none;border:1px solid var(--line2);padding:6px 11px;border-radius:8px;white-space:nowrap;flex:none;transition:background .15s}
.dh-open:hover{background:var(--surface2)}
.specs{display:flex;flex-wrap:wrap;gap:8px}
.spec{display:inline-flex;gap:7px;align-items:baseline;background:var(--surface2);border:1px solid var(--line);border-radius:8px;padding:5px 10px;font-size:12px;color:#c3c9d8;max-width:100%;overflow:hidden}
.spec .sl{color:var(--muted);font-size:10px;text-transform:uppercase;letter-spacing:.5px;flex:none}
.spec .sv{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chiprow{display:flex;flex-wrap:wrap;gap:6px;width:100%}
.meters{display:flex;gap:16px;flex-wrap:wrap;width:100%}
.meter{min-width:190px;flex:1;max-width:280px}
.meter-top{display:flex;justify-content:space-between;gap:8px;font-size:11px;color:var(--muted);margin-bottom:5px}
.meter-bar{height:7px;background:var(--surface2);border:1px solid var(--line2);border-radius:5px;overflow:hidden}
.meter-fill{height:100%;background:var(--accent);border-radius:5px;transition:width .4s ease}
.meter-fill.warn{background:var(--idle)}
.meter-fill.hot{background:var(--danger)}
.viewport{position:relative;flex:1;min-height:340px;background:#000;border-radius:12px;border:1px solid var(--line);display:flex;align-items:center;justify-content:center;overflow:hidden}
.viewport img{max-width:100%;max-height:100%;object-fit:contain;display:block}
.vp-hint{color:var(--muted2);font-size:13px;padding:24px;text-align:center;line-height:1.6}
.vp-hint b{color:var(--muted)}
.vp-tools{position:absolute;top:10px;right:10px;display:flex;gap:6px;z-index:2}
.output{background:#0b0d13;border:1px solid var(--line);border-radius:10px;padding:12px 14px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#c3c9d8;white-space:pre-wrap;max-height:220px;overflow:auto}
.term{flex:1;min-height:340px;display:flex;flex-direction:column;background:#0b0d13;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.term-head{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 12px;border-bottom:1px solid var(--line);font-size:12px;color:var(--muted)}
.xterm-host{flex:1;min-height:0;padding:8px 6px 6px 10px;overflow:hidden}
.xterm-host .xterm{height:100%}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;vertical-align:middle;flex:none}
.dot.on{background:var(--on);box-shadow:0 0 7px var(--on)}
.dot.idle{background:var(--idle)}
.dot.off{background:var(--off)}
.chip{display:inline-flex;gap:5px;align-items:center;background:var(--surface2);border:1px solid var(--line2);color:var(--muted);border-radius:6px;padding:3px 8px;font-size:11px;font-family:ui-monospace,Menlo,monospace}
.chip b{color:#aeb6c9;font-weight:600}
.chip.mic{font-family:inherit;color:#9aa2b6}
.chip.off{font-family:inherit;font-style:italic;color:var(--muted2)}
.dim{color:var(--muted2)}
.fbrow.dim{opacity:.55}
.controls{display:flex;flex-wrap:wrap;gap:7px;align-items:center;padding:13px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.b{background:var(--surface2);border:1px solid var(--line2);color:#d7dbe6;border-radius:7px;padding:6px 11px;cursor:pointer;font-size:12px;font-weight:500;white-space:nowrap;transition:background .15s,border-color .15s,color .15s}
.b:hover{background:#252b3a;border-color:#3a4258;color:#fff}
.b:active{background:#2c3346}
.b:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.b.subtle{color:var(--muted)}
.b.danger{color:#ffb0b0;border-color:#5a2b2b}
.b.danger:hover{background:#3a1e1e;border-color:var(--danger);color:#fff}
.campick{background:var(--surface2);border:1px solid var(--line2);color:#d7dbe6;border-radius:7px;padding:6px 8px;font-size:12px;cursor:pointer;max-width:180px}
.campick:focus-visible{outline:2px solid var(--accent)}
.cp{position:absolute;top:8px;right:8px;background:var(--surface2);border:1px solid var(--line2);color:#bbb;border-radius:6px;padding:8px 9px;cursor:pointer;line-height:0;transition:background .15s}
.cp:hover{background:#2a3040;color:#fff}.cp:active{background:#3a3a3a}
.fbwrap{display:none;position:fixed;inset:0;background:#000b;align-items:center;justify-content:center;z-index:50}
.fbpanel{background:var(--surface);border:1px solid var(--line);border-radius:12px;width:min(560px,92vw);max-height:80vh;display:flex;flex-direction:column}
.fbhead{display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid var(--line)}
.fbpath{font-size:12px;color:var(--muted);font-family:ui-monospace,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.fbbody{overflow:auto;padding:6px}
.fbrow{padding:8px 10px;border-radius:7px;cursor:pointer;font-size:13px}
.fbrow:hover{background:var(--surface2)}
.fbdir{color:#9ecbff}
.fbfoot{padding:10px 12px;border-top:1px solid var(--line)}
.fbwrap button{background:var(--surface2);border:1px solid var(--line2);color:#ddd;border-radius:7px;padding:6px 10px;cursor:pointer;font-size:12px;transition:background .15s}
.fbwrap button:hover{background:#2a3040}
"#;

const FB_HTML: &str = r#"<div id="fb" class="fbwrap"><div class="fbpanel"><div class="fbhead"><button onclick="fbLoad(fbParent)" title="up">&#8593;</button><span id="fbpath" class="fbpath"></span><button onclick="closeFb()">&#10005;</button></div><div id="fbbody" class="fbbody"></div><div class="fbfoot"><button id="fbupload" onclick="fbUploadHere()">Upload file here</button></div></div></div>"#;

const COPY_SCRIPT: &str = r#"<script>
function cp(b){var pre=b.parentElement.querySelector('pre');var t=pre.innerText;var o=b.innerHTML;var ok=function(){b.textContent='✓';setTimeout(function(){b.innerHTML=o;},1200);};if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,function(){fb(t,ok);});}else{fb(t,ok);}}
function fb(t,ok){var a=document.createElement('textarea');a.value=t;a.setAttribute('readonly','');a.style.position='fixed';a.style.top='0';a.style.opacity='0';document.body.appendChild(a);a.focus();a.select();try{a.setSelectionRange(0,t.length);}catch(e){}try{document.execCommand('copy');ok();}catch(e){}document.body.removeChild(a);}
function enc(s){return encodeURIComponent(s);}
function esc2(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function attrEsc(s){return esc2(s).replace(/"/g,'&quot;');}
function fmtSize(n){if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(0)+' KB';if(n<1073741824)return (n/1048576).toFixed(1)+' MB';return (n/1073741824).toFixed(1)+' GB';}
function toggleReg(){var r=document.getElementById('reg');r.style.display=(r.style.display==='none')?'block':'none';}
/* ---- devices ---- */
var DEV={},SEL=null,SEARCH='',LAST=[];
function baseOf(d){return d.scheme==='relay'?('relay://'+d.ip):(d.scheme+'://'+d.ip+':'+d.port);}
function statusOf(d){var s=(d.last_seen_secs==null)?99999:d.last_seen_secs;return s<15?'on':(s<40?'idle':'off');}
function seenTxt(s){if(s==null)return '';return s<60?(s+'s ago'):(s<3600?(Math.floor(s/60)+'m ago'):(Math.floor(s/3600)+'h ago'));}
function fetchAgents(){fetch('/agents').then(function(r){return r.json();}).then(function(j){var arr=(j&&j.agents)||[];DEV={};arr.forEach(function(d){DEV[baseOf(d)]=d;});LAST=arr;renderSide(arr);if(SEL&&DEV[SEL]){refreshHead(DEV[SEL]);}else if(SEL){SEL=null;showEmpty();}if(!SEL&&arr.length){select(baseOf(arr[0]));}}).catch(function(){});}
function renderSide(arr){var el=document.getElementById('devlist');document.getElementById('count').textContent=arr.length+' device'+(arr.length===1?'':'s');var fa=SEARCH?arr.filter(function(d){return ((d.name||'')+' '+(d.hostname||'')+' '+(d.os||'')+' '+(d.ip||'')).toLowerCase().indexOf(SEARCH)>=0;}):arr;if(!fa.length){el.innerHTML='<li class="empty-li">'+(arr.length?'No match.':'No devices yet — register one below.')+'</li>';return;}var h='';fa.forEach(function(d){var b=baseOf(d);var sel=(b===SEL)?' sel':'';var load=(d.cpu_pct!=null)?('<span class="dl-load '+loadCls(d.cpu_pct)+'" title="CPU load">'+Math.round(d.cpu_pct)+'%</span>'):'';var mcp=d.mcp_active?'<span class="mcp-live" title="an AI agent is accessing this device via MCP">🤖⇄</span>':'';var nm=d.name||d.hostname||d.ip;h+='<li class="dev-li'+sel+'" data-base="'+attrEsc(b)+'"><span class="dot '+statusOf(d)+'"></span><span class="dl-txt"><span class="dl-name">'+esc2(nm)+'</span><span class="dl-meta">'+esc2(d.os||'')+' · '+seenTxt(d.last_seen_secs)+'</span></span>'+mcp+load+'<button class="agi" title="copy AI-agent setup for this device" onclick="event.stopPropagation();copyAgentFor(this,\''+attrEsc(nm)+'\')">🤖</button></li>';});el.innerHTML=h;}
function activityHtml(d){var log=d.mcp_log||[];if(!log.length)return '';var head='<div class="act-head'+(d.mcp_active?' live':'')+'"><span class="act-dot"></span>'+(d.mcp_active?'AI agent accessing now':'recent MCP activity')+'</div>';var rows=log.map(function(e){var det=e.detail||'';var tip=det?(e.action+': '+det):e.action;return '<div class="act-row" title="'+attrEsc(tip)+'"><span class="act-act">'+esc2(e.action)+'</span><span class="act-det">'+esc2(det)+'</span><span class="act-by">'+esc2(e.owner||'—')+'</span><span class="act-ago">'+e.secs+'s ago</span></div>';}).join('');return '<div class="activity">'+head+rows+'</div>';}
function copyAgentFor(btn,name){var hb=window.HB||{};var base=hb.base||location.origin;var L=[];L.push('# HaiveControl — control \"'+name+'\" from your AI agent (Claude).');L.push('# 1) install the MCP once (macOS shown; -linux / -windows.exe also served):');L.push('curl -L -o haive-mcp '+base+'/bin/haive-mcp-macos && chmod +x haive-mcp');var env=' --env HAIVE_HUB='+base;if(hb.mtok)env+=' --env HIVE_MCP_TOKEN='+hb.mtok;if(hb.owner)env+=' --env HIVE_OWNER='+hb.owner;L.push('claude mcp add haive'+env+' -- \"$PWD/haive-mcp\"');L.push('');L.push('# 2) then ask your agent, e.g.:');L.push('#   take a screenshot of '+name);L.push('#   run `uname -a` on '+name);L.push('#   type \"hello\" on '+name+' then press Enter');copyText(L.join('\n'),btn);}
function copyText(t,btn){var ok=function(){if(!btn)return;var o=btn.textContent;btn.textContent='✓';setTimeout(function(){btn.textContent=o;},1200);};if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,function(){fb(t,ok);});}else{fb(t,ok);}}
function showEmpty(){document.getElementById('detail').style.display='none';document.getElementById('stage-empty').style.display='block';}
var AUDIT_ON=false;
function agoTxt(s){return s<60?(s+'s ago'):(s<3600?(Math.floor(s/60)+'m ago'):(Math.floor(s/3600)+'h ago'));}
function showAudit(){AUDIT_ON=true;SEL=null;highlight();document.getElementById('detail').style.display='none';document.getElementById('stage-empty').style.display='none';document.getElementById('fleet-view').style.display='none';document.getElementById('audit-view').style.display='block';loadAudit();}
function sysCall(kind,arg){var u='/x/sys?target='+enc(SEL)+'&kind='+enc(kind);if(arg)u+='&arg='+enc(arg);out(kind+' …');fetch(u).then(function(r){return r.json();}).then(function(j){out(j.output||('[error] '+(j.error||'failed')));}).catch(function(e){out('error: '+e);});}
function doSys(){var k=prompt('Report — hardware / av / encryption / firewall / processes / services / network / packages / updates / power_report','hardware');if(k)sysCall(k.trim(),'');}
function doPower(){var a=prompt('Action — reboot / shutdown / sleep / logoff / update_all / firewall_on / firewall_off / usb_lock / usb_unlock','sleep');if(!a)return;a=a.trim();if(!confirm(a+' — run on this device?'))return;sysCall(a,'');}
function doMsg(){var t=prompt('Message to show the logged-in user:');if(t)sysCall('message',t);}
function doInstall(){var p=prompt('Package to install (winget id / brew formula / apt package):');if(p)sysCall('install',p.trim());}
function doPosture(){out('checking compliance…');fetch('/x/sys?target='+enc(SEL)+'&kind=posture').then(function(r){return r.json();}).then(function(j){if(!j.ok){out('[error] '+(j.error||'failed'));return;}var s='Compliance: '+j.grade+' ('+j.score+'/100)\n';(j.checks||[]).forEach(function(c){s+='  ['+(c.pass?'PASS':'FAIL')+'] '+c.check+'\n';});out(s);}).catch(function(e){out('error: '+e);});}
function showFleet(){AUDIT_ON=false;SEL=null;highlight();document.getElementById('detail').style.display='none';document.getElementById('stage-empty').style.display='none';document.getElementById('audit-view').style.display='none';document.getElementById('fleet-view').style.display='block';document.getElementById('fleet-cmd').focus();}
function runFleet(){var c=document.getElementById('fleet-cmd').value;if(!c)return;var el=document.getElementById('fleet-results');el.innerHTML='<div class="aud-empty">running on all devices…</div>';fetch('/x/fleet?kind=exec&cmd='+enc(c)).then(function(r){return r.json();}).then(function(j){var rs=j.results||[];if(!rs.length){el.innerHTML='<div class="aud-empty">No devices.</div>';return;}el.innerHTML=rs.map(function(r){return '<div class="fleet-card"><div class="fleet-dev">'+esc2(r.device)+'</div><pre class="fleet-out">'+esc2(r.output||'')+'</pre></div>';}).join('');}).catch(function(e){el.innerHTML='<div class="aud-empty">error: '+esc2(''+e)+'</div>';});}
function loadAudit(){fetch('/audit').then(function(r){return r.json();}).then(function(j){var ev=j.audit||[];var el=document.getElementById('audit-rows');if(!ev.length){el.innerHTML='<div class="aud-empty">No device actions recorded yet.</div>';return;}el.innerHTML=ev.map(function(e){return '<div class="aud-row"><span class="aud-when">'+agoTxt(e.secs)+'</span><span class="aud-src '+(e.source||'')+'">'+esc2(e.source||'')+'</span><span class="aud-act">'+esc2(e.action||'')+'</span><span class="aud-dev">'+esc2(e.device||'')+'</span><span class="aud-actor">'+esc2(e.actor||'—')+'</span><span class="aud-detail" title="'+attrEsc(e.detail||'')+'">'+esc2(e.detail||'')+'</span></div>';}).join('');}).catch(function(){});}
function select(base){if(!DEV[base])return;SEL=base;highlight();renderDetail(DEV[base]);}
function highlight(){var lis=document.querySelectorAll('.dev-li');for(var i=0;i<lis.length;i++){lis[i].classList.toggle('sel',lis[i].getAttribute('data-base')===SEL);}}
function renderDetail(d){AUDIT_ON=false;document.getElementById('audit-view').style.display='none';document.getElementById('fleet-view').style.display='none';document.getElementById('stage-empty').style.display='none';document.getElementById('detail').style.display='block';refreshHead(d);document.getElementById('d-controls').innerHTML=buildControls(d);resetTerm();stopView();var o=document.getElementById('out');o.style.display='none';o.textContent='';}
function refreshHead(d){var relay=d.scheme==='relay';document.getElementById('d-dot').className='dot '+statusOf(d);document.getElementById('d-name').textContent=d.name||d.hostname||d.ip;document.getElementById('d-sub').textContent=(relay?('relay · '+d.ip):(((d.hostname&&d.hostname!==d.name)?(d.hostname+'  ·  '):'')+d.ip+':'+d.port))+'  ·  '+seenTxt(d.last_seen_secs);var op=document.getElementById('d-open');if(relay){op.style.display='none';}else{op.style.display='';op.href=SEL+'/';}document.getElementById('d-specs').innerHTML=specHtml(d);document.getElementById('d-activity').innerHTML=activityHtml(d);}
function loadCls(p){return p<60?'':(p<85?'warn':'hot');}
function meter(label,val,pct,cls){pct=Math.max(0,Math.min(100,pct));return '<div class="meter"><div class="meter-top"><span>'+label+'</span><span>'+val+'</span></div><div class="meter-bar"><div class="meter-fill '+cls+'" style="width:'+pct+'%"></div></div></div>';}
function metersHtml(d){var m='';if(d.cpu_pct!=null){m+=meter('CPU load',d.cpu_pct.toFixed(0)+'%',d.cpu_pct,loadCls(d.cpu_pct));}if(d.free_gb!=null&&d.mem_gb){var used=d.mem_gb-d.free_gb;var up=used/d.mem_gb*100;m+=meter('RAM',d.free_gb.toFixed(1)+' GB free of '+d.mem_gb,up,loadCls(up));}return m?('<div class="meters">'+m+'</div>'):'';}
function specHtml(d){function sp(l,v){return (v!=null&&v!=='')?('<span class="spec"><span class="sl">'+l+'</span><span class="sv">'+esc2(v)+'</span></span>'):'';}var ifs='';(d.interfaces||[]).forEach(function(i){if(!i.addr||i.addr.indexOf('fe80')===0||i.addr==='::1'||i.addr.indexOf('127.')===0)return;ifs+='<span class="chip"><b>'+esc2(i.name)+'</b> '+esc2(i.addr)+'</span>';});var mics='';(d.microphones||[]).forEach(function(m){mics+='<span class="chip mic">🎙 '+esc2(m)+'</span>';});var chips=(ifs||mics)?('<div class="chiprow">'+ifs+mics+'</div>'):'';return sp('OS',(d.os||'')+(d.arch?(' ('+d.arch+')'):''))+sp('User',d.user)+sp('CPU',d.cpu)+sp('Cores',d.cores)+sp('Memory',d.mem_gb?(d.mem_gb+' GB total'):'')+metersHtml(d)+chips;}
function camSelect(d){var o='';d.cameras.forEach(function(c,i){o+='<option value="'+i+'">'+esc2(c)+'</option>';});return '<select class="campick" id="campick" title="select camera">'+o+'</select>';}
function buildControls(d){var cam=d.cameras&&d.cameras.length;var h='';h+='<button class="b" onclick="doLive()" title="live screen video">● Live screen</button>';h+='<button class="b" onclick="doShot()" title="screenshot">Screenshot</button>';if(cam){h+=camSelect(d);h+='<button class="b" onclick="doCamSnap()" title="camera snapshot">Camera shot</button>';h+='<button class="b" onclick="doCamLive()" title="live camera video">● Cam live</button>';}else{h+='<span class="chip off">no camera</span>';}h+='<button class="b" onclick="doRun()" title="run one command">Run…</button>';h+='<button class="b" onclick="doShell()" title="open an interactive shell">Shell</button>';h+='<button class="b" onclick="doSys()" title="system report">System…</button>';h+='<button class="b" onclick="doPower()" title="power action">Power…</button>';h+='<button class="b" onclick="doMsg()" title="message the logged-in user">Message…</button>';h+='<button class="b" onclick="doInstall()" title="install a package">Install…</button>';h+='<button class="b" onclick="doPosture()" title="security compliance check">Compliance</button>';h+='<button class="b" onclick="doGet()" title="download a file">Get file</button>';h+='<button class="b" onclick="doPut()" title="upload a file">Put file</button>';h+='<button class="b subtle" onclick="doUpd()" title="update agent">Update</button>';h+='<button class="b danger" onclick="doDis()" title="dissolve agent">Dissolve</button>';return h;}
function camI(){var s=document.getElementById('campick');return (s&&s.value)?s.value:'0';}
function setView(url){var v=document.getElementById('view');v.src=url;v.style.display='block';document.getElementById('vp-hint').style.display='none';document.getElementById('vp-tools').style.display='flex';}
function stopView(){var v=document.getElementById('view');v.removeAttribute('src');v.style.display='none';document.getElementById('vp-hint').style.display='block';document.getElementById('vp-tools').style.display='none';}
function openTab(){var v=document.getElementById('view');var s=v.getAttribute('src');if(s)window.open(s,'_blank');}
function doLive(){setView('/x/stream?target='+enc(SEL));}
function doCamLive(){setView('/x/camstream?target='+enc(SEL)+'&index='+camI());}
function doShot(){setView('/x/frame?target='+enc(SEL)+'&_t='+Date.now());}
function doCamSnap(){setView('/x/camera?target='+enc(SEL)+'&index='+camI()+'&_t='+Date.now());}
function out(t){var o=document.getElementById('out');o.style.display='block';o.textContent=t;}
function doRun(){var c=prompt('Command to run:');if(!c)return;out('$ '+c+'\n…');fetch('/x/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:SEL,cmd:c})}).then(function(r){return r.json();}).then(function(j){out('$ '+c+'\n'+(j.ok?(((j.stdout||'')+(j.stderr||''))||('exit '+j.code)):('[error] '+(j.error||'failed'))));}).catch(function(e){out('error: '+e);});}
var SHSID=null,SHOFF=0,TERM=null,FIT=null;
function ensureTerm(){if(TERM)return;TERM=new Terminal({fontSize:12,fontFamily:'ui-monospace,SFMono-Regular,Menlo,monospace',cursorBlink:true,theme:{background:'#0b0d13',foreground:'#d3d8e4'}});FIT=new FitAddon.FitAddon();TERM.loadAddon(FIT);TERM.open(document.getElementById('xterm'));TERM.onData(function(d){if(SHSID)fetch('/x/shell/input?target='+enc(SEL)+'&sid='+enc(SHSID),{method:'POST',body:d});});}
function resetTerm(){SHSID=null;document.getElementById('terminal').style.display='none';document.getElementById('viewport').style.display='flex';if(TERM)TERM.reset();}
function fitShell(){if(!(TERM&&FIT&&SHSID))return;try{FIT.fit();}catch(e){}fetch('/x/shell/resize?target='+enc(SEL)+'&sid='+enc(SHSID)+'&cols='+TERM.cols+'&rows='+TERM.rows,{method:'POST'});}
function doShell(){var base=SEL;fetch('/x/shell/open?target='+enc(base),{method:'POST'}).then(function(r){return r.json();}).then(function(j){if(!j.ok){alert('shell failed: '+(j.error||'unreachable'));return;}SHSID=j.sid;SHOFF=0;document.getElementById('viewport').style.display='none';document.getElementById('terminal').style.display='flex';ensureTerm();TERM.reset();setTimeout(fitShell,0);TERM.focus();pumpShell(base,j.sid);}).catch(function(e){alert('error: '+e);});}
function pumpShell(base,sid){if(SHSID!==sid)return;fetch('/x/shell/read?target='+enc(base)+'&sid='+enc(sid)+'&from='+SHOFF).then(function(r){return r.arrayBuffer();}).then(function(ab){if(SHSID!==sid)return;var b=new Uint8Array(ab);if(b.length){SHOFF+=b.length;TERM.write(b);}pumpShell(base,sid);}).catch(function(){if(SHSID===sid)setTimeout(function(){pumpShell(base,sid);},1000);});}
function closeShell(){if(SHSID)fetch('/x/shell/close?target='+enc(SEL)+'&sid='+enc(SHSID),{method:'POST'}).catch(function(){});resetTerm();}
function doGet(){openFb(SEL,'get');}
function doPut(){openFb(SEL,'put');}
function doUpd(){if(!confirm('Update the agent on this device to the latest build?'))return;out('updating…');fetch('/x/update?target='+enc(SEL)).then(function(r){return r.text();}).then(out).catch(function(e){out('error: '+e);});}
function doDis(){if(!confirm('Dissolve the agent on this device? It will stop and remove its autostart.'))return;out('dissolving…');fetch('/x/dissolve?target='+enc(SEL)).then(function(r){return r.text();}).then(out).catch(function(e){out('error: '+e);});}
/* ---- file browser ---- */
var fbBase=null,fbMode=null,fbPath='',fbParent='';
function openFb(b,mode){fbBase=b;fbMode=mode;document.getElementById('fb').style.display='flex';fbLoad('');}
function closeFb(){document.getElementById('fb').style.display='none';}
function fbLoad(path){fetch('/x/list?target='+enc(fbBase)+'&path='+enc(path)).then(function(r){return r.json();}).then(function(d){if(!d.ok){alert('cannot list: '+(d.error||''));return;}fbPath=d.path;fbParent=d.parent||d.path;document.getElementById('fbpath').textContent=d.path;var h='';d.entries.forEach(function(e){var full=d.path+'/'+e.name;var cls=e.dir?'fbrow fbdir':(fbMode==='get'?'fbrow':'fbrow dim');var meta=e.dir?'':(' <span class="dim">'+fmtSize(e.size)+'</span>');h+='<div class="'+cls+'" data-path="'+attrEsc(full)+'" data-dir="'+(e.dir?'1':'0')+'">'+esc2(e.name)+(e.dir?'/':'')+meta+'</div>';});document.getElementById('fbbody').innerHTML=h||'<div class="dim" style="padding:8px">(empty)</div>';document.getElementById('fbupload').style.display=(fbMode==='put')?'inline-block':'none';});}
function fbGet(full){window.open('/x/download?target='+enc(fbBase)+'&path='+enc(full),'_blank');closeFb();}
function fbUploadHere(){var i=document.createElement('input');i.type='file';i.onchange=function(){var f=i.files[0];if(!f)return;var fd=new FormData();fd.append('file',f);fd.append('dir',fbPath);fetch('/x/upload?target='+enc(fbBase),{method:'POST',body:fd}).then(function(r){return r.json();}).then(function(j){alert(j.ok?('uploaded → '+j.saved):('[error] '+(j.error||'failed')));closeFb();});};i.click();}
/* ---- init + live poll (no full reload, so streams keep playing) ---- */
document.getElementById('devlist').addEventListener('click',function(e){var li=e.target.closest('.dev-li');if(li)select(li.getAttribute('data-base'));});
window.addEventListener('resize',function(){fitShell();});
document.getElementById('fleet-cmd').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();runFleet();}});
(function(){var fbb=document.getElementById('fbbody');if(fbb){fbb.onclick=function(e){var row=e.target.closest('.fbrow');if(!row)return;var p=row.getAttribute('data-path');if(!p)return;if(row.getAttribute('data-dir')==='1'){fbLoad(p);}else if(fbMode==='get'){fbGet(p);}};}fetchAgents();setInterval(function(){fetchAgents();if(AUDIT_ON)loadAudit();},5000);})();
</script>"#;

fn cmd_block(label: &str, cmd: &str) -> String {
    let esc = cmd.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
    format!("<div style=\"font-size:12px;color:#888\">{label}</div>\n<div style=\"position:relative\"><pre style=\"background:#1a1a1a;color:#e8e8e8;padding:11px 46px 11px 11px;border-radius:6px;overflow:auto;font-size:13px;margin:6px 0 14px\">{esc}</pre><button class=\"cp\" onclick=\"cp(this)\" title=\"copy\"><svg width=\"15\" height=\"15\" viewBox=\"0 0 16 16\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.4\"><rect x=\"5\" y=\"5\" width=\"9\" height=\"9\" rx=\"1.5\"/><path d=\"M11 5V3.5A1.5 1.5 0 0 0 9.5 2h-6A1.5 1.5 0 0 0 2 3.5v6A1.5 1.5 0 0 0 3.5 11H5\"/></svg></button></div>")
}

fn advertise(mac_id: &str, port: u16, ip: &str) -> Option<ServiceDaemon> {
    let mdns = ServiceDaemon::new().ok()?;
    let host = format!("{mac_id}-hub.local.");
    let props: [(&str, &str); 1] = [("path", "/")];
    let info = ServiceInfo::new(HUB_SERVICE, mac_id, &host, ip, port, &props[..]).ok()?;
    mdns.register(info).ok()?;
    Some(mdns)
}

fn mac_id() -> String {
    if let Ok(v) = std::env::var("MAC_ID") {
        return sanitize(&v);
    }
    if let Ok(o) = std::process::Command::new("scutil").args(["--get", "LocalHostName"]).output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() {
            return sanitize(&s);
        }
    }
    if let Ok(o) = std::process::Command::new("hostname").output() {
        let s = String::from_utf8_lossy(&o.stdout);
        let s = s.trim().split('.').next().unwrap_or("mac");
        if !s.is_empty() {
            return sanitize(s);
        }
    }
    "mac".to_string()
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '-' })
        .collect()
}

fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            Some(s.local_addr().ok()?.ip().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

fn hdr(k: &str, v: &str) -> Header {
    Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

fn json_resp(v: &serde_json::Value) -> Resp {
    Response::from_string(v.to_string()).with_header(hdr("Content-Type", "application/json"))
}
