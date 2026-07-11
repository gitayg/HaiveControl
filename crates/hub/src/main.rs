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

const VERSION: &str = "2.11.0";
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
    start_scheduler(agents.clone(), ip.clone(), port);

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
        if !matches!(path.as_str(), "/m/agents" | "/m/exec" | "/m/input" | "/m/sys" | "/m/script" | "/m/script-fleet") {
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
            // The device dials out, so the socket (or X-Forwarded-For behind the
            // AppCrane proxy) carries its real public IP — capture it for geo.
            let pip = req_header(&req, "X-Forwarded-For")
                .and_then(|h| h.split(',').next().map(|s| s.trim().to_string()))
                .or_else(|| req.remote_addr().map(|a| a.ip().to_string()));
            let mut body = String::new();
            let _ = req.as_reader().read_to_string(&mut body);
            let mut data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            if let (Some(ip), Some(o)) = (pip, data.as_object_mut()) {
                o.insert("public_ip".into(), serde_json::json!(ip));
            }
            relay::hello(agents, data);
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
        (Method::Post, "/x/shell/open") => proxy_shell_open(&url, agents),
        (Method::Get, "/x/recordings") => recordings_list(),
        (Method::Get, "/x/recording") => recording_get(&url),
        (Method::Get, "/x/recording-delete") => recording_delete(&url),
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
        (Method::Get, "/scripts") => scripts_list(&url),
        (Method::Get, "/m/scripts") => scripts_list(&url),
        (Method::Get, "/x/script") => proxy_script(&url, agents, user.as_deref(), false),
        (Method::Get, "/m/script") => proxy_script(&url, agents, mowner.as_deref(), true),
        (Method::Get, "/x/script-fleet") => proxy_script_fleet(&url, agents, user.as_deref(), false),
        (Method::Get, "/m/script-fleet") => proxy_script_fleet(&url, agents, mowner.as_deref(), true),
        (Method::Get, "/x/compliance-fleet") => proxy_compliance_fleet(&url, agents, user.as_deref(), false),
        (Method::Get, "/m/compliance-fleet") => proxy_compliance_fleet(&url, agents, mowner.as_deref(), true),
        (Method::Post, "/x/script-add") => script_add(&mut req, user.as_deref()),
        (Method::Get, "/x/script-delete") => script_delete(&url, user.as_deref()),
        (Method::Get, "/plugins") => plugins_list(),
        (Method::Get, "/m/plugins") => plugins_list(),
        (Method::Get, "/actions") => actions_catalog(),
        (Method::Get, "/m/actions") => actions_catalog(),
        (Method::Get, "/x/geo") => geo_devices(agents, user.as_deref()),
        (Method::Get, "/m/geo") => geo_devices(agents, mowner.as_deref()),
        (Method::Get, "/x/cve") => cve_lookup(&url),
        (Method::Get, "/m/cve") => cve_lookup(&url),
        (Method::Get, "/x/settings") => settings_get(),
        (Method::Post, "/x/settings") => settings_set(&mut req, user.as_deref()),
        (Method::Post, "/x/plugin-add") => plugin_add(&mut req, user.as_deref()),
        (Method::Get, "/x/plugin-delete") => plugin_delete(&url, user.as_deref()),
        (Method::Post, "/x/schedule-add") => schedule_add(&mut req, agents, user.as_deref()),
        (Method::Get, "/x/schedules") => schedules_list(user.as_deref()),
        (Method::Get, "/x/schedule-delete") => schedule_delete(&url, user.as_deref()),
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
    dq.truncate(50);
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
        Ok(bytes) => {
            let ct = if name.ends_with(".js") {
                "text/javascript; charset=utf-8"
            } else if name.ends_with(".css") {
                "text/css; charset=utf-8"
            } else if name.ends_with(".svg") {
                "image/svg+xml"
            } else {
                "application/octet-stream"
            };
            Response::from_data(bytes).with_header(hdr("Content-Type", ct))
        }
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
    let asset = match agent_asset(&platform) {
        Some(a) => a,
        None => return Response::from_string("unknown platform for device").with_status_code(400),
    };
    let payload = serde_json::json!({ "url": bin_url(asset, hub_ip, hub_port) }).to_string().into_bytes();
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

/// Indicative control mapping for a security check across common frameworks.
/// These are representative references to orient an operator — not an audited
/// crosswalk. Surface them as guidance, not certified compliance evidence.
fn compliance_controls(kind: &str) -> serde_json::Value {
    match kind {
        "encryption" => serde_json::json!({"CIS":"3.11","NIST 800-53":"SC-28","PCI-DSS":"3.5","HIPAA":"164.312(a)(2)(iv)","ISO 27001":"A.8.24","Essential Eight":"—"}),
        "firewall" => serde_json::json!({"CIS":"9.2","NIST 800-53":"SC-7","PCI-DSS":"1.4","HIPAA":"164.312(c)(1)","ISO 27001":"A.8.20","Essential Eight":"—"}),
        "av" => serde_json::json!({"CIS":"10.1","NIST 800-53":"SI-3","PCI-DSS":"5.2","HIPAA":"164.308(a)(5)(ii)(B)","ISO 27001":"A.8.7","Essential Eight":"—"}),
        "updates" => serde_json::json!({"CIS":"7.3","NIST 800-53":"SI-2","PCI-DSS":"6.3","HIPAA":"164.308(a)(1)(ii)(A)","ISO 27001":"A.8.8","Essential Eight":"Patch operating systems"}),
        _ => serde_json::json!({}),
    }
}

/// The frameworks compliance_controls maps to, in display order.
const COMPLIANCE_FRAMEWORKS: [&str; 6] = ["CIS", "NIST 800-53", "PCI-DSS", "HIPAA", "ISO 27001", "Essential Eight"];

/// Run the security-posture checks on one device → {score, grade, checks[]},
/// each check carrying its pass/fail, output snippet, and control mapping.
fn run_posture(target: &str, platform: &str) -> serde_json::Value {
    let checks = [("disk encryption", "encryption"), ("firewall", "firewall"), ("antivirus", "av"), ("OS updates", "updates")];
    let mut items = Vec::new();
    let mut pass_n = 0;
    for (label, k) in checks {
        let out = os_command(platform, k, "").map(|c| exec_output(target, &c)).unwrap_or_else(|| "n/a".into());
        let pass = posture_pass(k, &out);
        if pass {
            pass_n += 1;
        }
        items.push(serde_json::json!({"check": label, "kind": k, "pass": pass, "controls": compliance_controls(k), "output": out.chars().take(240).collect::<String>()}));
    }
    let score = (pass_n as f64 / checks.len() as f64 * 100.0).round() as i64;
    serde_json::json!({"score": score, "grade": grade(score), "checks": items})
}

/// GET /x|m/compliance-fleet — run the posture checks on every owned device,
/// in parallel, and return a per-device compliance matrix + the control legend.
fn proxy_compliance_fleet(url: &str, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let _ = url;
    let targets = owned_targets(agents, user);
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, "compliance (fleet)", &format!("all ({})", targets.len()), "");
    let out = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let mut handles = Vec::new();
    for (name, target, platform) in targets {
        let out = out.clone();
        handles.push(std::thread::spawn(move || {
            let mut r = run_posture(&target, &platform);
            if let Some(o) = r.as_object_mut() {
                o.insert("device".into(), serde_json::json!(name));
            }
            out.lock().unwrap().push(r);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut results = std::sync::Arc::try_unwrap(out).unwrap().into_inner().unwrap();
    results.sort_by(|a, b| a["device"].as_str().unwrap_or("").cmp(b["device"].as_str().unwrap_or("")));
    let legend: serde_json::Value = ["encryption", "firewall", "av", "updates"].iter().map(|k| (k.to_string(), compliance_controls(k))).collect::<serde_json::Map<_, _>>().into();
    json_resp(&serde_json::json!({"ok": true, "count": results.len(), "frameworks": COMPLIANCE_FRAMEWORKS, "legend": legend, "results": results}))
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
        let mut r = run_posture(&target, &platform);
        if let Some(o) = r.as_object_mut() {
            o.insert("ok".into(), serde_json::json!(true));
            o.insert("device".into(), serde_json::json!(dev));
        }
        return json_resp(&r);
    }
    let cmd = match os_command(&platform, &kind, &arg).or_else(|| plugin_command(&platform, &kind, &arg)) {
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
            let command = if kind == "exec" { cmd } else { os_command(&platform, &kind, &arg).or_else(|| plugin_command(&platform, &kind, &arg)).unwrap_or_default() };
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

// ── TacticalRMM community-scripts browser ────────────────────────────────────
// Search the amidaware/community-scripts library and run a chosen script on one
// device or the whole fleet. The script body is fetched from GitHub and
// base64-wrapped into a single `/exec` call (no temp files on the device).
// Mind the agent's ~65s `/exec` cap: long-running scripts get truncated —
// fire-and-forget + log-poll is a future enhancement.
const SCRIPTS_MANIFEST_URL: &str = "https://raw.githubusercontent.com/amidaware/community-scripts/main/community_scripts.json";
const SCRIPTS_RAW_BASE: &str = "https://raw.githubusercontent.com/amidaware/community-scripts/main/scripts/";

fn scripts_cache() -> &'static Mutex<Option<Vec<serde_json::Value>>> {
    static C: std::sync::OnceLock<Mutex<Option<Vec<serde_json::Value>>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(None))
}

/// Fetch + cache the community-scripts manifest (once per process, unless forced).
fn scripts_manifest(force: bool) -> Vec<serde_json::Value> {
    if !force {
        if let Some(v) = scripts_cache().lock().unwrap().as_ref() {
            return v.clone();
        }
    }
    let list: Vec<serde_json::Value> = http()
        .get(SCRIPTS_MANIFEST_URL)
        .send()
        .ok()
        .and_then(|r| r.json::<serde_json::Value>().ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    if !list.is_empty() {
        *scripts_cache().lock().unwrap() = Some(list.clone());
    }
    list
}

/// The OSes a script applies to — explicit `supported_platforms`, else inferred.
fn script_platforms(s: &serde_json::Value) -> Vec<String> {
    if let Some(a) = s.get("supported_platforms").and_then(|x| x.as_array()) {
        let v: Vec<String> = a.iter().filter_map(|x| x.as_str()).map(|x| x.to_lowercase()).collect();
        if !v.is_empty() {
            return v;
        }
    }
    let shell = s.get("shell").and_then(|x| x.as_str()).unwrap_or("");
    let fname = s.get("filename").and_then(|x| x.as_str()).unwrap_or("");
    match shell {
        "powershell" | "cmd" => vec!["windows".into()],
        _ if fname.starts_with("Mac") => vec!["macos".into()],
        _ if fname.starts_with("Linux") => vec!["linux".into()],
        _ => vec!["linux".into(), "macos".into()],
    }
}

/// GET /scripts?q=&platform=&refresh=1 — the searchable manifest (trimmed rows).
fn scripts_list(url: &str) -> Resp {
    let q = query_param(url, "q").unwrap_or_default().to_lowercase();
    let plat = query_param(url, "platform").unwrap_or_default().to_lowercase();
    let force = query_param(url, "refresh").as_deref() == Some("1");
    let all = all_scripts(force);
    let rows: Vec<serde_json::Value> = all
        .iter()
        .filter(|s| {
            let name = s.get("name").and_then(|x| x.as_str()).unwrap_or("");
            let desc = s.get("description").and_then(|x| x.as_str()).unwrap_or("");
            let cat = s.get("category").and_then(|x| x.as_str()).unwrap_or("");
            let hay = format!("{name} {desc} {cat}").to_lowercase();
            (q.is_empty() || hay.contains(&q))
                && (plat.is_empty() || script_platforms(s).iter().any(|p| p.contains(&plat) || plat.contains(p.as_str())))
        })
        .map(|s| {
            serde_json::json!({
                "filename": s.get("filename").and_then(|x| x.as_str()).unwrap_or(""),
                "name": s.get("name").and_then(|x| x.as_str()).unwrap_or(""),
                "description": s.get("description").and_then(|x| x.as_str()).unwrap_or(""),
                "shell": s.get("shell").and_then(|x| x.as_str()).unwrap_or(""),
                "category": s.get("category").and_then(|x| x.as_str()).unwrap_or(""),
                "platforms": script_platforms(s),
                "custom": s.get("custom").and_then(|x| x.as_bool()).unwrap_or(false),
            })
        })
        .collect();
    json_resp(&serde_json::json!({"ok": true, "count": rows.len(), "total": all.len(), "scripts": rows}))
}

fn find_script(all: &[serde_json::Value], id: &str) -> Option<serde_json::Value> {
    all.iter()
        .find(|s| s.get("filename").and_then(|x| x.as_str()) == Some(id) || s.get("guid").and_then(|x| x.as_str()) == Some(id))
        .cloned()
}

/// Wrap a script body into a single shell command for the agent's `/exec`.
fn wrap_script(shell: &str, body: &str) -> Option<String> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(body.as_bytes());
    match shell {
        "powershell" => {
            // PowerShell -EncodedCommand wants UTF-16LE base64.
            let utf16: Vec<u8> = body.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let enc = base64::engine::general_purpose::STANDARD.encode(&utf16);
            Some(format!("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc}"))
        }
        "cmd" | "batch" => {
            // No clean stdin path for a .bat — have PowerShell materialize + run a
            // temp file. The whole PS is EncodedCommand'd, so nothing needs escaping.
            let ps = format!(
                "$p=Join-Path $env:TEMP ('hs_'+$PID+'.bat');[IO.File]::WriteAllBytes($p,[Convert]::FromBase64String('{b64}'));& cmd /c $p;Remove-Item $p -Force -ErrorAction SilentlyContinue"
            );
            let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            let enc = base64::engine::general_purpose::STANDARD.encode(&utf16);
            Some(format!("powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand {enc}"))
        }
        "python" => Some(format!(
            "python3 -c \"import base64;exec(base64.b64decode('{b64}').decode())\" || python -c \"import base64;exec(base64.b64decode('{b64}').decode())\""
        )),
        "shell" | "bash" | "" => Some(format!("echo {b64} | base64 -d | sh")),
        _ => None,
    }
}

/// Fetch a named script and run it on one target; returns a JSON result object.
fn run_named_script(target: &str, platform: &str, all: &[serde_json::Value], id: &str) -> serde_json::Value {
    let meta = match find_script(all, id) {
        Some(m) => m,
        None => return serde_json::json!({"ok": false, "error": "script not found"}),
    };
    let plats = script_platforms(&meta);
    if !plats.iter().any(|p| p.contains(platform) || platform.contains(p.as_str())) {
        return serde_json::json!({"ok": false, "error": format!("script targets {plats:?}, device is {platform}")});
    }
    let shell = meta.get("shell").and_then(|x| x.as_str()).unwrap_or("shell");
    let fname = meta.get("filename").and_then(|x| x.as_str()).unwrap_or("");
    // Custom scripts carry their body inline; community scripts are fetched from GitHub.
    let body = if let Some(b) = meta.get("body").and_then(|x| x.as_str()) {
        b.to_string()
    } else {
        match http().get(format!("{SCRIPTS_RAW_BASE}{fname}")).send().ok().and_then(|r| r.text().ok()) {
            Some(b) if !b.is_empty() => b,
            _ => return serde_json::json!({"ok": false, "error": "could not fetch script body from GitHub"}),
        }
    };
    let cmd = match wrap_script(shell, &body) {
        Some(c) => c,
        None => return serde_json::json!({"ok": false, "error": format!("shell '{shell}' not supported yet")}),
    };
    serde_json::json!({"ok": true, "output": exec_output(target, &cmd)})
}

/// GET /x|m/script?target=&file= — run one community script on one device.
fn proxy_script(url: &str, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let id = query_param(url, "file").or_else(|| query_param(url, "guid")).unwrap_or_default();
    if !may_control(user, agents, &target) {
        return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}));
    }
    let platform = device_platform(agents, &target);
    let dev = device_name(agents, &target);
    record_mcp_access(&target, "run script", user.unwrap_or(""), &id);
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, "run script", &dev, &id);
    let mut r = run_named_script(&target, &platform, &all_scripts(false), &id);
    if let Some(o) = r.as_object_mut() {
        o.insert("device".into(), serde_json::json!(dev));
        o.insert("script".into(), serde_json::json!(id));
    }
    json_resp(&r)
}

/// GET /x|m/script-fleet?file= — run one community script on every owned device.
fn proxy_script_fleet(url: &str, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let id = query_param(url, "file").or_else(|| query_param(url, "guid")).unwrap_or_default();
    let targets = owned_targets(agents, user);
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, "run script (fleet)", &format!("all ({})", targets.len()), &id);
    let all = std::sync::Arc::new(all_scripts(false));
    let out = std::sync::Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
    let mut handles = Vec::new();
    for (name, target, platform) in targets {
        let (out, all, id) = (out.clone(), all.clone(), id.clone());
        handles.push(std::thread::spawn(move || {
            let r = run_named_script(&target, &platform, all.as_ref(), &id);
            let text = if r.get("ok").and_then(|x| x.as_bool()).unwrap_or(false) {
                r.get("output").and_then(|x| x.as_str()).unwrap_or("").to_string()
            } else {
                format!("({})", r.get("error").and_then(|x| x.as_str()).unwrap_or("failed"))
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

// ── Custom (user-added) scripts ──────────────────────────────────────────────
// Stored as JSON under HUB_DATA/custom-scripts/*.json so they survive redeploys
// (when HUB_DATA points at a persistent, writable volume). They're merged into
// the Script library alongside the community set, tagged `custom`. Adding/removing
// is SSO-only (never the token/MCP surface) — a custom script is arbitrary RCE.
fn data_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(std::env::var("HUB_DATA").unwrap_or_else(|_| "data".into()))
}

fn custom_scripts_dir() -> std::path::PathBuf {
    let d = data_dir().join("custom-scripts");
    let _ = std::fs::create_dir_all(&d);
    d
}

fn load_custom_scripts() -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(custom_scripts_dir()) {
        for e in rd.flatten() {
            if e.path().extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Ok(txt) = std::fs::read_to_string(e.path()) {
                if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&txt) {
                    if let Some(o) = v.as_object_mut() {
                        o.insert("custom".into(), serde_json::json!(true));
                    }
                    out.push(v);
                }
            }
        }
    }
    out.sort_by(|a, b| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")));
    out
}

/// Custom scripts first (always available, even offline), then the community set.
fn all_scripts(force: bool) -> Vec<serde_json::Value> {
    let mut v = load_custom_scripts();
    v.extend(scripts_manifest(force));
    v
}

/// POST /x/script-add — save a user-supplied script (SSO only).
fn script_add(req: &mut Request, user: Option<&str>) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let script_body = v.get("body").and_then(|x| x.as_str()).unwrap_or("");
    if name.is_empty() || script_body.trim().is_empty() {
        return json_resp(&serde_json::json!({"ok": false, "error": "name and script body are required"}));
    }
    let slug = sanitize(&name.to_lowercase());
    if slug.is_empty() {
        return json_resp(&serde_json::json!({"ok": false, "error": "name must contain letters or digits"}));
    }
    let rec = serde_json::json!({
        "filename": format!("custom:{slug}"),
        "name": name,
        "description": v.get("description").and_then(|x| x.as_str()).unwrap_or(""),
        "shell": v.get("shell").and_then(|x| x.as_str()).unwrap_or("shell"),
        "platforms": v.get("platforms").cloned().unwrap_or_else(|| serde_json::json!(["windows", "macos", "linux"])),
        "category": "Custom",
        "body": script_body,
        "added_by": user.unwrap_or(""),
    });
    let path = custom_scripts_dir().join(format!("{slug}.json"));
    if std::fs::write(&path, serde_json::to_string_pretty(&rec).unwrap_or_default()).is_err() {
        return json_resp(&serde_json::json!({"ok": false, "error": "could not save — is HUB_DATA writable?"}));
    }
    audit(user.unwrap_or(""), "browser", "add script", &name, &format!("custom:{slug}"));
    json_resp(&serde_json::json!({"ok": true, "filename": format!("custom:{slug}")}))
}

/// GET /x/script-delete?file=custom:<slug> — remove a user-added script (SSO only).
fn script_delete(url: &str, user: Option<&str>) -> Resp {
    let id = query_param(url, "file").unwrap_or_default();
    let slug = sanitize(id.strip_prefix("custom:").unwrap_or(&id)); // sanitize blocks path traversal
    if slug.is_empty() {
        return json_resp(&serde_json::json!({"ok": false, "error": "bad id"}));
    }
    let _ = std::fs::remove_file(custom_scripts_dir().join(format!("{slug}.json")));
    audit(user.unwrap_or(""), "browser", "delete script", &id, "");
    json_resp(&serde_json::json!({"ok": true}))
}

// ── Command plugins ──────────────────────────────────────────────────────────
// JSON manifests under HUB_DATA/plugins/*.json add new named actions with no
// rebuild: {id, name, description, group, arg?, cmd:{windows,macos,linux}}.
// They EXTEND os_command (checked as a fallback) — the dashboard action runner
// and MCP enumerate them via /plugins, so a dropped-in file becomes a first-class
// action everywhere. {{arg}} in a command template is substituted (shell-escaped).
fn plugins_dir() -> std::path::PathBuf {
    let d = data_dir().join("plugins");
    let _ = std::fs::create_dir_all(&d);
    d
}
fn load_plugins() -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(plugins_dir()) {
        for e in rd.flatten() {
            if e.path().extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            if let Some(v) = std::fs::read_to_string(e.path()).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()) {
                if v.get("id").and_then(|x| x.as_str()).is_some() {
                    out.push(v);
                }
            }
        }
    }
    out
}
/// Render a plugin's command for the platform, or None if no plugin/os match.
fn plugin_command(platform: &str, id: &str, arg: &str) -> Option<String> {
    let p = load_plugins().into_iter().find(|p| p.get("id").and_then(|x| x.as_str()) == Some(id))?;
    let tmpl = p.get("cmd").and_then(|c| c.get(platform)).and_then(|x| x.as_str())?;
    Some(tmpl.replace("{{arg}}", &shell_arg(arg)))
}
/// GET /plugins and /m/plugins — the command-plugin catalog.
fn plugins_list() -> Resp {
    let rows: Vec<serde_json::Value> = load_plugins()
        .iter()
        .map(|p| {
            serde_json::json!({
                "id": p.get("id").and_then(|x| x.as_str()).unwrap_or(""),
                "name": p.get("name").and_then(|x| x.as_str()).or_else(|| p.get("id").and_then(|x| x.as_str())).unwrap_or(""),
                "description": p.get("description").and_then(|x| x.as_str()).unwrap_or(""),
                "group": p.get("group").and_then(|x| x.as_str()).unwrap_or("Plugins"),
                "arg": p.get("arg").and_then(|x| x.as_str()).unwrap_or(""),
                "platforms": p.get("cmd").and_then(|c| c.as_object()).map(|o| o.keys().cloned().collect::<Vec<_>>()).unwrap_or_default(),
            })
        })
        .collect();
    json_resp(&serde_json::json!({"ok": true, "count": rows.len(), "plugins": rows}))
}
/// POST /x/plugin-add — save a command-plugin from the dashboard (SSO only).
fn plugin_add(req: &mut Request, user: Option<&str>) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let name = v.get("name").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    let cmd = v.get("cmd").cloned().unwrap_or_default();
    let has_cmd = cmd.as_object().map(|o| o.values().any(|x| x.as_str().map(|s| !s.trim().is_empty()).unwrap_or(false))).unwrap_or(false);
    if name.is_empty() || !has_cmd {
        return json_resp(&serde_json::json!({"ok": false, "error": "name and at least one platform command are required"}));
    }
    let slug = sanitize(&name.to_lowercase());
    if slug.is_empty() {
        return json_resp(&serde_json::json!({"ok": false, "error": "name must contain letters or digits"}));
    }
    let rec = serde_json::json!({
        "id": slug,
        "name": name,
        "description": v.get("description").and_then(|x| x.as_str()).unwrap_or(""),
        "group": v.get("group").and_then(|x| x.as_str()).filter(|s| !s.is_empty()).unwrap_or("Plugins"),
        "arg": v.get("arg").and_then(|x| x.as_str()).unwrap_or(""),
        "cmd": cmd,
        "added_by": user.unwrap_or(""),
    });
    if std::fs::write(plugins_dir().join(format!("{slug}.json")), serde_json::to_string_pretty(&rec).unwrap_or_default()).is_err() {
        return json_resp(&serde_json::json!({"ok": false, "error": "could not save — is HUB_DATA writable?"}));
    }
    audit(user.unwrap_or(""), "browser", "add plugin", &name, &slug);
    json_resp(&serde_json::json!({"ok": true, "id": slug}))
}
/// GET /x/plugin-delete?id=
fn plugin_delete(url: &str, user: Option<&str>) -> Resp {
    let slug = sanitize(&query_param(url, "id").unwrap_or_default());
    if !slug.is_empty() {
        let _ = std::fs::remove_file(plugins_dir().join(format!("{slug}.json")));
        audit(user.unwrap_or(""), "browser", "delete plugin", &slug, "");
    }
    json_resp(&serde_json::json!({"ok": true}))
}

// ── Geolocation (device map) ─────────────────────────────────────────────────
// Resolve each device's captured public IP to an approximate lat/lon server-side
// (cached), so the dashboard can plot a device map. City-level and best-effort —
// VPN/NAT/CGNAT make it approximate; private/LAN IPs stay unlocated.
fn geo_cache() -> &'static Mutex<HashMap<String, Option<serde_json::Value>>> {
    static G: std::sync::OnceLock<Mutex<HashMap<String, Option<serde_json::Value>>>> = std::sync::OnceLock::new();
    G.get_or_init(|| Mutex::new(HashMap::new()))
}
fn is_private_ip(ip: &str) -> bool {
    ip.is_empty()
        || ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip.starts_with("127.")
        || ip.starts_with("169.254.")
        || ip == "::1"
        || ip.starts_with("fc")
        || ip.starts_with("fd")
        || (ip.starts_with("172.") && ip.split('.').nth(1).and_then(|o| o.parse::<u8>().ok()).map(|o| (16..=31).contains(&o)).unwrap_or(false))
}
fn geo_lookup(ip: &str) -> Option<serde_json::Value> {
    if is_private_ip(ip) {
        return None;
    }
    if let Some(v) = geo_cache().lock().unwrap().get(ip) {
        return v.clone();
    }
    let v: Option<serde_json::Value> = http()
        .get(format!("http://ip-api.com/json/{ip}?fields=status,lat,lon,city,country"))
        .send()
        .ok()
        .and_then(|r| r.json::<serde_json::Value>().ok())
        .filter(|v| v.get("status").and_then(|x| x.as_str()) == Some("success"))
        .map(|v| serde_json::json!({"lat": v.get("lat"), "lon": v.get("lon"), "city": v.get("city").and_then(|x| x.as_str()).unwrap_or(""), "country": v.get("country").and_then(|x| x.as_str()).unwrap_or("")}));
    geo_cache().lock().unwrap().insert(ip.to_string(), v.clone());
    v
}
/// GET /x|m/geo — owned devices with resolved lat/lon (best-effort).
fn geo_devices(agents: &Agents, user: Option<&str>) -> Resp {
    let out: Vec<serde_json::Value> = live(agents, user)
        .iter()
        .map(|d| {
            let pip = d.get("public_ip").and_then(|x| x.as_str()).unwrap_or("");
            let geo = geo_lookup(pip);
            let name = d.get("name").and_then(|x| x.as_str()).or_else(|| d.get("hostname").and_then(|x| x.as_str())).or_else(|| d.get("ip").and_then(|x| x.as_str())).unwrap_or("");
            let base = if d.get("scheme").and_then(|x| x.as_str()) == Some("relay") {
                format!("relay://{}", d.get("ip").and_then(|x| x.as_str()).unwrap_or(""))
            } else {
                format!("{}://{}:{}", d.get("scheme").and_then(|x| x.as_str()).unwrap_or("http"), d.get("ip").and_then(|x| x.as_str()).unwrap_or(""), d.get("port").and_then(|x| x.as_i64()).unwrap_or(0))
            };
            serde_json::json!({
                "name": name,
                "base": base,
                "lat": geo.as_ref().and_then(|g| g.get("lat").cloned()),
                "lon": geo.as_ref().and_then(|g| g.get("lon").cloned()),
                "city": geo.as_ref().and_then(|g| g.get("city").and_then(|x| x.as_str())).unwrap_or(""),
                "country": geo.as_ref().and_then(|g| g.get("country").and_then(|x| x.as_str())).unwrap_or(""),
            })
        })
        .collect();
    json_resp(&serde_json::json!({"ok": true, "devices": out}))
}

// ── CVE lookup (NVD) ─────────────────────────────────────────────────────────
// Manual keyword lookup against the NVD 2.0 API — "show CVEs for product X".
// A lookup, not an automated scan (Windows software→CVE mapping is unreliable).
fn cve_cache() -> &'static Mutex<HashMap<String, serde_json::Value>> {
    static C: std::sync::OnceLock<Mutex<HashMap<String, serde_json::Value>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}
fn cvss_of(c: &serde_json::Value) -> (Option<f64>, String) {
    for k in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        if let Some(m) = c["metrics"][k].as_array().and_then(|a| a.first()) {
            let score = m["cvssData"]["baseScore"].as_f64();
            if score.is_some() {
                let sev = m["cvssData"]["baseSeverity"].as_str().or_else(|| m["baseSeverity"].as_str()).unwrap_or("").to_string();
                return (score, sev);
            }
        }
    }
    (None, String::new())
}
/// GET /x|m/cve?q=<keyword> — CVEs matching a product/keyword (NVD, cached).
fn cve_lookup(url: &str) -> Resp {
    let q = query_param(url, "q").unwrap_or_default().trim().to_string();
    if q.is_empty() {
        return json_resp(&serde_json::json!({"ok": true, "count": 0, "cves": []}));
    }
    if let Some(v) = cve_cache().lock().unwrap().get(&q) {
        return json_resp(v);
    }
    let api = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=20", urlencode(&q));
    let resp = http().get(&api).header("User-Agent", "HaiveControl").send().ok().and_then(|r| r.json::<serde_json::Value>().ok());
    let cves: Vec<serde_json::Value> = resp
        .as_ref()
        .and_then(|v| v["vulnerabilities"].as_array())
        .map(|arr| {
            let mut list: Vec<serde_json::Value> = arr
                .iter()
                .map(|w| {
                    let c = &w["cve"];
                    let desc = c["descriptions"].as_array().and_then(|d| d.iter().find(|x| x["lang"].as_str() == Some("en"))).and_then(|x| x["value"].as_str()).unwrap_or("");
                    let (score, sev) = cvss_of(c);
                    serde_json::json!({
                        "id": c["id"].as_str().unwrap_or(""),
                        "published": c["published"].as_str().unwrap_or("").chars().take(10).collect::<String>(),
                        "score": score,
                        "severity": sev,
                        "summary": desc.chars().take(320).collect::<String>(),
                    })
                })
                .collect();
            // Highest CVSS first.
            list.sort_by(|a, b| b["score"].as_f64().unwrap_or(-1.0).partial_cmp(&a["score"].as_f64().unwrap_or(-1.0)).unwrap_or(std::cmp::Ordering::Equal));
            list
        })
        .unwrap_or_default();
    let out = serde_json::json!({"ok": true, "count": cves.len(), "cves": cves});
    cve_cache().lock().unwrap().insert(q, out.clone());
    json_resp(&out)
}

// ── Hub settings + agent auto-update ─────────────────────────────────────────
// Admin-configurable settings persisted to HUB_DATA/settings.json. The
// `agent_update` mode ("manual" default | "auto") controls whether the hub
// pushes agent updates to out-of-date devices on its own.
fn settings_path() -> std::path::PathBuf {
    data_dir().join("settings.json")
}
fn load_settings() -> serde_json::Value {
    std::fs::read_to_string(settings_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_else(|| serde_json::json!({}))
}
fn setting_str(key: &str, default: &str) -> String {
    load_settings().get(key).and_then(|x| x.as_str()).unwrap_or(default).to_string()
}
fn save_setting(key: &str, val: &str) {
    let mut s = load_settings();
    s[key] = serde_json::json!(val);
    let _ = std::fs::create_dir_all(data_dir());
    let _ = std::fs::write(settings_path(), serde_json::to_string_pretty(&s).unwrap_or_default());
}
fn settings_get() -> Resp {
    json_resp(&serde_json::json!({"ok": true, "agent_update": setting_str("agent_update", "manual"), "server_version": VERSION}))
}
/// POST /x/settings — update an admin setting (SSO).
fn settings_set(req: &mut Request, user: Option<&str>) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    if let Some(m) = v.get("agent_update").and_then(|x| x.as_str()) {
        if m == "auto" || m == "manual" {
            save_setting("agent_update", m);
            audit(user.unwrap_or(""), "browser", "setting", "agent_update", m);
        }
    }
    settings_get()
}

fn agent_asset(platform: &str) -> Option<&'static str> {
    match platform {
        "windows" => Some("HaiveControl-windows.exe"),
        "macos" => Some("HaiveControl-macos"),
        "linux" => Some("HaiveControl-linux"),
        _ => None,
    }
}
/// Public URL for a served binary — HUB_PUBLIC_URL when set (so relay devices can
/// reach it), else the local address.
fn bin_url(asset: &str, hub_ip: &str, hub_port: u16) -> String {
    match std::env::var("HUB_PUBLIC_URL").ok().filter(|s| !s.is_empty()) {
        Some(base) => format!("{}/bin/{asset}", base.trim_end_matches('/')),
        None => format!("http://{hub_ip}:{hub_port}/bin/{asset}"),
    }
}
/// Tell a device to self-update to the hub-served build for its platform.
fn trigger_update(target: &str, platform: &str, hub_ip: &str, hub_port: u16) -> bool {
    let Some(asset) = agent_asset(platform) else { return false };
    let payload = serde_json::json!({ "url": bin_url(asset, hub_ip, hub_port) }).to_string().into_bytes();
    dev_unary(target, "POST", "/update", Some(("application/json".into(), payload))).is_some()
}
fn update_cooldown() -> &'static Mutex<HashMap<String, Instant>> {
    static C: std::sync::OnceLock<Mutex<HashMap<String, Instant>>> = std::sync::OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}
/// When agent_update=auto, push updates to devices whose reported agent version
/// is behind the hub's served build (5-min per-device cooldown).
fn auto_update_pass(agents: &Agents, hub_ip: &str, hub_port: u16) {
    if setting_str("agent_update", "manual") != "auto" {
        return;
    }
    let stale: Vec<(String, String)> = {
        let guard = agents.lock().unwrap();
        guard
            .values()
            .filter_map(|a| {
                let d = &a.data;
                let ver = d.get("agent_version").and_then(|x| x.as_str())?;
                if ver == VERSION {
                    return None;
                }
                let platform = d.get("platform").and_then(|x| x.as_str())?.to_string();
                let ip = d.get("ip").and_then(|x| x.as_str()).unwrap_or("");
                let target = if d.get("scheme").and_then(|x| x.as_str()) == Some("relay") {
                    format!("relay://{ip}")
                } else {
                    format!("{}://{ip}:{}", d.get("scheme").and_then(|x| x.as_str()).unwrap_or("http"), d.get("port").and_then(|x| x.as_i64()).unwrap_or(0))
                };
                Some((target, platform))
            })
            .collect()
    };
    let now = Instant::now();
    for (target, platform) in stale {
        {
            let mut cd = update_cooldown().lock().unwrap();
            if cd.get(&target).map(|t| now.duration_since(*t) < std::time::Duration::from_secs(300)).unwrap_or(false) {
                continue;
            }
            cd.insert(target.clone(), now);
        }
        if trigger_update(&target, &platform, hub_ip, hub_port) {
            audit("", "auto", "auto-update", &target, VERSION);
        }
    }
}

/// GET /actions and /m/actions — machine-readable catalog of runnable actions
/// (built-in canned actions + plugins) so a non-MCP agent can discover what it
/// can do and how to invoke it.
fn actions_catalog() -> Resp {
    let builtin = serde_json::json!([
        {"kind":"hardware","name":"Hardware inventory","group":"report"},
        {"kind":"packages","name":"Installed software","group":"report"},
        {"kind":"services","name":"Running services","group":"report"},
        {"kind":"processes","name":"Top processes","group":"report"},
        {"kind":"network","name":"Network neighbors (ARP)","group":"report"},
        {"kind":"updates","name":"Available updates","group":"report"},
        {"kind":"power_report","name":"Power / battery report","group":"report"},
        {"kind":"encryption","name":"Disk-encryption status","group":"security"},
        {"kind":"firewall","name":"Firewall status","group":"security"},
        {"kind":"av","name":"Antivirus status","group":"security"},
        {"kind":"posture","name":"Compliance posture (scored A–F)","group":"security","composite":true},
        {"kind":"firewall_on","name":"Firewall — enable","group":"security","danger":true},
        {"kind":"firewall_off","name":"Firewall — disable","group":"security","danger":true},
        {"kind":"usb_lock","name":"Lock USB storage (Windows)","group":"security","danger":true},
        {"kind":"usb_unlock","name":"Unlock USB storage (Windows)","group":"security"},
        {"kind":"install","name":"Install a package","group":"software","arg":"package id"},
        {"kind":"uninstall","name":"Uninstall a package","group":"software","arg":"package id"},
        {"kind":"update_all","name":"Install all updates","group":"software","danger":true},
        {"kind":"reboot","name":"Restart","group":"power","danger":true},
        {"kind":"shutdown","name":"Shut down","group":"power","danger":true},
        {"kind":"sleep","name":"Sleep","group":"power"},
        {"kind":"logoff","name":"Log off","group":"power","danger":true},
        {"kind":"message","name":"Message the logged-in user","group":"notify","arg":"message text"},
    ]);
    let plugins: Vec<serde_json::Value> = load_plugins()
        .iter()
        .map(|p| serde_json::json!({"kind": p.get("id").and_then(|x| x.as_str()).unwrap_or(""), "name": p.get("name").and_then(|x| x.as_str()).unwrap_or(""), "group": "plugin", "arg": p.get("arg").and_then(|x| x.as_str()).unwrap_or("")}))
        .collect();
    json_resp(&serde_json::json!({
        "ok": true,
        "how_to_run": {
            "one_device": "GET /m/sys?mtok=<t>&owner=<o>&target=<device>&kind=<kind>&arg=<arg>",
            "all_devices": "GET /m/fleet?mtok=<t>&owner=<o>&kind=<kind>&arg=<arg>",
            "arbitrary_command": "POST /m/exec {target,cmd,detach?,timeout?}",
            "scripts": "GET /m/scripts?q=<query>, then GET /m/script?target=&file=",
            "schedule": "POST /x/schedule-add {target,kind,arg,when:{type:once|interval|daily, mins|hhmm}}"
        },
        "actions": builtin,
        "plugins": plugins
    }))
}

// ── Scheduled actions ────────────────────────────────────────────────────────
// Persist scheduled runs to HUB_DATA/schedules.json; a background tick fires the
// due ones through the same exec path the dashboard/MCP use. Times are UTC.
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
fn schedules_path() -> std::path::PathBuf {
    data_dir().join("schedules.json")
}
fn load_schedules() -> Vec<serde_json::Value> {
    std::fs::read_to_string(schedules_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}
fn save_schedules(v: &[serde_json::Value]) {
    let _ = std::fs::create_dir_all(data_dir());
    let _ = std::fs::write(schedules_path(), serde_json::to_string_pretty(v).unwrap_or_default());
}
/// Next fire time (epoch secs) for a schedule spec: once / interval / daily (UTC).
fn next_run_from(when: &serde_json::Value) -> u64 {
    let now = now_secs();
    match when.get("type").and_then(|x| x.as_str()).unwrap_or("once") {
        "interval" => now + when.get("mins").and_then(|x| x.as_u64()).unwrap_or(60).max(1) * 60,
        "daily" => {
            let hhmm = when.get("hhmm").and_then(|x| x.as_str()).unwrap_or("00:00");
            let mut it = hhmm.split(':');
            let h: u64 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let m: u64 = it.next().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
            let tgt = (h * 3600 + m * 60) % 86400;
            let mut r = now - (now % 86400) + tgt;
            if r <= now {
                r += 86400;
            }
            r
        }
        _ => now + when.get("mins").and_then(|x| x.as_u64()).unwrap_or(0) * 60,
    }
}
fn sched_counter() -> u64 {
    static C: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    C.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
/// POST /x/schedule-add — schedule an action on a device (SSO).
fn schedule_add(req: &mut Request, agents: &Agents, user: Option<&str>) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if !may_control(user, agents, &target) {
        return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}));
    }
    let kind = v.get("kind").and_then(|x| x.as_str()).unwrap_or("").to_string();
    if kind.is_empty() {
        return json_resp(&serde_json::json!({"ok": false, "error": "kind required"}));
    }
    let when = v.get("when").cloned().unwrap_or_else(|| serde_json::json!({"type":"once","mins":0}));
    let arg = v.get("arg").and_then(|x| x.as_str()).unwrap_or("");
    let id = format!("s{}-{}", now_secs(), sched_counter());
    // Push the resolved command to the AGENT so it fires at the set time even while
    // disconnected. os_command/plugin/exec resolve to a shell command; composites
    // (posture) and scripts stay hub-side (agent_owned=false → hub fires as fallback).
    let platform = device_platform(agents, &target);
    let command = if kind == "exec" {
        arg.to_string()
    } else {
        os_command(&platform, &kind, arg).or_else(|| plugin_command(&platform, &kind, arg)).unwrap_or_default()
    };
    let mut agent_owned = false;
    if !command.is_empty() {
        let payload = serde_json::json!({"id": id, "command": command, "when": when}).to_string().into_bytes();
        agent_owned = dev_unary(&target, "POST", "/schedule/add", Some(("application/json".into(), payload))).is_some();
    }
    let rec = serde_json::json!({
        "id": id,
        "owner": user.unwrap_or(""),
        "target": target,
        "device": device_name(agents, &target),
        "kind": kind,
        "arg": arg,
        "label": v.get("label").and_then(|x| x.as_str()).unwrap_or(""),
        "when": when.clone(),
        "next_run": next_run_from(&when),
        "created": now_secs(),
        "agent_owned": agent_owned,
    });
    let mut all = load_schedules();
    all.push(rec.clone());
    save_schedules(&all);
    audit(user.unwrap_or(""), "browser", "schedule", rec["device"].as_str().unwrap_or(""), rec["label"].as_str().unwrap_or(&kind));
    json_resp(&serde_json::json!({"ok": true, "id": rec["id"]}))
}
/// GET /x/schedules — list this owner's schedules.
fn schedules_list(user: Option<&str>) -> Resp {
    let all: Vec<serde_json::Value> = load_schedules()
        .into_iter()
        .filter(|s| match user {
            None => true,
            Some(u) => s.get("owner").and_then(|x| x.as_str()) == Some(u),
        })
        .collect();
    json_resp(&serde_json::json!({"ok": true, "count": all.len(), "schedules": all}))
}
/// GET /x/schedule-delete?id= — cancel a schedule (owner-scoped).
fn schedule_delete(url: &str, user: Option<&str>) -> Resp {
    let id = query_param(url, "id").unwrap_or_default();
    let mut all = load_schedules();
    // Tell the owning agent to drop it too (best-effort).
    if let Some(target) = all.iter().find(|s| s.get("id").and_then(|x| x.as_str()) == Some(id.as_str())).and_then(|s| s.get("target").and_then(|x| x.as_str())) {
        let payload = serde_json::json!({"id": id}).to_string().into_bytes();
        let _ = dev_unary(target, "POST", "/schedule/del", Some(("application/json".into(), payload)));
    }
    all.retain(|s| !(s.get("id").and_then(|x| x.as_str()) == Some(id.as_str()) && (user.is_none() || s.get("owner").and_then(|x| x.as_str()) == user)));
    save_schedules(&all);
    json_resp(&serde_json::json!({"ok": true}))
}
/// Fire one scheduled action through the normal exec path.
fn run_scheduled(agents: &Agents, s: &serde_json::Value) {
    let target = s.get("target").and_then(|x| x.as_str()).unwrap_or("");
    let kind = s.get("kind").and_then(|x| x.as_str()).unwrap_or("");
    let arg = s.get("arg").and_then(|x| x.as_str()).unwrap_or("");
    let owner = s.get("owner").and_then(|x| x.as_str()).unwrap_or("");
    let platform = device_platform(agents, target);
    let dev = device_name(agents, target);
    if kind == "exec" {
        let _ = exec_output(target, arg);
    } else if let Some(file) = kind.strip_prefix("script:") {
        let _ = run_named_script(target, &platform, &all_scripts(false), file);
    } else if kind == "posture" {
        let _ = run_posture(target, &platform);
    } else if let Some(cmd) = os_command(&platform, kind, arg) {
        let _ = exec_output(target, &cmd);
    }
    audit(owner, "schedule", kind, &dev, arg);
}
/// Background tick: fire due schedules, re-arm recurring ones, drop one-shots.
fn start_scheduler(agents: Arc<Agents>, hub_ip: String, hub_port: u16) {
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        auto_update_pass(&agents, &hub_ip, hub_port);
        let now = now_secs();
        let mut all = load_schedules();
        let mut changed = false;
        let mut i = 0;
        while i < all.len() {
            if all[i].get("next_run").and_then(|x| x.as_u64()).unwrap_or(u64::MAX) > now {
                i += 1;
                continue;
            }
            let s = all[i].clone();
            // Agent-owned schedules fire on the device itself; the hub only advances
            // the display copy. Others (posture/scripts, or push-failed) fire here.
            if !s.get("agent_owned").and_then(|x| x.as_bool()).unwrap_or(false) {
                run_scheduled(&agents, &s);
            }
            let when = s.get("when").cloned().unwrap_or_default();
            if when.get("type").and_then(|x| x.as_str()).unwrap_or("once") == "once" {
                all.remove(i);
            } else {
                if let Some(o) = all[i].as_object_mut() {
                    o.insert("next_run".into(), serde_json::json!(next_run_from(&when)));
                    o.insert("last_run".into(), serde_json::json!(now));
                }
                i += 1;
            }
            changed = true;
        }
        if changed {
            save_schedules(&all);
        }
    });
}

// ── Session recording ────────────────────────────────────────────────────────
// Tee interactive-shell output to an asciinema v2 .cast under HUB_DATA/recordings,
// replayable in the dashboard via the bundled xterm.js. Best-effort — recording
// never affects the shell itself.
fn recordings_dir() -> std::path::PathBuf {
    let d = data_dir().join("recordings");
    let _ = std::fs::create_dir_all(&d);
    d
}
fn rec_registry() -> &'static Mutex<HashMap<String, (std::path::PathBuf, std::time::Instant)>> {
    static R: std::sync::OnceLock<Mutex<HashMap<String, (std::path::PathBuf, std::time::Instant)>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Mutex::new(HashMap::new()))
}
fn rec_key(target: &str, sid: &str) -> String {
    format!("{target}|{sid}")
}
fn rec_start(target: &str, sid: &str, device: &str) {
    let path = recordings_dir().join(format!("{}-{}-{}.cast", sanitize(device), now_secs(), sanitize(sid)));
    let header = serde_json::json!({"version": 2, "width": 120, "height": 30, "timestamp": now_secs(), "title": device});
    if std::fs::write(&path, format!("{header}\n")).is_ok() {
        rec_registry().lock().unwrap().insert(rec_key(target, sid), (path, std::time::Instant::now()));
    }
}
fn rec_output(target: &str, sid: &str, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let g = rec_registry().lock().unwrap();
    if let Some((path, start)) = g.get(&rec_key(target, sid)) {
        let line = serde_json::to_string(&serde_json::json!([start.elapsed().as_secs_f64(), "o", String::from_utf8_lossy(bytes)])).unwrap_or_default();
        if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(path) {
            use std::io::Write;
            let _ = writeln!(f, "{line}");
        }
    }
}
fn rec_stop(target: &str, sid: &str) {
    rec_registry().lock().unwrap().remove(&rec_key(target, sid));
}
/// GET /x/recordings — list saved shell recordings (newest first).
fn recordings_list() -> Resp {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(recordings_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("cast") {
                continue;
            }
            let size = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let (mut device, mut ts) = (String::new(), 0u64);
            if let Ok(txt) = std::fs::read_to_string(&p) {
                if let Some(h) = txt.lines().next().and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok()) {
                    device = h.get("title").and_then(|x| x.as_str()).unwrap_or("").to_string();
                    ts = h.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0);
                }
            }
            out.push(serde_json::json!({"file": e.file_name().to_string_lossy(), "device": device, "timestamp": ts, "size": size}));
        }
    }
    out.sort_by(|a, b| b["timestamp"].as_u64().unwrap_or(0).cmp(&a["timestamp"].as_u64().unwrap_or(0)));
    json_resp(&serde_json::json!({"ok": true, "recordings": out}))
}
fn rec_basename(url: &str) -> Option<String> {
    let file = query_param(url, "file").unwrap_or_default();
    let base = std::path::Path::new(&file).file_name().and_then(|x| x.to_str()).unwrap_or("").to_string();
    if base.ends_with(".cast") && !base.is_empty() {
        Some(base)
    } else {
        None
    }
}
/// GET /x/recording?file= — the raw .cast for playback.
fn recording_get(url: &str) -> Resp {
    match rec_basename(url).and_then(|b| std::fs::read(recordings_dir().join(b)).ok()) {
        Some(b) => Response::from_data(b).with_header(hdr("Content-Type", "text/plain; charset=utf-8")),
        None => Response::from_string("not found").with_status_code(404),
    }
}
/// GET /x/recording-delete?file=
fn recording_delete(url: &str) -> Resp {
    if let Some(b) = rec_basename(url) {
        let _ = std::fs::remove_file(recordings_dir().join(b));
    }
    json_resp(&serde_json::json!({"ok": true}))
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
    let detach = v.get("detach").and_then(|x| x.as_bool()).unwrap_or(false);
    let action = if detach { "launch command" } else { "run command" };
    if via_mcp {
        record_mcp_access(target, action, user.unwrap_or(""), cmd);
    }
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, action, &device_name(agents, target), cmd);
    let mut fwd = serde_json::json!({ "cmd": cmd, "detach": detach });
    if let Some(t) = v.get("timeout") {
        fwd["timeout"] = t.clone();
    }
    let payload = fwd.to_string().into_bytes();
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

fn proxy_shell_open(url: &str, agents: &Agents) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    match dev_unary(&target, "POST", "/shell/open", None) {
        Some((_st, _ct, b)) => {
            if let Some(sid) = serde_json::from_slice::<serde_json::Value>(&b).ok().and_then(|v| v.get("sid").and_then(|x| x.as_str()).map(String::from)) {
                rec_start(&target, &sid, &device_name(agents, &target));
            }
            Response::from_data(b).with_header(hdr("Content-Type", "application/json"))
        }
        None => json_resp(&serde_json::json!({"ok": false, "error": "device unreachable"})),
    }
}

fn proxy_shell_read(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let sid = query_param(url, "sid").unwrap_or_default();
    let from = query_param(url, "from").unwrap_or_else(|| "0".into());
    let path = format!("/shell/read?sid={}&from={}", urlencode(&sid), urlencode(&from));
    match dev_unary(&target, "GET", &path, None) {
        Some((_st, _ct, b)) => {
            rec_output(&target, &sid, &b);
            Response::from_data(b).with_header(hdr("Content-Type", "text/plain; charset=utf-8"))
        }
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
    rec_stop(&target, &sid);
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
        "<script>window.HB={{base:\"{}\",mtok:\"{}\",owner:\"{}\",ver:\"{}\"}}</script>",
        hb_base.replace('"', ""),
        hb_mtok.replace('"', ""),
        user.unwrap_or("").replace('"', ""),
        VERSION
    );
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>HaiveControl hub</title>\n<link rel=\"stylesheet\" href=\"/assets/xterm.css\"><style>{cp_css}</style></head>\n<body>\
<div class=\"app\">\
<nav class=\"rail\">\
<div class=\"rail-top\"><div class=\"rail-brand\">📡 <span class=\"rail-name\">Haive</span><span class=\"pill\" id=\"count\">…</span></div><code class=\"hubid\" title=\"This hub's ID — a stable name for this hub instance. Agents, the CLI (haivectl) and the MCP use it to address this hub. Set via the MAC_ID env var; otherwise derived from the machine hostname (in a container, that's the container ID).\">{mac_id}</code></div>\
<button class=\"railadd\" onclick=\"toggleReg()\" title=\"register a new device\">+ Add device</button>\
<div class=\"navsec\">Overview</div>\
<button class=\"navb\" data-nav=\"inventory\" onclick=\"showInventory()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"M11 21.73a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73z\"/><path d=\"M12 22V12\"/><path d=\"m3.3 7 8.7 5 8.7-5\"/><path d=\"m7.5 4.27 9 5.15\"/></svg></span>Inventory<span class=\"nbadge\" id=\"inv-badge\"></span></button>\
<button class=\"navb\" data-nav=\"dashboard\" onclick=\"showDashboard()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><rect width=\"7\" height=\"7\" x=\"3\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"7\" x=\"14\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"7\" x=\"14\" y=\"14\" rx=\"1\"/><rect width=\"7\" height=\"7\" x=\"3\" y=\"14\" rx=\"1\"/></svg></span>Dashboard</button>\
<div class=\"navsec\">Fleet</div>\
<button class=\"navb\" data-nav=\"fleet\" onclick=\"showFleet()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z\"/></svg></span>Fleet run</button>\
<div class=\"navsec\">Security</div>\
<button class=\"navb\" data-nav=\"compliance\" onclick=\"showCompliance()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\"/><path d=\"m9 12 2 2 4-4\"/></svg></span>Compliance</button>\
<button class=\"navb\" data-nav=\"cve\" onclick=\"showCVE()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><circle cx=\"11\" cy=\"11\" r=\"8\"/><path d=\"m21 21-4.3-4.3\"/></svg></span>CVE lookup</button>\
<div class=\"navsec\">Ops</div>\
<button class=\"navb\" data-nav=\"scripts\" onclick=\"showScripts()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"m7 11 2-2-2-2\"/><path d=\"M11 13h4\"/><rect width=\"18\" height=\"18\" x=\"3\" y=\"3\" rx=\"2\"/></svg></span>Scripts</button>\
<button class=\"navb\" data-nav=\"sched\" onclick=\"showSchedules()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><circle cx=\"12\" cy=\"12\" r=\"10\"/><polyline points=\"12 6 12 12 16 14\"/></svg></span>Scheduled</button>\
<div class=\"navsec\">Audit</div>\
<button class=\"navb\" data-nav=\"audit\" onclick=\"showAudit()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"M8 6h13\"/><path d=\"M8 12h13\"/><path d=\"M8 18h13\"/><path d=\"M3 6h.01\"/><path d=\"M3 12h.01\"/><path d=\"M3 18h.01\"/></svg></span>Audit log</button>\
<button class=\"navb\" data-nav=\"recs\" onclick=\"showRecordings()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"m16 13 5.22 3.48a.5.5 0 0 0 .78-.42V7.94a.5.5 0 0 0-.78-.42L16 11\"/><rect x=\"2\" y=\"6\" width=\"14\" height=\"12\" rx=\"2\"/></svg></span>Recordings</button>\
<div class=\"navsec\">System</div>\
<button class=\"navb\" data-nav=\"settings\" onclick=\"showSettings()\"><span class=\"ni\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></svg></span>Settings</button>\
</nav>\
<aside class=\"side\">\
<div class=\"dev-head\"><span class=\"navsec\">Devices</span></div>\
<div class=\"legend\"><span><span class=\"dot on\"></span>online</span><span><span class=\"dot idle\"></span>idle</span><span><span class=\"dot off\"></span>stale</span></div>\
<input id=\"devsearch\" class=\"devsearch\" type=\"search\" placeholder=\"Search devices…\" autocomplete=\"off\" oninput=\"SEARCH=this.value.toLowerCase();renderSide(LAST);\">\
<div id=\"reg\" class=\"reg\" style=\"display:none\"><p class=\"reg-hint\">Download the agent, then run it:</p>{win}{mac}{lin}</div>\
<ul id=\"devlist\" class=\"devlist\"></ul>\
</aside>\
<main class=\"stage\">\
<div class=\"stage-empty\" id=\"stage-empty\">Select a device from the left to control it.</div>\
<div id=\"inv-toggle\" class=\"inv-bar\" style=\"display:none\"><div class=\"aud-head\" style=\"margin:0\">Inventory</div><div class=\"seg\"><button id=\"invb-table\" class=\"segb\" onclick=\"invView('table')\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><rect width=\"18\" height=\"18\" x=\"3\" y=\"3\" rx=\"2\"/><path d=\"M3 9h18\"/><path d=\"M3 15h18\"/><path d=\"M12 3v18\"/></svg> Table</button><button id=\"invb-map\" class=\"segb\" onclick=\"invView('map')\"><svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" class=\"ic\"><path d=\"M20 10c0 4.4-5.6 8.6-7.4 9.8a1 1 0 0 1-1.2 0C9.6 18.6 4 14.4 4 10a8 8 0 0 1 16 0\"/><circle cx=\"12\" cy=\"10\" r=\"3\"/></svg> Map</button></div></div>\
<div id=\"dashboard-view\" style=\"display:none\"></div>\
<div id=\"audit-view\" style=\"display:none\"><div class=\"aud-head\">Audit log <span class=\"dim2\">— device actions on your account · last 500 events</span></div><input id=\"aud-q\" class=\"devsearch\" placeholder=\"Filter by device / action / who / via…\" autocomplete=\"off\" oninput=\"renderAudit();\"><div class=\"aud-cols\"><span>when</span><span>via</span><span>action</span><span>device</span><span>who</span><span>detail</span></div><div id=\"audit-rows\"></div></div>\
<div id=\"overview-view\" style=\"display:none\"><div class=\"aud-head\">Fleet status <span class=\"dim2\">— every device, every parameter, at a glance</span></div><div id=\"ov-summary\" class=\"ov-summary\"></div><div class=\"ov-scroll\"><table class=\"ov-tbl\"><thead><tr><th class=\"ovh\" onclick=\"ovSort('status')\">●</th><th class=\"ovh\" onclick=\"ovSort('name')\">Device</th><th class=\"ovh\" onclick=\"ovSort('os')\">OS</th><th class=\"ovh\" onclick=\"ovSort('user')\">User</th><th class=\"ov-num ovh\" onclick=\"ovSort('cpu')\">CPU</th><th class=\"ov-num ovh\" onclick=\"ovSort('ram')\">RAM free</th><th class=\"ov-num\">Cores</th><th class=\"ov-num\">Cam</th><th class=\"ov-num\">Mic</th><th>Address</th><th class=\"ovh\" onclick=\"ovSort('seen')\">Last seen</th><th>MCP</th></tr></thead><tbody id=\"ov-body\"></tbody></table></div></div>\
<div id=\"schedules-view\" style=\"display:none\"><div class=\"aud-head\">Scheduled <span class=\"dim2\">— actions queued to run automatically (times UTC)</span></div><div id=\"sched-list\"></div></div>\
<div id=\"map-view\" style=\"display:none\"><div class=\"aud-head\">Device map <span class=\"dim2\">— approximate location from public IP · city-level, VPN/NAT skews it</span></div><div id=\"map-count\" class=\"dim2\" style=\"font-size:11px;margin-bottom:8px\"></div><div id=\"map-svg\"></div><div id=\"map-un\" class=\"map-un\"></div></div>\
<div id=\"settings-view\" style=\"display:none\"><div class=\"aud-head\">Settings <span class=\"dim2\">— hub administration</span></div><div class=\"set-row\"><div class=\"set-main\"><div class=\"set-nm\">Agent updates</div><div class=\"set-desc\">How out-of-date device agents get updated to the hub's build (<span id=\"set-ver\" class=\"dim2\"></span>). <b>Automatic</b> pushes updates to behind devices on a schedule; <b>Manual</b> updates only when you click Update on a device.</div></div><select id=\"set-au\" class=\"scr-sel\" onchange=\"saveAgentUpdate()\"><option value=\"manual\">Manual</option><option value=\"auto\">Automatic</option></select></div></div>\
<div id=\"cve-view\" style=\"display:none\"><div class=\"aud-head\">CVE lookup <span class=\"dim2\">— known CVEs for a product, via NVD · a lookup, not an automated scan</span></div><div class=\"fleet-bar\"><input id=\"cve-q\" class=\"devsearch\" placeholder=\"Product / keyword — e.g. openssl 3.0, Google Chrome, log4j\" autocomplete=\"off\"><button class=\"b\" onclick=\"searchCVE()\">Search</button></div><div id=\"cve-count\" class=\"dim2\" style=\"font-size:11px;margin-bottom:8px\"></div><div id=\"cve-list\"></div></div>\
<div id=\"recordings-view\" style=\"display:none\"><div class=\"aud-head\">Recordings <span class=\"dim2\">— replay past interactive shell sessions</span></div><div id=\"rec-player\" class=\"rec-player\" style=\"display:none\"><div class=\"rec-pbar\"><span id=\"rec-title\" class=\"dim2\"></span><button class=\"b subtle\" onclick=\"stopPlay()\">Close player</button></div><div id=\"rec-term\" class=\"rec-term\"></div></div><div id=\"rec-list\"></div></div>\
<div id=\"compliance-view\" style=\"display:none\"><div class=\"aud-head\">Compliance <span class=\"dim2\">— posture across the fleet, mapped to a framework</span></div><div class=\"fleet-bar\"><select id=\"cmp-fw\" class=\"scr-sel\" title=\"framework to show control IDs for\" onchange=\"renderCompliance()\"></select><button class=\"b\" onclick=\"runCompliance()\">Run across fleet ▶</button></div><div id=\"cmp-note\" class=\"dim2\" style=\"font-size:11px;margin-bottom:8px\">Indicative control references to orient you — not certified audit evidence.</div><div class=\"ov-scroll\"><table class=\"ov-tbl cmp-tbl\"><thead id=\"cmp-head\"></thead><tbody id=\"cmp-body\"></tbody></table></div></div>\
<div id=\"scripts-view\" style=\"display:none\"><div class=\"aud-head\">Script library <span class=\"dim2\">— TacticalRMM community scripts (amidaware) · runs base64-wrapped, ~65s cap</span></div><div class=\"fleet-bar\"><input id=\"scr-q\" class=\"devsearch\" placeholder=\"Search scripts… (bitlocker, cleanup, defender, choco…)\" autocomplete=\"off\"><select id=\"scr-target\" class=\"scr-sel\" title=\"where to run\"></select><button class=\"b\" onclick=\"toggleScrForm()\" title=\"add your own script\">＋ Add</button></div>\
<div id=\"scr-form\" class=\"scr-form\" style=\"display:none\"><div class=\"scr-form-row\"><input id=\"sf-name\" class=\"devsearch\" placeholder=\"Script name\" autocomplete=\"off\"><select id=\"sf-shell\" class=\"scr-sel\" title=\"interpreter\"><option value=\"powershell\">PowerShell</option><option value=\"shell\">Shell / bash</option><option value=\"python\">Python</option><option value=\"cmd\">Batch (cmd)</option></select><select id=\"sf-plat\" class=\"scr-sel\" title=\"where it can run\"><option value=\"windows,macos,linux\">All platforms</option><option value=\"windows\">Windows</option><option value=\"macos\">macOS</option><option value=\"linux\">Linux</option></select></div><input id=\"sf-desc\" class=\"devsearch\" placeholder=\"Short description (optional)\" autocomplete=\"off\"><textarea id=\"sf-body\" class=\"sf-body\" placeholder=\"Paste the script here…\" spellcheck=\"false\"></textarea><div class=\"scr-form-row\"><button class=\"b\" onclick=\"submitScript()\">Save script</button><button class=\"b subtle\" onclick=\"toggleScrForm()\">Cancel</button><span id=\"sf-msg\" class=\"dim2\" style=\"font-size:11px\"></span></div></div>\
<div id=\"scr-out\" class=\"scr-out\" style=\"display:none\"></div><div id=\"scr-count\" class=\"dim2\" style=\"font-size:11px;margin-bottom:8px\"></div><div id=\"scr-list\" class=\"scr-list\"></div></div>\
<div id=\"fleet-view\" style=\"display:none\"><div class=\"aud-head\">Fleet run <span class=\"dim2\">— run on all your devices, in parallel</span></div><div class=\"fleet-bar\"><input id=\"fleet-cmd\" class=\"devsearch\" placeholder=\"shell command to run on every device…\" autocomplete=\"off\"><button class=\"b\" onclick=\"runFleet()\">Run on all</button></div><div id=\"fleet-results\"></div></div>\
<div id=\"detail\" style=\"display:none\">\
<div class=\"detail-head\"><div class=\"dh-id\"><span class=\"dot\" id=\"d-dot\"></span><div><div class=\"dh-name\" id=\"d-name\"></div><div class=\"dh-sub\" id=\"d-sub\"></div></div></div>\
<a class=\"dh-open\" id=\"d-open\" target=\"_blank\">Open agent&nbsp;↗</a></div>\
<div class=\"specs\" id=\"d-specs\"></div>\
<div id=\"d-activity\"></div>\
<div id=\"d-controls\"></div>\
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
.hubid{cursor:help;border-bottom:1px dotted var(--muted2)}
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
.act-rows{max-height:220px;overflow-y:auto;margin-right:-6px;padding-right:6px}
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
.ov-summary{display:flex;flex-wrap:wrap;gap:8px 16px;margin-bottom:14px;font-size:12px;color:var(--muted)}
.ov-summary .ovs{display:inline-flex;align-items:center;gap:6px}
.ov-summary b{color:var(--text)}
.ov-scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
.ov-tbl{width:100%;border-collapse:collapse;font-size:12px;white-space:nowrap}
.ov-tbl th{text-align:left;padding:9px 12px;color:var(--muted);text-transform:uppercase;font-size:10px;letter-spacing:.5px;border-bottom:1px solid var(--line2);position:sticky;top:0;background:var(--panel,var(--bg));font-weight:600}
.ov-tbl td{padding:9px 12px;border-bottom:1px solid var(--line2)}
.ov-tbl tbody tr:last-child td{border-bottom:0}
.ovh{cursor:pointer;user-select:none}
.ovh:hover{color:var(--text)}
.ov-row{cursor:pointer}
.ov-row:hover td{background:var(--hover,rgba(127,127,127,.08))}
.ov-nm{font-weight:600;color:var(--text)}
.ov-num{text-align:right;font-variant-numeric:tabular-nums}
.ov-tbl .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--muted)}
.ov-empty{text-align:center;color:var(--muted2);padding:24px}
.cmp-tbl th{vertical-align:top}
.cmp-ctl{font-size:9px;color:var(--muted2);font-weight:400;text-transform:none;letter-spacing:0;margin-top:2px}
.cmp-pass{color:var(--on);font-weight:700}
.cmp-fail{color:var(--danger);font-weight:700}
.cmp-g{font-weight:700}
.cmp-A,.cmp-B{color:var(--on)}
.cmp-C{color:var(--idle)}
.cmp-D,.cmp-F{color:var(--danger)}
.scr-sel{background:var(--surface2);color:var(--text);border:1px solid var(--line2);border-radius:8px;padding:0 10px;font-size:13px;max-width:220px}
.scr-list{display:flex;flex-direction:column;gap:8px}
.scr-row{display:flex;align-items:flex-start;gap:12px;border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.scr-main{flex:1;min-width:0}
.scr-nm{font-weight:600;font-size:13px;color:var(--text)}
.scr-desc{color:var(--muted);font-size:12px;margin:2px 0 6px;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.scr-meta{display:flex;flex-wrap:wrap;gap:6px;align-items:center}
.scr-cat{color:var(--muted2);font-size:10px}
.scr-row .b{flex:none}
.scr-out{border:1px solid var(--line2);border-radius:10px;padding:10px 12px;margin-bottom:12px;background:var(--surface)}
.scr-run{font-size:12px;color:var(--muted);margin-bottom:6px}
.scr-run.err{color:var(--danger)}
.scr-dev{font-size:11px;font-weight:600;color:var(--accent);margin-top:8px}
.scr-pre{white-space:pre-wrap;word-break:break-word;font-size:11px;background:var(--bg);border-radius:6px;padding:8px;margin:4px 0 0;max-height:280px;overflow:auto}
.scr-form{border:1px solid var(--line2);border-radius:10px;padding:12px;margin-bottom:12px;display:flex;flex-direction:column;gap:8px;background:var(--surface)}
.scr-form-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.scr-form .devsearch{margin:0}
.sf-body{width:100%;min-height:120px;background:var(--bg);color:var(--text);border:1px solid var(--line2);border-radius:8px;padding:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;resize:vertical;box-sizing:border-box}
.chip.cust{background:var(--accent);color:#08111f;border:0;margin-right:6px}
.scr-del{flex:none;color:var(--danger);padding:6px 9px}
.fleet-card{border:1px solid var(--line);border-radius:10px;margin-bottom:10px;overflow:hidden}
.fleet-dev{background:var(--surface2);padding:7px 12px;font-weight:600;font-size:12px;color:#d7dbe6}
.fleet-out{margin:0;padding:10px 12px;font-family:ui-monospace,Menlo,monospace;font-size:11px;line-height:1.5;color:#c3c9d8;white-space:pre-wrap;max-height:200px;overflow:auto}
.dl-load.warn{color:var(--idle)}
.dl-load.hot{color:var(--danger)}
.empty-li{color:var(--muted);font-size:12px;padding:14px 11px}
.addbtn{margin:9px;padding:9px;border-radius:9px;background:var(--surface2);border:1px solid var(--line2);color:#d7dbe6;cursor:pointer;font-size:12px;transition:background .15s}
.addbtn:hover{background:#252b3a}
.dev-head{display:flex;align-items:center;justify-content:space-between;padding:6px 12px 2px}
.miniadd{background:transparent;border:1px solid var(--line2);color:var(--muted);border-radius:6px;padding:2px 9px;font-size:11px;cursor:pointer;transition:color .12s,border-color .12s}
.miniadd:hover{color:var(--text);border-color:var(--accent)}
.nav{display:flex;flex-direction:column;gap:2px;margin:8px 6px 10px;padding-top:8px;border-top:1px solid var(--line)}
.navsec{font-size:9px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted2);font-weight:600;padding:7px 6px 3px}
.navb{display:flex;align-items:center;gap:9px;background:transparent;border:0;color:var(--muted);border-radius:7px;padding:6px 8px;font-size:12.5px;cursor:pointer;text-align:left;width:100%;transition:background .12s,color .12s}
.navb:hover{background:var(--surface2);color:var(--text)}
.navb.active{background:var(--surface2);color:var(--text);box-shadow:inset 2px 0 0 var(--accent)}
.navb .ni{font-size:13px;width:16px;text-align:center;flex:none}
.rail{width:178px;flex:none;border-right:1px solid var(--line);display:flex;flex-direction:column;gap:1px;background:#0e111a;padding:10px 8px;overflow-y:auto}
.rail-top{display:flex;flex-direction:column;gap:5px;padding:4px 8px 8px}
.rail-brand{display:flex;align-items:center;gap:6px;font-size:15px;font-weight:700}
.rail-name{font-size:14px;color:var(--text)}
.rail-brand .pill{margin-left:auto;font-size:10px;padding:1px 8px}
.rail-top .hubid{font-size:10px;color:var(--muted2);margin:0;align-self:flex-start;border-bottom:1px dotted var(--muted2);cursor:help}
.railadd{margin:0 4px 8px;background:transparent;border:1px dashed var(--line2);color:var(--muted);border-radius:8px;padding:6px;font-size:12px;cursor:pointer;transition:color .12s,border-color .12s}
.railadd:hover{color:var(--accent);border-color:var(--accent)}
.rail .navb{margin:0}
.nbadge{margin-left:auto;background:var(--accent);color:#08111f;font-size:10px;font-weight:700;border-radius:10px;padding:1px 7px;min-width:16px;text-align:center}
.inv-bar{display:flex;align-items:center;gap:14px}
.seg{display:inline-flex;border:1px solid var(--line2);border-radius:8px;overflow:hidden}
.segb{background:transparent;border:0;color:var(--muted);padding:6px 13px;font-size:12px;cursor:pointer;transition:background .12s,color .12s;display:inline-flex;align-items:center;gap:6px}
.segb.active{background:var(--surface2);color:var(--text)}
.dgrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin:6px 0 16px}
.dcard{border:1px solid var(--line);border-radius:12px;padding:14px 16px;background:var(--surface)}
.dcard-v{font-size:26px;font-weight:700;color:var(--text)}
.dcard-n{font-size:11px;color:var(--muted2);text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
.dquick{display:flex;flex-wrap:wrap;gap:8px}
.ic{width:15px;height:15px;flex:none;display:inline-block;vertical-align:middle}
.navb .ni .ic{width:15px;height:15px}
.bsend{padding:6px 11px;display:inline-flex;align-items:center;justify-content:center}
.bsend .ic{width:17px;height:17px}
.b.bsend:not(.subtle):not(.danger){background:var(--accent);border-color:var(--accent);color:#08111f}
.b.bsend:not(.subtle):not(.danger):hover{background:#4a8ff5}
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
.controls{display:flex;flex-wrap:wrap;gap:10px 14px;align-items:flex-start;padding:13px 0;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.bgroup{display:flex;flex-direction:column;gap:6px;padding-right:14px;border-right:1px solid var(--line)}
.bgroup:last-child{padding-right:0;border-right:0}
.blabel{font-size:9px;text-transform:uppercase;letter-spacing:.6px;color:var(--muted2);font-weight:600}
.brow{display:flex;flex-wrap:wrap;gap:7px;align-items:center}
.alist{display:flex;flex-direction:column;gap:6px}
.arow{display:flex;flex-wrap:wrap;gap:10px 12px;align-items:center;border:1px solid var(--line);border-radius:10px;padding:9px 12px}
.arow-main{flex:1;min-width:180px}
.arow-nm{font-weight:600;font-size:13px;color:var(--text)}
.arow-desc{font-size:11px;color:var(--muted);margin-top:1px}
.arow-ctl{display:flex;flex-wrap:wrap;gap:7px;align-items:center}
.arow-ctl .scr-sel{max-width:170px}
.arow-ctl .arow-arg{margin:0;width:190px}
.arow-sbtn{padding:6px 9px}
.arow-sched{flex-basis:100%;display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:12px;padding-top:8px;border-top:1px solid var(--line2)}
.sch-in{margin:0;width:110px}
.sched-row{display:flex;align-items:center;gap:12px;border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-bottom:8px}
.sched-main{flex:1;min-width:0}
.sched-nm{font-weight:600;font-size:13px;color:var(--text)}
.sched-meta{font-size:11px;color:var(--muted);margin-top:2px}
.rec-player{border:1px solid var(--line2);border-radius:10px;padding:10px;margin-bottom:12px;background:#0d0f14}
.rec-pbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:8px}
.rec-term{min-height:340px}
.worldsvg{width:100%;max-width:820px;border:1px solid var(--line2);border-radius:10px;display:block}
.mapbg{fill:var(--surface)}
.grat line{stroke:var(--line2);stroke-width:.3}
.pin circle{fill:var(--accent);stroke:#fff;stroke-width:.4;cursor:pointer;transition:fill .15s}
.pin:hover circle{fill:var(--danger);r:3.6}
.map-un{margin-top:12px}
.map-unh{font-size:11px;color:var(--muted2);margin-bottom:6px}
.map-unc{cursor:pointer}
.clabel{background:transparent;border:0;box-shadow:none;color:#08111f;font-weight:700;font-size:10px}
.cve-row{border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin-bottom:8px}
.cve-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:4px}
.cve-id{font-weight:600;font-size:13px;color:var(--accent);text-decoration:none}
.cve-id:hover{text-decoration:underline}
.cve-sev{font-size:10px;font-weight:700;padding:2px 7px;border-radius:20px;text-transform:uppercase;letter-spacing:.4px}
.sev-crit{background:#5a1a1a;color:#ff8f8f}
.sev-high{background:#5a2f1a;color:#ffb27a}
.sev-med{background:#5a501a;color:#f5df7a}
.sev-low{background:#1a3a5a;color:#8fc4ff}
.sev-none{background:var(--surface2);color:var(--muted)}
.cve-sum{font-size:12px;color:var(--muted);line-height:1.4}
.set-row{display:flex;gap:16px;align-items:flex-start;border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin-bottom:10px}
.set-main{flex:1;min-width:0}
.set-nm{font-weight:600;font-size:14px;color:var(--text)}
.set-desc{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.5}
.set-row .scr-sel{flex:none;height:34px}
.b{background:var(--surface2);border:1px solid var(--line2);color:#d7dbe6;border-radius:7px;padding:6px 11px;cursor:pointer;font-size:12px;font-weight:500;white-space:nowrap;transition:background .15s,border-color .15s,color .15s}
button:focus-visible,select:focus-visible,input:focus-visible,a:focus-visible,.navb:focus-visible,.dev-li:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
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
function fetchAgents(){fetch('/agents').then(function(r){return r.json();}).then(function(j){var arr=(j&&j.agents)||[];DEV={};arr.forEach(function(d){DEV[baseOf(d)]=d;});LAST=arr;renderSide(arr);updInvBadge();if(OVERVIEW_ON)renderOverview(arr);if(DASH_ON)renderDashboard();var special=AUDIT_ON||OVERVIEW_ON||SCRIPTS_ON||COMPLIANCE_ON||SCHED_ON||RECS_ON||MAP_ON||CVE_ON||SET_ON||DASH_ON||document.getElementById('fleet-view').style.display==='block';if(SEL&&DEV[SEL]){refreshHead(DEV[SEL]);}else if(SEL){SEL=null;if(!special)showEmpty();}if(!BOOTED){BOOTED=true;showDashboard();}}).catch(function(){});}
function renderSide(arr){var el=document.getElementById('devlist');document.getElementById('count').textContent=arr.length+' device'+(arr.length===1?'':'s');var fa=SEARCH?arr.filter(function(d){return ((d.name||'')+' '+(d.hostname||'')+' '+(d.os||'')+' '+(d.ip||'')).toLowerCase().indexOf(SEARCH)>=0;}):arr;if(!fa.length){el.innerHTML='<li class="empty-li">'+(arr.length?'No match.':'No devices yet — register one below.')+'</li>';return;}var h='';fa.forEach(function(d){var b=baseOf(d);var sel=(b===SEL)?' sel':'';var load=(d.cpu_pct!=null)?('<span class="dl-load '+loadCls(d.cpu_pct)+'" title="CPU load">'+Math.round(d.cpu_pct)+'%</span>'):'';var mcp=d.mcp_active?'<span class="mcp-live" title="an AI agent is accessing this device via MCP">🤖⇄</span>':'';var nm=d.name||d.hostname||d.ip;h+='<li class="dev-li'+sel+'" data-base="'+attrEsc(b)+'"><span class="dot '+statusOf(d)+'"></span><span class="dl-txt"><span class="dl-name">'+esc2(nm)+'</span><span class="dl-meta">'+esc2(d.os||'')+' · '+seenTxt(d.last_seen_secs)+'</span></span>'+mcp+load+'<button class="agi" title="copy AI-agent setup for this device" onclick="event.stopPropagation();copyAgentFor(this,\''+attrEsc(nm)+'\')">🤖</button></li>';});el.innerHTML=h;}
function activityHtml(d){var log=d.mcp_log||[];if(!log.length)return '';var head='<div class="act-head'+(d.mcp_active?' live':'')+'"><span class="act-dot"></span>'+(d.mcp_active?'AI agent accessing now':'Recent Activity')+'</div>';var rows=log.map(function(e){var det=e.detail||'';var tip=det?(e.action+': '+det):e.action;return '<div class="act-row" title="'+attrEsc(tip)+'"><span class="act-act">'+esc2(e.action)+'</span><span class="act-det">'+esc2(det)+'</span><span class="act-by">'+esc2(e.owner||'—')+'</span><span class="act-ago">'+e.secs+'s ago</span></div>';}).join('');return '<div class="activity">'+head+'<div class="act-rows">'+rows+'</div></div>';}
function copyAgentFor(btn,name){var hb=window.HB||{};var base=hb.base||location.origin;var L=[];L.push('# HaiveControl — control \"'+name+'\" from your AI agent (Claude).');L.push('# 1) install the MCP once (macOS shown; -linux / -windows.exe also served):');L.push('curl -L -o haive-mcp '+base+'/bin/haive-mcp-macos && chmod +x haive-mcp');var env=' --env HAIVE_HUB='+base;if(hb.mtok)env+=' --env HIVE_MCP_TOKEN='+hb.mtok;if(hb.owner)env+=' --env HIVE_OWNER='+hb.owner;L.push('claude mcp add haive'+env+' -- \"$PWD/haive-mcp\"');L.push('');L.push('# 2) then ask your agent, e.g.:');L.push('#   take a screenshot of '+name);L.push('#   run `uname -a` on '+name);L.push('#   type \"hello\" on '+name+' then press Enter');copyText(L.join('\n'),btn);}
function copyText(t,btn){var ok=function(){if(!btn)return;var o=btn.textContent;btn.textContent='✓';setTimeout(function(){btn.textContent=o;},1200);};if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok,function(){fb(t,ok);});}else{fb(t,ok);}}
function showEmpty(){hideViews();document.getElementById('stage-empty').style.display='block';setNav('');}
var AUDIT_ON=false;
function agoTxt(s){return s<60?(s+'s ago'):(s<3600?(Math.floor(s/60)+'m ago'):(Math.floor(s/3600)+'h ago'));}
function hideViews(){stopPlay();if(LMAP){try{LMAP.remove();}catch(e){}LMAP=null;}var v=['detail','stage-empty','fleet-view','overview-view','audit-view','scripts-view','compliance-view','schedules-view','recordings-view','map-view','cve-view','settings-view','inv-toggle','dashboard-view'];for(var i=0;i<v.length;i++){var el=document.getElementById(v[i]);if(el)el.style.display='none';}}
function setNav(n){var b=document.querySelectorAll('.navb');for(var i=0;i<b.length;i++){b[i].classList.toggle('active',b[i].getAttribute('data-nav')===n);}}
function showAudit(){AUDIT_ON=true;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;SEL=null;highlight();hideViews();document.getElementById('audit-view').style.display='block';setNav('audit');loadAudit();}
function sysCall(kind,arg){var u='/x/sys?target='+enc(SEL)+'&kind='+enc(kind);if(arg)u+='&arg='+enc(arg);out(kind+' …');fetch(u).then(function(r){return r.json();}).then(function(j){out(j.output||('[error] '+(j.error||'failed')));}).catch(function(e){out('error: '+e);});}
function doSys(){var k=prompt('Report — hardware / av / encryption / firewall / processes / services / network / packages / updates / power_report','hardware');if(k)sysCall(k.trim(),'');}
function doPower(){var a=prompt('Action — reboot / shutdown / sleep / logoff / update_all / firewall_on / firewall_off / usb_lock / usb_unlock','sleep');if(!a)return;a=a.trim();if(!confirm(a+' — run on this device?'))return;sysCall(a,'');}
function doMsg(){var t=prompt('Message to show the logged-in user:');if(t)sysCall('message',t);}
function doInstall(){var p=prompt('Package to install (winget id / brew formula / apt package):');if(p)sysCall('install',p.trim());}
function doPosture(){out('checking compliance…');fetch('/x/sys?target='+enc(SEL)+'&kind=posture').then(function(r){return r.json();}).then(function(j){if(!j.ok){out('[error] '+(j.error||'failed'));return;}var s='Compliance: '+j.grade+' ('+j.score+'/100)\n';(j.checks||[]).forEach(function(c){s+='  ['+(c.pass?'PASS':'FAIL')+'] '+c.check+'\n';});out(s);}).catch(function(e){out('error: '+e);});}
function showFleet(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;SEL=null;highlight();hideViews();document.getElementById('fleet-view').style.display='block';setNav('fleet');document.getElementById('fleet-cmd').focus();}
var OVERVIEW_ON=false,SCRIPTS_ON=false,COMPLIANCE_ON=false,SCHED_ON=false,SCR_T=null,CMP_DATA=null;
function showSchedules(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;SCHED_ON=true;SEL=null;highlight();hideViews();document.getElementById('schedules-view').style.display='block';setNav('sched');loadSchedules();}
function loadSchedules(){fetch('/x/schedules').then(function(r){return r.json();}).then(function(j){renderSchedules((j&&j.schedules)||[]);}).catch(function(){document.getElementById('sched-list').innerHTML='<div class="aud-empty">Could not load schedules.</div>';});}
function schedEvery(w){w=w||{};return w.type==='once'?('once, in '+(w.mins||0)+'m'):w.type==='interval'?('every '+(w.mins||0)+'m'):('daily at '+(w.hhmm||'')+' UTC');}
function nextIn(secs){if(secs==null)return '';var now=Math.floor(Date.now()/1000);var d=secs-now;if(d<=0)return 'due';return d<60?(d+'s'):d<3600?(Math.round(d/60)+'m'):d<86400?(Math.round(d/3600)+'h'):(Math.round(d/86400)+'d');}
function renderSchedules(arr){var el=document.getElementById('sched-list');if(!arr.length){el.innerHTML='<div class="aud-empty">No scheduled actions. Open a device → pick an action → tick “Schedule”.</div>';return;}el.innerHTML=arr.map(function(s){return '<div class="sched-row"><div class="sched-main"><div class="sched-nm">'+esc2(s.label||s.kind)+(s.arg?(' <span class="dim2">'+esc2(s.arg)+'</span>'):'')+'</div><div class="sched-meta">'+esc2(s.device||'?')+' · '+esc2(schedEvery(s.when))+' · next in '+nextIn(s.next_run)+(s.last_run?(' · last '+recWhen(s.last_run)):'')+(s.agent_owned?' · <span class="chip cust">on-device</span>':' · hub-run')+'</div></div><button class="b danger" onclick="delSchedule(\''+attrEsc(s.id)+'\')">Cancel</button></div>';}).join('');}
function delSchedule(id){fetch('/x/schedule-delete?id='+encodeURIComponent(id)).then(function(r){return r.json();}).then(function(){loadSchedules();}).catch(function(){});}
var RECS_ON=false,REC_TIMERS=[];
function showRecordings(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;RECS_ON=true;SEL=null;highlight();hideViews();document.getElementById('recordings-view').style.display='block';setNav('recs');stopPlay();loadRecordings();}
function loadRecordings(){fetch('/x/recordings').then(function(r){return r.json();}).then(function(j){renderRecordings((j&&j.recordings)||[]);}).catch(function(){document.getElementById('rec-list').innerHTML='<div class="aud-empty">Could not load recordings.</div>';});}
function recWhen(ts){if(!ts)return '';var d=Math.floor(Date.now()/1000)-ts;return d<60?(d+'s ago'):d<3600?(Math.round(d/60)+'m ago'):d<86400?(Math.round(d/3600)+'h ago'):(Math.round(d/86400)+'d ago');}
function recSize(n){return n<1024?(n+' B'):n<1048576?((n/1024).toFixed(0)+' KB'):((n/1048576).toFixed(1)+' MB');}
function renderRecordings(arr){var el=document.getElementById('rec-list');if(!arr.length){el.innerHTML='<div class="aud-empty">No recordings yet — open a device → Shell; the session records automatically.</div>';return;}el.innerHTML=arr.map(function(r){return '<div class="sched-row"><div class="sched-main"><div class="sched-nm">'+esc2(r.device||r.file)+'</div><div class="sched-meta">'+esc2(recWhen(r.timestamp))+' · '+esc2(recSize(r.size||0))+'</div></div><button class="b" onclick="playRecording(\''+attrEsc(r.file)+'\',\''+attrEsc(r.device||'')+'\')">Play ▶</button><button class="b danger" onclick="delRecording(\''+attrEsc(r.file)+'\')">Delete</button></div>';}).join('');}
function stopPlay(){if(REC_TIMERS){REC_TIMERS.forEach(clearTimeout);REC_TIMERS=[];}var p=document.getElementById('rec-player');if(p)p.style.display='none';var t=document.getElementById('rec-term');if(t)t.innerHTML='';}
function playRecording(file,dev){stopPlay();document.getElementById('rec-player').style.display='block';document.getElementById('rec-title').textContent='▶ '+dev+' — replaying…';fetch('/x/recording?file='+encodeURIComponent(file)).then(function(r){return r.text();}).then(function(txt){var lines=txt.split('\n');var term=new Terminal({convertEol:false,fontSize:12,cols:120,rows:30,theme:{background:'#0d0f14',foreground:'#e6e9f2'}});term.open(document.getElementById('rec-term'));REC_TIMERS=[];var last=0;for(var i=1;i<lines.length;i++){if(!lines[i])continue;try{var e=JSON.parse(lines[i]);if(e[1]!=='o')continue;(function(data,at){REC_TIMERS.push(setTimeout(function(){term.write(data);},at*1000));})(e[2],e[0]);if(e[0]>last)last=e[0];}catch(x){}}REC_TIMERS.push(setTimeout(function(){document.getElementById('rec-title').textContent='▶ '+dev+' — done';},last*1000+300));}).catch(function(){document.getElementById('rec-title').textContent='playback failed';});}
function delRecording(file){if(!confirm('Delete this recording?'))return;fetch('/x/recording-delete?file='+encodeURIComponent(file)).then(function(r){return r.json();}).then(function(){loadRecordings();}).catch(function(){});}
var MAP_ON=false,LMAP=null,INV_MODE=null,DASH_ON=false,BOOTED=false;
function showInventory(){AUDIT_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;CVE_ON=false;SET_ON=false;DASH_ON=false;SEL=null;highlight();hideViews();setNav('inventory');document.getElementById('inv-toggle').style.display='flex';invView(INV_MODE||'table');}
function invView(m){INV_MODE=m;document.getElementById('invb-table').classList.toggle('active',m==='table');document.getElementById('invb-map').classList.toggle('active',m==='map');if(m==='table'){document.getElementById('map-view').style.display='none';MAP_ON=false;document.getElementById('overview-view').style.display='block';OVERVIEW_ON=true;renderOverview(LAST);}else{document.getElementById('overview-view').style.display='none';OVERVIEW_ON=false;document.getElementById('map-view').style.display='block';MAP_ON=true;document.getElementById('map-svg').innerHTML='<div class="dim2" style="font-size:12px">Locating devices…</div>';ensureLeaflet(loadMap);}}
function showDashboard(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;DASH_ON=true;SEL=null;highlight();hideViews();setNav('dashboard');document.getElementById('dashboard-view').style.display='block';renderDashboard();}
function renderDashboard(){var arr=LAST||[];var on=0,idle=0,off=0,mcp=0,lsum=0,ln=0;arr.forEach(function(d){var s=statusOf(d);if(s==='on')on++;else if(s==='idle')idle++;else off++;if(d.mcp_active)mcp++;if(d.cpu_pct!=null){lsum+=d.cpu_pct;ln++;}});var avg=ln?Math.round(lsum/ln)+'%':'—';function card(n,v,c){return '<div class="dcard"><div class="dcard-v '+(c||'')+'">'+v+'</div><div class="dcard-n">'+esc2(n)+'</div></div>';}var cards=card('Devices',arr.length,'')+card('Online',on,'cmp-A')+card('Idle',idle,'cmp-C')+card('Stale',off,off?'cmp-F':'')+card('Avg CPU',avg,'')+card('MCP active',mcp,mcp?'sev-high':'');document.getElementById('dashboard-view').innerHTML='<div class="aud-head">Dashboard <span class="dim2">— fleet at a glance</span></div><div class="dgrid">'+cards+'</div>';}
function updInvBadge(){var arr=LAST||[];var act=0;arr.forEach(function(d){if(statusOf(d)!=='off')act++;});var b=document.getElementById('inv-badge');if(b)b.textContent=act?(''+act):'';}
function ensureLeaflet(cb){if(window.L||window.__lfTried){cb();return;}window.__lfTried=true;var css=document.createElement('link');css.rel='stylesheet';css.href='/bin/leaflet.css';document.head.appendChild(css);var s=document.createElement('script');s.src='/bin/leaflet.js';s.onload=cb;s.onerror=cb;document.head.appendChild(s);}
function showMap(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;CVE_ON=false;SET_ON=false;MAP_ON=true;SEL=null;highlight();hideViews();document.getElementById('map-view').style.display='block';setNav('map');document.getElementById('map-svg').innerHTML='<div class="dim2" style="font-size:12px">Locating devices…</div>';ensureLeaflet(loadMap);}
function loadMap(){fetch('/x/geo').then(function(r){return r.json();}).then(function(j){renderMap((j&&j.devices)||[]);}).catch(function(){document.getElementById('map-svg').innerHTML='<div class="aud-empty">Could not load map.</div>';});}
function renderMap(devs){var loc=devs.filter(function(d){return d.lat!=null&&d.lon!=null;});var un=devs.filter(function(d){return d.lat==null||d.lon==null;});document.getElementById('map-count').textContent=loc.length+' located · '+un.length+' unlocated'+(window.L?'':' · offline map');document.getElementById('map-un').innerHTML=un.length?('<div class="map-unh">Unlocated (LAN / private IP):</div>'+un.map(function(d){return '<span class="chip map-unc" onclick="select(\''+attrEsc(d.base)+'\')">'+esc2(d.name)+'</span>';}).join('')):'';if(window.L){renderLeaflet(loc);}else{renderGraticule(loc);}}
function renderLeaflet(loc){var el=document.getElementById('map-svg');el.innerHTML='<div id="lmap" style="height:440px;border-radius:10px;overflow:hidden;border:1px solid var(--line2)"></div>';if(LMAP){LMAP.remove();LMAP=null;}LMAP=L.map('lmap').setView([20,0],2);L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:18,attribution:'© OpenStreetMap'}).addTo(LMAP);var pts=[],groups={};loc.forEach(function(d){var k=(+d.lat).toFixed(2)+','+(+d.lon).toFixed(2);(groups[k]=groups[k]||[]).push(d);});Object.keys(groups).forEach(function(k){var g=groups[k],d0=g[0],lat=+d0.lat,lon=+d0.lon,n=g.length;var mk=L.circleMarker([lat,lon],{radius:n>1?9:7,weight:1,color:'#fff',fillColor:n>1?'#f5a623':'#5b9dff',fillOpacity:.9}).addTo(LMAP);var pop=g.map(function(d){return '<span class="cve-id" style="cursor:pointer" onclick="select(\''+attrEsc(d.base)+'\')">'+esc2(d.name)+'</span>';}).join('<br>');mk.bindPopup('<b>'+esc2((d0.city?d0.city+', ':'')+(d0.country||''))+'</b>'+(n>1?(' — '+n+' devices'):'')+'<br>'+pop);if(n>1)mk.bindTooltip(''+n,{permanent:true,direction:'center',className:'clabel'});pts.push([lat,lon]);});if(pts.length)LMAP.fitBounds(pts,{padding:[40,40],maxZoom:6});setTimeout(function(){if(LMAP)LMAP.invalidateSize();},120);}
function renderGraticule(loc){var grid='',i;for(i=0;i<=360;i+=30)grid+='<line x1="'+i+'" y1="0" x2="'+i+'" y2="180"/>';for(i=0;i<=180;i+=30)grid+='<line x1="0" y1="'+i+'" x2="360" y2="'+i+'"/>';var pins=loc.map(function(d){var x=(+d.lon)+180,y=90-(+d.lat);return '<g class="pin" onclick="select(\''+attrEsc(d.base)+'\')"><circle cx="'+x.toFixed(1)+'" cy="'+y.toFixed(1)+'" r="2.6"/><title>'+esc2(d.name+' — '+((d.city?d.city+', ':'')+(d.country||'')))+'</title></g>';}).join('');document.getElementById('map-svg').innerHTML='<svg viewBox="0 0 360 180" class="worldsvg"><rect x="0" y="0" width="360" height="180" class="mapbg"/><g class="grat">'+grid+'</g>'+pins+'</svg>';}
var CVE_ON=false;
function showCVE(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;SET_ON=false;CVE_ON=true;SEL=null;highlight();hideViews();document.getElementById('cve-view').style.display='block';setNav('cve');document.getElementById('cve-q').focus();}
function sevCls(s){s=(s||'').toUpperCase();return s==='CRITICAL'?'sev-crit':s==='HIGH'?'sev-high':s==='MEDIUM'?'sev-med':s==='LOW'?'sev-low':'sev-none';}
function searchCVE(){var q=document.getElementById('cve-q').value.trim();if(!q)return;var el=document.getElementById('cve-list');el.innerHTML='<div class="dim2" style="font-size:12px">Querying NVD…</div>';document.getElementById('cve-count').textContent='';fetch('/x/cve?q='+encodeURIComponent(q)).then(function(r){return r.json();}).then(function(j){renderCVE((j&&j.cves)||[]);}).catch(function(){el.innerHTML='<div class="aud-empty">NVD query failed (rate-limited? try again).</div>';});}
function renderCVE(arr){document.getElementById('cve-count').textContent=arr.length+' CVEs';var el=document.getElementById('cve-list');if(!arr.length){el.innerHTML='<div class="aud-empty">No CVEs found for that term.</div>';return;}el.innerHTML=arr.map(function(c){var sc=(c.score!=null)?c.score:'—';return '<div class="cve-row"><div class="cve-head"><a class="cve-id" href="https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(c.id)+'" target="_blank" rel="noopener">'+esc2(c.id)+'</a><span class="cve-sev '+sevCls(c.severity)+'">'+esc2(c.severity||'—')+' '+sc+'</span><span class="dim2">'+esc2(c.published||'')+'</span></div><div class="cve-sum">'+esc2(c.summary||'')+'</div></div>';}).join('');}
var SET_ON=false;
function showSettings(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=true;SEL=null;highlight();hideViews();document.getElementById('settings-view').style.display='block';setNav('settings');loadSettings();}
function loadSettings(){fetch('/x/settings').then(function(r){return r.json();}).then(function(j){document.getElementById('set-au').value=j.agent_update||'manual';document.getElementById('set-ver').textContent='serving v'+(j.server_version||'');}).catch(function(){});}
function saveAgentUpdate(){var m=document.getElementById('set-au').value;fetch('/x/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_update:m})}).then(function(r){return r.json();}).then(function(){}).catch(function(){});}
var CMP_CHECKS=[['disk encryption','encryption'],['firewall','firewall'],['antivirus','av'],['OS updates','updates']];
var CMP_FW=['CIS','NIST 800-53','PCI-DSS','HIPAA','ISO 27001','Essential Eight'];
function showCompliance(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;COMPLIANCE_ON=true;SEL=null;highlight();hideViews();document.getElementById('compliance-view').style.display='block';setNav('compliance');var s=document.getElementById('cmp-fw');if(!s.options.length){s.innerHTML=CMP_FW.map(function(f){return '<option>'+esc2(f)+'</option>';}).join('');}renderCompliance();}
function runCompliance(){var b=document.getElementById('cmp-body');b.innerHTML='<tr><td colspan="6" class="ov-empty">Running posture on every device…</td></tr>';fetch('/x/compliance-fleet').then(function(r){return r.json();}).then(function(j){CMP_DATA=j;renderCompliance();}).catch(function(){b.innerHTML='<tr><td colspan="6" class="ov-empty">Failed to run.</td></tr>';});}
function renderCompliance(){var fw=document.getElementById('cmp-fw').value||CMP_FW[0];var leg=(CMP_DATA&&CMP_DATA.legend)||{};document.getElementById('cmp-head').innerHTML='<tr><th>Device</th><th class="ov-num">Grade</th>'+CMP_CHECKS.map(function(c){var ctl=(leg[c[1]]&&leg[c[1]][fw])?('<div class="cmp-ctl">'+esc2(leg[c[1]][fw])+'</div>'):'';return '<th>'+esc2(c[0])+ctl+'</th>';}).join('')+'</tr>';var body=document.getElementById('cmp-body');if(!CMP_DATA){body.innerHTML='<tr><td colspan="6" class="ov-empty">Click “Run across fleet ▶”.</td></tr>';return;}var res=CMP_DATA.results||[];if(!res.length){body.innerHTML='<tr><td colspan="6" class="ov-empty">No devices.</td></tr>';return;}body.innerHTML=res.map(function(d){var by={};(d.checks||[]).forEach(function(c){by[c.kind]=c.pass;});var cells=CMP_CHECKS.map(function(c){var p=by[c[1]];return '<td class="ov-num '+(p?'cmp-pass':'cmp-fail')+'">'+(p?'✓':'✗')+'</td>';}).join('');return '<tr><td class="ov-nm">'+esc2(d.device||'?')+'</td><td class="ov-num cmp-g cmp-'+esc2(d.grade||'F')+'">'+esc2(d.grade||'?')+' <span class="dim2">'+(d.score!=null?d.score:'')+'</span></td>'+cells+'</tr>';}).join('');}
function showOverview(){AUDIT_ON=false;OVERVIEW_ON=true;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;SEL=null;highlight();hideViews();document.getElementById('overview-view').style.display='block';setNav('overview');renderOverview(LAST);}
function showScripts(){AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=true;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;SEL=null;highlight();hideViews();document.getElementById('scripts-view').style.display='block';setNav('scripts');fillScrTargets();searchScripts();document.getElementById('scr-q').focus();}
function fillScrTargets(){var s=document.getElementById('scr-target');var cur=s.value;var h='<option value="__FLEET__">All devices (fleet)</option>';(LAST||[]).forEach(function(d){h+='<option value="'+attrEsc(baseOf(d))+'">'+esc2(d.name||d.hostname||d.ip)+'</option>';});s.innerHTML=h;if(cur)s.value=cur;}
function searchScripts(){var q=document.getElementById('scr-q').value.trim();fetch('/scripts?q='+encodeURIComponent(q)).then(function(r){return r.json();}).then(function(j){renderScripts((j&&j.scripts)||[],j&&j.total);}).catch(function(){document.getElementById('scr-list').innerHTML='<div class="aud-empty">Could not load the script library.</div>';});}
function renderScripts(arr,total){document.getElementById('scr-count').textContent=arr.length+(total?(' of '+total):'')+' scripts';var el=document.getElementById('scr-list');if(!arr.length){el.innerHTML='<div class="aud-empty">No matching scripts.</div>';return;}el.innerHTML=arr.map(function(s){var pl=(s.platforms||[]).map(function(p){return '<span class="chip">'+esc2(p)+'</span>';}).join('');var cust=s.custom?'<span class="chip cust">custom</span>':'';var cat=s.category?('<span class="scr-cat">'+esc2(s.category)+'</span>'):'';var del=s.custom?('<button class="b subtle scr-del" title="delete this custom script" onclick="deleteScript(event,\''+attrEsc(s.filename)+'\')">✕</button>'):'';return '<div class="scr-row"><div class="scr-main"><div class="scr-nm">'+cust+esc2(s.name||s.filename)+'</div><div class="scr-desc">'+esc2(s.description||'')+'</div><div class="scr-meta">'+pl+cat+'</div></div>'+del+'<button class="b" onclick="runScript(this,\''+attrEsc(s.filename)+'\')">Run ▶</button></div>';}).join('');}
function toggleScrForm(){var f=document.getElementById('scr-form');f.style.display=(f.style.display==='none')?'block':'none';document.getElementById('sf-msg').textContent='';if(f.style.display==='block')document.getElementById('sf-name').focus();}
function submitScript(){var name=document.getElementById('sf-name').value.trim();var bodyv=document.getElementById('sf-body').value;var msg=document.getElementById('sf-msg');if(!name||!bodyv.trim()){msg.textContent='name and script body are required';return;}msg.textContent='saving…';fetch('/x/script-add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,description:document.getElementById('sf-desc').value,shell:document.getElementById('sf-shell').value,platforms:document.getElementById('sf-plat').value.split(','),body:bodyv})}).then(function(r){return r.json();}).then(function(j){if(j.ok){document.getElementById('sf-name').value='';document.getElementById('sf-desc').value='';document.getElementById('sf-body').value='';toggleScrForm();searchScripts();}else{msg.textContent=j.error||'failed';}}).catch(function(){msg.textContent='request failed';});}
function deleteScript(ev,file){ev.stopPropagation();if(!confirm('Delete this custom script?'))return;fetch('/x/script-delete?file='+encodeURIComponent(file)).then(function(r){return r.json();}).then(function(){searchScripts();}).catch(function(){});}
function runScript(btn,file){var s=document.getElementById('scr-target');var tgt=s.value;var label=s.options[s.selectedIndex].text;var o=document.getElementById('scr-out');o.style.display='block';o.innerHTML='<div class="scr-run">Running <b>'+esc2(file)+'</b> on <b>'+esc2(label)+'</b>…</div>';btn.disabled=true;var url=(tgt==='__FLEET__')?('/x/script-fleet?file='+encodeURIComponent(file)):('/x/script?target='+encodeURIComponent(tgt)+'&file='+encodeURIComponent(file));fetch(url).then(function(r){return r.json();}).then(function(j){btn.disabled=false;if(j.results){o.innerHTML='<div class="scr-run">'+esc2(file)+' on '+j.count+' device'+(j.count===1?'':'s')+':</div>'+j.results.map(function(x){return '<div class="scr-dev">'+esc2(x.device)+'</div><pre class="scr-pre">'+esc2(x.output||'')+'</pre>';}).join('');}else if(j.ok){o.innerHTML='<div class="scr-run">'+esc2(file)+' on '+esc2(j.device||label)+':</div><pre class="scr-pre">'+esc2(j.output||'(no output)')+'</pre>';}else{o.innerHTML='<div class="scr-run err">'+esc2(file)+': '+esc2(j.error||'failed')+'</div>';}}).catch(function(){btn.disabled=false;o.innerHTML='<div class="scr-run err">request failed</div>';});}
var OV_SORT={key:'name',dir:1};
function ovSort(k){if(OV_SORT.key===k){OV_SORT.dir*=-1;}else{OV_SORT.key=k;OV_SORT.dir=1;}renderOverview(LAST);}
function ovVal(d,k){switch(k){case 'name':return (d.name||d.hostname||d.ip||'').toLowerCase();case 'os':return (d.os||'').toLowerCase();case 'user':return (d.user||'').toLowerCase();case 'cpu':return (d.cpu_pct==null?-1:d.cpu_pct);case 'ram':return (d.free_gb==null?-1:d.free_gb);case 'seen':return (d.last_seen_secs==null?1e9:d.last_seen_secs);case 'status':return ({on:0,idle:1,off:2}[statusOf(d)]);default:return 0;}}
function renderOverview(arr){arr=arr||[];var on=0,idle=0,off=0,mcp=0,lsum=0,ln=0;arr.forEach(function(d){var s=statusOf(d);if(s==='on')on++;else if(s==='idle')idle++;else off++;if(d.mcp_active)mcp++;if(d.cpu_pct!=null){lsum+=d.cpu_pct;ln++;}});var avg=ln?Math.round(lsum/ln)+'%':'—';document.getElementById('ov-summary').innerHTML='<span class="ovs"><b>'+arr.length+'</b> devices</span><span class="ovs"><span class="dot on"></span>'+on+' online</span><span class="ovs"><span class="dot idle"></span>'+idle+' idle</span><span class="ovs"><span class="dot off"></span>'+off+' stale</span><span class="ovs">avg CPU <b>'+avg+'</b></span>'+(mcp?'<span class="ovs mcp-live">🤖⇄ '+mcp+' active</span>':'');var body=document.getElementById('ov-body');if(!arr.length){body.innerHTML='<tr><td colspan="12" class="ov-empty">No devices.</td></tr>';return;}var sorted=arr.slice();sorted.sort(function(a,b){var va=ovVal(a,OV_SORT.key),vb=ovVal(b,OV_SORT.key);return (va<vb?-1:va>vb?1:0)*OV_SORT.dir;});body.innerHTML=sorted.map(function(d){var b=baseOf(d);var nm=d.name||d.hostname||d.ip;var load=(d.cpu_pct!=null)?('<span class="dl-load '+loadCls(d.cpu_pct)+'">'+Math.round(d.cpu_pct)+'%</span>'):'—';var ram=(d.free_gb!=null&&d.mem_gb)?(d.free_gb.toFixed(1)+' / '+d.mem_gb+' GB'):'—';var addr=d.scheme==='relay'?('relay · '+d.ip):(d.ip+':'+d.port);var cams=(d.cameras||[]).length;var mics=(d.microphones||[]).length;var m=d.mcp_active?'<span class="mcp-live" title="AI agent accessing now">🤖⇄</span>':'';return '<tr class="ov-row" data-base="'+attrEsc(b)+'"><td><span class="dot '+statusOf(d)+'"></span></td><td class="ov-nm">'+esc2(nm)+'</td><td>'+esc2((d.os||'')+(d.arch?(' '+d.arch):''))+'</td><td>'+esc2(d.user||'—')+'</td><td class="ov-num">'+load+'</td><td class="ov-num">'+esc2(ram)+'</td><td class="ov-num">'+esc2(''+(d.cores||'—'))+'</td><td class="ov-num">'+(cams||'—')+'</td><td class="ov-num">'+(mics||'—')+'</td><td class="mono">'+esc2(addr)+'</td><td>'+esc2(seenTxt(d.last_seen_secs)||'—')+'</td><td>'+m+'</td></tr>';}).join('');}
function runFleet(){var c=document.getElementById('fleet-cmd').value;if(!c)return;var n=(LAST||[]).length;if(!confirm('Run this command on ALL '+n+' device'+(n===1?'':'s')+'?\n\n'+c))return;var el=document.getElementById('fleet-results');el.innerHTML='<div class="aud-empty">running on all devices…</div>';fetch('/x/fleet?kind=exec&cmd='+enc(c)).then(function(r){return r.json();}).then(function(j){var rs=j.results||[];if(!rs.length){el.innerHTML='<div class="aud-empty">No devices.</div>';return;}el.innerHTML=rs.map(function(r){return '<div class="fleet-card"><div class="fleet-dev">'+esc2(r.device)+'</div><pre class="fleet-out">'+esc2(r.output||'')+'</pre></div>';}).join('');}).catch(function(e){el.innerHTML='<div class="aud-empty">error: '+esc2(''+e)+'</div>';});}
var AUD_ALL=[];
function loadAudit(){fetch('/audit').then(function(r){return r.json();}).then(function(j){AUD_ALL=j.audit||[];renderAudit();}).catch(function(){});}
function renderAudit(){var q=(document.getElementById('aud-q')||{}).value;q=(q||'').toLowerCase();var el=document.getElementById('audit-rows');var ev=q?AUD_ALL.filter(function(e){return ((e.source||'')+' '+(e.action||'')+' '+(e.device||'')+' '+(e.actor||'')+' '+(e.detail||'')).toLowerCase().indexOf(q)>=0;}):AUD_ALL;if(!ev.length){el.innerHTML='<div class="aud-empty">'+(AUD_ALL.length?'No matching events.':'No device actions recorded yet.')+'</div>';return;}el.innerHTML=ev.map(function(e){return '<div class="aud-row"><span class="aud-when">'+agoTxt(e.secs)+'</span><span class="aud-src '+(e.source||'')+'">'+esc2(e.source||'')+'</span><span class="aud-act">'+esc2(e.action||'')+'</span><span class="aud-dev">'+esc2(e.device||'')+'</span><span class="aud-actor">'+esc2(e.actor||'—')+'</span><span class="aud-detail" title="'+attrEsc(e.detail||'')+'">'+esc2(e.detail||'')+'</span></div>';}).join('');}
function select(base){if(!DEV[base])return;SEL=base;highlight();renderDetail(DEV[base]);}
function highlight(){var lis=document.querySelectorAll('.dev-li');for(var i=0;i<lis.length;i++){lis[i].classList.toggle('sel',lis[i].getAttribute('data-base')===SEL);}}
function renderDetail(d){DASH_ON=false;AUDIT_ON=false;OVERVIEW_ON=false;SCRIPTS_ON=false;COMPLIANCE_ON=false;SCHED_ON=false;RECS_ON=false;MAP_ON=false;CVE_ON=false;SET_ON=false;hideViews();document.getElementById('detail').style.display='block';setNav('');refreshHead(d);document.getElementById('d-controls').innerHTML=buildControls(d);resetTerm();stopView();var o=document.getElementById('out');o.style.display='none';o.textContent='';}
function refreshHead(d){var relay=d.scheme==='relay';document.getElementById('d-dot').className='dot '+statusOf(d);document.getElementById('d-name').textContent=d.name||d.hostname||d.ip;document.getElementById('d-sub').textContent=(relay?('relay · '+d.ip):(((d.hostname&&d.hostname!==d.name)?(d.hostname+'  ·  '):'')+d.ip+':'+d.port))+'  ·  '+seenTxt(d.last_seen_secs);var op=document.getElementById('d-open');if(relay){op.style.display='none';}else{op.style.display='';op.href=SEL+'/';}document.getElementById('d-specs').innerHTML=specHtml(d);document.getElementById('d-activity').innerHTML=activityHtml(d);}
function loadCls(p){return p<60?'':(p<85?'warn':'hot');}
function meter(label,val,pct,cls){pct=Math.max(0,Math.min(100,pct));return '<div class="meter"><div class="meter-top"><span>'+label+'</span><span>'+val+'</span></div><div class="meter-bar"><div class="meter-fill '+cls+'" style="width:'+pct+'%"></div></div></div>';}
function metersHtml(d){var m='';if(d.cpu_pct!=null){m+=meter('CPU load',d.cpu_pct.toFixed(0)+'%',d.cpu_pct,loadCls(d.cpu_pct));}if(d.free_gb!=null&&d.mem_gb){var used=d.mem_gb-d.free_gb;var up=used/d.mem_gb*100;m+=meter('RAM',d.free_gb.toFixed(1)+' GB free of '+d.mem_gb,up,loadCls(up));}return m?('<div class="meters">'+m+'</div>'):'';}
function specHtml(d){function sp(l,v){return (v!=null&&v!=='')?('<span class="spec"><span class="sl">'+l+'</span><span class="sv">'+esc2(v)+'</span></span>'):'';}var ifs='';(d.interfaces||[]).forEach(function(i){if(!i.addr||i.addr.indexOf('fe80')===0||i.addr==='::1'||i.addr.indexOf('127.')===0)return;ifs+='<span class="chip"><b>'+esc2(i.name)+'</b> '+esc2(i.addr)+'</span>';});var mics='';(d.microphones||[]).forEach(function(m){mics+='<span class="chip mic">🎙 '+esc2(m)+'</span>';});var chips=(ifs||mics)?('<div class="chiprow">'+ifs+mics+'</div>'):'';var av=d.agent_version||'',sv=(window.HB&&window.HB.ver)||'';var agln=av?('v'+av+(sv?(av===sv?' (current)':(' — update to '+sv)):'')):(sv?(sv+' available from hub'):'');return sp('Hostname',d.hostname)+sp('OS',(d.os||'')+(d.arch?(' ('+d.arch+')'):''))+sp('User',d.user)+sp('CPU',d.cpu)+sp('Cores',d.cores)+sp('Memory',d.mem_gb?(d.mem_gb+' GB total'):'')+sp('Agent',agln)+metersHtml(d)+chips;}
function camSelect(d){var o='';d.cameras.forEach(function(c,i){o+='<option value="'+i+'">'+esc2(c)+'</option>';});return '<select class="campick" id="campick" title="select camera">'+o+'</select>';}
var ROWS=[
{nm:'System report',d:'Pull a system report from the device.',sched:1,opts:[['Hardware','hardware'],['Installed software','packages'],['Running services','services'],['Top processes','processes'],['Network neighbors','network'],['Available updates','updates'],['Power / battery','power_report']]},
{nm:'Compliance check',d:'Score encryption, firewall, antivirus and updates (A–F grade).',kind:'posture',sched:1},
{nm:'Security status',d:'Check a security control on the device.',sched:1,opts:[['Encryption','encryption'],['Firewall','firewall'],['Antivirus','av']]},
{nm:'Firewall control',d:'Enable or disable the firewall.',sched:1,danger:1,opts:[['Turn ON','firewall_on'],['Turn OFF','firewall_off']]},
{nm:'USB storage',d:'Lock or unlock USB mass storage (Windows).',sched:1,danger:1,opts:[['Lock','usb_lock'],['Unlock','usb_unlock']]},
{nm:'Install / uninstall',d:'Install or remove a package (winget / brew / apt).',sched:1,arg:'package id',opts:[['Install','install'],['Uninstall','uninstall']]},
{nm:'Install all updates',d:'Apply every available OS / app update.',kind:'update_all',sched:1,danger:1},
{nm:'Power',d:'Restart, shut down, sleep, or log the user off.',sched:1,danger:1,opts:[['Restart','reboot'],['Shut down','shutdown'],['Sleep','sleep'],['Log off','logoff']]},
{nm:'Message the user',d:'Pop up a message to the logged-in user.',kind:'message',arg:'message text',sched:1},
{nm:'Run a command',d:'Run a shell command and return its output.',kind:'exec',arg:'command',sched:1},
{nm:'Launch an app (no wait)',d:'Start a program and return immediately — for GUI apps that would otherwise block.',kind:'launch',arg:'command, e.g. cmd /C start "" notepad.exe'}
];
var PLUGINS=[];
var IC_SEND='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" class="ic"><path d="m6 17 5-5-5-5"/><path d="m13 17 5-5-5-5"/></svg>';
var IC_LATER='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="ic"><path d="m3 16 4-4-4-4"/><path d="m9 16 4-4-4-4"/><circle cx="18" cy="17" r="4.2"/><path d="M18 15.3V17l1.2 1"/></svg>';
function allRows(){return ROWS.concat(PLUGINS.map(function(p){return {nm:p.name,d:p.description,kind:p.id,arg:p.arg||'',sched:1,plugin:1};}));}
function loadPlugins(){fetch('/plugins').then(function(r){return r.json();}).then(function(j){PLUGINS=(j&&j.plugins)||[];var dc=document.getElementById('d-controls');if(dc&&SEL&&DEV[SEL]&&dc.querySelector('.alist'))dc.innerHTML=buildControls(DEV[SEL]);}).catch(function(){});}
function actionListHtml(){return '<div class="blabel" style="margin:2px 0 6px">Actions</div><div class="alist">'+allRows().map(function(r,i){var ctl='';if(r.opts){ctl+='<select class="scr-sel arow-opt">'+r.opts.map(function(o){return '<option value="'+attrEsc(o[1])+'">'+esc2(o[0])+'</option>';}).join('')+'</select>';}if(r.arg){ctl+='<input class="devsearch arow-arg" placeholder="'+attrEsc(r.arg)+'" autocomplete="off">';}ctl+='<button class="b bsend'+(r.danger?' danger':'')+'" title="Execute now" onclick="execRow('+i+')">'+IC_SEND+'</button>';if(r.sched){ctl+='<button class="b subtle bsend arow-sbtn" title="Send later — schedule" onclick="schedRow('+i+')">'+IC_LATER+'</button>';}var sbar=r.sched?'<div class="arow-sched" style="display:none"><select class="scr-sel sch-type" onchange="schTypeChg('+i+')"><option value="once">Once, in</option><option value="interval">Every</option><option value="daily">Daily at</option></select><input class="devsearch sch-in sch-mins" type="number" min="1" value="60"><span class="sch-unit dim2">min</span><input class="devsearch sch-in sch-hhmm" type="time" value="09:00" style="display:none"><span class="dim2">UTC</span><button class="b" onclick="doSchedRow('+i+')">Schedule</button></div>':'';return '<div class="arow" data-i="'+i+'"><div class="arow-main"><div class="arow-nm">'+esc2(r.nm)+(r.plugin?' <span class="chip cust">plugin</span>':'')+'</div><div class="arow-desc">'+esc2(r.d)+'</div></div><div class="arow-ctl">'+ctl+'</div>'+sbar+'</div>';}).join('')+'</div>';}
function buildControls(d){var cam=d.cameras&&d.cameras.length;
var scr='<button class="b" onclick="doLive()" title="live screen video">● Live screen</button><button class="b" onclick="doShot()" title="screenshot">Screenshot</button>';
if(cam){scr+=camSelect(d)+'<button class="b" onclick="doCamSnap()" title="camera snapshot">Camera shot</button><button class="b" onclick="doCamLive()" title="live camera video">● Cam live</button>';}else{scr+='<span class="chip off">no camera</span>';}
var term='<button class="b" onclick="doShell()" title="open an interactive shell">Shell</button>';
var files='<button class="b" onclick="doGet()" title="download a file">Get file</button><button class="b" onclick="doPut()" title="upload a file">Put file</button>';
var av=d.agent_version||'',sv=(window.HB&&window.HB.ver)||'';var updlbl=(av&&sv&&av===sv)?('Update ✓ '+sv):(sv?('Update → '+sv):'Update');var updtt=(av?('agent v'+av):'agent version unknown')+(sv?(' · server v'+sv):'');
var agent='<button class="b subtle" onclick="doUpd()" title="'+attrEsc(updtt)+'">'+updlbl+'</button><button class="b danger" onclick="doDis()" title="dissolve agent (stop + remove autostart)">Dissolve</button>';
function g(l,b){return '<div class="bgroup"><span class="blabel">'+l+'</span><div class="brow">'+b+'</div></div>';}
var groups='<div class="controls">'+g('Screen &amp; camera',scr)+g('Terminal',term)+g('Files',files)+g('Agent',agent)+'</div>';
return groups+actionListHtml();}
function rowOf(i){return document.querySelector('.arow[data-i="'+i+'"]');}
function rowKind(r,row){return r.opts?row.querySelector('.arow-opt').value:r.kind;}
function rowArg(r,row){var a=row.querySelector('.arow-arg');return a?a.value.trim():'';}
function runKind(kind,arg){if(kind==='exec'||kind==='launch'){var dt=kind==='launch';out((dt?'launch ':'$ ')+arg+'\n…');fetch('/x/exec',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:SEL,cmd:arg,detach:dt})}).then(function(r){return r.json();}).then(function(j){out((dt?'launch ':'$ ')+arg+'\n'+(j.detached?('launched (pid '+j.pid+')'):(j.ok?(((j.stdout||'')+(j.stderr||''))||('exit '+j.code)):('[error] '+(j.error||'failed')))));}).catch(function(e){out('error: '+e);});}else if(kind==='posture'){doPosture();}else{sysCall(kind,arg);}}
function execRow(i){var r=allRows()[i],row=rowOf(i);var kind=rowKind(r,row),arg=rowArg(r,row);if(r.arg&&!arg){out('[enter '+r.arg+']');return;}if(r.danger&&!confirm(r.nm+' — run on this device now?'))return;runKind(kind,arg);}
function schedRow(i){var b=rowOf(i).querySelector('.arow-sched');b.style.display=(b.style.display==='none')?'flex':'none';}
function schTypeChg(i){var row=rowOf(i),t=row.querySelector('.sch-type').value;row.querySelector('.sch-mins').style.display=(t==='daily')?'none':'';row.querySelector('.sch-unit').style.display=(t==='daily')?'none':'';row.querySelector('.sch-hhmm').style.display=(t==='daily')?'':'none';}
function doSchedRow(i){var r=allRows()[i],row=rowOf(i);var kind=rowKind(r,row),arg=rowArg(r,row);if(r.arg&&!arg){out('[enter '+r.arg+']');return;}var t=row.querySelector('.sch-type').value,when={type:t};if(t==='daily'){when.hhmm=row.querySelector('.sch-hhmm').value;}else{when.mins=parseInt(row.querySelector('.sch-mins').value,10)||1;}out('scheduling '+r.nm+'…');fetch('/x/schedule-add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:SEL,kind:kind,arg:arg,label:r.nm,when:when})}).then(function(rr){return rr.json();}).then(function(j){out(j.ok?('Scheduled: '+r.nm+' ('+schedWhen(when)+'). See ⏰ Scheduled.'):('[error] '+(j.error||'failed')));row.querySelector('.arow-sched').style.display='none';}).catch(function(e){out('error: '+e);});}
function schedWhen(w){return w.type==='once'?('once, in '+w.mins+'m'):w.type==='interval'?('every '+w.mins+'m'):('daily '+w.hhmm+' UTC');}
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
(function(){var fbb=document.getElementById('fbbody');if(fbb){fbb.onclick=function(e){var row=e.target.closest('.fbrow');if(!row)return;var p=row.getAttribute('data-path');if(!p)return;if(row.getAttribute('data-dir')==='1'){fbLoad(p);}else if(fbMode==='get'){fbGet(p);}};}var ovb=document.getElementById('ov-body');if(ovb){ovb.onclick=function(e){var row=e.target.closest('.ov-row');if(!row)return;var b=row.getAttribute('data-base');if(b&&DEV[b])select(b);};}var scrq=document.getElementById('scr-q');if(scrq){var scrT;scrq.oninput=function(){clearTimeout(scrT);scrT=setTimeout(searchScripts,250);};scrq.onkeydown=function(e){if(e.key==='Enter'){clearTimeout(scrT);searchScripts();}};}var cveq=document.getElementById('cve-q');if(cveq){cveq.onkeydown=function(e){if(e.key==='Enter')searchCVE();};}loadPlugins();fetchAgents();setInterval(function(){fetchAgents();if(AUDIT_ON)loadAudit();},5000);})();
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
