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

const VERSION: &str = "2.1.0";
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
    let port: u16 = std::env::var("HUB_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8770);
    let mid = mac_id();
    let ip = local_ip();
    let _mdns = advertise(&mid, port, &ip);

    println!("HaiveControl hub {VERSION}");
    println!("   Mac ID:  {mid}");
    println!("   Dashboard: http://localhost:{port}/  (or http://{ip}:{port}/)");
    println!("   On a device run:  HaiveControl {mid}");

    let agents: Arc<Agents> = Arc::new(Mutex::new(HashMap::new()));
    let server = Arc::new(Server::http(format!("0.0.0.0:{port}")).expect("bind hub port"));
    let mut handles = Vec::new();
    for _ in 0..4 {
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
    // Live MJPEG streams pipe an endless reqwest body straight through tiny_http,
    // so they bypass the `Resp` match below (which expects a finite Cursor body).
    if method == Method::Get && (path == "/x/stream" || path == "/x/camstream") {
        proxy_stream(req, &url, &path);
        return;
    }
    let resp = match (&method, path.as_str()) {
        (Method::Post, "/register") => {
            register(&mut req, agents);
            Response::from_string("").with_status_code(204)
        }
        (Method::Get, "/agents") => json_agents(agents),
        (Method::Get, "/install.ps1") => text_resp(install_ps1(hub_ip, hub_port, mac_id), "text/plain; charset=utf-8"),
        (Method::Get, "/install.sh") => text_resp(install_sh(hub_ip, hub_port, mac_id), "text/plain; charset=utf-8"),
        (Method::Get, p) if p.starts_with("/bin/") => serve_bin(&p[5..]),
        (Method::Get, "/x/frame") => proxy_frame(&url),
        (Method::Get, "/x/camera") => proxy_camera(&url),
        (Method::Get, "/x/update") => proxy_update(&url, agents, hub_ip, hub_port),
        (Method::Get, "/x/dissolve") => proxy_dissolve(&url),
        (Method::Post, "/x/exec") => proxy_exec(&mut req),
        (Method::Get, "/x/download") => proxy_download(&url),
        (Method::Get, "/x/list") => proxy_list(&url),
        (Method::Post, "/x/upload") => proxy_upload(&mut req, &url),
        (Method::Get, "/live") => live_page(&url),
        (Method::Get, "/") => dashboard(agents, mac_id, hub_ip, hub_port),
        _ => Response::from_string("not found").with_status_code(404),
    };
    let _ = req.respond(resp);
}

fn text_resp(body: String, ct: &str) -> Resp {
    Response::from_string(body).with_header(hdr("Content-Type", ct))
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

/// Pipe an endless MJPEG stream from the agent straight to the browser. `path` is
/// `/x/stream` (screen) or `/x/camstream` (camera); the agent path drops the `/x`.
fn proxy_stream(req: Request, url: &str, path: &str) {
    let target = match query_param(url, "target") {
        Some(t) => t,
        None => {
            let _ = req.respond(Response::from_string("no target").with_status_code(400));
            return;
        }
    };
    let index = query_param(url, "index").unwrap_or_default();
    let sub = &path[2..]; // "/stream" | "/camstream"
    let mut agent_url = format!("{target}{sub}");
    if sub == "/camstream" && !index.is_empty() {
        agent_url = format!("{agent_url}?index={index}");
    }
    match http_stream().get(agent_url).send() {
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
    match http().get(format!("{target}/frame")).send().and_then(|r| r.bytes()) {
        Ok(b) => Response::from_data(b.to_vec()).with_header(hdr("Content-Type", "image/jpeg")),
        Err(_) => Response::from_string("frame failed").with_status_code(502),
    }
}

fn proxy_update(url: &str, agents: &Agents, hub_ip: &str, hub_port: u16) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let ip = target.split("://").nth(1).and_then(|s| s.split(':').next()).unwrap_or("").to_string();
    let platform = agents
        .lock()
        .unwrap()
        .get(&ip)
        .and_then(|a| a.data.get("platform").and_then(|p| p.as_str()).map(String::from))
        .unwrap_or_default();
    let asset = match platform.as_str() {
        "windows" => "HaiveControl-windows.exe",
        "macos" => "HaiveControl-macos",
        "linux" => "HaiveControl-linux",
        _ => return Response::from_string("unknown platform for device").with_status_code(400),
    };
    let dl = format!("http://{hub_ip}:{hub_port}/bin/{asset}");
    match http().post(format!("{target}/update")).json(&serde_json::json!({"url": dl})).send().and_then(|r| r.text()) {
        Ok(t) => Response::from_string(t).with_header(hdr("Content-Type", "text/plain")),
        Err(e) => Response::from_string(format!("update failed: {e}")).with_status_code(502),
    }
}

fn proxy_dissolve(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    match http().post(format!("{target}/dissolve")).send().and_then(|r| r.text()) {
        Ok(t) => Response::from_string(t).with_header(hdr("Content-Type", "text/plain")),
        Err(e) => Response::from_string(format!("dissolve failed: {e}")).with_status_code(502),
    }
}

fn proxy_camera(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let index = query_param(url, "index").unwrap_or_default();
    let agent_url = if index.is_empty() {
        format!("{target}/camera")
    } else {
        format!("{target}/camera?index={index}")
    };
    match http().get(agent_url).send() {
        Ok(r) if r.status().is_success() => match r.bytes() {
            Ok(b) => Response::from_data(b.to_vec()).with_header(hdr("Content-Type", "image/jpeg")),
            Err(_) => Response::from_string("camera read failed").with_status_code(502),
        },
        Ok(r) => Response::from_string(r.text().unwrap_or_else(|_| "camera failed".to_string())).with_status_code(502),
        Err(_) => Response::from_string("camera unreachable").with_status_code(502),
    }
}

fn proxy_exec(req: &mut Request) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let target = v.get("target").and_then(|x| x.as_str()).unwrap_or("");
    let cmd = v.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
    match http().post(format!("{target}/exec")).json(&serde_json::json!({"cmd": cmd})).send().and_then(|r| r.text()) {
        Ok(t) => Response::from_string(t).with_header(hdr("Content-Type", "application/json")),
        Err(e) => json_resp(&serde_json::json!({"ok": false, "error": e.to_string()})),
    }
}

fn proxy_download(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let path = query_param(url, "path").unwrap_or_default();
    let agent_url = format!("{target}/download?path={}", urlencode(&path));
    match http().get(agent_url).send() {
        Ok(r) => {
            let disp = r.headers().get("content-disposition").and_then(|h| h.to_str().ok()).unwrap_or("attachment").to_string();
            let bytes = r.bytes().map(|b| b.to_vec()).unwrap_or_default();
            Response::from_data(bytes).with_header(hdr("Content-Type", "application/octet-stream")).with_header(hdr("Content-Disposition", &disp))
        }
        Err(_) => Response::from_string("download failed").with_status_code(502),
    }
}

fn proxy_list(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let path = query_param(url, "path").unwrap_or_default();
    let agent_url = format!("{target}/list?path={}", urlencode(&path));
    match http().get(agent_url).send().and_then(|r| r.text()) {
        Ok(t) => Response::from_string(t).with_header(hdr("Content-Type", "application/json")),
        Err(_) => Response::from_string("{\"ok\":false,\"error\":\"list failed\"}")
            .with_header(hdr("Content-Type", "application/json")),
    }
}

fn proxy_upload(req: &mut Request, url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let ct = req.headers().iter().find(|h| h.field.equiv("Content-Type")).map(|h| h.value.as_str().to_string()).unwrap_or_default();
    let mut body = Vec::new();
    let _ = req.as_reader().read_to_end(&mut body);
    match http().post(format!("{target}/upload")).header("Content-Type", ct).body(body).send().and_then(|r| r.text()) {
        Ok(t) => Response::from_string(t).with_header(hdr("Content-Type", "application/json")),
        Err(e) => json_resp(&serde_json::json!({"ok": false, "error": e.to_string()})),
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
        if let Some(obj) = v.as_object_mut() {
            obj.insert("ip".to_string(), serde_json::Value::String(ip.clone()));
        }
        agents.lock().unwrap().insert(ip, Agent { data: v, last: Instant::now() });
    }
}

fn live(agents: &Agents) -> Vec<serde_json::Value> {
    let now = Instant::now();
    agents
        .lock()
        .unwrap()
        .values()
        .filter(|a| now.duration_since(a.last) < STALE)
        .map(|a| {
            let mut d = a.data.clone();
            if let Some(o) = d.as_object_mut() {
                o.insert(
                    "last_seen_secs".to_string(),
                    serde_json::json!(now.duration_since(a.last).as_secs()),
                );
            }
            d
        })
        .collect()
}

fn json_agents(agents: &Agents) -> Resp {
    json_resp(&serde_json::json!({"agents": live(agents)}))
}

fn dashboard(_agents: &Agents, mac_id: &str, hub_ip: &str, hub_port: u16) -> Resp {
    let hub = format!("{hub_ip}:{hub_port}");
    let win = cmd_block("Windows (PowerShell or cmd)", &format!("curl.exe -L -o airm.exe http://{hub}/bin/HaiveControl-windows.exe\n.\\airm.exe {hub} --id {mac_id}"));
    let mac = cmd_block("macOS", &format!("curl -L -o airm http://{hub}/bin/HaiveControl-macos && chmod +x airm\n./airm {hub} --id {mac_id}"));
    let lin = cmd_block("Linux", &format!("curl -L -o airm http://{hub}/bin/HaiveControl-linux && chmod +x airm\n./airm {hub} --id {mac_id}"));
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>HaiveControl hub</title>\n<style>{cp_css}</style></head>\n<body>\
<div class=\"app\">\
<aside class=\"side\">\
<div class=\"side-head\"><div><h1>HaiveControl <span class=\"dim2\">hub</span></h1><code>{mac_id}</code></div><span class=\"pill\" id=\"count\">…</span></div>\
<div class=\"legend\"><span><span class=\"dot on\"></span>online</span><span><span class=\"dot idle\"></span>idle</span><span><span class=\"dot off\"></span>stale</span></div>\
<ul id=\"devlist\" class=\"devlist\"></ul>\
<button class=\"addbtn\" onclick=\"toggleReg()\">+ Register a device</button>\
<div id=\"reg\" class=\"reg\" style=\"display:none\"><p class=\"reg-hint\">Download the agent, then run it:</p>{win}{mac}{lin}</div>\
</aside>\
<main class=\"stage\">\
<div class=\"stage-empty\" id=\"stage-empty\">Select a device from the left to control it.</div>\
<div id=\"detail\" style=\"display:none\">\
<div class=\"detail-head\"><div class=\"dh-id\"><span class=\"dot\" id=\"d-dot\"></span><div><div class=\"dh-name\" id=\"d-name\"></div><div class=\"dh-sub\" id=\"d-sub\"></div></div></div>\
<a class=\"dh-open\" id=\"d-open\" target=\"_blank\">Open agent&nbsp;↗</a></div>\
<div class=\"specs\" id=\"d-specs\"></div>\
<div class=\"controls\" id=\"d-controls\"></div>\
<div class=\"viewport\" id=\"viewport\"><div class=\"vp-hint\" id=\"vp-hint\">Press <b>Live screen</b>, <b>Screenshot</b>, or a <b>Camera</b> action — it renders here.</div><img id=\"view\" alt=\"\" style=\"display:none\"><div class=\"vp-tools\" id=\"vp-tools\" style=\"display:none\"><button class=\"b\" onclick=\"stopView()\">Stop</button><button class=\"b\" onclick=\"openTab()\">Open in tab&nbsp;↗</button></div></div>\
<pre class=\"output\" id=\"out\" style=\"display:none\"></pre>\
</div>\
</main>\
</div>{fb}{script}</body></html>",
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
.dl-txt{display:flex;flex-direction:column;min-width:0}
.dl-name{font-size:13px;font-weight:600;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.dl-meta{font-size:11px;color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
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
.viewport{position:relative;flex:1;min-height:340px;background:#000;border-radius:12px;border:1px solid var(--line);display:flex;align-items:center;justify-content:center;overflow:hidden}
.viewport img{max-width:100%;max-height:100%;object-fit:contain;display:block}
.vp-hint{color:var(--muted2);font-size:13px;padding:24px;text-align:center;line-height:1.6}
.vp-hint b{color:var(--muted)}
.vp-tools{position:absolute;top:10px;right:10px;display:flex;gap:6px;z-index:2}
.output{background:#0b0d13;border:1px solid var(--line);border-radius:10px;padding:12px 14px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#c3c9d8;white-space:pre-wrap;max-height:220px;overflow:auto}
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
var DEV={},SEL=null;
function baseOf(d){return d.scheme+'://'+d.ip+':'+d.port;}
function statusOf(d){var s=(d.last_seen_secs==null)?99999:d.last_seen_secs;return s<15?'on':(s<40?'idle':'off');}
function seenTxt(s){if(s==null)return '';return s<60?(s+'s ago'):(s<3600?(Math.floor(s/60)+'m ago'):(Math.floor(s/3600)+'h ago'));}
function fetchAgents(){fetch('/agents').then(function(r){return r.json();}).then(function(j){var arr=(j&&j.agents)||[];DEV={};arr.forEach(function(d){DEV[baseOf(d)]=d;});renderSide(arr);if(SEL&&DEV[SEL]){refreshHead(DEV[SEL]);}else if(SEL){SEL=null;showEmpty();}if(!SEL&&arr.length){select(baseOf(arr[0]));}}).catch(function(){});}
function renderSide(arr){var el=document.getElementById('devlist');document.getElementById('count').textContent=arr.length+' device'+(arr.length===1?'':'s');if(!arr.length){el.innerHTML='<li class="empty-li">No devices yet — register one below.</li>';return;}var h='';arr.forEach(function(d){var b=baseOf(d);var sel=(b===SEL)?' sel':'';h+='<li class="dev-li'+sel+'" data-base="'+attrEsc(b)+'"><span class="dot '+statusOf(d)+'"></span><span class="dl-txt"><span class="dl-name">'+esc2(d.name||d.hostname||d.ip)+'</span><span class="dl-meta">'+esc2(d.os||'')+' · '+seenTxt(d.last_seen_secs)+'</span></span></li>';});el.innerHTML=h;}
function showEmpty(){document.getElementById('detail').style.display='none';document.getElementById('stage-empty').style.display='block';}
function select(base){if(!DEV[base])return;SEL=base;highlight();renderDetail(DEV[base]);}
function highlight(){var lis=document.querySelectorAll('.dev-li');for(var i=0;i<lis.length;i++){lis[i].classList.toggle('sel',lis[i].getAttribute('data-base')===SEL);}}
function renderDetail(d){document.getElementById('stage-empty').style.display='none';document.getElementById('detail').style.display='block';refreshHead(d);document.getElementById('d-controls').innerHTML=buildControls(d);stopView();var o=document.getElementById('out');o.style.display='none';o.textContent='';}
function refreshHead(d){document.getElementById('d-dot').className='dot '+statusOf(d);document.getElementById('d-name').textContent=d.name||d.hostname||d.ip;document.getElementById('d-sub').textContent=((d.hostname&&d.hostname!==d.name)?(d.hostname+'  ·  '):'')+d.ip+':'+d.port+'  ·  '+seenTxt(d.last_seen_secs);document.getElementById('d-open').href=SEL+'/';document.getElementById('d-specs').innerHTML=specHtml(d);}
function specHtml(d){function sp(l,v){return v?('<span class="spec"><span class="sl">'+l+'</span><span class="sv">'+esc2(v)+'</span></span>'):'';}var ifs='';(d.interfaces||[]).forEach(function(i){if(!i.addr||i.addr.indexOf('fe80')===0||i.addr==='::1'||i.addr.indexOf('127.')===0)return;ifs+='<span class="chip"><b>'+esc2(i.name)+'</b> '+esc2(i.addr)+'</span>';});var mics='';(d.microphones||[]).forEach(function(m){mics+='<span class="chip mic">🎙 '+esc2(m)+'</span>';});var chips=(ifs||mics)?('<div class="chiprow">'+ifs+mics+'</div>'):'';return sp('OS',(d.os||'')+(d.arch?(' ('+d.arch+')'):''))+sp('User',d.user)+sp('CPU',d.cpu)+sp('Cores',d.cores)+sp('Memory',d.mem_gb?(d.mem_gb+' GB'):'')+chips;}
function camSelect(d){var o='';d.cameras.forEach(function(c,i){o+='<option value="'+i+'">'+esc2(c)+'</option>';});return '<select class="campick" id="campick" title="select camera">'+o+'</select>';}
function buildControls(d){var cam=d.cameras&&d.cameras.length;var h='';h+='<button class="b" onclick="doLive()" title="live screen video">● Live screen</button>';h+='<button class="b" onclick="doShot()" title="screenshot">Screenshot</button>';if(cam){h+=camSelect(d);h+='<button class="b" onclick="doCamSnap()" title="camera snapshot">Camera shot</button>';h+='<button class="b" onclick="doCamLive()" title="live camera video">● Cam live</button>';}else{h+='<span class="chip off">no camera</span>';}h+='<button class="b" onclick="doRun()" title="run a command">Run…</button>';h+='<button class="b" onclick="doGet()" title="download a file">Get file</button>';h+='<button class="b" onclick="doPut()" title="upload a file">Put file</button>';h+='<button class="b subtle" onclick="doUpd()" title="update agent">Update</button>';h+='<button class="b danger" onclick="doDis()" title="dissolve agent">Dissolve</button>';return h;}
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
(function(){var fbb=document.getElementById('fbbody');if(fbb){fbb.onclick=function(e){var row=e.target.closest('.fbrow');if(!row)return;var p=row.getAttribute('data-path');if(!p)return;if(row.getAttribute('data-dir')==='1'){fbLoad(p);}else if(fbMode==='get'){fbGet(p);}};}fetchAgents();setInterval(fetchAgents,5000);})();
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
