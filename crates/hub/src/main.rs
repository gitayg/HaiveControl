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
use tiny_http::{Header, Method, Request, Response, Server};

const VERSION: &str = "1.0.0";
const HUB_SERVICE: &str = "_rmtscrn._tcp.local.";
const STALE: Duration = Duration::from_secs(40);

type Resp = Response<std::io::Cursor<Vec<u8>>>;
type Agents = Mutex<HashMap<String, Agent>>;

struct Agent {
    name: String,
    ip: String,
    port: u16,
    scheme: String,
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
        let (s, a, m) = (server.clone(), agents.clone(), mid.clone());
        handles.push(std::thread::spawn(move || loop {
            match s.recv() {
                Ok(req) => handle(req, &a, &m),
                Err(_) => break,
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
}

fn handle(mut req: Request, agents: &Agents, mac_id: &str) {
    let method = req.method().clone();
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let resp = match (&method, path.as_str()) {
        (Method::Post, "/register") => {
            register(&mut req, agents);
            Response::from_string("").with_status_code(204)
        }
        (Method::Get, "/agents") => json_agents(agents),
        (Method::Get, "/") => dashboard(agents, mac_id),
        _ => Response::from_string("not found").with_status_code(404),
    };
    let _ = req.respond(resp);
}

fn register(req: &mut Request, agents: &Agents) {
    let remote_ip = req.remote_addr().map(|a| a.ip().to_string());
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
        let ip = v
            .get("ip")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string())
            .or(remote_ip)
            .unwrap_or_default();
        let agent = Agent {
            name: v.get("name").and_then(|x| x.as_str()).unwrap_or("?").to_string(),
            ip: ip.clone(),
            port: v.get("port").and_then(|x| x.as_u64()).unwrap_or(8765) as u16,
            scheme: v.get("scheme").and_then(|x| x.as_str()).unwrap_or("http").to_string(),
            last: Instant::now(),
        };
        agents.lock().unwrap().insert(ip, agent);
    }
}

fn live<'a>(agents: &'a Agents) -> Vec<(String, String, u16, String)> {
    let now = Instant::now();
    agents
        .lock()
        .unwrap()
        .values()
        .filter(|a| now.duration_since(a.last) < STALE)
        .map(|a| (a.name.clone(), a.ip.clone(), a.port, a.scheme.clone()))
        .collect()
}

fn json_agents(agents: &Agents) -> Resp {
    let list: Vec<_> = live(agents)
        .into_iter()
        .map(|(name, ip, port, scheme)| serde_json::json!({"name":name,"ip":ip,"port":port,"scheme":scheme}))
        .collect();
    json_resp(&serde_json::json!({"agents": list}))
}

fn dashboard(agents: &Agents, mac_id: &str) -> Resp {
    let rows: String = live(agents)
        .into_iter()
        .map(|(name, ip, port, scheme)| {
            format!(
                "<li><a href=\"{scheme}://{ip}:{port}/\" target=\"_blank\">{name}</a> <span>{ip}:{port}</span></li>"
            )
        })
        .collect();
    let empty = if rows.is_empty() { "<p>No devices registered yet.</p>" } else { "" };
    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\n<meta http-equiv=\"refresh\" content=\"5\"><title>HaiveControl hub</title>\n<style>body{{font-family:system-ui;background:#111;color:#ddd;max-width:640px;margin:40px auto;padding:0 16px}}h1{{font-size:18px}}li{{margin:8px 0}}a{{color:#4ea1ff;font-size:16px}}span{{color:#888;font-size:13px;margin-left:8px}}code{{background:#222;padding:2px 6px;border-radius:4px}}</style></head>\n<body><h1>HaiveControl hub — <code>{mac_id}</code></h1>\n<ul>{rows}</ul>{empty}\n<p style=\"color:#777;font-size:13px\">On a device run: <code>HaiveControl {mac_id}</code></p>\n</body></html>"
    );
    Response::from_string(html).with_header(hdr("Content-Type", "text/html"))
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
