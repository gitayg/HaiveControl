// Resolve the Mac hub by its Bonjour id and (re)register this agent every 15s.
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent};

const HUB_SERVICE: &str = "_rmtscrn._tcp.local.";

pub fn local_ip() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            Some(s.local_addr().ok()?.ip().to_string())
        })
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

pub fn register_loop(mac_id: String, name: String, port: u16, scheme: &'static str) {
    loop {
        if let Some((hub_ip, hub_port)) = resolve(&mac_id) {
            let url = format!("http://{hub_ip}:{hub_port}/register");
            let body = serde_json::json!({
                "name": name, "ip": local_ip(), "port": port, "scheme": scheme
            });
            let _ = ureq::post(&url).send_json(body);
        }
        std::thread::sleep(Duration::from_secs(15));
    }
}

fn resolve(mac_id: &str) -> Option<(String, u16)> {
    let mdns = ServiceDaemon::new().ok()?;
    let rx = mdns.browse(HUB_SERVICE).ok()?;
    let prefix = format!("{mac_id}.");
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut found = None;
    while Instant::now() < deadline {
        if let Ok(ServiceEvent::ServiceResolved(info)) = rx.recv_timeout(Duration::from_secs(1)) {
            if info.get_fullname().starts_with(&prefix) {
                if let Some(ip) = info.get_addresses().iter().next() {
                    found = Some((ip.to_string(), info.get_port()));
                    break;
                }
            }
        }
    }
    let _ = mdns.shutdown();
    found
}
