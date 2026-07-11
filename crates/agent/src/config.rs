// Server-driven agent config: keep the enrollment command minimal and pull the
// rest (e.g. whether to show the tray icon) from the hub, refreshed periodically.
use std::sync::atomic::{AtomicBool, Ordering};

static TRAY: AtomicBool = AtomicBool::new(true);

/// Whether the hub wants a tray/menu-bar icon shown while the agent runs.
#[allow(dead_code)]
pub fn tray_enabled() -> bool {
    TRAY.load(Ordering::Relaxed)
}

/// Poll `{hub}/relay/config` every 60s and apply the returned config.
pub fn start_poll(hub: String, token: Option<String>) {
    std::thread::spawn(move || loop {
        let mut url = format!("{}/relay/config", hub.trim_end_matches('/'));
        if let Some(t) = token.as_deref() {
            url.push_str(&format!("?tok={t}"));
        }
        if let Ok(r) = ureq::get(&url).call() {
            if let Ok(v) = r.into_json::<serde_json::Value>() {
                if let Some(tray) = v.get("tray").and_then(|x| x.as_bool()) {
                    TRAY.store(tray, Ordering::Relaxed);
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(60));
    });
}
