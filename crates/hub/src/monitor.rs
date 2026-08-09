// #27 Monitoring + alerting. A background tick (piggybacking the 30s scheduler
// sweep) evaluates every device's live metrics + online status against thresholds
// from $HUB_DATA/monitor.json, records alerts to an in-memory ring, and — if a
// webhook is configured — POSTs them (Slack/Teams/PagerDuty-shaped `{"text": …}`).
// A per-(device,rule) cooldown prevents alert storms. Defaults are conservative so
// an unconfigured hub stays quiet until an admin sets thresholds.
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

struct Cfg {
    cpu_pct_max: f64,
    free_gb_min: f64,
    offline_secs: u64,
    cooldown_secs: u64,
    webhook_url: String,
}

fn cfg() -> Cfg {
    let v: serde_json::Value = std::fs::read(crate::data_dir().join("monitor.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    Cfg {
        cpu_pct_max: v.get("cpu_pct_max").and_then(|x| x.as_f64()).unwrap_or(95.0),
        free_gb_min: v.get("free_gb_min").and_then(|x| x.as_f64()).unwrap_or(0.3),
        offline_secs: v.get("offline_secs").and_then(|x| x.as_u64()).unwrap_or(600),
        cooldown_secs: v.get("cooldown_secs").and_then(|x| x.as_u64()).unwrap_or(1800),
        webhook_url: v.get("webhook_url").and_then(|x| x.as_str()).unwrap_or("").to_string(),
    }
}

fn alerts() -> &'static Mutex<VecDeque<serde_json::Value>> {
    static A: OnceLock<Mutex<VecDeque<serde_json::Value>>> = OnceLock::new();
    A.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn cooldowns() -> &'static Mutex<HashMap<String, u64>> {
    static C: OnceLock<Mutex<HashMap<String, u64>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fire(device: &str, owner: &str, rule: &str, message: String, value: f64, webhook: &str) {
    let alert = serde_json::json!({
        "ts": now(), "device": device, "owner": owner, "rule": rule,
        "message": message, "value": value,
    });
    {
        let mut a = alerts().lock().unwrap();
        a.push_back(alert.clone());
        while a.len() > 200 {
            a.pop_front();
        }
    }
    if !webhook.is_empty() {
        let text = format!("[IT-AI] {device}: {}", alert["message"].as_str().unwrap_or(""));
        let payload = serde_json::json!({ "text": text });
        let _ = crate::http()
            .post(webhook)
            .header("content-type", "application/json")
            .body(payload.to_string())
            .send();
    }
}

/// Evaluate every device against the thresholds; fire (cooldown-gated) alerts.
pub fn tick(agents: &crate::Agents) {
    let c = cfg();
    let n = now();
    // Snapshot under the lock, then evaluate + deliver without holding it.
    let devices: Vec<(String, serde_json::Value, u64)> = {
        let map = agents.lock().unwrap();
        map.iter()
            .map(|(k, a)| (k.clone(), a.data.clone(), a.last.elapsed().map(|e| e.as_secs()).unwrap_or(0)))
            .collect()
    };
    for (key, data, since) in devices {
        let device = data
            .get("name")
            .and_then(|x| x.as_str())
            .or_else(|| data.get("hostname").and_then(|x| x.as_str()))
            .unwrap_or(&key)
            .to_string();
        let owner = data.get("owner").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let mut checks: Vec<(&str, String, f64)> = Vec::new();
        if since >= c.offline_secs {
            checks.push(("offline", format!("offline for {since}s"), since as f64));
        }
        if let Some(cpu) = data.get("cpu_pct").and_then(|x| x.as_f64()) {
            if cpu >= c.cpu_pct_max {
                checks.push(("cpu", format!("CPU load {cpu:.0}% ≥ {:.0}%", c.cpu_pct_max), cpu));
            }
        }
        if let Some(free) = data.get("free_gb").and_then(|x| x.as_f64()) {
            if free <= c.free_gb_min {
                checks.push(("ram", format!("free RAM {free:.1}GB ≤ {:.1}GB", c.free_gb_min), free));
            }
        }
        for (rule, msg, val) in checks {
            let ckey = format!("{key}|{rule}");
            let recent = cooldowns()
                .lock()
                .unwrap()
                .get(&ckey)
                .map(|&t| n.saturating_sub(t) < c.cooldown_secs)
                .unwrap_or(false);
            if recent {
                continue;
            }
            cooldowns().lock().unwrap().insert(ckey, n);
            fire(&device, &owner, rule, msg, val, &c.webhook_url);
        }
    }
}

/// Recent alerts for one owner (most recent first). None = all (dev/admin).
pub fn recent(owner: Option<&str>) -> Vec<serde_json::Value> {
    let a = alerts().lock().unwrap();
    a.iter()
        .rev()
        .filter(|al| match owner {
            Some(o) => al.get("owner").and_then(|x| x.as_str()) == Some(o),
            None => true,
        })
        .take(100)
        .cloned()
        .collect()
}
