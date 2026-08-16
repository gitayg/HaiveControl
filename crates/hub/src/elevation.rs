// Just-In-Time (JIT) temporary local-admin elevation.
//
// Flow: a device user clicks "Request Admin" in the tray → the agent POSTs
// {minutes, reason} to the hub's /relay/request-elevation → the request lands
// here as `pending` and pops up in the owner's dashboard. On approve, the hub
// runs `net localgroup Administrators <user> /add` on the device and records a
// Grant with a revoke-at; a background sweep (in main.rs) runs the matching
// `/delete` when the window expires — even across a hub restart (Grants are
// persisted here) or while the device is offline (the revoke is queued for its
// next connect). This module owns only the state + persistence; dispatch and the
// sweeper live in main.rs where the relay/exec helpers are.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A pending/decided ask for temporary admin. In-memory (ephemeral) — a hub
/// restart drops undecided requests, which is fine: the user simply asks again.
#[derive(Clone, serde::Serialize)]
pub struct Request {
    pub id: u64,
    pub owner: String,
    pub device_key: String, // agents-map key ("relay:hc-…") — stable across reconnects
    pub target: String,     // proxy target ("relay://hc-…") used to dispatch
    pub device: String,     // display name
    pub user: String,       // OS account to elevate (the device's interactive user)
    pub minutes: u32,
    pub reason: String,
    pub ts: u64,
    pub status: String, // "pending" | "approved" | "denied"
}

/// An active grant with its auto-revoke deadline. Persisted so the window is
/// honored across a hub restart.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Grant {
    pub owner: String,
    pub device_key: String,
    pub target: String,
    pub device: String,
    pub user: String,
    pub granted_at: u64,
    pub revoke_at: u64,
}

fn requests() -> &'static Mutex<Vec<Request>> {
    static R: OnceLock<Mutex<Vec<Request>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}
fn grants() -> &'static Mutex<Vec<Grant>> {
    static G: OnceLock<Mutex<Vec<Grant>>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(Vec::new()))
}
fn next_id() -> u64 {
    static N: AtomicU64 = AtomicU64::new(1);
    N.fetch_add(1, Ordering::Relaxed)
}
static STORE: OnceLock<PathBuf> = OnceLock::new();

/// Point the grant store at HUB_DATA and load any persisted grants.
pub fn init(path: PathBuf) {
    let _ = STORE.set(path);
    load();
}

fn save() {
    if let Some(p) = STORE.get() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let g = grants().lock().unwrap();
        let _ = std::fs::write(p, serde_json::to_string(&*g).unwrap_or_default());
    }
}
fn load() {
    if let Some(p) = STORE.get() {
        if let Ok(txt) = std::fs::read_to_string(p) {
            if let Ok(v) = serde_json::from_str::<Vec<Grant>>(&txt) {
                *grants().lock().unwrap() = v;
            }
        }
    }
}

/// Record a new pending request; collapse any prior pending one for the same
/// device+user so a user hammering the button doesn't stack rows.
pub fn submit(owner: &str, device_key: &str, target: &str, device: &str, user: &str, minutes: u32, reason: &str) -> Request {
    let req = Request {
        id: next_id(),
        owner: owner.to_string(),
        device_key: device_key.to_string(),
        target: target.to_string(),
        device: device.to_string(),
        user: user.to_string(),
        minutes,
        reason: reason.chars().take(300).collect(),
        ts: now(),
        status: "pending".into(),
    };
    let mut r = requests().lock().unwrap();
    r.retain(|x| !(x.status == "pending" && x.device_key == device_key && x.user == user));
    r.push(req.clone());
    let len = r.len();
    if len > 200 {
        r.drain(0..len - 200);
    }
    req
}

/// Pending requests, optionally scoped to one owner (None = no scoping / full access).
pub fn pending_for(owner: Option<&str>) -> Vec<Request> {
    requests()
        .lock()
        .unwrap()
        .iter()
        .filter(|x| x.status == "pending" && owner.map(|o| o == x.owner).unwrap_or(true))
        .cloned()
        .collect()
}

/// Look up a still-pending request (owner-checked; None = full access) WITHOUT
/// transitioning it. Lets the caller attempt the grant first and only `decide`
/// once it succeeds — a denied grant leaves the request pending for a retry.
pub fn peek(id: u64, owner: Option<&str>) -> Option<Request> {
    requests()
        .lock()
        .unwrap()
        .iter()
        .find(|x| x.id == id && x.status == "pending" && owner.map(|o| o == x.owner).unwrap_or(true))
        .cloned()
}

/// Transition a still-pending request (owner-checked; None = full access).
/// Returns the request as it was (fields intact) on success, else None.
pub fn decide(id: u64, owner: Option<&str>, status: &str) -> Option<Request> {
    let mut r = requests().lock().unwrap();
    let x = r
        .iter_mut()
        .find(|x| x.id == id && x.status == "pending" && owner.map(|o| o == x.owner).unwrap_or(true))?;
    x.status = status.to_string();
    Some(x.clone())
}

/// Record (or replace) an active grant; returns it.
pub fn add_grant(owner: &str, device_key: &str, target: &str, device: &str, user: &str, minutes: u32) -> Grant {
    let n = now();
    let g = Grant {
        owner: owner.into(),
        device_key: device_key.into(),
        target: target.into(),
        device: device.into(),
        user: user.into(),
        granted_at: n,
        revoke_at: n + (minutes as u64) * 60,
    };
    {
        let mut gl = grants().lock().unwrap();
        gl.retain(|x| !(x.device_key == device_key && x.user == user));
        gl.push(g.clone());
    }
    save();
    g
}

/// Grants whose window has elapsed (revoke_at <= now_s).
pub fn due(now_s: u64) -> Vec<Grant> {
    grants().lock().unwrap().iter().filter(|g| g.revoke_at <= now_s).cloned().collect()
}

/// Active grants, optionally owner-scoped (None = no scoping).
pub fn active_for(owner: Option<&str>) -> Vec<Grant> {
    grants()
        .lock()
        .unwrap()
        .iter()
        .filter(|g| owner.map(|o| o == g.owner).unwrap_or(true))
        .cloned()
        .collect()
}

pub fn remove_grant(device_key: &str, user: &str) {
    grants().lock().unwrap().retain(|g| !(g.device_key == device_key && g.user == user));
    save();
}
