//! VPN exit: browse from a phone or PC with an enrolled device's public IP.
//!
//! The device (e.g. a Jetson Orin behind CGNAT) runs WireGuard through the
//! agent's `/vpn/*` endpoints; clients use the stock, open-source WireGuard app
//! and reach it through the UDP relay in vpnrelay.rs. This module owns the
//! passes: who may connect, until when. A pass is a WireGuard peer with an
//! expiry. The client's keypair is generated in the browser (assets/vpnpass.js),
//! which sends only the public key: the hub never sees a client private key. The
//! hub makes the pass's preshared key (it pushes it to the device) and returns
//! what the browser needs to write the .conf and QR itself.
//!
//! Configuration (env):
//!   VPN_RELAY_ENDPOINT  public host:port of the relay, e.g. crane.glick.run:31820
//!                       — what clients and devices connect to. Unset = VPN off.
//!   VPN_UDP_PORT        port the relay binds inside the container (default 51820)
//!   VPN_DNS             DNS for clients (default "1.1.1.1, 1.0.0.1")

use crate::{dev_unary, relay_target};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub const TTL_CHOICES_H: &[u64] = &[1, 8, 24, 72, 168];
const MAX_LIVE_PER_DEVICE: usize = 20;
const PURGE_AFTER_S: u64 = 7 * 24 * 3600;
/// Matches the agent's interface MTU: leaves room for the relay's framing.
const CLIENT_MTU: u32 = 1380;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct DevCfg {
    /// Hex HMAC key the device signs its relay HELLOs with.
    pub secret: String,
    #[serde(rename = "serverPublicKey")]
    pub server_public_key: String,
    #[serde(rename = "enabledBy", default)]
    pub enabled_by: String,
    #[serde(rename = "enabledAt", default)]
    pub enabled_at: u64,
    /// The device has not yet received the current peer list (it was offline).
    #[serde(default)]
    pub dirty: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Pass {
    pub id: String,
    pub device: String,
    pub name: String,
    pub owner: String,
    #[serde(rename = "publicKey")]
    pub public_key: String,
    #[serde(rename = "presharedKey")]
    pub preshared_key: String,
    pub address: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    #[serde(rename = "revokedAt", default)]
    pub revoked_at: Option<u64>,
}

impl Pass {
    pub fn status(&self, now: u64) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at <= now {
            "expired"
        } else {
            "active"
        }
    }
    fn live(&self, now: u64) -> bool {
        self.status(now) == "active"
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct Store {
    #[serde(default)]
    pub devices: BTreeMap<String, DevCfg>,
    #[serde(default)]
    pub passes: Vec<Pass>,
}

fn store() -> &'static Mutex<Store> {
    static S: std::sync::OnceLock<Mutex<Store>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(load()))
}

fn path() -> std::path::PathBuf {
    crate::data_dir().join("vpn.json")
}

fn load() -> Store {
    std::fs::read_to_string(path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save(s: &Store) {
    // Holds preshared keys and the devices' HELLO secrets: owner-only.
    let _ = crate::secretfile::write_secret(&path(), &serde_json::to_string_pretty(s).unwrap_or_default());
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn endpoint() -> Option<String> {
    std::env::var("VPN_RELAY_ENDPOINT").ok().map(|s| s.trim().to_string()).filter(|s| s.contains(':'))
}

fn dns() -> String {
    std::env::var("VPN_DNS").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "1.1.1.1, 1.0.0.1".into())
}

// ---- keys ------------------------------------------------------------------------

pub(crate) fn b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("OS entropy");
    b
}

pub fn decode_key(k: &str) -> Option<[u8; 32]> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(k.trim()).ok()?.try_into().ok()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).filter_map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()).collect()
}

// ---- pass bookkeeping ---------------------------------------------------------------

/// Lowest free 10.77.0.N on this device (N in 2..=254; .1 is the device).
pub fn allocate(passes: &[Pass], device: &str, now: u64) -> Option<String> {
    let used: Vec<&str> = passes.iter().filter(|p| p.device == device && p.live(now)).map(|p| p.address.as_str()).collect();
    (2..=254u32).map(|h| format!("10.77.0.{h}")).find(|a| !used.contains(&a.as_str()))
}

/// Is `p` still its holder's to use on a device now owned by `owner`? A pass
/// belongs to the owner who issued it (empty: issued with no identity, as
/// `may_control` lets anyone then).
fn owned(p: &Pass, owner: Option<&str>) -> bool {
    p.owner.is_empty() || owner == Some(p.owner.as_str())
}

/// Send the device everything it should have: relay, secret, live peers whose
/// pass its current `owner` issued. Returns the agent's status (which carries its
/// WireGuard public key).
fn push(target: &str, cfg: &DevCfg, passes: &[Pass], device: &str, owner: Option<&str>) -> Result<Value, String> {
    let ep = endpoint().ok_or("VPN_RELAY_ENDPOINT is not set on the hub")?;
    let t = now();
    let peers: Vec<Value> = passes
        .iter()
        .filter(|p| p.device == device && p.live(t) && owned(p, owner))
        .map(|p| json!({"publicKey": p.public_key, "presharedKey": p.preshared_key, "allowedIps": format!("{}/32", p.address), "expiresAt": p.expires_at}))
        .collect();
    let body = json!({"relay": ep, "secret": cfg.secret, "peers": peers}).to_string();
    let (st, _, b) = dev_unary(target, "POST", "/vpn/apply", Some(("application/json".into(), body.into_bytes()))).ok_or("device unreachable")?;
    let v: Value = serde_json::from_slice(&b).unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&b)}));
    if st != 200 || v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(v.get("error").and_then(Value::as_str).unwrap_or("the device refused the VPN config (agent too old?)").to_string());
    }
    Ok(v.get("status").cloned().unwrap_or(Value::Null))
}

/// Err names the device that already uses this one's server key.
fn register_relay(device: &str, cfg: &DevCfg) -> Result<(), String> {
    match decode_key(&cfg.server_public_key) {
        Some(pk) => crate::vpnrelay::set_device(device, unhex(&cfg.secret), &pk),
        None => Ok(()),
    }
}

/// At startup: bind the relay and register every enabled device, then keep
/// retrying pushes to devices that missed a change while offline.
pub fn start(agents: std::sync::Arc<crate::Agents>) {
    let port = std::env::var("VPN_UDP_PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(51820u16);
    if endpoint().is_none() {
        println!("[vpn] VPN_RELAY_ENDPOINT unset — VPN exit disabled");
        return;
    }
    crate::vpnrelay::start(port);
    {
        let s = store().lock().unwrap();
        for (id, cfg) in &s.devices {
            if let Err(other) = register_relay(id, cfg) {
                println!("[vpn] {id}: not routed — {other} has the same WireGuard key");
            }
        }
    }
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(30));
        sweep(&agents);
    });
}

fn sweep(agents: &crate::Agents) {
    let (dirty, passes): (Vec<(String, DevCfg)>, Vec<Pass>) = {
        let mut s = store().lock().unwrap();
        let t = now();
        let before = s.passes.len();
        s.passes.retain(|p| p.live(t) || t.saturating_sub(p.revoked_at.unwrap_or(p.expires_at)) < PURGE_AFTER_S);
        if s.passes.len() != before {
            save(&s);
        }
        (s.devices.iter().filter(|(_, c)| c.dirty).map(|(k, c)| (k.clone(), c.clone())).collect(), s.passes.clone())
    };
    for (id, cfg) in dirty {
        let target = format!("relay://{id}");
        if push(&target, &cfg, &passes, &id, crate::device_owner(agents, &target).as_deref()).is_ok() {
            let mut s = store().lock().unwrap();
            if let Some(c) = s.devices.get_mut(&id) {
                c.dirty = false;
            }
            save(&s);
            println!("[vpn] {id}: caught up after reconnect");
        }
    }
}

// ---- endpoints (all behind the /x/ SSO + may_control target gate) -----------------

fn device_of(target: &str) -> Result<String, String> {
    relay_target(target).filter(|s| !s.is_empty()).ok_or_else(|| "the VPN exit needs a relay-enrolled device".to_string())
}

fn view(p: &Pass, peers: &[Value], t: u64) -> Value {
    let peer = peers.iter().find(|x| x.get("publicKey").and_then(Value::as_str) == Some(p.public_key.as_str()));
    json!({
        "id": p.id, "name": p.name, "owner": p.owner, "address": p.address,
        "createdAt": p.created_at, "expiresAt": p.expires_at, "revokedAt": p.revoked_at,
        "status": p.status(t),
        "lastHandshake": peer.and_then(|x| x.get("latestHandshake")).cloned().unwrap_or(Value::Null),
        "rx": peer.and_then(|x| x.get("rx")).cloned().unwrap_or(json!(0)),
        "tx": peer.and_then(|x| x.get("tx")).cloned().unwrap_or(json!(0)),
    })
}

pub fn status_ep(target: &str) -> (Value, u16) {
    let device = match device_of(target) {
        Ok(d) => d,
        Err(e) => return (json!({"ok": false, "error": e}), 400),
    };
    let agent = dev_unary(target, "GET", "/vpn/status", None)
        .filter(|(st, _, _)| *st == 200)
        .and_then(|(_, _, b)| serde_json::from_slice::<Value>(&b).ok());
    let peers = agent.as_ref().and_then(|a| a.get("peers")).and_then(Value::as_array).cloned().unwrap_or_default();
    let s = store().lock().unwrap();
    let t = now();
    let cfg = s.devices.get(&device);
    let (relay_connected, clients) = crate::vpnrelay::device_status(&device);
    let passes: Vec<Value> = s.passes.iter().filter(|p| p.device == device).rev().map(|p| view(p, &peers, t)).collect();
    (
        json!({
            "ok": true,
            "configured": endpoint().is_some() && crate::vpnrelay::running(),
            "endpoint": endpoint(),
            "enabled": cfg.is_some(),
            "pendingSync": cfg.map(|c| c.dirty).unwrap_or(false),
            "agent": agent,
            "agentReachable": agent.is_some(),
            "relayConnected": relay_connected,
            "clients": clients,
            "ttlChoices": TTL_CHOICES_H,
            "passes": passes,
        }),
        200,
    )
}

pub fn enable_ep(target: &str, user: &str, owner: Option<&str>) -> (Value, u16) {
    let device = match device_of(target) {
        Ok(d) => d,
        Err(e) => return (json!({"ok": false, "error": e}), 400),
    };
    if endpoint().is_none() || !crate::vpnrelay::running() {
        return (json!({"ok": false, "error": "the hub's VPN relay is not configured (set VPN_RELAY_ENDPOINT and publish VPN_UDP_PORT over UDP)"}), 503);
    }
    let (mut cfg, passes) = {
        let s = store().lock().unwrap();
        let cfg = s.devices.get(&device).cloned().unwrap_or_else(|| DevCfg { secret: hex(&random32()), enabled_by: user.to_string(), enabled_at: now(), ..Default::default() });
        (cfg, s.passes.clone())
    };
    let st = match push(target, &cfg, &passes, &device, owner) {
        Ok(st) => st,
        Err(e) => return (json!({"ok": false, "error": e}), 502),
    };
    let Some(pk) = st.get("publicKey").and_then(Value::as_str).filter(|k| decode_key(k).is_some()) else {
        return (json!({"ok": false, "error": "the device did not report a WireGuard key"}), 502);
    };
    cfg.server_public_key = pk.to_string();
    cfg.dirty = false;
    if let Err(other) = register_relay(&device, &cfg) {
        // Clients find a device by its key: a second device with it (a cloned image,
        // or one copying another's reported key) would take the first one's clients.
        println!("[vpn] {device}: enable refused — {other} already uses its WireGuard key");
        crate::audit(user, "browser", "VPN exit refused", &device, "its WireGuard key is already used by another VPN exit");
        return (json!({"ok": false, "error": "this device reports a WireGuard key that another VPN exit already uses (a cloned image?) — give it a fresh key, then enable again"}), 409);
    }
    let mut s = store().lock().unwrap();
    s.devices.insert(device.clone(), cfg);
    save(&s);
    println!("[vpn] {device}: exit enabled by {user}");
    (json!({"ok": true, "status": st}), 200)
}

pub fn disable_ep(target: &str, user: &str) -> (Value, u16) {
    let device = match device_of(target) {
        Ok(d) => d,
        Err(e) => return (json!({"ok": false, "error": e}), 400),
    };
    let reached = dev_unary(target, "POST", "/vpn/disable", None).map(|(st, _, _)| st == 200).unwrap_or(false);
    switch_off(&device, false);
    println!("[vpn] {device}: exit disabled by {user}");
    // Even unreached, the relay no longer routes to it, so no pass can connect;
    // the device tears its interface down on the next disable that reaches it.
    (json!({"ok": true, "deviceReached": reached}), 200)
}

/// The hub side of switching a device's exit off, whether or not the device is
/// reachable: the relay stops accepting its HELLOs and drops its client sessions,
/// and vpn.json no longer has it enabled. `drop_passes` deletes its passes;
/// otherwise they stay, revoked, for the dashboard's history.
/// Returns `(was enabled, passes revoked or dropped)`.
fn switch_off(device: &str, drop_passes: bool) -> (bool, usize) {
    crate::vpnrelay::remove_device(device);
    let mut s = store().lock().unwrap();
    let was_enabled = s.devices.remove(device).is_some();
    let n = if drop_passes {
        let before = s.passes.len();
        s.passes.retain(|p| p.device != device);
        before - s.passes.len()
    } else {
        let t = now();
        s.passes.iter_mut().filter(|p| p.device == device && p.revoked_at.is_none()).map(|p| p.revoked_at = Some(t)).count()
    };
    if was_enabled || n > 0 {
        save(&s);
    }
    (was_enabled, n)
}

/// The device's credential was revoked, or it was removed or dissolved: shut its
/// exit down as Disable does, and drop its passes so vpn.json keeps no orphan.
/// Returns `(was enabled, passes dropped)`.
pub fn shut_down(device: &str) -> (bool, usize) {
    let r = switch_off(device, true);
    if r != (false, 0) {
        println!("[vpn] {device}: exit shut down with the device's credential");
    }
    r
}

/// Issue a pass for the client whose WireGuard public key is `client_public_key`
/// (base64, 32 bytes). The browser generated the keypair and keeps the private key.
pub fn issue_ep(target: &str, name: &str, hours: u64, client_public_key: &str, user: &str, owner: Option<&str>) -> (Value, u16) {
    let device = match device_of(target) {
        Ok(d) => d,
        Err(e) => return (json!({"ok": false, "error": e}), 400),
    };
    if !TTL_CHOICES_H.contains(&hours) {
        return (json!({"ok": false, "error": format!("hours must be one of {TTL_CHOICES_H:?}")}), 400);
    }
    let Some(client_key) = decode_key(client_public_key) else {
        return (json!({"ok": false, "error": "publicKey must be the client's WireGuard public key (32 bytes, base64)"}), 400);
    };
    let public_key = b64(&client_key);
    let ep = match endpoint() {
        Some(e) => e,
        None => return (json!({"ok": false, "error": "VPN_RELAY_ENDPOINT is not set"}), 503),
    };
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(40).collect();
    let name = if name.is_empty() { "device".to_string() } else { name };
    let t = now();
    let (pass, cfg, passes) = {
        let mut s = store().lock().unwrap();
        let Some(cfg) = s.devices.get(&device).cloned() else {
            return (json!({"ok": false, "error": "enable the VPN exit on this device first"}), 409);
        };
        if s.passes.iter().any(|p| p.device == device && p.live(t) && p.public_key == public_key) {
            return (json!({"ok": false, "error": "an active pass on this device already uses that public key"}), 409);
        }
        if s.passes.iter().filter(|p| p.device == device && p.live(t)).count() >= MAX_LIVE_PER_DEVICE {
            return (json!({"ok": false, "error": format!("{MAX_LIVE_PER_DEVICE} passes are already active on this device — revoke one first")}), 429);
        }
        let Some(address) = allocate(&s.passes, &device, t) else {
            return (json!({"ok": false, "error": "no free tunnel addresses"}), 503);
        };
        let pass = Pass {
            id: hex(&random32()[..12]),
            device: device.clone(),
            name: name.clone(),
            owner: user.to_string(),
            public_key,
            preshared_key: b64(&random32()),
            address,
            created_at: t,
            expires_at: t + hours * 3600,
            revoked_at: None,
        };
        s.passes.push(pass.clone());
        save(&s);
        (pass, cfg, s.passes.clone())
    };
    let pushed = push(target, &cfg, &passes, &device, owner);
    if pushed.is_err() {
        mark_dirty(&device);
    }
    let file = format!("itai-{}.conf", pass.name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect::<String>());
    (
        json!({
            "ok": true,
            "pass": view(&pass, &[], t),
            // The .conf minus [Interface] PrivateKey, which only the browser has.
            "wireguard": {
                "address": format!("{}/32", pass.address),
                "dns": dns(),
                "mtu": CLIENT_MTU,
                "serverPublicKey": cfg.server_public_key,
                "presharedKey": pass.preshared_key,
                "endpoint": ep,
                "allowedIps": "0.0.0.0/0, ::/0",
                "persistentKeepalive": 25,
            },
            "filename": file,
            "warning": pushed.err().map(|e| format!("saved, but the device has not taken it yet ({e}); it activates when the device reconnects")),
        }),
        201,
    )
}

pub fn revoke_ep(target: &str, id: &str, owner: Option<&str>) -> (Value, u16) {
    let device = match device_of(target) {
        Ok(d) => d,
        Err(e) => return (json!({"ok": false, "error": e}), 400),
    };
    let (cfg, passes) = {
        let mut s = store().lock().unwrap();
        // The pass must belong to the target the caller was authorized for.
        let Some(p) = s.passes.iter_mut().find(|p| p.id == id && p.device == device) else {
            return (json!({"ok": false, "error": "not found"}), 404);
        };
        if p.revoked_at.is_none() {
            p.revoked_at = Some(now());
        }
        let cfg = s.devices.get(&device).cloned();
        save(&s);
        (cfg, s.passes.clone())
    };
    let mut synced = true;
    if let Some(cfg) = cfg {
        if push(target, &cfg, &passes, &device, owner).is_err() {
            mark_dirty(&device);
            synced = false;
        }
    }
    (json!({"ok": true, "synced": synced}), 200)
}

fn mark_dirty(device: &str) {
    let mut s = store().lock().unwrap();
    if let Some(c) = s.devices.get_mut(device) {
        c.dirty = true;
    }
    save(&s);
}

/// What `enable_ep` + `issue_ep` leave behind once the device has answered, for
/// tests that cannot reach a device: `device` enabled with `server_pub` and one
/// live pass. Returns the HELLO secret it signs with.
#[cfg(test)]
pub(crate) fn enable_for_test(device: &str, server_pub: &[u8; 32]) -> Vec<u8> {
    let cfg = DevCfg { secret: hex(&random32()), server_public_key: b64(server_pub), enabled_by: "test".into(), enabled_at: now(), dirty: false };
    register_relay(device, &cfg).unwrap();
    let t = now();
    let mut s = store().lock().unwrap();
    let address = allocate(&s.passes, device, t).unwrap();
    let pass = Pass { id: hex(&random32()[..12]), device: device.into(), name: "phone".into(), owner: "test".into(), public_key: test_key(), preshared_key: b64(&random32()), address, created_at: t, expires_at: t + 3600, revoked_at: None };
    s.passes.push(pass);
    let secret = unhex(&cfg.secret);
    s.devices.insert(device.to_string(), cfg);
    save(&s);
    secret
}

/// `(enabled, passes)` for `device` as /data/vpn.json has it on disk.
#[cfg(test)]
pub(crate) fn on_disk(device: &str) -> (bool, usize) {
    // Every save happens under the store lock and truncates first: read under it too.
    let _g = store().lock().unwrap();
    let s = load();
    (s.devices.contains_key(device), s.passes.iter().filter(|p| p.device == device).count())
}

/// Add a live pass on `device` issued by `owner`; returns its public key.
#[cfg(test)]
pub(crate) fn add_pass_for_test(device: &str, owner: &str) -> String {
    let t = now();
    let mut s = store().lock().unwrap();
    let address = allocate(&s.passes, device, t).unwrap();
    let public_key = test_key();
    let pass = Pass { id: hex(&random32()[..12]), device: device.into(), name: "injected".into(), owner: owner.into(), public_key: public_key.clone(), preshared_key: b64(&random32()), address, created_at: t, expires_at: t + 3600, revoked_at: None };
    s.passes.push(pass);
    save(&s);
    public_key
}

/// A random 32-byte key in base64, as a WireGuard public key looks on the wire.
#[cfg(test)]
pub(crate) fn test_key() -> String {
    b64(&random32())
}

/// The exit's WireGuard public key, if `device` is enabled.
#[cfg(test)]
pub(crate) fn server_key(device: &str) -> Option<String> {
    store().lock().unwrap().devices.get(device).map(|c| c.server_public_key.clone())
}

/// The HELLO secret `device` is enabled with, if it is.
#[cfg(test)]
pub(crate) fn hello_secret(device: &str) -> Option<Vec<u8>> {
    store().lock().unwrap().devices.get(device).map(|c| unhex(&c.secret))
}

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(device: &str, addr: &str, exp: u64, revoked: Option<u64>) -> Pass {
        Pass { id: "x".into(), device: device.into(), name: "n".into(), owner: "o".into(), public_key: String::new(), preshared_key: String::new(), address: addr.into(), created_at: 0, expires_at: exp, revoked_at: revoked }
    }

    #[test]
    fn allocation_is_per_device_and_reuses_dead_addresses() {
        let ps = vec![pass("a", "10.77.0.2", 100, None), pass("a", "10.77.0.3", 10, None), pass("a", "10.77.0.4", 100, Some(5)), pass("b", "10.77.0.5", 100, None)];
        assert_eq!(allocate(&ps, "a", 50).as_deref(), Some("10.77.0.3"));
        assert_eq!(allocate(&ps, "b", 50).as_deref(), Some("10.77.0.2"));
    }

    #[test]
    fn status_reflects_revocation_and_expiry() {
        assert_eq!(pass("a", "x", 100, None).status(50), "active");
        assert_eq!(pass("a", "x", 100, None).status(100), "expired");
        assert_eq!(pass("a", "x", 100, Some(1)).status(50), "revoked");
    }
}
