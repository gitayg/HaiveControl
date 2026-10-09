// Per-device relay secrets — the hub side of docs/DEVICE-SECRETS.md.
//
// A device enrolls ONCE with its owner's enrollment token (`htok_…`, shared by the
// owner's whole fleet). On that hello, if it asks (`ds=1`), the hub issues it its own
// secret (`hdev_…`) and the device uses that from then on. So rotating the
// enrollment token no longer disconnects enrolled devices, and one device's
// credential can be revoked on its own.
//
// Only sha256(secret) is stored, in `<HUB_DATA>/device_secrets.json` (0600, dir
// 0700, via `secretfile`), keyed by relay id:
//   { "<relay_id>": { "hash": "<sha256 hex>", "owner": "<owner id>", "issued": <unix secs> } }
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Every device secret starts with this; anything else on `tok=` is an enrollment
/// token or the shared RELAY_TOKEN and takes the pre-existing path.
pub const PREFIX: &str = "hdev_";

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub hash: String,
    pub owner: String,
    pub issued: u64,
}

#[derive(Debug, PartialEq)]
pub enum MintError {
    /// The relay id already holds a secret issued under a different owner.
    OtherOwner,
    /// No OS entropy — never fall back to a guessable secret.
    NoEntropy,
    /// The store could not be written. A secret handed out but not persisted would
    /// be rejected after the next hub restart, AFTER the agent dropped its
    /// enrollment token — so it is not handed out.
    Persist,
}

fn store() -> &'static Mutex<HashMap<String, Entry>> {
    static S: OnceLock<Mutex<HashMap<String, Entry>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn path() -> std::path::PathBuf {
    crate::data_dir().join("device_secrets.json")
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// sha256 hex — the only form of a secret the hub keeps.
pub fn hash(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}

pub fn is_device_secret(tok: &str) -> bool {
    tok.starts_with(PREFIX)
}

/// `hdev_` + 32 bytes of OS randomness as lowercase hex.
fn generate() -> Option<String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).ok()?;
    Some(format!("{PREFIX}{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

fn persist(m: &HashMap<String, Entry>) -> std::io::Result<()> {
    crate::secretfile::ensure_private_dir(&crate::data_dir())?;
    let txt = serde_json::to_string(m).map_err(std::io::Error::other)?;
    crate::secretfile::write_secret(&path(), &txt)
}

/// Load the store at startup. Reading through `secretfile` tightens a file found
/// with wider permissions (and says so). Missing or unparseable = no secrets: every
/// device falls back to its enrollment token, which is the pre-3.16 behaviour.
pub fn load() {
    match crate::secretfile::read_secret(&path()) {
        Ok(Some(txt)) => match serde_json::from_str::<HashMap<String, Entry>>(&txt) {
            Ok(m) => *store().lock().unwrap() = m,
            Err(e) => println!("device secrets: {} is unparseable ({e}) — no device credentials loaded", path().display()),
        },
        Ok(None) => {}
        Err(e) => println!("device secrets: {e}"),
    }
}

/// The owner a presented device secret proves, if it is the secret issued for
/// `relay_id`. Constant-time on the hash; a secret is only ever valid for its own id.
pub fn verify(relay_id: &str, secret: &str) -> Option<String> {
    if relay_id.is_empty() || !is_device_secret(secret) {
        return None;
    }
    let h = hash(secret);
    let g = store().lock().unwrap();
    let e = g.get(relay_id)?;
    crate::ct_eq_str(&e.hash, &h).then(|| e.owner.clone())
}

pub fn owner_of(relay_id: &str) -> Option<String> {
    store().lock().unwrap().get(relay_id).map(|e| e.owner.clone())
}

pub fn has(relay_id: &str) -> bool {
    store().lock().unwrap().contains_key(relay_id)
}

/// Issue a fresh secret for `relay_id` under `owner`, replacing any previous one —
/// but only one this same owner was issued. Returns the plaintext, which exists
/// nowhere else after this call returns.
pub fn mint(relay_id: &str, owner: &str) -> Result<String, MintError> {
    let secret = generate().ok_or(MintError::NoEntropy)?;
    let mut g = store().lock().unwrap();
    if g.get(relay_id).is_some_and(|e| e.owner != owner) {
        return Err(MintError::OtherOwner);
    }
    let prev = g.insert(relay_id.to_string(), Entry { hash: hash(&secret), owner: owner.to_string(), issued: now() });
    if let Err(e) = persist(&g) {
        match prev {
            Some(p) => g.insert(relay_id.to_string(), p),
            None => g.remove(relay_id),
        };
        println!("device secrets: could not save {} ({e}) — {relay_id} stays on its enrollment token", path().display());
        return Err(MintError::Persist);
    }
    Ok(secret)
}

/// Delete `relay_id`'s secret. True if there was one.
pub fn remove(relay_id: &str) -> bool {
    let mut g = store().lock().unwrap();
    if g.remove(relay_id).is_none() {
        return false;
    }
    if let Err(e) = persist(&g) {
        // In memory it is gone now, so the device is refused until the hub restarts;
        // after a restart the stale entry would load again. Say so.
        println!("device secrets: could not save {} after deleting {relay_id} ({e}) — it will return on restart", path().display());
    }
    true
}

// ---- HTTP -----------------------------------------------------------------------

use crate::{json_resp, query_param, relay, req_header, Agents, Resp};
use tiny_http::{Request, Response};

/// 401 body for a refused device secret — the agent keys "re-enroll" off it.
pub const REJECTED: &str = "device credential rejected";
const IN_USE: &str = "relay id in use by another enrollment";

/// The owner behind a /relay call that `relay_ok` already let through: the owner its
/// device secret was issued to, or its enrollment token's owner.
pub fn relay_caller_owner(url: &str) -> Option<String> {
    let tok = query_param(url, "tok").unwrap_or_default();
    if is_device_secret(&tok) {
        return owner_of(&query_param(url, "id").unwrap_or_default());
    }
    crate::resolve_owner_token(&tok)
}

/// Record the device's public IP and owner on its hello payload. No side effects:
/// the payload is only stored if `relay::hello` accepts it.
fn stamp(req: &Request, data: &mut serde_json::Value, owner: Option<&str>) {
    // The device dials out, so the socket (or X-Forwarded-For behind the AppCrane
    // proxy) carries its real public IP — capture it for geo.
    let pip = req_header(req, "X-Forwarded-For")
        .and_then(|h| h.split(',').next().map(|s| s.trim().to_string()))
        .or_else(|| req.remote_addr().map(|a| a.ip().to_string()));
    if let Some(o) = data.as_object_mut() {
        if let Some(ip) = pip {
            o.insert("public_ip".into(), serde_json::json!(ip));
        }
        if let Some(owner) = owner {
            o.insert("owner".into(), serde_json::json!(owner));
        }
    }
}

/// Pin the owner as a persistent override so it survives every check-in. Call only
/// after `relay::hello` accepted the hello, with the id it registered (the payload's
/// `relay_id`): a refused hello must change no ownership.
fn record_owner(agents: &Agents, rid: &str, owner: Option<&str>) {
    if let Some(owner) = owner {
        crate::set_owner(agents, &format!("relay:{rid}"), owner, "system", "relay");
    }
}

/// True if `rid` already belongs to an owner other than `owner`: by its device
/// secret, its persisted owner override, or its device row.
fn owned_by_other(agents: &Agents, rid: &str, owner: &str) -> bool {
    let key = format!("relay:{rid}");
    let row = agents.lock().unwrap().get(&key).and_then(|a| a.data.get("owner").and_then(|o| o.as_str()).map(String::from));
    [owner_of(rid), crate::owner_override(&key), row].into_iter().flatten().any(|held| held != owner)
}

/// POST /relay/hello?id=<rid>&tok=<t>[&ds=1] — register or heartbeat a relay agent.
pub fn hello_ep(req: &mut Request, url: &str, agents: &Agents) -> Resp {
    let tok = query_param(url, "tok").unwrap_or_default();
    let rid = query_param(url, "id").unwrap_or_default();
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let mut data: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    // The id the payload registers. A credential checked against `id=` must be
    // registering that same id, or a secret for one device could heartbeat — and,
    // since a secret may re-bind, take over — another device's tunnel.
    let body_id = data.get("relay_id").and_then(|x| x.as_str()).unwrap_or_default().to_string();
    let same_id = !rid.is_empty() && body_id == rid;

    if is_device_secret(&tok) {
        let owner = match verify(&rid, &tok) {
            Some(o) if same_id => o,
            _ => return Response::from_string(REJECTED).with_status_code(401),
        };
        stamp(req, &mut data, Some(&owner));
        // A valid device secret proves identity, so it may take over a tunnel still
        // bound to the enrollment token it was issued under.
        if relay::hello(agents, data, &relay::auth_hash(&tok), true) {
            record_owner(agents, &body_id, Some(&owner));
        }
        return Response::from_string("").with_status_code(204);
    }

    // Enrollment token / shared token: the pre-3.16 behaviour, plus `ds=1`.
    // Strict enrollment: when the hub is authed (RELAY_TOKEN set), a device must
    // present a per-owner enrollment token (htok_…) so it enrolls UNDER an owner —
    // never un-owned. relay_ok already blocks a wholly tokenless call; this
    // additionally rejects a bare shared-token enrollment that would otherwise land
    // un-owned (and thus invisible to everyone).
    let owner = crate::resolve_owner_token(&tok);
    let authed = std::env::var("RELAY_TOKEN").map(|t| !t.is_empty()).unwrap_or(false);
    if authed && owner.is_none() {
        return Response::from_string(
            "enrollment requires a personal enrollment token (--relay-token htok_…) — get one from the dashboard's Register a device panel",
        )
        .with_status_code(403);
    }
    // The tunnel registry is in memory, so after a hub restart the takeover check in
    // `relay::hello` has nothing to compare against until the device reconnects. The
    // owner is persisted, though: an id already owned by someone else is refused here.
    if let Some(o) = &owner {
        if owned_by_other(agents, &body_id, o) {
            return Response::from_string(IN_USE).with_status_code(403);
        }
    }
    // Mint only for an enrollment token, only when asked (agents ≤ 3.6.x never ask),
    // and only for the id the payload actually registers.
    let mint_for = match (&owner, query_param(url, "ds").as_deref()) {
        (Some(o), Some("1")) if same_id => Some(o.clone()),
        _ => None,
    };
    // Re-minting replaces a secret only for the owner it was issued to. That owner's
    // enrollment token may also re-bind the tunnel (the device lost its secret, or
    // it was revoked): it could re-enroll any of its own devices anyway.
    let rebind = match (&mint_for, mint_for.as_ref().and_then(|_| owner_of(&rid))) {
        (Some(o), Some(held)) if held != *o => return Response::from_string(IN_USE).with_status_code(403),
        (Some(_), Some(_)) => true,
        _ => false,
    };
    // A device queued to dissolve is dissolved by this hello; don't issue it a credential.
    let dissolving = crate::is_dissolve_pending(&format!("relay:{rid}"));
    stamp(req, &mut data, owner.as_deref());
    if !relay::hello(agents, data, &relay::auth_hash(&tok), rebind) {
        // The id is already bound to a different enrollment token —
        // someone is trying to take over another device's tunnel.
        return Response::from_string(IN_USE).with_status_code(403);
    }
    let owner = match mint_for {
        Some(o) if !dissolving => o,
        _ => {
            record_owner(agents, &body_id, owner.as_deref());
            return Response::from_string("").with_status_code(204);
        }
    };
    match mint(&rid, &owner) {
        Ok(secret) => {
            record_owner(agents, &body_id, Some(&owner));
            // Its next poll will carry the new secret; accept it straight away.
            relay::rebind(&rid, &relay::auth_hash(&secret));
            println!("relay: {rid} issued a device credential");
            json_resp(&serde_json::json!({ "device_secret": secret }))
        }
        Err(MintError::OtherOwner) => Response::from_string(IN_USE).with_status_code(403),
        // Not issued: the device stays on its enrollment token, as with an older hub.
        Err(_) => {
            record_owner(agents, &body_id, Some(&owner));
            Response::from_string("").with_status_code(204)
        }
    }
}

/// POST /x/device-secret/revoke?target=<t> — delete a device's secret. `may_control`
/// and the audit entry ("revoke device secret") are applied by the /x/ preamble in
/// `handle`. The device's next relay call is refused with 401, and its VPN exit is
/// shut down (audited as `actor`): re-enrolling does not bring the exit back.
pub fn revoke_ep(url: &str, agents: &Agents, actor: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let rid = match crate::relay_target(&target) {
        Some(r) if !r.is_empty() => r,
        _ => return json_resp(&serde_json::json!({"ok": false, "error": "not a relay device"})),
    };
    let revoked = remove(&rid);
    if revoked {
        // The tunnel is bound to the revoked secret. Dropping it lets the device
        // re-enroll with its enrollment token; until it does, it is disconnected.
        relay::drop_tunnel(&rid);
        crate::shut_down_vpn_exit(&rid, &crate::device_name(agents, &target), actor, "browser", "device credential revoked");
        println!("relay: {rid} device credential revoked");
    }
    json_resp(&serde_json::json!({"ok": true, "revoked": revoked}))
}

// ---- dashboard ------------------------------------------------------------------
// Per device: which credential it relays with, and Revoke when it holds its own.
// Register-a-device: how many devices a Rotate would disconnect. `DEV`, `SEL`,
// `API`, `enc`, `fetchAgents` come from the main dashboard script.

pub const DS_CSS: &str = r#"
.ds-chip{display:inline-block;font-size:10px;font-weight:600;letter-spacing:.02em;padding:1px 6px;border-radius:5px;margin-left:6px;vertical-align:middle;font-family:inherit}
.ds-chip.own{background:#1f4a35;color:#8fe3b5}
.ds-chip.enr{background:#4a3f1f;color:#f0d08a}
.ds-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0;font-size:12px}
.ds-row .ds-chip{margin-left:0}
.ds-lbl{color:var(--muted)}
.ds-warn{display:block;margin-top:6px}
.ds-warn.bad{color:#e0a94a}
"#;

pub const DS_JS: &str = r#"<script>
function dsCount(){var m=0,n=0;Object.keys(DEV).forEach(function(k){var d=DEV[k];if(d.scheme!=='relay')return;m++;if(!d.device_secret)n++;});return {n:n,m:m};}
function dsWarnText(){var c=dsCount();return c.n+' of '+c.m+' devices still authenticate with the enrollment token and will be disconnected.';}
function dsRegWarn(){var el=document.getElementById('ds-warn');if(!el)return;el.textContent=dsWarnText();el.className='ds-warn'+(dsCount().n?' bad':'');}
function credChip(d){if(!d||d.scheme!=='relay')return '';return d.device_secret?'<span class="ds-chip own" title="relays with its own device credential — rotating the enrollment token does not affect it">own credential</span>':'<span class="ds-chip enr" title="relays with your enrollment token — rotating it disconnects this device">enrollment token</span>';}
function dsCred(d){var el=document.getElementById('d-cred');if(!el)return;if(!d||d.scheme!=='relay'){el.innerHTML='';return;}el.innerHTML='<div class="ds-row"><span class="ds-lbl">Relay credential</span>'+credChip(d)+(d.device_secret?'<button class="b danger" onclick="dsRevoke()" title="delete this device\'s own credential — it is refused until re-enrolled">Revoke</button>':'<span class="dim2">Rotating the enrollment token disconnects this device. Agents 3.7+ get their own credential.</span>')+'</div>';}
function dsRevoke(){var t=SEL;if(!t)return;var d=DEV[t]||{};if(!confirm('Revoke the device credential of '+(d.name||d.hostname||t)+'? Its next call to the hub is refused, and it stays disconnected until re-enrolled with an enrollment token.'))return;fetch(API+'/x/device-secret/revoke?target='+enc(t),{method:'POST'}).then(function(r){return r.json();}).then(function(j){if(!j||!j.ok){alert((j&&j.error)||'revoke failed');return;}if(DEV[t])DEV[t].device_secret=false;if(SEL===t)dsCred(DEV[t]);fetchAgents();}).catch(function(e){alert('error: '+e);});}
</script>"#;

#[cfg(test)]
pub(crate) mod tests;
