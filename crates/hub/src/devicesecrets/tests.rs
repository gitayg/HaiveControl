use super::{has, hash, mint, owner_of, path, remove, verify, MintError, PREFIX};

// ---- the store, directly ------------------------------------------------------

#[test]
fn a_minted_secret_is_hdev_plus_32_random_bytes_of_lowercase_hex() {
    crate::testenv::init();
    let s = mint("ds-unit-format", "owner-format").unwrap();
    let hex = s.strip_prefix(PREFIX).expect("hdev_ prefix");
    assert_eq!(hex.len(), 64, "32 bytes as hex");
    assert!(hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "lowercase hex only");
    assert_ne!(s, mint("ds-unit-format", "owner-format").unwrap(), "two mints must not repeat");
}

#[test]
fn a_secret_is_valid_only_for_its_own_id() {
    crate::testenv::init();
    let s = mint("ds-unit-own", "owner-own").unwrap();
    assert_eq!(verify("ds-unit-own", &s).as_deref(), Some("owner-own"));
    let other = mint("ds-unit-other", "owner-own").unwrap();
    assert_eq!(verify("ds-unit-other", &s), None, "another device's id");
    assert_eq!(verify("ds-unit-own", &other), None, "another device's secret");
    assert_eq!(verify("", &s), None, "no id");
    let mut wrong = s.clone();
    wrong.replace_range(s.len() - 1.., if s.ends_with('0') { "1" } else { "0" });
    assert_eq!(verify("ds-unit-own", &wrong), None, "one hex digit off");
    assert_eq!(verify("ds-unit-own", s.trim_start_matches(PREFIX)), None, "prefix is part of the secret");
}

#[test]
fn re_mint_replaces_for_the_same_owner_and_refuses_another() {
    crate::testenv::init();
    let first = mint("ds-unit-remint", "owner-r1").unwrap();
    assert_eq!(mint("ds-unit-remint", "owner-r2"), Err(MintError::OtherOwner));
    assert!(verify("ds-unit-remint", &first).is_some(), "a refused re-mint must leave the device's secret alone");
    let second = mint("ds-unit-remint", "owner-r1").unwrap();
    assert!(verify("ds-unit-remint", &first).is_none(), "the replaced secret is dead");
    assert_eq!(verify("ds-unit-remint", &second).as_deref(), Some("owner-r1"));
}

#[test]
fn remove_kills_the_secret() {
    crate::testenv::init();
    let s = mint("ds-unit-remove", "owner-rm").unwrap();
    assert!(remove("ds-unit-remove"));
    assert!(verify("ds-unit-remove", &s).is_none());
    assert!(!has("ds-unit-remove") && owner_of("ds-unit-remove").is_none());
    assert!(!remove("ds-unit-remove"), "second remove reports nothing to remove");
}

#[test]
fn the_store_file_is_0600_and_holds_only_hashes() {
    crate::testenv::init();
    let s = mint("ds-unit-file", "owner-file").unwrap();
    let txt = std::fs::read_to_string(path()).unwrap();
    assert!(!txt.contains(&s), "plaintext secret on disk");
    assert!(!txt.contains(s.trim_start_matches(PREFIX)), "secret hex on disk");
    let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
    assert_eq!(v["ds-unit-file"]["hash"], hash(&s));
    assert_eq!(v["ds-unit-file"]["owner"], "owner-file");
    assert!(v["ds-unit-file"]["issued"].as_u64().unwrap() > 1_700_000_000);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "store mode {mode:o}");
        let dmode = std::fs::metadata(path().parent().unwrap()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "data dir mode {dmode:o}");
    }
}

// ---- end-to-end through `handle`: a real hub socket, RELAY_TOKEN set ------------

use super::{IN_USE, REJECTED};
use crate::{audit_log, handle, relay_ok, rotate_enroll_token, Agents};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

fn hub() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        crate::testenv::init();
        let agents: &'static Agents = Box::leak(Box::new(Mutex::new(HashMap::new())));
        let srv = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = srv.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || {
            for req in srv.incoming_requests() {
                std::thread::spawn(move || handle(req, agents, "test", "127.0.0.1", port));
            }
        });
        format!("http://127.0.0.1:{port}")
    })
}

/// The owner's enrollment token. Through `hub()` first: minting persists the token
/// map under HUB_DATA, which must already point at the test dir.
fn htok(owner: &str) -> String {
    hub();
    crate::enroll_token_for(owner)
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// (status, content-type, body)
fn call(method: &str, pq: &str, body: &str, headers: &[(&str, &str)]) -> (u16, String, String) {
    let c = reqwest::blocking::Client::new();
    let url = format!("{}{pq}", hub());
    let mut rb = if method == "POST" { c.post(url).body(body.to_string()) } else { c.get(url) };
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    let r = rb.send().unwrap();
    let ct = r.headers().get("content-type").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    (r.status().as_u16(), ct, r.text().unwrap())
}

/// POST /relay/hello as device `body_id`, authenticating as `query_id` (None = no id=).
fn hello_as(query_id: Option<&str>, body_id: &str, tok: &str, ds: bool) -> (u16, String) {
    let mut q = format!("/relay/hello?tok={}", enc(tok));
    if let Some(id) = query_id {
        q.push_str(&format!("&id={}", enc(id)));
    }
    if ds {
        q.push_str("&ds=1");
    }
    let (st, _, b) = call("POST", &q, &serde_json::json!({"relay_id": body_id, "name": format!("host-{body_id}"), "hostname": format!("host-{body_id}")}).to_string(), &[]);
    (st, b)
}

fn hello(rid: &str, tok: &str, ds: bool) -> (u16, String) {
    hello_as(Some(rid), rid, tok, ds)
}

/// Any authenticated non-hello relay route.
fn relay_get(id: Option<&str>, tok: &str) -> (u16, String) {
    let q = match id {
        Some(id) => format!("/relay/config?id={}&tok={}", enc(id), enc(tok)),
        None => format!("/relay/config?tok={}", enc(tok)),
    };
    let (st, _, b) = call("GET", &q, "", &[]);
    (st, b)
}

/// Enroll `rid` under `owner` the way a 3.7 agent does and return its device secret.
fn enroll(rid: &str, owner: &str) -> String {
    let (st, body) = hello(rid, &htok(owner), true);
    assert_eq!(st, 200, "enroll {rid}: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["device_secret"].as_str().unwrap().to_string()
}

fn audited(action: &str, device: &str) -> bool {
    audit_log().lock().unwrap().iter().any(|(_, _, _, a, d, _)| a == action && d == device)
}

#[test]
fn a_valid_device_secret_passes_relay_ok_and_hello_for_its_own_id() {
    let s = enroll("ds-http-own", "owner-http-own");
    assert!(relay_ok(&format!("/relay/config?id=ds-http-own&tok={s}")));
    assert_eq!(hello("ds-http-own", &s, false), (204, String::new()));
    assert_eq!(hello("ds-http-own", &s, true), (204, String::new()), "a device secret never mints");
    assert_eq!(relay_get(Some("ds-http-own"), &s).0, 200);
    let (st, _, _) = call("GET", &format!("/relay/cap-key?id=ds-http-own&tok={s}"), "", &[]);
    assert_eq!(st, 200);
    // Control: the shared RELAY_TOKEN still passes (now via a constant-time compare).
    assert!(relay_ok(&format!("/relay/config?tok={}", crate::testenv::RELAY_TOKEN)));
    assert!(!relay_ok("/relay/config?tok=relay-shared-test-tokeX"));
}

#[test]
fn a_device_secret_for_another_id_a_wrong_one_or_one_without_id_is_rejected() {
    let a = enroll("ds-http-a", "owner-http-ab");
    let b = enroll("ds-http-b", "owner-http-ab");
    // Another device's id.
    assert!(!relay_ok(&format!("/relay/config?id=ds-http-b&tok={a}")));
    assert_eq!(relay_get(Some("ds-http-b"), &a), (401, REJECTED.to_string()));
    assert_eq!(hello("ds-http-b", &a, false), (401, REJECTED.to_string()));
    // Right id in the query, but registering another device in the body.
    assert_eq!(hello_as(Some("ds-http-a"), "ds-http-b", &a, false), (401, REJECTED.to_string()));
    // Wrong secret.
    let mut wrong = a.clone();
    wrong.replace_range(a.len() - 1.., if a.ends_with('0') { "1" } else { "0" });
    assert_eq!(relay_get(Some("ds-http-a"), &wrong), (401, REJECTED.to_string()));
    assert_eq!(hello("ds-http-a", &wrong, false), (401, REJECTED.to_string()));
    // No id at all.
    assert!(!relay_ok(&format!("/relay/config?tok={a}")));
    assert_eq!(relay_get(None, &a), (401, REJECTED.to_string()));
    assert_eq!(hello_as(None, "ds-http-a", &a, false), (401, REJECTED.to_string()));
    // Controls: both devices still authenticate as themselves.
    assert_eq!(hello("ds-http-a", &a, false).0, 204);
    assert_eq!(hello("ds-http-b", &b, false).0, 204);
}

#[test]
fn ds1_with_an_enrollment_token_mints_200_json_and_without_ds_answers_204_storing_nothing() {
    let htok = htok("owner-http-ds");
    assert_eq!(hello("ds-http-nods", &htok, false), (204, String::new()));
    assert!(!has("ds-http-nods"), "no ds=1 → nothing stored");

    let (st, ct, body) = call("POST", &format!("/relay/hello?id=ds-http-ds&tok={htok}&ds=1"), r#"{"relay_id":"ds-http-ds"}"#, &[]);
    assert_eq!(st, 200, "{body}");
    assert!(ct.starts_with("application/json"), "{ct}");
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let s = v["device_secret"].as_str().unwrap();
    assert!(s.starts_with(PREFIX));
    assert_eq!(v.as_object().unwrap().len(), 1, "{body}");
    assert_eq!(verify("ds-http-ds", s).as_deref(), Some("owner-http-ds"));
    let disk = std::fs::read_to_string(path()).unwrap();
    assert!(!disk.contains(s) && disk.contains(&hash(s)), "store holds the hash, never the secret");

    // The shared RELAY_TOKEN is not an enrollment token: no owner → refused, nothing minted.
    assert_eq!(hello("ds-http-shared", crate::testenv::RELAY_TOKEN, true).0, 403);
    assert!(!has("ds-http-shared"));
    // ds=1 for an id the payload does not register: registered as before, nothing minted.
    let (st, _) = hello_as(Some("ds-http-q"), "ds-http-body", &htok, true);
    assert_eq!(st, 204);
    assert!(!has("ds-http-q") && !has("ds-http-body"));
}

/// Whether `tok` is the credential `rid`'s tunnel is bound to: a bound poll long-polls
/// (no reply within 2s), an unbound one is answered 204 at once.
fn tunnel_bound_to(rid: &str, tok: &str) -> bool {
    let c = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(2)).build().unwrap();
    match c.get(format!("{}/relay/poll?id={rid}&tok={}", hub(), enc(tok))).send() {
        Err(e) => e.is_timeout(),
        Ok(r) => r.status().as_u16() == 200,
    }
}

#[test]
fn re_mint_with_another_owners_enrollment_token_is_403() {
    let s = enroll("ds-http-steal", "owner-http-victim");
    let thief = htok("owner-http-thief");
    let (st, body) = hello("ds-http-steal", &thief, true);
    assert_eq!((st, body.as_str()), (403, IN_USE));
    assert_eq!(verify("ds-http-steal", &s).as_deref(), Some("owner-http-victim"), "secret and owner untouched");
    assert!(!tunnel_bound_to("ds-http-steal", &thief), "the refused hello re-bound the tunnel to the thief");
    assert!(tunnel_bound_to("ds-http-steal", &s), "control: the device's own secret holds the tunnel");
    assert_eq!(hello("ds-http-steal", &s, false).0, 204, "the device keeps working");
    // Control: the device's own owner may re-mint (lost secret), which kills the old one.
    let s2 = enroll("ds-http-steal", "owner-http-victim");
    assert_ne!(s, s2);
    assert_eq!(hello("ds-http-steal", &s, false), (401, REJECTED.to_string()));
    assert_eq!(hello("ds-http-steal", &s2, false).0, 204);
}

#[test]
fn rotating_the_enrollment_token_keeps_secret_holders_and_drops_old_token_devices() {
    let owner = "owner-http-rotate";
    let old = htok(owner);
    let x = enroll("ds-http-rot-x", owner);
    assert_eq!(hello("ds-http-rot-y", &old, false).0, 204, "an agent ≤ 3.6 on the enrollment token");
    let new = rotate_enroll_token(owner);
    assert_ne!(old, new);
    assert_eq!(hello("ds-http-rot-x", &x, false).0, 204, "secret holder unaffected");
    assert_eq!(relay_get(Some("ds-http-rot-x"), &x).0, 200);
    assert_eq!(hello("ds-http-rot-y", &old, false).0, 401, "old-token device disconnected");
    assert_eq!(relay_get(Some("ds-http-rot-y"), &old).0, 401);
}

/// `/agents`' `connected` flag for relay device `rid` (None = not listed).
fn connected(rid: &str) -> Option<bool> {
    let (st, _, body) = call("GET", "/agents", "", &[]);
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    v["agents"].as_array().unwrap().iter().find(|a| a["relay_id"] == rid).and_then(|a| a["connected"].as_bool())
}

#[test]
fn rotating_drops_the_tunnel_of_a_device_on_the_old_token() {
    let owner = "owner-http-rot-tun1";
    let old = htok(owner);
    assert_eq!(hello("ds-http-rot-tun1", &old, false).0, 204);
    assert_eq!(connected("ds-http-rot-tun1"), Some(true), "control: connected before the rotate");
    rotate_enroll_token(owner);
    assert_eq!(connected("ds-http-rot-tun1"), Some(false), "a device whose every call is now 401 is still shown connected");
}

#[test]
fn a_device_on_the_old_token_re_enrolls_with_the_new_one() {
    let owner = "owner-http-rot-tun2";
    let old = htok(owner);
    assert_eq!(hello("ds-http-rot-tun2", &old, false).0, 204);
    let new = rotate_enroll_token(owner);
    assert_eq!(hello("ds-http-rot-tun2", &new, false), (204, String::new()), "re-enrollment refused as a takeover");
    assert_eq!(relay_get(Some("ds-http-rot-tun2"), &new).0, 200);
    assert!(tunnel_bound_to("ds-http-rot-tun2", &new), "tunnel not bound to the new token");
    assert_eq!(connected("ds-http-rot-tun2"), Some(true));
}

#[test]
fn rotating_leaves_the_tunnel_of_a_secret_holder_alone() {
    let owner = "owner-http-rot-tun3";
    let old = htok(owner);
    let a = enroll("ds-http-rot-tun3-a", owner);
    assert_eq!(hello("ds-http-rot-tun3-b", &old, false).0, 204, "an old-token device the rotate does drop");
    rotate_enroll_token(owner);
    assert_eq!(connected("ds-http-rot-tun3-b"), Some(false), "control: the rotate dropped something");
    assert_eq!(connected("ds-http-rot-tun3-a"), Some(true), "the secret holder's tunnel was dropped");
    assert!(tunnel_bound_to("ds-http-rot-tun3-a", &a), "the secret holder's tunnel is no longer bound to its secret");
    assert_eq!(relay_get(Some("ds-http-rot-tun3-a"), &a).0, 200);
    assert_eq!(hello("ds-http-rot-tun3-a", &a, false).0, 204);
}

#[test]
fn revoke_makes_the_next_call_401_and_the_owner_can_re_enroll() {
    let owner = "owner-http-revoke";
    let s = enroll("ds-http-rev", owner);
    let target = enc("relay://ds-http-rev");
    // Someone who does not own the device cannot revoke it.
    let (st, _, _) = call("POST", &format!("/x/device-secret/revoke?target={target}"), "", &[("X-AppCrane-User-Email", "stranger@test.example")]);
    assert_eq!(st, 403);
    assert!(has("ds-http-rev"));
    assert_eq!(call("GET", &format!("/x/device-secret/revoke?target={target}"), "", &[]).0, 404, "POST only");

    let (st, _, body) = call("POST", &format!("/x/device-secret/revoke?target={target}"), "", &[]);
    assert_eq!((st, body.as_str()), (200, r#"{"ok":true,"revoked":true}"#));
    assert!(audited("revoke device secret", "host-ds-http-rev"));
    assert_eq!(hello("ds-http-rev", &s, false), (401, REJECTED.to_string()));
    assert_eq!(relay_get(Some("ds-http-rev"), &s), (401, REJECTED.to_string()));
    // Re-enrollment with the enrollment token (the agent's fallback) gets a new secret.
    let s2 = enroll("ds-http-rev", owner);
    assert_eq!(hello("ds-http-rev", &s2, false).0, 204);
}

/// A fake 3.7 agent: long-polls its tunnel with its device secret and answers the
/// first request it is sent with 200.
fn fake_agent(rid: &'static str, secret: String) -> std::thread::JoinHandle<Option<String>> {
    std::thread::spawn(move || {
        let c = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(40)).build().unwrap();
        for _ in 0..3 {
            let r = c.get(format!("{}/relay/poll?id={rid}&tok={secret}", hub())).send().ok()?;
            if r.status().as_u16() != 200 {
                continue;
            }
            let job: serde_json::Value = r.json().ok()?;
            let req_id = job["id"].as_u64()?;
            c.post(format!("{}/relay/reply?id={rid}&tok={secret}&req={req_id}&st=200&ct=text%2Fplain", hub())).body("dissolving").send().ok()?;
            return job["p"].as_str().map(String::from);
        }
        None
    })
}

fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    false
}

#[test]
fn removing_or_dissolving_a_device_deletes_its_secret() {
    // Remove.
    enroll("ds-http-forget", "owner-http-gone");
    let (st, _, _) = call("GET", &format!("/x/forget?target={}", enc("relay://ds-http-forget")), "", &[]);
    assert_eq!(st, 200);
    assert!(!has("ds-http-forget"), "remove left the secret behind");

    // Dissolve, device online: delivered through its tunnel, which polls with its secret.
    let s = enroll("ds-http-dis", "owner-http-gone");
    let agent = fake_agent("ds-http-dis", s);
    let (st, _, body) = call("GET", &format!("/x/dissolve?target={}", enc("relay://ds-http-dis")), "", &[]);
    assert_eq!((st, body.as_str()), (200, "dissolving"));
    assert_eq!(agent.join().unwrap().as_deref(), Some("/dissolve"));
    assert!(!has("ds-http-dis"), "dissolve left the secret behind");

    // Dissolve queued while offline: the secret must survive until the dissolve is
    // delivered (the device reconnects on it to receive it), then go.
    let s = enroll("ds-http-dis-q", "owner-http-gone");
    crate::queue_dissolve("relay:ds-http-dis-q");
    let agent = fake_agent("ds-http-dis-q", s.clone());
    assert_eq!(hello("ds-http-dis-q", &s, false).0, 204, "the device reconnects on its secret");
    assert_eq!(agent.join().unwrap().as_deref(), Some("/dissolve"));
    assert!(eventually(|| !has("ds-http-dis-q")), "queued dissolve left the secret behind");
}

#[test]
fn another_owners_enrollment_token_cannot_take_over_a_tunnel_with_no_secret() {
    // A ≤ 3.6 device: its tunnel is bound to its owner's enrollment token, no secret.
    let mine = htok("owner-http-legacy");
    assert_eq!(hello("ds-http-legacy", &mine, false).0, 204);
    let other = htok("owner-http-intruder");
    for ds in [false, true] {
        let (st, body) = hello("ds-http-legacy", &other, ds);
        assert_eq!((st, body.as_str()), (403, IN_USE), "ds={ds}");
        assert!(!tunnel_bound_to("ds-http-legacy", &other), "ds={ds}: tunnel re-bound to another owner");
    }
    assert!(!has("ds-http-legacy"), "nothing minted for the intruder");
    assert!(tunnel_bound_to("ds-http-legacy", &mine), "control: still the device's own token");
}

/// Both places a relay device's owner lives: the persisted override and the
/// `/agents` row (which `may_control` reads).
fn owner_state(rid: &str) -> (Option<String>, Option<String>) {
    let ov = crate::owner_override(&format!("relay:{rid}"));
    let (st, _, body) = call("GET", "/agents", "", &[]);
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let row = v["agents"].as_array().unwrap().iter().find(|a| a["relay_id"] == rid).and_then(|a| a["owner"].as_str().map(String::from));
    (ov, row)
}

fn owned_by(owner: &str) -> (Option<String>, Option<String>) {
    (Some(owner.to_string()), Some(owner.to_string()))
}

#[test]
fn a_refused_hello_with_another_owners_token_leaves_the_owner_alone() {
    let x = htok("owner-http-own-x");
    assert_eq!(hello("ds-http-own-noss", &x, false).0, 204);
    assert_eq!(owner_state("ds-http-own-noss"), owned_by("owner-http-own-x"), "control: enrolled under X");
    let y = htok("owner-http-own-y");
    for ds in [false, true] {
        let (st, body) = hello("ds-http-own-noss", &y, ds);
        assert_eq!((st, body.as_str()), (403, IN_USE), "ds={ds}");
        assert_eq!(owner_state("ds-http-own-noss"), owned_by("owner-http-own-x"), "ds={ds}: a refused hello changed the owner");
    }
}

#[test]
fn a_refused_hello_against_a_secret_holder_leaves_the_owner_alone() {
    let s = enroll("ds-http-own-sec", "owner-http-own-sx");
    assert_eq!(owner_state("ds-http-own-sec"), owned_by("owner-http-own-sx"), "control: enrolled under X");
    let y = htok("owner-http-own-sy");
    for ds in [false, true] {
        let (st, body) = hello("ds-http-own-sec", &y, ds);
        assert_eq!((st, body.as_str()), (403, IN_USE), "ds={ds}");
        assert_eq!(owner_state("ds-http-own-sec"), owned_by("owner-http-own-sx"), "ds={ds}: a refused hello changed the owner");
    }
    assert_eq!(verify("ds-http-own-sec", &s).as_deref(), Some("owner-http-own-sx"));
    assert_eq!(hello("ds-http-own-sec", &s, false).0, 204, "the device keeps working");
}

#[test]
fn the_legitimate_enrollment_and_re_enrollment_still_record_the_owner() {
    let x = htok("owner-http-own-legit");
    assert_eq!(owner_state("ds-http-own-legit").0, None, "control: no owner before enrolling");
    let s = enroll("ds-http-own-legit", "owner-http-own-legit");
    assert_eq!(owner_state("ds-http-own-legit"), owned_by("owner-http-own-legit"), "first enrollment sets the owner");
    // The owner's own token re-enrolls (lost secret): a new secret, same owner.
    let s2 = enroll("ds-http-own-legit", "owner-http-own-legit");
    assert_ne!(s, s2);
    assert_eq!(owner_state("ds-http-own-legit"), owned_by("owner-http-own-legit"));
    assert_eq!(hello("ds-http-own-legit", &s2, false).0, 204);
    // A ≤ 3.6 device on the enrollment token: first hello records the owner too.
    assert_eq!(hello("ds-http-own-legit-old", &x, false).0, 204);
    assert_eq!(owner_state("ds-http-own-legit-old"), owned_by("owner-http-own-legit"));
    assert_eq!(hello("ds-http-own-legit-old", &x, false).0, 204, "heartbeat on its own token");
}

#[test]
fn the_device_list_says_which_credential_each_device_relays_with() {
    let owner = "owner-http-list";
    enroll("ds-http-list-own", owner);
    assert_eq!(hello("ds-http-list-enr", &htok(owner), false).0, 204);
    let (st, _, body) = call("GET", "/agents", "", &[]);
    assert_eq!(st, 200);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    let flag = |rid: &str| {
        v["agents"].as_array().unwrap().iter().find(|a| a["relay_id"] == rid).map(|a| a["device_secret"].clone())
    };
    assert_eq!(flag("ds-http-list-own"), Some(serde_json::json!(true)));
    assert_eq!(flag("ds-http-list-enr"), Some(serde_json::json!(false)));

    // The page carries the per-device status + Revoke, and the Rotate warning.
    let (st, _, html) = call("GET", "/", "", &[]);
    assert_eq!(st, 200);
    for needle in ["id=\"d-cred\"", "id=\"ds-warn\"", "function dsRevoke()", "/x/device-secret/revoke", "dsRegWarn();", "dsCred(d);", "credChip(d)", "will be disconnected", "+dsWarnText()+"] {
        assert!(html.contains(needle), "dashboard is missing {needle}");
    }
    assert!(!html.contains("devices already enrolled are unaffected"), "stale rotation text");
}

// ---- after a hub restart ---------------------------------------------------------
// The tunnel registry is in memory; owners, device secrets and enrollment tokens are
// persisted. `relay::drop_tunnel(rid)` is exactly what a restart loses for `rid`
// (the whole registry is not cleared: tests share one hub and run in parallel).

/// Per ds: (ds, status, body, owner state).
type Outcomes = Vec<(bool, u16, String, (Option<String>, Option<String>))>;

fn restart(rid: &str) {
    crate::relay::drop_tunnel(rid);
}

/// For ds = false, then true: (status, body, owner state) of `tok`'s hello for `rid`
/// right after a restart. Both are collected before asserting so a failure shows both.
fn after_restart(rid: &str, tok: &str) -> Outcomes {
    [false, true]
        .into_iter()
        .map(|ds| {
            restart(rid);
            let (st, body) = hello(rid, tok, ds);
            // Never print a minted secret in a failure message.
            let body = if body.contains(PREFIX) { "<device secret minted>".to_string() } else { body };
            (ds, st, body, owner_state(rid))
        })
        .collect()
}

fn refused_and_owned_by(owner: &str) -> Outcomes {
    [false, true].into_iter().map(|ds| (ds, 403, IN_USE.to_string(), owned_by(owner))).collect()
}

#[test]
fn after_a_restart_another_owners_token_cannot_claim_a_device_holding_a_secret() {
    let s = enroll("ds-http-rs-sec", "owner-http-rs-sx");
    assert_eq!(owner_state("ds-http-rs-sec"), owned_by("owner-http-rs-sx"), "control: enrolled under X");
    let y = htok("owner-http-rs-sy");
    assert_eq!(after_restart("ds-http-rs-sec", &y), refused_and_owned_by("owner-http-rs-sx"));
    assert_eq!(verify("ds-http-rs-sec", &s).as_deref(), Some("owner-http-rs-sx"), "secret untouched");
    restart("ds-http-rs-sec");
    assert_eq!(hello("ds-http-rs-sec", &s, false).0, 204, "the device reconnects on its own secret");
    assert_eq!(owner_state("ds-http-rs-sec"), owned_by("owner-http-rs-sx"));
}

#[test]
fn after_a_restart_another_owners_token_cannot_claim_a_device_without_a_secret() {
    let x = htok("owner-http-rs-nx");
    assert_eq!(hello("ds-http-rs-nos", &x, false).0, 204);
    assert_eq!(owner_state("ds-http-rs-nos"), owned_by("owner-http-rs-nx"), "control: enrolled under X");
    let y = htok("owner-http-rs-ny");
    assert_eq!(after_restart("ds-http-rs-nos", &y), refused_and_owned_by("owner-http-rs-nx"));
    assert!(!has("ds-http-rs-nos"), "a secret was minted for another owner");
}

#[test]
fn after_a_restart_the_shared_relay_token_cannot_claim_an_owned_device() {
    let x = htok("owner-http-rs-shx");
    assert_eq!(hello("ds-http-rs-shared", &x, false).0, 204);
    for (ds, st, _, owners) in after_restart("ds-http-rs-shared", crate::testenv::RELAY_TOKEN) {
        assert_eq!(st, 403, "ds={ds}");
        assert_eq!(owners, owned_by("owner-http-rs-shx"), "ds={ds}");
    }
    assert!(!has("ds-http-rs-shared"));
}

#[test]
fn after_a_restart_the_owner_re_enrolls_and_the_device_reconnects() {
    let owner = "owner-http-rs-own";
    let x = htok(owner);
    // Secret holder: reconnects on its hdev_, and its owner's token re-enrolls it.
    let s = enroll("ds-http-rs-own", owner);
    restart("ds-http-rs-own");
    assert_eq!(hello("ds-http-rs-own", &s, false), (204, String::new()));
    restart("ds-http-rs-own");
    let s2 = enroll("ds-http-rs-own", owner);
    assert_ne!(s, s2);
    assert_eq!(hello("ds-http-rs-own", &s2, false).0, 204);
    assert_eq!(owner_state("ds-http-rs-own"), owned_by(owner));
    // Enrollment-token device: its owner's token reconnects it, with or without ds=1.
    assert_eq!(hello("ds-http-rs-own-old", &x, false).0, 204);
    restart("ds-http-rs-own-old");
    assert_eq!(hello("ds-http-rs-own-old", &x, false), (204, String::new()));
    restart("ds-http-rs-own-old");
    assert_eq!(hello("ds-http-rs-own-old", &x, true).0, 200);
    assert_eq!(owner_state("ds-http-rs-own-old"), owned_by(owner));
    // A rotated token of the same owner re-enrolls it too.
    let new = rotate_enroll_token(owner);
    restart("ds-http-rs-own-old");
    assert_eq!(hello("ds-http-rs-own-old", &new, true).0, 200);
    assert_eq!(owner_state("ds-http-rs-own-old"), owned_by(owner));
}

#[test]
fn after_a_restart_a_new_id_still_enrolls_under_any_owner() {
    let y = htok("owner-http-rs-new");
    assert_eq!(owner_state("ds-http-rs-new").0, None, "control: unowned");
    assert_eq!(hello("ds-http-rs-new", &y, false), (204, String::new()));
    assert_eq!(owner_state("ds-http-rs-new"), owned_by("owner-http-rs-new"));
    assert_eq!(owner_state("ds-http-rs-new-ds").0, None, "control: unowned");
    enroll("ds-http-rs-new-ds", "owner-http-rs-new");
    assert_eq!(owner_state("ds-http-rs-new-ds"), owned_by("owner-http-rs-new"));
}

// ---- the VPN exit goes with the credential ---------------------------------------

/// A device with its VPN exit enabled and one pass, checked in at the relay with a
/// client routed to it. Returns what `vpn_alive` needs.
struct Exit {
    rid: &'static str,
    secret: Vec<u8>,
    server_pub: [u8; 32],
    device: std::net::SocketAddr,
    phone: std::net::SocketAddr,
}

fn vpn_exit(rid: &'static str, n: u8) -> Exit {
    hub(); // vpn.json lives under HUB_DATA, which must already point at the test dir
    let server_pub = [n; 32];
    let secret = crate::vpn::enable_for_test(rid, &server_pub);
    let e = Exit { rid, secret, server_pub, device: format!("198.51.100.{n}:40000").parse().unwrap(), phone: format!("203.0.113.{n}:55555").parse().unwrap() };
    assert_eq!(vpn_alive(&e), (true, true, 1), "{rid}: control: the exit works before");
    assert_eq!(crate::vpn::on_disk(rid), (true, 1), "{rid}: control: enabled with a pass on disk");
    e
}

/// (relay ACKs its signed HELLO, relay routes a client to it, clients routed to it)
fn vpn_alive(e: &Exit) -> (bool, bool, usize) {
    crate::vpnrelay::probe(e.rid, &e.secret, &e.server_pub, e.device, e.phone)
}

fn assert_vpn_gone(e: &Exit, after: &str) {
    assert_eq!(crate::vpn::on_disk(e.rid), (false, 0), "{after}: vpn.json still has {}'s exit or passes", e.rid);
    assert_eq!(crate::vpnrelay::device_status(e.rid), (false, 0), "{after}: the relay kept {}'s client sessions", e.rid);
    assert_eq!(vpn_alive(e), (false, false, 0), "{after}: the relay still accepts {}", e.rid);
}

#[test]
fn revoking_the_credential_shuts_the_vpn_exit_down() {
    let owner = "owner-http-vpn-rev";
    enroll("ds-http-vpn-rev-a", owner);
    enroll("ds-http-vpn-rev-b", owner);
    let a = vpn_exit("ds-http-vpn-rev-a", 61);
    let b = vpn_exit("ds-http-vpn-rev-b", 62);
    let (st, _, body) = call("POST", &format!("/x/device-secret/revoke?target={}", enc("relay://ds-http-vpn-rev-a")), "", &[]);
    assert_eq!((st, body.as_str()), (200, r#"{"ok":true,"revoked":true}"#));
    assert_vpn_gone(&a, "revoke");
    assert!(audited("shut down VPN exit", "host-ds-http-vpn-rev-a"), "the shutdown was not audited");
    // Control: the other device's exit is untouched.
    assert_eq!(vpn_alive(&b), (true, true, 1), "revoking A broke B's exit");
    assert_eq!(crate::vpn::on_disk(b.rid), (true, 1));
    assert!(!audited("shut down VPN exit", "host-ds-http-vpn-rev-b"));
}

#[test]
fn removing_or_dissolving_a_device_shuts_its_vpn_exit_down() {
    let owner = "owner-http-vpn-gone";
    let b = vpn_exit("ds-http-vpn-keep", 70);

    // Remove (Forget).
    enroll("ds-http-vpn-forget", owner);
    let e = vpn_exit("ds-http-vpn-forget", 71);
    assert_eq!(call("GET", &format!("/x/forget?target={}", enc("relay://ds-http-vpn-forget")), "", &[]).0, 200);
    assert_vpn_gone(&e, "forget");
    assert!(audited("shut down VPN exit", "host-ds-http-vpn-forget"), "forget: not audited");

    // Dissolve, device online.
    let s = enroll("ds-http-vpn-dis", owner);
    let e = vpn_exit("ds-http-vpn-dis", 72);
    let agent = fake_agent("ds-http-vpn-dis", s);
    let (st, _, body) = call("GET", &format!("/x/dissolve?target={}", enc("relay://ds-http-vpn-dis")), "", &[]);
    assert_eq!((st, body.as_str()), (200, "dissolving"));
    assert_eq!(agent.join().unwrap().as_deref(), Some("/dissolve"));
    assert_vpn_gone(&e, "dissolve");
    assert!(audited("shut down VPN exit", "host-ds-http-vpn-dis"), "dissolve: not audited");

    // Dissolve queued while offline: the exit goes once the dissolve is delivered.
    let s = enroll("ds-http-vpn-dis-q", owner);
    let e = vpn_exit("ds-http-vpn-dis-q", 73);
    crate::queue_dissolve("relay:ds-http-vpn-dis-q");
    let agent = fake_agent("ds-http-vpn-dis-q", s.clone());
    assert_eq!(hello("ds-http-vpn-dis-q", &s, false).0, 204);
    assert_eq!(agent.join().unwrap().as_deref(), Some("/dissolve"));
    assert!(eventually(|| crate::vpn::on_disk(e.rid) == (false, 0)), "queued dissolve: vpn.json still has the exit");
    assert_vpn_gone(&e, "queued dissolve");
    assert!(audited("shut down VPN exit", "host-ds-http-vpn-dis-q"), "queued dissolve: not audited");

    // Control: a device nobody touched keeps its exit.
    assert_eq!(vpn_alive(&b), (true, true, 1), "another device's exit was shut down");
    assert_eq!(crate::vpn::on_disk(b.rid), (true, 1));
}
