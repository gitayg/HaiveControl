// The VPN exit through the real `handle`, with fake agents answering over the relay
// tunnel. Shares the hub fixture with devicesecrets::tests.
use crate::devicesecrets::tests::{audited, call, enc, enroll, hub};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex, OnceLock};

/// The hub fixture plus a bound relay socket: enable refuses without one.
fn vpn_hub() {
    static ON: OnceLock<()> = OnceLock::new();
    ON.get_or_init(|| {
        hub();
        crate::vpnrelay::start(0);
        assert!(crate::vpnrelay::running());
    });
}

/// A fake agent with a VPN, polling its tunnel with its device secret. It answers
/// /vpn/apply with WireGuard key `pubkey`, and keeps every body it was sent there.
fn fake_vpn(rid: &'static str, secret: String, pubkey: String) -> Arc<Mutex<Vec<Value>>> {
    let applied = Arc::new(Mutex::new(Vec::new()));
    let seen = applied.clone();
    std::thread::spawn(move || {
        let c = reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(90)).build().unwrap();
        loop {
            let Ok(r) = c.get(format!("{}/relay/poll?id={rid}&tok={secret}", hub())).send() else { continue };
            if r.status().as_u16() != 200 {
                continue;
            }
            let Ok(job) = r.json::<Value>() else { continue };
            let id = job["id"].as_u64().unwrap();
            let reply = if job["p"] == "/vpn/apply" {
                use base64::Engine;
                let b = base64::engine::general_purpose::STANDARD.decode(job["b"].as_str().unwrap_or("")).unwrap();
                seen.lock().unwrap().push(serde_json::from_slice::<Value>(&b).unwrap());
                json!({"ok": true, "status": {"publicKey": pubkey}})
            } else {
                json!({"ok": true})
            };
            let _ = c.post(format!("{}/relay/reply?id={rid}&tok={secret}&req={id}&st=200&ct=application%2Fjson", hub())).body(reply.to_string()).send();
        }
    });
    applied
}

pub(super) fn target(rid: &str) -> String {
    enc(&format!("relay://{rid}"))
}

/// POST /x/vpn/<path>?target=relay://<rid><q>, as `user` (None = no identity).
fn vpn_post(path: &str, rid: &str, q: &str, user: Option<&str>) -> (u16, Value) {
    let h: Vec<(&str, &str)> = user.map(|u| vec![("X-AppCrane-User-Email", u)]).unwrap_or_default();
    let (st, _, body) = call("POST", &format!("/x/vpn/{path}?target={}{q}", target(rid)), "", &h);
    (st, serde_json::from_str(&body).unwrap_or(json!({"raw": body})))
}

/// (relay ACKs the device's HELLO, routes a client handshake to it, clients routed)
fn routes(rid: &str, pubkey: &str, n: u8) -> (bool, bool, usize) {
    let secret = crate::vpn::hello_secret(rid).expect("enabled");
    let pk = crate::vpn::decode_key(pubkey).unwrap();
    crate::vpnrelay::probe(rid, &secret, &pk, format!("198.51.100.{n}:41000").parse().unwrap(), format!("203.0.113.{n}:56000").parse().unwrap())
}

#[test]
fn a_device_cannot_enable_with_another_devices_wireguard_key() {
    vpn_hub();
    let owner = "owner-vpn-dupkey";
    let pk = crate::vpn::test_key();
    let a = enroll("vpn-dupkey-a", owner);
    fake_vpn("vpn-dupkey-a", a, pk.clone());
    let b = enroll("vpn-dupkey-b", owner);
    fake_vpn("vpn-dupkey-b", b, pk.clone());

    let (st, v) = vpn_post("enable", "vpn-dupkey-a", "", None);
    assert_eq!(st, 200, "{v}");
    let (st, v) = vpn_post("enable", "vpn-dupkey-b", "", None);
    assert_eq!(st, 409, "a second device took A's key: {v}");
    assert!(v["error"].as_str().unwrap().contains("WireGuard key"), "{v}");
    assert!(!v.to_string().contains("vpn-dupkey-a"), "the refusal names the other tenant's device: {v}");
    assert!(audited("VPN exit refused", "vpn-dupkey-b"), "the refusal was not audited");
    assert_eq!(crate::vpn::on_disk("vpn-dupkey-b"), (false, 0));
    assert_eq!(routes("vpn-dupkey-a", &pk, 81), (true, true, 1), "A no longer gets its clients");
}

#[test]
fn a_change_of_owner_shuts_the_vpn_exit_down() {
    use crate::devicesecrets::tests::{assert_vpn_gone, vpn_alive, vpn_exit};
    enroll("vpn-xfer-a", "owner-vpn-xfer-1");
    enroll("vpn-xfer-b", "owner-vpn-xfer-1");
    let a = vpn_exit("vpn-xfer-a", 91);
    let b = vpn_exit("vpn-xfer-b", 92);
    let (st, _, body) = call("GET", &format!("/x/set-owner?target={}&owner=owner-vpn-xfer-2", target("vpn-xfer-a")), "", &[]);
    assert_eq!(st, 200, "{body}");
    assert_vpn_gone(&a, "transfer");
    assert!(audited("shut down VPN exit", "host-vpn-xfer-a"), "the shutdown was not audited");
    // Control: setting B's current owner again is not a change.
    let (st, _, body) = call("GET", &format!("/x/set-owner?target={}&owner=owner-vpn-xfer-1", target("vpn-xfer-b")), "", &[]);
    assert_eq!(st, 200, "{body}");
    assert_eq!(vpn_alive(&b), (true, true, 1), "re-asserting the owner shut B's exit down");
    assert_eq!(crate::vpn::on_disk(b.rid), (true, 1));
}

#[test]
fn a_push_carries_only_passes_the_current_owner_issued() {
    vpn_hub();
    let email = "vpn-push@test.example";
    let owner = crate::canon_owner(email);
    let s = enroll("vpn-push", &owner);
    let applied = fake_vpn("vpn-push", s, crate::vpn::test_key());
    let (st, v) = vpn_post("enable", "vpn-push", "", Some(email));
    assert_eq!(st, 200, "{v}");
    let mine = crate::vpn::add_pass_for_test("vpn-push", &owner);
    let theirs = crate::vpn::add_pass_for_test("vpn-push", "owner-vpn-push-before");
    let (st, v) = vpn_post("pass", "vpn-push", &format!("&hours=1&name=phone&publicKey={}", enc(&crate::vpn::test_key())), Some(email));
    assert_eq!(st, 201, "{v}");
    let last = applied.lock().unwrap().last().cloned().expect("nothing was pushed");
    let keys: Vec<&str> = last["peers"].as_array().unwrap().iter().map(|p| p["publicKey"].as_str().unwrap()).collect();
    assert!(keys.contains(&mine.as_str()), "control: the owner's own pass is missing: {last}");
    assert!(!keys.contains(&theirs.as_str()), "a pass another owner issued was pushed: {last}");
    assert_eq!(keys.len(), 2, "the owner's two passes: {last}");
}

// ---- the client's private key never reaches the hub ----------------------------------

/// An enabled exit on `rid` with a fake agent; returns what the agent was sent.
fn enabled_exit(rid: &'static str, owner: &str) -> Arc<Mutex<Vec<Value>>> {
    vpn_hub();
    let s = enroll(rid, owner);
    let applied = fake_vpn(rid, s, crate::vpn::test_key());
    let (st, v) = vpn_post("enable", rid, "", None);
    assert_eq!(st, 200, "{v}");
    applied
}

fn passes_on_disk(rid: &str) -> usize {
    crate::vpn::on_disk(rid).1
}

#[test]
fn a_pass_needs_the_clients_public_key() {
    let rid = "vpn-pk-required";
    enabled_exit(rid, "owner-vpn-pk-required");
    let bad = [
        ("missing", String::new()),
        ("empty", "&publicKey=".to_string()),
        ("not base64", "&publicKey=not*base64*at*all*not*base64*at*all*".to_string()),
        ("31 bytes", format!("&publicKey={}", enc(&crate::vpn::b64(&[7u8; 31])))),
        ("33 bytes", format!("&publicKey={}", enc(&crate::vpn::b64(&[7u8; 33])))),
        ("a private key's worth of hex", format!("&publicKey={}", "ab".repeat(32))),
    ];
    for (what, q) in bad {
        let (st, v) = vpn_post("pass", rid, &format!("&hours=1&name=phone{q}"), None);
        assert_eq!(st, 400, "{what}: {v}");
        assert!(v["error"].as_str().unwrap_or("").contains("public key"), "{what}: {v}");
    }
    assert_eq!(passes_on_disk(rid), 0, "a refused pass was stored");
    // Control: a valid key is accepted.
    let (st, v) = vpn_post("pass", rid, &format!("&hours=1&name=phone&publicKey={}", enc(&crate::vpn::test_key())), None);
    assert_eq!(st, 201, "{v}");
    assert_eq!(passes_on_disk(rid), 1);
}

#[test]
fn a_pass_response_carries_no_private_key() {
    let rid = "vpn-no-priv";
    let applied = enabled_exit(rid, "owner-vpn-no-priv");
    let pk = crate::vpn::test_key();
    let (st, v) = vpn_post("pass", rid, &format!("&hours=8&name=laptop&publicKey={}", enc(&pk)), None);
    assert_eq!(st, 201, "{v}");
    let text = v.to_string();
    for word in ["PrivateKey", "privateKey", "private_key", "[Interface]", "qrSvg"] {
        assert!(!text.contains(word), "the response has {word}: {text}");
    }
    // Everything the browser needs to write the .conf, except its own private key.
    let w = &v["wireguard"];
    assert!(!applied.lock().unwrap().is_empty(), "control: the exit was pushed to the device");
    let server = crate::vpn::server_key(rid).expect("enabled");
    assert_eq!(w["serverPublicKey"], json!(server), "{v}");
    assert_eq!(w["endpoint"], json!("vpn.test.invalid:51820"), "{v}");
    assert_eq!(w["address"], json!("10.77.0.2/32"), "{v}");
    assert_eq!(w["mtu"], json!(1380), "{v}");
    assert!(w["dns"].as_str().is_some_and(|d| !d.is_empty()), "{v}");
    assert_eq!(w["allowedIps"], json!("0.0.0.0/0, ::/0"), "{v}");
    assert!(v["pass"]["expiresAt"].as_u64().is_some_and(|e| e > v["pass"]["createdAt"].as_u64().unwrap()), "{v}");
    let psk = w["presharedKey"].as_str().expect("psk");
    // The only 32-byte keys in the response: the exit's public key and the pass's PSK.
    // Nothing that could be a private key.
    let mut keys: Vec<String> = Vec::new();
    collect_keys(&v, &mut keys);
    keys.sort();
    let mut want = vec![server.clone(), psk.to_string()];
    want.sort();
    assert_eq!(keys, want, "unexpected key material in {v}");
}

/// Every string in `v` that decodes as a 32-byte base64 key.
fn collect_keys(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if crate::vpn::decode_key(s).is_some() => out.push(s.clone()),
        Value::Array(a) => a.iter().for_each(|x| collect_keys(x, out)),
        Value::Object(o) => o.values().for_each(|x| collect_keys(x, out)),
        _ => {}
    }
}

#[test]
fn the_dashboard_loads_the_pass_scripts_from_the_hub() {
    hub();
    let (st, _, html) = call("GET", "/", "", &[]);
    assert_eq!(st, 200);
    for (name, bytes) in [("x25519.js", crate::X25519_JS), ("qrcode.js", crate::QRCODE_JS), ("vpnpass.js", crate::VPNPASS_JS)] {
        let src = format!("/assets/{name}?v={}", crate::VERSION);
        // The dashboard prefixes the hub's base URL.
        assert!(html.contains(&format!("{src}\"></script>")), "the dashboard does not load {src}");
        let (st, _, body) = call("GET", &src, "", &[]);
        assert_eq!((st, body.as_bytes() == bytes), (200, true), "{src}");
    }
    assert!(!html.contains("cdn") && !html.contains("unpkg"), "a script from a CDN");
}

/// The dashboard half (assets/vpnpass.js) under node: keygen on both paths checked
/// against OpenSSL's X25519, and the .conf built from this real pass response.
#[test]
fn the_dashboard_builds_the_pass_in_the_browser() {
    let rid = "vpn-js-conf";
    enabled_exit(rid, "owner-vpn-js-conf");
    let (st, v) = vpn_post("pass", rid, &format!("&hours=1&name=phone&publicKey={}", enc(&crate::vpn::test_key())), None);
    assert_eq!(st, 201, "{v}");
    let resp = crate::testenv::init().join("vpn-js-conf-response.json");
    std::fs::write(&resp, v.to_string()).unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/vpn/vpnpass_check.js");
    let out = std::process::Command::new("node").arg(&script).arg(&resp).output().expect("node (>= 20) is needed for this test");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "{text}");
    assert!(text.contains("from a real pass response"), "{text}");
}

#[test]
fn the_peer_pushed_to_the_device_is_the_clients_public_key() {
    let rid = "vpn-pk-pushed";
    let applied = enabled_exit(rid, "owner-vpn-pk-pushed");
    let pk = crate::vpn::test_key();
    let (st, v) = vpn_post("pass", rid, &format!("&hours=1&name=phone&publicKey={}", enc(&pk)), None);
    assert_eq!(st, 201, "{v}");
    let last = applied.lock().unwrap().last().cloned().expect("nothing was pushed");
    let peers = last["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1, "{last}");
    assert_eq!(peers[0]["publicKey"], json!(pk), "the device got a key the client did not supply: {last}");
    assert_eq!(peers[0]["presharedKey"], v["wireguard"]["presharedKey"], "{last}");
    assert_eq!(peers[0]["allowedIps"], v["wireguard"]["address"], "{last}");
    // The same key cannot be a second live pass on this device.
    let (st, v) = vpn_post("pass", rid, &format!("&hours=1&name=again&publicKey={}", enc(&pk)), None);
    assert_eq!(st, 409, "{v}");
    assert_eq!(passes_on_disk(rid), 1);
}
