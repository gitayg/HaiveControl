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
    let pk = crate::vpn::keypair().1;
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
    let applied = fake_vpn("vpn-push", s, crate::vpn::keypair().1);
    let (st, v) = vpn_post("enable", "vpn-push", "", Some(email));
    assert_eq!(st, 200, "{v}");
    let mine = crate::vpn::add_pass_for_test("vpn-push", &owner);
    let theirs = crate::vpn::add_pass_for_test("vpn-push", "owner-vpn-push-before");
    let (st, v) = vpn_post("pass", "vpn-push", "&hours=1&name=phone", Some(email));
    assert_eq!(st, 201, "{v}");
    let last = applied.lock().unwrap().last().cloned().expect("nothing was pushed");
    let keys: Vec<&str> = last["peers"].as_array().unwrap().iter().map(|p| p["publicKey"].as_str().unwrap()).collect();
    assert!(keys.contains(&mine.as_str()), "control: the owner's own pass is missing: {last}");
    assert!(!keys.contains(&theirs.as_str()), "a pass another owner issued was pushed: {last}");
    assert_eq!(keys.len(), 2, "the owner's two passes: {last}");
}
