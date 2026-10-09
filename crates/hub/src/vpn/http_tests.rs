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
