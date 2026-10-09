//! UDP relay for the VPN exit (see vpn.rs and the agent's vpn.rs).
//!
//! Exit devices sit behind CGNAT, so phones cannot reach them. Both sides talk
//! to this socket instead: the device dials out with HMAC-authenticated HELLO
//! frames (which also keep its NAT mapping open), and clients send plain
//! WireGuard here. The relay moves packets between them and never sees
//! plaintext — everything it forwards is WireGuard ciphertext.
//!
//! Routing a new client to the right device uses WireGuard's own `mac1` field:
//! a handshake initiation carries a MAC keyed by the responder's public key, so
//! the relay knows which device it is for without any extra protocol on the
//! phone. After that the client's address is pinned to that device. Junk that is
//! not a valid initiation for a known device is dropped here, and DATA from a
//! device is only delivered to clients that recently spoke to that device, so
//! the relay cannot be used to reflect traffic at arbitrary hosts.
//!
//! Wire format (shared with haive-agent crates/agent/src/vpn.rs):
//!   HELLO  device→relay  F0 01 | ts_ms u64 BE | idlen u8 | id | hmac_sha256[32]
//!   ACK    relay→device  F0 02 | ts_ms u64 BE (echo)
//!   DATA   both ways     F0 03 | fam u8 (4|6) | ip | port u16 BE | payload

use blake2::digest::{consts::U16, Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use sha2::Sha256;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAGIC: u8 = 0xF0;
pub const T_HELLO: u8 = 1;
pub const T_ACK: u8 = 2;
pub const T_DATA: u8 = 3;
/// A device that has not said HELLO for this long is treated as offline.
const DEVICE_TTL: Duration = Duration::from_secs(35);
/// A client that has been silent this long must handshake again to be routed.
const SESSION_TTL: Duration = Duration::from_secs(180);
/// A client the device has not answered within this long is dropped first.
const PENDING_TTL: Duration = Duration::from_secs(10);
/// Session caps: overall (memory), per exit device, and per client IP (generous:
/// phones behind one carrier NAT share an IP). A full cap evicts its own oldest
/// unanswered session, so a flood only ever displaces its own kind.
const MAX_SESSIONS: usize = 4096;
const MAX_SESSIONS_PER_DEVICE: usize = 256;
const MAX_SESSIONS_PER_IP: usize = 64;
/// HELLO timestamps must be within this of our clock (replay window).
const CLOCK_SKEW_MS: u64 = 120_000;

struct Dev {
    secret: Vec<u8>,
    mac1_key: [u8; 32],
    addr: Option<SocketAddr>,
    last_ts: u64,
    last_seen: Option<Instant>,
}

/// A client pinned to a device. `answered` once the device sent it a handshake
/// response or transport data: it is a real peer of that device.
struct Session {
    device: String,
    last: Instant,
    answered: bool,
}

impl Session {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.last) >= if self.answered { SESSION_TTL } else { PENDING_TTL }
    }
}

#[derive(Default)]
struct Relay {
    devs: HashMap<String, Dev>,
    sessions: HashMap<SocketAddr, Session>,
}

fn relay() -> &'static Mutex<Relay> {
    static R: OnceLock<Mutex<Relay>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Relay::default()))
}

static SOCK: OnceLock<UdpSocket> = OnceLock::new();

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// WireGuard's mac1 key for a responder: BLAKE2s-256("mac1----" || pubkey).
pub fn mac1_key(server_pubkey: &[u8; 32]) -> [u8; 32] {
    Blake2s256::new().chain_update(b"mac1----").chain_update(server_pubkey).finalize().into()
}

/// Is `pkt` a handshake initiation addressed to the responder owning `key`?
pub fn initiation_matches(pkt: &[u8], key: &[u8; 32]) -> bool {
    if pkt.len() != 148 || pkt[0] != 1 || pkt[1..4] != [0, 0, 0] {
        return false;
    }
    let Ok(mut m) = <Blake2sMac<U16> as KeyInit>::new_from_slice(key) else { return false };
    m.update(&pkt[..116]);
    ct_eq(&m.finalize().into_bytes(), &pkt[116..132])
}

pub fn encode_data(client: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(payload.len() + 22);
    f.extend_from_slice(&[MAGIC, T_DATA]);
    match client.ip() {
        IpAddr::V4(ip) => {
            f.push(4);
            f.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            f.push(6);
            f.extend_from_slice(&ip.octets());
        }
    }
    f.extend_from_slice(&client.port().to_be_bytes());
    f.extend_from_slice(payload);
    f
}

pub fn decode_data(f: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if f.len() < 3 || f[0] != MAGIC || f[1] != T_DATA {
        return None;
    }
    let (ip, rest): (IpAddr, &[u8]) = match f[2] {
        4 if f.len() >= 9 => (IpAddr::from(<[u8; 4]>::try_from(&f[3..7]).ok()?), &f[7..]),
        6 if f.len() >= 21 => (IpAddr::from(<[u8; 16]>::try_from(&f[3..19]).ok()?), &f[19..]),
        _ => return None,
    };
    Some((SocketAddr::new(ip, u16::from_be_bytes([rest[0], rest[1]])), &rest[2..]))
}

/// `(device id, ts_ms)` of an authentic HELLO, given a lookup from id to secret.
pub fn verify_hello<'a>(f: &'a [u8], secret_for: impl Fn(&str) -> Option<Vec<u8>>) -> Option<(&'a str, u64)> {
    if f.len() < 11 + 32 || f[0] != MAGIC || f[1] != T_HELLO {
        return None;
    }
    let ts = u64::from_be_bytes(f[2..10].try_into().ok()?);
    let idlen = f[10] as usize;
    if f.len() != 11 + idlen + 32 {
        return None;
    }
    let id = std::str::from_utf8(&f[11..11 + idlen]).ok()?;
    let secret = secret_for(id)?;
    let (body, mac) = f.split_at(11 + idlen);
    ct_eq(&hmac_sha256(&secret, body), mac).then_some((id, ts))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// Bind the relay socket and serve it on a background thread. A bind failure is
/// reported and the hub carries on without the VPN.
pub fn start(port: u16) {
    let sock = match UdpSocket::bind(("0.0.0.0", port)) {
        Ok(s) => s,
        Err(e) => {
            println!("[vpn] relay: cannot bind UDP {port}: {e} — VPN exit disabled");
            return;
        }
    };
    println!("[vpn] relay listening on UDP {port}");
    let _ = SOCK.set(sock);
    std::thread::spawn(|| {
        let sock = SOCK.get().unwrap();
        let mut buf = vec![0u8; 65535];
        let mut n_since_prune = 0u32;
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
            for (dst, pkt) in route(&buf[..n], from, Instant::now(), now_ms()) {
                let _ = sock.send_to(&pkt, dst);
            }
            n_since_prune += 1;
            if n_since_prune >= 1000 {
                n_since_prune = 0;
                prune(Instant::now());
            }
        }
    });
}

fn prune(now: Instant) {
    relay().lock().unwrap().sessions.retain(|_, s| !s.expired(now));
}

/// Get under `cap` sessions matching `of`, evicting the stalest one that is
/// unanswered or expired. False if every one of them is answered and live: then
/// only this IP or this device is turned away, never everyone.
fn make_room(r: &mut Relay, of: &dyn Fn(&SocketAddr, &Session) -> bool, cap: usize, now: Instant) -> bool {
    let mut n = 0;
    let mut victim: Option<(SocketAddr, Instant)> = None;
    for (a, s) in r.sessions.iter().filter(|(a, s)| of(a, s)) {
        n += 1;
        if (!s.answered || s.expired(now)) && victim.is_none_or(|(_, t)| s.last < t) {
            victim = Some((*a, s.last));
        }
    }
    if n < cap {
        return true;
    }
    victim.is_some_and(|(a, _)| r.sessions.remove(&a).is_some())
}

/// Room for a new session from `ip` to `device`, under the per-IP, per-device and
/// overall caps in turn.
fn admit(r: &mut Relay, ip: IpAddr, device: &str, now: Instant) -> bool {
    make_room(r, &|a, _| a.ip() == ip, MAX_SESSIONS_PER_IP, now)
        && make_room(r, &|_, s| s.device == device, MAX_SESSIONS_PER_DEVICE, now)
        && make_room(r, &|_, _| true, MAX_SESSIONS, now)
}

/// Decide what one incoming datagram turns into. Pure apart from the relay
/// table, so the routing rules can be tested without sockets.
fn route(pkt: &[u8], from: SocketAddr, now: Instant, wall_ms: u64) -> Vec<(SocketAddr, Vec<u8>)> {
    route_in(&mut relay().lock().unwrap(), pkt, from, now, wall_ms)
}

fn route_in(r: &mut Relay, pkt: &[u8], from: SocketAddr, now: Instant, wall_ms: u64) -> Vec<(SocketAddr, Vec<u8>)> {
    if pkt.first() == Some(&MAGIC) {
        if pkt.get(1) == Some(&T_HELLO) {
            let Some((id, ts)) = verify_hello(pkt, |id| r.devs.get(id).map(|d| d.secret.clone())) else { return vec![] };
            let id = id.to_string();
            let dev = r.devs.get_mut(&id).unwrap();
            // Strictly increasing and close to our clock: a captured HELLO replayed
            // from elsewhere cannot steal the device's traffic.
            if ts <= dev.last_ts || ts.abs_diff(wall_ms) > CLOCK_SKEW_MS {
                return vec![];
            }
            dev.last_ts = ts;
            dev.addr = Some(from);
            dev.last_seen = Some(now);
            let mut ack = vec![MAGIC, T_ACK];
            ack.extend_from_slice(&ts.to_be_bytes());
            return vec![(from, ack)];
        }
        if let Some((client, payload)) = decode_data(pkt) {
            // Only from the device's current address, and only to a client that
            // is talking to THAT device right now.
            let Some(id) = r.devs.iter().find(|(_, d)| d.addr == Some(from)).map(|(id, _)| id.clone()) else { return vec![] };
            if let Some(s) = r.sessions.get_mut(&client) {
                if s.device == id && now.duration_since(s.last) < SESSION_TTL {
                    // A handshake response or transport data: the device took this
                    // client as a peer. (Not a cookie reply, which anyone can get.)
                    if matches!(payload.first(), Some(2 | 4)) {
                        s.answered = true;
                    }
                    return vec![(client, payload.to_vec())];
                }
            }
        }
        return vec![];
    }
    // Plain WireGuard from a client.
    if pkt.len() < 4 || !(1..=4).contains(&pkt[0]) || pkt[1..4] != [0, 0, 0] {
        return vec![];
    }
    let live = |d: &Dev| d.addr.is_some() && d.last_seen.map(|t| now.duration_since(t) < DEVICE_TTL).unwrap_or(false);
    let target = if pkt[0] == 1 {
        // Only an initiation exactly one device answers to. `set_device` refuses a
        // second device with the same key; if one existed anyway, routing to either
        // would hand it the other's clients.
        let mut m = r.devs.iter().filter(|(_, d)| initiation_matches(pkt, &d.mac1_key));
        match (m.next(), m.next()) {
            (Some((id, d)), None) if live(d) => Some(id.clone()),
            _ => None,
        }
    } else {
        r.sessions.get(&from).filter(|s| now.duration_since(s.last) < SESSION_TTL).map(|s| s.device.clone())
    };
    let Some(id) = target else { return vec![] };
    match r.sessions.get_mut(&from) {
        Some(s) if s.device == id => s.last = now,
        _ => {
            // New, or re-pinned to another device: it takes a slot like any newcomer.
            r.sessions.remove(&from);
            if !admit(r, from.ip(), &id, now) {
                return vec![];
            }
            r.sessions.insert(from, Session { device: id.clone(), last: now, answered: false });
        }
    }
    match r.devs.get(&id) {
        Some(d) if live(d) => vec![(d.addr.unwrap(), encode_data(from, pkt))],
        _ => vec![],
    }
}

/// Register (or update) an exit device. Keeps its learned address across updates.
/// Refuses a server key another device already uses, and names that device:
/// clients are routed by the key, so a copy could take the other device's clients.
pub fn set_device(id: &str, secret: Vec<u8>, server_pubkey: &[u8; 32]) -> Result<(), String> {
    let mut r = relay().lock().unwrap();
    let key = mac1_key(server_pubkey);
    if let Some(other) = r.devs.iter().find(|(o, d)| o.as_str() != id && d.mac1_key == key).map(|(o, _)| o.clone()) {
        return Err(other);
    }
    let d = r.devs.entry(id.to_string()).or_insert(Dev { secret: vec![], mac1_key: key, addr: None, last_ts: 0, last_seen: None });
    d.secret = secret;
    d.mac1_key = key;
    Ok(())
}

pub fn remove_device(id: &str) {
    let mut r = relay().lock().unwrap();
    r.devs.remove(id);
    r.sessions.retain(|_, s| s.device != id);
}

/// `(device connected to the relay, clients routed to it)`.
pub fn device_status(id: &str) -> (bool, usize) {
    let r = relay().lock().unwrap();
    let now = Instant::now();
    let connected = r.devs.get(id).and_then(|d| d.last_seen).map(|t| now.duration_since(t) < DEVICE_TTL).unwrap_or(false);
    let clients = r.sessions.values().filter(|s| s.device == id && now.duration_since(s.last) < SESSION_TTL).count();
    (connected, clients)
}

pub fn running() -> bool {
    SOCK.get().is_some()
}

/// For tests outside this module: does the relay ACK a freshly signed HELLO from
/// `id` at `device`, and then route a client's handshake for `server_pub` to it?
/// Also returns the clients routed to `id` afterwards.
#[cfg(test)]
pub(crate) fn probe(id: &str, secret: &[u8], server_pub: &[u8; 32], device: SocketAddr, phone: SocketAddr) -> (bool, bool, usize) {
    // HELLO timestamps must strictly increase per device, even within one ms.
    static LAST: Mutex<u64> = Mutex::new(0);
    let ts = {
        let mut l = LAST.lock().unwrap();
        *l = (*l + 1).max(now_ms());
        *l
    };
    let now = Instant::now();
    let out = route(&tests::hello(id, secret, ts), device, now, ts);
    let acked = out.len() == 1 && out[0].0 == device && out[0].1[..2] == [MAGIC, T_ACK];
    let out = route(&tests::initiation(server_pub), phone, now, ts);
    let routed = out.len() == 1 && out[0].0 == device;
    (acked, routed, device_status(id).1)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn hello(id: &str, secret: &[u8], ts: u64) -> Vec<u8> {
        let mut f = vec![MAGIC, T_HELLO];
        f.extend_from_slice(&ts.to_be_bytes());
        f.push(id.len() as u8);
        f.extend_from_slice(id.as_bytes());
        let mac = hmac_sha256(secret, &f);
        f.extend_from_slice(&mac);
        f
    }

    pub(super) fn initiation(server_pub: &[u8; 32]) -> Vec<u8> {
        let mut p = vec![0u8; 148];
        p[0] = 1;
        for (i, b) in p.iter_mut().enumerate().take(116).skip(4) {
            *b = i as u8;
        }
        let mut m = <Blake2sMac<U16> as KeyInit>::new_from_slice(&mac1_key(server_pub)).unwrap();
        m.update(&p[..116]);
        p[116..132].copy_from_slice(&m.finalize().into_bytes());
        p
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        let hex: String = hmac_sha256(b"Jefe", b"what do ya want for nothing?").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
    }

    #[test]
    fn end_to_end_routing() {
        let (id, secret, server_pub) = ("hc-test-route", b"s3cret-s3cret-s3".to_vec(), [7u8; 32]);
        set_device(id, secret.clone(), &server_pub).unwrap();
        let device: SocketAddr = "198.51.100.9:40000".parse().unwrap();
        let phone: SocketAddr = "203.0.113.5:55555".parse().unwrap();
        let stranger: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let t0 = Instant::now();
        let wall = now_ms();

        // A client handshake before the device has checked in goes nowhere.
        assert!(route(&initiation(&server_pub), phone, t0, wall).is_empty());

        // Forged and replayed HELLOs are ignored; a genuine one is acked.
        assert!(route(&hello(id, b"wrong", wall), device, t0, wall).is_empty());
        let out = route(&hello(id, &secret, wall), device, t0, wall);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, device);
        assert_eq!(&out[0].1[..2], &[MAGIC, T_ACK]);
        assert!(route(&hello(id, &secret, wall), stranger, t0, wall).is_empty(), "replay from another address");
        assert!(route(&hello(id, &secret, wall + 10 * CLOCK_SKEW_MS), stranger, t0, wall).is_empty(), "far-future ts");
        assert_eq!(device_status(id).0, true);

        // A valid initiation for this device is framed and sent to it.
        let init = initiation(&server_pub);
        let out = route(&init, phone, t0, wall);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, device);
        let (client, payload) = decode_data(&out[0].1).unwrap();
        assert_eq!((client, payload), (phone, &init[..]));

        // An initiation for some other server is dropped.
        assert!(route(&initiation(&[9u8; 32]), stranger, t0, wall).is_empty());
        // Transport data from an unknown address is dropped.
        assert!(route(&[4, 0, 0, 0, 1, 2, 3], stranger, t0, wall).is_empty());

        // Device → phone works; device → a host that never spoke to it does not (no reflection).
        let back = route(&encode_data(phone, b"\x02\0\0\0resp"), device, t0, wall);
        assert_eq!(back, vec![(phone, b"\x02\0\0\0resp".to_vec())]);
        assert!(route(&encode_data(stranger, b"x"), device, t0, wall).is_empty());
        // DATA from anywhere but the device's address is ignored.
        assert!(route(&encode_data(phone, b"x"), stranger, t0, wall).is_empty());

        // After the session goes stale the phone must handshake again.
        let later = t0 + SESSION_TTL + Duration::from_secs(1);
        assert!(route(&[4, 0, 0, 0, 9], phone, later, wall).is_empty());

        remove_device(id);
        assert!(route(&init, phone, t0, wall).is_empty());
    }

    #[test]
    fn a_second_device_cannot_register_another_devices_server_key() {
        let (key, a, b) = ([31u8; 32], "hc-test-key-a", "hc-test-key-b");
        set_device(a, b"secret-a".to_vec(), &key).unwrap();
        assert_eq!(set_device(b, b"secret-b".to_vec(), &key), Err(a.to_string()));
        assert!(set_device(a, b"secret-a".to_vec(), &key).is_ok(), "a device may re-register its own key");
        let wall = now_ms();
        let t0 = Instant::now();
        assert!(route(&hello(b, b"secret-b", wall), "198.51.100.32:1".parse().unwrap(), t0, wall).is_empty(), "the refused device was registered");
        let dev_a: SocketAddr = "198.51.100.31:1".parse().unwrap();
        assert_eq!(route(&hello(a, b"secret-a", wall), dev_a, t0, wall).len(), 1);
        let out = route(&initiation(&key), "203.0.113.31:1".parse().unwrap(), t0, wall);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, dev_a, "A's client went elsewhere");
        remove_device(a);
    }

    #[test]
    fn an_initiation_matching_two_devices_goes_to_neither() {
        let (key, a, b) = ([33u8; 32], "hc-test-dup-a", "hc-test-dup-b");
        set_device(a, b"secret-a".to_vec(), &key).unwrap();
        // A copy that got in some other way (set_device would refuse it).
        relay().lock().unwrap().devs.insert(b.to_string(), Dev { secret: b"secret-b".to_vec(), mac1_key: mac1_key(&key), addr: None, last_ts: 0, last_seen: None });
        let wall = now_ms();
        let t0 = Instant::now();
        let (dev_a, dev_b): (SocketAddr, SocketAddr) = ("198.51.100.33:1".parse().unwrap(), "198.51.100.34:1".parse().unwrap());
        assert_eq!(route(&hello(a, b"secret-a", wall), dev_a, t0, wall).len(), 1);
        assert_eq!(route(&hello(b, b"secret-b", wall), dev_b, t0, wall).len(), 1);
        let phone: SocketAddr = "203.0.113.33:1".parse().unwrap();
        assert!(route(&initiation(&key), phone, t0, wall).is_empty(), "routed to one of two devices sharing a key");
        remove_device(b);
        assert_eq!(route(&initiation(&key), phone, t0, wall)[0].0, dev_a, "control: one device with the key is routed");
        remove_device(a);
    }

    fn add_dev(r: &mut Relay, id: &str, key: &[u8; 32]) {
        r.devs.insert(id.to_string(), Dev { secret: id.as_bytes().to_vec(), mac1_key: mac1_key(key), addr: None, last_ts: 0, last_seen: None });
    }

    /// A private relay table with live devices `ids` (server key [n; 32] each) at
    /// 198.51.100.n. A table of its own, so filling it cannot evict other tests'.
    fn table(ids: &[(&str, u8)], t0: Instant, wall: u64) -> Relay {
        let mut r = Relay::default();
        for (id, n) in ids {
            add_dev(&mut r, id, &[*n; 32]);
            let dev = SocketAddr::new(IpAddr::from([198, 51, 100, *n]), 40000);
            assert_eq!(route_in(&mut r, &hello(id, id.as_bytes(), wall), dev, t0, wall).len(), 1, "{id} HELLO");
        }
        r
    }

    fn dev_addr(n: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::from([198, 51, 100, n]), 40000)
    }

    /// `client` handshakes with device n and the device answers: an established peer.
    fn connect(r: &mut Relay, client: SocketAddr, n: u8, t: Instant, wall: u64) -> bool {
        let out = route_in(r, &initiation(&[n; 32]), client, t, wall);
        if out.len() != 1 || out[0].0 != dev_addr(n) {
            return false;
        }
        route_in(r, &encode_data(client, b"\x02\0\0\0resp"), dev_addr(n), t, wall) == vec![(client, b"\x02\0\0\0resp".to_vec())]
    }

    #[test]
    fn a_flood_cannot_lock_another_device_out() {
        let (t0, wall) = (Instant::now(), now_ms());
        type From = Box<dyn Fn(u32) -> (SocketAddr, u8)>;
        let floods: [(&str, From); 3] = [
            ("A, from one IP on many ports", Box::new(|i| (SocketAddr::new(IpAddr::from([192, 0, 2, 1]), 1024 + i as u16), 51))),
            ("A, from many IPs", Box::new(|i| (SocketAddr::new(IpAddr::from([10, (i >> 16) as u8, (i >> 8) as u8, i as u8]), 5000), 51))),
            ("17 other devices, from one IP", Box::new(|i| (SocketAddr::new(IpAddr::from([192, 0, 2, 2]), 1024 + i as u16), 60 + (i % 17) as u8))),
        ];
        for (flood, from) in floods {
            let mut ids: Vec<(String, u8)> = vec![("hc-flood-a".into(), 51), ("hc-flood-b".into(), 52)];
            ids.extend((60..77u8).map(|n| (format!("hc-flood-{n}"), n)));
            let refs: Vec<(&str, u8)> = ids.iter().map(|(s, n)| (s.as_str(), *n)).collect();
            let mut r = table(&refs, t0, wall);
            let a_phone: SocketAddr = "203.0.113.51:1000".parse().unwrap();
            assert!(connect(&mut r, a_phone, 51, t0, wall), "{flood}: control: A's client connects");
            // B's client is mid-handshake when the flood starts.
            let b_phone: SocketAddr = "198.18.0.7:4000".parse().unwrap();
            assert_eq!(route_in(&mut r, &initiation(&[52; 32]), b_phone, t0, wall).len(), 1);
            // Each flood packet a microsecond later, so B's pending session is the
            // oldest unanswered one: the first to go if the flood can reach it.
            let n_flood = MAX_SESSIONS as u32 + 1000;
            for i in 0..n_flood {
                let (src, n) = from(i);
                route_in(&mut r, &initiation(&[n; 32]), src, t0 + Duration::from_micros(i as u64 + 1), wall);
            }
            let t1 = t0 + Duration::from_micros(n_flood as u64 + 1);
            assert!(r.sessions.len() <= MAX_SESSIONS, "{flood}: {} sessions", r.sessions.len());
            let resp = b"\x02\0\0\0resp".to_vec();
            assert_eq!(route_in(&mut r, &encode_data(b_phone, &resp), dev_addr(52), t1, wall), vec![(b_phone, resp)], "{flood}: B's pending client was evicted");
            assert!(connect(&mut r, "198.18.0.8:4000".parse().unwrap(), 52, t1, wall), "{flood}: a new client of B was locked out");
            assert_eq!(route_in(&mut r, &[4, 0, 0, 0, 1], a_phone, t1, wall).len(), 1, "{flood}: A's established client was evicted");
        }
    }

    #[test]
    fn a_full_table_evicts_unanswered_sessions_not_established_ones() {
        let (t0, wall) = (Instant::now(), now_ms());
        let ids: Vec<(String, u8)> = (100..118u8).map(|n| (format!("hc-full-{n}"), n)).collect();
        let refs: Vec<(&str, u8)> = ids.iter().map(|(s, n)| (s.as_str(), *n)).collect();
        let mut r = table(&refs, t0, wall);
        let old: SocketAddr = "203.0.113.100:1".parse().unwrap();
        assert!(connect(&mut r, old, 100, t0, wall));
        // Unanswered handshakes from many IPs to 17 devices: more than the table holds.
        let mut i = 0u32;
        for n in 101..118u8 {
            for _ in 0..MAX_SESSIONS_PER_DEVICE {
                i += 1;
                route_in(&mut r, &initiation(&[n; 32]), SocketAddr::new(IpAddr::from([10, 9, (i >> 8) as u8, i as u8]), 7000), t0 + Duration::from_micros(i as u64), wall);
            }
        }
        let t1 = t0 + Duration::from_micros(i as u64 + 1);
        assert_eq!(r.sessions.len(), MAX_SESSIONS, "the table should be full");
        assert!(connect(&mut r, "198.18.0.9:4000".parse().unwrap(), 100, t1, wall), "a newcomer is refused when the table is full");
        assert_eq!(route_in(&mut r, &[4, 0, 0, 0, 1], old, t1, wall).len(), 1, "an established client was evicted");
    }

    #[test]
    fn data_frames_round_trip() {
        for a in ["203.0.113.7:51000", "[2001:db8::1]:443"] {
            let addr: SocketAddr = a.parse().unwrap();
            let f = encode_data(addr, b"abc");
            assert_eq!(decode_data(&f).unwrap(), (addr, &b"abc"[..]));
        }
        assert!(decode_data(&[MAGIC, T_DATA, 6, 1]).is_none());
    }
}
