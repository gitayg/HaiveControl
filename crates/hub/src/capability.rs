// IT-AI — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The IT-AI Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hub-issued capability tokens for the LAN-direct path.
//!
//! A controller that shares a LAN with an agent talks to it straight over TCP and
//! never touches `proxy_exec`/`proxy_input` — so the four controls those run
//! (`may_control`, `policy::enforce`, `record_mcp_access`, `audit`) would be
//! skipped entirely. A capability token puts them back: the controller must first
//! ask the hub, at `/m/capability`, for permission to perform one specific
//! operation on one specific device with one specific argument. The hub runs the
//! same four controls it would have run for a proxied call and, only on success,
//! signs a 60-second token the agent verifies before serving the direct request.
//!
//! The token is deliberately narrow — it names the device, the operation and a
//! hash of the argument — so it cannot be replayed against a different device, a
//! different endpoint, or a different command. The agent additionally refuses a
//! repeated `nonce`, so it cannot be replayed against the same one either.
//!
//! The key is ed25519 and lives only here. It is NOT the rcgen CA key (that one
//! is ECDSA P-256, which the agent has no verifier for) and NOT the release
//! signing key `UPDATE_PUBKEY` (whose private half must never be on the hub).

use std::sync::OnceLock;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::data_dir;

/// Token lifetime. Long enough to cover a mint + a LAN round trip with clock
/// skew, short enough that a captured token is worthless by the time it could be
/// replayed anywhere useful.
pub const TTL_SECS: u64 = 60;

/// The operations a capability can name. Frozen wire contract — the agent
/// matches on exactly these strings.
const OPS: &[&str] = &["exec", "launch", "input", "frame", "camera", "download", "upload", "shell"];

pub fn is_known_op(op: &str) -> bool {
    OPS.contains(&op)
}

/// The deny-list kind `policy::enforce` should be asked about for an operation.
/// `exec`/`launch`/`input` map to the same kinds `proxy_exec`/`proxy_input` use,
/// so a command denied through the hub proxy is denied through a capability too.
pub fn policy_kind(op: &str) -> &'static str {
    // The op names were chosen to match the deny-list kinds `proxy_exec` and
    // `proxy_input` already pass, so this is an identity map. It exists so the
    // two vocabularies stay explicitly linked rather than accidentally equal.
    match op {
        "exec" => "exec",
        "launch" => "launch",
        "input" => "input",
        "frame" => "frame",
        "camera" => "camera",
        "download" => "download",
        "upload" => "upload",
        _ => "shell",
    }
}

fn key_path() -> std::path::PathBuf {
    data_dir().join("cap.key")
}

/// The capability signing key — loaded from HUB_DATA, or generated once and
/// persisted there (same persist-or-generate shape as the CA in `ca.rs`). Stored
/// as the 32-byte ed25519 seed in hex, owner-only, so a lost file means agents
/// reject every token minted by the old key rather than silently accepting both.
///
/// Every failure here is fatal by design. This key IS the authorization boundary
/// for the LAN-direct path: a seed that could not be persisted would be
/// regenerated on the next hub restart (silently invalidating every agent's
/// pinned key), and a seed found world-readable is one an attacker may already
/// hold. Neither is something to continue past, so both stop the request loudly
/// instead of degrading into a hub that mints tokens nobody should trust.
fn signing_key() -> &'static SigningKey {
    static KEY: OnceLock<SigningKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let p = key_path();
        let existing = crate::secretfile::read_secret(&p)
            .unwrap_or_else(|e| panic!("capability key unusable: {e}"));
        if let Some(s) = existing {
            let seed = hex32(s.trim())
                .unwrap_or_else(|| panic!("{} is not 64 hex characters — delete it to re-key", p.display()));
            return SigningKey::from_bytes(&seed);
        }
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).expect("cap key entropy");
        crate::secretfile::ensure_private_dir(&data_dir())
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", data_dir().display()));
        crate::secretfile::write_new_secret(&p, &hex(&seed))
            .unwrap_or_else(|e| panic!("cannot persist {}: {e}", p.display()));
        SigningKey::from_bytes(&seed)
    })
}

/// The 32-byte ed25519 public key as lowercase hex — served at `/m/cap-key` and
/// fetched by every agent at startup.
pub fn public_key_hex() -> String {
    hex(signing_key().verifying_key().as_bytes())
}

/// The canonicalization rule for a capability's `arg`, shared verbatim with the
/// agent: lowercase hex SHA-256 over the UTF-8 bytes of the operation's canonical
/// argument string, with no trimming, no case folding and no normalization. An
/// operation with no meaningful argument hashes the empty string.
pub fn arg_hash(arg: &str) -> String {
    let mut h = Sha256::new();
    h.update(arg.as_bytes());
    hex(&h.finalize())
}

/// Sign a capability for one device + operation + argument. Returns the compact
/// token and its expiry. Callers must have run the authorization, policy and
/// audit controls first — minting is the last step, never the first.
pub fn mint(relay_id: &str, op: &str, arg: &str) -> (String, u64) {
    let iat = now();
    let exp = iat + TTL_SECS;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).expect("cap nonce entropy");
    // Built by hand rather than through serde so the byte order of the signed
    // payload is fixed by this literal and cannot drift with a struct field
    // reorder — the agent verifies the signature over exactly these bytes.
    let payload = serde_json::json!({
        "v": 1,
        "dev": relay_id,
        "op": op,
        "arg": arg_hash(arg),
        "iat": iat,
        "exp": exp,
        "nonce": hex(&nonce),
    })
    .to_string();
    let sig = signing_key().sign(payload.as_bytes());
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    (format!("{}.{}", b64.encode(payload.as_bytes()), b64.encode(sig.to_bytes())), exp)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}
