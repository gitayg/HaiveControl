// Scoped, expiring MCP tokens (#11). Each token is bound SERVER-SIDE to an owner and
// a scope (read | write | admin) with a TTL — so a leaked token has a bounded blast
// radius and can't be re-pointed at another owner's devices by passing a different
// `?owner=` (the M1 gap in the security review). Only the sha256 of each secret is
// stored (in $HUB_DATA/mcp-tokens.json); the plaintext is shown once, at mint.
//
// The legacy shared MCP_TOKEN env var still works (full access, owner taken from the
// caller) for backward compatibility — scoped tokens are additive.
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone)]
pub struct Scoped {
    #[allow(dead_code)]
    pub id: String,
    pub owner: String,
    pub scope: String,
    #[allow(dead_code)]
    pub expires_at: u64,
}

fn store_path() -> std::path::PathBuf {
    crate::data_dir().join("mcp-tokens.json")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hash(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}

fn read_all() -> Vec<serde_json::Value> {
    std::fs::read(store_path())
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

fn write_all(items: &[serde_json::Value]) {
    let _ = std::fs::create_dir_all(crate::data_dir());
    let _ = std::fs::write(
        store_path(),
        serde_json::to_vec_pretty(&serde_json::json!(items)).unwrap_or_default(),
    );
}

/// Resolve a presented secret to a live (non-expired) scoped token, or None.
pub fn resolve(secret: &str) -> Option<Scoped> {
    if secret.is_empty() {
        return None;
    }
    let h = hash(secret);
    let n = now();
    for t in read_all() {
        if t.get("hash").and_then(|x| x.as_str()) == Some(h.as_str()) {
            let exp = t.get("expires_at").and_then(|x| x.as_u64()).unwrap_or(0);
            if exp != 0 && exp < n {
                return None; // expired
            }
            return Some(Scoped {
                id: t.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                owner: t.get("owner").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                scope: t.get("scope").and_then(|x| x.as_str()).unwrap_or("read").to_string(),
                expires_at: exp,
            });
        }
    }
    None
}

/// Mint a token for `owner` with `scope` (read|write|admin) and `ttl_days` (0 = no
/// expiry). Returns (id, plaintext secret) — only the hash is persisted.
pub fn mint(owner: &str, scope: &str, ttl_days: u64) -> (String, String) {
    let id = format!("mtk_{}", crate::rand_token().trim_start_matches("htok_"));
    let secret = format!("mcp_{}", crate::rand_token().trim_start_matches("htok_"));
    let scope = match scope {
        "write" | "admin" => scope,
        _ => "read",
    };
    let expires_at = if ttl_days == 0 { 0 } else { now() + ttl_days * 86400 };
    let mut items = read_all();
    items.push(serde_json::json!({
        "id": id, "owner": owner, "scope": scope,
        "expires_at": expires_at, "hash": hash(&secret), "created_at": now(),
    }));
    write_all(&items);
    (id, secret)
}

/// Revoke a token by id (only if it belongs to `owner`). Returns true if removed.
pub fn revoke(id: &str, owner: &str) -> bool {
    let mut items = read_all();
    let before = items.len();
    items.retain(|t| {
        !(t.get("id").and_then(|x| x.as_str()) == Some(id)
            && t.get("owner").and_then(|x| x.as_str()) == Some(owner))
    });
    if items.len() != before {
        write_all(&items);
        true
    } else {
        false
    }
}

/// Public listing for one owner (no hashes/secrets).
pub fn list(owner: &str) -> Vec<serde_json::Value> {
    read_all()
        .into_iter()
        .filter(|t| t.get("owner").and_then(|x| x.as_str()) == Some(owner))
        .map(|t| {
            serde_json::json!({
                "id": t.get("id").cloned().unwrap_or_default(),
                "scope": t.get("scope").cloned().unwrap_or_default(),
                "expires_at": t.get("expires_at").cloned().unwrap_or_default(),
                "created_at": t.get("created_at").cloned().unwrap_or_default(),
            })
        })
        .collect()
}
