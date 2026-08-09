// Runtime policy enforcement (#13): a deny-by-default-capable gate consulted BEFORE
// any write action reaches a device — raw exec, canned device-actions, AI fixes, and
// input injection all pass through it. This is the substrate the plan-first (#1),
// AI-script (#9), and auto-remediation (#2) features build on.
//
// The policy is loaded from $HUB_DATA/policy.json. ABSENT or unparseable = permissive
// (allow everything), so existing deployments are unaffected until an admin writes a
// policy. It is re-read from disk on every check (write actions are low-frequency), so
// an edit takes effect immediately without a hub restart. A policy can:
//   - deny action kinds outright        → "deny_actions":   ["shutdown","exec"]
//   - deny commands matching a substring → "deny_patterns":  ["rm -rf","format ","mkfs"]
//   - require approval for destructive kinds → "require_approval": ["reboot","shutdown"]
//
// The enforcement point is deterministic and runs before the agent is contacted —
// the pattern the 2026 agentic-security guidance calls the pre-dispatch policy check.

#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub deny_actions: Vec<String>,
    pub deny_patterns: Vec<String>,
    pub require_approval: Vec<String>,
}

/// The result of evaluating a write action against the active policy.
#[allow(dead_code)] // NeedApproval + check() are consumed by the plan-first (#1) flow.
pub enum Decision {
    Allow,
    Deny(String),
    NeedApproval(String),
}

fn policy_path() -> std::path::PathBuf {
    crate::data_dir().join("policy.json")
}

/// Load the active policy (permissive default when the file is absent/invalid).
pub fn load() -> Policy {
    let v: serde_json::Value = std::fs::read(policy_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    let arr = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(|x| x.as_array())
            .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    Policy {
        deny_actions: arr("deny_actions"),
        deny_patterns: arr("deny_patterns"),
        require_approval: arr("require_approval"),
    }
}

/// Evaluate a write action. `kind` is the action verb (`exec`, `launch`, `reboot`,
/// `shutdown`, a fix kind, `input`, `install`, …); `detail` is the command/arg used
/// for substring matching. Case-insensitive throughout.
pub fn check(kind: &str, detail: &str) -> Decision {
    let p = load();
    let k = kind.to_ascii_lowercase();
    if p.deny_actions.iter().any(|a| a.eq_ignore_ascii_case(&k)) {
        return Decision::Deny(format!("action '{kind}' is blocked by hub policy"));
    }
    let hay = format!("{k} {}", detail.to_ascii_lowercase());
    if let Some(pat) = p
        .deny_patterns
        .iter()
        .find(|pat| !pat.is_empty() && hay.contains(&pat.to_ascii_lowercase()))
    {
        return Decision::Deny(format!("command blocked by hub policy (matched '{pat}')"));
    }
    if p.require_approval.iter().any(|a| a.eq_ignore_ascii_case(&k)) {
        return Decision::NeedApproval(format!("action '{kind}' requires approval by hub policy"));
    }
    Decision::Allow
}

/// A remediation the admin has mapped to a failing compliance check (#2). `auto`
/// means "apply without waiting for a human" — but auto-apply still passes through
/// `enforce`, so a deny rule wins and an auto remediation of a policy-denied action
/// is refused rather than run.
#[derive(Debug, Clone)]
pub struct Remediation {
    pub kind: String,
    pub arg: String,
    pub auto: bool,
}

/// Look up the admin-configured remediation for a failed check kind (encryption /
/// firewall / av / updates), from policy.json's `"remediations": { "<check>":
/// {"kind": "...", "arg": "...", "auto": false} }`. None = no mapping (the default;
/// a failed check just gets surfaced, nothing runs).
pub fn remediation_for(check: &str) -> Option<Remediation> {
    let v: serde_json::Value = std::fs::read(policy_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(serde_json::Value::Null);
    let r = v.get("remediations")?.get(check)?;
    let kind = r.get("kind")?.as_str()?.to_string();
    if kind.is_empty() {
        return None;
    }
    Some(Remediation {
        kind,
        arg: r.get("arg").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        auto: r.get("auto").and_then(|x| x.as_bool()).unwrap_or(false),
    })
}

/// Enforce the deny rules for a direct (already-authorized) write path: `Deny` →
/// `Err(reason)`. `NeedApproval` is treated as allowed here — those paths are the
/// human-approved execution itself; the plan-first AI flow surfaces approval before
/// it reaches this point.
pub fn enforce(kind: &str, detail: &str) -> Result<(), String> {
    match check(kind, detail) {
        Decision::Deny(r) => Err(r),
        _ => Ok(()),
    }
}
