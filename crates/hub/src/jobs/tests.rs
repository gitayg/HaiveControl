use super::{agent_reply, audit_detail, logs_path, valid_id, START_LABEL, STOP_LABEL};
use crate::{action_label, auditable, audit_log, canon_owner, device_key, handle, mcp_is_write, mcptokens, Agent, Agents};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

#[test]
fn job_ids_are_lowercase_alnum_only() {
    assert!(valid_id("j1790420836094a3f1"));
    for bad in ["", "J1", "j1&x=1", "../x", "j-1", "j 1", "j1%26x"] {
        assert!(!valid_id(bad), "should reject id {bad:?}");
    }
}

#[test]
fn start_and_stop_are_writes_logs_and_list_are_reads() {
    assert!(mcp_is_write("/m/job/start", "/m/job/start?target=x"));
    assert!(mcp_is_write("/m/job/stop", "/m/job/stop?target=x&id=j1"));
    assert!(!mcp_is_write("/m/job/logs", "/m/job/logs?target=x&id=j1"));
    assert!(!mcp_is_write("/m/job/list", "/m/job/list?target=x"));
}

#[test]
fn start_and_stop_are_labelled_and_auditable() {
    for p in ["/x/job/start", "/m/job/start"] {
        assert_eq!(action_label(p), START_LABEL);
        assert!(auditable(p));
    }
    for p in ["/x/job/stop", "/m/job/stop"] {
        assert_eq!(action_label(p), STOP_LABEL);
        assert!(auditable(p));
    }
    assert!(!auditable("/m/job/logs"), "log polling is noise, not an audit event");
    assert!(!auditable("/m/job/list"));
}

#[test]
fn stop_is_audited_with_the_job_id() {
    assert_eq!(audit_detail("/m/job/stop", "/m/job/stop?target=t&id=j42"), "j42");
    assert_eq!(audit_detail("/x/frame", "/x/frame?target=t&id=j42"), "");
}

#[test]
fn logs_path_validates_and_rebuilds_the_query() {
    assert_eq!(logs_path("/m/job/logs?target=t&id=j1").as_deref(), Some("/jobs/logs?id=j1"));
    assert_eq!(logs_path("/m/job/logs?target=t&id=j1&offset=10&max=5").as_deref(), Some("/jobs/logs?id=j1&offset=10&max=5"));
    assert_eq!(logs_path("/m/job/logs?target=t&id=j1%26x%3D1"), None, "an encoded & must not reach the agent path");
    assert_eq!(logs_path("/m/job/logs?target=t&id=j1&offset=-1"), None);
    assert_eq!(logs_path("/m/job/logs?target=t&id=j1&max=1%26id%3Dj2"), None);
}

#[test]
fn agent_json_is_verbatim_and_non_json_becomes_a_refusal() {
    let js = br#"{"ok":false,"error":"unknown job"}"#.to_vec();
    assert_eq!(agent_reply(404, js.clone()), (404, js));
    let (st, b) = agent_reply(404, b"not found".to_vec());
    assert_eq!(st, 404);
    let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(v["ok"], false);
    assert!(v["error"].as_str().unwrap().contains("update"), "{v}");
}

// ---- end-to-end through `handle`: a real hub socket in front of a fake agent ----

const RO_OWNER: &str = "ro-jobs@test.example";

struct Fixture {
    hub: String,
    target: String,
    hits: Arc<Mutex<Vec<(String, String, String)>>>, // (method, url, body) seen by the agent
    ro_tok: String,
    rw_tok: String,
}

const AGENT_START_REPLY: &str = r#"{"ok":true,"id":"j1790420836094a3f1","pid":4242,"log":"/tmp/j.log"}"#;

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        // HUB_DATA (with its deny-`rm -rf` policy) and MCP_TOKEN are process-wide, so
        // they come from the one shared setup rather than a fixture of their own.
        crate::testenv::init();
        let (_, ro_tok) = mcptokens::mint(RO_OWNER, "read", 1);
        let (_, rw_tok) = mcptokens::mint(RO_OWNER, "write", 1);

        // Fake agent: records every request, answers like the spec says.
        let agent = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let aport = agent.server_addr().to_ip().unwrap().port();
        let hits: Arc<Mutex<Vec<(String, String, String)>>> = Arc::default();
        let h = hits.clone();
        std::thread::spawn(move || {
            for mut req in agent.incoming_requests() {
                let mut body = String::new();
                let _ = req.as_reader().read_to_string(&mut body);
                let url = req.url().to_string();
                h.lock().unwrap().push((req.method().to_string(), url.clone(), body));
                let reply = if url.starts_with("/jobs/start") { AGENT_START_REPLY } else { r#"{"ok":true}"# };
                let _ = req.respond(tiny_http::Response::from_string(reply));
            }
        });
        let target = format!("http://127.0.0.1:{aport}");

        // The device is owned by the scoped tokens' owner, so ownership never masks
        // the scope check being tested.
        let mut m = HashMap::new();
        m.insert(device_key(&target), Agent { data: serde_json::json!({"owner": canon_owner(RO_OWNER)}), last: std::time::SystemTime::now() });
        let agents: &'static Agents = Box::leak(Box::new(Mutex::new(m)));

        let hub = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let hport = hub.server_addr().to_ip().unwrap().port();
        std::thread::spawn(move || {
            for req in hub.incoming_requests() {
                std::thread::spawn(move || handle(req, agents, "test", "127.0.0.1", hport));
            }
        });
        Fixture { hub: format!("http://127.0.0.1:{hport}"), target, hits, ro_tok, rw_tok }
    })
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn call(method: &str, path_and_query: &str, body: &str) -> (u16, String) {
    let f = fixture();
    let c = reqwest::blocking::Client::new();
    let url = format!("{}{path_and_query}", f.hub);
    let rb = if method == "POST" { c.post(url).body(body.to_string()) } else { c.get(url) };
    let r = rb.send().unwrap();
    (r.status().as_u16(), r.text().unwrap())
}

fn agent_saw(needle: &str) -> bool {
    fixture().hits.lock().unwrap().iter().any(|(_, u, b)| u.contains(needle) || b.contains(needle))
}

fn audited(action: &str, detail: &str) -> bool {
    audit_log().lock().unwrap().iter().any(|(_, _, _, a, _, d)| a == action && d == detail)
}

#[test]
fn denied_job_start_is_refused_before_any_forward() {
    let f = fixture();
    let t = enc(&f.target);
    for (route, cmd) in [("/m/job/start", "rm -rf /tmp/deny-m"), ("/x/job/start", "rm -rf /tmp/deny-x")] {
        let q = format!("{route}?target={t}&mtok=legacy-jobs-test-token");
        let (st, body) = call("POST", &q, &serde_json::json!({ "cmd": cmd }).to_string());
        let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_else(|_| panic!("{route}: not JSON: {st} {body}"));
        assert_eq!(v["ok"], false, "{route}: {body}");
        assert!(v["error"].as_str().unwrap_or("").contains("policy"), "{route}: {body}");
        assert!(!agent_saw(cmd), "{route}: a denied command reached the agent");
        assert!(!audited(START_LABEL, cmd), "{route}: a denied command was audited as started");
    }

    // Positive control: an allowed command IS forwarded (so the absence above is not
    // just a dead fake agent), with its cwd, and the agent's JSON comes back verbatim.
    let q = format!("/m/job/start?target={t}&mtok=legacy-jobs-test-token");
    let (st, body) = call("POST", &q, r#"{"cmd":"echo allowed-job","cwd":"/tmp/wd"}"#);
    assert_eq!((st, body.as_str()), (200, AGENT_START_REPLY));
    let fwd = fixture().hits.lock().unwrap().iter().find(|(_, _, b)| b.contains("allowed-job")).cloned().expect("allowed job forwarded");
    assert_eq!((fwd.0.as_str(), fwd.1.as_str()), ("POST", "/jobs/start"));
    let fb: serde_json::Value = serde_json::from_str(&fwd.2).unwrap();
    assert_eq!(fb, serde_json::json!({"cmd": "echo allowed-job", "cwd": "/tmp/wd"}));
    assert!(audited(START_LABEL, "echo allowed-job"), "an allowed start must be audited with its command");
    // Exempt from the generic preamble: no command-less duplicate audit entry.
    assert!(!audited(START_LABEL, ""), "job/start went through the generic preamble");
}

#[test]
fn read_only_token_is_refused_for_start_and_stop() {
    let f = fixture();
    let t = enc(&f.target);
    let (st, body) = call("POST", &format!("/m/job/start?target={t}&mtok={}", f.ro_tok), r#"{"cmd":"echo ro-start"}"#);
    assert_eq!((st, body.as_str()), (403, "this MCP token is read-only"), "start");
    let (st, body) = call("POST", &format!("/m/job/stop?target={t}&id=jrostop1&mtok={}", f.ro_tok), "");
    assert_eq!((st, body.as_str()), (403, "this MCP token is read-only"), "stop");
    assert!(!agent_saw("ro-start") && !agent_saw("jrostop1"), "a read-only call reached the agent");

    // Controls: the same read token may read logs and list; a write token for the
    // same owner may start and stop — so the 403s above are the scope, nothing else.
    let (st, _) = call("GET", &format!("/m/job/logs?target={t}&id=jrologs1&offset=0&mtok={}", f.ro_tok), "");
    assert_eq!(st, 200);
    assert!(agent_saw("/jobs/logs?id=jrologs1&offset=0"));
    let (st, _) = call("GET", &format!("/m/job/list?target={t}&mtok={}", f.ro_tok), "");
    assert_eq!(st, 200);
    let (st, body) = call("POST", &format!("/m/job/start?target={t}&mtok={}", f.rw_tok), r#"{"cmd":"echo rw-start"}"#);
    assert_eq!((st, body.as_str()), (200, AGENT_START_REPLY));
    let (st, _) = call("POST", &format!("/m/job/stop?target={t}&id=jrwstop1&mtok={}", f.rw_tok), "");
    assert_eq!(st, 200);
    assert!(agent_saw("/jobs/stop?id=jrwstop1"));
}

#[test]
fn stop_is_forwarded_and_audited_with_its_id() {
    let f = fixture();
    let t = enc(&f.target);
    let (st, body) = call("POST", &format!("/x/job/stop?target={t}&id=jauditstop1"), "");
    assert_eq!((st, body.as_str()), (200, r#"{"ok":true}"#));
    assert!(agent_saw("/jobs/stop?id=jauditstop1"));
    assert!(audited(STOP_LABEL, "jauditstop1"));
}

#[test]
fn a_malformed_id_is_refused_without_forwarding() {
    let f = fixture();
    let t = enc(&f.target);
    let (st, body) = call("GET", &format!("/m/job/logs?target={t}&id=j1%26smuggled%3D1&mtok=legacy-jobs-test-token"), "");
    assert_eq!(st, 400, "{body}");
    let (st, _) = call("POST", &format!("/m/job/stop?target={t}&id=j1%26smuggled%3D2&mtok=legacy-jobs-test-token"), "");
    assert_eq!(st, 400);
    assert!(!agent_saw("smuggled"));
}
