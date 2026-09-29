// Background jobs — the hub half of docs/JOBS-API.md ("Hub"). A job is a long-running
// command on a device (dev server, build) that outlives one run_command; the agent owns
// the process and its log, the hub only authorizes, audits and relays.
//
// `job/start` is the one that matters for security: it carries a command, so it gets
// exactly the `/m/exec` treatment — exempt from the generic /m and /x preambles (the
// deny-list needs the command text, which only the body has) and running its own
// may_control → policy::enforce("launch") → record_mcp_access → audit before forwarding.
// Starting a job must never be a way around the deny-list or the audit log.
// logs/stop/list carry their target in the query, so the normal preamble covers them.

use tiny_http::{Request, Response};

use crate::{audit, dev_unary, device_name, hdr, json_resp, may_control, policy, query_param, record_mcp_access, Agents, Resp};

pub(crate) const START_LABEL: &str = "start job";
pub(crate) const STOP_LABEL: &str = "stop job";

/// Job ids are `j` + unix millis + hex — only `[a-z0-9]`. Checked hub-side too, so a
/// caller can't smuggle extra query params into the agent path.
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The audit/access detail the generic preamble records for a jobs path: the job id
/// for stop, nothing otherwise.
pub(crate) fn audit_detail(path: &str, url: &str) -> String {
    if path.ends_with("/job/stop") {
        query_param(url, "id").unwrap_or_default()
    } else {
        String::new()
    }
}

fn refuse(status: u16, error: &str) -> Resp {
    json_resp(&serde_json::json!({"ok": false, "error": error})).with_status_code(status)
}

/// The agent's JSON goes back verbatim with its status. A non-JSON body (an agent
/// that predates jobs answers 404 "not found") becomes an `{"ok":false}` refusal so
/// the CLI/MCP always get JSON.
pub(crate) fn agent_reply(status: u16, body: Vec<u8>) -> (u16, Vec<u8>) {
    if serde_json::from_slice::<serde_json::Value>(&body).is_ok() {
        return (status, body);
    }
    let text = String::from_utf8_lossy(&body).trim().chars().take(200).collect::<String>();
    let error = if status == 404 {
        "the agent does not support jobs — update it".to_string()
    } else {
        format!("agent returned {status}: {text}")
    };
    (status, serde_json::json!({"ok": false, "error": error}).to_string().into_bytes())
}

fn forward(target: &str, method: &str, path: &str, body: Option<(String, Vec<u8>)>) -> Resp {
    match dev_unary(target, method, path, body) {
        Some((st, _ct, b)) => {
            let (st, b) = agent_reply(st, b);
            Response::from_data(b).with_status_code(st).with_header(hdr("Content-Type", "application/json"))
        }
        None => json_resp(&serde_json::json!({"ok": false, "error": "device unreachable"})),
    }
}

/// POST /m/job/start · /x/job/start `?target=` with body `{"cmd", "cwd"?}`.
pub(crate) fn start(req: &mut Request, url: &str, agents: &Agents, user: Option<&str>, via_mcp: bool) -> Resp {
    let mut body = String::new();
    let _ = req.as_reader().read_to_string(&mut body);
    let target = query_param(url, "target").unwrap_or_default();
    if !may_control(user, agents, &target) {
        return json_resp(&serde_json::json!({"ok": false, "error": "forbidden"}));
    }
    let v: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
    let cmd = v.get("cmd").and_then(|x| x.as_str()).unwrap_or("");
    // Same gate as a detached /exec: a job is a launched command.
    if let Err(e) = policy::enforce("launch", cmd) {
        return json_resp(&serde_json::json!({"ok": false, "error": e}));
    }
    if via_mcp {
        record_mcp_access(&target, START_LABEL, user.unwrap_or(""), cmd);
    }
    audit(user.unwrap_or(""), if via_mcp { "mcp" } else { "browser" }, START_LABEL, &device_name(agents, &target), cmd);
    let mut fwd = serde_json::json!({ "cmd": cmd });
    if let Some(cwd) = v.get("cwd").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        fwd["cwd"] = serde_json::json!(cwd);
    }
    forward(&target, "POST", "/jobs/start", Some(("application/json".into(), fwd.to_string().into_bytes())))
}

/// The agent path for a logs read, or None when id/offset/max are malformed.
pub(crate) fn logs_path(url: &str) -> Option<String> {
    let id = query_param(url, "id").unwrap_or_default();
    if !valid_id(&id) {
        return None;
    }
    let mut p = format!("/jobs/logs?id={id}");
    for k in ["offset", "max"] {
        if let Some(n) = query_param(url, k).filter(|s| !s.is_empty()) {
            p.push_str(&format!("&{k}={}", n.parse::<u64>().ok()?));
        }
    }
    Some(p)
}

/// GET /m/job/logs · /x/job/logs `?target=&id=&offset=&max=`.
pub(crate) fn logs(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    match logs_path(url) {
        Some(p) => forward(&target, "GET", &p, None),
        None => refuse(400, "bad job id, offset or max"),
    }
}

/// POST /m/job/stop · /x/job/stop `?target=&id=` (audited by the preamble).
pub(crate) fn stop(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    let id = query_param(url, "id").unwrap_or_default();
    if !valid_id(&id) {
        return refuse(400, "bad job id");
    }
    forward(&target, "POST", &format!("/jobs/stop?id={id}"), None)
}

/// GET /m/job/list · /x/job/list `?target=`.
pub(crate) fn list(url: &str) -> Resp {
    let target = query_param(url, "target").unwrap_or_default();
    forward(&target, "GET", "/jobs/list", None)
}

pub(crate) const JOBS_CSS: &str = r#"
.jb-form{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px}
.jb-form .devsearch{margin:0;flex:2;min-width:180px}
.jb-form .jb-cwd{flex:1;min-width:140px}
.jb-msg{font-size:11px;color:var(--muted);min-height:14px;margin:-2px 0 6px}
.jb-msg.bad{color:#d9694f}
.jb-row{display:flex;align-items:center;gap:8px;padding:7px 10px;border:1px solid var(--line2);border-radius:8px;font-size:12px}
.jb-row.sel{border-color:var(--accent)}
.jb-cmd{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px}
.jb-st{font-size:10px;font-weight:700;white-space:nowrap}
.jb-run{color:#4fb06a}.jb-ok{color:var(--muted)}.jb-bad{color:#d9694f}
.jb-when{font-size:10px;color:var(--muted);white-space:nowrap}
.jb-row .b{padding:3px 9px}
.jb-log{margin-top:8px;border:1px solid var(--line2);border-radius:8px;overflow:hidden}
.jb-log-h{display:flex;align-items:center;gap:8px;padding:7px 10px;font-size:12px;border-bottom:1px solid var(--line2)}
.jb-log-h .an-upd{margin-left:auto}
.jb-out{margin:0;padding:8px 10px;font-size:11px;max-height:360px;overflow:auto;white-space:pre-wrap;word-break:break-word;background:#0b0d13;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
@media (max-width:700px){.jb-when{display:none}}
"#;

pub(crate) const JOBS_JS: &str = r#"<script>
/* ---- background jobs (docs/JOBS-API.md) ---- */
var JB_T=null,JB_ID=null,JB_OFF=0,JB_TOK=0,JB_TIMER=null;
function jbUrl(p,extra){return API+'/x/job/'+p+'?target='+enc(JB_T)+(extra||'');}
function jbMsg(t,bad){var m=document.getElementById('jb-msg');if(!m)return;m.textContent=t||'';m.className='jb-msg'+(bad?' bad':'');}
function jbStopPoll(){JB_TOK++;if(JB_TIMER){clearTimeout(JB_TIMER);JB_TIMER=null;}}
function jobsOpen(t){jbStopPoll();JB_T=t;JB_ID=null;JB_OFF=0;var el=document.getElementById('d-jobs');if(!el)return;
el.innerHTML='<div class="an-head"><span class="an-title">Background jobs <span class="dim2">— long-running commands: dev servers, builds</span></span><button class="b subtle an-rf" title="refresh" onclick="jobsLoad()">↻</button></div>'+
'<div class="jb-form"><input id="jb-cmd" class="devsearch" placeholder="command, e.g. npm run dev" autocomplete="off"><input id="jb-cwd" class="devsearch jb-cwd" placeholder="working dir (optional)" autocomplete="off"><button class="b" onclick="jobsStart()">Start job</button></div>'+
'<div id="jb-msg" class="jb-msg"></div><div id="jb-list" class="an-secs"><div class="an-empty">Loading jobs…</div></div>'+
'<div id="jb-log" class="jb-log" style="display:none"><div class="jb-log-h"><span class="an-lbl" id="jb-log-t"></span><span class="an-upd" id="jb-log-s"></span><button class="b subtle" onclick="jobsCloseLog()">Close</button></div><pre id="jb-out" class="jb-out"></pre></div>';
document.getElementById('jb-cmd').addEventListener('keydown',function(e){if(e.key==='Enter'){e.preventDefault();jobsStart();}});
jobsLoad();}
function jbStatus(j){if(j.running)return '<span class="jb-st jb-run">● running</span>';if(j.exit_code==null)return '<span class="jb-st jb-ok">ended</span>';return '<span class="jb-st '+(j.exit_code===0?'jb-ok':'jb-bad')+'">exit '+j.exit_code+'</span>';}
function jobsLoad(){var t=JB_T;if(!t)return;fetch(jbUrl('list'),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(t!==JB_T)return;var el=document.getElementById('jb-list');if(!el)return;if(!j.ok){el.innerHTML='<div class="an-empty">'+esc2(j.error||'could not list jobs')+'</div>';return;}var jobs=(j.jobs||[]).slice().sort(function(a,b){return (b.started||0)-(a.started||0);});if(!jobs.length){el.innerHTML='<div class="an-empty">No jobs on this device yet.</div>';return;}
el.innerHTML=jobs.map(function(x){var when=x.started?new Date(x.started*1000).toLocaleString():'';return '<div class="jb-row'+(x.id===JB_ID?' sel':'')+'">'+jbStatus(x)+'<span class="jb-cmd" title="'+attrEsc(x.cmd||'')+'">'+esc2(x.cmd||'')+'</span><span class="jb-when">'+esc2(when)+'</span><button class="b subtle" onclick="jobsView(\''+attrEsc(x.id)+'\',this)">Logs</button>'+(x.running?'<button class="b danger" onclick="jobsStop(\''+attrEsc(x.id)+'\')">Stop</button>':'')+'</div>';}).join('');}).catch(function(e){if(t===JB_T)jbMsg('error: '+e,1);});}
function jobsStart(){var c=document.getElementById('jb-cmd'),w=document.getElementById('jb-cwd');var cmd=(c.value||'').trim(),cwd=(w.value||'').trim();if(!cmd){jbMsg('Enter a command to start.',1);return;}var body={cmd:cmd};if(cwd)body.cwd=cwd;jbMsg('starting…');var t=JB_T;
fetch(jbUrl('start'),{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(j){if(t!==JB_T)return;if(!j.ok){jbMsg('[error] '+(j.error||'failed'),1);return;}c.value='';jbMsg('started '+j.id+(j.pid?(' (pid '+j.pid+')'):''));jobsView(j.id,null,cmd);jobsLoad();}).catch(function(e){jbMsg('error: '+e,1);});}
function jobsView(id,btn,label){jbStopPoll();JB_ID=id;JB_OFF=0;var box=document.getElementById('jb-log');if(!box)return;box.style.display='block';var row=btn&&btn.closest('.jb-row');var lbl=label||(row?row.querySelector('.jb-cmd').textContent:'');document.getElementById('jb-log-t').textContent=id+(lbl?(' — '+lbl):'');document.getElementById('jb-out').textContent='';document.getElementById('jb-log-s').textContent='loading…';document.querySelectorAll('.jb-row').forEach(function(r){r.classList.remove('sel');});if(row)row.classList.add('sel');jbPoll(JB_T,id,JB_TOK);}
function jbPoll(t,id,tok){if(tok!==JB_TOK||t!==JB_T||SEL!==t)return;fetch(jbUrl('logs','&id='+enc(id)+'&offset='+JB_OFF),{cache:'no-store'}).then(function(r){return r.json();}).then(function(j){if(tok!==JB_TOK||t!==JB_T)return;var st=document.getElementById('jb-log-s');if(!j.ok){st.textContent='[error] '+(j.error||'failed');return;}var o=document.getElementById('jb-out');if(j.data){var near=o.scrollTop+o.clientHeight>=o.scrollHeight-24;var s=o.textContent+j.data;if(s.length>400000)s=s.slice(s.length-400000);o.textContent=s;if(near)o.scrollTop=o.scrollHeight;}if(typeof j.offset==='number')JB_OFF=j.offset;
if(j.eof){st.textContent='exited'+(j.exit_code!=null?(' — code '+j.exit_code):'')+' · '+JB_OFF+' bytes';jobsLoad();return;}st.textContent=(j.running?'running':'finishing')+' · '+JB_OFF+' bytes';var more=(typeof j.size==='number'&&JB_OFF<j.size);JB_TIMER=setTimeout(function(){jbPoll(t,id,tok);},more?150:2000);}).catch(function(){if(tok===JB_TOK)JB_TIMER=setTimeout(function(){jbPoll(t,id,tok);},3000);});}
function jobsCloseLog(){jbStopPoll();JB_ID=null;var b=document.getElementById('jb-log');if(b)b.style.display='none';document.querySelectorAll('.jb-row').forEach(function(r){r.classList.remove('sel');});}
function jobsStop(id){if(!confirm('Stop job '+id+'? Its whole process tree is ended.'))return;var t=JB_T;jbMsg('stopping '+id+'…');fetch(jbUrl('stop','&id='+enc(id)),{method:'POST'}).then(function(r){return r.json();}).then(function(j){if(t!==JB_T)return;jbMsg(j.ok?('stopped '+id+(j.exit_code!=null?(' — exit '+j.exit_code):'')):('[error] '+(j.error||'failed')),!j.ok);jobsLoad();if(JB_ID===id)jobsView(id);}).catch(function(e){jbMsg('error: '+e,1);});}
</script>"#;

#[cfg(test)]
mod tests;
