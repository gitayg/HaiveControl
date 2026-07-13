// Windows Session 0 isolation: a service runs as SYSTEM in session 0, walled off
// from the interactive desktop — so it can't screen-capture or inject input into
// the logged-in user's session (session 1+). When we detect we're that session-0
// service, we act as a SUPERVISOR instead of serving directly: run the real agent
// inside the active user's session (a per-user scheduled task with an interactive
// token, so it has desktop access), and fall back to a session-0 agent (still
// manageable — exec/reports/presence — capture just won't work) when nobody's
// logged in. Exactly one managed agent runs at a time, all under one relay id
// (the supervisor passes --relay-id), so the device shows up once.
#![cfg(windows)]

use std::os::windows::process::CommandExt;
use std::process::{Child, Command};
use std::time::Duration;

const NO_WINDOW: u32 = 0x0800_0000; // CREATE_NO_WINDOW — no console flash
const TASK: &str = "HaiveDesktopWorker";

/// True when we're running as SYSTEM — i.e. a service in session 0, which can't
/// reach the interactive desktop.
pub fn is_system_service() -> bool {
    Command::new("whoami")
        .creation_flags(NO_WINDOW)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().eq_ignore_ascii_case("nt authority\\system"))
        .unwrap_or(false)
}

/// The username of the active interactive session (prefer the physical console;
/// otherwise any active session with a user, e.g. RDP). None = no user logged on.
fn active_user() -> Option<String> {
    let out = Command::new("query").args(["user"]).creation_flags(NO_WINDOW).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut any_active: Option<String> = None;
    for line in text.lines().skip(1) {
        let cleaned = line.trim_start().trim_start_matches('>').trim_start();
        let low = cleaned.to_lowercase();
        if !low.contains("active") {
            continue;
        }
        let user = match cleaned.split_whitespace().next() {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => continue,
        };
        if low.contains("console") {
            return Some(user);
        }
        if any_active.is_none() {
            any_active = Some(user);
        }
    }
    any_active
}

fn qarg(a: &str) -> String {
    if a.contains(' ') || a.contains('"') {
        format!("\"{}\"", a.replace('"', "\\\""))
    } else {
        a.to_string()
    }
}

fn worker_cmdline(args: &[String]) -> String {
    let exe = std::env::current_exe().unwrap_or_default();
    let mut s = format!("\"{}\"", exe.display());
    for a in args {
        s.push(' ');
        s.push_str(&qarg(a));
    }
    s
}

/// (Re)create + start the per-user worker task. /IT runs it with the user's
/// interactive token (their session, desktop-accessible); no password needed —
/// SYSTEM has the privilege. /F overwrites so a changed user/args take effect.
fn run_worker_for(user: &str, args: &[String]) {
    let tr = worker_cmdline(args);
    let _ = Command::new("schtasks")
        .args(["/Create", "/TN", TASK, "/TR", &tr, "/SC", "ONLOGON", "/RU", user, "/IT", "/RL", "LIMITED", "/F"])
        .creation_flags(NO_WINDOW)
        .status();
    let _ = Command::new("schtasks").args(["/Run", "/TN", TASK]).creation_flags(NO_WINDOW).status();
}

fn worker_running() -> bool {
    Command::new("schtasks")
        .args(["/Query", "/TN", TASK, "/FO", "LIST", "/V"])
        .creation_flags(NO_WINDOW)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| {
            s.lines().any(|l| {
                let l = l.to_lowercase();
                l.trim_start().starts_with("status:") && l.contains("running")
            })
        })
        .unwrap_or(false)
}

fn delete_worker_task() {
    let _ = Command::new("schtasks").args(["/End", "/TN", TASK]).creation_flags(NO_WINDOW).status();
    let _ = Command::new("schtasks").args(["/Delete", "/TN", TASK, "/F"]).creation_flags(NO_WINDOW).status();
}

fn spawn_session0(args: &[String]) -> Option<Child> {
    let exe = std::env::current_exe().ok()?;
    Command::new(exe)
        .args(args)
        .creation_flags(NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()
}

/// Supervise loop: keep exactly one managed agent alive in the best session
/// available. Never returns.
pub fn supervise(args: Vec<String>) -> ! {
    println!("HaiveControl supervisor (session 0) — delegating capture to the active user session");
    let mut current_user: Option<String> = None;
    let mut fallback: Option<Child> = None;
    loop {
        match active_user() {
            Some(user) => {
                // A user is logged in — the managed agent must run in their session.
                if let Some(mut c) = fallback.take() {
                    let _ = c.kill();
                }
                if current_user.as_deref() != Some(user.as_str()) {
                    run_worker_for(&user, &args);
                    current_user = Some(user);
                } else if !worker_running() {
                    let _ = Command::new("schtasks").args(["/Run", "/TN", TASK]).creation_flags(NO_WINDOW).status();
                }
            }
            None => {
                // No interactive user — run a session-0 agent so the box stays
                // manageable (exec/reports/presence work; only capture won't).
                if current_user.is_some() {
                    delete_worker_task();
                    current_user = None;
                }
                let dead = fallback.as_mut().map(|c| c.try_wait().ok().flatten().is_some()).unwrap_or(true);
                if dead {
                    fallback = spawn_session0(&args);
                }
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}
