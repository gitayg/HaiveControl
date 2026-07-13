// Windows Session 0 isolation: a service runs as SYSTEM in session 0, walled off
// from the interactive desktop — so it can't screen-capture. Rather than move the
// whole agent out of session 0 (which risks leaving the device unmanaged), we keep
// the service running normally — always connected, self-updating, exec/reports/
// presence all work — and delegate ONLY screen capture to the active user's
// session, on demand: a one-shot `--capture-once` run via a scheduled task with an
// interactive token. If that fails (no user logged in, etc.) only the screenshot
// fails; the device stays online.
#![cfg(windows)]

use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const NO_WINDOW: u32 = 0x0800_0000; // CREATE_NO_WINDOW — no console flash
const CAP_TASK: &str = "HaiveCaptureOnce";

/// True when we're running as SYSTEM — i.e. a service in session 0, which can't
/// reach the interactive desktop. Cached (it doesn't change over a run).
pub fn is_session0() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        Command::new("whoami")
            .creation_flags(NO_WINDOW)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().eq_ignore_ascii_case("nt authority\\system"))
            .unwrap_or(false)
    })
}

/// Username of the active interactive session (prefer the physical console; else
/// any active session with a user). None = nobody logged on.
fn active_user() -> Option<String> {
    let out = Command::new("query").args(["user"]).creation_flags(NO_WINDOW).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut any: Option<String> = None;
    for line in text.lines().skip(1) {
        let c = line.trim_start().trim_start_matches('>').trim_start();
        let low = c.to_lowercase();
        if !low.contains("active") {
            continue;
        }
        let user = match c.split_whitespace().next() {
            Some(u) if !u.is_empty() => u.to_string(),
            _ => continue,
        };
        if low.contains("console") {
            return Some(user);
        }
        if any.is_none() {
            any = Some(user);
        }
    }
    any
}

fn task_running() -> bool {
    Command::new("schtasks")
        .args(["/Query", "/TN", CAP_TASK, "/FO", "LIST", "/V"])
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

/// Grab one screen frame from the active user's session and return the JPEG.
/// None if nobody's logged in or the capture produced nothing — the caller stays
/// online regardless (only this screenshot fails).
pub fn capture_once() -> Option<Vec<u8>> {
    let user = active_user()?;
    let exe = std::env::current_exe().ok()?;
    let tmp = std::env::temp_dir().join("haive_shot.jpg");
    let _ = std::fs::remove_file(&tmp);

    let tr = format!("\"{}\" --capture-once \"{}\"", exe.display(), tmp.display());
    // Interactive-token task (runs in the user's session, desktop-accessible); no
    // password needed — SYSTEM has the privilege. /F overwrites any prior one.
    let created = Command::new("schtasks")
        .args(["/Create", "/TN", CAP_TASK, "/TR", &tr, "/SC", "ONLOGON", "/RU", &user, "/IT", "/RL", "LIMITED", "/F"])
        .creation_flags(NO_WINDOW)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !created {
        return None;
    }
    let _ = Command::new("schtasks").args(["/Run", "/TN", CAP_TASK]).creation_flags(NO_WINDOW).status();

    // Wait (bounded) for the one-shot to finish and drop the file.
    std::thread::sleep(Duration::from_millis(400));
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        let running = task_running();
        if !running {
            // give the file write a beat to land after the process exits
            std::thread::sleep(Duration::from_millis(300));
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    let bytes = std::fs::read(&tmp).ok().filter(|b| !b.is_empty());
    let _ = std::fs::remove_file(&tmp);
    let _ = Command::new("schtasks").args(["/Delete", "/TN", CAP_TASK, "/F"]).creation_flags(NO_WINDOW).status();
    bytes
}
