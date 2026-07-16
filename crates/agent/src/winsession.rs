// Windows Session 0 isolation: a service runs as SYSTEM in session 0, walled off
// from the interactive desktop — so it can't screen-capture. We keep the service
// running normally (always connected, self-updating, exec/reports/presence all
// work) and delegate ONLY screen capture to the active user's session, on demand.
//
// The delegation addresses the session by ID via the WTS/token APIs and never
// needs a username. That matters: an earlier attempt shelled out to
// `schtasks /RU <user>`, which fails with "No mapping between account names and
// security IDs" on Azure AD / Microsoft-account machines (there's no local
// account to resolve) — i.e. most corporate fleets. WTSQueryUserToken has no such
// problem, and it also sidesteps schtasks' /TR quoting and the fact that a
// SYSTEM service's %TEMP% (C:\Windows\TEMP) isn't writable by the user.
#![cfg(windows)]

use std::os::windows::ffi::OsStrExt;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, TokenPrimary, TOKEN_ALL_ACCESS,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
};

/// True when we're running as SYSTEM in session 0 — i.e. a service with no access
/// to the interactive desktop. Cached (it can't change over a run).
pub fn is_session0() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("whoami")
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().eq_ignore_ascii_case("nt authority\\system"))
            .unwrap_or(false)
    })
}

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Grab one screen frame from the active user's session and return the JPEG.
/// None if nobody's logged on or the capture produced nothing — the caller stays
/// online regardless (only this screenshot fails).
pub fn capture_once() -> Option<Vec<u8>> {
    let exe = std::env::current_exe().ok()?;
    // Both accounts must reach this file: the helper (the logged-in user) writes
    // it, we (SYSTEM) read it. A service's %TEMP% is C:\Windows\TEMP, which the
    // user can't write — so use the world-writable Public dir.
    let dir = std::env::var("PUBLIC").unwrap_or_else(|_| "C:\\Users\\Public".into());
    let shot = format!("{dir}\\haive_shot.jpg");
    let _ = std::fs::remove_file(&shot);

    let cmdline = format!("\"{}\" --capture-once \"{}\"", exe.display(), shot);
    let ok = unsafe { run_in_active_session(&cmdline) };
    if !ok {
        return None;
    }
    let bytes = std::fs::read(&shot).ok().filter(|b| !b.is_empty());
    let _ = std::fs::remove_file(&shot);
    bytes
}

/// Run `cmdline` inside the active console session and wait (bounded) for it to
/// exit. Returns whether it ran to completion.
unsafe fn run_in_active_session(cmdline: &str) -> bool {
    let session = WTSGetActiveConsoleSessionId();
    // 0xFFFFFFFF = no session attached to the console (nobody logged on).
    if session == u32::MAX {
        return false;
    }
    let mut token: HANDLE = std::ptr::null_mut();
    if WTSQueryUserToken(session, &mut token) == 0 || token.is_null() || token == INVALID_HANDLE_VALUE {
        return false; // no interactive user in that session
    }

    let mut primary: HANDLE = std::ptr::null_mut();
    let dup = DuplicateTokenEx(
        token,
        TOKEN_ALL_ACCESS,
        std::ptr::null(),
        SecurityImpersonation,
        TokenPrimary,
        &mut primary,
    );
    CloseHandle(token);
    if dup == 0 || primary.is_null() {
        return false;
    }

    // The user's environment, so the helper resolves their paths/profile.
    let mut env: *mut std::ffi::c_void = std::ptr::null_mut();
    let have_env = CreateEnvironmentBlock(&mut env, primary, 0) != 0;

    let mut si: STARTUPINFOW = std::mem::zeroed();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // Target the interactive desktop of that session.
    let mut desktop = wide("winsta0\\default");
    si.lpDesktop = desktop.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
    let mut cl = wide(cmdline);

    let started = CreateProcessAsUserW(
        primary,
        std::ptr::null(),
        cl.as_mut_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        0,
        CREATE_NO_WINDOW | if have_env { CREATE_UNICODE_ENVIRONMENT } else { 0 },
        if have_env { env } else { std::ptr::null_mut() },
        std::ptr::null(),
        &si,
        &mut pi,
    );

    let mut ok = false;
    if started != 0 {
        // Bounded wait so a wedged helper can't hang the request.
        WaitForSingleObject(pi.hProcess, 15_000);
        let mut code: u32 = 1;
        GetExitCodeProcess(pi.hProcess, &mut code);
        ok = code == 0;
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    if have_env {
        DestroyEnvironmentBlock(env);
    }
    CloseHandle(primary);
    ok
}
