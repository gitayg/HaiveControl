// Standard, visible autostart per OS. Nothing hidden; uninstall removes it.
use std::env;
#[allow(unused_imports)]
use std::path::{Path, PathBuf};

pub fn install(args: &[String]) {
    let exe = env::current_exe().unwrap_or_default();
    #[cfg(windows)]
    win_install(&exe, args);
    #[cfg(target_os = "macos")]
    mac_install(&exe, args);
    #[cfg(all(unix, not(target_os = "macos")))]
    linux_install(&exe, args);
    let _ = (&exe, args);
}

/// Boot/logon-level autostart — a Scheduled Task (Windows), LaunchDaemon (macOS)
/// or systemd system service (Linux). More robust than `install` (per-user Run
/// key / LaunchAgent): survives reboots and restarts the agent if it dies.
/// Requires elevation to create; run the enrollment command as admin/root.
pub fn install_service(args: &[String]) {
    let exe = env::current_exe().unwrap_or_default();
    #[cfg(windows)]
    win_install_service(&exe, args);
    #[cfg(target_os = "macos")]
    mac_install_service(&exe, args);
    #[cfg(all(unix, not(target_os = "macos")))]
    linux_install_service(&exe, args);
    let _ = (&exe, args);
}

pub fn uninstall() {
    #[cfg(windows)]
    {
        win_uninstall();
        win_service_uninstall();
    }
    #[cfg(target_os = "macos")]
    {
        mac_uninstall();
        mac_service_uninstall();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux_uninstall();
        linux_service_uninstall();
    }
}

fn home() -> String {
    env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_default()
}

// ---- macOS: LaunchAgent ----
#[cfg(target_os = "macos")]
fn plist_path() -> PathBuf {
    PathBuf::from(home()).join("Library/LaunchAgents/com.haive.agent.plist")
}

#[cfg(target_os = "macos")]
fn mac_install(exe: &Path, args: &[String]) {
    let mut pa = format!("      <string>{}</string>\n", exe.display());
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.haive.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n"
    );
    let p = plist_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&p, plist);
    let _ = std::process::Command::new("launchctl")
        .args(["load", &p.to_string_lossy()])
        .status();
}

#[cfg(target_os = "macos")]
fn mac_uninstall() {
    let p = plist_path();
    let _ = std::process::Command::new("launchctl")
        .args(["unload", &p.to_string_lossy()])
        .status();
    let _ = std::fs::remove_file(&p);
}

// ---- Linux: XDG autostart ----
#[cfg(all(unix, not(target_os = "macos")))]
fn desktop_path() -> PathBuf {
    PathBuf::from(home()).join(".config/autostart/haivecontrol.desktop")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_install(exe: &Path, args: &[String]) {
    let mut ex = format!("{}", exe.display());
    for a in args {
        ex.push(' ');
        ex.push_str(a);
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=HaiveControl\nExec={ex}\nX-GNOME-Autostart-enabled=true\n"
    );
    let p = desktop_path();
    if let Some(dir) = p.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(&p, entry);
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_uninstall() {
    let _ = std::fs::remove_file(desktop_path());
}

// ---- Windows: HKCU Run ----
#[cfg(windows)]
fn win_install(exe: &Path, args: &[String]) {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    ) {
        let mut cmd = format!("\"{}\"", exe.display());
        for a in args {
            cmd.push_str(&format!(" \"{a}\""));
        }
        let _ = key.set_value("HaiveControl", &cmd);
    }
}

#[cfg(windows)]
fn win_uninstall() {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = hkcu.open_subkey_with_flags(
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        KEY_SET_VALUE,
    ) {
        let _ = key.delete_value("HaiveControl");
    }
}

// ---- Windows: Scheduled Task (starts at logon, elevated) ----
#[cfg(windows)]
fn win_install_service(exe: &Path, args: &[String]) {
    let mut tr = format!("\"{}\"", exe.display());
    for a in args {
        tr.push(' ');
        tr.push_str(a);
    }
    let _ = std::process::Command::new("schtasks")
        .args(["/Create", "/TN", "HaiveControl", "/TR", &tr, "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"])
        .status();
}

#[cfg(windows)]
fn win_service_uninstall() {
    let _ = std::process::Command::new("schtasks")
        .args(["/Delete", "/TN", "HaiveControl", "/F"])
        .status();
}

// ---- macOS: LaunchDaemon (starts at boot, root) ----
#[cfg(target_os = "macos")]
fn daemon_path() -> PathBuf {
    PathBuf::from("/Library/LaunchDaemons/com.haive.agent.plist")
}

#[cfg(target_os = "macos")]
fn mac_install_service(exe: &Path, args: &[String]) {
    let mut pa = format!("      <string>{}</string>\n", exe.display());
    for a in args {
        pa.push_str(&format!("      <string>{a}</string>\n"));
    }
    let plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>com.haive.agent</string>\n  <key>ProgramArguments</key><array>\n{pa}  </array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n</dict></plist>\n"
    );
    let p = daemon_path();
    let _ = std::fs::write(&p, plist);
    let _ = std::process::Command::new("launchctl").args(["load", &p.to_string_lossy()]).status();
}

#[cfg(target_os = "macos")]
fn mac_service_uninstall() {
    let p = daemon_path();
    let _ = std::process::Command::new("launchctl").args(["unload", &p.to_string_lossy()]).status();
    let _ = std::fs::remove_file(&p);
}

// ---- Linux: systemd system service (starts at boot, root) ----
#[cfg(all(unix, not(target_os = "macos")))]
fn unit_path() -> PathBuf {
    PathBuf::from("/etc/systemd/system/haivecontrol.service")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_install_service(exe: &Path, args: &[String]) {
    let mut ex = format!("{}", exe.display());
    for a in args {
        ex.push(' ');
        ex.push_str(a);
    }
    let unit = format!(
        "[Unit]\nDescription=HaiveControl agent\nAfter=network.target\n\n[Service]\nExecStart={ex}\nRestart=always\nRestartSec=5\n\n[Install]\nWantedBy=multi-user.target\n"
    );
    let _ = std::fs::write(unit_path(), unit);
    let _ = std::process::Command::new("systemctl").arg("daemon-reload").status();
    let _ = std::process::Command::new("systemctl").args(["enable", "--now", "haivecontrol.service"]).status();
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_service_uninstall() {
    let _ = std::process::Command::new("systemctl").args(["disable", "--now", "haivecontrol.service"]).status();
    let _ = std::fs::remove_file(unit_path());
}
