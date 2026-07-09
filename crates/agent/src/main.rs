// HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
// Copyright (C) 2026 The HaiveControl Authors.
// SPDX-License-Identifier: AGPL-3.0-or-later
mod capture;
mod discovery;
mod http;
mod input;
mod persistence;
mod tls;

use std::sync::{mpsc, Arc};
use std::time::Duration;

use clap::Parser;

const VERSION: &str = "2.1.0";

#[derive(Parser)]
#[command(name = "HaiveControl", version = VERSION,
    about = "HaiveControl agent — screen + control + shell over HTTPS on the LAN")]
struct Args {
    /// the id shown by the Mac hub
    mac_id: Option<String>,
    /// optional — if set, connecting prompts for it
    password: Option<String>,
    /// friendly device name shown in the hub (default: hostname)
    #[arg(long)]
    name: Option<String>,
    /// hub Mac ID for mDNS fallback when the target is a direct IP
    #[arg(long)]
    id: Option<String>,
    /// install autostart so it survives reboot
    #[arg(long, conflicts_with = "ttl")]
    persist: bool,
    /// run for MIN minutes, then auto-exit (dissolve)
    #[arg(long, value_name = "MIN")]
    ttl: Option<f64>,
    /// remove autostart and exit
    #[arg(long)]
    uninstall: bool,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn hostname() -> String {
    if let Ok(o) = std::process::Command::new("hostname").output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "device".to_string())
}

fn collect_sysinfo() -> serde_json::Value {
    use sysinfo::System;
    let mut sys = System::new_all();
    sys.refresh_memory();
    let os = System::long_os_version().unwrap_or_else(|| std::env::consts::OS.to_string());
    let host = System::host_name().unwrap_or_default();
    let cpu = sys.cpus().first().map(|c| c.brand().trim().to_string()).unwrap_or_default();
    let cores = sys.cpus().len();
    let mem_gb = ((sys.total_memory() as f64 / 1_073_741_824.0) * 10.0).round() / 10.0;
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_default();
    let nets = sysinfo::Networks::new_with_refreshed_list();
    let mut interfaces: Vec<serde_json::Value> = Vec::new();
    for (name, data) in &nets {
        for ipn in data.ip_networks() {
            interfaces.push(serde_json::json!({"name": name, "addr": ipn.addr.to_string()}));
        }
    }
    let (cameras, microphones) = media_devices();
    serde_json::json!({
        "os": os,
        "arch": std::env::consts::ARCH,
        "platform": std::env::consts::OS,
        "hostname": host,
        "user": user,
        "cpu": cpu,
        "cores": cores,
        "mem_gb": mem_gb,
        "interfaces": interfaces,
        "cameras": cameras,
        "microphones": microphones,
    })
}

#[cfg(target_os = "macos")]
fn media_devices() -> (Vec<String>, Vec<String>) {
    (macos_cameras(), macos_mics())
}
#[cfg(target_os = "macos")]
fn sp_json(dtype: &str) -> Option<serde_json::Value> {
    let out = std::process::Command::new("system_profiler").args(["-json", dtype]).output().ok()?;
    serde_json::from_slice(&out.stdout).ok()
}
#[cfg(target_os = "macos")]
fn macos_cameras() -> Vec<String> {
    sp_json("SPCameraDataType")
        .and_then(|v| v.get("SPCameraDataType").and_then(|x| x.as_array()).cloned())
        .map(|arr| arr.iter().filter_map(|i| i.get("_name").and_then(|n| n.as_str()).map(String::from)).collect())
        .unwrap_or_default()
}
#[cfg(target_os = "macos")]
fn macos_mics() -> Vec<String> {
    let mut mics = Vec::new();
    if let Some(v) = sp_json("SPAudioDataType") {
        if let Some(arr) = v.get("SPAudioDataType").and_then(|x| x.as_array()) {
            for group in arr {
                if let Some(items) = group.get("_items").and_then(|x| x.as_array()) {
                    for d in items {
                        if d.get("coreaudio_device_input").is_some() {
                            if let Some(n) = d.get("_name").and_then(|n| n.as_str()) {
                                mics.push(n.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    mics
}

#[cfg(target_os = "windows")]
fn media_devices() -> (Vec<String>, Vec<String>) {
    (
        ps_lines("Get-PnpDevice -Class Camera -PresentOnly -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FriendlyName"),
        ps_lines("Get-PnpDevice -Class AudioEndpoint -PresentOnly -ErrorAction SilentlyContinue | Where-Object {$_.FriendlyName -match 'microphone|mic'} | Select-Object -ExpandProperty FriendlyName"),
    )
}
#[cfg(target_os = "windows")]
fn ps_lines(cmd: &str) -> Vec<String> {
    match std::process::Command::new("powershell").args(["-NoProfile", "-Command", cmd]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
        Err(_) => Vec::new(),
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn media_devices() -> (Vec<String>, Vec<String>) {
    let mut cams: Vec<String> = Vec::new();
    if let Ok(rd) = std::fs::read_dir("/sys/class/video4linux") {
        for e in rd.flatten() {
            if let Ok(name) = std::fs::read_to_string(e.path().join("name")) {
                let n = name.trim().to_string();
                if !n.is_empty() && !cams.contains(&n) {
                    cams.push(n);
                }
            }
        }
    }
    let mut mics: Vec<String> = Vec::new();
    if let Ok(o) = std::process::Command::new("arecord").arg("-l").output() {
        for line in String::from_utf8_lossy(&o.stdout).lines() {
            if line.starts_with("card ") {
                if let Some(pos) = line.find(": ") {
                    let name = line[pos + 2..].split('[').next().unwrap_or("").trim().to_string();
                    if !name.is_empty() && !mics.contains(&name) {
                        mics.push(name);
                    }
                }
            }
        }
    }
    (cams, mics)
}

fn main() {
    let args = Args::parse();

    if args.uninstall {
        persistence::uninstall();
        println!("HaiveControl autostart removed.");
        return;
    }

    let mac_id = match args.mac_id.clone().or_else(|| std::env::var("SCREEN_HUB").ok()) {
        Some(m) => m,
        None => {
            eprintln!("usage: HaiveControl <mac-id> [password] [--name N] [--persist | --ttl MIN]");
            std::process::exit(2);
        }
    };

    let password = args.password.clone().unwrap_or_else(|| env_or("SCREEN_PW", ""));
    let port: u16 = env_or("SCREEN_PORT", "8765").parse().unwrap_or(8765);
    let quality: u8 = env_or("SCREEN_QUALITY", "60").parse().unwrap_or(60);
    let max_width: u32 = env_or("SCREEN_MAXW", "1600").parse().unwrap_or(1600);
    let monitor: usize = env_or("SCREEN_MONITOR", "0").parse().unwrap_or(0);
    let exec_enabled = env_or("SCREEN_EXEC", "1") != "0";
    let mut tls = env_or("SCREEN_TLS", "1") != "0";
    let share = env_or("SCREEN_SHARE", "");
    let name = args
        .name
        .clone()
        .or_else(|| std::env::var("SCREEN_NAME").ok())
        .unwrap_or_else(hostname);

    let grabber = capture::Grabber { index: monitor };
    let geo = grabber.geometry();

    let lifetime = if args.persist {
        persistence::install(&persistence::boot_args(&mac_id, &args.password, &args.name));
        "persistent (starts on boot)".to_string()
    } else if let Some(mins) = args.ttl {
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs_f64(mins * 60.0));
            persistence::uninstall();
            std::process::exit(0);
        });
        format!("{mins} min then auto-exit")
    } else {
        "one-time (until closed)".to_string()
    };

    let cert = if tls {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .unwrap_or_default();
        let dir = format!("{home}/.haive");
        let c = tls::ensure_cert(&dir, &discovery::local_ip(), &[hostname(), "haive.local".to_string()]);
        if c.is_none() {
            eprintln!("cert generation failed; falling back to plain HTTP");
            tls = false;
        }
        c
    } else {
        None
    };
    let scheme: &'static str = if tls { "https" } else { "http" };

    let (tx, rx) = mpsc::channel::<input::Ev>();
    std::thread::spawn(move || input::run(rx, geo));

    let sysinfo = collect_sysinfo();
    {
        let (primary, fid, nm) = (mac_id.clone(), args.id.clone(), name.clone());
        std::thread::spawn(move || discovery::register_loop(primary, fid, nm, port, scheme, sysinfo));
    }
    {
        let asset = match std::env::consts::OS {
            "windows" => "HaiveControl-windows.exe",
            "macos" => "HaiveControl-macos",
            _ => "HaiveControl-linux",
        }
        .to_string();
        let (primary, fid) = (mac_id.clone(), args.id.clone());
        std::thread::spawn(move || discovery::auto_update_loop(primary, fid, asset));
    }

    println!("HaiveControl {VERSION} — serving '{name}' on {scheme}://…:{port}, registering to '{mac_id}'");
    println!("   lifetime: {lifetime}");
    println!(
        "   tls: {} | password: {} | exec: {}",
        if tls { "on" } else { "off" },
        if password.is_empty() { "none" } else { "required" },
        if exec_enabled { "enabled" } else { "disabled" }
    );

    let cfg = Arc::new(http::Config {
        password,
        port,
        quality,
        max_width,
        exec_enabled,
        tls,
        share,
        grabber,
        cert,
    });
    http::serve(cfg, tx);
}
