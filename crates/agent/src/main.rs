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

const VERSION: &str = "2.0.0";

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

    {
        let (mac, nm) = (mac_id.clone(), name.clone());
        std::thread::spawn(move || discovery::register_loop(mac, nm, port, scheme));
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
