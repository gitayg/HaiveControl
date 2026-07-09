# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

import os
import shlex
import subprocess
import sys

APP_NAME = "HaiveControl"
LABEL = "com.haive.agent"


def boot_command(agent_args):
    """The command that relaunches this agent at boot, as a list of strings.
    Uses the frozen exe path when built, else `python server.py`."""
    if getattr(sys, "frozen", False):
        return [sys.executable] + agent_args
    return [sys.executable, os.path.abspath(sys.argv[0])] + agent_args


def install(agent_args):
    cmd = boot_command(agent_args)
    if sys.platform.startswith("win"):
        _install_windows(cmd)
    elif sys.platform == "darwin":
        _install_macos(cmd)
    else:
        _install_linux(cmd)


def uninstall():
    try:
        if sys.platform.startswith("win"):
            _uninstall_windows()
        elif sys.platform == "darwin":
            _uninstall_macos()
        else:
            _uninstall_linux()
    except Exception:
        pass


# ---- Windows: HKCU \...\Run ----

def _win_run_key(access):
    import winreg

    return winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        0,
        access,
    )


def _install_windows(cmd):
    import winreg

    with _win_run_key(winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(
            key, APP_NAME, 0, winreg.REG_SZ, subprocess.list2cmdline(cmd)
        )


def _uninstall_windows():
    import winreg

    with _win_run_key(winreg.KEY_SET_VALUE) as key:
        winreg.DeleteValue(key, APP_NAME)


# ---- macOS: LaunchAgent ----

def _plist_path():
    return os.path.expanduser(f"~/Library/LaunchAgents/{LABEL}.plist")


def _install_macos(cmd):
    args = "".join(f"\n      <string>{c}</string>" for c in cmd)
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array>{args}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
"""
    path = _plist_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(plist)
    subprocess.run(["launchctl", "load", path], check=False)


def _uninstall_macos():
    path = _plist_path()
    subprocess.run(["launchctl", "unload", path], check=False)
    if os.path.exists(path):
        os.remove(path)


# ---- Linux: XDG autostart (.desktop) ----

def _desktop_path():
    return os.path.expanduser(f"~/.config/autostart/{APP_NAME.lower()}.desktop")


def _install_linux(cmd):
    exec_line = " ".join(shlex.quote(c) for c in cmd)
    entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        f"Exec={exec_line}\n"
        "X-GNOME-Autostart-enabled=true\n"
    )
    path = _desktop_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(entry)


def _uninstall_linux():
    path = _desktop_path()
    if os.path.exists(path):
        os.remove(path)
