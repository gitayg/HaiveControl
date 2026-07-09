#!/usr/bin/env python3
# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later
"""HaiveControl MCP server — exposes registered devices as MCP tools:
list_devices, screenshot, run_command, download_file, upload_file.

Runs on the Mac next to the hub. Devices are resolved by their hub name, so an
AI client never needs an IP. Configure via env:
  HAIVE_HUB      hub URL (default http://localhost:8770)
  SCREEN_PW   agent password, if one was set
  HAIVE_CAFILE   agent cert.pem to verify TLS (else unverified — LAN only)

Register it with, e.g.:
  claude mcp add haive -- python3 /path/to/mcp_server.py
"""
import base64
import json
import os
import ssl
import urllib.parse
import urllib.request

from mcp.server.fastmcp import FastMCP, Image

HUB = os.environ.get("HAIVE_HUB", "http://localhost:8770")
PASSWORD = os.environ.get("SCREEN_PW")
CAFILE = os.environ.get("HAIVE_CAFILE")
CTX = ssl.create_default_context(cafile=CAFILE) if CAFILE else ssl._create_unverified_context()

mcp = FastMCP("haive")


def _auth():
    if not PASSWORD:
        return {}
    token = base64.b64encode(f"admin:{PASSWORD}".encode()).decode()
    return {"Authorization": "Basic " + token}


def _req(url, data=None, headers=None, timeout=65):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout, context=CTX)


def _agents():
    with _req(HUB.rstrip("/") + "/agents", timeout=5) as r:
        return json.load(r).get("agents", [])


def _resolve(name):
    agents = _agents()
    matches = [a for a in agents if a["name"].lower() == name.lower() or a["ip"] == name]
    matches = matches or [a for a in agents if name.lower() in a["name"].lower()]
    if not matches:
        raise ValueError(f"no device matching '{name}' — call list_devices first")
    if len(matches) > 1:
        raise ValueError("ambiguous device: " + ", ".join(a["name"] for a in matches))
    a = matches[0]
    return f"{a['scheme']}://{a['ip']}:{a['port']}"


@mcp.tool()
def list_devices() -> str:
    """List devices currently registered with the hub (i.e. ready to connect)."""
    agents = _agents()
    if not agents:
        return "no devices registered"
    return "\n".join(f"{a['name']} — {a['scheme']}://{a['ip']}:{a['port']}" for a in agents)


@mcp.tool()
def run_command(device: str, command: str) -> str:
    """Run a shell command on the named device and return its combined output."""
    base = _resolve(device)
    body = json.dumps({"cmd": command}).encode()
    headers = {"Content-Type": "application/json", **_auth()}
    with _req(base + "/exec", data=body, headers=headers) as r:
        out = json.load(r)
    if not out.get("ok"):
        return "[error] " + out.get("error", "failed")
    return (out.get("stdout", "") + out.get("stderr", "")) or f"(exit {out.get('code')})"


@mcp.tool()
def screenshot(device: str) -> Image:
    """Capture the current screen of the named device as an image."""
    base = _resolve(device)
    with _req(base + "/frame", headers=_auth(), timeout=15) as r:
        data = r.read()
    return Image(data=data, format="jpeg")


@mcp.tool()
def download_file(device: str, remote_path: str, save_as: str = "") -> str:
    """Download a file from the device to the Mac. Returns the local path."""
    base = _resolve(device)
    url = base + "/download?path=" + urllib.parse.quote(remote_path)
    local = save_as or os.path.join(
        os.path.expanduser("~/Downloads"), os.path.basename(remote_path)
    )
    with _req(url, headers=_auth()) as r:
        with open(local, "wb") as f:
            f.write(r.read())
    return f"saved to {local}"


@mcp.tool()
def upload_file(device: str, local_path: str, remote_dir: str = "") -> str:
    """Upload a local file to the device. Returns the saved remote path."""
    base = _resolve(device)
    name = os.path.basename(local_path)
    with open(local_path, "rb") as f:
        payload = f.read()
    boundary = "----rsmcp"
    parts = [
        f"--{boundary}".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{name}"'.encode(),
        b"Content-Type: application/octet-stream", b"", payload,
    ]
    if remote_dir:
        parts += [
            f"--{boundary}".encode(),
            b'Content-Disposition: form-data; name="dir"', b"", remote_dir.encode(),
        ]
    parts += [f"--{boundary}--".encode(), b""]
    body = b"\r\n".join(parts)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        **_auth(),
    }
    with _req(base + "/upload", data=body, headers=headers) as r:
        out = json.load(r)
    return out.get("saved") if out.get("ok") else "[error] " + out.get("error", "failed")


if __name__ == "__main__":
    mcp.run()
