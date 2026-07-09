# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import os
import re
import socket
import subprocess
import time

from flask import Flask, request

from discovery import advertise_hub

VERSION = "1.0.0"

HUB_PORT = int(os.environ.get("HUB_PORT", "8770"))
STALE_AFTER = 40  # seconds without a heartbeat → drop from the list

app = Flask(__name__)
agents = {}  # ip -> {name, ip, port, last}


def mac_id():
    """The Mac's id an agent connects with. Defaults to the Bonjour LocalHostName."""
    override = os.environ.get("MAC_ID")
    if override:
        return re.sub(r"[^A-Za-z0-9-]", "-", override)
    try:
        name = subprocess.check_output(
            ["scutil", "--get", "LocalHostName"], text=True
        ).strip()
    except Exception:
        name = socket.gethostname().split(".")[0]
    return re.sub(r"[^A-Za-z0-9-]", "-", name) or "mac"


def live_agents():
    now = time.time()
    return [a for a in agents.values() if now - a["last"] < STALE_AFTER]


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True, silent=True) or {}
    ip = data.get("ip") or request.remote_addr
    agents[ip] = {
        "name": data.get("name", "?"),
        "ip": ip,
        "port": int(data.get("port", 8765)),
        "scheme": data.get("scheme", "http"),
        "last": time.time(),
    }
    return ("", 204)


@app.route("/agents")
def agents_json():
    return {"agents": live_agents()}


@app.route("/")
def dashboard():
    rows = "".join(
        f'<li><a href="{a["scheme"]}://{a["ip"]}:{a["port"]}/" target="_blank">'
        f'{a["name"]}</a> <span>{a["ip"]}:{a["port"]}</span></li>'
        for a in live_agents()
    )
    empty = "" if rows else "<p>No devices registered yet.</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5"><title>HaiveControl hub</title>
<style>body{{font-family:system-ui;background:#111;color:#ddd;max-width:640px;
margin:40px auto;padding:0 16px}}h1{{font-size:18px}}li{{margin:8px 0}}
a{{color:#4ea1ff;font-size:16px}}span{{color:#888;font-size:13px;margin-left:8px}}
code{{background:#222;padding:2px 6px;border-radius:4px}}</style></head>
<body><h1>HaiveControl hub — <code>{mac_id()}</code></h1>
<ul>{rows}</ul>{empty}
<p style="color:#777;font-size:13px">On Windows run: <code>HaiveControl.exe {mac_id()}</code></p>
</body></html>"""


if __name__ == "__main__":
    argparse.ArgumentParser(
        prog="HaiveHub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"HaiveControl hub {VERSION} — run this on the Mac. It advertises a\n"
            "Mac ID over Bonjour, collects agent registrations, and serves a\n"
            "dashboard listing every device that registered."
        ),
        epilog=(
            "env vars:\n"
            "  HUB_PORT   dashboard/registration port (default 8770)\n"
            "  MAC_ID     override the advertised id (default: Bonjour LocalHostName)"
        ),
    ).parse_args()

    mid = mac_id()
    zc, ip = advertise_hub(mid, HUB_PORT)
    print(f"HaiveControl hub {VERSION}")
    print(f"   Mac ID:  {mid}")
    print(f"   Dashboard: http://localhost:{HUB_PORT}/  (or http://{ip}:{HUB_PORT}/)")
    print(f"   On Windows run:  HaiveControl.exe {mid}")
    try:
        app.run(host="0.0.0.0", port=HUB_PORT, threaded=True)
    finally:
        zc.close()
