#!/usr/bin/env python3
# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later
"""HaiveControl CLI — run commands (and transfer files) against a registered
device from the Mac, by its hub name. Stdlib only.

  haivectl.py list
  haivectl.py exec <device> <command...>
  haivectl.py get  <device> <remote-path> [local-path]
  haivectl.py put  <device> <local-path> [remote-dir]

The device is resolved through the hub (default http://localhost:8770), so you
never type its IP. Use --password if the agent was started with one.

TLS: the agent uses a self-signed cert. Pass --cafile ~/.haive/cert.pem
(copied from the device) to verify it. Without it, the connection is encrypted
but unauthenticated (vulnerable to a LAN MITM) and a warning is printed.
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.0.0"
CTX = None  # ssl context, set from args in main()
VERIFIED = False
_warned = False


def build_context(cafile):
    global VERIFIED
    if cafile:
        VERIFIED = True
        return ssl.create_default_context(cafile=cafile)
    return ssl._create_unverified_context()


def _auth_header(password):
    if not password:
        return {}
    token = base64.b64encode(f"admin:{password}".encode()).decode()
    return {"Authorization": "Basic " + token}


def _request(url, data=None, headers=None, timeout=65):
    global _warned
    if url.startswith("https") and not VERIFIED and not _warned:
        sys.stderr.write("warning: TLS not verified (no --cafile) — LAN use only\n")
        _warned = True
    req = urllib.request.Request(url, data=data, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout, context=CTX)


def list_agents(hub):
    with _request(hub.rstrip("/") + "/agents", timeout=5) as r:
        return json.load(r).get("agents", [])


def resolve(hub, name):
    agents = list_agents(hub)
    exact = [a for a in agents if a["name"].lower() == name.lower() or a["ip"] == name]
    matches = exact or [a for a in agents if name.lower() in a["name"].lower()]
    if not matches:
        sys.exit(f"no device matching '{name}' (try: haivectl.py list)")
    if len(matches) > 1:
        sys.exit(f"'{name}' is ambiguous: " + ", ".join(a["name"] for a in matches))
    a = matches[0]
    return f"{a['scheme']}://{a['ip']}:{a['port']}"


def cmd_list(args):
    for a in list_agents(args.hub):
        print(f"{a['name']:24} {a['scheme']}://{a['ip']}:{a['port']}")


def cmd_exec(args):
    base = resolve(args.hub, args.device)
    body = json.dumps({"cmd": " ".join(args.command)}).encode()
    headers = {"Content-Type": "application/json", **_auth_header(args.password)}
    with _request(base + "/exec", data=body, headers=headers) as r:
        out = json.load(r)
    if not out.get("ok"):
        sys.exit("[error] " + out.get("error", "failed"))
    sys.stdout.write(out.get("stdout", ""))
    sys.stderr.write(out.get("stderr", ""))
    sys.exit(out.get("code", 0))


def cmd_get(args):
    base = resolve(args.hub, args.device)
    url = base + "/download?path=" + urllib.parse.quote(args.remote)
    local = args.local or os.path.basename(args.remote)
    with _request(url, headers=_auth_header(args.password)) as r:
        with open(local, "wb") as f:
            f.write(r.read())
    print(f"saved → {local}")


def cmd_put(args):
    base = resolve(args.hub, args.device)
    name = os.path.basename(args.local)
    with open(args.local, "rb") as f:
        payload = f.read()
    boundary = "----haivectl"
    parts = [
        f"--{boundary}".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{name}"'.encode(),
        b"Content-Type: application/octet-stream", b"", payload,
    ]
    if args.remote_dir:
        parts += [
            f"--{boundary}".encode(),
            b'Content-Disposition: form-data; name="dir"', b"", args.remote_dir.encode(),
        ]
    parts += [f"--{boundary}--".encode(), b""]
    data = b"\r\n".join(parts)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        **_auth_header(args.password),
    }
    with _request(base + "/upload", data=data, headers=headers) as r:
        out = json.load(r)
    print(out.get("saved") if out.get("ok") else "[error] " + out.get("error", "failed"))


def main():
    global CTX
    p = argparse.ArgumentParser(
        prog="haivectl.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--hub", default=os.environ.get("HAIVE_HUB", "http://localhost:8770"),
                   help="hub URL (default http://localhost:8770)")
    p.add_argument("--password", default=os.environ.get("SCREEN_PW"),
                   help="agent password, if one was set")
    p.add_argument("--cafile", default=os.environ.get("HAIVE_CAFILE"),
                   help="agent cert.pem to verify TLS against")
    p.add_argument("--version", action="version", version=f"haivectl {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list registered devices").set_defaults(func=cmd_list)

    e = sub.add_parser("exec", help="run a command on a device")
    e.add_argument("device")
    e.add_argument("command", nargs=argparse.REMAINDER)
    e.set_defaults(func=cmd_exec)

    g = sub.add_parser("get", help="download a file from a device")
    g.add_argument("device")
    g.add_argument("remote")
    g.add_argument("local", nargs="?")
    g.set_defaults(func=cmd_get)

    u = sub.add_parser("put", help="upload a file to a device")
    u.add_argument("device")
    u.add_argument("local")
    u.add_argument("remote_dir", nargs="?")
    u.set_defaults(func=cmd_put)

    args = p.parse_args()
    CTX = build_context(args.cafile)
    try:
        args.func(args)
    except urllib.error.HTTPError as e:
        sys.exit(f"error: {e.code} {e.reason}")
    except (urllib.error.URLError, OSError) as e:
        sys.exit(f"error: cannot reach {args.hub} ({getattr(e, 'reason', e)})")


if __name__ == "__main__":
    main()
