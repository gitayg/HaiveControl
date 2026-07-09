# HaiveControl — LAN remote control & screen sharing with an AI/MCP interface.
# Copyright (C) 2026 The HaiveControl Authors.
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request
from functools import wraps

import mss
from flask import Flask, Response, request, send_file

import persistence
from capture import ScreenGrabber
from discovery import local_ip, resolve_hub
from input_control import InputController
from tls import ensure_cert

VERSION = "1.0.0"

app = Flask(__name__)

PASSWORD = os.environ.get("SCREEN_PW", "")  # empty = open (LAN-only mode)
PORT = int(os.environ.get("SCREEN_PORT", "8765"))
FPS = float(os.environ.get("SCREEN_FPS", "10"))
QUALITY = int(os.environ.get("SCREEN_QUALITY", "60"))
MAX_WIDTH = int(os.environ.get("SCREEN_MAXW", "1600"))
MONITOR = int(os.environ.get("SCREEN_MONITOR", "0"))
EXEC_ENABLED = os.environ.get("SCREEN_EXEC", "1") != "0"
TLS_ENABLED = os.environ.get("SCREEN_TLS", "1") != "0"
SCHEME = "https" if TLS_ENABLED else "http"
SHARE = os.environ.get("SCREEN_SHARE", "")  # empty = whole filesystem; else confine here

grabber = ScreenGrabber(monitor=MONITOR)

with mss.mss() as _sct:
    _geometry = dict(_sct.monitors[MONITOR])
controller = InputController(_geometry)


def require_auth(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not PASSWORD:
            return view(*args, **kwargs)
        auth = request.authorization
        if not auth or auth.password != PASSWORD:
            return Response(
                "Authentication required",
                401,
                {"WWW-Authenticate": 'Basic realm="HaiveControl"'},
            )
        return view(*args, **kwargs)

    return wrapper


def mjpeg_stream():
    interval = 1.0 / FPS
    with mss.mss() as sct:
        while True:
            started = time.time()
            frame = grabber.grab_jpeg(sct, quality=QUALITY, max_width=MAX_WIDTH)
            yield b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" + frame + b"\r\n"
            elapsed = time.time() - started
            if elapsed < interval:
                time.sleep(interval - elapsed)


@app.route("/")
@require_auth
def index():
    return PAGE


@app.route("/stream")
@require_auth
def stream():
    return Response(
        mjpeg_stream(),
        mimetype="multipart/x-mixed-replace; boundary=frame",
    )


@app.route("/frame")
@require_auth
def frame():
    with mss.mss() as sct:
        jpg = grabber.grab_jpeg(sct, quality=QUALITY, max_width=MAX_WIDTH)
    return Response(jpg, mimetype="image/jpeg")


@app.route("/input", methods=["POST"])
@require_auth
def send_input():
    controller.handle(request.get_json(force=True, silent=True) or {})
    return ("", 204)


@app.route("/exec", methods=["POST"])
@require_auth
def run_command():
    if not EXEC_ENABLED:
        return {"ok": False, "error": "remote exec disabled"}, 403
    cmd = (request.get_json(force=True, silent=True) or {}).get("cmd", "").strip()
    if not cmd:
        return {"ok": False, "error": "empty command"}, 400
    try:
        proc = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=60
        )
        return {
            "ok": True,
            "code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timed out after 60s"}, 504


def resolve_path(path):
    """Map a requested path to an absolute path. If SCREEN_SHARE is set, confine
    everything under it (blocking `..` escapes); otherwise allow any path the
    running user can reach. Returns None if the path escapes the share."""
    if SHARE:
        base = os.path.abspath(os.path.expanduser(SHARE))
        full = os.path.abspath(os.path.join(base, path))
        if full != base and not full.startswith(base + os.sep):
            return None
        return full
    return os.path.abspath(os.path.expanduser(path))


@app.route("/download")
@require_auth
def download():
    full = resolve_path(request.args.get("path", ""))
    if not full or not os.path.isfile(full):
        return {"ok": False, "error": "not a file"}, 404
    return send_file(full, as_attachment=True)


@app.route("/upload", methods=["POST"])
@require_auth
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        return {"ok": False, "error": "no file"}, 400
    target = request.form.get("dir") or SHARE or os.path.expanduser("~")
    dest_dir = resolve_path(target)
    if not dest_dir or not os.path.isdir(dest_dir):
        return {"ok": False, "error": "target dir not found"}, 400
    dest = os.path.join(dest_dir, os.path.basename(f.filename))
    f.save(dest)
    return {"ok": True, "saved": dest}


PAGE = """<!doctype html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HaiveControl</title>
<style>
 html,body{margin:0;background:#111;color:#ddd;font-family:system-ui,sans-serif}
 #screen{display:block;max-width:100%;height:auto;cursor:crosshair;margin:0 auto}
 #bar{position:fixed;left:0;right:0;bottom:0;display:flex;gap:8px;align-items:center;
      padding:6px;background:#000c;backdrop-filter:blur(4px)}
 #cmd{flex:1;background:#1c1c1c;color:#eee;border:1px solid #444;padding:7px;
      font-family:ui-monospace,monospace;border-radius:4px}
 #out{position:fixed;right:8px;bottom:50px;max-width:46%;max-height:42%;overflow:auto;
      background:#000d;color:#4ade80;font-family:ui-monospace,monospace;font-size:12px;
      padding:10px;white-space:pre-wrap;border-radius:6px;display:none}
 button,label{background:#2a2a2a;color:#eee;border:1px solid #555;padding:7px 11px;
      border-radius:4px;cursor:pointer;font-size:13px}
</style></head><body>
<img id="screen" src="/stream">
<pre id="out"></pre>
<div id="bar">
  <label><input type="checkbox" id="ctrl" checked> control</label>
  <input id="cmd" placeholder="remote command (Enter to run)…" autocomplete="off">
  <input type="file" id="file" style="max-width:150px">
  <button id="upbtn">upload</button>
  <input id="dlpath" placeholder="download path…" autocomplete="off" style="max-width:150px">
  <button id="dlbtn">get</button>
  <button id="outbtn">output</button>
</div>
<script>
const img=document.getElementById('screen'),cmd=document.getElementById('cmd'),
      out=document.getElementById('out'),ctrl=document.getElementById('ctrl');
const on=()=>ctrl.checked;
function norm(e){const r=img.getBoundingClientRect();
  return {x:Math.min(1,Math.max(0,(e.clientX-r.left)/r.width)),
          y:Math.min(1,Math.max(0,(e.clientY-r.top)/r.height))};}
function send(ev){fetch('/input',{method:'POST',
  headers:{'Content-Type':'application/json'},body:JSON.stringify(ev)});}
let last=0;
img.addEventListener('mousemove',e=>{if(!on())return;const t=Date.now();
  if(t-last<45)return;last=t;const p=norm(e);send({type:'move',x:p.x,y:p.y});});
img.addEventListener('mousedown',e=>{if(!on())return;e.preventDefault();const p=norm(e);
  send({type:'down',button:e.button,x:p.x,y:p.y});});
img.addEventListener('mouseup',e=>{if(!on())return;e.preventDefault();const p=norm(e);
  send({type:'up',button:e.button,x:p.x,y:p.y});});
img.addEventListener('contextmenu',e=>e.preventDefault());
img.addEventListener('wheel',e=>{if(!on())return;e.preventDefault();
  send({type:'scroll',dy:-Math.sign(e.deltaY)*3});},{passive:false});
document.addEventListener('keydown',e=>{if(!on()||document.activeElement===cmd)return;
  e.preventDefault();send({type:'key',action:'down',key:e.key});});
document.addEventListener('keyup',e=>{if(!on()||document.activeElement===cmd)return;
  e.preventDefault();send({type:'key',action:'up',key:e.key});});
cmd.addEventListener('keydown',e=>{if(e.key==='Enter'){const c=cmd.value;cmd.value='';run(c);}});
document.getElementById('outbtn').onclick=()=>{
  out.style.display=out.style.display==='none'?'block':'none';};
document.getElementById('upbtn').onclick=async()=>{
  const f=document.getElementById('file').files[0];if(!f)return;
  out.style.display='block';out.textContent='uploading '+f.name+'…';
  const fd=new FormData();fd.append('file',f);
  try{const r=await fetch('/upload',{method:'POST',body:fd});const j=await r.json();
    out.textContent=j.ok?('uploaded → '+j.saved):('[error] '+(j.error||'failed'));}
  catch(err){out.textContent='[error] '+err;}};
document.getElementById('dlbtn').onclick=()=>{
  const p=document.getElementById('dlpath').value.trim();if(!p)return;
  window.open('/download?path='+encodeURIComponent(p),'_blank');};
async function run(c){if(!c)return;out.style.display='block';out.textContent='$ '+c+'\\n…';
  try{const r=await fetch('/exec',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({cmd:c})});
  const j=await r.json();
  out.textContent='$ '+c+'\\n'+(j.ok?((j.stdout||'')+(j.stderr||'')||'(exit '+j.code+')')
    :('[error] '+(j.error||'failed')));}
  catch(err){out.textContent='$ '+c+'\\n[error] '+err;}}
</script></body></html>"""


def register_loop(mac_id, name):
    """Find the Mac hub by its id and (re)register this agent every 15s."""
    while True:
        hub = resolve_hub(mac_id)
        if hub:
            hub_ip, hub_port = hub
            payload = json.dumps(
                {"name": name, "ip": local_ip(), "port": PORT, "scheme": SCHEME}
            ).encode()
            req = urllib.request.Request(
                f"http://{hub_ip}:{hub_port}/register",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            try:
                urllib.request.urlopen(req, timeout=5).read()
            except OSError:
                pass
        time.sleep(15)


def main():
    global PASSWORD
    parser = argparse.ArgumentParser(
        prog="HaiveControl",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"HaiveControl {VERSION} — stream this machine's screen (with mouse,\n"
            "keyboard and shell) to the Mac hub over HTTPS, on the LAN."
        ),
        epilog=(
            "examples:\n"
            "  HaiveControl mymac                 open, one-time run\n"
            "  HaiveControl mymac secret          require password 'secret'\n"
            "  HaiveControl mymac secret --persist   survive reboot\n"
            "  HaiveControl mymac secret --ttl 30    self-exit after 30 min\n"
            "  HaiveControl --uninstall           remove autostart and quit\n"
            "\n"
            "env vars: SCREEN_PORT SCREEN_FPS SCREEN_QUALITY SCREEN_MAXW\n"
            "          SCREEN_MONITOR SCREEN_EXEC SCREEN_TLS SCREEN_PW\n"
            "          SCREEN_SHARE (confine file transfer) SCREEN_NAME (device label)"
        ),
    )
    parser.add_argument("mac_id", nargs="?", default=os.environ.get("SCREEN_HUB"),
                        help="the id shown by the Mac hub")
    parser.add_argument("password", nargs="?", default=None,
                        help="optional — if set, connecting prompts for it")
    parser.add_argument("--name", default=os.environ.get("SCREEN_NAME"),
                        help="friendly device name shown in the hub (default: hostname)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--persist", action="store_true",
                      help="install autostart so it survives reboot")
    mode.add_argument("--ttl", type=float, metavar="MIN",
                      help="run for MIN minutes, then auto-exit (dissolve)")
    parser.add_argument("--uninstall", action="store_true",
                        help="remove autostart and exit")
    parser.add_argument("--version", action="version", version=f"HaiveControl {VERSION}")
    args = parser.parse_args()

    if args.uninstall:
        persistence.uninstall()
        print("HaiveControl autostart removed.")
        return
    if not args.mac_id:
        parser.error("mac-id is required (the id shown by the Mac hub)")
    if args.password:
        PASSWORD = args.password

    if args.persist:
        boot_args = [args.mac_id] + ([args.password] if args.password else [])
        persistence.install(boot_args)
        lifetime = "persistent (starts on boot)"
    elif args.ttl:
        def dissolve():
            persistence.uninstall()
            os._exit(0)

        threading.Timer(args.ttl * 60, dissolve).start()
        lifetime = f"{args.ttl:g} min then auto-exit"
    else:
        lifetime = "one-time (until closed)"

    ssl_context = None
    if TLS_ENABLED:
        cert_dir = os.path.join(os.path.expanduser("~"), ".haive")
        ssl_context = ensure_cert(
            cert_dir, local_ip(), [socket.gethostname(), "haive.local"]
        )
    name = args.name or socket.gethostname()
    threading.Thread(target=register_loop, args=(args.mac_id, name), daemon=True).start()
    print(f"HaiveControl {VERSION} — serving '{name}' on {SCHEME}://…:{PORT}, registering to '{args.mac_id}'")
    print(f"   lifetime: {lifetime}")
    print(f"   tls: {'on (self-signed)' if TLS_ENABLED else 'off'}")
    print(f"   password: {'required' if PASSWORD else 'none (open on LAN)'}")
    print(f"   exec: {'enabled' if EXEC_ENABLED else 'disabled'}   fps: {FPS}")
    app.run(host="0.0.0.0", port=PORT, threaded=True, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
