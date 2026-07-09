# HaiveControl

**A hive of your machines, one AI mind.** Self-hosted, LAN-first remote control with a
built-in **MCP interface** — so an AI (Claude, etc.) can see the screen, run commands,
and move files across a whole fleet of devices from one place.

![license: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)

A tiny single-file tool for **your own machines** (Windows, macOS, Linux). One binary
runs on each target: it streams the full screen, accepts mouse + keyboard control, runs
shell commands, and transfers files over HTTPS. Drive it from **any browser**, a CLI,
or an **MCP-enabled AI** — nothing to install on the viewing side.

> View + control + a remote command box. **LAN-only, hub model:** the Mac runs a
> small hub with an ID; you launch the Windows exe with just that ID; it finds the
> Mac over Bonjour and registers itself. This is a real remote-admin agent — see
> **Security** below.

## How it works

```
  Mac:      python3 hub.py          → prints  "Mac ID: itays-macbook-pro"
  Windows:  HaiveControl.exe itays-macbook-pro
                 └─ finds the Mac by that id (Bonjour), registers itself,
                    then serves screen + control + shell on port 8765
  Mac:      open the hub dashboard  → the Windows box is listed → click to view
```

The only thing you configure on Windows is **one argument: the Mac's ID**.

## Getting the binaries (CI builds all three platforms)

Push this folder to a GitHub repo. `.github/workflows/build.yml` runs a
**Windows + macOS + Linux** matrix and builds two single-file binaries per OS —
the agent (`HaiveControl`) and the hub (`HaiveHub`):

- Tag a release: `git tag v1.0.0 && git push --tags` → binaries are attached to the
  GitHub Release (e.g. `HaiveControl-windows.exe`, `HaiveControl-macos`,
  `HaiveControl-linux`, plus the `HaiveHub-*` set).
- Or run the **build** workflow manually (workflow_dispatch) → download from the run's
  Artifacts.

No Python needed on any target machine to *run* them. To build the agent locally on
Windows instead, `build.bat` still works.

### Platform notes (runtime)
- **Windows** — works out of the box.
- **macOS** — the agent needs **Screen Recording** and **Accessibility** permission
  (System Settings → Privacy & Security). Unsigned binary: right-click → Open the
  first time to clear Gatekeeper.
- **Linux** — needs an **X11** session (mss/pynput don't support Wayland). Install
  `libx11`/`libxtst` if missing.

## Step 1 — start the hub on the Mac

Double-click `run_hub.command` (or `python3 hub.py`). It prints your **Mac ID** and a
dashboard URL, e.g.:
```
Mac ID:  itays-macbook-pro
Dashboard: http://localhost:8770/
On Windows run:  HaiveControl.exe itays-macbook-pro
```
Keep it running. Both machines must be on the **same LAN**.

## Step 2 — run the agent on Windows

```bat
HaiveControl.exe itays-macbook-pro my-secret-password
```
(Windows shown; on macOS/Linux it's `./HaiveControl-macos itays-macbook-pro …`.)
- 1st argument: the **Mac ID** from step 1.
- 2nd argument (optional): a **password**. If given, the admin is prompted for it when
  connecting. Omit it for an open LAN-only session.

The first run triggers a **firewall** prompt — allow it on private networks. The agent
finds the Mac by that id and registers itself.

### Lifetime modes
Pick how long the agent sticks around (default = one-time):

| Mode | Flag | Behaviour |
|------|------|-----------|
| One-time | *(none)* | Runs until you close it. Nothing installed. |
| Persistent | `--persist` | Installs autostart so it comes back on every boot. |
| Timed | `--ttl MIN` | Runs for `MIN` minutes, then exits and removes any autostart. |

```bat
HaiveControl.exe mymac secret --persist       :: survives reboot
HaiveControl.exe mymac secret --ttl 30         :: self-dissolves after 30 min
HaiveControl.exe --uninstall                   :: remove autostart, exit
```

Autostart uses the **standard, visible** mechanism per OS — Windows `HKCU\…\Run`,
a macOS **LaunchAgent** (`~/Library/LaunchAgents/com.haive.agent.plist`), or a
Linux XDG **autostart `.desktop`**. Nothing hidden; `--uninstall` (or deleting that
entry) removes it. "Dissolve" stops the process and clears autostart — it does **not**
delete the binary (self-deleting executables are a malware pattern, intentionally
avoided).

## Step 3 — connect from the Mac

Open the hub dashboard (`http://localhost:8770/`). The Windows machine appears in the
list — click it. The dashboard link uses **https** (see below). If a password was set,
the browser shows a login prompt (username can be anything, password = the one you
passed); otherwise the live screen opens directly. No IP to look up.

> Password can also come from the `SCREEN_PW` env var — the 2nd CLI argument just
> overrides it, so it's easy to bake into a Startup shortcut.

## HTTPS (on by default)

The agent serves over **TLS** using a self-signed certificate it generates on first
run (stored in `~/.haive/` on the Windows box, so it's stable across restarts).
Traffic — screen, keystrokes, password, command output — is encrypted.

Because the cert is self-signed, the first time you connect the browser shows a
**"Not private / not secure"** warning. Two options:

- **Quick:** click *Advanced → Proceed*. You're now on an encrypted connection.
- **No more warnings:** copy `~/.haive/cert.pem` from the Windows box to the
  Mac, open it in **Keychain Access**, and set it to *Always Trust*. The lock goes
  green for that machine.

Set `SCREEN_TLS=0` to fall back to plain HTTP if you'd rather not deal with the cert.

## Using it

- **View:** the full screen streams live.
- **Control:** the "control" checkbox (top bar) is on by default — move/click/scroll
  and type go to the target machine. Uncheck to look without touching.
- **Remote commands:** type in the bottom box, Enter runs it via the shell; output
  appears in the overlay (toggle with the **output** button).
- **File transfer:**
  - *Upload* — pick a file and click **upload**. It lands in `SCREEN_SHARE` (or the
    user's home dir if unset). The overlay shows the saved path.
  - *Download* — type a path in the **download path** box and click **get**; the
    browser downloads it. With `SCREEN_SHARE` set, paths are relative to that folder
    and can't escape it (`..` is blocked); unset = any path the user can read.

## Run commands from the Mac (API + CLI)

Everything the browser does is a plain HTTP API on the agent, so you can drive a
device from a script. Two ways:

**`haivectl.py` (recommended)** — resolves the device through the hub by name, so you
never type its IP:

```bash
python3 haivectl.py list                          # list registered devices
python3 haivectl.py exec mymac "ipconfig /all"    # run a command, print output
python3 haivectl.py get  mymac C:\logs\app.log    # download a file
python3 haivectl.py put  mymac ./patch.zip C:\tmp # upload a file
```
Global flags come **before** the subcommand: `--hub` (default `http://localhost:8770`),
`--password` (if the agent set one), `--cafile` (agent `cert.pem` to verify TLS).

**Raw API** (talk to the agent directly; `-k` because the cert is self-signed):
```bash
curl -sk -u :SECRET https://DEVICE_IP:8765/exec \
  -H 'Content-Type: application/json' -d '{"cmd":"whoami"}'
```
Returns `{"ok":true,"code":0,"stdout":"…","stderr":"…"}`. Other endpoints:
`GET /download?path=…`, `POST /upload` (multipart `file`, optional `dir`).

## Use it as an MCP server (drive devices from an AI)

`mcp_server.py` wraps the same API as MCP tools, so an AI client (Claude Code, Claude
Desktop, etc.) can operate a device by name. Tools exposed:

- `list_devices()` — registered devices
- `screenshot(device)` — returns the current screen as an image
- `run_command(device, command)` — run a shell command, get output
- `download_file(device, remote_path, save_as?)` / `upload_file(device, local_path, remote_dir?)`

### One MCP server, many devices
The hub tracks every registered agent, so a single `mcp_server.py` controls them all —
just run the agent on each device with the **same Mac ID**. They each register and you
target them by name: `run_command("linux-box", …)`, `screenshot("macmini")`. Give each
a clear label with `--name` (or `SCREEN_NAME`) so they're easy to tell apart:

```bat
HaiveControl.exe mymac secret --name reception-pc
```

Runs on the Mac next to the hub. Install its one dependency and register it:

```bash
pip install -r requirements-mcp.txt
claude mcp add haive -- python3 /full/path/to/mcp_server.py
```

Config via env (set in your MCP client, or export before launch): `HAIVE_HUB`
(default `http://localhost:8770`), `SCREEN_PW` (if the agent set one), `HAIVE_CAFILE`
(agent `cert.pem` to verify TLS — otherwise unverified, LAN only).

Then just ask: *"take a screenshot of mymac"*, *"run `ipconfig` on mymac"*,
*"download C:\logs\app.log from mymac"*.

## Config (environment variables)

| Var              | Default    | Meaning                                      |
|------------------|------------|----------------------------------------------|
| `SCREEN_PW`      | *(empty)*  | Password. Empty = open (LAN mode); set to require auth |
| `SCREEN_PORT`    | `8765`     | Listen port                                   |
| `SCREEN_FPS`     | `10`       | Frames per second                             |
| `SCREEN_QUALITY` | `60`       | JPEG quality 1–95                             |
| `SCREEN_MAXW`    | `1600`     | Downscale frames wider than this (px)         |
| `SCREEN_MONITOR` | `0`        | 0 = all monitors, 1 = primary, 2 = second, … |
| `SCREEN_EXEC`    | `1`        | Set `0` to disable the remote command box     |
| `SCREEN_TLS`     | `1`        | Set `0` to serve plain HTTP instead of HTTPS  |
| `SCREEN_SHARE`   | *(empty)*  | Confine file transfer to this folder; empty = whole filesystem |
| `SCREEN_NAME`    | *hostname* | Friendly device label shown in the hub (also `--name`) |

## Unattended / start at login
Put a shortcut to `HaiveControl.exe` in the Startup folder
(`shell:startup`), or create a Task Scheduler task "At log on". To pass a password,
point the shortcut at a small `.bat` that does `set SCREEN_PW=… & HaiveControl.exe`.

## Security — read this
- **LAN-only, open by default.** With no `SCREEN_PW`, anyone on the same LAN who
  reaches port 8765 gets the screen, control, **and** the shell. That's fine on a
  trusted home network; on an untrusted/shared LAN, set `SCREEN_PW` and/or
  `SCREEN_EXEC=0`. Don't port-forward this to the internet.
- **`/exec` is a full remote shell** on the Windows box, running as you. Set
  `SCREEN_EXEC=0` to disable it if you only want view + control.
- **Plain HTTP** — traffic is unencrypted. Acceptable on a trusted LAN, which is the
  intended use here.
- **Browser eats some shortcuts.** Combos like Ctrl+W / Ctrl+T are handled by your Mac
  browser before reaching the remote. Use the command box for those cases.
- Intended for **your own devices**. Don't deploy it to watch someone without consent.

## Files
- `hub.py` / `run_hub.command` — **Mac** hub: advertises the Mac ID, collects
  registrations, serves the dashboard
- `server.py` — the **agent** (Windows/macOS/Linux): MJPEG stream, `/input`, `/exec`,
  `/upload`, `/download`, viewer page; registers to the hub
- `capture.py` — screen grab → JPEG
- `input_control.py` — mouse/keyboard injection (pynput)
- `discovery.py` — Bonjour advertise (hub) + resolve (agent)
- `tls.py` — self-signed certificate generation (agent HTTPS)
- `persistence.py` — autostart install/uninstall (`--persist` / `--ttl` / `--uninstall`)
- `haivectl.py` — **Mac** CLI: `list` / `exec` / `get` / `put` against a device by name
- `mcp_server.py` — **Mac** MCP server: `list_devices` / `screenshot` / `run_command` /
  `download_file` / `upload_file` tools (deps in `requirements-mcp.txt`)
- `build.bat` / `.github/workflows/build.yml` — single-exe build (local / CI)

## License

HaiveControl is free software licensed under the **GNU Affero General Public License
v3.0 or later** (AGPL-3.0-or-later) — see [LICENSE](LICENSE). In short: you may use,
modify, and redistribute it, but if you run a modified version as a network service,
you must offer that service's users the corresponding source. It comes with **no
warranty**.

## Intended use

For administering **your own devices**, or devices you're authorized to manage with the
user's knowledge. It's deliberately visible — the autostart entry is standard and
removable, and it does not hide its process or erase its traces. Don't deploy it to
surveil people without consent.
