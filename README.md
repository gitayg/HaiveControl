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
  Mac:      HaiveHub                 → prints  "Mac ID: itays-macbook-pro"
  Windows:  HaiveControl.exe itays-macbook-pro
                 └─ finds the Mac by that id (Bonjour), registers itself,
                    then serves screen + control + shell on port 8765
  Mac:      open the hub dashboard  → the Windows box is listed → click to view
```

The only thing you configure on Windows is **one argument: the Mac's ID**.

## Built in Rust

HaiveControl is a Rust workspace producing four small, dependency-free binaries:

| Binary | Role | ~size |
|---|---|---|
| `HaiveControl` | agent (runs on each device) | 5 MB |
| `HaiveHub` | hub (runs on the Mac) | 3 MB |
| `haivectl` | CLI (Mac) | 5 MB |
| `haive-mcp` | MCP server (Mac) | 6 MB |

**Build from source:** `cargo build --release` → binaries land in `target/release/`.

**CI builds all three platforms.** `.github/workflows/build.yml` runs a
**Windows + macOS + Linux** matrix (`cargo build --release`) and attaches all four
binaries per OS to the release:

- Tag a release: `git tag v1.0.0 && git push --tags` → e.g. `HaiveControl-windows.exe`,
  `HaiveControl-macos`, `HaiveControl-linux`, plus the `HaiveHub-*`, `haivectl-*`,
  `haive-mcp-*` sets.
- Or run the **build** workflow manually (workflow_dispatch) → download from Artifacts.

Nothing to install to *run* them — they're static native binaries.

### Platform notes (runtime)
- **Windows** — works out of the box. The C runtime is **statically linked**
  (`+crt-static`), so no Visual C++ Redistributable is required (no `VCRUNTIME140.dll`).
- **macOS** — the agent needs **Screen Recording** and **Accessibility** permission
  (System Settings → Privacy & Security). Unsigned binary: right-click → Open the
  first time to clear Gatekeeper.
- **Linux** — runs headless (registers with the hub) with no extra libs. Screen
  capture works on **X11** and on **wlroots** Wayland (Sway/Hyprland) out of the
  box. On **GNOME/KDE Wayland** (no wlr-screencopy) it uses the **xdg-desktop-portal
  ScreenCast** API: the first capture raises a one-time "Share your screen" consent
  dialog on the device's display — approve it once (with "remember") and every later
  capture is silent (a `restore_token` is stashed in `~/.haive/screencast.token`).
  Until consent is given, capture reports "consent pending" rather than a blank error.
  Input control still needs X11. Build deps: `libxcb1-dev libx11-dev libxtst-dev
  libpipewire-0.3-dev libdbus-1-dev` (already in CI).

## Step 1 — start the hub on the Mac

Run `HaiveHub` (`./HaiveHub-macos`). It prints your **Mac ID** and a dashboard URL, e.g.:
```
Mac ID:  itays-macbook-pro
Dashboard: http://localhost:8770/
On Windows run:  HaiveControl.exe itays-macbook-pro
```
Keep it running. Both machines must be on the **same LAN**.

## Step 2 — run the agent on the target

**The hub hosts the binaries**, so the target downloads and runs in one line — no manual
copy. The dashboard shows a ready-made, per-OS command with a copy button. It downloads
the file as **`airm`** and registers it. For example:

```powershell
# Windows (PowerShell or cmd) — works in both
curl.exe -L -o airm.exe http://MAC_IP:8770/bin/HaiveControl-windows.exe
.\airm.exe MAC_IP:8770 --id itays-macbook-pro
```
```bash
# macOS / Linux
curl -L -o airm http://MAC_IP:8770/bin/HaiveControl-macos && chmod +x airm
./airm MAC_IP:8770 --id itays-macbook-pro
```

The target can be given by **direct IP** (`MAC_IP:8770`), by **Mac ID** (Bonjour
`--id`), or both (IP first, Bonjour fallback). Append a **password** as a final argument
to require auth. After registering, the agent prints **`ready`**. The first run triggers
a **firewall** prompt — allow it on private networks.

### Staying current
The agent **auto-checks the hub for a newer build every 2 minutes** and self-updates in
place. You can also push an update on demand from the dashboard (**Update**) or MCP
(`update_agent`) — the agent replaces its own executable and relaunches with the same
arguments.

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

## Using it — the hub dashboard

The dashboard is a single-page console: a **device sidebar** on the left, a **stage** on
the right. Pick a device and everything happens in place — no new tabs. The sidebar
polls every few seconds so status dots (online / idle / stale) and last-seen stay live
without reloading (an active stream keeps playing).

Per selected device you get its details (OS, CPU, memory, user, IPs, cameras, mics),
**live CPU-load and free-RAM meters** (re-sampled every cycle), and an action bar that
renders results **in the stage viewport**:

- **● Live screen** — the full screen streams live (MJPEG).
- **● Cam live** — live webcam video. A **camera picker** chooses which camera; the
  same picker feeds **Camera shot**.
- **Screenshot** / **Camera shot** — a single fresh frame.
- **Run…** — enter a single command; stdout/stderr print to the inline console.
- **Shell** — a full **interactive terminal** (xterm.js over a real PTY): colors,
  `Ctrl-C`, arrows, tab-completion, `top`/`vim`, live resize.
- **Get file / Put file** — a remote **file browser** to download or upload.
- **Update** — hot-update this agent to the hub's latest build.
- **Dissolve** — stop the agent and remove its autostart (does not delete the binary).
  If the device is **offline**, the dissolve is **queued** and runs automatically on
  its next connect (the dashboard shows a "⏳ dissolve queued" chip with a Cancel button).

Uploads land in `SCREEN_SHARE` (or the user's home dir if unset); with `SCREEN_SHARE`
set, browsing/downloads are confined to that folder (`..` is blocked).

Each device in the sidebar has a **🤖 icon** — click it to copy a ready-to-paste block
that sets up the MCP for that device (the `claude mcp add …` line with the hub URL, your
`MCP_TOKEN`, and your owner pre-filled) plus a few example prompts. Hand it to your AI agent
and it can drive that machine.

**Live MCP activity.** When an AI agent is accessing a device through the MCP, the hub
shows it: the sidebar row gets a pulsing **🤖⇄** badge, and the device's detail pane shows
an **"AI agent accessing now"** panel with a rolling log of the recent MCP actions (screenshot,
run command, input, …) and which owner made them. So you can watch agents work in real time.

**Action runner.** Per device, non-interactive actions are a single consistent control: an
**action dropdown** (Reports · Security · Software · Power · Notify · Run) → a **description** →
an input only when needed → **Execute**. Tick **Schedule** to run it later instead — **once in N
min**, **every N min**, or **daily at HH:MM (UTC)**; queued runs fire server-side and appear in
the **⏰ Scheduled** view (with next-run + cancel). GUI apps / long tasks use **Launch an app (no
wait)** so they can't block the channel.

**Session recording.** Every interactive **Shell** session is auto-recorded (asciinema `.cast`)
and replayable in **🎬 Recordings** through the bundled terminal, original timing preserved.

**Command plugins.** Drop a JSON manifest in `HUB_DATA/plugins/`
(`{id,name,description,group,cmd:{windows,macos,linux}}`) and it becomes a first-class action
everywhere — dropdown, fleet, schedule, and MCP (`list_plugins` / `run_plugin`) — no rebuild.

**Device map.** **🗺 Map** plots each device by approximate location (public-IP geolocation,
city-level, resolved server-side) on a real Leaflet/OpenStreetMap basemap (graticule fallback if
offline). LAN/private-IP devices are listed as unlocated.

**CVE lookup.** **🔎 CVE lookup** queries NVD for known CVEs of a product/keyword (CVSS-sorted).
A manual lookup, not an automated scan. Also over MCP as `cve_lookup`.

**Settings & auto-update.** **⚙ Settings** lets an admin choose **Manual** or **Automatic** agent
updates; on automatic, the hub pushes updates to devices running behind its served build.

**Action discovery.** `GET /actions` (and `/m/actions`) returns a machine-readable catalog of every
runnable action (built-ins + plugins) with how-to-invoke hints — so a non-MCP agent can discover
capabilities. Actions are presented per-device as a labeled list (variant dropdown + Execute +
optional schedule), and the sidebar groups the global views (Fleet / Security / Ops / System).

**Agent version.** The device detail shows the running agent version and whether it's behind the
hub's served build; the **Update** button shows the target version (`Update → x.y.z`).

Everything persistent (custom scripts, schedules, recordings, plugins) lives under `HUB_DATA`
(set it to a persistent, writable volume — `/data` in the shipped image).

**Compliance.** The sidebar's **🛡 Compliance** runs the security-posture checks
(disk encryption, firewall, antivirus, OS updates) across **every** device in parallel and
shows a matrix — one row per device, a ✓/✗ per check, and an A–F grade. Pick a framework
(**CIS · NIST 800-53 · PCI-DSS · HIPAA · ISO 27001 · Essential Eight**) and each check column
shows its mapped control ID. These are *indicative* references to orient an operator, not
certified audit evidence. Per-device compliance is also on the device's **Compliance** button,
and over MCP as `compliance_posture` (one device) and `fleet_compliance` (all, with grades).

**Script library.** The sidebar's **🧰 Script library** exposes the
[TacticalRMM community-scripts](https://github.com/amidaware/community-scripts) repo (130+
maintenance/diagnostic scripts). Search by name/description/category, pick a target (one device
or **All devices (fleet)**), and hit **Run ▶**. The script body is fetched from GitHub and
base64-wrapped into a single `/exec` call — PowerShell via `-EncodedCommand`, `cmd` batch via a
temp file, `python`/`shell` inline — so nothing is left on the device. A per-OS guard blocks
running a Windows-only script on a Mac, etc. (Subject to the agent's ~65s `/exec` cap; long
scripts get truncated — fire-and-forget is a future enhancement.) Also available over MCP as
`search_scripts`, `run_script`, and `run_script_fleet`.

**Fleet status.** The sidebar's **📊 Fleet status** opens a whole-fleet overview — one row
per device, every parameter at a glance: status dot, OS/arch, logged-in user, live CPU load,
free/total RAM, cores, camera/mic counts, address (LAN or relay), last-seen, and a **🤖⇄**
marker when an AI agent is on it. A summary strip up top counts online / idle / stale devices,
shows average CPU load, and how many are being accessed via MCP right now. It's owner-scoped and
refreshes live; click any row to jump straight into that device's control view.

**Audit log.** The sidebar's **📋 Audit log** opens a running record of every device action —
each row is *when · via (browser/MCP) · action · device · who · detail* (e.g. the exact
command run). It's scoped to your account (you see actions on your own devices) and updates
live. Recorded server-side (in memory, last 500 events).

## Run commands from the Mac (API + CLI)

Everything the browser does is a plain HTTP API on the agent, so you can drive a
device from a script. Two ways:

**`haivectl` (recommended)** — resolves the device through the hub by name, so you
never type its IP:

```bash
haivectl list                          # list registered devices
haivectl exec mymac "ipconfig /all"    # run a command, print output
haivectl get  mymac C:\logs\app.log    # download a file
haivectl put  mymac ./patch.zip C:\tmp # upload a file
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

The `haive-mcp` binary wraps the same API as MCP tools, so an AI client (Claude Code,
Claude Desktop, etc.) can operate a device by name. Tools exposed:

- `list_devices()` — registered devices, with full details (OS, CPU, memory, logged-in
  user, IPs, cameras, microphones, last-seen)
- `screenshot(device)` — the current screen as an image
- `camera_snapshot(device, index?)` — a still from a connected webcam (pick which with `index`)
- `run_command(device, command)` — run a shell command, get output
- `click(device, x, y)` / `type_text(device, text)` / `press_key(device, key)` — drive mouse + keyboard
- `download_file(device, remote_path, save_as?)` / `upload_file(device, local_path, remote_dir?)`
- `update_agent(device)` — hot-update the agent to the hub's latest build
- `dissolve_agent(device)` — stop the agent and remove its autostart

Live video (screen and camera) streams as MJPEG in the browser dashboard; it isn't an
MCP tool because a stream isn't a single tool response — use `screenshot` /
`camera_snapshot` for AI-driven stills.

### One MCP server, many devices
The hub tracks every registered agent, so a single `haive-mcp` controls them all —
just run the agent on each device with the **same Mac ID**. They each register and you
target them by name: `run_command("linux-box", …)`, `screenshot("macmini")`. Give each
a clear label with `--name` (or `SCREEN_NAME`) so they're easy to tell apart:

```bat
HaiveControl.exe mymac secret --name reception-pc
```

Runs on the Mac next to the hub. Register the binary:

```bash
claude mcp add haive -- /full/path/to/haive-mcp
```

The MCP drives devices **entirely through the hub's `/m` API** (it never talks to an
agent directly), so the same setup works for LAN *and* cloud/relay devices. Config via env
(set in your MCP client, or export before launch):
- `HAIVE_HUB` — hub base URL (default `http://localhost:8770`; a cloud hub's `https://…`).
- `HIVE_MCP_TOKEN` — token for the hub's `/m` API (must match the hub's `MCP_TOKEN`).
- `HIVE_OWNER` — **optional.** Scope the tools to one owner's devices on a multi-user hub;
  omit it to see every device the token can reach. (The hub can also set `MCP_OWNER` so a
  token maps to an owner server-side — then clients never need `HIVE_OWNER`.)
- `HAIVE_CAFILE` — optional PEM to verify a self-signed hub cert.

Then just ask: *"take a screenshot of mymac"*, *"run `ipconfig` on mymac"*,
*"download C:\logs\app.log from mymac"*.

**Against a cloud hub (crane.glick.run):** set `MCP_TOKEN` on the hub and add `/m` to
`auth_bypass_paths` (a headless MCP can't pass SSO — same reason as the agent). Then point
the local MCP at it with `HAIVE_HUB=https://<app-url>`, `HIVE_MCP_TOKEN=<token>`,
`HIVE_OWNER=<your-email>` (optional). The MCP runs on your Mac; only its HTTP calls to the hub cross
the network.

## Device management & fleet actions

Beyond raw control, the hub exposes canned management actions (run the right OS command
per device, no agent change) — as dashboard buttons, `/x/sys` + `/m/sys` endpoints, and MCP
tools:

- **System reports** — hardware, antivirus status, disk-encryption status, firewall,
  processes, services, network (ARP), installed packages, available updates, power.
- **Actions** — reboot / shutdown / sleep / logoff, firewall on/off, USB-storage lock/unlock
  (Windows), message the logged-in user, install/uninstall a package (winget / brew / apt),
  apply all updates.
- **Compliance posture** — one click scores a device (disk encryption, firewall, AV, OS
  updates) into an A–F grade with per-check pass/fail.
- **Fleet run** — the sidebar's **⚡ Fleet run** runs any shell command (or a report) on
  **every device you own, in parallel**, and shows each device's output. MCP: `fleet_run`,
  `fleet_report`.
- A **search box** above the device list filters by name / host / OS / IP.

## Identity & owner scoping

A device's owner is a **stable id derived from the owner's email** (`UUIDv5(namespace,
lower(trim(email)))`) — deterministic across redeploys and hub instances, with no dependence
on any machine MAC/hostname (which is ephemeral in containers) and no persistence needed.
Emails, pre-hashed ids, and the SSO identity all canonicalize to the same key. The owner id
is only a **scope selector** — the MCP/relay **token is the auth boundary**, so its
guessability is harmless. `HIVE_OWNER` is optional (unset = see all the token reaches).

## Reverse-tunnel relay (control beyond the LAN)

The default model is **pull**: the hub reaches *into* each device at its IP. That only
works when the hub can route to the device — same LAN. To control devices **across NAT**
or from a **cloud-hosted hub**, run the agent in **relay mode**: it dials *out* to the
hub and holds the connection, and the hub drives it back down that channel. The device
never needs a public address.

```bash
HaiveControl <mac-id> --relay https://your-hub.example.com     # cloud hub
HaiveControl <mac-id> --relay http://192.168.1.10:8770         # or any reachable hub
```

- The tunnel is **HTTP long-poll on the hub's normal port** (`/relay/hello`, `/relay/poll`,
  `/relay/reply`) — no extra port, no WebSocket — so it rides a single HTTPS endpoint.
  Every action (screenshot, live video, shell, files, update, dissolve) works over it:
  the agent satisfies each request by calling its own loopback server and streams the
  result back.
- Relay devices show up in the dashboard like any other, tagged `relay`, with live
  CPU/RAM.

### Deploy the hub on AppCrane (crane.glick.run)

The repo ships a `Dockerfile` + `deployhub.json` that build the hub from source and bake
in the current agent binaries (served at `/bin/*`). The hub reads `PORT`, exposes
`/api/health` → `{status, version}`, and — when `HUB_PUBLIC_URL` is set — shows relay-mode
install commands in the dashboard. Recipe:

A **headless agent can't pass SSO** (no browser, no login), so the agent-facing paths must
be SSO-bypassed — and the hub then authenticates the agent itself with a shared token.

1. Create the app from this repo (custom Dockerfile is auto-detected).
2. Set env / secrets:
   - `HUB_PUBLIC_URL=https://<your-app-url>` — makes the dashboard show relay-mode install
     commands (add a custom domain for a cleaner product).
   - `RELAY_TOKEN=<a long random secret>` — **the agent's credential**; it replaces SSO on
     `/relay`, and the dashboard bakes it into the shown install command.
3. **Bypass SSO on the agent-facing paths** (`auth_bypass_paths=["/relay","/bin","/m"]`;
   add `/m` only if you use the MCP) so
   devices can reach the tunnel + downloads and long-lived connections aren't buffered or
   cut — on AppCrane this sets `flush_interval -1` and zero read/write timeouts. **Keep
   `/x/*` behind SSO** — that's the device-control surface, admin-only. TLS is terminated at
   the platform edge, so the tunnel is encrypted even though it's plain HTTP inside. `/bin`
   serves only public binaries, so it needs no token.
4. Deploy, then on each device run the relay command the dashboard shows
   (`./airm --relay https://<your-app-url> --relay-token <token> --name <device>`).

**Relay auth:** with `RELAY_TOKEN` set, every `/relay/*` call must carry `?tok=<token>` —
the agent sends it (`--relay-token` or `HIVE_RELAY_TOKEN`); wrong/absent → `401`. Unset =
open (trusted LAN / dev). Query-string tokens on bypass paths aren't logged by the proxy.

**Relay reliability.** The tunnel is HTTP long-poll, so it can be torn down between
commands (proxy/NAT idle timeout, or a hub redeploy that clears the in-memory tunnel
registry). To keep that from surfacing as spurious "unreachable":
- The agent heartbeats every **10s** (app-level keepalive under proxy/NAT idle windows)
  and, the instant a poll fails, re-registers at a steady ~½s cadence until the hub
  answers — so its tunnel is back within ~½s of the hub returning, not on the next
  heartbeat.
- The hub **waits up to ~4s** for a reconnecting agent's tunnel before declaring it
  unreachable, absorbing redeploy/blip gaps (one central retry for every relay call).
- The dashboard shows a **RECONNECTING** pill (device is heartbeat-online but has no live
  tunnel this moment) distinct from **OFFLINE**, via a `connected` flag on `/agents`.

**Per-user devices (multi-user hub).** When AppCrane forwards the authenticated user
(`X-AppCrane-User-Email`), the hub scopes everything to that user: the device list
(`/agents` + dashboard) shows only devices they own, and device actions (`/x/*`) are
refused (`403`) on devices they don't. Ownership comes from the `owner` a device registered
with — the dashboard bakes a per-account **enrollment token** (`--owner htok_…`) into the
install command it shows, so a device a user enrolls is automatically theirs. No user header
(LAN/dev) = full access, as before.

**Enrollment tokens.** Instead of putting the raw owner id (a UUIDv5 of the email) on every
device command line, each account gets an opaque enrollment token. The token maps to the
owner id on the hub (resolved in `canon_owner`, persisted to `HUB_DATA/owner_tokens.json`),
so a device enrolled with `--owner htok_…` scopes to that account. The token is minted on
first view and shown in **+ Add device**; **Rotate token** there issues a fresh one and
stops the old one working for *new* enrollments — devices already enrolled keep their scope
(they stored the resolved owner id, not the token). `GET /x/enroll-token[?rotate=1]` (behind
SSO) is the API. An email or a raw owner id still works as `--owner`, for backward compat.

> The `owner` is still self-asserted at the transport level (any holder of the shared
> `RELAY_TOKEN` could send an `owner`), so it's a **visibility/soft boundary**. The
> enrollment token narrows this: the value on the device is now an opaque, rotatable
> credential rather than the derivable email/uuid.

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

## Layout (Rust workspace)
- `crates/agent` → **`HaiveControl`** — the agent (Windows/macOS/Linux): screen capture,
  `/frame`, `/stream` (live MJPEG), `/camera` + `/camstream` (webcam), `/input`, `/exec`,
  `/shell/*` (interactive PTY shell), `/upload`, `/download`, `/list`, `/update`,
  `/dissolve`; registers to the hub and reports full sysinfo + live CPU/RAM. Modules:
  `capture` (xcap + nokhwa), `input` (enigo), `shell` (portable-pty), `tls` (rcgen),
  `discovery` (mdns-sd, self-update), `relay` (outbound long-poll tunnel), `http`
  (which also runs a loopback twin the relay self-calls), `persistence`.
- `crates/hub` → **`HaiveHub`** — the Mac hub: Bonjour advertise, `/register`, `/agents`,
  the single-page dashboard (with a bundled xterm.js terminal at `/assets/*`), hosts the
  agent binaries (`/bin/*`), proxies device actions (`/x/*`, incl. live-stream
  passthrough), and terminates the reverse tunnel (`/relay/*`, see `relay.rs`).
- `crates/cli` → **`haivectl`** — Mac CLI: `list` / `exec` / `get` / `put` by device name.
- `crates/mcp` → **`haive-mcp`** — Mac MCP server: `list_devices` / `screenshot` /
  `run_command` / `download_file` / `upload_file` tools (rmcp).
- `.github/workflows/build.yml` — `cargo build --release` matrix (Windows/macOS/Linux).

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
