# HaiveControl — RMM feature roadmap

Distilled from 8 research passes. Effort is rough dev-days for a shippable MVP.
Everything is owner-scoped and, per our rule, must surface in the **dashboard** too —
not just MCP/CLI.

---

## The keystone: plugin architecture (do this first)

The hub already has a proto-plugin system: `os_command(platform, kind, arg) -> Option<String>`
maps ~30 named actions to per-OS shell strings, and `proxy_sys` / `proxy_fleet` run them via
the agent's `/exec`. **Externalize that `match` into a data-driven registry** and both surfaces
(dashboard buttons, MCP tools) enumerate from it instead of hardcoded lists.

- **Manifest** (one JSON per plugin): `id, name, description, category, platforms{win,mac,linux},
  kind(command|script), params[], timeout, destructive, elevated, output{render,pass_when}, expose{dashboard,mcp,fleet}`.
- **Live in** baked-in `plugins/` (image default) → `/data/plugins/*.json` (survives redeploys, primary
  extension point) → optional `PLUGIN_REPO` sync. Registry = `RwLock<HashMap<id, Plugin>>`, `POST /plugins/reload`.
- **Discovery:** `GET /plugins` (SSO) + `GET /m/plugins` (token) → both surfaces read it. Dashboard
  `buildControls` renders buttons per category with a param form + destructive-confirm. MCP MVP =
  `list_plugins()` + `run_plugin(id, params)` (proxy_sys already takes arbitrary kinds).
- **Execution:** unchanged — resolve `kind` via registry → render template → existing `exec_output`.
  Script plugins base64-wrap the body to dodge quoting. Migrate the 30 `os_command` arms to seed manifests;
  keep `os_command` as fallback during migration.
- **Trust:** admin-only plugin management; plugins are global (not per-tenant); typed/validated params;
  `type:secret` resolves a hub env var server-side, redacted from audit. A plugin is RCE as the agent user —
  same trust the tool already grants.
- **Effort:** ~2–4 days (MVP command plugins). Phase 2 (~1–2 wk): script plugins, repo sync + signing,
  per-plugin MCP tools with real JSON Schema + `tools/list_changed`.

**Why first:** PSADT, TacticalRMM scripts, and app-control inventory all become *plugins* on top of this.

---

## Rides on the plugin layer

### TacticalRMM community-scripts browser  ·  ✅ SHIPPED v2.5.0
Expose the ~170-script [amidaware/community-scripts](https://github.com/amidaware/community-scripts)
repo so the user can search + run them. Cache the `community_scripts.json` manifest; each script becomes
a script-plugin. Base64-wrap the raw script into one `/exec` call. **Mind the 65s hub timeout** — long
scripts need fire-and-forget + log poll. Dashboard: a searchable script gallery; MCP: `search_scripts` +
`run_script`.

### PSAppDeployToolkit (PSADT) integration  ·  ~2–3 days (Windows)
Standardized app deploy/uninstall on Windows. Because installs exceed the 65s timeout: **fire-and-forget**
(kick off the PSADT run) **+ poll the PSADT log** for progress/exit. Ships as plugin(s): `psadt_deploy`,
`psadt_status`. Dashboard: deploy dialog + live log tail; fleet-capable.

### Application control + privilege elevation (feature 56)  ·  staged
**The agent runs as a standard user** (HKCU Run / user LaunchAgent / XDG autostart) — this governs everything.
- **MVP-0 (hours, no arch change):** `apps_list`, `app_kill`, `app_policy_show` — inventory + soft control,
  works everywhere, zero elevation. *Good candidate for a quick standalone win before plugins land.*
- **MVP-1 (days):** declarative allow/block where privilege already exists — AppLocker XML (Win) / SRP /
  sudoers.d / AppArmor / fapolicyd. Gate behind an elevation probe; return a clear "needs elevated agent"
  error instead of silently failing (fixes the existing `sudo`-in-`sh -c` foot-gun).
- **MVP-2 (1–2 wk):** opt-in **elevated install** (Win Service / mac LaunchDaemon / Linux systemd root).
  Big security-posture change — requires a hardened `/exec` auth review first (a SYSTEM/root `/exec` = remote root).
- **MVP-3:** per-app standard-user elevation (the ThreatLocker model) via SYSTEM scheduled task / sudoers NOPASSWD broker.
- macOS *real* enforcement (ES system extension) needs MDM + signing — separate effort, not MVP.

---

## Standalone tracks (independent of plugins)

### Compliance → standards mapping  ·  ✅ SHIPPED v2.6.0
Extend the existing `posture` composite: more checks, then map results to control IDs across
**CIS / NIST 800-53 / PCI-DSS / HIPAA / ISO 27001 / Essential Eight**. Dashboard: a compliance matrix
per device + fleet roll-up with grade; MCP: `compliance_report(standard)`.

### Session recording  ·  ~1–2 days
Tee the interactive-shell proxy stream into an **asciinema `.cast`** file on `/data`, per session.
Dashboard: a recordings list per device with an inline player; owner-scoped. Cheap because it hangs off
the existing shell proxy.

### Geolocation + map view (feature 30)  ·  ~3–4 days (offline)
Capture each device's **public IP** where the hub sees it (`X-Forwarded-For` in `relay::hello`), resolve
via a bundled offline **DB-IP City-Lite MMDB** (`maxminddb` crate, CC-BY, no account) cached per device on
IP change, and store `lat/lng` in `Agent.data` (flows to the dashboard already, owner-scoped for free).
Render an **inline-SVG world map** (equirectangular pins, no CDN) as a `#map-view` toggle mirroring
`showAudit`; click a pin → device detail. Honest caveats in UI: city-level, VPN/NAT/CGNAT skew, LAN devices
unlocated. Optional online upgrade: bundled Leaflet + OSM tiles (~+1 day).

### OSV vulnerability scan  ·  ~1–2 days (Linux-first)
Query [OSV.dev](https://osv.dev) against installed packages. **Great on Linux** (dpkg/rpm), **near-useless
for winget/Windows** — scope the MVP to Linux and say so. Dashboard: a CVE list per device; low priority.

---

## Recommended sequence

1. **Plugin architecture MVP** — the keystone. (Optionally slip **App-control MVP-0** in first as a
   2-hour standalone win, since it's pure `os_command` additions.)
2. **TacticalRMM script browser** — highest borrowed-value, rides straight on plugins.
3. **PSADT** — Windows deploy, also a plugin.
4. **Compliance → standards** and **Session recording** — independent, parallelizable.
5. **Geo + map view** — self-contained, ship when the above settle.
6. **OSV** — last; Linux-only value.

---

## Known fixes to make (surfaced in use)

### (a) `/exec` must be non-blocking / per-command isolated  ·  ✅ IMPLEMENTED
The agent's `/exec` used to `.output()` (spawn **and wait**), so a spawned GUI/long-running
process wedged the whole exec/relay channel — surfaced launching an app remotely (every `.exe`
dropped the relay). **Fix shipped:** `exec_ep` now (1) supports **`detach:true`** — spawn
fire-and-forget, return `{detached, pid}` immediately (for GUI apps); and (2) bounds
run-and-capture with a **timeout** (default 60s, `timeout` overridable ≤300s) on a worker thread
that kills the process on expiry — so a hung command can't wedge the channel. The default timeout
protects **every** exec path (sys/scripts/fleet/run) automatically. Plumbed through the hub
`proxy_exec` (`detach`/`timeout` passthrough), a **"Launch an app (no wait)"** action in the
dashboard runner, and MCP `run_command`'s optional `detach`. Pairs with driving the GUI via
`/frame` + `/input`. _Needs the release + agent-update cycle to reach devices (agent change)._

### (b) `/exec` capture wedges on GUI grandchildren (handle inheritance)  ·  ✅ ADDRESSED
Root cause (Windows, classic): the agent captured output by spawning `cmd /c <cmd>` with
**inherited pipe handles** and reading stdout/stderr to EOF. When the command launches a
long-running **GUI grandchild** (`start "" App.exe`, an installer's runAfterFinish), the
grandchild **inherits the write-end of the exec pipe**. `cmd.exe` exits, but the pipe never
reaches EOF (the app still holds the write handle and doesn't quit) → the read blocks forever →
the single exec worker stays wedged and every later exec times out (heartbeat is a separate
channel, so the device still shows "online"). `start ""` doesn't help — it detaches the console
but does **not** stop handle inheritance. A command that exits cleanly (e.g.
`AgentClubBuilder --dispatch KEY`) is fine because its pipe closes.
**Fix:** for launches, spawn **detached, stdio → NUL, non-inheritable**. Implemented in
`exec_ep`'s `detach` path — `Stdio::null()` on all three streams + Windows
`DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` creation flags — so no exec pipe
can leak into a GUI grandchild. Combined with fix (a)'s timeout, a captured command can no longer
wedge the channel. Use **Launch an app (no wait)** / `detach:true` for anything that starts a GUI.
_(Needs the release + agent-update cycle to reach devices.)_

---

## Recently shipped (beyond the original list)

- **NVD CVE-lookup** ✅ — `🔎 CVE lookup` view + `/x|m/cve` + MCP `cve_lookup` (keyword → CVEs, CVSS-sorted). Replaces the dropped OSV scan idea (both weak on Windows; this is an honest manual lookup).
- **Geo basemap** ✅ — the `🗺 Map` upgraded from a graticule to **Leaflet + OSM tiles** (fetched at build, served at `/bin/leaflet.*`, graticule fallback).
