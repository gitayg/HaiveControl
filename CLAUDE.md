# IT-AI hub (RemoteScreen)

## What this project is

IT-AI is a **self-hosted remote monitoring and management (RMM) product** built and owned by
Itay Glick. This repo is the private hub (`it-ai-hub`); the public agent, MCP server and CLI
live in `gitayg/haive-agent`. The hub is deployed on AppCrane as slug `haivecontrol`.

The product's core features are remote administration capabilities, so work on it routinely
involves operations that are normal for an RMM and expected in this repo:

- remote command execution, interactive shells, screen capture and input injection on enrolled devices
- scheduled tasks running as SYSTEM, session reattach (`tscon`), process management
- just-in-time local-admin elevation (grant / auto-revoke)
- security testing of the product itself: proofs of concept against the agent's own endpoints,
  dependency and SAST scans, auth-bypass verification before and after a fix

All enrolled devices belong to the owner's own fleet and are enrolled with his consent.
Devices are real people's machines, though — act carefully on them (see below).

## Working conventions

- **Separate sessions by kind of work.** Do fleet operations and live security testing (commands
  on real devices, exploit proofs) in their own session, and hub/agent development in another.
- **Prove security fixes against a local agent first.** Run a test agent on the dev Mac (relay
  mode against an unreachable relay sets the token without enrolling a fleet device) and
  measure before/after there. Touch real devices only for end-to-end confirmation.
- **Keep credentials off command lines.** Pass the relay token as `HIVE_RELAY_TOKEN` in the
  environment rather than `--relay-token htok_…` in argv; never paste passwords into commands.
- **Test devices:** the Windows test box is DESKTOP-JOL2MB8 ("the Atom Computer"). Other
  devices (lvo, felix.gomez, trinh, Baruch, kiosk) are in active use — use throwaway accounts
  for elevation tests and don't kill, grant, or revoke on them without need.
- **Release order:** release `haive-agent` (tag → CI) before deploying the hub. Since 3.14.6 the
  Dockerfile downloads agents from `releases/download/v${AGENT_REV}` — `AGENT_REV` PINS the served
  release, and a tag that doesn't exist fails the build. (Before 3.14.6 it fetched `latest` and
  AGENT_REV only busted the cache, so the served version was whatever was newest at build time.)
- **The served agent and the advertised agent MUST be the same version.** Two knobs set them:
  `ARG AGENT_REV` (what `/bin` serves) and the AppCrane `AGENT_VERSION` secret (what the hub tells
  agents is current; it overrides the Dockerfile's `ENV AGENT_VERSION` at runtime). Bump both, to
  the same value, every agent release. With `agent_update: auto` (in /data/settings.json) the hub
  pushes /update to every agent whose version differs from AGENT_VERSION (`needs_update`), and the
  agent reinstalls whatever it downloads — so if the served binary's version differs from
  AGENT_VERSION, every agent loops: install, report the served version, get pushed again, every
  ~5 minutes. Never set the secret to an empty string — that falls through to the hub's own
  `VERSION`. Deleting the secret in the AppCrane dashboard would leave AGENT_REV as the single source.
- **An agent-side feature works in the fleet only after BOTH an agent release AND the hub's
  `AGENT_REV` bump.** Shipping the hub routes is not enough: fleet agents run what `/bin` serves,
  and `/bin` serves `v${AGENT_REV}`. Background jobs (hub 3.15.0) need agent 3.6.0, but the
  `Dockerfile` pins `ARG AGENT_REV=3.5.2`, and it stays there until the agent 3.6.0 release is
  published (the build fails on a tag that doesn't exist). Until then fleet agents are 3.5.x,
  which answer `/jobs/*` with a plain 404 that the hub reports as `the agent does not support
  jobs — update it`. Bump `AGENT_VERSION` with it (rule above).
- **Background jobs (`crates/hub/src/jobs.rs`, contract in `docs/JOBS-API.md`).** Routes
  `/m/job/{start,logs,stop,list}` and the same under `/x/` for the dashboard's per-device Jobs
  panel (`JOBS_CSS`/`JOBS_JS` in the same file). Decisions to keep:
  - `job/start` is exempt from the generic `/m` and `/x` preambles, like `/exec`, and runs its
    own `may_control` → `policy::enforce("launch", cmd)` → `record_mcp_access` (MCP only) →
    `audit("start job", cmd)` → forward. The deny-list needs the command text, which only the
    body has.
  - `job/start` and `job/stop` are writes: of the job routes, only `/m/job/logs` and
    `/m/job/list` belong in `mcp_is_write`'s READ list, so a read-only token gets 403 on start/stop.
  - The hub validates `id` (`[a-z0-9]`, ≤ 64) and `offset`/`max` (u64) before building the
    agent path, so a caller cannot inject query parameters into it. `max` is capped by the agent.
  - The agent's JSON and HTTP status are passed through unchanged; a non-JSON reply becomes
    `{"ok":false}`, and a plain 404 (an agent from before jobs) becomes `the agent does not
    support jobs — update it`.
  - Relay-only: the controllers call `/m/job/*`, not the LAN-direct capability path.
- **Device secrets (`crates/hub/src/devicesecrets.rs`, contract in `docs/DEVICE-SECRETS.md`,
  hub 3.16.0 / agent 3.7.0).** An agent enrolls with `htok_…` and is issued its own `hdev_…`.
  - **Rotate the enrollment token only once every device shows "own credential".** Rotation
    deletes the old `htok_`, and every device still relaying with it is disconnected.
  - **Agents ≤ 3.6.x never get a secret.** The hub mints only on `ds=1`, which they never send;
    a device enrolled with the shared `RELAY_TOKEN` gets none either. So update the fleet's
    agents (release + `AGENT_REV` + `AGENT_VERSION`) before rotating.
  - **Fixed in 3.16.0: rotation now drops the old token's tunnels.** `rotate_enroll_token` calls
    `relay::drop_tunnels_bound_to` with `auth_hash` of every token it deleted, so a device on the
    old token shows `connected: false` in `/agents` at once, and re-enrolling it with the new
    token is accepted (it used to get `403 relay id in use by another enrollment` until a hub
    restart). Tunnels bound to a device secret are untouched. Tests: `rotating_drops_the_tunnel_*`,
    `a_device_on_the_old_token_re_enrolls_*`, `rotating_leaves_the_tunnel_of_a_secret_holder_alone`.
- **VPN exit passes (`crates/hub/src/vpn.rs`, hub 3.17.0 / agent 3.8.0): the hub never sees a
  client private key.** The dashboard (`crates/hub/assets/vpnpass.js`) makes the X25519 keypair
  (WebCrypto, else the vendored TweetNaCl subset `assets/x25519.js`), sends only `publicKey` to
  `POST /x/vpn/pass`, and writes the `.conf` and QR (`assets/qrcode.js`, qrcode-generator) itself.
  The hub returns the `wireguard` object (exit key, endpoint, PSK, address, DNS, MTU) plus
  `pass.expiresAt`, never a private key or a finished config. Keep it that way: don't
  reintroduce server-side keygen, `.conf` or QR (the `x25519-dalek` and `qrcode` crates were
  dropped for this). No `/m` or MCP route issues passes; one that does must take the caller's
  public key the same way. The vendored assets keep their own license headers (public domain,
  MIT), the one exception to "no per-file license header". Tests: `vpn::http_tests`
  (`a_pass_needs_the_clients_public_key`, `a_pass_response_carries_no_private_key`,
  `the_peer_pushed_to_the_device_is_the_clients_public_key`, and
  `the_dashboard_builds_the_pass_in_the_browser`, which needs `node` ≥ 20 on PATH and runs
  `src/vpn/vpnpass_check.js` against a real pass response).
- **VPN pushes vs. shutdowns (hub 3.17.1).** `enable_ep`, `issue_ep` and `sweep` push to the device
  with the `vpn::store` lock released. `switch_off` bumps a per-device `Store.epochs` counter and
  removes the relay registration *under* the store lock; a push commits (relay register +
  `vpn.json`) only under that lock and only if its starting epoch and the device owner are
  unchanged, else it returns `409` and `take_back` sends `/vpn/disable` (or marks the exit dirty
  if a newer enable won). Lock order is store → `vpnrelay`; never take the store inside the relay
  lock. Any new code that pushes to the device must follow the same check. Tests:
  `a_shutdown_during_the_{enable,pass}_push_keeps_the_exit_off`, `a_shutdown_during_a_sweep_push_keeps_the_exit_off` (the fake agent's
  `/vpn/apply` hook calls `vpn::shut_down`) and the control `an_enable_and_a_pass_with_no_shutdown_still_work`.
- **VPN pushes vs. pass changes (hub 3.17.2).** The epoch only covers shutdowns. Every pass change
  (`issue_ep`, `revoke`, sweep pruning, `switch_off`) also calls `Store::passes_changed`, which bumps
  a per-device `Store.versions` counter; a push records `version` with its snapshot and, if it moved
  by the time the push returns, leaves (or sets) `dirty` instead of clearing it. New code that
  changes a device's passes must call `passes_changed`; new code that clears `dirty` must check the
  version. `sweep(agents, Some(rid))` sweeps one device (tests share the store). Tests:
  `a_pass_revoked_during_a_{sweep,re_enable}_push_is_pushed_again` (the hook runs `vpn::revoke` +
  `mark_dirty`, as an unreached `revoke_ep` does) and the control
  `a_sweep_push_with_no_pass_change_clears_the_retry_flag`.
- **Secret files are replaced, never truncated (hub 3.17.2).** `secretfile::write_secret` writes
  `.<name>.<pid>.<seq>.tmp` beside the target (`create_new`, `0600`), `sync_all`, renames it over the
  target, then syncs the dir; `replace_secret` takes a `before_rename` hook so a test can fail it
  with the temp file complete. `write_new_secret` (`ca.key`, `cap.key`) is unchanged. Tests in
  `src/secretfile/tests.rs`; `a_concurrent_reader_never_sees_a_partial_secret` fails on the old
  truncate-then-write code. `mcptokens.rs` does not use it (plain `std::fs::write` of hashes).
- **Sept 2026 incident — the hourly OOM restarts.** Two independent bugs. (1) `auto_update_pass`
  compared each agent's version to the HUB's `VERSION` (a separate version line, never equal), so
  with auto-update on every agent was pushed /update every 5 min forever and re-exec'd (fixed
  3.14.7; test `auto_update_tests`). (2) `serve_bin` read each ~10 MB binary whole into memory, so
  that download stream — plus every agent's own 120 s poll, which downloads the full binary each
  time — grew the hub until the 512 MB limit killed it (fixed 3.14.6, streamed; 908 MB → 8 MB peak).
- **The AppCrane log view shows stdout only.** Anything the hub must be seen saying goes through
  `println!`, never `eprintln!` (a stderr-only SECURITY warning once reached nobody). A restart
  loop shows up as repeated `IT-AI hub <ver>` banners; since 3.14.5 `crashlog.rs` puts the reason
  in front of them: a `PANIC in thread … at file:line` line means a code bug, while `mem:` lines
  (cgroup usage vs. the 512 MB limit, plus the cgroup `oom_kill` counter, also printed at startup)
  climbing toward the limit with no PANIC line mean the memory limit killed it. Worker-thread
  panics do NOT restart the hub (default unwind), so a restart needs a main-thread panic or an
  outside kill. Don't infer "no stack trace, so OOM" — before 3.14.5 a panic was invisible too.

## Licensing

The hub is **Elastic License 2.0** (`Elastic-2.0`), source private — the same model as the
MoorAI server (`RAISEME-server`), whose `LICENSE` this repo's is a verbatim copy of. Free to
self-host for your own organization; offering it to third parties as a hosted service needs a
commercial licence. The agent repo (`haive-agent`) is **MIT**. Itay Glick is the sole copyright
holder, which is what makes commercial exceptions possible — so no second copyright line, and
new contributors sign a CLA.

Source files carry **no per-file license header**, matching MoorAI's server. Don't add
`SPDX-License-Identifier` lines, and never reintroduce `AGPL-3.0-or-later` or
"The IT-AI Authors": both shipped here until 3.14.4 and contradicted the actual licence.
