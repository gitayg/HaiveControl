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
- **Release order:** release `haive-agent` (tag → CI) before deploying the hub; the hub
  Dockerfile pulls agents from the public release and `AGENT_REV` must be bumped to bust the cache.
- **Every agent release is two bumps:** `ARG AGENT_REV` in the Dockerfile AND the AppCrane
  `AGENT_VERSION` secret. The secret overrides the Dockerfile's `ENV` at runtime, so bumping only
  `AGENT_REV` makes the dashboard advertise the old version and offer agents a downgrade. Never
  set the secret to an empty string — that falls through to the hub's own `VERSION`.
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
