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
