# Security Posture

IT-AI is an IT-management tool: enrolled agents can run code as SYSTEM on the machines they
run on. That power makes the control plane a high-value target, and the security model is
built accordingly. This page describes the trust model, how to report a vulnerability, and
the knobs you use to harden a deployment.

The v3.0.7 release focused specifically on security hardening: signed self-update,
per-device relay-tunnel authentication, fail-closed identity, and TLS by default.

---

## Trust model

**Token-gated enrollment.** When the hub is authenticated (`RELAY_TOKEN` set), a device
cannot enroll un-owned. Enrollment requires a personal, opaque, rotatable enrollment token
(`htok_…`) minted per account from the dashboard's *Register a device* panel. A device
enrolled with your token is scoped to your account from birth.

**Per-device credentials.** The enrollment token is meant to be used once. On its first
hello an agent ≥ 3.7 asks the hub for its own secret (`hdev_…`) and authenticates every
later `/relay/*` call with that instead; it keeps the secret in a private file
(`~/.it-ai/relay.cred`, 0600) rather than on a command line. A device secret is valid only
for the relay id it was issued to. The hub stores only its sha256, in
`<HUB_DATA>/device_secrets.json` (0600, in a 0700 dir), and compares in constant time. One
device's secret can be revoked from the dashboard without touching any other device, and
removing or dissolving a device deletes its secret. Agents ≤ 3.6.x never ask for a secret
and keep authenticating with the enrollment token. The contract is in
[DEVICE-SECRETS.md](DEVICE-SECRETS.md).

**Per-device relay-tunnel authentication.** The reverse tunnel binds each device to its own
credential. A poll/reply caller must be authorized for *that* tunnel — the shared
`RELAY_TOKEN` alone does not authorize acting as an arbitrary device id. This prevents one
enrolled endpoint from dequeuing (stealing), reading, or forging another device's tunnel
traffic, so a single compromised endpoint cannot pivot into fleet-wide control.

**Fail-closed identity and per-user ownership.** A device's owner is a stable id derived
from the owner's email (`UUIDv5`), deterministic across redeploys with no persistence
needed. When SSO / `RELAY_TOKEN` is configured, authorization fails **closed**: an
authenticated user sees and drives only their own devices — the list, screen, shell, files,
AI assistant, and every device action are gated on `owner == you`. A user cannot see,
reach, or seize another user's device. Ownership persists across redeploys and cannot be
silently dropped (there is no "unclaim" — only transfer). With no identity configured (a
trusted LAN / dev hub with `RELAY_TOKEN` unset), the hub is intentionally unscoped for
single-operator use.

**A refused enrollment changes no ownership (fixed in hub 3.16.1).** Before 3.16.1 a `/relay/hello` with another owner's enrollment token recorded that owner on the device *before* the takeover check refused it with `403`, so anyone holding any enrollment token who knew a relay id became that device's owner (and could control it). The owner is now recorded only after the hello, and any mint, is accepted.

**An owned device cannot be claimed by another owner's token after a hub restart (fixed in hub 3.16.2).** Tunnels live in memory, so until a device reconnected after a restart, a hello for its relay id with another owner's enrollment token was taken as a fresh enrollment and re-owned the device (even one holding its own device secret). An enrollment-token hello is now refused with `403` when the id's device secret, persisted owner override, or device row names a different owner.

**A VPN exit shut down mid-enable stays shut down (fixed in hub 3.17.1).** Enable, pass issue and the 30-second catch-up sweep push to the device without the store lock held, then recorded the result. A credential revoke, Forget, dissolve, owner change or Disable that landed during that push was undone afterwards: the enable re-registered the exit at the relay and wrote it back to `vpn.json`, so the relay routed clients to a device whose exit had been revoked. Each shutdown now bumps a per-device epoch under the store lock, and the relay registration and the `vpn.json` write happen under that lock only when the epoch the request started with (and the device's owner) is unchanged. Otherwise the request returns `409`, the hub state stays off, and the device is sent `/vpn/disable`.

**Approval-gated AI writes.** The AI assistant investigates autonomously with read tools
(inventory, system reports, compliance posture, screenshots, CVE lookup) but **cannot
change a machine on its own**. Writes go through a fixed, server-side fix menu
(`fix_command`): the client sends only a `kind` plus a sanitized argument, and the approval
gate is enforced on the hub — `propose_fix` never executes inside the AI's tool loop.
Nothing is applied until a human approves it. This is the governed-autonomy model:
autonomous inspect, human-approved fix.

**Signed self-update.** Agent updates are verified against a pinned signing key before the
running executable is replaced, and non-HTTPS update sources are refused. This closes the
supply-chain path that turns an RMM compromise into a fleet-wide event: a malicious or
compromised hub cannot push an unsigned build that trojans every agent.

**TLS by default.** The agent serves over TLS using a certificate generated on first run
(stable across restarts). In relay deployments behind a proxy, TLS is terminated at the
platform edge. Controller channels (MCP / CLI) can pin the hub certificate with a CA file
rather than trusting on first use.

**Per-user ownership as isolation.** On a multi-user hub, ownership is the isolation
boundary: the device list, dashboard, and all `/x/*` device-control actions are scoped to
the authenticated user; device-affecting requests on devices you don't own are refused.

---

## Reporting a vulnerability

If you find a security issue, please report it privately — do **not** open a public issue
for an unpatched vulnerability.

- Open a **GitHub Security Advisory** on the repository
  (*Security → Report a vulnerability*), which keeps the report private until a fix ships.
- Include: affected component (hub / agent / MCP / CLI) and version, a description of the
  issue and its impact, and reproduction steps or a proof of concept.
- Please allow a reasonable window for a fix before any public disclosure.

We aim to acknowledge reports promptly, confirm the issue, and coordinate a fixed release
and disclosure timeline with you.

---

## Hardening knobs

Configure these on the hub and at agent enrollment to tighten a deployment.

| Knob | Where | What it does |
|---|---|---|
| **`RELAY_TOKEN`** | hub env + agent (`--relay-token` / `HIVE_RELAY_TOKEN`) | Turns on authenticated (strict-ownership) mode. Every `/relay/*` call must carry a valid token; wrong/absent → `401`. Unset = open trusted-LAN/dev mode. Use a long random secret (`openssl rand -hex 32`). |
| **`PROXY_AUTH_SECRET`** | hub env (behind an SSO proxy) | Requires a proxy-injected shared secret before the hub honors the forwarded `X-AppCrane-User-*` identity headers, so a client-supplied header can't impersonate a user. Make identity trust depend on the proxy, not on a spoofable header. |
| **Personal enrollment tokens (`htok_…`)** | dashboard *Register a device* → `--relay-token htok_…` | Opaque, per-account, rotatable credential that scopes an enrolled device to your account. Prefer these over putting a raw owner id/email on the command line. **Rotate token** issues a fresh one and deletes the old one. Devices that hold their own device secret are unaffected. Devices still authenticating with the old enrollment token (agents ≤ 3.6.x, or any device not yet issued a secret) are **disconnected** on their next call and must be re-enrolled with the new token. The *Register a device* panel shows how many of your devices that is before you rotate. |
| **Device secrets (`hdev_…`)** | issued by the hub to agents ≥ 3.7 on enrollment | Per-device relay credential, valid only for its own relay id. **Revoke** on a device in the dashboard deletes it; that device's next relay call is refused (`401`) until it is re-enrolled with an enrollment token. |
| **`HAIVE_CAFILE`** | MCP / CLI env (`--cafile` on the CLI) | PEM used to verify the hub's (self-signed) certificate, so the controller channel pins the hub cert instead of accepting any certificate. Set this rather than running without certificate verification. |
| **`MCP_TOKEN` / `HIVE_MCP_TOKEN`** | hub env + MCP client | Credential for the hub's `/m` MCP API. Only expose `/m` (and SSO-bypass it) if you actually use the MCP; keep `/x/*` behind SSO. Bind the token to a server-side owner (`MCP_OWNER`) so a shared token can't act as an arbitrary owner. |
| **`SCREEN_SHARE`** | agent env | Confines file browse/upload/download to one folder (`..` blocked). Set it — leaving it unset exposes the whole filesystem to the file-transfer surface. |
| **`SCREEN_EXEC=0`** | agent env | Disables the remote command box / `/exec` entirely, for view-plus-control-only deployments. |
| **`SCREEN_TLS`** | agent env | Leave at `1` (TLS on) for any non-trusted-LAN use. `0` falls back to plain HTTP — only acceptable inside a trusted LAN or behind an edge that terminates TLS. |
| **SSO bypass paths** | hub / proxy config | Expose only the agent-facing paths (`/relay`, `/bin`, and `/m` if used) to unauthenticated agents; keep the human control surface `/x/*` behind SSO. `/bin` serves only public binaries and needs no token. |

### Deployment recommendations

- **Set `RELAY_TOKEN` on every hub that isn't a single-operator trusted-LAN box.** Without
  it the hub is unscoped by design; with it you get token-gated enrollment, per-device
  tunnel auth, and fail-closed per-user ownership.
- **Behind an SSO proxy, always set `PROXY_AUTH_SECRET`** so forwarded identity headers are
  trusted only when they come from the proxy.
- **Pin certificates** for MCP/CLI controllers with `HAIVE_CAFILE` (or `--cafile`) rather
  than disabling verification.
- **Confine the agent** with `SCREEN_SHARE`, and set `SCREEN_EXEC=0` where you only need
  view + control.
- **Rotate enrollment tokens** periodically and after any suspected exposure. Devices
  holding their own device secret are unaffected; devices still on the old enrollment
  token (agents ≤ 3.6.x) are disconnected until re-enrolled, so update agents to ≥ 3.7
  first. Revoke a single device's secret, rather than rotating, when only that device is
  suspect.

---

## See also

- **[DATA-SOVEREIGNTY.md](DATA-SOVEREIGNTY.md)** — why self-hosting shrinks the blast
  radius, with the 2024–25 SaaS-RMM breach record.
- **[README-QUICKSTART.md](README-QUICKSTART.md)** — stand up a hardened hub in under five
  minutes.
