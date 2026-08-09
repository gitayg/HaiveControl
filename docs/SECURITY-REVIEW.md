# IT-AI — Security / Bug / Performance Review

Covers both repos: **hub** (`RemoteScreen/crates/hub`) and **agent+mcp+cli** (`haive-agent/crates/{agent,mcp,cli}`). Findings verified by reading the cited code. Items marked ✔︎verified were re-confirmed directly during compilation.

The dominant theme: **authentication/authorization is fail-open in several places, and the two highest-value trust anchors (the LAN control API and the self-update path) are effectively unauthenticated.** Fix the CRITICAL/HIGH auth issues before building anything on the ideas backlog.

---

## CRITICAL

### C1 — Agent: unauthenticated LAN control API → remote code execution ✔︎verified
`haive-agent/crates/agent/src/http.rs:231` · `main.rs:472,477,615`
The agent binds `0.0.0.0:8765` unconditionally (even in relay mode), `password` defaults to empty, and `authorized()` returns `true` whenever the password is empty — regardless of the `direct_token`. `exec` defaults on.
**Exploit:** any host on the same LAN as a relay-enrolled device sends `POST /exec {"cmd":…}` with no credentials → arbitrary command execution (also `/download`, `/upload`, `/fetch-file`, `/camera`, `/update`, `/dissolve`). TLS doesn't help — it protects the channel, not client identity.
**Fix:** when relay-enrolled (direct_token set) or any credential is configured, require it on the LAN listener; drop the "empty password ⇒ authorized" shortcut for non-loopback. Only bind `0.0.0.0` when a credential exists.

### C2 — Agent: unsigned, unverified self-update → supply-chain RCE ✔︎verified (enabler)
`haive-agent/crates/agent/src/http.rs:332-417,435` · `discovery.rs:111-149`
`/update` takes a `url` from the request body; `download_bytes` fetches it with a bare `ureq::get` (any scheme, incl. `http://`); `apply_update` writes it over the running exe via `self_replace` and re-execs — **no signature, no checksum, no pinning**. Auto-update loops pull `http://…/bin/…` over plaintext. Combined with C1 this is unauthenticated LAN → RCE, and a malicious/compromised hub trojans the whole fleet.
**Fix:** require a detached signature (ed25519/minisign) over update bytes, verify against a pinned key before `self_replace`; refuse non-HTTPS update sources.

### C3 — Hub: relay tunnel has no per-device authorization → fleet-wide hijack/eavesdrop/forge
`RemoteScreen/crates/hub/src/relay.rs:163-204` · `main.rs:263-277,697-708`
`GET /relay/poll?id=X` and `POST /relay/reply?id=X&req=n` look up the tunnel **solely by caller-supplied `id`**, gated only by `relay_ok` (the shared `RELAY_TOKEN` baked into every agent, OR any valid owner token). No check that the caller owns tunnel `X`. `req_id` starts at 1 and increments; `relay_id` is `hc-<machine-id>` (enumerable).
**Exploit:** any enrolled endpoint calls `/relay/poll?id=hc-<victim>` to dequeue (steal + read) the victim's pending exec/file/shell requests (also a DoS — the real agent never gets them), and `/relay/reply?id=<victim>&req=1` to forge responses to the hub. Single-endpoint → fleet lateral movement.
**Fix:** bind each tunnel to an authenticated principal — require the poll/reply caller to present that device's own secret (per-tunnel token minted at `hello`); the shared `RELAY_TOKEN` must not authorize acting as an arbitrary `id`.

---

## HIGH

### H1 — Hub: identity trusted from unauthenticated header, fails OPEN ✔︎verified
`RemoteScreen/crates/hub/src/main.rs:102-111,671-683` · abused via `set_owner_ep:1521`
Owner is derived entirely from `X-AppCrane-User-Email` with no secret proving the request came from the proxy. `may_control` returns `true` when identity is `None`. (a) if the proxy forwards a client-supplied header → impersonate any user, incl. `/x/set-owner` to steal devices; (b) any request with no header (direct/LAN reach, proxy misconfig) → `None` → full access to all devices. LAN mode is an advertised deployment.
**Fix:** require a proxy-injected shared secret before honoring `X-AppCrane-User-*`; make `may_control` fail **closed** when SSO/`RELAY_TOKEN` is configured.

### H2 — Hub: AI "read-only" gate escapes to unapproved RCE ✔︎verified
`RemoteScreen/crates/hub/src/main.rs:1750-1767` (`ro_stage_ok`), reached via `run_readonly_command` (no approval)
The read-only allowlist includes interpreters `awk`, `sed`, `find`, `xargs` with no sub-command restriction. `awk 'BEGIN{system("id")}'` contains none of the blocked metachars (`;&><\`$(`, newline) → `is_readonly_cmd` returns true → runs on the device **without the Apply/approval gate**. Prompt-injection in device output fed back as a tool result can steer this. Any principal with `ai-chat` but not `exec` gets escalation.
**Fix:** remove interpreters from the allowlist (deny-by-default), or hard-reject `-exec`/`system(`/sed `e`,`w`.

### H3 — Agent: path traversal / sandbox escape via absolute paths ✔︎verified by reviewer
`haive-agent/crates/agent/src/http.rs:839-848` (`resolve_path`)
Rejects only `".."`. `PathBuf::join` replaces the base on an absolute arg, so `/download?path=/etc/shadow` (or `C:\…`, UNC) escapes the share. With `SCREEN_SHARE` unset (default) there's no restriction at all. With C1 = unauthenticated file read/write (drop into autostart → persistence).
**Fix:** reject absolute paths, canonicalize the join, verify it stays under a canonical share root; default to a real share root, never the whole FS.

### H4 — Agent: relay control channel defaults to plaintext; loopback fully trusted ✔︎verified by reviewer
`haive-agent/crates/agent/src/relay.rs:24-30,129-154` · `config.rs:14-20` · `http.rs:255`
A bare relay host normalizes to `http://`; the agent replays hub-supplied method+path against `http://127.0.0.1:{lp}{path}`, which `handle()` treats as loopback-trusted (fully authorized). An on-path attacker between agent and hub injects commands that run with no further auth.
**Fix:** refuse non-HTTPS relay URLs (or pin the hub cert); authenticate dispatched requests instead of blanket-trusting loopback.

### H5 — MCP + CLI disable TLS verification by default ✔︎verified by reviewer
`haive-agent/crates/mcp/src/main.rs:195-200` · `cli/src/main.rs:55-67`
Both set `danger_accept_invalid_certs(true)` when no CA file is given (MCP does it silently). The self-signed design makes "no cafile" the common case → controller channel is MITM-able.
**Fix:** pin the hub/agent leaf cert (the agent already fetches a hub-signed cert); fail closed rather than accept-invalid silently.

### H6 — Hub: session recordings have no owner scoping ✔︎verified by reviewer
`RemoteScreen/crates/hub/src/main.rs:3042-3079` + `/x/recording-delete`
These `/x/` endpoints take no `?target=`, so the preamble `may_control` is skipped and the handlers apply no owner filter. Any authenticated user can list/read/delete **every** owner's `.cast` recordings (which can contain typed credentials). Path traversal itself is blocked (basename only) — the issue is missing authZ.
**Fix:** stamp recordings with owner and filter list/get/delete by requesting user.

---

## MEDIUM

- **M1 — Hub: MCP owner scoping is a filter, not a boundary.** `/m/` "owner" comes from the client-supplied `?owner=` param; a valid `MCP_TOKEN` holder passes `owner=victim@corp.com` to satisfy `may_control`. A shared MCP token = zero isolation. Bind the token to a server-side owner. (`main.rs:131-134,3092`)
- **M2 — Both: non-constant-time secret comparison.** `==` on `MCP_TOKEN`/`RELAY_TOKEN`/password/`direct_token` (hub `main.rs:704,713`; agent `http.rs:226,239`) — network timing oracle. Use `subtle`/`ring` constant-time eq.
- **M3 — Both: long-lived secrets in query strings** (`?mtok=`, `?tok=`, `?dtok=`, `?id=`) — land in proxy logs/history/Referer. Move to `Authorization` headers; rotate device tokens. (hub `main.rs:700,713`; agent `relay.rs:57,85`)
- **M4 — Agent: `percent_decode` can panic on a non-UTF-8 char boundary → worker-thread DoS.** Slices `&str` by byte index; a crafted `%`+multibyte request panics the worker; a few exhaust the 8 LAN workers. Index the byte slice instead. (`http.rs:1139-1155`)
- **M5 — Hub: fixed 64-thread blocking pool exhaustible by long-polls + MJPEG streams → fleet DoS.** Each `/relay/poll` holds a thread ≤25s; each stream holds one indefinitely. >64 polling devices + a few streams wedge the hub. Move long-poll/stream off the fixed pool or cap streams. (`main.rs:78-86,155,265`)
- **M6 — Hub: authZ silently skipped for any `/x/`|`/m/` endpoint that omits `?target=`.** Structural fail-open-by-omission (root cause of H6). Default-deny: require every device-affecting handler to call `may_control`. (`main.rs:114-151`)

---

## LOW

- **L1 — Agent: loopback unconditionally trusted** — any local unprivileged process can drive `/exec`/`/update`/`/dissolve`; local PE when agent runs as SYSTEM. Consider a loopback token. (`http.rs:255-257`)
- **L2 — Agent: detached exec children never reaped** → zombies on Unix. Reap on a thread or `setsid`. (`http.rs:780-799`)
- **L3 — Agent: camera/analysis timeouts leak the capture thread/child** (webcam LED may stay on). Kill child on timeout like `exec_ep`. (`http.rs:645-656`, `analysis.rs:66-94`)
- **L4 — Hub: `window.HB` inline-`<script>` interpolation strips only `"`** — latent script-context injection if identity is attacker-set (bounded: self-scoped). HTML-escape or emit via JSON. (`main.rs:3586-3592`)
- **L5 — Hub: whole dashboard HTML rebuilt with `format!` per `GET /`.** Cache the static shell in a `OnceLock`. (`main.rs:3516-3593`)

---

## Verified NOT vulnerable (checked, reported as negatives)
- Stage-and-pull path traversal — `serve_staged`/`serve_bin` validate charset and reject `/`,`..`. Safe.
- AI **write/fix** path injection — `fix_command` is a fixed server-side menu; client sends only `kind`+`arg`; `sanitize_fix_arg` restricts to `[A-Za-z0-9 ._-]` ≤80; **approval gate enforced server-side** (`propose_fix` never executes in the tool loop). Solid.
- Dashboard stored XSS from device fields (hostname/name/user/camera/interfaces/os) — all go through `esc2`/`attrEsc`/`textContent`. No unescaped sink found.
- `identity_from_cookie` SSRF — outbound `/api/me` pinned to `*.glick.run`. Safe.
- `winprobe.rs` FFI — `GetDriveTypeW`/`SHEmptyRecycleBinW` use documented null-terminated/null forms, run only for exact `it-ai:probe/*` sentinels. Sound, no panics.

---

## Fix-first order
1. **C1 + C2** (agent): require a credential on the LAN listener; verify update signatures. Closes unauthenticated-LAN→RCE.
2. **C3 + H1** (hub): per-device relay tunnel auth; proxy shared-secret + fail-closed `may_control`.
3. **H2** (hub): remove interpreters from the AI read-only allowlist.
4. **H3–H6**: path-traversal fix, HTTPS-only relay + no-silent-accept-invalid TLS, recording owner scoping.
5. **Medium tier**: constant-time compares, secrets out of query strings, percent-decode panic, thread-pool exhaustion.
