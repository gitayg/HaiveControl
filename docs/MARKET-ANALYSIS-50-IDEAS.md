# IT-AI — Market Analysis & 50 Ideas to Improve

*Self-hosted, open-source, AI/MCP-native IT management: single Rust agent + reverse-tunnel hub + approval-gated AI IT-assistant.*

---

## 1. Where the market is (2025–2026)

**Size & shape.** The RMM software market is ~$4.8–5.7B in 2025, growing ~11–13% CAGR toward ~$14B by 2034. ~840K MSP/IT seats, 6.2M+ endpoint agents installed. Two buyer shapes: **MSPs** (multi-tenant, PSA/billing, per-endpoint economics) and **internal IT** (single-tenant, per-tech/per-seat, ITSM-flavored).

**The field is entirely proprietary and cloud-locked.** NinjaOne (autonomous patching + AI vuln mgmt), Atera ("IT Autopilot" autonomous ticket resolution), Kaseya VSA ("Digital Workforce"), ConnectWise (Robin/Copilot), Datto, Syncro, Level.io, Action1 (patch-first, free ≤200), Automox, Tanium (feeds MS Security Copilot), Intune (Copilot). The 2025–26 theme everyone is shouting: **agentic / autonomous IT**.

**Adjacent markets are siloed.** Remote-control (MeshCentral, Tactical RMM, RustDesk), visibility (Fleet/osquery, Wazuh), and secure-networking (Tailscale/Headscale, NetBird, Twingate) are three separate worlds. **None is AI/MCP-native.**

**The defining buyer fear is blast radius.** An RMM is fleet-wide, SYSTEM-level code execution. The 2021 Kaseya VSA → REvil event (ransomware to ~1,500 businesses) permanently marked RMM as a top attacker target; 2024–25 brought the ScreenConnect cloud breach (nation-state, ~9-month persistence), AnyDesk's production breach, and mass exploitation of ConnectWise CVE-2024-1709 and SimpleHelp. Crucially: **patched on-prem ScreenConnect instances stayed safe** — a concrete, citable argument that self-hosting shrinks the blast radius.

**MCP is now standard — and notorious.** ~28% of Fortune 500 run MCP servers; Anthropic donated MCP to the Linux Foundation (Dec 2025). But 40+ MCP CVEs landed Jan–Apr 2026, with a recurring trio: over-permissioned tools, direct API exposure, and no *runtime* enforcement. Tool-poisoning (malicious instructions in tool descriptions) is a named, Microsoft-warned attack.

## 2. IT-AI's position

**The whitespace is real and unoccupied: open-source + self-hosted + MCP-native + agentic-but-governed IT.** IT-AI already sits on the credible 2026 autonomy line — **autonomous inspect/diagnose, human-approved fix** (propose_fix → approval → apply) — which every serious incumbent (Intune, Dropzone, ServiceNow) also gates. The reverse-tunnel (outbound-only, zero inbound ports) is exactly the zero-trust access pattern, and self-hostable.

**What IT-AI has today (30 MCP tools + hub):** device inventory, run_command, screenshot, camera, remote input (click/type/key), file transfer (upload/download/stage-and-pull w/ sha256), system_report (hardware/av/encryption/firewall/processes/services/network/packages), device_action (reboot/shutdown/sleep/logoff/firewall/usb-lock/update_all), install/uninstall/check_updates, compliance_posture (mapped to CIS/NIST 800-53/PCI/HIPAA/ISO 27001/Essential Eight), fleet_run/report/compliance, TacticalRMM script library search+run, CVE lookup (NVD), plugins, self-update, dissolve, 5-min live analysis, per-user ownership, token-gated enrollment, approval-gated AI fixes.

**Table-stakes gaps vs incumbents:** real patch management (rings/scheduling/confidence), a monitoring/alerting engine, PSA/ticketing, reporting/exec dashboards, network discovery, backup, EDR integration, multi-tenancy for MSPs.

**The strategy in one line:** *don't out-feature NinjaOne — win on the axis they can't cross (open, self-hosted, MCP-native) and make governed AI autonomy + MCP-safety the headline, not the fine print.*

---

## 3. Fifty ideas to improve IT-AI

Tagged by effort **[S]mall / [M]edium / [L]arge** and priority **★** (do-first).

### A. AI / agentic differentiation — the wedge

1. **★[M] Plan-first "dry-run" for every fix.** Before `ai_apply`, have the assistant emit a structured plan (commands, target files, expected effect, reversibility) rendered for approval. Matches the 2026 buyer checklist (pre-dispatch policy point closes ~60% of practical attack surface) and Intune/ServiceNow's gated model.
2. **★[M] Auto-remediation policies ("Worklets"-style).** Let admins codify "if compliance check X fails → propose fix Y," still approval-gated by default, with an opt-in per-policy autonomy toggle. This is Atera/Automox's headline; IT-AI can do it *governed and self-hosted*.
3. **[M] Root-cause narrative on every alert.** When live analysis flips a check to FAIL, have the AI summarize *why*, *since when*, and *the one-click fix* — turning raw posture into decisions (the ServiceNow "reasoning + orchestration" pitch).
4. **★[L] Fleet-wide natural-language ops.** "Which machines are missing BitLocker and haven't rebooted in 30 days?" → AI composes the fleet query across `system_report`/`compliance_posture`. NL-to-fleet-query is the incumbents' flashiest demo.
5. **[M] Learned remediations.** When an admin approves a fix, store it as a reusable, named playbook keyed to the failing signature, so the next occurrence is one click. Directly answers the "repetition without learning" critique of current NL ops.
6. **[M] Confidence + risk score per proposed fix.** Label each AI action low/med/high risk (reversible? touches system dirs? affects boot?) and require step-up approval for high. Mirrors NinjaOne's "patch-confidence scoring."
7. **[L] Anomaly detection on the 5-min telemetry.** Baseline per-device CPU/RAM/new-services/new-processes and surface deviations proactively instead of only threshold checks.
8. **[M] "Explain this device" one-shot.** A single AI action that ingests the full `system_report` + compliance + recent deltas and returns a plain-language health/security brief for that endpoint — great for handoffs and audits.
9. **[S] AI-generated scripts, sandboxed to preview.** Let the assistant draft a PowerShell/Bash script for a task but route it through the same plan-first approval + dry-run rather than direct exec (ConnectWise ships AI scripting; do it safer).
10. **[M] Conversational fleet triage.** A chat mode scoped to "your fleet" that can call read tools freely (investigate 100% of devices) but gates every write — the Dropzone "autonomous investigate, gated response" pattern.

### B. MCP safety & security hardening — differentiate on the thing everyone's scared of

11. **★[M] Authenticated MCP with scoped, ephemeral tokens.** Per-operator MCP tokens with least-privilege scopes (read-only vs write vs fleet) and short TTL. Thousands of public MCP servers run with *no auth*; being the safe one is a selling point.
12. **★[S] Separate read vs write MCP tool roles.** Split the 30 tools into read (list/report/screenshot/cve) and write (run_command/device_action/install/apply) capability sets, grantable independently. Least-privilege tool binding is the 2026 identity best practice.
13. **★[M] Runtime policy enforcement, not post-hoc.** A deterministic policy check that runs *before* any write tool executes (deny by default for destructive ops, allowlists per device group). Researchers cite "no runtime enforcement" as the #1 MCP failure.
14. **[S] Pinned/verified tool descriptions.** Hash the MCP tool manifest and detect drift, so a tampered description can't silently re-scope a tool (anti tool-poisoning, the Microsoft-warned attack).
15. **[M] Per-tool rate limits + circuit breakers.** Cap fleet_run / run_script_fleet blast radius (e.g., max N devices/min, kill-switch) so a poisoned or runaway agent can't sweep the whole fleet at once.
16. **[M] Command allow/deny lists per device group.** Server-enforced (not UI) list of permitted commands/actions per group; the AI physically cannot run outside them.
17. **[S] Redact secrets from all tool output.** Scrub tokens/keys/passwords from `run_command`/report output before it reaches the model context or logs.
18. **[M] Signed agent releases + update pinning.** Verify a signature/checksum on self-update against a pinned key (not just "latest from hub"), closing the highest-impact supply-chain path — a trojaned update is game-over for an RMM.

### C. Trust, governance & audit — ship the buyer's checklist as product

19. **★[M] Immutable, exportable audit log.** Every tool call, approval, and AI action → append-only log with who/what/when/device/before-after, exportable to SIEM. Increasingly a compliance requirement (EU AI Act high-risk record-keeping).
20. **★[L] One-click rollback (<5 min target).** Snapshot the pre-fix state (changed files, registry keys, service states) and offer a revert. The 2026 best-practice rollback target is <5 minutes; almost no RMM does true rollback.
21. **[M] Approval workflows / four-eyes.** Route high-risk fixes to a second approver (manager/security) before execution; Slack/email/webhook notification. Distinguishes governed-autonomy from cowboy automation.
22. **[M] RBAC + device groups/tags.** Roles (viewer/operator/admin) × device groups, so an operator only sees/acts on their scope. Prereq for both MSP multi-tenant and internal-IT least-privilege.
23. **[S] "Reason for action" prompt.** Require a short justification on destructive actions, captured in the audit log — cheap accountability, strong for regulated buyers.
24. **[M] Compliance evidence export.** Turn `compliance_posture` (already CIS/NIST/PCI/HIPAA/ISO/E8-mapped) into a timestamped, per-framework PDF/CSV audit report — a concrete sales artifact.
25. **[S] Session recording for remote-control.** Record screen/input sessions (screenshot/click/type) with retention policy — table stakes for support accountability and incident forensics.

### D. RMM table-stakes — close the gaps that lose deals

26. **★[L] Real patch management.** Rings/groups, schedules/maintenance windows, third-party app patching (not just `update_all`), per-patch approval, reporting. This is the #1 RMM function and IT-AI's biggest gap.
27. **★[M] Monitoring + alerting engine.** Thresholds on the 5-min telemetry (CPU/RAM/disk/service-down/offline) → notifications (email/Slack/webhook/PagerDuty), with sane defaults to avoid alert fatigue (a top incumbent complaint).
28. **[M] Ticketing / PSA integration.** Webhook or native connectors to Autotask/ConnectWise Manage/Jira/ServiceNow; auto-open tickets from alerts, close on remediation. MSPs won't adopt without this.
29. **[M] Network discovery.** Agentless LAN sweep from an enrolled agent (ARP/mDNS/port scan) to find unmanaged devices and offer one-click enrollment.
30. **[M] Reporting & executive dashboards.** Scheduled compliance/patch/asset/uptime reports; a fleet health overview page. Buyers evaluate on reporting quality.
31. **[L] Software/hardware asset inventory over time.** Track installed-software and hardware changes historically (not just point-in-time `packages`), with license/EOL flagging.
32. **[M] Scheduled & triggered automation.** You have scheduled actions; add event-triggered ones (on-alert, on-enroll, on-compliance-fail) to complete the automation story.
33. **[M] Backup status visibility / integration.** Surface backup state (Windows Backup, Time Machine, restic/Veeam presence) in `system_report`; NinjaOne bought Dropsuite because buyers want backup+RMM in one pane.
34. **[M] EDR/AV integration & response.** Beyond `av` status: surface Defender/third-party detections and offer isolate-device (network-quarantine) as a `device_action` — the security-adjacent buyer wants this.
35. **[M] Mobile/agentless coverage note.** At minimum document + detect unmanaged OSes; consider an agentless SSH/WinRM mode for servers where an agent isn't welcome.

### E. Remote access & fleet UX

36. **[M] Attended/on-demand support mode.** A one-time short-code support session (like ScreenConnect/TeamViewer QuickSupport) without full enrollment — the classic helpdesk entry point.
37. **[S] File-transfer UX in the dashboard.** Drag-drop upload, progress, resume on the stage-and-pull path (you have the backend; make it first-class UI).
38. **[M] Multi-monitor + clipboard + quality control in live view.** Table-stakes remote-desktop ergonomics that Splashtop/AnyDesk win on.
39. **[S] Wake-on-LAN.** Trigger WoL via a peer agent on the same LAN to power on offline devices before maintenance (MeshCentral has it; cheap win).
40. **[M] Bulk fleet actions from the dashboard UI.** Surface fleet_run/report/compliance as guided multi-select UI flows, not just MCP tools — most admins won't drive it via chat.

### F. Open-source GTM, packaging & ecosystem

41. **★[S] Single-binary, minutes-to-deploy install.** Lean hard into your existing single-Rust-agent + self-contained-hub strength: one-command install script, embedded DB, <5-min setup. This is *the* strongest OSS adoption lever (Headscale/GoatCounter/OpenObserve all sell on it).
42. **★[S] Deliberate license choice + clarity.** You're AGPL — good defensive moat for a self-hostable SaaS-alternative. Make it explicit and consider an Apache-licensed *agent/SDK* to maximize embedding while AGPL protects the hub. Procurement filters on license.
43. **[M] Public tool/plugin registry.** Formalize the plugin manifest system into a shareable community registry (like TacticalRMM's community-scripts you already query) — network effects + ecosystem lock-in.
44. **[S] Killer docs + one-glance architecture page.** GitHub stars are the OSS trust proxy; frictionless quickstart + a clear "how the reverse tunnel keeps you safe" page convert. Data-sovereignty is the headline given the SaaS-RMM breach wave.
45. **[M] Managed/hosted upsell tier.** Offer an optional hosted control plane for those who don't want to self-host — AGPL protects you from resellers while you monetize convenience.
46. **[S] Benchmarks vs incumbents.** Publish agent footprint (CPU/RAM/binary size) vs bloated legacy agents; "our agent won't get quarantined by Defender" (cf. the May 2026 Datto `cagservice.exe` false-positive incident) is a concrete, timely message.

### G. Performance, reliability & agent footprint

47. **[M] Incremental telemetry diffs.** Send only changed sections in the 5-min analysis (you already delta some) to cut relay bandwidth and hub load at fleet scale.
48. **[S] Agent resource self-cap.** Bound the agent's own CPU/RAM (esp. camera warm-up, capture, WMI probes) so it never becomes the noisy neighbor — counters the #1 RMM complaint (agent bloat).
49. **[M] Hub horizontal scale / relay sharding.** Ensure the reverse-tunnel registry and per-request dashboard render scale to thousands of agents (connection sharding, cached render, backpressure).
50. **[S] Offline queue + reconcile.** Queue actions for offline devices and reconcile on reconnect (you have dissolve-on-next-connect; generalize it to any action) so fleet ops don't silently drop.

---

## 4. If you do only five

1. **#1 Plan-first dry-run** + **#19 immutable audit** + **#20 rollback** — the governed-autonomy trust story, which is your category.
2. **#11 authenticated scoped MCP** + **#13 runtime policy enforcement** — be the *safe* MCP-native RMM while the field is full of unauthenticated ones.
3. **#26 real patch management** — the table-stakes gap most likely to lose an otherwise-won deal.
4. **#27 monitoring/alerting** — without it you're a remote-control tool, not an RMM.
5. **#41 single-binary install + #44 docs/data-sovereignty page** — convert the OSS/self-hosted wedge into adoption.

*Sources: NinjaOne/Atera/Kaseya/ConnectWise/Action1 vendor & analyst material; MS Security Copilot & Intune agent docs; ServiceNow Autonomous Workforce; Dropzone; CSA/NSA MCP security guidance; Aembit MCP CVE analysis; Fleet/MeshCentral/Tactical RMM/RustDesk/Headscale project docs; CISA Kaseya guidance; ConnectWise/AnyDesk 2024–25 breach reporting.*
