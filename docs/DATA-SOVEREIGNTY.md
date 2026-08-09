# Data Sovereignty — Why Self-Host IT-AI

An IT-management tool holds the keys to your entire fleet: it can run code as SYSTEM on
every machine you enroll. That makes the *control plane* the single most valuable target
an attacker can reach. The question every buyer should ask isn't "how good is the AI" —
it's **"what happens when the vendor gets breached?"**

With a cloud RMM, the answer is: their breach is your breach. With IT-AI, the control
plane is a binary you run on infrastructure you own. There is no shared multi-tenant cloud
to compromise, no vendor credential store that unlocks your fleet, and no third party in
the trust path between you and your machines.

---

## The 2024–25 SaaS-RMM breach record

The remote-management category has been a repeat, marquee target — and the pattern is
consistent: **when the vendor's cloud is breached, every downstream customer is exposed at
once.**

- **Kaseya VSA → REvil (2021).** Attackers exploited a VSA vulnerability to push
  ransomware through the RMM itself, hitting roughly 1,500 downstream businesses in a
  single supply-chain event. This is the incident that permanently marked RMM as a
  top-tier attacker target.
  <https://www.cisa.gov/news-events/alerts/2021/07/04/cisa-fbi-guidance-msps-and-their-customers-affected-kaseya-vsa-supply>

- **ConnectWise ScreenConnect cloud breach (2025).** ConnectWise disclosed a
  nation-state intrusion into its cloud environment affecting a subset of ScreenConnect
  customers, with attacker persistence reported over a period of months. The cloud
  control plane was the entry point.
  <https://www.connectwise.com/company/trust/advisories>
  <https://www.bleepingcomputer.com/news/security/connectwise-breached-in-attack-linked-to-nation-state-hackers/>

- **ScreenConnect CVE-2024-1709 (mass exploitation, 2024).** An authentication-bypass
  flaw (CVSS 10.0) in ScreenConnect was exploited within days of disclosure to deploy
  ransomware and remote-access tooling. **Crucially, on-prem instances that had been
  patched stayed safe** — the compromise tracked exposure and patch latency, not the
  product itself. That is the concrete argument for self-hosting: patched, non-internet-
  facing instances were not swept up in the mass-exploitation wave.
  <https://nvd.nist.gov/vuln/detail/CVE-2024-1709>
  <https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060b>

- **AnyDesk production-systems breach (2024).** AnyDesk confirmed a compromise of its
  production systems, prompting a code-signing certificate rotation and a company-wide
  password reset. When the vendor's own build/production environment is breached, the
  blast radius is every customer that trusts its signed software.
  <https://anydesk.com/en/public-statement-2-2-2024>

- **SimpleHelp CVEs (2025).** A chain of SimpleHelp remote-support vulnerabilities was
  exploited to breach downstream customers via unpatched RMM servers — again, exposure and
  patch state decided who was hit.
  <https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-141b>

The through-line: **a cloud RMM concentrates risk.** One vendor-side compromise cascades to
every tenant simultaneously, and you have no ability to patch, air-gap, or contain it —
you can only wait for the vendor's advisory.

---

## Why self-hosting shrinks the blast radius

Self-hosting doesn't make you invulnerable — it changes *who* your fate depends on and
*how large* a single failure can be.

- **No shared cloud tenancy.** There is no multi-tenant control plane whose breach exposes
  you alongside thousands of strangers. Your hub is yours; a compromise elsewhere is not a
  compromise of you.
- **You control patch latency.** The ScreenConnect and SimpleHelp waves rewarded whoever
  patched fast. When you run the binary, patching is your decision on your schedule — not a
  queue behind a vendor's global rollout.
- **You can air-gap or segment.** The hub can live on an isolated management network with
  no path to the public internet (see below). A cloud control plane cannot.
- **No vendor credential in your trust path.** No vendor-held key, session, or support
  backdoor can be stolen to reach your machines. The trust anchors are secrets *you*
  generate and hold.
- **Open source is auditable.** IT-AI is AGPL-3.0. You (or your security team) can read
  exactly what the agent and hub do — no opaque cloud service to take on faith. The AGPL
  also keeps the self-hostable form open: a modified network deployment must offer its
  source to its users.

---

## Air-gap and regulatory fit

Because the endpoint agent is **outbound-only** and the hub is a binary you place wherever
you like, IT-AI fits deployment models that a cloud RMM structurally cannot:

- **Air-gapped / isolated management networks.** Run the hub on a segmented network; the
  agents dial out only to that hub. No device needs a public address or an inbound port,
  so nothing has to be exposed to the internet for the system to work.
- **Data residency and sovereignty.** All telemetry, screen data, command output, session
  recordings, and audit logs stay on infrastructure you choose, in the jurisdiction you
  choose. Nothing transits a vendor cloud.
- **Regulated environments (HIPAA / finance / government).** Sensitive endpoint data —
  which can include screen contents and typed input captured in session recordings — never
  leaves your control boundary. The built-in `compliance_posture` checks map to **CIS,
  NIST 800-53, PCI-DSS, HIPAA, ISO 27001, and Essential Eight** controls (indicative
  references to orient an operator, not certified audit evidence), and the audit log
  captures who did what, when, on which device.

---

## The architecture that makes the blast radius small

IT-AI's design (hardened in v3.0.7) is built to minimize what a single compromise can
reach:

- **Reverse tunnel, outbound-only.** The agent dials *out* to the hub over HTTPS and holds
  the connection; the hub drives it back down that channel. Zero inbound ports on the
  endpoint, no public address, TLS by default. There is no listening attack surface on the
  managed device to scan or exploit from the network.
- **Per-device relay-tunnel authentication.** Each device's tunnel is bound to that
  device's own credential, so one enrolled endpoint cannot poll, hijack, or forge traffic
  on another device's tunnel. A single compromised endpoint stays contained instead of
  becoming a pivot into the rest of the fleet.
- **Fail-closed identity and per-user ownership.** When the hub is authenticated
  (`RELAY_TOKEN` set), every device is owned from birth via a personal enrollment token,
  ownership can never be silently dropped, and each authenticated user sees and drives only
  their own devices. Authorization fails closed rather than defaulting open.
- **Signed self-update.** Agent updates are verified against a pinned key before an update
  can replace the running executable — closing the highest-impact supply-chain path, the
  one that turned the Kaseya and AnyDesk incidents into fleet-wide events. A malicious or
  compromised hub cannot silently trojan the fleet with an unsigned build.
- **Governed AI autonomy.** The AI investigates freely (read tools) but every change is
  approval-gated on the server (`propose_fix` → human approval → apply). An
  over-permissioned or prompt-injected agent cannot make a change on its own.

Put together: **outbound-only endpoints + per-device auth + fail-closed ownership + signed
updates** means a single stolen credential or one compromised endpoint does not cascade
into fleet-wide control. That containment is the property a cloud control plane cannot
offer you — and it is the reason to self-host.

---

## See also

- **[SECURITY.md](SECURITY.md)** — the full trust model, hardening knobs, and how to
  report a vulnerability.
- **[README-QUICKSTART.md](README-QUICKSTART.md)** — stand up your own hub in under five
  minutes.

*Breach details above are drawn from vendor advisories, CISA advisories, and NVD entries
linked inline. Patch-state outcomes (patched on-prem instances staying safe) reflect the
public advisory record for the cited CVEs.*
