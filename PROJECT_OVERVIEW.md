# Veritas: Project Overview

Veritas is an on-premise compliance monitoring platform for India's Digital Personal Data Protection Act (DPDPA) 2023. It watches an organisation's application logs and API traffic, finds personal data being handled improperly, records tamper-evident evidence, and gives compliance staff a live dashboard to investigate and resolve each case. Everything runs inside the customer's network.

**Contents**
1. [Project status](#1-project-status)
2. [Architecture](#2-architecture)
3. [Implementation](#3-implementation)
4. [How it works](#4-how-it-works)
5. [Example: deploying in a real company](#5-example-deploying-in-a-real-company)

Related documents: `README.md` (start here), `INSTALL.md` (install steps, all platforms), `docs/MACOS.md`, `docs/OPERATIONS.md` (running it), `docs/CUSTOMER_ONBOARDING.md` (the vendor's runbook), `docs/ENTERPRISE_TELEMETRY_SPEC.md` (the intended enterprise agent and telemetry model), `IMPLEMENTATION_ORDER.md` (what was done and what is open), and `veritas-demo/SIMULATION_PLAN.md`.

---

## 1. Project status

Last updated: 2026-10-14. Latest release: **v1.0.22**.

### What is built and verified

| Area | State | Evidence |
|---|---|---|
| Detection (PII in logs/API payloads) | Working | Presidio + spaCy with custom Aadhaar, PAN and Indian phone recognizers |
| Rule engine | Working | Four rules: EXPOSURE_001, PURPOSE_001, RETENTION_001, LINKAGE_001 |
| Evidence store | Working | Append-only SQLite, SHA-256 hash chain per organisation, chain verification (also run with every backup) |
| Dashboard | Working | Overview (with a system-health panel), Live Stream, Audit Ledger, Agents, Policy, Users, Audit Log, Scan Sandbox; driven by a real browser in CI |
| Authentication and roles | Working | Local accounts; roles SUPER_ADMIN, COMPLIANCE_ADMIN, AUDITOR, VIEWER; password policy (10+ characters, common-password list, no username or email), forced change after a reset, per-account lockout, sessions revoked on password change, offline `reset-password` |
| Agent (log forwarder) | Working | File and Docker log tailing, rotation and truncation handled, retry and bounded buffer, health reported with every heartbeat; forms: Linux `.deb`, macOS `.pkg` (self-contained), Docker image, Kubernetes DaemonSet |
| Licensing | Working | RSA-PSS signed `.vlic`, machine-bound; `v2:` fingerprints on Linux (machine-id) and macOS (hardware UUID); the portal's output is checked against the Python and Go verifiers |
| License portal | Live, own repository | Fingerprint validation, no unsaved licenses, license id, Reissue (one database transaction), re-download, audit log, hardened admin login, row-level security; 21 unit tests plus end-to-end runs against the real database |
| Backup and restore | Working | Daily verified backups; `veritas backup`, `backups`, `verify-backup`, `restore` (checks the file first, keeps a safety copy, rolls back on failure); tested in CI on Ubuntu and macOS |
| Operations | Working | Warnings for license, TLS certificate and disk; company certificate install; `veritas check` acceptance command |
| Multi-organisation | Working, org-agnostic | No customer-specific code or bundled configs; each org uploads its own config |
| Linux package | Released, tested | `.deb` installed and exercised on a clean Ubuntu 22.04 runner in CI, and by hand on a separate Ubuntu machine |
| macOS packages | Released, tested in CI | Server and agent `.pkg` installed on a clean Apple-silicon runner: license binding, browser test, agent, restart, certificate, backup and restore, upgrade over the same version, uninstall; the server `.pkg` has also been run on a real Mac |
| Windows installer | Released, tested in CI | Installer test passes; older fingerprint scheme, no agent package |
| Automated tests | About 760 server tests, 138 agent tests, 21 portal tests | Server and agent suites run on Ubuntu, macOS and Windows in CI |

### Open items
| Item | Status |
|---|---|
| Load and long-run testing | Planned: heavy log volume, weeks of uptime, SQLite limits. Detection currently runs inside the `/events` request, so heavy bursts from many agents are not proven |
| Ingest queue and worker pool | Planned, after the baseline from load testing |
| Simulated enterprise environment | Planned (`veritas-demo/SIMULATION_PLAN.md`); a teammate will build it |
| macOS: a settings file that survives upgrades | Open (see `IMPLEMENTATION_ORDER.md`); signing and notarization parked until an Apple Developer account exists |
| Windows: fingerprint v2, an agent package | Open |
| Sanitization mode B | Needs design decisions |
| Offline hardening | Planned: bundle fonts and the PDF library locally |
| Support email, a separate CI signing key, other items | Listed in the backlog in `IMPLEMENTATION_ORDER.md` |

### Known limitations
- One server process and SQLite: suitable for a pilot and mid-sized deployments, not for horizontal scale; no high availability.
- License "revocation" is not enforceable (licenses are files verified offline and expire by date); the portal's "Delete record" only removes its own entry.
- Performance at about 100 events per second is untested.
- No outside security review has been done.

---

## 2. Architecture

![Veritas enterprise deployment and simulation architecture](dpdpa-agent/docs/architecture-enterprise.svg)

*Diagram key: blue boxes exist today, orange dashed boxes are recommended changes (the ingest queue and worker pool), grey dashed boxes are real-environment or optional parts. The left zone is what the simulation stands in for.*

### Components

| Component | What it does | Runs on |
|---|---|---|
| **Veritas Agent** | Tails log files and Docker container logs, forwards each line to the server with a per-agent token, buffers and retries when the server is unreachable | Every application host or node |
| **Reverse proxy** | Terminates TLS and exposes only port 443 | Customer edge |
| **Veritas Server (runtime)** | Receives events, detects PII, evaluates rules, stores evidence, serves the dashboard and API | One VM or server |
| **Launcher / service wrapper** | Starts the runtime under the OS service manager (systemd on Linux) | Same machine |
| **Evidence store** | Append-only, hash-chained record of every verdict, per organisation | Server disk |
| **Org config (YAML)** | The organisation's data inventory and policy: fields, purposes, consent scopes, retention, linkage rules | Server disk, versioned |
| **Dashboard** | Live feed, audit ledger, case handling, agent management, policy view, PDF/evidence export | Browser |
| **License portal** | Vendor-side web app that signs `.vlic` license files | Vendor (Vercel + Supabase) |
| **LLM (optional)** | Natural-language investigation of a violation; receives rule, field name and statute text, never raw PII. Supports cloud APIs or a local model (Ollama-compatible) | Cloud or local |

### Key design choices
- **Everything stays inside the customer network.** Agents only make outbound calls to the server. The only optional egress is the LLM call, and a local model removes even that.
- **Config-driven, no customer logic in code.** Each organisation uploads a YAML describing its fields and policy. The same code serves every organisation.
- **Tamper-evident evidence.** Each verdict stores a hash of itself and the previous one; the dashboard can verify the whole chain.
- **Strict tenant separation.** The organisation id comes from the URL path and the user's permissions, never from the browser state, and each org has its own evidence chain.
- **Offline-first licensing.** A license is a signed file checked locally. No call home is needed.

---

## 3. Implementation

### Technology
| Layer | Choice |
|---|---|
| Server | Python 3.11, FastAPI, uvicorn, Pydantic v2 |
| PII detection | Microsoft Presidio, spaCy `en_core_web_lg`, custom recognizers (Aadhaar, PAN, Indian phone) with validators |
| Storage | SQLite (evidence, agents, users, audit log), YAML (org configs) |
| Frontend | Single-page vanilla HTML/CSS/JS served by the server (no build step) |
| Agent | Python (Docker image, `.deb`, Kubernetes manifests); a single-file build for macOS |
| Packaging | PyInstaller binary; `.deb` (Linux), `.pkg` (macOS, server and agent), Inno Setup installer (Windows); systemd on Linux, launchd on macOS, a Go launcher for the Windows service |
| Licensing | RSA-2048, RSA-PSS SHA-256, base64 payload; Go and Python verifiers |
| License portal | Next.js 14, Supabase (PostgreSQL, row-level security), hosted on Vercel; its own repository |
| CI | GitHub Actions: cross-platform tests, per-OS install tests, tagged release builds |

### Repository layout
```
dpdpa-agent/            core server
  run_pipeline.py       entry point and command-line tools (--fingerprint, --check, --setup-code,
                        --reset-password, --install-cert, --backup-now, --restore, --port)
  dashboard/            FastAPI app, WebSocket live feed, HTML pages
  api/                  event ingestion, agents, auth, RBAC dependencies
  detection/            PII detection engine and custom recognizers
  rules/                rule engine (exposure, purpose, retention, linkage)
  evidence_store/       hash-chained, append-only store
  org_config/           org config schema, validator, versioned store
  registry/             builds per-field policy entries from the org config
  user_store/           accounts and roles
  backup.py, maintenance.py   backups, restore, scheduled backup and chain check
  llm_explainer/        templated and optional LLM explanations
  license.py            license validation and machine fingerprint
  tests/fixtures/       sample org configs used only by the tests
veritas-agent/          log forwarder (Dockerfile, k8s manifests, .deb scripts, macOS build)
veritas-launcher/       Go service wrapper and license check (Windows service)
veritas-demo/           demo services and the simulation plan
package/                .deb and .pkg packaging (server and agent)
installer/              Windows installer script
tools/                  license generation and fingerprint tools
docs/                   guides (macOS, operations, onboarding, telemetry spec)
.github/workflows/      CI, release, per-OS install tests
(the license portal is a separate repository: veritas-license-portal)
```

### Data model (essentials)
- **Event:** organisation, source system, timestamp, raw text snippet, optional structured fields.
- **Verdict:** organisation, rule id, severity (LOW/MEDIUM/HIGH), the field and source involved, an explanation, a breach-notification flag, status (OPEN, ACKNOWLEDGED, RESOLVED; the only mutable part), the previous verdict's hash and its own hash.
- **Org config:** identifiers, fields (name, category, declared purpose, consent scope, retention days, source system, optional `data_since`) and linkage rules.

### Security
- Passwords hashed with bcrypt, with a policy (10+ characters, not common, no username or email) and a per-account lockout; signed session tokens that end when the password changes; login, setup and agent-registration endpoints are rate-limited.
- Agents authenticate with a revocable bearer token issued from a one-time registration key.
- TLS is automatic (self-signed by default, or install your own certificate with `veritas install-cert`); sensitive evidence payloads are encrypted with a locally generated key; on macOS the logs are private and the program folder belongs to root.
- Role checks are enforced on the server side (covered by the RBAC tests); the browser cannot grant itself access by changing the organisation or role it sends.
- PII is masked in API responses and filtered from the server's own logs.

### Licensing
The vendor signs `{org, tier, issued, expiry, optional fingerprint}` with a private key that never leaves the vendor. The product embeds only the public key. On Linux the fingerprint is `v2:` plus a hash of the machine's `/etc/machine-id` (disk serial as fallback), and on macOS `v2:` plus a hash of the hardware UUID, so it does not change when the machine is renamed or its network changes. A machine-bound license only runs on the machine it was issued for. Each license also carries a unique id that ties the file to its record in the portal.

---

## 4. How it works

### The path of one event
1. An application writes a log line, for example a debug message that dumps a customer record.
2. The **agent** reads the new line and sends it to `POST /v1/{org}/events` with its token.
3. The server checks the token, then **detects PII** in the text and in any structured fields (names, Aadhaar, PAN, phone, email), with validators to cut false matches.
4. The **rule engine** compares what was found with the organisation's declared policy:

| Rule | Fires when |
|---|---|
| EXPOSURE_001 | Raw personal data appears where it should never appear, such as logs or API responses |
| PURPOSE_001 | Data appears in a system whose declared purpose or consent scope does not allow it, or a field that is not declared at all |
| RETENTION_001 | Data in a source system is older than the retention days declared for that field |
| LINKAGE_001 | Several individually harmless fields appear together and could identify a person |

5. Each finding becomes a **verdict** with severity and an explanation (statute reference included). It is appended to the **evidence chain** and pushed to connected browsers over a WebSocket.
6. A compliance user sees it in the **Live Stream**, opens the case, asks the investigation panel questions, comments, and moves it from OPEN to ACKNOWLEDGED to RESOLVED. Reports and evidence can be exported, and the hash chain can be verified at any time.

### An illustrative example
*(Illustrative values, not real data.)*

A log line from an order service:
```
[2026-10-05T09:14:02Z] DEBUG order-service: fetched customer record {name: "Rohan Verma", phone: "9876543210", address: "Flat 4B, Green Meadows, Pune"}
```
Veritas detects a name and a phone number in a log, which the org's policy says must never be logged. It records an EXPOSURE_001 verdict with severity HIGH, masks the values in the dashboard (`[PHONE_REDACTED]`), and links the verdict to the previous one in the chain.

### Onboarding an organisation
An administrator creates the org in the dashboard (or uploads YAML) describing what data each system holds:
```yaml
org_id: acme_retail
fields:
  - field_name: phone
    pii_category: phone
    declared_purpose: order_fulfillment
    consent_scope: order_fulfillment
    retention_days: 1095
    source_system: order-service
  - field_name: aadhaar
    pii_category: aadhaar
    declared_purpose: onboarding_kyc
    consent_scope: onboarding_kyc
    retention_days: 180
    source_system: partner-service
    data_since: 2025-12-24     # this system already holds data from this date
linkage_rules:
  - fields: [name, phone, delivery_address]
```
No code change or redeploy is needed. Updating the policy creates a new versioned file, so policy changes are themselves auditable.

---

## 5. Example: deploying in a real company

A worked scenario for a fictional company, **Acme Retail**, which runs an order service, a payments service and a support tool on 8 application servers plus a small Kubernetes cluster. Compliance has two analysts and a data protection officer.

### Before the project starts
- Acme provides one Ubuntu 22.04 VM (4 GB RAM or more, 20 GB disk) in its compliance network zone, and a DNS name such as `veritas.acme.internal`.
- IT opens only the reverse proxy port (443) to the app network and to the compliance team, and allows outbound calls from the app servers to the Veritas VM.
- Acme decides whether investigations may use a cloud LLM, a local model, or no LLM at all.

### Day 1: install the server
1. Install the package: `sudo apt install ./veritas_<version>_amd64.deb`. The installer prints the machine fingerprint.
2. Send that fingerprint to the vendor (`veritas fingerprint`). The vendor issues a license in the portal and sends back `acme.vlic`.
3. `sudo veritas license acme.vlic`. The service starts after a minute and the dashboard is available.
4. Put the reverse proxy in front, or replace the self-signed certificate with one from Acme's internal CA.
5. Open `/setup`, enter the one-time setup code from `sudo veritas setup-code` (it proves you have access to the server), create the first administrator, then add users with roles: the DPO as COMPLIANCE_ADMIN, the analysts as AUDITOR, and management as VIEWER.

### Day 2: describe the data
The compliance team creates the organisation `acme_retail` and declares the fields each system holds: purpose, consent scope and retention. They set `data_since` for any system that already stores older data, so the retention clock starts correctly.

### Day 3: connect the applications
For each application host:
1. In the dashboard, **Agents → Issue Registration Key**.
2. Install the agent (`veritas-agent` package), set the server address and the key in `agent-config.yaml`, and list the log files to watch.
3. For Kubernetes, apply the DaemonSet, Secret and ConfigMap from `veritas-agent/k8s/`.

Each agent shows up as ACTIVE with a heartbeat. If a host is retired or compromised, **Revoke** stops it immediately.

### Week 1: tune and operate
- Run in observation mode: review the first violations, fix the applications that log personal data, and correct the org config where the policy was too strict or too loose.
- Backups run daily by themselves, with a chain check each time; copy them off the machine (`sudo veritas backup`, `restore` and `verify-backup` are there when needed). Point monitoring at `/health` and `/ready` and collect the service logs.
- The DPO exports the audit report when needed; the hash chain proves the records were not changed.

### Ongoing
- Updates arrive as a new package; the data directory and configs stay in place.
- Policy changes are made by uploading a new org config version.
- Licenses are renewed by issuing a new file before the expiry date.

### Recommended capacity for this scenario
About 8 agents sending a few events per second each is within what one server handles today. For larger or burstier traffic, the planned ingest queue and worker pool should be in place first; the simulated environment is being built to measure exactly this.
