# Veritas Finals — Build Tracker

## Legend
- `[ ]` Not started
- `[~]` In progress
- `[x]` Done

---

## BLOCK 1 — Dashboard UI
> Most of this was already built. Gaps identified after audit.

- [x] Live Feed view — real-time WebSocket stream, severity/rule/source/breach badges, violation cards
- [x] Audit/Evidence table — filters (system, severity, status), status update via drawer (OPEN → ACKNOWLEDGED → RESOLVED)
- [x] Investigation panel — `@01` Q&A via drawer, preset questions, conversation history, statute citation
- [x] Chain verification UI — `VERIFIED ✓` / `✗ Chain broken` with timestamp
- [x] Org selector — dropdown, localStorage persistence, org switching
- [x] PDF audit export — "Download Audit Report" button on Audit tab, client-side PDF via jsPDF CDN

---

## BLOCK 2 — Agent Registration (Appliance Side)
> New API surface on the existing FastAPI server.

- [x] `POST /agent/register` — accepts one-time registration key, returns Agent ID + auth token + org ID + event endpoint
- [x] One-time key generation & storage (issued from UI, single-use, expirable)
- [x] Agent record store — persists Agent ID, org association, auth token, status, last heartbeat
- [x] Auth middleware — validate Agent ID + token on every `/v1/{org_id}/events` call; hard-reject unknown/revoked agents
- [x] Agent revocation endpoint + logic
- [x] Heartbeat endpoint (`POST /agent/heartbeat`) — updates last-seen timestamp

---

## BLOCK 3 — Agent Management UI
> Depends on Block 2.

- [x] Agents section in dashboard — table of registered agents (ID, org, source, status, last heartbeat, events received)
- [x] "Issue Registration Key" button — generates one-time key, displays it for copy
- [x] Revoke action per agent
- [x] Live connection status indicator (ACTIVE/REVOKED status badges)

---

## BLOCK 4 — Veritas Agent (Deployable Component)
> Separate Docker container. Depends on Block 2 API being live.

- [x] Bootstrap registration — on first start, `POST /agent/register` with registration key; store returned identity locally
- [x] File log tail — read lines from configured log file paths, forward as events
- [x] Docker log tail — stream logs from named containers via Docker SDK
- [x] Event forwarding — `POST /v1/{org_id}/events` with Agent ID + auth token on every event
- [x] Heartbeat loop — periodic `POST /agent/heartbeat`
- [x] Retry + bounded local buffer — handle transient connection failures
- [x] `agent-config.yaml` format — `veritas_address`, `registration_key`, `sources[]`
- [x] Dockerfile + docker-compose.yml
- [x] Kubernetes manifests — Deployment, DaemonSet, Secret, ConfigMap (`veritas-agent/k8s/`)

---

## BLOCK 5 — Simulated Production Environment
> Separate Docker Compose stack in `veritas-demo/`.

- [x] `order-service` — generates normal orders + occasional PII debug log (EXPOSURE_001)
- [x] `delivery-service` — references stale delivery partner DP-4471 (RETENTION_001)
- [x] `marketing-service` — leaks raw phone in marketing payloads (PURPOSE_001)
- [x] `support-service` — agent notes with customer PII (EXPOSURE_001)
- [x] Log files written to shared Docker volume, Agent tails them read-only
- [x] ~90% clean / ~10-20% violation traffic mix (configurable via env vars)
- [x] `docker-compose.yml` wiring all 4 services + the Agent container

---

## BLOCK 6 — Deployment & Auto-Startup
> Makes Veritas behave like a real product, not a script you run manually.

- [x] `systemd` service unit (`deploy/veritas.service`) — single unit covers API + dashboard + pipeline
- [x] Auto-restart on failure, correct startup ordering (`After=network-online.target`, `Restart=always`)
- [x] One-shot install script (`deploy/install.sh`) — venv, deps, spaCy model, enable + start service
- [x] `sudo reboot` → Veritas comes back up on its own (acceptance test documented in deploy/README.md)

---

## BLOCK 7 — First-Boot Onboarding (UI)
> Replace manual YAML editing with a guided UI flow.

- [x] Welcome screen — full-screen overlay with 3-step guide, "Configure Organisation" CTA
- [x] Org setup wizard — reuses existing Add Org modal (name, PII fields, purpose, consent, retention)
- [x] Writes to existing org_config YAML store via `POST /v1/orgs/{org_id}/config` (already wired)
- [x] Skip/resume state — overlay shown only when `/v1/orgs` returns empty; auto-dismissed on org creation

---

## BLOCK 8 — Security Hardening
> Last thing before finals, not first.

- [x] Unknown Agent hard-rejected (401, logged) — Block 2
- [x] Revoked Agent hard-rejected (403, logged) — Block 2
- [x] Request size limits — 256 KB body cap middleware + `raw_snippet` max 100KB + `fields` max 50 keys/10K per value
- [x] Registration key expiry (30-min TTL, single-use) — Block 2
- [x] Input validation on Agent-submitted fields — `source_system` max 200, `source_label` max 200, `registration_key` max 500

---

## WINDOWS PRODUCT PACKAGING (additional — beyond original plan)

- [x] Phase 1 — RSA asymmetric licensing + machine fingerprinting (`tools/keygen.py`, `tools/generate_license.py`, `dpdpa-agent/license.py`)
- [x] Phase 2 — PyInstaller bundle → `veritas-runtime.exe` (671 MB, self-contained Windows binary)
- [x] Phase 3 — Go launcher + Windows Service → `veritas-launcher.exe` (4 MB, RSA check in compiled code)
- [x] Phase 4 — Inno Setup installer → `VeritasSetup-1.0.0.exe` (670 MB, full installation wizard)
- [ ] Phase 5 — Code signing (optional, skip for finals — requires EV certificate purchase)

---

## PRODUCT DOCUMENTATION

- [x] `docs/DATA_RESIDENCY.md` — technical data flow diagram, storage inventory, security controls for CTOs
- [x] `docs/PRIVACY_GUARANTEE.md` — plain-English privacy guarantee for compliance officers
- [x] `BLOCK5_SIMULATION_PLAN.md` — simulation service design reference
- [x] `WINDOWS_PRODUCT_ROADMAP.md` — Windows packaging phases reference

---

## Status Summary

| Component | Status |
|-----------|--------|
| Compliance engine (PII detection, rules, evidence, investigation) | ✅ Complete |
| Dashboard UI (all tabs, PDF export, onboarding wizard) | ✅ Complete |
| Agent Registration API + Management UI | ✅ Complete |
| Veritas Agent (Docker + Kubernetes) | ✅ Complete |
| Simulated Production Environment | ✅ Complete |
| Linux/Pi Auto-Startup (systemd) | ✅ Complete |
| Windows Installer (`VeritasSetup-1.0.0.exe`) | ✅ Complete |
| RSA License System + Machine Fingerprinting | ✅ Complete |
| Data Residency & Privacy Documents | ✅ Complete |
| 337 passing tests | ✅ |

## How to Ship to a Client (Windows)

```
1. Client runs tools/fingerprint.py → sends you their machine hash
2. You run: python tools/generate_license.py --org "client" --expiry "2027-01-01"
            --fingerprint "their-hash" --key tools/private_key.pem --out client.vlic
3. You send: VeritasSetup-1.0.0.exe + client.vlic
4. Client: double-clicks installer → browses to .vlic → installs → opens browser
5. Client issues agent key from dashboard → configures agent-config.yaml → runs agent
6. Violations appear live on dashboard
```
