# Veritas DPDPA Compliance Platform — Technical Audit
**Date:** September 2026  
**Auditor:** Automated codebase analysis  
**Purpose:** Establish technical baseline before major architectural transition to on-premise deployment  
**Rule:** No code was modified during this audit.

---

## 1. Executive Summary

**What Veritas is:** A locally-deployed DPDPA (Digital Personal Data Protection Act, India) compliance monitoring platform. It detects PII violations in application telemetry, enforces DPDPA compliance rules, maintains a tamper-evident audit ledger, and serves an investigation dashboard — all within the client's own infrastructure.

**Primary problem solved:** Organisations processing Indian personal data need to detect when that data is handled improperly (exposed in logs, used beyond declared purpose, retained past the permitted window). Veritas automates this detection and produces auditor-grade evidence.

**End-to-end user workflow:**
1. Admin installs Veritas Runtime on their server (Pi, VM, Windows PC)
2. Admin configures their organisation (PII fields, purposes, retention policies) via dashboard wizard
3. Admin deploys the Veritas Agent (Docker container) on production servers
4. Agent tails application logs and forwards lines to the Veritas Runtime
5. Runtime detects PII, evaluates DPDPA rules, stores evidence
6. Violations appear live on the dashboard; admin investigates and resolves

**Current architecture:** Single-process Python server (FastAPI + uvicorn) + SQLite databases + HTML/JS frontend + Go launcher/service manager. No cloud dependency for core operation.

**Frontend technology:** Vanilla HTML/CSS/JavaScript (~3,100 lines, single file). No React, no build step. CDN dependencies: jsPDF (PDF export) + Google Fonts.

**Backend technology:** Python 3.12, FastAPI 0.115, uvicorn 0.30, Pydantic v2.

**Database/storage:** Two SQLite files (`evidence.db` for compliance verdicts, `agents.db` for agent registrations) + YAML files for org configs.

**Ingestion/pipeline:** HTTP push model. Veritas Agent (Python/Docker) tails logs and POSTs to `/v1/{org_id}/events`. No message queues. No synthetic generators in production build.

**Authentication/authorization:** Agent-level Bearer token auth (only for the `/events` endpoint). No human user authentication. No RBAC. Admin dashboard is open to anyone with network access.

**External services:** OpenAI or Anthropic API for on-demand LLM investigation (optional, graceful fallback). Google Fonts and jsDelivr CDN for UI only (no data sent). No other external dependencies for core compliance operation.

**AI/ML components:** Microsoft Presidio (regex + spaCy NLP) for PII detection — runs fully locally. OpenAI/Anthropic API for natural-language breach investigation — optional, sends only field names and statute text (no raw PII).

**Current deployment:** Run `python run_pipeline.py` (dev) or via systemd/launchd/Windows SCM (production). Windows installer (`VeritasSetup-1.0.0.exe`) bundles everything including the Go launcher.

**Production-like vs prototype:**
- Core compliance engine (detection, rules, evidence): **Production-quality**
- Dashboard UI: **Production-quality**
- Agent registration and auth: **Production-quality**
- License system: **Production-quality** (RSA-PSS, machine fingerprinting)
- Human user authentication: **Not implemented** (explicitly deferred)
- Role-based access control: **Not implemented**
- API authentication for admin routes: **Not implemented** (only Agent routes are auth-protected)

---

## 2. Repository / Codebase Structure

### Top-Level Layout

```
Veritas/Veritas/
├── dpdpa-agent/          ← Core compliance engine + dashboard (Python)
├── veritas-agent/        ← Deployable telemetry forwarder (Python + Docker)
├── veritas-launcher/     ← Windows/Linux/macOS service manager (Go)
├── veritas-demo/         ← Simulation environment for demos (Docker Compose)
├── installer/            ← Windows installer (Inno Setup)
├── tools/                ← License generation + machine fingerprinting
├── .github/workflows/    ← GitHub Actions (macOS build)
├── FINALS_PROGRESS.md    ← Build tracker
├── WINDOWS_PRODUCT_ROADMAP.md
├── HOW_TO_DEPLOY_TO_CLIENT.md
├── BLOCK5_SIMULATION_PLAN.md
└── VERITAS_TECHNICAL_AUDIT.md  ← this file
```

### `dpdpa-agent/` — Core Product (detailed)

```
dpdpa-agent/
├── run_pipeline.py           ← ENTRY POINT: starts FastAPI server, waits
├── dashboard/
│   ├── server.py             ← FastAPI app, all HTTP routes, WebSocket
│   ├── live_feed.py          ← WebSocket room management (per-org)
│   └── index.html            ← Single-file frontend (~3,100 lines)
├── api/
│   ├── integration.py        ← /v1/* routes (events, scan, investigate, orgs)
│   ├── agents.py             ← /agents/* routes (management)
│   └── agent_auth.py         ← Bearer token validation dependency
├── detection/
│   ├── engine.py             ← detect_event() orchestrator
│   ├── analyzer_engine.py    ← Presidio AnalyzerEngine wrapper + spaCy
│   └── recognizers.py        ← Custom: AadhaarRecognizer, PANRecognizer, IndianPhoneRecognizer
├── rules/
│   ├── engine.py             ← evaluate_event(): EXPOSURE/PURPOSE/RETENTION checks
│   ├── linkage.py            ← LINKAGE_001 rule
│   ├── fanout.py             ← Verdict fan-out
│   └── sensitivity.py        ← Entity type → severity mapping
├── evidence_store/
│   └── store.py              ← Append-only SQLite, SHA-256 hash chains, per-tenant
├── agent_store/
│   ├── models.py             ← Agent, RegistrationKey, AgentStatus
│   └── store.py              ← SQLite for agents + registration keys
├── org_config/
│   ├── schema.py             ← OrgConfig, OrgField, OrgIdentifier, LinkageRule
│   ├── store.py              ← YAML file storage (versioned by timestamp)
│   └── validator.py          ← Config validation
├── registry/
│   ├── loader.py             ← In-memory registry cache (load_registry)
│   └── seed_registry.py      ← Blinkit demo seed data + seeded violations
├── llm_explainer/
│   └── explainer.py          ← OpenAI/Anthropic wrapper, fallback template
├── investigation.py          ← @N reference parsing, LLM investigation Q&A
├── masking.py                ← PII redaction for API responses
├── schemas/models.py         ← Event, Verdict, enums (frozen Phase 0)
├── license.py                ← RSA-PSS license validation
├── runtime_paths.py          ← Cross-platform data directory detection
├── deploy/
│   ├── install.sh            ← Pi/Linux installer (systemd)
│   ├── install-linux.sh      ← Generic Linux installer
│   ├── install-mac.sh        ← macOS installer (launchd)
│   ├── veritas-linux.service ← systemd unit
│   └── com.veritas.technologies.veritas.plist ← launchd plist
├── veritas.spec              ← PyInstaller spec (Windows)
├── veritas-mac.spec          ← PyInstaller spec (macOS)
├── veritas-linux.spec        ← PyInstaller spec (Linux)
└── requirements.txt          ← Python dependencies
```

**Entry points:**
- `run_pipeline.py` — production startup
- `dashboard/server.py:app` — FastAPI application object
- `api/integration.py:router` — v1 API router
- `api/agents.py:router` — agent management router

---

## 3. Current Architecture

### System Diagram

```
ORGANISATION'S INTERNAL NETWORK
═══════════════════════════════════════════════════════════════════

Production Application Services
(order-service, marketing-service, etc.)
         │
         │  Writes application logs to files
         ▼
┌────────────────────────────────────────────┐
│          VERITAS AGENT                      │
│  (Docker container or system service)       │
│                                             │
│  ┌─────────────────────────────────────┐   │
│  │ File Tailer (per log file)          │   │
│  │ Docker Log Tailer (per container)   │   │
│  └────────────────┬────────────────────┘   │
│                   │ raw log lines            │
│  ┌────────────────▼────────────────────┐   │
│  │ Event Queue (max 1000)              │   │
│  └────────────────┬────────────────────┘   │
│                   │                         │
│  ┌────────────────▼────────────────────┐   │
│  │ Forwarding Worker                   │   │
│  │  - Bearer token auth                │   │
│  │  - Retry: 1s → 30s backoff          │   │
│  │  - 401/403: drop (revoked)          │   │
│  └────────────────┬────────────────────┘   │
└───────────────────┼────────────────────────┘
                    │ POST /v1/{org_id}/events
                    │ Authorization: Bearer {token}
                    │ (stays within org network)
                    ▼
┌────────────────────────────────────────────────────────────────┐
│                    VERITAS RUNTIME                              │
│          (VM / Server / Pi / Windows PC)                       │
│                                                                 │
│  FastAPI Server (uvicorn, port 8000)                           │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ POST /v1/{org_id}/events  [Agent token required]        │  │
│  │          │                                               │  │
│  │          ▼                                               │  │
│  │  detect_event(event)  ← Presidio + spaCy (local)        │  │
│  │          │                                               │  │
│  │          ▼                                               │  │
│  │  evaluate_event(detected)  ← Rules engine (local)       │  │
│  │          │                                               │  │
│  │          ▼                                               │  │
│  │  build_deferred_explanation(verdict)  ← Template        │  │
│  │          │                                               │  │
│  │          ├─────────────────────────────────┐            │  │
│  │          ▼                                 ▼            │  │
│  │  evidence_store.append()         publish_live_feed()    │  │
│  │  (SQLite, hash-chained)          (WebSocket broadcast)  │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
│  SQLite Databases (local disk):                                 │
│  ├── evidence.db   ← Compliance verdicts (hash-chained)        │
│  └── agents.db     ← Agent registrations + tokens              │
│                                                                 │
│  YAML Files (local disk):                                       │
│  └── org_config/configs/{org_id}/*.yaml ← Org policies         │
│                                                                 │
└─────────────────────────┬──────────────────────────────────────┘
                          │ http://server:8000
                          │ WebSocket ws://server:8000/ws/{org_id}
                          ▼
                   Admin's Browser
                   (dashboard, no auth)

═══════════════════════════════════════════════════════════════════
EXTERNAL (internet) — OPTIONAL ONLY
═══════════════════════════════════════════════════════════════════

OpenAI / Anthropic API
  ← Called ONLY on POST /v1/{org_id}/investigate
  ← Sends: rule type, field name, statute text (NO raw PII)
  ← Optional: falls back to template if key not configured

Google Fonts / jsDelivr CDN
  ← HTTP request for UI fonts + jsPDF library
  ← No sensitive data sent
  ← UI degrades gracefully if unavailable
```

### Data Flows

| Flow | Source | Component | Processing | Storage | Destination |
|------|--------|-----------|------------|---------|-------------|
| Telemetry | App log files | Veritas Agent | Line parsing, queue | In-memory (max 1000) | POST /v1/{org_id}/events |
| Event ingestion | HTTP POST | FastAPI route | Pydantic validation | Synthesized Event object | Detection engine |
| PII detection | Event object | Presidio + spaCy | Regex + NER | DetectedEvent in memory | Rules engine |
| Rule evaluation | DetectedEvent | Rules engine | Policy checks | Verdict in memory | Evidence store + live feed |
| Evidence storage | Verdict | Evidence store | Hash computation | evidence.db (append-only) | Persistent |
| Live broadcast | ExplainedVerdict | live_feed.py | WebSocket send | Not stored separately | Browser WebSocket client |
| Investigation | Stored verdict | investigation.py | LLM Q&A | Not stored | API response |
| Org config | YAML upload | org_config/store.py | Pydantic validation | YAML files on disk | In-memory registry |

---

## 4. Frontend Audit

**Technology:** Single HTML file (`dashboard/index.html`, ~3,100 lines). Vanilla JS, no framework. No build step.

### Pages/Views

#### Overview Tab
- **Purpose:** High-level compliance stats
- **APIs called:** `GET /api/{org_id}/stats`, `GET /api/{org_id}/verdicts` (aggregation)
- **Data displayed:** Total violations, breach candidates, open cases, resolved; severity distribution; top violating systems; most triggered rules
- **Status:** Fully functional

#### Live Stream Tab
- **Purpose:** Real-time violation feed
- **Mechanism:** WebSocket `ws://server:8000/ws/{org_id}` — persistent connection, 3s reconnect
- **Data displayed:** Violation cards (severity, rule, source system, affected field, timestamp, template explanation)
- **Raw PII displayed:** NO — only field names and metadata
- **Status:** Fully functional

#### Audit Ledger Tab
- **Purpose:** Historical record, filtering, chain verification, status updates, PDF export
- **APIs called:** `GET /api/{org_id}/verdicts`, `GET /api/{org_id}/verify-chain`, `POST /api/{org_id}/verdicts/{id}/status`
- **Features:** Filter by source system/severity/status, jump to violation #N, drawer with investigation Q&A
- **Status:** Fully functional

#### Agents Tab
- **Purpose:** Agent fleet management
- **APIs called:** `GET /agents?org_id=`, `POST /agents/issue-key`, `POST /agents/{id}/revoke`
- **Data displayed:** Agent ID, source label, status, events received, last heartbeat
- **Status:** Fully functional

#### Scan Sandbox Tab
- **Purpose:** Manual PII testing / ad-hoc scan
- **API called:** `POST /v1/{org_id}/scan`
- **Features:** Preset scenarios, editable JSON payload, masked output display
- **Status:** Fully functional

### No Login Page
There is no login, session, or authentication UI anywhere in the dashboard. This is explicitly documented in the server.py docstring.

### Org Creation UI
Modal (`#addOrgModal`) with org ID, PII fields, identifiers, and linkage rules. Submits to `POST /v1/orgs/{org_id}/config`. No auth required.

### CDN Dependencies
- `cdnjs.cloudflare.com` — jsPDF 2.5.1 + jsPDF AutoTable 3.8.2 (PDF export)
- `fonts.googleapis.com` / `fonts.gstatic.com` — Geist + Geist Mono fonts

### Backend Capabilities Without Frontend
- `POST /v1/{org_id}/scan` — partially surfaced (Scan Sandbox)
- `GET /api/{org_id}/violations/{n}` — surfaced via "Jump to Violation #" input
- All endpoints accessible directly via HTTP clients

---

## 5. Backend / API Audit

### Complete Endpoint List

| # | Method | Route | Auth | Functional | Notes |
|---|--------|-------|------|-----------|-------|
| 1 | POST | `/v1/{org_id}/events` | Agent token ✓ | YES | Main telemetry ingestion |
| 2 | POST | `/v1/{org_id}/scan` | None | YES | Ad-hoc scan, returns masked output |
| 3 | GET | `/v1/orgs` | None | YES | List registered org IDs |
| 4 | POST | `/v1/orgs/{org_id}/config` | None | YES | Upload org compliance config |
| 5 | POST | `/v1/{org_id}/investigate` | None | YES | LLM Q&A on stored violation |
| 6 | POST | `/agents/issue-key` | None | YES | Issue 30-min one-time key |
| 7 | GET | `/agents` | None | YES | List agents (optional org filter) |
| 8 | GET | `/agents/{agent_id}` | None | YES | Single agent detail |
| 9 | POST | `/agents/{agent_id}/revoke` | None | YES | Revoke agent permanently |
| 10 | POST | `/agent/register` | Key-based | YES | Agent bootstrap (consumes one-time key) |
| 11 | POST | `/agent/heartbeat` | Agent token ✓ | YES | Update last-seen timestamp |
| 12 | GET | `/api/{org_id}/verdicts` | None | YES | Filtered verdict query |
| 13 | GET | `/api/{org_id}/verdicts/{verdict_id}` | None | YES | Single verdict by UUID |
| 14 | GET | `/api/{org_id}/violations/{violation_id}` | None | YES | Lookup by per-tenant seq # |
| 15 | POST | `/api/{org_id}/verdicts/{verdict_id}/status` | None | YES | Update remediation status |
| 16 | GET | `/api/{org_id}/verify-chain` | None | YES | Verify SHA-256 hash chain |
| 17 | GET | `/api/{org_id}/stats` | None | YES | Aggregate counts by rule/severity/status |
| 18 | WS | `/ws/{org_id}` | None | YES | Live feed (per-org room) |
| 19 | GET | `/api/license` | None | YES | License metadata for dashboard badge |
| 20 | GET | `/` | None | YES | Serve dashboard HTML |

**Critical observation:** Only endpoints 1 and 11 require authentication. All admin routes (agent revocation, org config upload, verdict queries) are unauthenticated.

---

## 6. Database / Data Model Audit

### `evidence.db` — Compliance Ledger

**Technology:** SQLite (single file, append-only writes)

**Table: `evidence`**

| Column | Type | Purpose | Notes |
|--------|------|---------|-------|
| `row_index` | INTEGER PK AUTOINCREMENT | Global sequence | Never used as identifier; internal ordering |
| `verdict_id` | TEXT UNIQUE | UUID (from Verdict) | Primary lookup key |
| `payload_json` | TEXT | Serialized immutable verdict data | Hash-protected |
| `row_hash` | TEXT | SHA-256(payload_json + prev_hash) | Chain integrity |
| `previous_hash` | TEXT | Chain link | GENESIS_HASH for first row per tenant |
| `remediation_status` | TEXT | OPEN/ACKNOWLEDGED/RESOLVED | MUTABLE (outside hash) |
| `remediation_updated_at` | TEXT | Timestamp of last status change | MUTABLE |
| `appended_at` | TEXT | ISO 8601 store time | Immutable |
| `tenant_id` | TEXT (indexed) | Org isolation | Added Phase 5+6 |
| `violation_id` | INTEGER | Per-tenant sequential number | Unique per (tenant_id, violation_id) |

**`payload_json` contents:** tenant_id, verdict_id, event_id, rule_id, severity, source, source_system, **field name** (NOT matched value), timestamp, matched_registry_entry, breach_notification_candidate, explanation, section_cited, confidence, used_fallback.

**Where raw PII is stored:** Nowhere. `matched_text` is intentionally excluded from the Verdict schema.

### `agents.db` — Agent Registry

**Table: `registration_keys`**

| Column | Purpose |
|--------|---------|
| `key_id` | UUID primary key |
| `org_id` | Which org this key is for |
| `key_hash` | SHA-256(plaintext_key) — plaintext never stored |
| `created_at`, `expires_at` | 30-minute TTL |
| `used`, `used_at` | Single-use enforcement |

**Table: `agents`**

| Column | Purpose |
|--------|---------|
| `agent_id` | "VERITAS-AGENT-XXXXXX" format |
| `org_id` | Which org this agent belongs to |
| `token_hash` | SHA-256(plaintext_token) — plaintext never stored |
| `status` | ACTIVE / REVOKED |
| `source_label` | Human label from config |
| `last_heartbeat_at` | Updated every 30s |
| `events_received` | Monotonic counter |

### Org Config Storage

**Format:** YAML files at `org_config/configs/{org_id}/{ISO8601_timestamp}.yaml`
**Versioning:** Each upload creates a new file (never overwrites); latest = lexicographically greatest filename
**Schema:** OrgField (field_name, pii_category, declared_purpose, consent_scope, retention_days, source_system), OrgIdentifier (name, pattern, validator), LinkageRule (fields, risk)

---

## 7. Data Ingestion / Breach Pipeline

### How Ingestion Works (Production Mode)

1. **Veritas Agent** (separate Docker container) tails configured log files or Docker container stdout
2. Each log line is queued in-memory (max 1,000 events)
3. Forwarding worker POSTs to `POST /v1/{org_id}/events` with Bearer token auth
4. FastAPI route validates agent token, constructs `Event` object
5. `detect_event(event)` — Presidio + spaCy + custom recognizers scan all fields and raw_snippet
6. `evaluate_event(detected)` — rules engine produces zero or more Verdicts
7. `build_deferred_explanation(verdict)` — deterministic template (no LLM)
8. `evidence_store.append(explained_verdict)` — SQLite write, hash chain update, violation_id assigned
9. `publish_live_feed(payload)` — WebSocket broadcast to org's connected clients

### Pipeline Characteristics

| Property | Value |
|----------|-------|
| Synchronous/async | Synchronous within HTTP request |
| Duplicate handling | `verdict_id` has UNIQUE constraint; duplicate append silently skipped |
| Idempotent | YES for same event (same verdict_id) |
| Pipeline state persisted | YES (evidence.db) |
| Error handling | Per-event try/catch; single failure doesn't stop pipeline |
| Retry on ingestion failure | Agent-side (exponential backoff 1s→30s) |
| Live feed on failure | Best-effort; failure logged but not fatal |

### Status: Fully Functional

No simulated/mocked/stubbed components in the core ingestion path. All detection, rule evaluation, storage, and broadcasting is real.

---

## 8. Live Feed Audit

**Mechanism:** WebSocket (full-duplex, persistent)  
**Endpoint:** `ws://server:8000/ws/{org_id}`  
**Org isolation:** Per-org rooms; org A clients never receive org B verdicts  
**Reconnect:** Client-side 3-second retry on disconnect  

**Data per live event:**
- verdict_id, rule_id, severity, field (name only), source_system
- timestamp, breach_notification_candidate, remediation_status
- explanation (template text), section_cited (statute reference)
- confidence, used_fallback

**Raw PII in live events:** NO — matched_text explicitly excluded from Verdict schema.

**Persistence:** Live feed events are NOT separately persisted. The evidence.db row is the durable record.

**On disconnect:** Client removed from room; next broadcast skips. Events during disconnect are NOT replayed.

**Status:** Fully functional, production-grade tenant isolation.

---

## 9. Organization Management

| Question | Answer |
|----------|--------|
| How are orgs created? | Via `POST /v1/orgs/{org_id}/config` (API) — also exposed in dashboard modal |
| How are orgs stored? | YAML files: `org_config/configs/{org_id}/{timestamp}.yaml` |
| Are users scoped to orgs? | No — no user concept at all |
| Multi-tenancy? | YES — enforced at every storage and query layer |
| Org isolation? | YES — Evidence Store, Live Feed, Agent auth all scoped by org_id |
| Org admin concept? | NO |
| Multiple ingestion sources per org? | YES — multiple agents with different source_systems |
| Frontend org creation? | YES — Add Organization modal with full form |
| Auth on org config upload? | NO — any client can upload/modify org configs |

**Seed orgs bundled:** blinkit (e-commerce), edtech_co (education), acme_bank (banking) — 3 reference configurations for demos.

---

## 10. Authentication, Authorization & Access Control

### What Exists

**Agent authentication (strong):**
- Bearer token issued at registration
- Stored as SHA-256 hash (plaintext never persisted)
- Validates: token exists, agent ACTIVE, agent.org_id matches URL org_id
- Applied to: `/v1/{org_id}/events` and `/agent/heartbeat` only

**License enforcement (platform-level):**
- RSA-PSS signature checked on startup
- Machine fingerprint optional binding
- Hard gate: exits if invalid

**Org-level data isolation (strong):**
- Every Evidence Store query requires tenant_id
- WebSocket rooms scoped by org_id
- Agent auth enforces cross-org restriction

### What Does NOT Exist

| Missing | Severity |
|---------|---------|
| Human user login/session/JWT | Critical for production multi-user |
| RBAC / role system | High |
| Auth on admin API routes (revoke, config upload, dashboard queries) | Critical |
| API rate limiting | Medium |
| CSRF protection | Medium (no session to protect) |
| Secrets management (keys in plain files) | Medium |

### Security Findings

| Finding | Risk | File |
|---------|------|------|
| Admin routes completely open (no auth) | CRITICAL — anyone on network can revoke agents, upload configs | `api/agents.py`, `api/integration.py` |
| Dashboard accessible without login | HIGH — any network user sees all org data | `dashboard/server.py` |
| Org selector is client-side localStorage | HIGH — switching org_id in browser switches data view | `dashboard/index.html` |
| RSA private key in `tools/private_key.pem` | HIGH — must never be committed to git (excluded by .gitignore) | `tools/` |
| License not re-validated per request | Low — startup gate sufficient for single-process model | `license.py` |

---

## 11. PII / Sensitive Data Detection

### Detection Methods (Hybrid)

| Method | Used for | Provider |
|--------|---------|---------|
| Regex (pattern matching) | Aadhaar, PAN, Indian phone | Custom `PatternRecognizer` subclasses |
| NLP Named Entity Recognition | PERSON (names) | spaCy `en_core_web_lg` via Presidio |
| Regex (Presidio built-in) | EMAIL_ADDRESS, PHONE_NUMBER | Presidio default recognizers |
| Confidence scoring | All types | Presidio scoring framework |
| Context word boosting | Aadhaar, PAN, phone | Presidio context enhancement |
| Checksum validation | PAN (structural), Aadhaar (Verhoeff, via validators.py) | Custom validators |

### Supported PII Types

| Type | Presidio Entity ID | Detection Method | Confidence |
|------|-------------------|-----------------|------------|
| Name | `PERSON` | spaCy NER (en_core_web_lg) | 0.85 |
| Email | `EMAIL_ADDRESS` | Presidio regex | 0.85 |
| Generic phone | `PHONE_NUMBER` | Presidio regex | 0.75 |
| Aadhaar (spaced 4-4-4) | `IN_AADHAAR` | Custom regex | 0.75 |
| Aadhaar (unspaced 12-digit) | `IN_AADHAAR` | Custom regex | 0.40 |
| PAN card | `IN_PAN` | Custom regex | 0.85 |
| Indian mobile (10-digit) | `IN_PHONE` | Custom regex | 0.75 |
| Indian mobile (+91 prefix) | `IN_PHONE` | Custom regex | 0.90 |

**NOT currently supported:** Passport, DOB, address (detected as PERSON false-positive via NER), financial account numbers, health information, biometric data.

**Known limitation:** Unspaced 12-digit Aadhaar (confidence 0.40) can collide with order IDs. Verhoeff checksum validation exists in `validators.py` but is not integrated into the real-time detection path.

---

## 12. Data Masking / Redaction

**Where masking happens:** API responses for the `/scan` endpoint only.

**Method:** Substring replacement. Sorted by match length (longest first) to prevent nested replacement issues.

**Mask format:** `[{CATEGORY}_REDACTED]` — e.g., `[PHONE_REDACTED]`, `[AADHAAR_REDACTED]`, `[EMAIL_REDACTED]`

**What is masked:**
- `masked_text` in `/scan` response — free text with PII replaced
- `masked_fields` in `/scan` response — structured fields with PII values replaced

**What is NOT masked:**
- Evidence Store storage — raw PII is never written (matched_text excluded from schema)
- Dashboard displays — Evidence Store contains only field names, not values
- Live feed events — no matched_text in payload
- LLM investigation calls — field names only, not values
- Application logs — detection engine does not log matched_text

**Masking reversibility:** Not reversible (no tokenization or pseudonymization). Masking is output-only.

**Raw PII exposure risk assessment:**
- Evidence Store: No exposure (field names only stored)
- API responses: No exposure except intentional masked output in `/scan`
- Dashboard: No exposure
- LLM calls: No exposure (field names + statute text only)
- Application logs: Minimal risk (field names may appear in INFO logs, not values)

---

## 13. External Network Dependencies

| Service | Data Sent | Purpose | Mandatory | Can Work Without |
|---------|-----------|---------|-----------|-----------------|
| OpenAI API | Rule type, field name, statute text (no PII) | Natural language investigation explanations | NO | YES — deterministic template fallback |
| Anthropic API | Same as above | Alternative LLM provider | NO | YES — same fallback |
| Google Fonts CDN | HTTP GET (no data) | Geist/Geist Mono font loading | NO | YES — system font fallback |
| jsDelivr CDN | HTTP GET (no data) | jsPDF library for PDF export | NO | YES — PDF export fails, rest works |
| GitHub Actions | Source code | macOS binary build CI | Build-time only | N/A |
| Vercel | License portal source code | License generation UI | Admin tool only | N/A |

**Conclusion:** Veritas can operate completely offline (no internet) with no loss of core compliance functionality. Only PDF font quality and LLM investigation degrade when offline.

---

## 14. AI / LLM Components

### Verdict Explanation (Automatic Path)
- **Current behavior:** Deterministic template only (LLM call removed from automatic path)
- **Why removed:** Unbounded cost at traffic volume; template is sufficient for detection/storage
- **Template location:** `llm_explainer/explainer.py:_build_fallback()`

### Breach Investigation (On-Demand)
- **Provider:** OpenAI (gpt-4o-mini default) or Anthropic (claude-sonnet-4-5)
- **When called:** Only on `POST /v1/{org_id}/investigate` request
- **Data sent:** Stored verdict metadata (rule_id, field, severity, timestamp), static statute text, aggregate violation counts for org — NO raw PII
- **Data NOT sent:** Matched PII values, other tenants' data, raw log lines
- **Mandatory:** NO — fallback to stored template explanation if key missing or API fails
- **Guardrails:**
  - `temperature=0` for determinism
  - Grounding check: verifies answer cites correct statute section
  - Fallback on any failure (never raises)
  - One-way: LLM output annotates, never writes back to evidence store
- **Local alternative:** None currently. Could be replaced with a local Ollama/LLaMA model via environment variable change.

---

## 15. Logging, Telemetry & Auditability

### Application Logs

**Format:** `%(asctime)s %(levelname)s %(name)s: %(message)s`  
**Output:** stdout (captured by systemd journal or terminal)  
**File:** `pipeline.log` (created by some startup flows, but primarily stdout)

**What is logged:**
- License validation result (org, tier, expiry)
- Server startup/shutdown
- Rule engine: verdict count per event (field names only, not values)
- WebSocket disconnect events
- LLM fallback warnings
- Evidence store append failures (duplicates)

**What is NOT logged:**
- Matched PII values (deliberately excluded)
- Raw log snippets from agents
- Agent tokens or registration keys
- User actions (no user concept)

### Audit Logs
No dedicated audit log table. The evidence.db itself serves as the audit ledger (append-only, hash-chained, tamper-evident).

### Telemetry / Analytics
None. No third-party analytics, error reporting, or telemetry.

---

## 16. File Handling & Storage

| Format | Support | How Handled |
|--------|---------|-------------|
| Log files (any text) | YES (via Agent) | Agent tails line-by-line, forwards as raw_snippet |
| Docker container logs | YES (via Agent) | Docker SDK streams stdout/stderr |
| JSON payloads | YES (via /scan or /events fields dict) | Parsed as structured fields |
| YAML org configs | YES (upload via API) | Validated → written as versioned YAML file |
| PDF reports | YES (export via dashboard) | Client-side jsPDF generation, no server upload |
| CSV, SQL dumps, ZIP | NO | Not supported |

**Temporary files:** None created by the core product.  
**File retention:** Org configs persist indefinitely (versioned). Evidence.db is append-only (no deletion).  
**File size limits:** `raw_snippet` max 100,000 chars; `fields` max 50 keys × 10,000 chars each; HTTP body max 256KB.

---

## 17. Current Deployment Model

### Development (any OS with Python)
```bash
cd dpdpa-agent
pip install -r requirements.txt
python -m spacy download en_core_web_lg
# Place veritas.vlic in dpdpa-agent/
python run_pipeline.py
# Open http://localhost:8000
```

### Production — Linux/Raspberry Pi
```bash
sudo bash dpdpa-agent/deploy/install-linux.sh
# Installs to /opt/veritas/, creates systemd service
# sudo reboot → auto-starts
```

### Production — macOS
```bash
sudo bash dpdpa-agent/deploy/install-mac.sh
# Installs to /Library/Application Support/Veritas/
# Creates launchd daemon → auto-starts on boot
```

### Production — Windows
```
VeritasSetup-1.0.0.exe  (double-click)
→ Standard installer wizard
→ Select .vlic file
→ Installs to C:\Program Files\Veritas\
→ Registers Windows Service (auto-start)
```

### Can it run completely offline?
YES — for all core compliance functionality. Internet only needed for: LLM investigation (optional), Google Fonts (cosmetic), jsPDF (PDF export only).

---

## 18. Testing & Reliability

### Test Inventory

| Test File | Count | What It Covers |
|-----------|-------|----------------|
| `schemas/test_schemas.py` | 23 | Event/Verdict schema validation, immutability |
| `registry/test_registry.py` | 25 | Registry entry lookups, seeded violation checks |
| `ingestion/test_ingestion.py` | 21 | Ingestion pipeline, event normalization |
| `detection/test_detection.py` | 31 | PII entity detection, recognizer accuracy |
| `detection/test_phase2_validation.py` | 4 | Aadhaar/PAN checksum validation wiring |
| `rules/test_rule_engine.py` | 27 | All 4 rules, short-circuit logic, severity mapping |
| `rules/test_phase4_generalization.py` | 7 | Multi-tenant rule evaluation |
| `evidence_store/test_evidence_store.py` | 19 | Append-only, hash chain, status transitions |
| `evidence_store/test_multi_tenant.py` | 16 | Tenant isolation, per-tenant violation IDs |
| `api/test_integration.py` | 19 | REST endpoints, cross-tenant isolation at HTTP level |
| `api/test_agents.py` | 27 | Agent auth, registration, revocation, events endpoint |
| `agent_store/test_agent_store.py` | 32 | Key issuance/consumption, token validation, fingerprint |
| `dashboard/test_live_feed.py` | 6 | WebSocket room scoping, tenant isolation |
| `org_config/test_org_config.py` | 34 | Config validation, YAML serialization |
| `test_investigation.py` | 17 | Investigation Q&A, reference parsing |
| `test_validators.py` | 16 | Aadhaar Verhoeff, PAN structural validation |
| **TOTAL** | **337** | All phases |

**Frontend tests:** None (plain HTML/JS, no test framework).  
**E2E tests:** None.  
**Security tests:** Partial — agent auth tested, but no adversarial tests.

### Critical Gaps in Test Coverage
- No tests for admin route authentication bypass (because there is no auth to test)
- No tests for PDF export
- No tests for LLM call with real API (mocked in tests)
- No tests for machine fingerprint binding
- No tests for PyInstaller bundle behavior

---

## 19. Current Bugs / Technical Debt

### Critical

| # | Location | Problem | Why It Matters |
|---|----------|---------|---------------|
| C1 | All admin API routes | No authentication — anyone on the network can revoke agents, upload org configs, read all verdicts | Any attacker on the same network can disrupt operations or exfiltrate compliance data |
| C2 | `dashboard/server.py` | Dashboard has no login — any browser on the network can access any org's data | Org data isolation relies on URL parameter, not identity |

### High

| # | Location | Problem | Why It Matters |
|---|----------|---------|---------------|
| H1 | `detection/recognizers.py` | Unspaced 12-digit Aadhaar pattern (confidence 0.40) collides with order IDs like "BLK-583927" if they happen to be 12 digits | False positives produce noise in the violation feed |
| H2 | `evidence_store/store.py` | SQLite threading.Lock() — adequate for single process but blocks under concurrent writes | Won't scale beyond one process; blocks all writes during a slow append |
| H3 | Google Fonts CDN | Dashboard loads fonts from internet — if offline, fonts degrade silently | For air-gapped deployments, font loading either fails or delays |
| H4 | jsPDF CDN | PDF export fails completely if CDN unreachable | Not critical but unexpectedly breaks export |

### Medium

| # | Location | Problem | Why It Matters |
|---|----------|---------|---------------|
| M1 | `investigation.py` | Stateless conversation model — caller re-sends full history each turn | Conversation history size grows unboundedly for long investigations |
| M2 | `rules/linkage.py` | LINKAGE_001 always produces MEDIUM severity (hardcoded) | Cannot distinguish high-risk linkage (name+aadhaar+DOB) from low-risk |
| M3 | `org_config/store.py` | No API to retrieve previous org config versions | Config history exists on disk but is inaccessible via API |
| M4 | `run_pipeline.py` | License re-checked only at startup; expiry during long-running session not caught | Could run with expired license until next restart |
| M5 | `dashboard/index.html` | Org display name mapping is hardcoded (blinkit→"E-Commerce") | New orgs show raw ID unless mapping is added to JS |

### Low

| # | Location | Problem | Why It Matters |
|---|----------|---------|---------------|
| L1 | `masking.py` | Substring replacement fails gracefully but may double-mask overlapping entities | Cosmetic: `[EMAIL_REDACTED]` is still masked, just under wrong category |
| L2 | Various | `ingestion/` module still exists but is unused in production | Dead code that could confuse future developers |
| L3 | `deployment/install-linux.sh` | Fallback `cp -r` if rsync unavailable may fail to exclude large build artifacts | Could bloat the installation |

---

## 20. Implemented vs Planned Matrix

| Capability | Implemented | Partial | Mocked | Missing | Notes |
|-----------|-------------|---------|--------|---------|-------|
| Organization creation (API) | ✅ | | | | `POST /v1/orgs/{org_id}/config` |
| Organization creation (UI) | ✅ | | | | Full form modal in dashboard |
| Organization selection | ✅ | | | | Dropdown, localStorage persistence |
| Breach detection (EXPOSURE_001) | ✅ | | | | Raw PII in logs |
| Breach detection (PURPOSE_001) | ✅ | | | | PII beyond declared purpose |
| Breach detection (RETENTION_001) | ✅ | | | | Data past retention window |
| Breach detection (LINKAGE_001) | ✅ | | | | Quasi-identifier combinations |
| Real-time live feed | ✅ | | | | WebSocket, per-org rooms |
| PII detection (Indian) | ✅ | | | | Aadhaar, PAN, Indian mobile |
| PII detection (general) | ✅ | | | | Name, email, phone via spaCy+Presidio |
| Data masking (API responses) | ✅ | | | | `/scan` endpoint only |
| Data masking (storage) | ✅ | | | | Raw PII never written to DB |
| Investigation (LLM) | ✅ | | | | On-demand via `/investigate` |
| Investigation (fallback) | ✅ | | | | Deterministic template |
| Assignment / workflow | | | | ❌ | No assignment to users/teams |
| Risk classification | ✅ | | | | HIGH/MEDIUM/LOW per entity type |
| Authentication (Agents) | ✅ | | | | Bearer token, RSA validation |
| Authentication (Human users) | | | | ❌ | No login, no session |
| Authorization (RBAC) | | | | ❌ | No roles, no permissions |
| Audit logging (compliance verdicts) | ✅ | | | | Hash-chained evidence store |
| Audit logging (user actions) | | | | ❌ | No user concept |
| Reporting (PDF export) | ✅ | | | | Client-side jsPDF |
| Reporting (CSV/scheduled) | | | | ❌ | Not implemented |
| Local deployment | ✅ | | | | All three platforms |
| Offline operation | ✅ | | | | Core functions fully offline |
| License enforcement | ✅ | | | | RSA-PSS, machine fingerprint |
| Multi-tenancy | ✅ | | | | Per-tenant DB chains, WS rooms |
| Agent telemetry forwarding | ✅ | | | | File + Docker log tail |
| Kubernetes agent deployment | ✅ | | | | DaemonSet + Deployment manifests |
| Breach notification | | ✅ | | | `breach_notification_candidate` flag set, no actual notification sent |
| Data deletion / right to forget | | | | ❌ | Evidence store is append-only |
| Encryption at rest | | | | ❌ | SQLite files unencrypted |
| Encryption in transit | | ✅ | | | HTTPS if behind reverse proxy; HTTP by default |

---

## 21. Data Privacy Readiness Baseline

### Currently Implemented

| Control | Status | Notes |
|---------|--------|-------|
| Data minimisation | ✅ | Only field names stored; raw PII not persisted |
| Purpose limitation | ✅ | PURPOSE_001 rule enforces declared purposes |
| Org isolation | ✅ | Full tenant scoping at every layer |
| PII masking in API output | ✅ | `/scan` returns masked text |
| Tamper-evident audit trail | ✅ | SHA-256 hash chain per org |
| Agent token authentication | ✅ | SHA-256 hashed tokens, no plaintext storage |
| License-based access control | ✅ | RSA-PSS signed, machine-bound optional |
| LLM data minimisation | ✅ | Only field names + statute text sent to LLM |
| Offline operation | ✅ | No cloud dependency for core compliance |

### Partially Implemented

| Control | Status | Notes |
|---------|--------|-------|
| Breach notification | Partial | Flag set (`breach_notification_candidate`), but no actual notification workflow |
| Encryption in transit | Partial | HTTP by default; HTTPS requires reverse proxy setup |
| Admin authentication | Partial | Agent routes protected; admin dashboard routes open |

### Not Implemented

| Control | Gap | Risk |
|---------|-----|------|
| Encryption at rest | SQLite files unencrypted on disk | HIGH — physical access to server exposes compliance data |
| Human user authentication | No login/session | HIGH — any network user can access all org data |
| Role-based access control | No roles | HIGH — auditor and admin have identical access |
| Data retention / deletion | Append-only only | MEDIUM — no mechanism to enforce org's own retention on evidence |
| Backup security | Not specified | MEDIUM — backup files would expose same unencrypted DB |
| Secrets management | Keys in .pem files | MEDIUM — private key must be manually protected |
| Access logs | No HTTP access logging | MEDIUM — cannot audit who queried what |

---

## 22. Requirements for Future On-Premise Architecture

Based on the current implementation, the following identifies **what would need to change** for a full on-premise architecture. No design is proposed here — only constraints.

### Components That Already Run On-Premise (No Change Needed)
- Core Python compliance engine (detection, rules, evidence store)
- FastAPI server and WebSocket dashboard
- SQLite databases (already local file)
- YAML org configs (already local file)
- Veritas Agent (Docker container)
- Launcher and service management

### Components That Need Change

| Component | Current State | Migration Need |
|-----------|--------------|----------------|
| Human user authentication | None | Requires login system (OAuth, LDAP, or local users) |
| Admin API authorization | None | Requires auth middleware on all non-agent routes |
| Encryption at rest | None | SQLite encryption or full-disk encryption requirement |
| LLM integration | External API | Must offer local model alternative (Ollama, local Llama) for air-gapped |
| Fonts/jsPDF | CDN | Must be bundled locally for air-gapped deployments |
| License portal | Vercel deployment | Must work offline or via org-local network |
| Audit log access | No dedicated API | Requires access log API for org administrators |
| Multi-user support | None | Requires user management, session management |
| Data deletion | Append-only only | Requires secure deletion API for right-to-erasure |

### Architectural Constraints
- SQLite single-writer model limits concurrent agent throughput; PostgreSQL migration needed at scale
- WebSocket broadcaster runs in same process as API; high event volume could starve API threads
- No horizontal scaling — single-process model; load balancer not supported without shared DB

---

## 23. Critical Questions We Must Answer Before Redesign

### Deployment Environment
1. Single workstation per client, or shared server per client org?
2. Is the deployment environment within the client's own data center, or hosted in a private cloud they control?
3. Should Veritas support completely air-gapped deployments (no internet at all)?
4. Should Veritas support multi-site deployments (one org, multiple offices)?

### Users and Roles
5. Who operates the Veritas instance — a Veritas employee, the client's IT team, or the client's compliance officer?
6. What roles must exist? (e.g., admin, auditor, read-only viewer, agent manager)
7. Should different roles see different levels of masking (e.g., compliance officer sees raw PII, auditor sees only metadata)?
8. Should the dashboard require multi-factor authentication?

### Data and Privacy
9. Should raw PII ever be viewable by any role? If so, in what context and with what controls?
10. Should masking be reversible (tokenization/pseudonymization) or irreversible (redaction)?
11. Where should encryption keys live? (Hardware Security Module, client-managed KMS, file-based?)
12. What are the expected data retention and deletion requirements for compliance evidence?
13. Is client data ever permitted to be sent to a Veritas-operated cloud service for any reason?

### Sources and Ingestion
14. What breach-data sources will clients actually have? (Log files, APIs, databases, SIEM exports?)
15. Should Veritas ingest from external breach notification feeds (CERT-In, HIBP, etc.) or only internal application telemetry?
16. Should file-based ingestion support batch processing (upload and scan a CSV dump) or only real-time streaming?
17. Should the Veritas Agent support syslog, Kafka, or other standard log transport protocols?

### Multi-tenancy and Isolation
18. Does each client organisation get an isolated Veritas instance (dedicated VM/server), or a shared multi-tenant installation?
19. If shared: what guarantees must exist between tenant data? Database-level? OS-level? Hardware-level?

### AI and LLM
20. Is LLM-powered investigation a required feature or optional? What happens if a client's policy prohibits external API calls?
21. Should Veritas support a local LLM option (e.g., Llama 3 via Ollama)? What hardware requirements would this impose?
22. If a local LLM is used, who is responsible for updates and security patches to the model?

### Updates and Licensing
23. How will software updates be delivered to an on-premise installation? (Manual download, signed package, auto-update agent?)
24. Should the license portal (currently on Vercel) have an on-premise alternative?
25. Is telemetry about the installation (version, uptime, violation counts) permitted? Who sees it?

---

## 24. Final Deliverable

### A. Current Veritas Architecture

A single-process Python application serving a compliance monitoring system. All computation, storage, and serving happens locally within the client's infrastructure. The Veritas Agent (separate Docker container) forwards telemetry from production services to the Python server. The dashboard is a plain HTML/JS single-page application served by the same Python process. Data is stored in SQLite files and YAML configs on the local filesystem. LLM investigation is optional and sends no raw PII externally. The system is fully functional offline for all core compliance operations.

```
[Production Services] → [Veritas Agent] → [FastAPI Server]
                                              ├── PII Detection (local spaCy)
                                              ├── Rules Engine (local)
                                              ├── Evidence Store (local SQLite)
                                              └── Dashboard (local HTML)
```

### B. What Already Works

- PII detection (Aadhaar, PAN, Indian mobile, name, email, generic phone) — fully functional
- Three DPDPA compliance rules (EXPOSURE_001, PURPOSE_001, RETENTION_001) — fully functional
- Tamper-evident evidence store with SHA-256 hash chains — fully functional
- Multi-tenant data isolation at every layer — fully functional
- Agent registration, authentication, and revocation — fully functional
- Real-time WebSocket live feed (per-org rooms) — fully functional
- Investigation Q&A with LLM guardrails — fully functional
- Remediation workflow (OPEN → ACKNOWLEDGED → RESOLVED) — fully functional
- Cryptographic chain verification — fully functional
- PDF audit report export — fully functional
- RSA-PSS license system with machine fingerprinting — fully functional
- Cross-platform deployment (Windows, Linux, macOS) — fully functional
- 337 automated tests — all passing

### C. What Is Broken / Incomplete

- **No human user authentication** — dashboard is open to anyone on the network
- **No RBAC** — all users have identical full access to all features
- **No auth on admin routes** — agent revocation, org config upload, verdict queries are unauthenticated
- **No encryption at rest** — SQLite databases stored in plaintext
- **No breach notification workflow** — flag set but no actual notification
- **No data deletion mechanism** — evidence store is append-only with no deletion
- **No access logging** — cannot audit who queried what
- **No multi-user support** — no user concept exists
- **Unspaced Aadhaar false positives** — low-confidence 12-digit pattern can match numeric order IDs

### D. Privacy & Security Gaps

| Gap | Risk Level | Impact |
|-----|-----------|--------|
| No dashboard authentication | CRITICAL | Any network user sees all org compliance data |
| Admin APIs unauthenticated | CRITICAL | Attacker can revoke agents, modify org policies |
| No encryption at rest | HIGH | Physical server access exposes all compliance data |
| No access logging | HIGH | Cannot audit who queried sensitive compliance data |
| No RBAC | HIGH | Auditor and admin have identical capabilities |
| LLM calls external (optional) | LOW | Field names sent to OpenAI; no raw PII; fully optional |
| Fonts/jsPDF from CDN | MINIMAL | No data sent; cosmetic/functional degradation offline |

### E. Migration Starting Point

**Can be retained as-is:**
- Core detection/rules/evidence pipeline (Python, local, no cloud deps)
- SQLite evidence store (may need encryption added, not replacement)
- YAML org config storage (sufficient for current scale)
- FastAPI server structure (only auth middleware needs adding)
- Veritas Agent (Docker/K8s, already production-ready)
- Org isolation model (already enforced at every layer)

**Will likely need architectural change:**
- Human authentication layer (requires adding session/JWT/OAuth middleware)
- Admin route protection (requires auth middleware on all non-agent routes)
- Encryption at rest (SQLite encrypted extension or full-disk encryption)
- LLM local alternative (Ollama/local model for air-gapped clients)
- CDN dependencies (must be bundled locally for offline operation)
- SQLite → PostgreSQL migration (for high-volume multi-agent deployments)
- Single-process → separated processes (if horizontal scaling needed)
