# Veritas Finals — Enterprise-Deployable Compliance Platform & Deployable Agent

*A restructured, explained version of the finals implementation plan*

---

## 1. The Big Picture

**What you're building:** you're turning Veritas — currently a software-only DPDPA compliance pipeline — into an **enterprise-deployable software product** that organisations run inside their own infrastructure: a VM, a server, a Kubernetes cluster, or an optional physical reference appliance (currently prototyped on a Raspberry Pi). A small companion program, the **Veritas Agent**, sits inside the organisation's production systems and feeds telemetry back to wherever Veritas is running.

**Why this split matters:** it keeps "smart" and "dumb" cleanly separated.

| Component | Role | Lives where |
|---|---|---|
| **Veritas Agent** | Reads logs/telemetry, authenticates, forwards events. Makes *no* compliance decisions. | Inside the org's production environment |
| **Veritas Runtime / Deployment** | Detects PII, evaluates DPDPA rules, seals evidence, serves the dashboard, runs investigations. | Anywhere it's installed — VM, server, Kubernetes cluster, or the optional physical Veritas Appliance (reference hardware: Raspberry Pi) |

**The demo experience you're aiming for:**

```
Veritas deployment starts (e.g. the reference Pi appliance powers on,
or a VM/server install starts) → Admin opens browser
→ Configures organisation → Registers Agent → Deploys Agent
→ Production telemetry reaches Veritas → Violations detected live
→ Evidence sealed → Auditor investigates
```

Your existing pipeline (**Telemetry → PII Detection → Rule Engine → Evidence Store → Dashboard → Investigation**) is *not* being rebuilt. The finals effort is almost entirely about **deployment, onboarding, and connecting the Agent to that pipeline** — not new compliance logic.

---

## 2. Target Architecture

```
                    ORGANISATION PRODUCTION ENVIRONMENT

  Application / Services
           │
           ▼
  Logs / API Telemetry / Container Logs
           │
           ▼
  ┌─────────────────────────┐
  │      VERITAS AGENT       │
  │  Agent ID                │
  │  Auth Token               │
  │  Source Configuration     │
  │  Telemetry Forwarder      │
  └────────────┬──────────────┘
               │ authenticated telemetry
               ▼
  ┌──────────────────────────────────────────┐
  │       VERITAS RUNTIME / DEPLOYMENT         │
  │  (VM / Server / Kubernetes / Physical      │
  │   Appliance — e.g. Raspberry Pi)            │
  │                                              │
  │  Agent / API Gateway                         │
  │        │                                     │
  │        ▼                                     │
  │  PII Detection → DPDPA Rule Engine           │
  │        │                                     │
  │        ▼                                     │
  │  Evidence Store + Hash Chain                 │
  │        │                                     │
  │        ▼                                     │
  │  Dashboard + Investigation                   │
  └──────────────────────┬────────────────────────┘
                          │
                          ▼
                    Admin Browser
```

The key design decision embedded here: **the Veritas deployment can't reach into a remote server and read an arbitrary file.** The Agent exists specifically to bridge that gap — it's deployed where the data already lives, and it pushes rather than Veritas pulling. This holds regardless of what Veritas itself is running on.

---

## 3. Segment A — The Veritas Agent

### 3.1 Purpose
A minimal, deployable bridge component. Its entire job: read telemetry → authenticate → forward it. Nothing more.

### 3.2 What it does
- Reads configured log sources (files, Docker/container logs)
- Optionally exposes a local HTTP endpoint to receive app telemetry directly
- Tags every event with its unique Agent ID
- Authenticates to the appliance with a token/secret
- Forwards events to the appliance
- Sends heartbeat/health signals
- Retries on temporary connection failure, with bounded local buffering

### 3.3 What it deliberately does *not* do
This boundary is the most important design constraint in the whole plan — keep it intact even under demo pressure:
- No DPDPA decision-making
- No PII detection
- No compliance policy storage
- No authoritative evidence storage
- No investigation LLM
- No remediation actions

The appliance stays the sole "trusted intelligence layer." The Agent is deliberately dumb.

### 3.4 Deployment
- **Primary format: Docker container.** Deployed independently of the appliance.
- A native `.exe` installer is explicitly **out of scope** for finals — the target is server/container infrastructure, not desktop.

### 3.5 Agent identity example
Initial config the Agent starts with (before it has an identity):
```
veritas_address: http://192.168.1.50:8000
registration_key: <one-time-key>
```
After successful bootstrap registration, the Agent internally receives and stores:
```
Agent ID
Organisation ID
Authentication Token
Final Event Endpoint
```
Identity is scoped to one organisation — an Agent must never be able to impersonate another org's data.

### 3.6 Registration flow (step by step)
1. Admin opens the Veritas appliance UI → **"Configure Organisation."**
2. Admin creates/selects the organisation (e.g. `acme_bank`).
3. Admin goes to **Data Sources → "Register Agent."** The appliance issues a one-time **registration key** for the org, shown in the UI.
4. Admin deploys the Agent into the production environment with just that registration key (and the appliance's base address) — no Agent ID, auth token, or event endpoint are hardcoded yet.
5. On first start, the Agent calls the appliance's single **bootstrap/registration endpoint**: `POST /agent/register`, presenting the registration key.
6. The appliance authenticates the request and, in the response, returns: **Agent ID**, **authentication token**, **organisation ID**, and the **final telemetry/event endpoint** (e.g. `/v1/acme_bank/events`).
7. The Agent stores these locally and uses the returned event endpoint for **all subsequent telemetry forwarding** — it never needs to be told the endpoint manually.
8. Appliance UI reflects the live connection: `Agent: VERITAS-AGENT-7F82A1 | Status: CONNECTED | Organisation: Acme Bank | Source: order-service`.

This keeps Agent deployment config minimal and lets the appliance be the single source of truth for endpoint/token assignment — an Agent is never handed its full identity up front.

### 3.7 Input sources — build in priority order
| Priority | Source | Example |
|---|---|---|
| 1 (build first) | Log files | `/var/log/order-service/app.log` |
| 2 | Docker container logs | `order-service`, `marketing-service`, `support-service` |
| 3 | HTTP telemetry (local push from app to Agent) | — |

Don't try to support every logging system — one solid reference implementation (file logs) is the priority.

### 3.8 Minimal configuration format
Initial config file (all the Agent needs before it has registered):
```yaml
veritas_address: http://192.168.1.50:8000
registration_key: <one-time-key>

sources:
  - type: docker
    container: order-service
  - type: file
    path: /var/log/marketing-service/app.log
```
After successful bootstrap registration, the Agent internally receives and stores:
```
Agent ID
Organisation ID
Authentication Token
Final Event Endpoint
```
Note: compliance rules never live in this file — they stay entirely on the appliance.

### 3.9 Security checklist
- Agent ID + auth token validation
- Organisation association enforced
- Agent revocation supported
- Input validation + request size limits
- Minimal file permissions
- Bounded buffering, retry/backoff
- Heartbeat-based health reporting
- **Unknown or revoked Agents must be hard-rejected by the appliance** — this is your key security acceptance test.

---

## 4. Segment B — The Veritas Runtime / Deployment Software

### 4.1 Purpose
Take the existing Veritas platform and package it as installable enterprise software that self-starts on whatever infrastructure it's deployed to — a VM, a server, a Kubernetes cluster, or the optional physical reference appliance (Raspberry Pi + Linux). Not a custom OS build, and **not dependent on any specific hardware.**

### 4.2 Reference Hardware Appliance
The Raspberry Pi is **not** the enterprise deployment target — it's the development/reference/edge hardware used to prototype and demo the optional physical form factor. Enterprise customers primarily run Veritas on their own VM/server/Kubernetes infrastructure; the Pi build stays useful for edge or air-gapped scenarios where a small dedicated box is genuinely wanted, and for physical demos.
- Raspberry Pi (current prototype/reference unit)
- Ethernet (preferred for the final demo; Wi-Fi fine during dev)
- Reliable power supply
- Local SD card or SSD storage
- Branded enclosure (cosmetic, for Phase 9)
- Optional status LEDs / small OLED for *status only*, never for configuration

### 4.3 Automatic Startup
Target: Veritas starts automatically on whatever it's deployed to — no manual step required, whether that's a VM booting, a server process starting, a Kubernetes pod scheduling, or the physical reference appliance powering on.
```
Veritas deployment starts (VM boot / service start / Pi power-on)
→ Veritas services start automatically
→ Network/UI available → Admin opens browser → "Welcome to Veritas"
```
Critically: the demo must **never** require manually running something like `python run_pipeline.py` after a restart, regardless of the underlying infrastructure.

### 4.4 Service Layer (deployment-agnostic)
Use the appropriate service manager for the target environment — `systemd` on a VM, server, or the reference Pi appliance, or native restart/scheduling policies on Kubernetes — to manage:
- Veritas API
- Dashboard
- Agent registration/management service
- Background pipeline services
- Evidence store access

Configure: auto-restart on failure, service startup ordering, startup logging, health checks.

**Acceptance test:** restart the underlying deployment (Pi reboot, VM restart, or pod restart) → Veritas UI comes back up on its own.

### 4.5 Network Setup
```
              Organisation Internal Network
              /                          \
    Veritas Deployment                Admin Laptop
(VM / Server / K8s / Appliance)            │
             │                             │
             └─────────────┬───────────────┘
                            │
                    Production Demo Machine
```
Admin reaches the Veritas deployment over the organisation's internal network — e.g. `http://veritas.local` or `http://192.168.1.50:8000` for the reference appliance, or an internal DNS/service name for VM/Kubernetes deployments.

### 4.6 First-boot onboarding screen
```
             VERITAS
Welcome to Veritas.
Your local DPDPA compliance appliance is ready.
       [ Configure Organisation ]
```

### 4.7 Organisation configuration (via UI, not manual YAML editing)
Admin can configure: organisation name/ID, PII fields & categories, declared purpose, consent scope, retention period, source system, linkage rules, custom identifiers. The underlying storage stays the existing YAML/registry model — the UI is just a friendlier layer on top of it.

### 4.8 Agent management UI
A dedicated **"Agents"** section showing, per Agent: ID, organisation, source, status, last heartbeat, events received — with **View** and **Revoke** actions.

### 4.9 Data source view
Shows the admin which production source is connected to which Agent and its live status — reinforcing that the admin configures the *connection* on the appliance, while the Agent is what physically sits next to the logs.

---

## 5. Reusing the Existing Pipeline (don't rebuild this)

```
Veritas Agent → /v1/{org_id}/events → Event → PII Detection → Registry
→ Rule Engine → Verdict → ┬→ Evidence Store → Hash Chain
                            └→ Dashboard
```

- **PII Detection:** Presidio + custom Indian recognizers (Aadhaar, PAN, Indian phone, email/name), field-level attribution, raw snippet detection, dedup, masking — all runs on the appliance.
- **Rule Engine (four families):**
  - `EXPOSURE_001` — raw PII in prohibited channels (e.g. logs)
  - `PURPOSE_001` — PII without a declared purpose/registry entry, or wrong category
  - `RETENTION_001` — data past its configured retention period
  - `LINKAGE_001` — quasi-identifier combinations creating re-identification risk
- **Evidence Store:** append-only, SHA-256 hash-chained, per-tenant chains and sequential violation IDs, `OPEN → ACKNOWLEDGED → RESOLVED` workflow, chain verification. Lives on the Pi's local storage (SQLite now; Postgres is a later scaling step, not a finals task).
- **Investigation Layer:** stays on-demand — the LLM is invoked only when an auditor asks a question (e.g. `@01 What happened?`), and answers stay grounded in the stored violation, explanation, and approved statute snippet. Basic monitoring must keep working even with no LLM key configured.

---

## 6. Dashboard → "Appliance Control Center"

| Section | Contents |
|---|---|
| **Overview** | Org, appliance status, Agent status, events processed, violations (incl. high severity), open remediation |
| **Live Feed** | Real-time violations as they occur |
| **Evidence** | Violation ID, rule, severity, source, timestamp, field, status |
| **Agents** | Registered Agents, connection status, heartbeats, event counts, revoke action |
| **Configuration** | Organisation, PII fields, purpose, consent, retention, linkage rules |
| **Investigation** | Auditor Q&A (e.g. `@01`) + evidence chain verification (`VERIFIED ✓`) |

---

## 7. Simulated Production Environment

Instead of generating fake events *inside* the appliance itself, build a separate demo environment that behaves like a real org:

```
Simulated Organisation → Application Services → Logs/Telemetry
→ Veritas Agent → Raspberry Pi
```

**Suggested Docker layout:**
```
veritas-demo-environment/
├── services/
│   ├── order-service
│   ├── delivery-service
│   ├── marketing-service
│   └── support-service
└── logs/
    ├── order-service.log
    ├── delivery-service.log
    ├── marketing-service.log
    └── support-service.log
```

**Traffic mix:**
- **Normal (90%)**: `order_created`, `delivery_assigned`, `payment_completed`, `customer_updated`
- **Violations (10%, intentional)**: e.g. `[DEBUG] customer phone: 9876543210`, `[DEBUG] customer aadhaar: 2345 6789 0124`, or a marketing payload leaking a raw phone number

A controlled ~90/10 split keeps the demo predictable while still looking like live production traffic.

---

## 8. Full Demo Walkthrough (the script to rehearse)

1. Veritas deployment is started/installed (physically demonstrated on the reference Pi appliance)
2. Veritas starts automatically
3. Admin opens the local Veritas UI
4. Admin creates an organisation
5. Admin configures PII / purpose / consent / retention policies
6. Admin registers an Agent → receives ID + token + endpoint
7. Agent is deployed into simulated production
8. Production app generates telemetry
9. Agent forwards authenticated telemetry
10. Pi detects PII → rule engine evaluates the event
11. Violation appears live on the dashboard
12. Evidence is stored and hash-chained
13. Auditor opens `@01` and asks an investigation question
14. Veritas returns a grounded explanation
15. Evidence chain is verified

This whole sequence should run **without any external Veritas cloud service** for the core compliance workload.

---

## 9. Implementation Roadmap — 10 Phases

| # | Phase | Goal | "Done" test |
|---|---|---|---|
| 1 | **Veritas Deployment Foundation** | Build the core so it can be packaged/deployed independently of hardware | Deployment → Veritas → Browser works reliably (on VM/server and on the reference Pi) |
| 2 | **Automatic Startup** | Behave like a real deployment on any target infrastructure | Restart → Veritas comes up on its own |
| 3 | **Appliance Onboarding** | Remove manual YAML editing from first run | New org configurable entirely via UI |
| 4 | **Agent Registration** | Veritas deployment can securely create/manage Agents | Only registered Agents can send telemetry |
| 5 | **Veritas Agent build** | Lightweight production-side component | Agent independently forwards telemetry to the Veritas deployment |
| 6 | **Simulated Production** | Realistic org environment | Simulated services continuously generate telemetry the Agent can capture |
| 7 | **End-to-End Integration** | Connect the deployment to simulation | A generated violation appears live on the dashboard |
| 8 | **Security Hardening** | Make it credible as an enterprise product | Invalid/revoked Agents can't submit telemetry |
| 9 | **Physical Appliance (Optional Offering)** | Offer the physical hardware form factor as one optional deployment option, not the core product | The physical appliance can be demoed as a legitimate offering without any part of the product depending on it |
| 10 | **Finals Reliability** | Repeatable demo | Full demo runs from a clean start with zero manual repair |

**Suggested sequencing logic:** Phases 1–2 get the core deployment and startup loop solid — on VM/server as well as the reference Pi — before anything else depends on it. Phases 3–4 build the deployment-side onboarding/auth surface. Phase 5 (Agent) and Phase 6 (simulation) can be built in parallel once Phase 4's registration API exists, since both just need a stable `/v1/{org_id}/events` contract. Phase 7 is the integration checkpoint — treat it as your first "full dry run." Phases 8–10 are hardening and polish, and should be the last things touched before finals, not built early.

---

## 10. Explicit Scope Boundaries (do *not* build these)

- A custom operating system
- Custom PCB/hardware
- Touchscreen-based configuration
- A full cloud SaaS platform
- A universal SIEM
- Connectors for every possible logging platform
- Compliance logic inside the Agent
- Automatic data deletion/remediation
- Automatic regulatory notification
- Full enterprise IAM
- A native Windows `.exe` (unless a specific demo requirement forces it)
- **Making the product dependent on Raspberry Pi hardware** — the Pi is an optional reference/edge deployment, never a requirement for Veritas to run

The core deliverable, stated plainly: **an enterprise-deployable Veritas Runtime + lightweight deployable Agent + realistic production simulation + a complete live compliance workflow, with the Raspberry Pi appliance as one optional physical deployment option.**

---

## 11. Final Product Definition

> Veritas is a **licensed enterprise DPDPA compliance software product** that organisations deploy inside their own infrastructure — as a VM image, a server install, a Kubernetes deployment, or an optional physical reference appliance. A lightweight Veritas Agent connects production telemetry to wherever Veritas Runtime is running, while Veritas Core locally performs PII detection, DPDPA policy evaluation, tamper-evident evidence preservation, and breach investigation.

**North-star flow:**
```
PURCHASE LICENSE → INSTALL/DEPLOY VERITAS → WELCOME TO VERITAS
→ CONFIGURE ORGANISATION → REGISTER AGENT → DEPLOY AGENT
→ PRODUCTION TELEMETRY CONNECTED → PII DETECTED → DPDPA VIOLATION
→ EVIDENCE SEALED → LIVE DASHBOARD → AUDITOR INVESTIGATION → CHAIN VERIFIED
```

---

## 12. Enterprise Deployment Model

This is the core architectural evolution: **Veritas is a licensed enterprise software product, not a device.** The same product can be delivered as a licensed software deployment across supported infrastructure:

```
                    VERITAS ENTERPRISE
                           │
             ┌─────────────┼─────────────┐
             ▼             ▼             ▼
        VM Deployment   Server       Kubernetes
             │
       Optional Physical
       Veritas Appliance
             │
        Raspberry Pi
       (prototype/edge)
```

**Terminology used throughout this plan:**
- **Veritas Core** — the compliance intelligence (PII detection, rule engine, evidence store, investigation)
- **Veritas Agent** — the production telemetry bridge
- **Veritas Runtime / Deployment** — the installable enterprise Veritas product, running on any supported infrastructure
- **Physical Veritas Appliance** — an optional hardware form factor for Veritas Runtime
- **Raspberry Pi** — the current prototype/reference hardware for that optional appliance

**The customer experience this is designed around:**

**Purchase License → Receive Veritas Package → Install → Setup Wizard → Register Agents → Monitor**

— not:

**Buy Raspberry Pi → Install Docker → Run Docker Compose.**

The Raspberry Pi build stays exactly as planned technically — it's simply repositioned as *one* deployment target (the physical/edge option) rather than *the* product.

---

## 13. Update & Licensing

Because Veritas is positioned as a licensed enterprise product rather than a one-off device, it needs an update and licensing model from day one — this is what avoids ever having to physically update individual boxes one at a time:

- Enterprise license / tenant activation
- Versioned Veritas releases
- Signed updates
- Update availability checking
- Controlled/staged upgrades
- Rollback capability
- License expiry / renewal
- Deployment/version reporting (which version each customer instance is running)

This is also what makes the physical appliance viable as *one* offering rather than a liability: updates flow the same way regardless of whether a given customer is running a VM, a Kubernetes deployment, or a physical Pi-based unit.
