# VERITAS — ON-PREMISE PRODUCTIZATION & PRODUCTION IMPLEMENTATION PLAN

## 0. Mission

Transform the existing Veritas codebase from a locally executable compliance application into a **production-ready, installable, on-premise privacy monitoring product**.

The final product must allow an organization to deploy Veritas entirely inside its own infrastructure and monitor multiple Linux/Windows production systems through lightweight Veritas Agents.

### Target customer deployment

Example customer:

- 5 Linux production servers
- 2 Windows production servers
- 1 dedicated Linux VM/server running Veritas Server

Target architecture:

```text
                    CUSTOMER PRIVATE NETWORK
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│  Linux Server 01 ── Veritas Agent ──┐                      │
│  Linux Server 02 ── Veritas Agent ──┤                      │
│  Linux Server 03 ── Veritas Agent ──┤                      │
│  Linux Server 04 ── Veritas Agent ──┤                      │
│  Linux Server 05 ── Veritas Agent ──┤                      │
│                                     │                       │
│  Windows Server 01 ─ Veritas Agent ─┤                       │
│  Windows Server 02 ─ Veritas Agent ─┘                       │
│                                     │                       │
│                                     ▼                       │
│                         ┌──────────────────────┐            │
│                         │   VERITAS SERVER     │            │
│                         │                      │            │
│                         │ Runtime / API        │            │
│                         │ PII Detection        │            │
│                         │ Rules Engine         │            │
│                         │ Evidence Ledger      │            │
│                         │ Agent Management     │            │
│                         │ User Authentication  │            │
│                         │ RBAC                 │            │
│                         │ Organization Mgmt    │            │
│                         │ Live Feed            │            │
│                         │ Investigation        │            │
│                         │ Dashboard            │            │
│                         └──────────┬───────────┘            │
│                                    │                        │
│                                    ▼                        │
│                              Admin Browser                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

The customer's raw application data must remain inside their infrastructure.

The long-term preferred data flow is:

```text
Application
    ↓
Veritas Agent
    ↓
Local PII Detection / Minimization
    ↓
Policy Evaluation
    ↓
Raw sensitive values discarded
    ↓
Authenticated + Encrypted Transport
    ↓
Veritas Server
    ↓
Privacy-safe Evidence
    ↓
Dashboard / Audit / Investigation
```

---

# 1. NON-NEGOTIABLE ENGINEERING RULES

Before implementing anything:

### Rule 1 — Audit before modifying

Inspect the entire repository and determine:

- what already exists
- what is partially implemented
- what is production-ready
- what is broken
- what can be reused
- what actually requires architectural change

Do NOT rebuild existing functionality merely because it appears in this plan.

The technical audit identifies the current working foundation, including:

- PII detection
- compliance rules
- evidence ledger
- tenant isolation
- agent registration
- agent authentication
- live feed
- investigation
- PDF reporting
- licensing
- cross-platform deployment
- 337 automated tests

Preserve these unless implementation changes are genuinely required.

### Rule 2 — No unnecessary rewrite

Do not:

- rewrite the frontend into React
- migrate to microservices
- introduce Kubernetes for the Veritas Server
- introduce Kafka
- introduce Redis
- introduce PostgreSQL immediately
- replace SQLite without evidence that it is necessary
- replace the current rules engine
- replace Presidio unnecessarily

The current architecture is a modular monolith. Keep it that way unless measurable requirements force a change.

### Rule 3 — Preserve privacy-by-design

Never introduce functionality that causes raw detected PII to be persisted unnecessarily.

The current Evidence Store intentionally excludes matched PII values. Preserve this principle.

### Rule 4 — Every phase must end in a working state

After each phase:

1. Run automated tests.
2. Add tests for new functionality.
3. Manually verify the feature.
4. Verify that existing functionality still works.
5. Document what changed.
6. Do not proceed if the phase introduces unresolved regressions.

### Rule 5 — Do not assume "production ready" means "implemented"

For every requirement classify it as:

```text
IMPLEMENTED
PARTIALLY IMPLEMENTED
WEAK / NEEDS HARDENING
MISSING
BROKEN
NOT REQUIRED YET
```

---

# PHASE 0 — FULL CODEBASE AUDIT & BASELINE

## Goal

Establish an accurate baseline before changing architecture.

## Tasks

Inspect:

```text
dpdpa-agent/
veritas-agent/
veritas-launcher/
installer/
tools/
veritas-demo/
deploy/
tests/
```

Inspect:

- startup flow
- configuration loading
- API routes
- authentication
- database access
- organization isolation
- agent registration
- WebSocket live feed
- frontend
- deployment scripts
- installers
- licensing
- logging
- PII detection
- rules
- evidence storage
- investigation
- existing tests

Create a dependency and component map.

Identify:

- server entry point
- agent entry point
- installer entry points
- configuration locations
- persistent data directories
- service definitions
- database files
- API routes
- WebSocket routes

## Deliverable

Create:

```text
docs/ARCHITECTURE.md
docs/PRODUCTION_GAP_ANALYSIS.md
```

The gap analysis must explicitly state what will and will not be changed.

## Exit criteria

The agent can explain the entire current Veritas architecture and has not modified functionality unnecessarily.

---

# PHASE 1 — DEFINE THE VERITAS SERVER PRODUCT

## Goal

Turn the existing Runtime into a clearly defined **Veritas Server**.

Current:

```text
./veritas-runtime
python run_pipeline.py
```

Target:

```text
Veritas Server
```

The executable/process may internally still be Python/FastAPI, but the customer should experience it as a proper server product rather than a development script.

## Required behavior

The Veritas Server must:

- start automatically
- survive reboot
- restart after failure
- expose the dashboard
- expose authenticated APIs
- manage organizations
- manage users
- manage agents
- receive telemetry
- process violations
- store evidence
- provide live feed
- provide investigation
- expose health information

## Linux service

Create a production systemd service:

```text
veritas-server.service
```

Expected operational commands:

```bash
sudo systemctl start veritas-server
sudo systemctl stop veritas-server
sudo systemctl restart veritas-server
sudo systemctl status veritas-server
```

Enable automatic startup:

```bash
sudo systemctl enable veritas-server
```

## Standard directories

Use an appropriate Linux layout such as:

```text
/etc/veritas/
    config/
    certificates/
    secrets/

/var/lib/veritas/
    evidence.db
    agents.db
    organizations/

/var/log/veritas/

/opt/veritas/
    application/
```

Do not blindly use these exact paths if the existing cross-platform runtime abstraction provides a better solution. Preserve platform independence.

## Exit criteria

A customer can install Veritas Server and run it as an OS-managed service without manually executing Python.

---

# PHASE 2 — PRODUCTION SERVER INSTALLER

## Goal

Create a real customer-facing installation process.

The customer should NOT need to understand:

```text
pip
virtualenv
spaCy
uvicorn
Python dependencies
```

## Linux installer

Create a production installer/package capable of:

1. checking OS compatibility
2. checking required resources
3. creating Veritas directories
4. installing application files
5. installing dependencies/bundled runtime
6. installing systemd service
7. creating configuration
8. initializing databases
9. installing/binding license
10. generating or configuring certificates
11. creating initial administrator
12. starting the service
13. running health checks
14. displaying the dashboard URL

Example customer experience:

```bash
sudo ./install-veritas.sh
```

Then:

```text
Veritas Server installed successfully.

Dashboard:
https://veritas-server.company.local/

Service:
veritas-server.service

Status:
Running
```

## Important

Do not require internet access.

The installer must be capable of installing from a complete offline package.

## Exit criteria

A fresh Linux VM can be converted into a working Veritas Server through a documented installation procedure.

---

# PHASE 3 — HUMAN AUTHENTICATION

## Goal

Fix the most critical current security weakness.

The audit identifies the absence of human authentication and open admin routes as critical.

Implement authentication for human users.

## Required functionality

Create:

```text
Login
Logout
Session management
Password management
```

At minimum support local authentication.

Design the system so enterprise authentication can later support:

```text
LDAP
Active Directory
OIDC / SSO
```

Do not make those integrations mandatory for the first production release.

## Security requirements

Passwords must:

- never be stored plaintext
- use a modern password hashing algorithm
- have appropriate password validation
- support account disabling
- support session expiration
- support logout/invalidation

Do not store authentication secrets in frontend localStorage.

## Exit criteria

A user cannot access the Veritas dashboard without authenticating.

---

# PHASE 4 — RBAC & AUTHORIZATION

## Goal

Introduce real user roles and permissions.

Recommended initial roles:

### SUPER_ADMIN

Can:

- manage organizations
- manage users
- manage agents
- configure policies
- revoke agents
- view evidence
- investigate
- export reports
- manage system settings

### COMPLIANCE_ADMIN

Can:

- configure organization
- view violations
- investigate
- acknowledge/resolve violations
- export reports
- view agents

Cannot:

- manage system-level users
- change licensing
- access unrelated organizations

### AUDITOR

Can:

- view evidence
- verify evidence chain
- view reports
- investigate

Cannot:

- modify organization configuration
- revoke agents
- manage users

### VIEWER

Read-only access to permitted dashboard information.

## Permission model

Do not rely only on frontend hiding.

Every permission must be enforced server-side.

Example:

```text
POST /agents/{id}/revoke
        ↓
authenticated user?
        ↓
authorized role?
        ↓
organization scope?
        ↓
perform operation
```

## Exit criteria

An auditor cannot perform administrative actions even if they manually call the API.

---

# PHASE 5 — ORGANIZATION / TENANT MANAGEMENT

## Goal

Turn organization management into a real administrative capability.

Current organization isolation is already strong at the storage, WebSocket and agent layers. Preserve it.

Implement:

```text
Organizations
    ├── Organization details
    ├── Compliance configuration
    ├── Users
    ├── Agents
    ├── Policies
    └── Evidence
```

## Dashboard

Create a proper:

```text
Settings
  → Organizations
  → Add Organization
  → Edit Organization
  → Organization Details
```

The existing Add Organization UI should be reused where possible rather than rewritten unnecessarily.

## Critical requirement

Never trust:

```text
?org_id=...
```

or frontend localStorage as authorization.

The authenticated user's organization access must be determined server-side.

## Exit criteria

Changing `org_id` manually in a URL cannot expose another organization's data.

---

# PHASE 6 — AGENT ENROLLMENT & FLEET MANAGEMENT

## Goal

Transform the existing agent registration mechanism into a customer-friendly fleet-management system.

The customer should be able to go to:

```text
Dashboard
→ Agents
→ Add Agent
```

and receive an enrollment process.

## Enrollment flow

Example:

```text
Admin clicks "Add Agent"

        ↓

Select:
Linux / Windows

        ↓

Select organization

        ↓

Generate enrollment token

        ↓

Dashboard displays:
Server URL
Enrollment token
Installation instructions

        ↓

Customer installs Veritas Agent

        ↓

Agent registers

        ↓

Server assigns Agent ID

        ↓

Agent receives configuration

        ↓

Agent starts heartbeat

        ↓

Dashboard:
🟢 ONLINE
```

## Agent identity

Every agent must have a unique identity.

Example:

```text
VERITAS-AGENT-7F83A2
```

Display:

- Agent ID
- hostname
- OS
- architecture
- agent version
- organization
- status
- last heartbeat
- event count
- configured sources
- assigned policy

## Status model

At minimum:

```text
ONLINE
OFFLINE
REVOKED
UNKNOWN
```

Determine online/offline using heartbeat timestamps rather than only the last received event.

## Exit criteria

A customer can deploy seven agents and manage all seven from one dashboard.

---

# PHASE 7 — LINUX & WINDOWS AGENT PRODUCTIZATION

## Goal

Turn the current Agent into a professional deployable endpoint component.

## Linux

Agent should run as:

```text
veritas-agent.service
```

It should:

- start on boot
- restart after failure
- maintain configuration
- maintain identity
- heartbeat
- monitor configured sources
- queue events
- retry failed transmission
- expose local health information

## Windows

Agent should run as a:

```text
Windows Service
```

It should:

- start automatically
- restart after failure
- run without requiring a logged-in user
- maintain configuration
- heartbeat
- monitor configured sources
- securely communicate with Veritas Server

## Agent configuration

Do not require customers to edit Python files.

Use a dedicated configuration structure.

Example:

```yaml
server:
  url: https://veritas-server.company.local

agent:
  id: VERITAS-AGENT-123456

sources:
  - type: file
    path: /var/log/application/app.log

  - type: docker
    container: order-service
```

Exact format should follow the existing configuration architecture where possible.

## Exit criteria

Linux and Windows endpoints can be installed and run as native services.

---

# PHASE 8 — SECURE AGENT ↔ SERVER COMMUNICATION

## Goal

Eliminate the current HTTP-by-default transport weakness.

The audit identifies encryption in transit as only partially implemented because HTTPS currently requires reverse-proxy setup.

Target:

```text
Agent
   │
   │ HTTPS / TLS
   │
   ▼
Veritas Server
```

## Requirements

Production communication must:

- use TLS
- validate the server certificate
- authenticate the agent
- reject revoked agents
- prevent cross-organization access
- avoid transmitting credentials unnecessarily
- fail closed on invalid TLS

Do not silently fall back from HTTPS to HTTP.

## Preferred architecture

Where practical:

```text
Agent
 ↓
TLS
 ↓
Authenticated API
 ↓
Server
```

If mTLS is introduced, make it deliberate and document certificate lifecycle management.

Do not add certificate complexity merely for marketing purposes.

## Exit criteria

A production agent cannot transmit telemetry over plaintext HTTP by accident.

---

# PHASE 9 — EDGE PRIVACY / PII MINIMIZATION

## Goal

Strengthen Veritas's biggest privacy differentiator.

Current architecture sends raw log lines from Agent to Runtime before PII detection. The technical audit explicitly identifies this as an architectural improvement opportunity.

Preferred target:

```text
Application Log
      ↓
Veritas Agent
      ↓
Local PII Detection
      ↓
Policy Evaluation / Minimization
      ↓
Raw PII discarded
      ↓
Privacy-safe event
      ↓
TLS
      ↓
Veritas Server
```

## Important

Do NOT immediately rewrite the entire detection engine.

First evaluate whether existing detection components can safely run in the Agent.

Determine:

- memory footprint
- CPU overhead
- startup time
- model packaging
- detection consistency
- false positives
- false negatives

If edge detection is too expensive for certain environments, provide a documented fallback mode.

## Exit criteria

Where edge detection is enabled, raw PII does not need to leave the monitored machine.

---

# PHASE 10 — PII DETECTION HARDENING

## Goal

Improve detection quality without introducing unnecessary false positives.

Current supported detection includes:

- PERSON
- EMAIL_ADDRESS
- PHONE_NUMBER
- Aadhaar
- PAN
- Indian phone

The audit identifies unspaced 12-digit Aadhaar as a known false-positive risk and notes that Verhoeff validation exists but is not fully integrated into realtime detection.

## Tasks

Integrate identifier validation into the real-time pipeline where appropriate.

Improve:

```text
Aadhaar
PAN
Indian phone
```

Investigate support for:

```text
Passport
DOB
Address
Financial account identifiers
Health information
Biometric-related identifiers
```

Do not add detection types merely to increase the list.

Each recognizer must have:

- test cases
- false-positive tests
- false-negative tests
- confidence behavior
- contextual detection where appropriate

## Exit criteria

PII detection is measurably more reliable than the current implementation.

---

# PHASE 11 — EVIDENCE LEDGER HARDENING

## Goal

Make the current evidence system suitable for serious compliance/audit use.

Preserve:

```text
Append-only evidence
SHA-256 hash chaining
Per-organization chains
No matched PII storage
```

The current audit confirms this is already implemented.

## Add

- chain verification endpoint protection
- verification UI
- audit metadata
- evidence export
- evidence integrity status
- immutable event metadata
- clear distinction between immutable evidence and mutable remediation status

## Important terminology

Call the ledger:

```text
Tamper-evident
```

Do NOT claim:

```text
Tamper-proof
Immutable
Blockchain
```

unless the implementation actually supports those claims.

## Exit criteria

An auditor can verify that the evidence chain has not been altered.

---

# PHASE 12 — USER ACTIVITY AUDIT LOG

## Goal

Create a separate audit trail for human administrative actions.

The evidence ledger records compliance events, but currently there is no dedicated audit log for user actions.

Record actions such as:

```text
LOGIN
LOGOUT
CREATE_ORGANIZATION
UPDATE_ORGANIZATION
CREATE_USER
DISABLE_USER
CREATE_AGENT
REVOKE_AGENT
CHANGE_POLICY
VIEW_EVIDENCE
EXPORT_REPORT
ACKNOWLEDGE_VIOLATION
RESOLVE_VIOLATION
CHANGE_SYSTEM_CONFIGURATION
```

Record:

```text
timestamp
user
organization
action
resource
result
request metadata
```

Never log passwords, tokens or raw PII.

## Exit criteria

An administrator can answer:

> Who changed this configuration and when?

---

# PHASE 13 — REMEDIATION / CASE MANAGEMENT

## Goal

Evolve the current:

```text
OPEN
→ ACKNOWLEDGED
→ RESOLVED
```

workflow into useful enterprise remediation.

Add:

```text
Assignee
Team
Priority
Comments
Resolution reason
Due date
Activity history
```

Example:

```text
Violation #1832

Severity: HIGH
Rule: EXPOSURE_001
Source: order-service
Field: customer_phone

Status:
OPEN

Assigned to:
Security Team

Due:
12 Sep 2026
```

Do not store raw PII.

## Exit criteria

A compliance officer can manage a violation from detection through resolution.

---

# PHASE 14 — POLICY MANAGEMENT

## Goal

Make compliance configuration manageable from the product.

Organizations should be able to configure:

```text
PII fields
Purpose
Consent scope
Retention
Source systems
Identifiers
Linkage rules
Severity
```

Preserve existing YAML versioning if it remains appropriate.

Expose configuration history:

```text
Version 1
Version 2
Version 3
```

Allow administrators to inspect previous versions.

## Important

Do not allow arbitrary users to modify policy.

Every policy modification must:

- require authorization
- be audit logged
- create a new version
- never silently overwrite history

---

# PHASE 15 — OFFLINE / AIR-GAPPED MODE

## Goal

Make offline operation a first-class deployment mode.

The audit confirms core Veritas functionality already works offline, while CDN dependencies and external LLM calls are exceptions.

Remove production dependence on:

```text
Google Fonts CDN
jsDelivr
External analytics
Cloud telemetry
```

Bundle required frontend assets locally.

## LLM architecture

Support:

```text
AI = Disabled
AI = External Provider
AI = Local Provider
```

Default for air-gapped:

```text
AI = Disabled
```

Core detection must never depend on an LLM.

## Exit criteria

A disconnected machine can:

- install Veritas
- create organizations
- install agents
- detect PII
- generate violations
- view dashboard
- verify evidence
- export reports

without internet access.

---

# PHASE 16 — SECRETS & CONFIGURATION HARDENING

## Goal

Ensure production secrets are handled securely.

Review:

- license keys
- agent tokens
- registration keys
- TLS private keys
- admin credentials
- LLM API keys
- encryption keys

Never:

- commit secrets
- log secrets
- expose secrets through API
- send secrets to frontend unnecessarily

Use appropriate OS permissions.

Example:

```text
/etc/veritas/secrets/
    permissions: 0600
```

where appropriate.

## Exit criteria

A normal dashboard/API user cannot retrieve server secrets.

---

# PHASE 17 — ENCRYPTION AT REST

## Goal

Protect locally stored compliance information.

The audit currently identifies SQLite files as unencrypted.

Evaluate:

### Option A

Encrypted SQLite/database layer.

### Option B

Full-disk encryption as a deployment requirement.

### Option C

Application-level encryption for sensitive metadata.

Choose based on:

- security
- deployment complexity
- backup implications
- performance
- portability
- offline operation

Do not implement encryption merely for appearance.

Document the threat model.

## Exit criteria

The production security posture around stored evidence and credentials is explicitly defined and implemented.

---

# PHASE 18 — BACKUP & RECOVERY

## Goal

Make Veritas recoverable after machine failure.

Define backup strategy for:

```text
evidence database
agent database
organization configurations
license/configuration
encryption material
```

Provide:

```text
backup
restore
verification
```

Do not corrupt the evidence chain during backup/restore.

Test:

```text
Fresh server
↓
Restore backup
↓
Start Veritas
↓
Verify evidence chain
↓
Verify organizations
↓
Verify agents
```

## Exit criteria

A customer can recover a Veritas installation from a documented backup.

---

# PHASE 19 — HEALTH & OBSERVABILITY

## Goal

Give administrators confidence that Veritas itself is healthy.

Implement:

```text
GET /health
GET /ready
```

Dashboard:

```text
Server Health
Agent Health
Database Health
Pipeline Health
Storage Health
License Status
```

Example:

```text
Veritas Server       🟢 Healthy
Evidence Store       🟢 Healthy
Agent Pipeline       🟢 Healthy
WebSocket            🟢 Healthy
License              🟢 Valid
Disk Space           🟢 72% free
```

## Agent health

Display:

```text
Last heartbeat
Last event
Agent version
CPU
Memory
Connection status
```

Do not collect unnecessary telemetry.

---

# PHASE 20 — RATE LIMITING & RESOURCE PROTECTION

## Goal

Prevent accidental or malicious resource exhaustion.

Protect:

- authentication
- agent registration
- scan API
- investigation API
- organization creation
- configuration upload

Limit:

- request body sizes
- event sizes
- queue sizes
- concurrent operations
- investigation requests

The current audit already notes limits on event payloads and queue size; preserve these protections while hardening them.

## Exit criteria

One faulty agent cannot easily exhaust the server.

---

# PHASE 21 — FRONTEND SECURITY HARDENING

## Goal

Make the dashboard safe for enterprise use.

Remove reliance on:

```text
localStorage org_id
```

for authorization.

Implement:

```text
authenticated session
server-derived organization access
role-aware UI
```

Add appropriate:

```text
CSP
security headers
secure cookies
XSS protections
CSRF protection where applicable
```

Do not expose sensitive backend information in browser responses.

---

# PHASE 22 — API SECURITY & VERSIONING

## Goal

Create a stable production API.

Current APIs are a mixture of:

```text
/v1/*
/api/*
/agents/*
```

Do not blindly rename everything.

First document existing contracts.

Then establish a clear convention.

Example:

```text
/api/v1/auth/*
/api/v1/organizations/*
/api/v1/agents/*
/api/v1/violations/*
/api/v1/policies/*
/api/v1/system/*
```

Maintain backwards compatibility where reasonable.

Agent ingestion should have explicit API versioning.

## Exit criteria

Agent and Server versions can be upgraded without silently breaking communication.

---

# PHASE 23 — LOCAL LLM ARCHITECTURE

## Goal

Make AI optional and privacy-preserving.

Current LLM investigation already sends only minimized metadata and does not send raw PII. Preserve this behavior.

Design:

```text
Investigation
      ↓
AI Provider abstraction
      ├── Disabled
      ├── External
      └── Local
```

Local provider may later support:

```text
Ollama
Local model
```

But do NOT make local LLM deployment a prerequisite for production readiness.

Detection and compliance decisions must remain deterministic.

LLM output must never modify evidence automatically.

---

# PHASE 24 — PRODUCTION INSTALLER & PACKAGING MATRIX

## Goal

Deliver real distributable products.

### Veritas Server

At minimum:

```text
Linux x86_64
```

Then:

```text
Linux ARM64
Windows Server
macOS
```

only where justified.

### Veritas Agent

At minimum:

```text
Linux x86_64
Linux ARM64
Windows x86_64
```

Potentially:

```text
macOS
```

if required.

Provide versioned artifacts:

```text
veritas-server-1.0.0-linux-amd64
veritas-agent-1.0.0-linux-amd64
veritas-agent-1.0.0-linux-arm64
veritas-agent-1.0.0-windows-amd64
```

---

# PHASE 25 — END-TO-END TEST ENVIRONMENT

## Goal

Prove the product works as an actual distributed system.

Create a test environment representing:

```text
1 Veritas Server
5 Linux Agents
2 Windows Agents
```

Where Windows virtualization is practical.

Test:

```text
Agent enrollment
Agent authentication
TLS
Heartbeat
Log ingestion
PII detection
Rule evaluation
Evidence storage
Live feed
Dashboard
Organization isolation
RBAC
Agent revocation
Agent reconnect
Server restart
Agent restart
Network outage
Database recovery
License expiry
Offline operation
```

---

# PHASE 26 — FAILURE / RECOVERY TESTING

## Goal

Verify Veritas behaves safely when components fail.

Test:

### Agent loses network

Expected:

```text
Queue locally
Retry
Do not lose events unnecessarily
```

### Server unavailable

Expected:

```text
Agent retries
Agent remains operational
```

### Server restarts

Expected:

```text
Server recovers
Database remains valid
Agents reconnect
```

### Agent revoked

Expected:

```text
Server rejects events
Agent does not regain access without re-enrollment
```

### Database failure

Expected:

```text
Pipeline fails safely
No corrupted evidence
Clear health status
```

### Invalid TLS

Expected:

```text
Connection rejected
No insecure fallback
```

---

# PHASE 27 — SECURITY TESTING

## Goal

Attempt to break Veritas before calling it production-ready.

Test:

```text
Unauthenticated dashboard access
Unauthenticated admin API access
Cross-organization API access
Role escalation
Agent token reuse
Registration token reuse
Revoked agent access
Expired session
CSRF
XSS
Path traversal
Oversized payloads
Malformed events
WebSocket tenant isolation
Database tampering
Configuration tampering
Secret exposure
```

Especially test:

```text
User A → Organization A
User A attempts → Organization B
```

Expected:

```text
403 / denied
```

not merely an empty response.

---

# PHASE 28 — PERFORMANCE & SCALE VALIDATION

## Goal

Determine the actual scale supported by the current architecture.

Do not migrate SQLite simply because PostgreSQL is considered more "enterprise".

Benchmark:

```text
10 agents
25 agents
50 agents
100 agents
```

Measure:

- events/sec
- detection latency
- CPU
- RAM
- SQLite write latency
- WebSocket load
- API latency
- queue growth

Only migrate the database or split processes if measurements justify it.

The current audit notes SQLite's single-writer characteristics and the limitations of the single-process WebSocket/API architecture.

---

# PHASE 29 — DATABASE MIGRATION STRATEGY — ONLY IF REQUIRED

## Goal

Prepare for scale without prematurely increasing deployment complexity.

If benchmarks show SQLite is sufficient:

```text
KEEP SQLITE
```

If benchmarks demonstrate a real limitation:

Design:

```text
SQLite
   ↓
PostgreSQL
```

with:

- migration tooling
- schema migration
- backup migration
- rollback strategy
- data integrity verification

Do not introduce PostgreSQL merely because enterprise products commonly use it.

---

# PHASE 30 — DOCUMENTATION

## Goal

A real product must be installable by someone who did not write it.

Create:

```text
docs/
├── INSTALLATION.md
├── ADMIN_GUIDE.md
├── AGENT_DEPLOYMENT.md
├── WINDOWS_AGENT.md
├── LINUX_AGENT.md
├── ORGANIZATION_SETUP.md
├── RBAC.md
├── SECURITY.md
├── OFFLINE_DEPLOYMENT.md
├── BACKUP_RESTORE.md
├── TROUBLESHOOTING.md
├── API.md
├── ARCHITECTURE.md
└── UPGRADE.md
```

Documentation must include the real commands and real configuration used by the final implementation.

---

# PHASE 31 — CUSTOMER DEMONSTRATION ENVIRONMENT

## Goal

Create a realistic demonstration deployment.

Demonstration topology:

```text
                     Veritas Server
                           │
            ┌──────────────┼──────────────┐
            │              │              │
         Agent 01       Agent 02       Agent 03
            │
        Application
         Logs
```

Demonstrate:

1. organization creation
2. agent enrollment
3. agent appears online
4. application produces PII-containing log
5. Veritas detects it
6. violation appears in live feed
7. evidence is stored
8. raw PII is not stored
9. compliance officer investigates
10. violation is assigned
11. violation is resolved
12. audit report exported
13. evidence chain verified

This should become the standard customer demo.

---

# PHASE 32 — FINAL PRODUCTION ACCEPTANCE TEST

The implementation is complete only when the following scenario works from a clean machine.

## Customer scenario

Customer receives:

```text
Veritas Server installer
Veritas Agent installer
License
Documentation
```

### Step 1

Customer provisions:

```text
Linux VM
```

### Step 2

Runs:

```text
Veritas Server installer
```

### Step 3

Server starts automatically.

### Step 4

Customer opens:

```text
https://veritas-server/
```

### Step 5

Creates first administrator.

### Step 6

Creates organization:

```text
Acme Corporation
```

### Step 7

Dashboard provides:

```text
Add Agent
```

### Step 8

Customer installs agents on:

```text
Linux 01
Linux 02
Linux 03
Linux 04
Linux 05
Windows 01
Windows 02
```

### Step 9

All seven agents register.

Dashboard:

```text
Agents

7 Total
7 Online

Linux-01       ONLINE
Linux-02       ONLINE
Linux-03       ONLINE
Linux-04       ONLINE
Linux-05       ONLINE
Windows-01     ONLINE
Windows-02     ONLINE
```

### Step 10

Customer configures monitored sources.

### Step 11

Applications generate telemetry.

### Step 12

Veritas detects:

```text
EMAIL
PHONE
PAN
AADHAAR
NAME
```

and other supported sensitive data.

### Step 13

Rules evaluate:

```text
EXPOSURE_001
PURPOSE_001
RETENTION_001
LINKAGE_001
```

### Step 14

Dashboard receives live violation.

### Step 15

Evidence is persisted without storing matched PII.

### Step 16

Compliance officer opens the violation.

### Step 17

Officer assigns it to a team/member.

### Step 18

Officer acknowledges and resolves it.

### Step 19

Auditor verifies the evidence chain.

### Step 20

Auditor exports a report.

### Step 21

Administrator can see who performed each administrative action.

### Step 22

Server is rebooted.

Everything automatically recovers.

### Step 23

An agent loses network connectivity.

Agent queues/retries according to policy.

### Step 24

Network returns.

Agent reconnects.

### Step 25

Server operates without internet access.

Core functionality continues working.

---

# FINAL PRODUCT DEFINITION

At the end of this project, Veritas must no longer feel like:

```text
"Run this Python application and open localhost."
```

It must feel like:

```text
"Install Veritas Server inside your infrastructure,
enroll your endpoints,
configure your privacy policies,
and Veritas continuously monitors your environment."
```

The final product consists of two primary components.

---

## 1. VERITAS SERVER

A centrally installed on-premise application containing:

```text
┌────────────────────────────────────────────┐
│              VERITAS SERVER                │
├────────────────────────────────────────────┤
│                                            │
│ Authentication                             │
│ RBAC                                       │
│ Organization Management                    │
│ Agent Management                           │
│ Policy Management                          │
│                                            │
│ Telemetry Ingestion                        │
│ PII Detection                              │
│ Compliance Rules                           │
│ Evidence Ledger                            │
│                                            │
│ Live Monitoring                            │
│ Investigation                              │
│ Remediation / Cases                        │
│ Reporting                                  │
│                                            │
│ Audit Logs                                 │
│ Health Monitoring                          │
│ Licensing                                  │
│ Backup / Recovery                          │
│                                            │
│ Dashboard                                  │
└────────────────────────────────────────────┘
```

---

## 2. VERITAS AGENT

A lightweight endpoint service installed on monitored systems.

Responsibilities:

```text
Monitor configured sources
        ↓
Collect telemetry
        ↓
Local processing / PII minimization where enabled
        ↓
Secure transmission
        ↓
Heartbeat
        ↓
Retry / queue when disconnected
```

It should be completely invisible to normal application users and operate as an OS service.

---

# WHAT MUST NOT CHANGE

The following principles are fundamental to Veritas and must be preserved:

### 1. Local-first

Customer data remains within customer infrastructure.

### 2. No unnecessary raw PII persistence

The evidence database should not become a repository of the sensitive information Veritas is supposed to protect.

### 3. Deterministic compliance engine

LLMs must never become a dependency for core detection.

### 4. Tamper-evident evidence

Compliance evidence must remain verifiable.

### 5. Tenant isolation

Organization boundaries must be enforced server-side.

### 6. Offline capability

Core compliance functionality must work without the internet.

### 7. Simple deployment

Do not turn Veritas into a Kubernetes/microservices platform unless actual scale requires it.

---

# PRIORITY ORDER

Implement in this order:

## P0 — Security / Production Foundation

```text
Phase 0   Audit
Phase 1   Server productization
Phase 2   Server installer
Phase 3   Human authentication
Phase 4   RBAC
Phase 5   Organization security
Phase 6   Agent enrollment
Phase 7   Agent services
Phase 8   TLS
```

## P1 — Product Completeness

```text
Phase 9    Edge privacy
Phase 10   PII hardening
Phase 11   Evidence hardening
Phase 12   Audit logging
Phase 13   Case management
Phase 14   Policy management
Phase 15   Offline mode
Phase 16   Secrets
```

## P2 — Enterprise Hardening

```text
Phase 17   Encryption at rest
Phase 18   Backup/recovery
Phase 19   Health monitoring
Phase 20   Resource protection
Phase 21   Frontend security
Phase 22   API versioning
Phase 23   Local AI
```

## P3 — Scale / Optimization

```text
Phase 24   Packaging matrix
Phase 25   E2E testing
Phase 26   Failure testing
Phase 27   Security testing
Phase 28   Performance testing
Phase 29   Database scaling
Phase 30   Documentation
Phase 31   Customer demo
Phase 32   Production acceptance
```

---

# DEFINITION OF DONE

Veritas is considered production-ready only when:

- [ ] Server installs without developer tooling
- [ ] Server runs as an OS service
- [ ] Agent installs as an OS service
- [ ] Linux Agent works
- [ ] Windows Agent works
- [ ] Agent enrollment works
- [ ] Agent revocation works
- [ ] Agent heartbeat works
- [ ] TLS is enforced in production
- [ ] Human login exists
- [ ] RBAC exists
- [ ] Admin APIs are protected
- [ ] Organization isolation is server-enforced
- [ ] PII is not unnecessarily persisted
- [ ] Compliance rules work
- [ ] Evidence chain works
- [ ] User actions are audited
- [ ] Live feed works
- [ ] Investigation works without requiring external AI
- [ ] Offline deployment works
- [ ] CDN dependencies are removed from production
- [ ] Backup/restore is tested
- [ ] Health checks exist
- [ ] Security tests exist
- [ ] E2E tests exist
- [ ] Agent/server failure recovery is tested
- [ ] Installation has been tested on a clean machine
- [ ] Upgrade procedure exists
- [ ] Documentation exists
- [ ] Customer can deploy multiple agents without developer assistance

---

# REQUIRED FINAL REPORT FROM THE CODING AGENT

At the end of implementation, produce:

```text
VERITAS_PRODUCTION_IMPLEMENTATION_REPORT.md
```

It must contain:

## 1. Executive summary

What changed.

## 2. Architecture before vs after

Show diagrams.

## 3. Implemented features

List every feature.

## 4. Files changed

List files and purpose.

## 5. Database changes

List migrations/schema changes.

## 6. API changes

List new/changed endpoints.

## 7. Security changes

Authentication, RBAC, TLS, secrets, audit logs, etc.

## 8. Deployment changes

Server and Agent installation.

## 9. Testing

Show:

```text
Existing tests:
New tests:
Integration tests:
E2E tests:
Security tests:
Manual tests:
```

## 10. Performance

Provide measured results rather than assumptions.

## 11. Known limitations

Clearly identify anything still incomplete.

## 12. Production readiness verdict

Choose exactly one:

```text
READY
READY WITH DOCUMENTED LIMITATIONS
NOT READY
```

Do not claim production readiness merely because tests pass.

---

# CORE SUCCESS CRITERION

The final question the implementation must answer is:

> "If I give Veritas to a real organization with 5 Linux servers and 2 Windows servers, can their IT team install one Veritas Server, deploy seven Veritas Agents, configure their policies, and have a secure centralized dashboard continuously monitor privacy violations — without needing the Veritas development team to manually run Python commands?"

If the answer is **YES**, the transformation is successful.

If the answer is **NO**, identify exactly what prevents it and continue implementation.

The objective is not to make the codebase larger.

The objective is to make **Veritas a deployable product.**