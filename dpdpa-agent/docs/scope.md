# DPDPA Agent — Scope Document
> **Status: LOCKED after Phase 0. Do not modify without full team review.**

---

## What This System Is

An autonomous, real-time DPDPA compliance monitoring agent configured per organisation (no customer-specific code). It ingests streaming telemetry (application logs, API payloads), evaluates events against core DPDPA compliance rules, flags violations on a live dashboard, and maintains an immutable audit evidence store.

**Primary user persona:** Priya — a compliance auditor running monthly DPDPA audits. She needs a live feed of violations broken down by source system and a point-in-time audit export.

---

## In Scope — Detectable via Telemetry

These three rule categories are what the agent enforces. They are the only things detectable by observing system telemetry without organizational-level access:

| Rule ID | Category | What It Detects |
|---|---|---|
| `EXPOSURE_001` | PII Exposure | Personal data appearing in logs or API responses where it should not |
| `PURPOSE_001` | Purpose / Consent Limitation | Data fields flowing through an endpoint whose declared consent scope does not permit that field |
| `RETENTION_001` | Retention | Data records present in a system past the consent expiry timestamp |

**Locked PII types** (the only field types the PII detector and rule engine check for):
- `name`
- `email`
- `phone`
- `aadhaar`
- `pan`

This taxonomy is sanity-checked against the `amjadali-110/DPDPA-Checklist` reference (reference only — not a code dependency).

---

## Also in scope since release 1.2: what can be seen in telemetry

Besides application logs, Veritas observes **API payloads** (through a library in the service that masks before it sends), **database schema statements** found in database logs, and standard streaming receivers (syslog and OpenTelemetry). Retention is **tracked to closure by people** (a review, a task, a confirmation, recurrence if the data is still seen): it is never enforced by deleting anything.

---

## Out of Scope — Organizational, Not Telemetry-Observable

The following cannot be determined by watching logs and API payloads alone. They require access to organizational processes, legal documents, or human workflows:

- **Consent-notice validity** — Whether the notice shown to users at data collection time was legally adequate. The agent can see *that* data was collected; it cannot evaluate *how* consent was obtained. (What **is** in scope, from the notice registry: whether a *current* notice is on record that lists the kind of data observed in a system. That is coverage, not adequacy, and it does not show the notice was displayed to anyone. See `docs/PS_ALIGNMENT_PLAN.md`, Phase E.)
- **Breach-notification workflow execution** — The agent flags `breach_notification_candidate = true` on qualifying verdicts; it does NOT send notifications to the Data Protection Board of India. That is a human workflow.
- **DPO / DPIA governance** — Data Protection Officer appointment, Data Protection Impact Assessments, and Board-level governance are organizational obligations outside telemetry scope.
- **Children's data flows** — Detecting whether a user is a minor requires identity verification data the agent does not have access to.
- **Cross-border transfer** — Whether data leaves Indian jurisdiction cannot be determined from internal telemetry alone.

---

## Explicitly Out of Scope by Design — Auto-Remediation

**The agent detects, explains, and evidences. It never modifies production logs, databases, or systems.**

`remediation_status` on a Verdict exists precisely to track **human and engineering follow-up** — not to enact automated changes. Setting a verdict to `RESOLVED` means a human has confirmed the issue was fixed. It does not mean the agent fixed anything.

This boundary is intentional. Auto-remediation in a compliance context risks:
- Destroying audit evidence
- Masking the root cause
- Creating new violations through unintended side effects

---

## Immutability Contract

On a `Verdict` record, **only two fields may ever be mutated** after the record is written to the Evidence Store:

1. `remediation_status`
2. `remediation_updated_at`

Every other Verdict field is immutable and will be covered by a SHA-256 hash chain implemented in Phase 6. Any code that mutates other Verdict fields after write is a **bug** and violates audit integrity.

`Event` records are **fully immutable** — no fields may be changed after ingestion.

---

## Source Systems in Scope (Retail Co)

| System | `source_system` value |
|---|---|
| Order management | `order-service` |
| Delivery partner ops | `delivery-partner-service` |
| Customer support | `support-ticketing` |
| Campaign / analytics | `marketing-analytics` |

---

## What "Done" Looks Like Per Phase

| Phase | Deliverable |
|---|---|
| 0 | Schemas, contracts, repo skeleton (this document) |
| 1 | Consent registry (what data each endpoint is allowed to use) |
| 2 | Ingestion pipeline (log simulator + WebSocket streamer) |
| 3 | PII detection engine (Presidio + regex for Indian identifiers) |
| 4 | Rule engine (evaluates events against registry + rules) |
| 5 | LLM explainer (Claude API — plain-English explanation + remediation suggestion) |
| 6 | Evidence store (SQLite + hash chain, immutability enforcement) |
| 7 | Live dashboard (React — live feed, audit view, PDF export) |
