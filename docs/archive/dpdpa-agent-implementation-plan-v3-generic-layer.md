# DPDPA Compliance Monitoring Agent — Implementation Plan v3
## From Blinkit Demo → Generic, Pluggable Compliance API Layer

**What changed from v2:** v2 proved the concept end-to-end on one hardcoded domain (Blinkit). v3's only job is to make every domain-specific piece **configurable** instead of hardcoded, add a **validated-identifier layer** (PAN/Aadhaar checksum), add a **linkage/combination-risk rule**, and expose the whole thing as an **integratable API/SDK** instead of a standalone demo app. The rule engine, evidence store, and dashboard concepts from v2 stay — this plan only touches what needs to become generic.

---

## Guiding principle

Nothing about *detection logic* changes. What changes is **where the domain knowledge lives**: it moves out of Python code and into a **config file the integrating org supplies**. A new organisation should be able to onboard by writing a config file and calling an API — never by forking your codebase.

---

## PHASE 0 — Generalization Contract Lock

**Goal:** Freeze the shape of the config file and the multi-tenant identifiers before touching any code, so every other phase can build in parallel.

**Procedure:**
1. Add `tenant_id` / `org_id` to the event schema, verdict schema, and Evidence Store schema (this is the single biggest change — everything downstream partitions by it).
2. Design the **Org Config schema** (replaces the hardcoded Blinkit registry):
   ```yaml
   org_id: "edtech_co"
   identifiers:
     - name: apaar_id
       pattern: "^[A-Z0-9]{12}$"     # org-supplied regex
       validator: none               # or: pan | aadhaar | custom_fn
     - name: student_phone
       pattern: "indian_phone"       # reuse built-in
   fields:
     - field_name: apaar_id
       pii_category: student_identifier
       declared_purpose: academic_records
       consent_scope: enrollment
       retention_days: 3650
       source_system: student_portal
   linkage_rules:
     - fields: [pincode, dob, gender]
       risk: LINKAGE_RISK
     - fields: [student_name, school_name, city]
       risk: LINKAGE_RISK
   ```
3. Decide config delivery: file upload, API `POST /orgs/{org_id}/config`, or Git-synced config repo. (Recommend: API upload + versioned storage, so config changes are themselves auditable.)
4. Write the "reference org" config for Blinkit (retail) — this is your regression test, not special-cased code.

**Exit criteria:** Two orgs (Blinkit + one new domain) can each have a config file committed, and nothing in the pipeline code references "Blinkit" or "Aadhaar" by name anymore — only through config.

---

## PHASE 1 — Registry Becomes a Config Loader (replaces old Phase 1)

**Goal:** Turn the hardcoded 4-table Blinkit registry into a generic **config-driven registry service**.

**Procedure:**
1. Replace static Python dicts with a loader: `load_org_config(org_id) → registry`.
2. `get_registry_entry(org_id, field_name, source_system)` — same function signature as before, just keyed by `org_id` now.
3. Support hot-reload or versioning of configs (an org updates its retention policy without redeploying the whole agent).
4. Validate uploaded configs on ingest (schema check, regex sanity check, no duplicate field names) — reject bad configs with a clear error, don't silently accept garbage.

**Exit criteria:** Loading a brand-new org's config and querying it returns correct entries, with zero code changes required.

---

## PHASE 2 — Identifier Validation Layer (new — your PAN/Aadhaar point)

**Goal:** Upgrade "looks like PII" (regex match) into "confirmed identifier" (structurally/mathematically validated), and make this pluggable so any org can register their own identifier type with its own validator.

**Procedure:**
1. Build `validators.py`:
   - `is_valid_pan(value) -> bool` — regex `[A-Z]{5}[0-9]{4}[A-Z]{1}` + basic structural check.
   - `is_valid_aadhaar(value) -> bool` — 12-digit pattern **+ Verhoeff checksum** algorithm (this is the detail that shows real technical depth, not just regex-matching).
   - `validator_registry = {"pan": is_valid_pan, "aadhaar": is_valid_aadhaar}` — a **plugin dict**, so a new org can register `"apaar": is_valid_apaar` without touching this file's core logic.
2. Wire into Phase 3 detection: every Presidio match additionally runs through its declared validator (from Phase 0 config) if one exists. Result: `confidence: "pattern_match" | "validated"`.
3. This directly reduces false positives (a random 12-digit number ≠ confirmed Aadhaar) — a strong, demonstrable improvement over v2.
4. Document that unvalidated identifier types (no known checksum) fall back to pattern-match confidence only — that's an honest limitation, not a gap to hide.

**Exit criteria:** Feed a syntactically-valid-but-checksum-invalid Aadhaar number and a real one; system correctly distinguishes `pattern_match` vs `validated` in the output.

---

## PHASE 3 — Linkage / Combination-Risk Detection (new — your second point)

**Goal:** Detect the case where no single field is a smoking gun, but a **combination of quasi-identifiers** in the same event is enough to re-identify someone — a real privacy concept (k-anonymity/linkage risk), not just per-field regex matching.

**Procedure:**
1. Add `linkage_rules` to org config (Phase 0) — sets of field names that, when co-occurring in one event, constitute a risk (e.g. `[pincode, dob, gender]`, `[name, employer, city]`).
2. After per-field PII detection (Phase 2 output), run a **combination check** across all fields present in the event: if all fields in any configured `linkage_rules` set are present → flag `LINKAGE_RISK` verdict, severity typically MEDIUM–HIGH depending on org config.
3. This becomes a **4th rule category** alongside Exposure / Purpose / Retention in the Rule Engine (Phase 4 of v2) — same verdict schema, new `rule_id` prefix: `LINKAGE_001`.
4. Keep it config-driven so any org defines their own "dangerous combination" sets — this is domain knowledge the agent shouldn't hardcode.

**Exit criteria:** An event containing pincode+dob+gender individually-non-flagged fields correctly produces a `LINKAGE_RISK` verdict; an event with only one of the three does not.

---

## PHASE 4 — Rule Engine Generalization (updates v2's Phase 4)

**Goal:** Make the existing Exposure/Purpose/Retention logic read entirely from config, and add Linkage as a 4th check — no other logic changes.

**Procedure:**
1. Replace any hardcoded field names/thresholds with lookups against the Phase 1 config loader, scoped by `tenant_id`.
2. Order of checks: Exposure → Purpose/Consent → Retention → Linkage (linkage runs last since it needs the full field set of the event, not just one field at a time).
3. Verdict schema gains `tenant_id` and `rule_category: exposure | purpose | retention | linkage`.

**Exit criteria:** Same correctness bar as v2 (zero false negatives on seeded violations), now proven across 2+ org configs simultaneously without cross-contamination between tenants.

---

## PHASE 5 — Expose as an Integration Layer (the "generic API" ask)

**Goal:** Turn the pipeline from "a demo app with a dashboard" into "a service any org's stack can call or embed."

**Procedure — three integration modes, same detection engine underneath:**

1. **Stream/Telemetry mode (what you already have):** org points their log shipper / event bus at your ingestion endpoint (`POST /v1/{org_id}/events`). This is the v2 Live Feed + Evidence Store flow, now multi-tenant.
2. **Synchronous scan API (new, lightweight, high-value for tonight):**
   `POST /v1/{org_id}/scan` with `{ "text": "..." }` or `{ "fields": {...} }` → returns detected entities, validated identifiers, linkage risks, and a masked/redacted version of the input. This is a **stateless single-call endpoint** — trivial for any team to integrate into anything (a debug script, an API gateway, a log viewer).
3. **DevOps interception mode (your idea — build a thin proof-of-concept, not the full thing):** a small CLI/wrapper (`veritas-scan < logfile` or a `kubectl logs | veritas-scan`) that pipes output through the Phase 5 scan API and masks matches before displaying — proves the "catch it before an engineer sees it while debugging" story live, without needing real CI/CD integration tonight.

**Exit criteria:** A new, previously-uninvolved org config can call `/scan` with zero prior setup beyond registering their config, and get back a correct, masked result — this is your live "integration in under a minute" demo moment.

---

## PHASE 6 — Evidence Store & Dashboard Multi-Tenancy (updates v2's Phase 6–7)

**Goal:** Same tamper-evident, hash-chained store and dual-view dashboard from v2, just partitioned so one org can never see another's data.

**Procedure:**
1. Every Evidence Store entry carries `tenant_id`; all queries (`verify_chain()`, filters, exports) are scoped to a tenant.
2. Dashboard gets an org-selector (or per-org API key → auto-scoped view).
3. Everything else (hash chain, `remediation_status`, Live Feed / Audit view split) stays exactly as designed in v2 — no rework needed here, only the tenant boundary.

**Exit criteria:** Two orgs' data coexist in the same running instance; a `verify_chain()` for org A never touches org B's chain.

---

## PHASE 7 — Two-Domain Proof + Onboarding Docs (the demo-winning move)

**Goal:** Prove genericity with evidence, not a claim.

**Procedure:**
1. Ship the Blinkit config (retail) **and** one new domain config end-to-end (recommend EdTech: `student_id`, `apaar_id`, `academic_records`, `guardian_contact`) — same running instance, same code, two tenants.
2. Write a one-page **"Integrate Veritas in 4 steps"** doc (Phase 8 covers the content) — this becomes both your judge-facing artifact and your actual product onboarding doc.
3. Live demo sequence: show config upload for the new domain → immediately call `/scan` with a sample EdTech payload containing an APAAR ID → correct detection, zero code changes.

**Exit criteria:** The single most convincing 90 seconds of your pitch — new domain, live, no redeploy.

---

## PHASE 8 — Pitch & Onboarding Narrative Prep

**Procedure:**
1. Prepare the "what's generic vs. what's still org-specific" slide: detection engine, validators, linkage rules, evidence chain, dashboard = generic/reusable. Field names, retention periods, which identifiers matter = org-supplied config.
2. Prepare the integration story (see explanation below) as a rehearsed 60-second pitch beat.
3. Rehearse the two-domain live demo (Phase 7) and the PAN/Aadhaar validation live demo (feed a fake-but-pattern-matching Aadhaar, show it rejected by checksum) together as back-to-back "depth" moments.
4. Keep the DevOps CLI wrapper demo clearly framed as **proof-of-concept / roadmap direction**, not a finished integration — judges respect honesty about maturity level.

---

## What stays untouched from v2
- Core Exposure/Purpose/Retention rule logic (just made config-driven)
- LLM Explainer + guardrails (statute-grounded, fact-match validated, deterministic fallback) — this is domain-agnostic already, no changes needed
- Evidence Store's hash-chain integrity design
- Dashboard's Live Feed vs. Audit view split

---

## Short explanation: how another organisation integrates Veritas

**In one paragraph:** An organisation never touches Veritas's code. They write a small config file describing *their* PII fields (name, category, purpose, retention period) and *their* identifier formats (with a validator if one exists, like PAN/Aadhaar's checksums), upload it once via `POST /orgs/{org_id}/config`, and from that point on can either (a) point their existing log/event stream at Veritas's ingestion endpoint for continuous monitoring, or (b) call the stateless `POST /v1/{org_id}/scan` endpoint from anywhere in their stack — a debug script, an internal tool, a log viewer — to get instant PII detection, identifier validation, linkage-risk flagging, and a masked-safe version of their data back, with every violation automatically landing in their own tamper-evident, tenant-scoped Evidence Store for their auditor to review monthly.

**Concrete example — EdTech company onboarding:**
1. They write a config: `apaar_id` (pattern + no built-in validator yet, falls back to pattern-match confidence), `student_phone` (reuse built-in Indian-phone validator), `guardian_contact`, with purposes like `academic_records` and `admissions`, and a linkage rule `[student_name, school_name, dob]`.
2. They `POST` this config once.
3. Their support-ticket system starts sending events to `/v1/edtech_co/events` — within minutes, a support ticket containing a raw APAAR ID plus student name and school gets flagged: one `EXPOSURE` verdict (raw ID in a free-text field) plus one `LINKAGE_RISK` verdict (name+school+dob combination) — both statute-explained and evidenced, without EdTech's engineers writing a single line of detection logic.

Want me to draft the actual `POST /orgs/{org_id}/config` schema + the `/v1/{org_id}/scan` endpoint contract next, or start with the `validators.py` (PAN regex + Verhoeff Aadhaar) code?
