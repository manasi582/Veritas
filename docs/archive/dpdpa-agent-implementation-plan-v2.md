# Real-Time DPDPA Compliance Monitoring Agent — Implementation Plan v2

**Problem statement:** PSE11
**Framing:** Built for **Blinkit** as the example organization. Primary user is a **compliance auditor** (e.g. a DPO analyst, "Priya") who runs a **monthly DPDPA audit** — not an engineer watching a dashboard all day. The live feed exists to *prove detection works in real time* (hackathon MVP requirement); the Evidence Store + remediation tracking is what makes the system *usable by an auditor after the fact*.

**Scope covered:** Exposure detection, purpose-limitation checks, retention checks — the observable-in-telemetry subset of DPDPA.
**Not in scope:** Consent-notice validity, breach-notification workflow execution, DPO/DPIA governance, children's-data flows, cross-border transfer — organizational obligations outside what a telemetry pipeline can detect. Auto-remediation is also explicitly out of scope: the agent **detects, explains, and evidences** — it does not modify production logs/systems. Fixing the underlying issue is a human/engineering action, tracked via `remediation_status`.

---

## System Flow (dual consumption)

```
Telemetry Sources (Blinkit-flavored, simulated)
   │  order-service logs · delivery-partner onboarding · support tickets · marketing-analytics events
   ▼
Ingestion Pipeline (normalize)
   ▼
PII Detection (Presidio + Aadhaar/PAN recognizers)
   ▼
Rule Engine / Policy Decision Point (Exposure → Purpose → Retention)
   │
   ├──────────────┬──────────────┐
   ▼              ▼              ▼
LLM Explainer   Evidence Store   (verdict object)
(guardrailed,        │
statute-grounded)    │ append-only, hash-chained, remediation_status mutable
   │                 │
   └────────┬────────┘
            ▼
     Live Dashboard (two consumption modes)
     ├─ Live Feed  → proves real-time detection (hackathon MVP demo)
     └─ Evidence / Audit View → auditor's monthly workflow (filter, drill-down,
        remediation status, hash-chain verify, export)
```

---

## Reference Stack Mapping

| Component | Reference project | How it's used here |
|---|---|---|
| PII entity detection | [microsoft/presidio](https://github.com/microsoft/presidio) | Base Analyzer engine; extended with custom Aadhaar/PAN/Indian-phone recognizers. This is the deterministic detection layer — never the LLM. |
| Ingestion pattern | [confluentinc/tutorials — pii-detection](https://github.com/confluentinc/tutorials) (Kafka+Faust redact-and-alert) | We don't run real Kafka at hackathon scale, but we borrow the **pattern**: raw stream → detection app → alert stream (violations) + clean stream (pass-through). Our in-process async queue mimics this topology. |
| Statute grounding | [Ansvar-Systems/india-law-mcp](https://github.com/Ansvar-Systems/india-law-mcp) | Source for the fixed lookup of actual DPDPA section text used by the LLM Explainer, instead of hand-typed snippets — adds real statutory credibility. |
| Rule taxonomy sanity-check | [amjadali-110/DPDPA-Checklist](https://github.com/amjadali-110/DPDPA-Checklist) | Used only to confirm our exposure/purpose/retention taxonomy correctly maps to real DPDPA categories, and to clearly document what's out of scope (consent, DPIA, breach workflow, cross-border, children's data). |
| Alternative/stretch detection layer | [HydroXai/pii-masker](https://github.com/HydroXai/pii-masker), [rpgeeganage/pII-guard](https://github.com/rpgeeganage/pII-guard) | Not in MVP critical path. Optional Phase 9 stretch: an ML/LLM-based secondary detector to catch obfuscated PII regex misses — framed as a research extension, never replacing the deterministic Presidio layer as decision-maker. |
| Schema/DB scanning inspiration | Go-based PII/PHI filesystem scanners (`github.com/topics/pii`, `github.com/topics/hipaa`) | Conceptual reference only, for Phase 1's registry-loader design (walking a schema and classifying columns by sensitivity). Not adopted directly — reimplemented lightweight in Python for stack consistency. |

---

## Shared Contracts (locked in Phase 0)

### Event schema
```json
{
  "event_id": "string",
  "source_type": "log | api",
  "source_system": "order-service | delivery-partner-service | support-ticketing | marketing-analytics",
  "timestamp": "ISO8601",
  "raw_snippet": "string",
  "fields": { "field_name": "value" }
}
```
`source_system` is new vs. v1 — it's what lets the auditor's monthly report break violations down **by Blinkit system**, which is how a real auditor thinks ("what's wrong in support logs" vs. "what's wrong in marketing").

### Verdict schema
```json
{
  "verdict_id": "string",
  "event_id": "string",
  "rule_id": "EXPOSURE_001 | PURPOSE_001 | RETENTION_001",
  "severity": "LOW | MEDIUM | HIGH",
  "source": "log | api",
  "source_system": "string",
  "field": "string",
  "timestamp": "ISO8601",
  "matched_registry_entry": "object",
  "breach_notification_candidate": "boolean",
  "remediation_status": "OPEN | ACKNOWLEDGED | RESOLVED",
  "remediation_updated_at": "ISO8601 | null"
}
```
`remediation_status` and `remediation_updated_at` are the **only mutable fields** on a verdict after it's written to the Evidence Store. Everything else is immutable and part of the hash chain.

---

## PHASE 0 — Setup & Scope Lock

**Goal:** Freeze what's live-built vs. architected-only; lock the two shared contracts above so every module can build in parallel without blocking on another module's decisions.

**Expected outcome of this phase:** A repo with committed schemas that nobody argues about again.

**Procedure:**
1. Confirm demo data sources: logs + API payloads are live-simulated (Blinkit-flavored, see Phase 2); DB schema/registry is a static input, not a live stream.
2. Assign module owners: Ingestion, Detection/Rule Engine, LLM Explainer + Guardrails, Dashboard (live + audit views), Evidence Store, Pitch/Docs.
3. Commit the **event schema** and **verdict schema** (above) to a shared `/schemas` folder.
4. Lock PII types to detect: name, email, phone, Aadhaar, PAN.
5. Lock DPDPA rule categories: exposure, purpose/consent, retention — cross-check against `DPDPA-Checklist` categories to confirm nothing is silently out of taxonomy, and explicitly write down what's excluded (consent-notice validity, DPIA, breach workflow, cross-border, children's data).
6. Set up repo/branch structure.

**Exit criteria:** Written scope doc + both schemas committed. Every module owner can start Phase 1–2 work without waiting on another team member.

---

## PHASE 1 — Compliance Reference Registry (Blinkit-flavored)

**Goal:** Establish ground truth — for every field Blinkit systems handle, what it is, why it was collected, and how long it can legally be kept — before any event can be judged. This registry is what turns a raw PII match into an actual compliance verdict.

**Expected outcome of this phase:** A queryable in-memory (or SQLite) table that Phase 4 can call synchronously with zero ambiguity.

**Procedure:**
1. Define schema columns: `field_name`, `pii_category`, `declared_purpose`, `consent_scope`, `retention_days`, `created_at`, `source_system`.
2. Seed **four Blinkit-realistic mock tables** (this is the auditor-relevant upgrade from generic `users`/`orders`):
   - `customers` — name, phone, delivery address, order history. Purpose: `order_fulfillment`.
   - `delivery_partners` — Aadhaar, PAN, bank details, address. Purpose: `onboarding_kyc`. Retention should be tight (e.g. 180 days post-engagement) — this is your deliberate retention-violation seed.
   - `support_tickets` — name, phone, order reference, free-text notes (highest exposure risk — free text is where PII "rides along" unintentionally).
   - `marketing_events` — should contain only de-identified/hashed identifiers. Purpose: `marketing_analytics`. Any raw PII appearing here is automatically a purpose-limitation violation by construction.
3. Deliberately seed violations: e.g. a `delivery_partners.retention_days` row where `created_at` is already past the limit; a `marketing_events` schema entry that (on paper) shouldn't accept raw phone/Aadhaar but the mock event generator will occasionally violate anyway (see Phase 2).
4. Build the loader: `field_name → pii_type → declared_purpose → consent_scope → retention_limit`.
5. Expose `get_registry_entry(field_name, source_system) → entry | null`.

**Explicitly NOT in scope for this phase:** live ingestion, rule evaluation.

**Exit criteria:** Registry is queryable and returns correct entries for all four mock tables, including the deliberately-seeded violation rows.

---

## PHASE 2 — Ingestion Layer (Blinkit-simulated telemetry)

**Goal:** Produce a continuous, realistic, parallel stream of events across Blinkit's systems — standing in for what production log shippers / API gateways would emit. This is the layer a judge is really asking about with "what feed is this."

**Expected outcome of this phase:** Two-plus independent generators producing normalized events at a steady rate, with a controlled violation rate so the demo is reliable.

**Procedure:**
1. **Log generator** — emits realistic Blinkit log lines at intervals, e.g.:
   `[timestamp] DEBUG support-service: fetched customer record {phone: "...", address: "..."}`
   Mix of clean lines and PII-containing lines. This models the **exposure** vector (debug logging dumping full objects — see "why engineers still leak PII" discussion: greedy serialization, temporary debug statements left in).
2. **API traffic generator** — emits request/response JSON payloads independently, modeling:
   - `marketing-analytics` events that should carry only hashed IDs but occasionally (intentionally, for demo) carry a raw phone/Aadhaar — models the **purpose-limitation** vector (third-party/vendor over-sharing, analytics event schema copy-pasted from an internal-only type).
   - `delivery-partner-service` payloads referencing onboarding records older than their retention window — models the **retention** vector.
3. Both generators push into a shared in-process async queue — no sequencing dependency (mirrors the Confluent raw-topic pattern, without needing real Kafka at this scale).
4. **Normalizer**: converts each source's raw shape into the Phase 0 event schema, tagging `source_system` correctly.
5. This layer does **no PII detection, no rule checking** — purely produces and normalizes.

**Other breach vectors worth modeling if time allows (stretch, not MVP-blocking):** cache/queue over-retention (a payload representing a Redis-cached user object past its TTL), stale test/staging data (a payload tagged `env: staging` carrying production-shaped PII).

**Exit criteria:** Both streams visibly emitting normalized JSON events at a steady rate via console output, with a demonstrable, controllable violation rate.

---

## PHASE 3 — PII Detection Pass

**Goal:** Cheaply and deterministically filter incoming events down to only those containing PII, before spending compute on registry lookups. This is the layer that answers "how do you know it's actually PII and not a false positive" — deterministic, not LLM-based.

**Expected outcome of this phase:** Every event tagged with a boolean + structured entity list before it reaches the Rule Engine.

**Procedure:**
1. Integrate **Microsoft Presidio Analyzer** as the base engine (per reference repo mapping).
2. Add custom recognizers for identifiers Presidio doesn't cover out of the box:
   - Aadhaar: 12-digit, commonly spaced (`XXXX XXXX XXXX`) pattern
   - PAN: `[A-Z]{5}[0-9]{4}[A-Z]{1}`
   - Indian phone formats (with/without `+91`)
3. Run each normalized event's `fields` (and `raw_snippet` for log-type events, since PII in logs is often embedded in free text, not structured fields) through the Analyzer.
4. Tag: `contains_pii: boolean`, `matched_entities: [{field, entity_type, confidence}]`.
5. Pass through non-PII events without further processing.

**Exit criteria:** Every incoming event correctly tagged; Aadhaar/PAN/phone recognizers verified against seeded test cases from Phase 2's generators.

---

## PHASE 4 — Rule Engine (Policy Decision Point)

**Goal:** Cross-reference PII-flagged events against the Phase 1 registry and produce a structured compliance verdict — fully deterministic, fully decoupled from how it's displayed (OPA-style PDP/PEP separation). **This module is protected — never cut, even under time pressure.**

**Expected outcome of this phase:** A verdict object per violation, correctly attributing severity, rule, and registry match.

**Procedure:**
1. **Check 1 — Exposure** (cheapest, binary, runs first): is raw PII present somewhere it structurally shouldn't be (e.g. plaintext in a debug log, unmasked in a payload meant for a system that shouldn't see raw PII)? If yes → HIGH severity, short-circuit (skip checks 2–3).
2. **Check 2 — Purpose/Consent scope**: look up the field in the registry via `get_registry_entry(field, source_system)`; is it appearing outside its `declared_purpose`/`consent_scope`? (e.g. Aadhaar, `consent_scope: onboarding_kyc`, appearing in a `marketing_events` payload.)
3. **Check 3 — Retention**: `event.timestamp − registry_entry.created_at` vs. `registry_entry.retention_days`. Past the window → violation.
4. Construct the verdict object per the Phase 0 schema, with `remediation_status` initialized to `OPEN`.
5. **Breach-notification tagging**: if `severity == HIGH` and field is high-sensitivity (Aadhaar/PAN) → `breach_notification_candidate: true`. This does not implement the notification workflow — it marks what *would* trigger Section 8(6) obligations, signaling scope-awareness without overreach.
6. Push verdicts to both the LLM Explainer (Phase 5) and Evidence Store (Phase 6) in parallel.

**Exit criteria:** A correct, structured stream of violation verdicts for every deliberately-seeded violation from Phases 1–2, with zero false negatives on the seeded set.

---

## PHASE 5 — LLM Explainer (Guardrailed, statute-grounded)

**Goal:** Turn a structured verdict into a human-readable, statute-cited explanation an auditor can read without needing to reverse-engineer the rule logic — **without** letting the LLM make, alter, or influence any compliance decision.

**Expected outcome of this phase:** Every verdict arrives with either a validated, grounded explanation or a safe deterministic fallback — never blank, never hallucinated.

**Procedure:**
1. Fix `temperature = 0` for deterministic, low-variance output.
2. Build a fixed lookup of actual DPDPA section snippets keyed by `rule_id`, sourced from `india-law-mcp`'s statute database rather than hand-typed text (e.g. `EXPOSURE_001 → Section 8 security safeguards`, `RETENTION_001 → Section 8(7) erasure`). This is the **only** legal text the LLM is ever allowed to see — it never recalls statute text from its own training weights.
3. Construct the prompt: strictly `{verdict_object, matching_section_snippet}` as input — no open-ended "explain this violation" framing that invites improvisation.
4. Enforce structured output against a fixed schema:
   ```json
   { "explanation": "string", "section_cited": "string", "confidence": "float" }
   ```
   Reject and discard any response failing schema validation.
5. **Fact-match/grounding check**: verify every factual token in `explanation` (field name, section number, severity word, system name) actually appears in the input verdict object or section snippet. Anything not traceable to input → discard the output.
6. On any failure (schema or fact-match) → deterministic template fallback: `"Violation: {rule_id} — {field} exposed in {source_system}. See {section}."` Pipeline never blocks on an LLM failure.
7. Enforce one-way data flow: LLM output only annotates the dashboard payload — no write access to registry, no ability to re-trigger Phase 4.

**Stretch (Phase 9, optional, not MVP-blocking):** a secondary ML/LLM-based detector (`pii-masker` / `pII-guard` pattern) run *alongside* Presidio to catch obfuscated PII regex misses — strictly additive signal, never a decision override, and clearly labeled as research-extension in the pitch if demoed.

**Exit criteria:** Demonstrable live failure-and-fallback: feed a malformed verdict, show the fact-match check reject it and the template kick in — this is a rehearsed pitch moment (Phase 8).

---

## PHASE 6 — Evidence Store (the auditor's actual artifact)

**Goal:** Provide an auditable, tamper-evident trail proving violations were caught — this is what turns "we monitor logs" into "we can prove compliance," and is the module Priya (the auditor) actually lives in once a month.

**Expected outcome of this phase:** An append-only, hash-chained log with exactly one mutable field (`remediation_status`) and a working integrity-verification function.

**Procedure:**
1. Build an append-only store (flat file or SQLite table) — every verdict object written immutably, in received order.
2. Hash chain: each entry stores `hash(current_entry + previous_entry_hash)`. Any retroactive tampering with a past entry is detectable via hash mismatch on replay.
3. **Remediation status update path**: the *only* permitted mutation — updating `remediation_status` (`OPEN → ACKNOWLEDGED → RESOLVED`) and `remediation_updated_at` on an existing entry, without altering the entry's original hashed content (status lives outside the hashed payload, or the update is itself appended as a linked follow-on record — decide and document which approach is used, since this is a detail a sharp judge may probe).
4. Expose a `verify_chain()` function: recompute the chain from the full log and confirm integrity — this is what the auditor runs as part of monthly sign-off.
5. Expose a query function: filter by date range, `source_system`, `severity`, `remediation_status` — this is what powers the monthly audit report (Phase 7).

**Exit criteria:** A verifiable, append-only record of every violation from a demo run; `verify_chain()` correctly detects a deliberately-corrupted entry in testing.

---

## PHASE 7 — Dashboard (two consumption modes)

**Goal:** Make the system usable for both audiences at once — the live feed proves real-time detection for the hackathon judges; the audit/evidence view is what Priya actually uses monthly.

**Expected outcome of this phase:** One dashboard, two views, sharing the same underlying data.

**Procedure — Live Feed view (MVP-critical):**
1. Lightweight live-updating view (WebSocket or polling) showing incoming events and flagged violations as they happen.
2. Per violation: rule broken, severity, `source_system`, timestamp, offending field, LLM (or fallback) explanation, `breach_notification_candidate` flag.
3. Basic filtering/sorting by severity or rule type (time permitting).
4. Summary panel: counts by rule type, violation rate over time.

**Procedure — Evidence / Audit view (auditor-critical):**
5. Date-range filter (default: current month) querying the Evidence Store.
6. Breakdown by `source_system` (customers / delivery_partners / support_tickets / marketing_events) and by rule type/severity — this is the "what's wrong and where" view an auditor needs.
7. Per-entry drill-down: full verdict, LLM explanation, statute citation, current `remediation_status`.
8. **Remediation status control**: mark an entry `ACKNOWLEDGED` / `RESOLVED` directly from this view.
9. "Verify evidence integrity" button surfacing `verify_chain()` result — visibly proving the month's record hasn't been tampered with. This is the differentiator to make visible, not backend-only.
10. (Stretch) Export button producing a summarized report (counts, open vs. resolved, integrity-verified) suitable for handing to a manager/regulator.

**Exit criteria:** Both views functional against the same live demo run; the auditor view correctly reflects a `RESOLVED` status change made mid-demo.

---

## PHASE 8 — Integration, Demo Rehearsal & Pitch Prep

**Goal:** Wire every module together, verify the end-to-end flow live, and prepare a pitch that's honest about scope and strong on the auditor value story.

**Expected outcome of this phase:** A working end-to-end demo and a rehearsed pitch that survives Q&A.

**Procedure:**
1. Run all modules end-to-end: registry loads → streams run → PII detected → rules evaluated → LLM explains (or falls back) → evidence stored → live dashboard updates → auditor view reflects the same data.
2. Rehearse triggering a visible violation live on cue (inject a bad log line mid-demo) — show it appear on the Live Feed, then switch to the Evidence view and show it there too, then mark it `RESOLVED` live.
3. Rehearse triggering an **LLM guardrail failure on cue** — feed a malformed verdict, show the fact-match check reject it and the fallback template kick in. Strong, memorable feasibility-round moment.
4. Rehearse the hash-chain verification live — optionally corrupt a test entry beforehand and show `verify_chain()` catch it.
5. Prepare the "what's mocked vs. what's real" slide: Blinkit's DB schema and traffic are simulated; detection, rule evaluation, guardrails, and evidence-chaining are genuine logic that would plug into real log shippers, API gateways, and live schema introspection in production.
6. Prepare the scope-boundary line for Q&A: *"We cover exposure, purpose limitation, and retention — the subset of DPDPA observable in real-time telemetry. Consent validity, breach workflows, DPO/DPIA governance, and cross-border transfer are organizational processes outside what a monitoring agent can detect from logs and payloads alone."*
7. Prepare the "why would a trained engineer even cause this" line: *"This isn't about developer carelessness — debug logging, greedy object serialization, and cross-team payload drift make certain classes of leak structurally inevitable at the pace modern teams ship. That's a detection problem, not a discipline problem — which is exactly why Section 8's 'reasonable security safeguards' is framed as an organizational obligation."*
8. Prepare the auditor-value line: *"The live feed proves detection works in real time. The Evidence Store with remediation tracking is what turns that into something an auditor can actually use a month later — a tamper-proof record of what broke and what's been fixed."*
9. Assign speakers per pitch section (Problem → Architecture → Feasibility split → Team plan) and rehearse handoffs.

**Exit criteria:** Full run-through completed at least twice without manual intervention; every rehearsed failure-mode demo works on cue.

---

## Team Ownership Map (fill in names)

| Module | Owner | First cut if time runs short |
|---|---|---|
| Registry (Phase 1) | | Reduce to 2 tables (`customers`, `delivery_partners`) instead of 4 |
| Ingestion (Phase 2) | | Single generator (logs only), drop API generator |
| PII Detection + Rule Engine (Phase 3–4) | | **Protected — never cut** |
| LLM Explainer + Guardrails (Phase 5) | | Fact-match check first, then LLM layer entirely (template fallback still works standalone) |
| Evidence Store (Phase 6) | | Drop remediation-status UI control, keep the append-only hash-chained log itself |
| Dashboard — Live Feed (Phase 7) | | Filtering/sorting, summary panel |
| Dashboard — Evidence/Audit view (Phase 7) | | Export button; keep drill-down + status toggle |
| Pitch/Docs | | — |

---

## Tech Stack (hackathon-scope, swap freely)

| Component | Choice | Reference |
|---|---|---|
| Backend | Python, FastAPI | — |
| Ingestion/queue | In-process async queue | Pattern borrowed from Confluent Kafka+Faust tutorial, no real Kafka needed at this scale |
| PII Detection | Microsoft Presidio + custom Aadhaar/PAN/phone recognizers | `microsoft/presidio` |
| Rule Engine | Plain Python rule functions, described in PDP/PEP terms | No real OPA/Rego deployment needed |
| LLM Explainer | Existing LLM API key, temp=0, JSON-schema-constrained (Pydantic) | Statute text sourced via `india-law-mcp` |
| Evidence Store | Flat file / SQLite + SHA-256 hash chain | — |
| Dashboard | FastAPI + WebSocket, lightweight frontend (React or plain JS) | — |
| Rule taxonomy validation | — | `amjadali-110/DPDPA-Checklist` (reference only, not code dependency) |

---

## Scope Note — What This Plan Does Not Attempt

DPDPA spans governance, consent infrastructure, and technical controls. This plan deliberately targets only the obligations observable in real-time telemetry: **exposure, purpose limitation, retention**. Consent-notice validity, breach-notification workflow execution, DPO/DPIA governance, children's-data handling, and cross-border transfer rules are organizational processes outside what a log/API/schema monitoring agent can detect — they are not gaps in this plan, they are outside its architectural boundary by design. Auto-remediation (automatically editing/redacting production systems) is likewise out of scope by design: the agent detects, explains, and evidences; fixing the issue remains a human/engineering action tracked via `remediation_status`.
