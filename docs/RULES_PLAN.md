# Plan: a configurable rule engine with guardrails

Status: **plan, nothing built.** Written 2026-10-21. It answers the review that rules should be "condition, context, severity, action, evidence, validation", and that a technical signal must not be presented as a legal verdict.

## 1. Where we are

The rules are code (`rules/engine.py`): `EXPOSURE_001`, `PURPOSE_001`, `RETENTION_001`, `LINKAGE_001`, plus `ERASURE_001` and `NOTICE_001`, `PURPOSE_001` also for schema changes. A field triggers at most one of the first three (checked in order). Severity comes from the data's sensitivity tier, fixed in code. The only customer settings are declarations (fields, purposes, retention, notices, owners, hints), not rules. The dashboard and docs say "violation" in about 45 places.

| Review point | Today |
|---|---|
| Condition | fixed in code |
| Context (service, field, destination, purpose) | service, field, purpose yes; destination shown on the map, not used by a rule |
| Severity | fixed by data tier |
| Action | alert; redaction happens in the agent and tap, set separately from rules |
| Evidence | strong (chain, no raw values) |
| Validation (why did this fire) | partial: the verdict shows rule, field and explanation, not which condition matched |

## 2. What we will build

**Principle:** rules become *data with a safe vocabulary*, evaluated by the engine we already trust. A customer can narrow or add; nothing a customer writes can silently weaken a core protection, and every change is a signed record.

### R0. Spec and spike (small)
- Write the `RuleSpec`: `id`, `version`, `title`, `core` (true for the six built-ins), `condition`, `context`, `severity`, `action`, `evidence`, `wording`.
- **Condition vocabulary (no code, no regex from users):** data kinds in a list; source kinds (log, api, schema, otlp); systems and fields (names and simple `*` patterns); destination patterns; a "declared purpose does / does not include" test; retention state. Clauses combine with AND; OR is a list of rules.
- **Parity harness:** run the existing rule test corpus through old code and the new spec-driven path and require identical verdicts. Nothing ships until this is exact.
- **Chain decision to settle in the spike:** the Go verifier treats every record generically (hash over the canonical body, no per-type logic), so a **new record type `RULE_EVENT` needs no verifier change**; only the server's `verify_chain_detail` replay must learn it. Changing the *verdict* body is riskier, so the "which condition matched" trace is kept in a non-hashed column and only the rule id and version go into the signed record. If the spike disagrees, we stop here.

### R1. Built-in rules as data, with overlays (medium)
- The six rules are written as specs; the existing check functions stay as the evaluators behind them.
- **Overlays** per organization: raise severity freely; lower it only down to a **floor** the core rule defines (Aadhaar, PAN, card and similar never go below HIGH); turn a non-core rule off; change thresholds that are already configurable (retention warn days, observation window).
- Core rules cannot be disabled and their floors cannot be overridden.

### R2. Exceptions with an expiry (medium)
- An **approved exception** ("this system may log phone numbers until 2027-03-31, reason, owner, ticket") suppresses a finding for that scope only, with an end date. It is not a deletion of the rule.
- Suppressed events are still counted and visible ("12 findings covered by exception EX-4"), and an exception that expires reopens the finding.
- **Maker-checker:** one person proposes, a different COMPLIANCE_ADMIN approves (or SUPER_ADMIN, never the proposer). Every proposal, approval, rejection and expiry is a `RULE_EVENT` in the chain.

### R3. Custom rules and a shadow mode (large)
- Customers can add **custom rules** using the safe vocabulary, with a severity and an action, never a legal citation or the label "violation".
- **Shadow mode first (your point B):** a new or changed rule runs against the last N days of stored evidence and live traffic **without raising findings**, and reports "would have fired X times, on these systems". Enabling it is a separate, approved step.
- Custom rules cannot read raw values (there are none to read) and cannot call out to anything.

### R4. Actions (medium)
| Action | Meaning | Status |
|---|---|---|
| `alert` | a finding and the existing alerts | exists |
| `redact` | the rule tells the agent or tap which kinds to mask, hash or drop, delivered the way the org key already is | new wiring over existing redaction |
| `require_review` | opens an owner task that must be confirmed, closed in the chain (reuses the rights-request task machinery) | new, small |
| `escalate` | if unacknowledged after a set time, notify the owner's secondary contact | new, small (owners and alerts exist) |
| `block` | stopping a request or a write | **not built, on purpose** (the tap never blocks; blocking production traffic is a different risk). We say so. |

### R5. Why did it fire, wording, evidence (medium)
- **"Why this fired"** panel on every finding: the rule and version, each condition clause with matched or not, the context values used, the overlay or exception in force. Built from the trace, not re-derived.
- **Wording pass:** "finding" and "possible control failure" in the dashboard, API text and docs. The statute reference stays as context beside the finding ("relates to section 8(1)"), never as a conclusion. Rule ids stay stable. Counsel reviews the wording and the statute snippets.
- Evidence note per rule says what is kept (counts, kinds, system, field) and what never is (values).

## 3. Guardrails (the part that makes it safe)

1. Core rules and their severity floors cannot be removed or lowered by any customer setting.
2. Every change to a rule, overlay or exception is chained, with who proposed, who approved, and when.
3. No change takes effect without a second person (configurable off only for a single-admin organization, and then flagged in the audit pack).
4. Exceptions expire. There is no permanent suppression.
5. Custom rules start in shadow mode.
6. Everything is visible in the audit pack, so an auditor sees the rules in force and every change.

## 4. Decisions (defaults if you do not object)

| # | Question | Default |
|---|---|---|
| D1 | Customers can write their own rules in this release? | Yes, but only after R1 and R2; R3 can be cut if time is short |
| D2 | Maker-checker required for a single-admin organization? | No, but recorded as "self-approved" and shown in the audit pack |
| D3 | `block` action? | Not built; stated in the docs |
| D4 | Who owns the wording and the statute text? | Counsel; the code only displays it |
| D5 | Version | 1.2.0 candidate keeps growing; the rule engine goes into 1.3.0 unless you want it in 1.2.0 |

## 5. Risks

- **Parity.** A rewrite can change what fires. The parity harness is the answer, and R1 does not start before R0 passes it.
- **Chain impact.** Settled in R0 (new record type, trace outside the hash).
- **Scope creep into a legal-rules product.** Counsel owns text; the vocabulary stays small.
- **Performance.** The rule path runs per event: R0 includes a benchmark, and the budget is no measurable slowdown against `docs/PERFORMANCE.md`.
- **A customer weakens protection by mistake.** Floors, maker-checker, expiry and shadow mode.

## 6. Order and evidence

R0 → R1 → R2 → R5 (the wording and "why it fired" view are valuable even before custom rules) → R4 → R3. Each phase ends with unit and API tests, a new step in `tools/trust_e2e.py`, and CI green on a clean machine, the same standard as the earlier plans. Status is recorded in a `RULES_STATUS.md`, scored against the review's six points.

## 7. Not in this plan

Consent management, a public rights portal, data-at-rest scanning, blocking, legal conclusions, a rule marketplace.
