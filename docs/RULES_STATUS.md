# Rules: status

Built 2026-10-21 against [RULES_PLAN.md](RULES_PLAN.md) (unchanged). **R3 (customer-written rules) was skipped by decision.** How it works: [RULES.md](RULES.md).

| Phase | What | State |
|---|---|---|
| R0 | Rule specs as data; with nothing configured the engine's findings are unchanged | Done. The rule layer is an overlay applied after the engine, so the engine and its tests are untouched; a test holds the layer to the engine's exact answers. |
| R1 | Overlays: severity with floors, actions; core rules cannot be switched off | Done |
| R2 | Exceptions with an end date, maker-checker, chained | Done |
| R5 | "Why this fired" panel and API; wording pass; evidence note per rule | Done (counsel still has to review the wording and the statute context) |
| R4 | Actions: alert, require_review, escalate, redact | Done, with limits below. `block` is deliberately not built. |
| R3 | Customer-written rules and shadow mode | **Skipped** |

## Against the review's six points

| Point | Before | Now |
|---|---|---|
| Condition | fixed in code | Fixed in code, but each rule's conditions are written down as data and shown. Customers cannot define conditions (R3). |
| Context | service, field, purpose | Unchanged; destination still only on the map. An exception can scope by system and field. |
| Severity | fixed by data tier | Configurable with floors, approved by a second person |
| Action | alert; redaction set separately | alert, require_review, escalate, redact (agents); no block |
| Evidence | strong | Strong; rule changes are now in the chain, the audit pack lists the rules in force and self-approvals |
| Validation | partial | A per-finding trace answers each condition; the rule's version and the approved settings are recorded |

The review's remaining ask, "arbitrary custom policies must not silently bypass guardrails", is met for what exists: nothing a customer can set removes a core rule or its floors, and every change is approved and chained.

## Limits that stay true

- **Customers cannot write their own rules** (R3 skipped). They can tune, scope and extend the actions of the six.
- **Redact reaches agents only**, takes up to one heartbeat (30 s) to arrive, only makes an agent stricter, and does not change an application's own log files. The Payload Tap does not receive it.
- **Escalate** uses the alert channels already configured and names the contact; it does not page the person. Without configured channels nothing is sent.
- **Traces exist only for findings raised after this release.** Older findings say so.
- **Exceptions suppress storage, not detection:** the finding is counted but its details are not kept. A breach candidate is never suppressed.
- **The `block` action does not exist.**
- **Statute context and the new wording are drafts for counsel.** The dashboard's internal audit-log action names (for example `VIOLATION_ACKNOWLEDGED`) and API field names keep their old identifiers so existing integrations do not break.
- The browser smoke test for the Rules page has not been run on a real browser from this machine; CI runs it.

## Evidence

Unit and API tests as listed in RULES.md; the end-to-end scenario passes locally (stand-in detection) with the rules step, and CI runs it with the real model.
