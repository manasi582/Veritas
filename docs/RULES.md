# Rules: what is in force, how to change it, and why a finding fired

Veritas has six core rules. Each one reports a **possible control failure**: a technical signal. Whether something is a breach of the Act is for the organization and its counsel; a finding shows the related section of the Act as context beside it, never as a conclusion.

| Rule | Looks at | Related section (context only) |
|---|---|---|
| `EXPOSURE_001` Personal data where it should not be | a log, or a system declared de-identified-only, carried personal data | 8(5) security safeguards |
| `PURPOSE_001` Personal data without a matching declaration | personal data (or a new personal-data column) the policy does not declare for that system | 4 and 6 |
| `RETENTION_001` Data held longer than declared | data still seen past the declared period | 8(7) |
| `LINKAGE_001` Fields that identify a person together | a combination of fields the policy names appeared in one event | none |
| `ERASURE_001` An erased identifier appeared again | an identifier whose erasure request was closed was seen again | 8(7), 12(3) |
| `NOTICE_001` Data without a current notice | a kind of data in a system that no current notice recorded in the policy covers | 5 |

The section references are drafts for counsel to confirm (see `docs/legal`). Each rule's spec (what it looks at, its default severity, what evidence is kept, its wording) is in `dpdpa-agent/rulebook/specs.py` and shown on the **Rules** page and by `GET /v1/{org}/rules`.

## What an organization can change

Only through a **proposal that a second person approves** (a single-administrator organization may approve its own; that is recorded as *self-approved* and shown in the audit pack). Each step is a signed `RULE_EVENT` in the evidence chain and an entry in the audit log.

**Overlay** on a rule:
- **Severity.** Raise freely. Lower only down to the floor for the finding's kind of data: **Aadhaar, PAN, card, passport and voter findings never go below HIGH**, and `ERASURE_001` never goes below HIGH. Never above what the engine decided, by a floor.
- **Actions** (default `alert`):
  - `require_review`: once per incident, a task for the system's owner; confirming it is a chain entry (a "review" request on the Rights requests page).
  - `escalate`: if the incident is still unacknowledged after the stated minutes (15 to 10080), one more alert naming the owner's `escalation_contact` (a new optional field of `owners` in the policy). It goes through the alert channels already configured; it does not contact the person itself.
  - `redact`: the organization's agents are told to mask, hash or drop the named kinds of data (for example `{"phone": "mask"}`). This only makes an agent stricter than its own configuration, never looser, and is removed when the rule is changed back. Hash needs the organization's key and is applied as mask until the agent holds it. **Agents only:** the Payload Tap is configured in the service's code and does not take this from the server.
  - There is **no block action**. Veritas never stops a request or a write.
- A core rule **cannot be switched off**: there is no such setting.

**Exception**: a bounded suppression, for "known and accepted, until a date".
- Names the rule, a system and/or a field (patterns with `*`), a reason, an owner, and an end date no more than 180 days away (`VERITAS_EXCEPTION_MAX_DAYS`). It must narrow to a system or a field.
- Findings inside it are **not stored and not alerted**, but are **counted against the exception** ("findings covered") so they stay visible. When it ends (a chained `EXPIRED` event, checked every minute) or is revoked, findings are raised again.
- A finding that is a **possible breach candidate is never suppressed**; its trace says the exception did not apply.

## Why did this fire

Open a finding's **Details**, or `GET /v1/{org}/findings/{n}/why`. It shows the rule and its version, each condition of the rule answered (matched or not, with the detail: the system, the field, the declared retention against the age of the data, and so on), the severity the rule gave and the severity after the organization's approved setting, and any exception considered. It is built when the finding is raised from names, kinds of data and dates; it holds no value from the data. It is kept beside the finding, outside the signed record, so the chain's format is unchanged. Findings raised before this release have no trace and say so.

## Roles

Anyone with access to the organization can read the rules, changes and traces. Proposing, approving, rejecting, withdrawing and revoking need COMPLIANCE_ADMIN (SUPER_ADMIN has it too). The proposer cannot approve their own change unless they are the only administrator. Only the proposer can withdraw a proposal. Revoking an approved exception (which only tightens) takes one person. Changing an overlay back is a new proposal that needs approval.

## What is not here

Customer-written rules (the plan's R3), a block action, per-field severity beyond the rule, and rules for legal obligations Veritas cannot see. The statute context and the wording are for counsel to review.

## Tests

`rulebook/test_rulebook.py` (floors, approvals, chain replay and tamper detection, exceptions, traces, review tasks, escalation, redaction asks), `api/test_rulebook_api.py` (roles, two-person approval, single-admin self-approval, the why endpoint), the agent's `test_redaction.py` (the server floor), the notice sweep test, the audit-pack summary test, the browser smoke test (Rules page, why panel), and the end-to-end scenario's rules step (two administrators, one review task, an exception that counts and spares a breach candidate, a trace, the agent taking the redaction floor, the chain still valid and the verifier accepting it).
