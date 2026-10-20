# Incidents

One debug line in a busy service can produce tens of thousands of findings. Veritas groups findings that are the same problem into one **incident**, so people work on a short list instead of a flood. Grouping is a view: every finding stays in the evidence chain exactly as before.

## What makes two findings "the same"

Five things:

1. the organization,
2. the rule (for example `EXPOSURE_001`),
3. the source system,
4. the field,
5. the **template** of the log line.

The template is the line with everything that changes removed. Detected personal values are removed first (the same masking used elsewhere), then times, ids, addresses, numbers and quoted text become placeholders, and so does every capitalised word, every word with digits in it, and whatever follows an `=`. What remains is the wording of the program.

```
2026-10-20 10:01:02 ERROR payment failed for order 88231 card [CARD_REDACTED] user=asha
  -> <TS> ERROR payment failed for order <N> card <PII:CARD> user=<*>
```

The fingerprint is a hash of those five parts. It is stored; the line itself is not. The template (never the line) is shown in the dashboard.

## What an incident shows

Count of findings, first and last time seen, the highest severity, a count per hour for the last 24 hours, whether any finding is a breach-notification candidate, the status, and how often it has **recurred**. Where the line names a place in the code (a file and line, a stack frame, a logger name), that is shown as a hint for the developer; only file base names are kept, never a path.

The owner comes from the organization settings, per source system:

```yaml
owners:
  payments-service:
    team: Payments
    email: payments@example.com
    slack_channel: "#payments-oncall"
```

## Working with them

Acknowledge or resolve an incident once instead of per finding. Status changes are recorded in the evidence chain (who, when, from, to, why).

**Recurrence.** If an incident is `RESOLVED` and the same fingerprint appears again more than the grace period later (`VERITAS_INCIDENT_GRACE_SECONDS`, default 3600), it reopens as `OPEN` and is marked *recurred*. The system records that as a chain event too. A straggler inside the grace period is counted but does not reopen it.

**Too loose or too tight.** If one incident hides two problems, tick the findings in its detail view and move them to a new incident (*split*). If one problem was split in two, *merge* one incident into the other; later lines of either kind land in the merged incident. Both are chain events.

Resolving an incident does not change the status of its individual findings; those keep their own history in "All findings".

## API

| Request | Role | |
|---|---|---|
| `GET /v1/{org}/incidents?status=&severity=&source_system=&recurred=&limit=&offset=` | any role of the organization | list, with owner and sparkline |
| `GET /v1/{org}/incidents/summary` | any role | counts: findings, incidents, by status |
| `GET /v1/{org}/incidents/{id}` | any role | one incident |
| `GET /v1/{org}/incidents/{id}/verdicts` | any role | the findings behind it |
| `POST /v1/{org}/incidents/{id}/status` `{"status": "ACKNOWLEDGED" or "RESOLVED", "reason": "..."}` | COMPLIANCE_ADMIN | chain event |
| `POST /v1/{org}/incidents/{id}/merge` `{"merge_from": "<id>"}` | COMPLIANCE_ADMIN | chain event |
| `POST /v1/{org}/incidents/{id}/split` `{"verdict_ids": ["..."]}` | COMPLIANCE_ADMIN | chain event |

## Settings

| Variable | Default | |
|---|---|---|
| `VERITAS_INCIDENTS` | `on` | `off` stops grouping (findings are stored as before) |
| `VERITAS_INCIDENT_GRACE_SECONDS` | `3600` | how long after resolution a returning finding is treated as a straggler |

## Integrity

An incident's status is a cache of its chain events, like a verdict's: **Verify chain** replays the events and reports `STATUS_CACHE_MISMATCH` if the table disagrees, and the stand-alone verifier hashes them like any other record. Which finding belongs to which incident is *not* signed: it can be recomputed and is meant to be corrected by an analyst.

## Older findings

Findings stored before this release are grouped on the first start, in the background, by rule, source system and field only (their wording was never kept; the template reads "finding from before grouping"). They start `OPEN`; resolve them like any incident.

## Limits, said plainly

- A template that is too loose merges unrelated problems; too tight splits one problem in many. That is why split and merge exist.
- The template keeps short lower-case words. A personal name the detector missed, written in lower case on its own, would stay in it. The template is shown to staff in the dashboard and is never sent anywhere.
- Grouping follows what the detector reads. If it takes a number in a line for a phone number on some lines and not on others, those lines get a different template and a different incident (in the CI scenario, 6,039 findings from four kinds of line became 13 incidents: four large ones and a few small ones). Split and merge exist for this.
- Lines that are structurally the same but whose only difference is wording (a changed message text) are different incidents.
- Cost: grouping adds a few microseconds to the template and three small writes to storing a finding; measured on a laptop, storing 12,000 findings ran at about 4,800 per second with grouping against about 6,400 without (detection, at about 90 to 300 events a second, is the limit, not storing).
