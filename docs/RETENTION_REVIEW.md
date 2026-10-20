# Retention review

Your policy declares how long each kind of data may be kept (`retention_days`, and optionally `data_since`). The retention review shows, for every declared field, **when that period runs out and whether data of that kind is still being seen in that system**, warns the owner in time, and tracks the follow-up to a confirmed close.

It never deletes anything. Veritas does not see data at rest: it sees what passes through logs, API payloads and database schema statements. So the review says what it can see, and says it plainly.

## The statuses

| Status | Meaning |
|---|---|
| **within** | the declared period has not run out |
| **due soon** | it runs out within `VERITAS_RETENTION_WARN_DAYS` (default 14) |
| **overdue** | it has run out **and** data of this kind was seen in this system in the last `VERITAS_RETENTION_OBSERVED_DAYS` (default 7): someone should confirm it was purged, or justify keeping it |
| **past, not seen** | it has run out but nothing has been seen lately (shown for information, no alert) |
| **not observed** | nothing has ever been seen for it and the policy sets no `data_since`, so there is no clock |

**The clock** starts at the field's `data_since` if the policy sets it (set it when you onboard a system that already holds old data), otherwise at the first time Veritas saw data of that kind in that system. A sighting matches a declared field by the field's own name (so `user.phone` in an API payload counts for `phone`) or by its kind of data.

## The loop

1. **Warn.** The daily maintenance run raises the existing alerts (webhook or e-mail), once, and again if still unresolved after a day: `retention_due_soon_<org>` and `retention_overdue_<org>`. They name the systems and fields, never values.
2. **See.** *Data map, Retention review*: each field, its period, when it runs out, its status, the owner, and whether a task is open.
3. **Ask.** *Open task* (compliance administrators) creates a rights-request-style task of type `retention`: one task for the system's owner, recorded in the evidence chain, with the review's findings kept for the record. There can be only one open retention task per system.
4. **Confirm.** The owner confirms (Rights requests page, or `POST /v1/{org}/requests/{id}/tasks/{system}/confirm`). When every task is confirmed the request closes; both steps are chain entries, and a record can be downloaded (PDF or signed JSON, titled "Retention review record").
5. **Check.** If data of that kind is still seen after the task closed, the field is **overdue again** with no open task, and a new task can be opened. That is the verification: not "it was deleted", but "it was confirmed and it did not keep arriving".

## API

| Request | Role |
|---|---|
| `GET /v1/{org}/retention` | any role of the organization |
| `POST /v1/{org}/retention/tasks` `{"systems": ["support-ticketing"]}` | COMPLIANCE_ADMIN |

## Settings

| Variable | Default |
|---|---|
| `VERITAS_RETENTION_WARN_DAYS` | 14 |
| `VERITAS_RETENTION_OBSERVED_DAYS` | 7 |

## Limits, said plainly

- **It does not see data at rest.** "Overdue" means "the declared period has run out and data of this kind was still seen lately". Data sitting in a database that no longer appears in any log is not visible here.
- **It never deletes or changes anything** (`dpdpa-agent/docs/scope.md`). "Closed" means a person confirmed their system, and the data was not seen again.
- The clock starts when Veritas first saw the data unless you set `data_since`, so a system onboarded late looks younger than it is until you say otherwise.
- It does not know of legal reasons to keep data longer (sector rules, litigation holds). Record those in the policy and in the task's confirmation note.
