# Observed processing map and record

A picture of which systems produce which kinds of personal data, set against what the policy declares, and a record you can hand to an auditor. It is called **observed** because that is what it is: what Veritas has seen in the logs it received since it began counting. It is not a complete data map, and the record does not claim to satisfy any particular legal requirement.

## What is counted

For every event that contained personal data, Veritas counts, per organization:

| | |
|---|---|
| system | the event's `source_system` |
| field | the field the data was found in (`raw_snippet` for free text) |
| kind of data | aadhaar, pan, phone, email, name ... (the same labels as the masked placeholders) |
| destination | a host name, only when the event names one (below), otherwise empty |
| count, first seen, last seen | events, not values |

**Never stored here:** the value, the log line, an identifier, a URL path or query, credentials or a port. Counts are kept in memory and written in batches every few seconds; a crash loses at most that batch of counts (they are not evidence and are not in the chain). Events sent to the Scan Sandbox are counted like any other event stored by the server.

## Where destinations come from

Two places only, so an edge is a fact the log stated:

1. a structured field named `destination`, `dest`, `target`, `target_url`, `endpoint`, `url`, `host`, `upstream`, `sink` and similar;
2. a URL in the text straight after a word that says it was sent: `to`, `->`, `calling`, `posting to`, `uploaded to`, `forwarded to`, `POST`, `GET`, `PUT`.

Only the host name is kept. If the host is another system of the organization, the edge is *internal*; otherwise it is an *outside destination*. Logs that do not name a destination give you the systems and kinds of data but no edges. (Traces and agent-side hints can add more later.)

## Colours

| Colour | Meaning |
|---|---|
| red | the system has an open incident (acknowledged still counts as open) |
| amber | a kind of data was observed there that its declared fields do not cover |
| green | everything observed is declared and nothing is open |
| grey | declared in the policy, never observed |

"Declared" means a declared field of that system whose data category or field name is, or contains as a word, the observed kind (for example `phone_number` covers phone). Name your categories so they say what the data is.

## The record

*Data map*, **Record (CSV)** or **Record (PDF)**, or `GET /v1/{org}/flows/export?format=csv|json`. One row per declared field (purpose, consent scope, retention, whether it was observed, how many events, first and last seen, open incidents), one per kind of data observed but not declared, and one per destination. The title is "Record of observed processing". Cells that start with `=`, `+`, `-` or `@` are prefixed so a spreadsheet cannot run them.

## API

| Request | Role |
|---|---|
| `GET /v1/{org}/flows` | any role of the organization |
| `GET /v1/{org}/flows/export?format=csv|json` | any role of the organization |

Setting: `VERITAS_FLOWS=off` stops counting.

## Limits, said plainly

- It shows what was observed, since counting began. History before that is not reconstructed.
- A line that does not name its destination produces no edge; a data flow that does not appear in a log does not appear here.
- Detection is probabilistic, so counts are indications, not an inventory.
- Colours come from the declared policy; an undeclared kind of data is a question to ask, not a finding of non-compliance.
