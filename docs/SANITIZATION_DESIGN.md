# Sanitization and downstream forwarding (Mode B): design

**Status: design agreed on 2026-10-18, not built.** Decisions below were proposed and accepted; the build is a separate go-ahead. Source requirement: `docs/ENTERPRISE_TELEMETRY_SPEC.md`, "Mode B: Inspect + Sanitize + Forward" and "Priority 7".

## What it is

Today Veritas reads a log line, records what is wrong with it, and stops. Many customers also want the line itself passed on to their own storage or SIEM, with the personal data masked.

```
Application log  →  Agent  →  Veritas (detect, decide, mask)  →  customer's HTTP endpoint / syslog
```

Only Veritas ever holds the raw line. The agent stays a plain forwarder and needs no change.

## The three output actions (set per organization)

| Action | What the destination receives |
|---|---|
| `raw` | The original line, unchanged. (Mode A.) |
| `sanitized` | The line with every detected personal-data value replaced by a placeholder. |
| `compliance-metadata-only` | No log text at all: one record per finding (organization, rule, severity, field name, source system, time, violation number, statute). |

The default is **no forwarding**: nothing is sent anywhere unless an administrator sets a destination. An optional override per source system lets one noisy application be treated differently from the rest.

## Masking

`masking.py` already replaces a value with `[<CATEGORY>_REDACTED]` (for example `[AADHAAR_REDACTED]`) and is used in scan responses today. Mode B reuses it.

- Default style: the placeholder token.
- Optional style: partial mask that keeps the last 4 characters (`XXXXXXXX9012`), for customers who need to match a record by its tail.
- Not offered: reversible tokens or hashing. They need key management and bring back a re-identification risk this product exists to reduce.

A value that was detected is masked wherever it appears in the line, including a second copy.

## Hard rules

1. **A `sanitized` or `compliance-metadata-only` destination can never receive a raw line.** The sender takes the already-masked text from the masking step; there is no code path that hands it the original. A test sends known personal data through every action and asserts that none of it appears at a sanitized destination.
2. **If masking fails or is unsure, nothing is sent.** Any error in detection or masking for a line means that line is held back and counted, not forwarded as-is.
3. A destination's address and credentials are administrator-set only (settings, not the API), and secrets are never shown in the dashboard or the support bundle.

## Connectors (first version)

| Connector | Details |
|---|---|
| HTTP(S) | POST, one JSON object per line (or batched), optional bearer token or header, TLS verification on by default. |
| Syslog | RFC 5424 over TCP, optionally TLS. |

Object storage (S3-compatible) and others come when a customer asks; the connector interface is small so they are additive.

## Delivery

Forwarding must never slow down or lose detection.

- Forwarding runs after detection and storage, off the request path.
- Lines wait in an on-disk queue (a separate small database) and are sent in batches.
- If the destination is down: retry with growing waits. The queue holds up to a size limit (default 1 GB or 24 hours). When it is full the **oldest** lines are dropped and counted.
- Delivery is at-least-once: a line may arrive twice after a retry; each carries a unique id so the receiver can drop duplicates.
- The health card, `/metrics` and the alerts get: queue depth, oldest waiting line, delivered, failed, dropped.

## Settings

Per organization, in the dashboard (administrators only) and the existing policy: action, destination, masking style, optional per-source override, test button ("send a sample line"). Changes apply at once and are written to the audit log.

## What this does not do

- It does not change what is stored in the evidence database (that already holds no personal data values).
- It does not rewrite the log files on the source machine.
- It does not guarantee that personal data the detector cannot recognise is masked. Detection is probabilistic; the documentation and the dashboard say so next to the setting.

## Build plan and effort (about 4 to 5 days)

1. Settings model and migration, audit log entries (0.5 day).
2. Forwarding queue with retry, limits and metrics (1 day).
3. HTTP and syslog connectors with TLS (1 day).
4. The three actions and masking styles wired into the event path (0.5 day).
5. Dashboard settings page and the test button (0.5 day).
6. Tests: the "no personal data at a sanitized destination" test over a corpus, outage and recovery, queue limit, duplicate ids, load test with forwarding on (1 day).
7. Documentation and a security review addendum (0.5 day).

## Open points for the first customer who wants it

- Which SIEM, and so which format (plain JSON, CEF, or their vendor's schema).
- Whether they need partial masking, and for which fields.
- Their retention for the queue if the destination is down for longer than a day.
