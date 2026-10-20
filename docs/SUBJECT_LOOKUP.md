# Identifier lookup and rights requests

*Where has this person's identifier been observed?* Veritas can answer that without keeping the identifier, and can track a rights request (access, erasure, correction) from the first lookup to a signed record.

## What it does and does not claim

- It reports where Veritas **observed** an identifier in the logs it received: which systems, how many events, first and last seen.
- It does **not** say data is erased everywhere. A closed erasure request records that each system's owner confirmed their system. The record says so in words and is never called a certificate.
- It cannot see systems that send no logs to Veritas, copies outside logs, backups, or data that was never logged.
- It handles structured identifiers only: phone, e-mail, Aadhaar, PAN, card. **Names cannot be matched this way** (an exact hash does not suit them).

## How it keeps no identifier

When Veritas sees a structured identifier it reduces it to a canonical form, then stores only `HMAC-SHA256(organization key, canonical form)`, counted per system. A lookup does the same to the identifier that was typed in and reads the counts back. The identifier you type is used in memory and dropped: it is not stored, not logged, not in the audit log (which keeps a short token prefix) and not repeated in an error message. Tests scan the database file, the logs, the audit log and every response for it.

| Kind | Canonical form |
|---|---|
| phone | digits only, `+91` or a leading `0` removed, last 10 digits |
| e-mail | trimmed, lower case |
| Aadhaar | digits only |
| PAN | trimmed, upper case |
| card | digits only |

So `+91 98765 43210`, `09876543210` and `91-9876543210` are one identifier. (Writing the number with a space in the middle of the digits is something the *detector* does not recognise in a log line, but a lookup accepts any of the forms above.)

## Keys

One random 32-byte key per organization and purpose, encrypted at rest like the evidence records, never part of an export:

| Purpose | Used by |
|---|---|
| `lookup` | the server, for identifiers it sees in clear |
| `agent` | agents in **hash mode**: the server delivers it to the organization's agents over TLS at registration and at the next heartbeat after a rotation, and needs it to look the same identifiers up again |

Every key has an id (6 hex characters of a hash of it) which every token carries, so **rotation never breaks old tokens**: a lookup tries every key that is not retired. `POST /v1/{org}/subjects/keys/rotate` makes a new key; `.../retire` stops trying one, which is what to do if a host that held the agent key was compromised (its tokens can then no longer be found). A key in an agent's own configuration (`hash_key`) takes precedence over the delivered one; tokens made under it can be looked up only if the server knows that key, so prefer the delivered key.

**Say this plainly to customers:** a phone number has few possible values, so anyone who holds both the key and the tokens can test guesses. Protect the key like a password. A backup contains the keys (a backup contains every key needed to read it): keep backups as protected as the server.

## The workflow

1. **Create a request** (type, an opaque reference such as a ticket number, received date, optional due date, one or more identifiers). Veritas looks each one up, makes **one task per system** where it was observed (the owner comes from the organization's `owners:` settings, otherwise "unassigned"), and writes `CREATED` and `TASKS_CREATED` to the evidence chain. The reference may not look like an identifier (it is refused if it contains one).
2. **Owners confirm** their task (a compliance administrator records it). Each confirmation is a chain entry.
3. **The request closes** when every task is confirmed (or, if nothing was observed, when an administrator closes it). `CLOSED` is a chain entry.
4. **Resurrection watch.** When an *erasure* request closes, its tokens join a watch list. If the identifier is observed again in a later event (clear, or hashed by an agent) Veritas raises a finding under a new rule, **`ERASURE_001`** (HIGH): "an identifier for which an erasure request was closed was observed again". It says it cannot tell whether the data was collected again, a copy was not erased, or the number now belongs to someone else.
5. **The record**: `GET /v1/{org}/requests/{id}/record.pdf` and `record.json`. It lists what was asked, what was observed where, who confirmed what and when, the chain entries (sequence numbers and hashes) the facts rest on, and the chain head at that moment. It is **signed with Veritas's Ed25519 key** (the key that signs anchoring checkpoints): `record.json` holds `{record, signature}`; the signature covers the canonical JSON of `record` with null members omitted (see `EVIDENCE_FORMAT.md` for the rules). The PDF prints the same signature and key.

Status changes of a request are a cache of its chain entries: **Verify chain** replays them and reports `STATUS_CACHE_MISMATCH` if the table disagrees.

## Deadlines

Veritas shows a due date only if one is entered on the request or the administrator has set `VERITAS_RIGHTS_RESPONSE_DAYS`. There is no default: confirm the current response periods under the DPDPA Rules first.

## API

| Request | Role |
|---|---|
| `POST /v1/{org}/subjects/lookup` `{category, identifier}` | COMPLIANCE_ADMIN; 30 per minute per user; every call, and every refusal, is audited |
| `POST /v1/{org}/requests` `{type, requester_ref, received_at?, due_at?, identifiers:[{category, identifier}]}` | COMPLIANCE_ADMIN |
| `GET /v1/{org}/requests`, `GET /v1/{org}/requests/{id}` | AUDITOR and above |
| `POST /v1/{org}/requests/{id}/tasks/{system}/confirm` `{note?}` | COMPLIANCE_ADMIN |
| `POST /v1/{org}/requests/{id}/close` `{reason?}` | COMPLIANCE_ADMIN |
| `GET /v1/{org}/requests/{id}/record.pdf`, `record.json` | AUDITOR and above (audited) |
| `GET /v1/{org}/subjects/keys` (ids and dates only), `POST .../keys/rotate`, `POST .../keys/retire` | AUDITOR and above to list; COMPLIANCE_ADMIN to change |

## Limits, said plainly

- Only identifiers Veritas saw, only in the logs it received, only since it began indexing.
- An identifier that appears with a space inside the digits of a log line is not recognised by the detector, so it is not indexed.
- A number that now belongs to someone else matches the old token: `ERASURE_001` is a question to ask, not a finding of fault.
- Agent tokens made under a key the server does not hold (a key written in an agent's file) are kept but cannot be found.
- Verifying the record's signature needs the public key shown in it; trusting that key needs it to have been recorded elsewhere (for example the key id in your anchoring export).
