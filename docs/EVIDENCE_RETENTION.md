# Evidence growth and retention: design note

**Decision recorded (2026-10-15): anything that retires evidence runs only on an administrator's command, never by itself.** Nothing has been built yet; the rest of this note says why that is reasonable and what to build when it is needed.

## What is stored, and what is not

Veritas does **not** keep the personal data it finds. Detection runs in memory; what is written to the evidence database per finding is the verdict: organization, rule, severity, field name, source system, time, the statute reference and the explanation text, chained to the previous record by a SHA-256 hash (`evidence_store/store.py`, `schemas/models.py`). There is no matched value in it. (Free text typed by staff in case comments is stored as typed.)

So retiring evidence is **not** a privacy duty in the way deleting a customer database is. The reasons to retire it are size, and a customer's own record-keeping policy.

## The problem

Each record's hash covers the record and the previous hash, which is what makes the evidence tamper-evident. A record therefore cannot simply be deleted: every hash after it would stop matching. The database only grows. What grows per finding is one encrypted record of a few KB plus an index row; the load test will give a real number. `veritas_database_bytes` (metrics) and the disk warning show it.

## Options

| Option | How it works | Keeps the proof | Cost |
|---|---|---|---|
| **A. Do nothing; size the disk** | Document growth per million findings and what disk to provision. | Fully | None. Right for a pilot. |
| **B. Archive and checkpoint** (on command) | `veritas retire-evidence --older-than <years>` exports the oldest records of an organization, with their hashes, to a signed archive file, then replaces them in the live database with one **checkpoint record** that carries the last archived hash. The remaining chain keeps verifying from the checkpoint; the archive verifies by itself and can be stored or removed under the customer's policy. A dry run shows what would move. | Yes. The checkpoint binds the live chain to the archive. | A new record type, export and verify tools, rules for restore. About 3 to 5 days. |
| **C. Redact payloads, keep hashes** | Delete the record's content after N years, keep the hash and metadata. | Partly: the chain proves records existed, not what they said | About 2 days. Not recommended: it throws away the explanations, and there is no personal data in them to protect. |

## Recommendation

Do **A** now and write the sizing into the operations guide once the load test has a number. Build **B**, as an administrator's command with a dry run, when a database approaches the size a customer is willing to keep online. Do not build C.

## Still to decide when B is built

1. The default age (for example 5 years), or no default and the administrator must name it each time.
2. Whether the archive is signed with a key held on the server, or only checksummed.
