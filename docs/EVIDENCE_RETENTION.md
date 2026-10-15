# Evidence growth and retention: design note

**Status: a decision is needed before anything is built.** This note sets out the problem and the options so the decision can be made once.

## The problem

Every finding is appended to a per-organization hash chain: each record's hash covers the record and the previous hash. That is what makes the evidence tamper-evident, and it is also why a record cannot simply be deleted: removing one breaks every hash after it. The database therefore only grows. The DPDPA expects data to be kept no longer than needed, so customers will ask how old evidence is retired.

What grows, per finding: the encrypted payload (a few KB) plus an index row. Rough sizing to be confirmed by the load test: 1 million findings is on the order of a few GB.

## What exists today

- `veritas_database_bytes` (metrics) and the disk warning show growth.
- Backups are kept for 7 days by default (`VERITAS_BACKUP_KEEP`); they are full copies, so they grow with the evidence.
- Nothing retires old evidence.

## Options

| Option | How it works | Keeps the proof | Cost |
|---|---|---|---|
| **A. Do nothing; size the disk** | Document growth per million findings and the disk to provision. | Fully | None. Fine for a pilot. |
| **B. Archive and checkpoint** | After N years, export the oldest records to a signed archive file (the records plus their hashes), then replace them in the live database with one **checkpoint record** that carries the last archived hash. The chain keeps verifying from the checkpoint; the archive verifies on its own and can be put on cheap storage or removed by policy. | Yes: the checkpoint binds the remaining chain to what was archived | A new record type, an export and verify tool, restore rules. About 3 to 5 days. |
| **C. Redact payloads, keep hashes** | After N years, delete the encrypted payload but keep the hash and the metadata. The chain still verifies (hashes stay), the personal data is gone. | Mostly: the chain proves records existed, not their content | Smaller. About 2 days. Matches "delete personal data after its purpose". |

## Recommendation

Do **A** now, document the sizing once the load test gives numbers, and build **C** first when a customer asks (it answers the legal question: personal data does not live forever), then **B** only if databases become too large.

## Decisions needed

1. What retention period should the product offer by default (for example 3 years of payloads, hashes forever)?
2. Should retirement run by itself (a scheduled job) or only by an administrator's command?
3. Is a signed export (option B) wanted, or is deleting payloads (option C) enough?
