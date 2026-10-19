# Evidence record format

For auditors, and for anyone writing a verifier. This is exactly what the chain hashes, so that an independent program can check evidence without trusting the dashboard. Golden test vectors that every implementation must reproduce are in [`tests/vectors/`](../tests/vectors/): `chain_v0.json` and `chain_v1.json`. The code is `dpdpa-agent/evidence_store/canonical.py` (the format) and `store.py` (the chain).

Each organization has its own chain. Records are checked in the order they were written.

## hash_version 0 (every record made before release 1.1.0)

```
record_hash = lowercase_hex( SHA-256( payload_json + previous_hash ) )     // payload_json then previous_hash, UTF-8
```

`payload_json` is the exact text stored for the record (a JSON object of the verdict's fixed fields, written by Python's `json.dumps(..., sort_keys=True)`); to verify a version 0 record, hash the stored text as it is, do not re-serialize it. The first record of an organization uses `previous_hash = "DPDPA-AGENT-GENESIS-2026"`. Version 0 records are never rehashed; the migration only adds columns around them.

## hash_version 1 (records written from release 1.1.0)

```
hash_input  = "veritas-chain-v1" LF previous_hash LF canonical_json(record_body)        // LF = one 0x0A byte
record_hash = lowercase_hex( SHA-256( hash_input as UTF-8 ) )
```

The first version 1 record of an organization that already has records continues from the last version 0 hash; an organization with none starts from the genesis string above.

**Canonical JSON.** UTF-8; no whitespace outside strings; object keys sorted by their UTF-8 bytes; values are strings, integers, objects or arrays only (no floating point, no booleans: a flag is `0` or `1`, a fraction is a whole number such as `confidence_permille`); a member whose value is null is left out; in a string only `"` and `\` are escaped with a backslash, control characters U+0000 to U+001F are written as `\u00xx` with lowercase hex, and every other character is written as itself. Timestamps are RFC 3339 UTC with exactly three fractional digits and a `Z`.

**Record body.** It never contains the hash or the previous hash. Every body has `type`, `org` and `seq` (the record's position in its organization's chain, 1, 2, 3 ...), so a record cannot be moved to another place or organization without changing its hash.

| `type` | Other members |
|---|---|
| `VERDICT` | `verdict_id`, `event_id`, `rule_id`, `severity`, `source`, `source_system`, `field`, `timestamp`, `matched_registry_entry` (omitted if none), `breach_notification_candidate` (0/1), `explanation`, `section_cited`, `confidence_permille`, `used_fallback` (0/1) |
| `STATUS_CHANGE` | `event_id`, `target` (a verdict id), `old_status`, `new_status`, `actor`, `reason` (omitted if none), `at` |
| `COMMENT` | `event_id`, `target`, `actor`, `text_sha256` (SHA-256 of the comment text, which is stored beside the chain, not in it), `at` |

A verdict's status is its status when written (`OPEN` for new records) followed by its `STATUS_CHANGE` events in order. The `remediation_status` column in the database is only a cache of that result; the check recomputes it and reports a difference as tampering.

## What the dashboard check verifies

1. every record's hash, using the rule for its `hash_version`;
2. every `previous_hash` equals the previous record's hash, and `seq` counts 1, 2, 3 without a gap;
3. for a verdict, the plain summary columns used for the overview counts equal the signed record;
4. every event is about a verdict of the same organization, and each status change is a valid step from the status before it;
5. every verdict's cached status equals the replay of its events.

It reports the first record that fails and why: `HASH_MISMATCH`, `CHAIN_BREAK`, `SUMMARY_MISMATCH`, `EVENT_INVALID` or `STATUS_CACHE_MISMATCH`.

## What this check cannot do

Someone who can write to the server's disk can edit a record **and recompute every later hash**, and this check will then pass. Deleting the newest records is also invisible to it. Closing that gap is the job of external anchoring and the stand-alone verifier (the next phase of the plan in `docs/TRUST_VISIBILITY_PLAN.md`).
