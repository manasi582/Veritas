# Audit pack

One zip an auditor, a customer's security team or the Data Protection Board can take away and check **without Veritas**: no server, no network, no login.

`GET /v1/{org}/audit-pack` (roles AUDITOR, COMPLIANCE_ADMIN and above; every download is recorded in the audit log). The dashboard has a **Download audit pack** button on the Audit Ledger page.

| File | What it is |
|---|---|
| `evidence.jsonl` | The whole chain, as `GET /v1/{org}/evidence/export` ([EVIDENCE_FORMAT.md](EVIDENCE_FORMAT.md)) |
| `checkpoints.jsonl` | The signed checkpoints ([ANCHORING.md](ANCHORING.md)) |
| `veritas.pub` | The public key that verifies them |
| `SUMMARY.md`, `summary.json` | The chain, the server's own check, open incidents, retention and notice counts, and what the pack does not prove |
| `VERIFY.md`, `verify.sh`, `verify.bat` | How to check it, and a script that runs the stand-alone verifier |
| `veritas-verify*` | The verifier binaries, only when `VERITAS_VERIFIER_DIR` names a folder holding them (the release assets) |
| `MANIFEST.sha256` | A hash of every other file, so a changed file is noticed |

## What it proves, and what it does not

The independent check (`veritas-verify`) shows that the records match the signed checkpoints: nothing was changed, removed or reordered up to the last checkpoint. It does not cover records written after the last checkpoint, it does not show that Veritas saw everything, and it is not a statement of legal compliance. `SUMMARY.md` says so in the pack itself.

The summary quotes counts, rule names and system names, never a personal value.

## Setting it up for customers

Anchoring should be on (a pack with no checkpoints has nothing for the verifier to compare against, and says so). To bundle the verifier, download the `veritas-verify_*` release assets into a folder and set `VERITAS_VERIFIER_DIR` to it.

## Tests

`audit_pack/test_audit_pack.py`: contents, manifest hashes, the "does not prove" text, audit logging, roles, verifier bundling.
