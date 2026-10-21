# Evidence anchoring and the stand-alone verifier

## Why

The chain of findings proves a record was not edited **if the chain is intact**. But someone with administrator access to the server's disk can edit a record and recompute every hash after it, and the chain will still verify. Deleting the newest records is also invisible. Anchoring puts a signed copy of the chain's head somewhere that person cannot reach, and a small program (`veritas-verify`) lets an auditor check an export against those copies without the Veritas server and without a network.

## How it works

- Every few minutes (or every N new records, whichever comes first, and only if something changed) Veritas writes a **checkpoint** for each organization: the chain's latest position and hash, the time, a link to the previous checkpoint, and an Ed25519 signature. The signing key is made on first use and kept, owner-only, in the data folder's `secrets` (separate from the license and database keys).
- Each checkpoint is copied to one or more **witnesses** outside the server's control. It counts as **witnessed** once enough of them (`min_witnesses`) have taken it; until then it is retried with growing waits.
- A clean stop takes a last checkpoint.
- The dashboard's **Anchoring** item shows when the last witnessed checkpoint was, how many records are not yet anchored, and witness health. A red banner appears when records are waiting and no checkpoint has been witnessed for two intervals.

## Turning it on

Anchoring is **off** until you configure it. Quick start, one witness: set a folder (ideally a remote share where the Veritas account can add files but not change or delete them) in `/etc/veritas/config.env` and restart:

```
VERITAS_ANCHOR_DIR=/mnt/audit-witness/veritas
```

Full settings, in `/etc/veritas/anchoring.yaml` (in the data folder on Windows; `VERITAS_ANCHOR_CONFIG` overrides the path):

```yaml
anchoring:
  enabled: true
  interval_minutes: 5        # at least every 5 minutes if the chain changed
  every_n_records: 100       # or after 100 new records
  min_witnesses: 2           # recommended: two independent witnesses
  sinks:
    - type: file
      path: /mnt/audit-witness/veritas/      # one file per checkpoint, written once, never changed
    - type: syslog
      host: siem.internal
      port: 6514
      protocol: tcp-tls                      # udp, tcp or tcp-tls
```

| Witness | Notes |
|---|---|
| `file` | The simplest, works offline. One file per checkpoint under `<path>/<organization>/`, created exclusively and flushed to disk; the same checkpoint is never overwritten with a different one. |
| `syslog` | RFC 5424 to your SIEM over UDP, TCP or TCP with TLS (verifies the server's certificate; `ca_file` optional). UDP gives no confirmation, so it is accepted but reported as unconfirmed. |
| e-mail, timestamp authority, PDF digest | Planned for a later release of this feature. |

Choose **two witnesses that do not share an administrator**. The dashboard shows an amber "one witness only" note until you do.

## Taking an export and checking it

As an auditor (or administrator), per organization:

```bash
curl -sk -H "Cookie: <your session>" https://veritas.example:8000/v1/ORG/evidence/export   > evidence.jsonl
curl -sk -H "Cookie: <your session>" https://veritas.example:8000/v1/ORG/anchors/export    > checkpoints.jsonl
curl -sk -H "Cookie: <your session>" https://veritas.example:8000/v1/ORG/anchors/pubkey    > veritas.pub

veritas-verify --evidence evidence.jsonl --checkpoints checkpoints.jsonl --pubkey veritas.pub \
               --witness-dir /mnt/audit-witness/veritas/ORG
```

(The dashboard's session cookie works in a browser; for scripts use the same login as any other API call.) Every export is written to the audit log with who took it.

The verifier is one small program with no dependencies, built from `tools/veritas-verify/` (about 600 lines of Go using only the standard library). **Build it yourself from the published source** rather than trusting a binary we hand you. Each release also carries ready-made builds for Linux, macOS (Apple silicon) and Windows, listed in the signed `SHA256SUMS`.

Exit codes: `0` pass, `1` integrity failure, `2` a problem with what you gave it (missing file, an export cut short, an unsupported record version).

| Result | Meaning |
|---|---|
| `PASS` | Every record matches its hash and link, every checkpoint is signed and linked, and the evidence agrees with each checkpoint |
| `HASH_MISMATCH` | A record's content does not match its hash (names the record) |
| `CHAIN_BREAK` | A record does not link to its predecessor: one was removed, added or reordered |
| `CHECKPOINT_HEAD_MISMATCH` | The chain does not match an anchored checkpoint: records up to that point were altered, even if every hash was recomputed |
| `TAIL_TRUNCATED` | The evidence ends before the last checkpoint: the newest records were removed |
| `SIGNATURE_INVALID` | A checkpoint's signature fails: forged, edited, or made with another key |
| `CHECKPOINT_GAP` | A checkpoint is missing from the sequence |
| `WITNESS_DIVERGENCE` | A witness copy differs from the server's copy |
| `UNANCHORED_TAIL` | Information only: records after the last checkpoint are not covered yet |
| `RESTORED_HISTORY` | Information only: the evidence holds a signed `RESTORE_EVENT` that names these checkpoints as describing history a restore set aside. See "After a restore" below |

## More witnesses: e-mail, a time-stamp authority, a printable digest

Besides a file share and your SIEM, a checkpoint can go to three more places (all in `anchoring.yaml` under `sinks:`):

```yaml
        - type: email                   # a mailbox outside this server
          to: audit@yourcompany.example # one or more, comma separated
          # host, port, security, user, password and from default to VERITAS_SMTP_* (the alert settings)
        - type: tsa                     # an RFC 3161 time-stamp authority
          url: https://tsa.yourcompany.example/ts
        - type: pdf-digest              # a daily PDF of the checkpoints, to print or archive
          path: /mnt/audit-archive/veritas-digests
```

| Witness | What it adds | What it does not |
|---|---|---|
| e-mail | a copy in a mailbox the Veritas account cannot reach into | the receipt is the mail server's acceptance, not proof of delivery; the verifier does not read mail (copy the checkpoint into a witness folder to check it) |
| time-stamp authority | a signed statement from a third party that the checkpoint (its SHA-256) existed at that time. The token is kept as the receipt (`tsr:` and base64). Check one with `openssl ts -verify -data <checkpoint line> -in token.tsr -CAfile <authority certificate>`; the checkpoint line is the single line of JSON a file witness holds, without its newline | `veritas-verify` does not check tokens; Veritas checks only that the response is a granted answer to its own request, not the authority's signature |
| PDF digest | a page a person can print or file; the same checkpoints are kept as lines of JSON beside it | it is a witness only as far as its folder is: use write-once or off-box storage |

Only witnesses that Veritas can reach count toward `min_witnesses`; each one that accepts a checkpoint counts, including these. Choose `min_witnesses` knowing which of your witnesses an auditor can actually check.

## A demonstration

1. Anchoring on with two file witnesses; a few findings; wait for a checkpoint (or `POST /v1/ORG/anchors/run`).
2. On the server, with the service stopped, edit one finding in the database file and recompute every hash after it with a script. Start the service: the dashboard's **Verify chain** still says the chain is intact.
3. Export and run `veritas-verify` with the witness folder: **FAIL, `CHECKPOINT_HEAD_MISMATCH`**, naming the record where the evidence stops matching what the witnesses were told.

The same steps run in the repository's test suite (`dpdpa-agent/anchoring/test_verifier.py`) against the real program.

## Honest limits

- Integrity is guaranteed **as of the last checkpoint**. Records after it are exposed until the next one, so choose a short interval.
- If an attacker also controls the witnesses, this fails. Use two independent witnesses.
- The verifier is only as trustworthy as its source: publish it and have the auditor build it.
- A checkpoint proves what the chain looked like, not that the findings in it are complete or correct.
- Changes to a finding's assignee, priority, due date or notes (the case metadata) are not part of the chain; status changes and comments are.
- The signing key is on the same server. It shows who made a checkpoint; the protection comes from the witness copies.
- The signing key is part of the data folder's `secrets`, so it is in backups. Restoring a backup on another machine restores the ability to sign as this server.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Red banner "anchoring has fallen behind" | Open the Anchoring item: a witness is unreachable (share offline, SIEM down) or none is configured. The checkpoints are kept and sent when it returns. |
| "anchoring is on but no witness is configured" | Add a `sinks:` entry or `VERITAS_ANCHOR_DIR`. |
| "min_witnesses is 2 but only 1 witness" | Add a second witness or lower `min_witnesses`. |
| Verifier says `CHECKPOINT_GAP` after a restore | Checkpoints made after the backup are not in the restored database. Give the verifier `--witness-dir`: the witnesses still hold them. |
| Verifier exits 2, "the header says N records but the file holds M" | The export was cut short. Take it again. |


## After a restore

Restoring an older backup rewinds the evidence to the moment of the backup. The witnesses still hold the checkpoints made after it, so without more information a legitimate restore is indistinguishable from someone deleting the newest records. Veritas therefore records it:

1. `sudo veritas restore` leaves a small marker (`RESTORE_PENDING.json`) naming the backup, what the live data held (records, chain head) and the numbers of the signed checkpoints that described the history being set aside. It holds counts, hashes and numbers, nothing personal.
2. At its next start the server writes a signed **`RESTORE_EVENT`** into each organization's chain (the backup, the records before and after, the head before, the checkpoint numbers set aside), an audit-log entry `RESTORE` (who, which backup, how many records were dropped), and raises a floor under the checkpoint numbers, so **no checkpoint number is ever used twice**: after a restore that set aside checkpoints 9 and 10, the next checkpoint is 11.
3. `veritas-verify` reads the event. Checkpoints 9 and 10, still in the witness folders, and the gap they leave in the server's own numbering, are reported as `RESTORED_HISTORY` (information, result PASS) with the backup and time. A checkpoint the event does **not** name that fails still fails.

What it does not do: it cannot tell whether the restore was *authorised*. The event shows that a restore happened, when, and how much it dropped; compare it with your change records. The data set aside stays in `backups/pre-restore-<time>/` until you delete it.
