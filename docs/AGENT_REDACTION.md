# Agent-side redaction

The agent can mask, hash or drop structured personal data in a log line **before the line leaves the host**. Veritas, and anything that reads the agent's masked copy, then never holds the raw value.

It is off by default (the agent sends lines as it always did). Turn it on in the agent's configuration:

```yaml
redaction:
  mode: mask                 # monitor (default) | mask | hash | drop, for every kind below unless overridden
  categories:                # optional, per kind: aadhaar, pan, phone, email, card
    card: drop
    email: monitor
  fail_closed: true          # default; see below
  max_line_chars: 65536      # default
  tee_file: /var/log/veritas-agent/masked.log   # optional masked copy
  hash_key: ${VERITAS_HASH_KEY}                 # needed for mode: hash, 16 or more characters
```

## Modes, per kind of data

| Mode | What is sent |
|---|---|
| `monitor` | the line as it is (the server finds the data) |
| `mask` | the value replaced by `[PHONE_REDACTED]`, `[AADHAAR_REDACTED]` ... |
| `hash` | the value replaced by a keyed token `[PHONE#0123456789abcdef]`: the same person's number gives the same token however it is written (`+91 98765 43210`, `9876543210`), so the server can later find where it appeared without holding it |
| `drop` | the whole line is not sent; the agent counts it |

What it can find is in [RECOGNIZERS.md](RECOGNIZERS.md): Aadhaar (checksum), PAN, Indian mobile numbers, e-mail and payment cards. **It cannot find names or anything that needs context.** A line masked in the agent can still contain a name.

## Hard rules

- **Before queueing.** The line is redacted when it is read, before it enters the agent's buffer, the masked copy or the network. A raw value is never queued once masking is on.
- **Fail-closed (default).** If redaction itself fails for a line, the line is dropped and counted, not sent raw. `fail_closed: false` sends it as it was and says so in the dashboard.
- **Line-size limit.** A line longer than `max_line_chars` is cut and marked `[TRUNCATED]`; nothing past the cut is sent, and the cut moves back before any value it would split, so half of a number is never left behind.
- **The masked copy** (`tee_file`) holds exactly what is sent, so a log shipper (Filebeat, Splunk forwarder) can read it and never see raw data. Dropped lines are not written. It is created with mode 0640 and rotated at 50 MB (one `.1` file). If it cannot be written, forwarding continues and the failure is counted.
- **A hash key is a secret.** A token cannot be turned back into the value, but anyone with the key can test a guess against it. Keep it in the environment or a secrets store, not in the file.

## What the server does with it

The agent adds fields to each event (event schema 2): `redaction_mode`, `recognizer_pack_version` and `agent_detections`, counts per kind of what it masked or hashed (never a value). Because the server only sees placeholders in such a line, it turns them into findings for the kinds the agent names, only where the placeholder is really in the text: a masked value is one finding per kind per line, each distinct hashed identifier is its own finding. Findings, incidents and the Data map therefore keep working. Values the agent left in clear (`monitor`) are found by the server's own detection as before. Schema 1 events from older agents are unchanged.

Every heartbeat reports the agent's mode per kind, whether it is fail-closed, whether it writes a masked copy, how many values were masked or hashed and how many lines were not sent, and the version and fingerprint of its recognizer rules. The dashboard's **Agents** page shows this in a Redaction column, and flags an agent whose rules differ from the server's ("rules differ": it may mask differently from what the server would).

## Trade-offs, said plainly

- **It protects Veritas and downstream tools. It does not clean your logs.** The application's own log files are not changed.
- **Regular expressions miss things.** Names, free-form addresses and unusual formats get through. Use it as one layer, not as the only one.
- **The server sees less.** With masking on, the server cannot run its name detection on the masked parts and cannot check a number's checksum again. With `drop`, the server never learns that line existed except from the agent's counts.
- **Card numbers** found by the agent are reported as a kind of data; the policy does not yet rate their sensitivity, so such findings carry the lowest severity.
- **Cost:** about 0.01 ms per ordinary line (a test fails above 1.5 ms; `docs/PERFORMANCE.md`); a very long line costs more, which is why there is a size limit.

## Settings that are rejected at start

Unknown settings, an unknown kind or mode, `mode: hash` without a key, a size limit outside 1,024 to 1,000,000, and `tee_file` when nothing is set to mask, hash or drop (it would copy raw lines). The agent stops with the reason rather than starting half-configured.
