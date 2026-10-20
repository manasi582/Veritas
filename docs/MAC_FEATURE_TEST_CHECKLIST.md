# Mac test checklist: install a fresh package and test every feature

A hands-on test of the whole product from a clean download, on an Apple-silicon Mac. It covers everything in release **1.0.29**: install, license, sign-in, and each feature added since 1.0.28. Tick each box; write down anything that surprises you in the Notes column.

**Not covered by CI:** this checklist is the only test that uses a real Mac, a real browser and your eyes. CI already proves the logic on clean machines; this proves it feels right and works for a person.

Legend: **Expect** is what you should see. If it differs, note it and carry on.

---

## 0. Before you start

- [ ] An Apple-silicon Mac, macOS 12 or later, and an administrator account (you will type your password for `sudo`).
- [ ] About 3 GB free disk. The server package is 450 MB.
- [ ] A license for **this Mac**. If this is the Mac the license in the repo was issued for: `~/Desktop/Veritas/Veritas/dpdpa-agent/veritas.vlic`.
- [ ] Nothing from an earlier Veritas install is left: `pkgutil --pkgs | grep -i veritas` prints nothing (or run `sudo veritas uninstall --purge-data` first).
- [ ] Open the Terminal. Everything below runs from there unless it says "in the browser".

## 1. Download and verify

```bash
mkdir -p ~/veritas-test && cd ~/veritas-test
VER=1.0.29      # use the version you are testing
BASE=https://github.com/shreyaaassss/Veritas/releases/download/v$VER
curl -L -C - -O $BASE/veritas_${VER}_arm64.pkg            # about 450 MB
curl -L -O $BASE/SHA256SUMS
curl -L -O $BASE/veritas-verify_${VER}_darwin_arm64        # the stand-alone evidence verifier, about 2 MB
curl -L -O $BASE/veritas-agent_${VER}_arm64.pkg            # optional: the agent, about 9 MB
```

- [ ] The downloads finish (re-running the same command resumes a broken download).
- [ ] `shasum -a 256 -c SHA256SUMS --ignore-missing` says **OK** for each file you downloaded.
- [ ] `chmod +x veritas-verify_*` works.

## 2. Install the server

```bash
sudo installer -pkg ~/veritas-test/veritas_${VER}_arm64.pkg -target /
veritas version
```

- [ ] The installer ends with "The install was successful".
- [ ] `veritas version` prints `Veritas 1.0.29`.
- [ ] `veritas status` says the service is **not running** yet. That is expected: there is no license.
- [ ] `sudo veritas logs` (Ctrl+C to leave) says the license file is missing, in plain words.

## 3. License, administrator, first sign-in

```bash
veritas fingerprint                                   # one line starting v2:
sudo veritas license /path/to/your.vlic
sudo veritas setup-code
```

- [ ] `veritas fingerprint` prints a `v2:` line.
- [ ] `sudo veritas license ...` copies the license, starts Veritas and waits until it answers (up to a minute: the language model loads).
- [ ] A license for a different Mac is refused with a message that prints this Mac's fingerprint.
- [ ] In the browser: `https://localhost:8000/setup`. The browser shows a certificate warning (expected). Optional: `sudo veritas trust-cert`, reload, no warning.
- [ ] Enter the setup code. The page lists what the password still needs while you type. A weak password is refused; a good one (10+ characters, not containing your username) works.
- [ ] After creating the administrator, `/setup` redirects to `/login`. Sign in works.
- [ ] A wrong password shows an error and does not sign you in.
- [ ] `sudo veritas check` reports everything healthy.

## 4. First look at the dashboard

- [ ] The header shows the license (organization, tier, expiry) and your user.
- [ ] **Overview** loads with zeros and no errors; **System health** shows Evidence Store, Agent Store, License, TLS, Disk, Anchoring, Runtime.
- [ ] Every tab opens with no blank page: Overview, Live Stream, Audit Ledger, Data map, Rights requests, Rules, Agents, Policy, Scan Sandbox (and Users, System Audit Log for an administrator).
- [ ] The theme toggle switches light and dark and remembers the choice after a reload.
- [ ] *(Next package only, v1.0.30 or later: the new look.)* Lavender page, cream floating panel, lime-on-black logo in the header and the browser tab, pill navigation, rounded white cards. The sign-in page shows the logo.

## 5. Create an organization and a policy

- [ ] **Policy**, Add Organization (or the header button): create `demo_corp`.
- [ ] **Edit Policy**: paste the contents of `docs/demo/demo-corp.json` (in the repository) and save. The policy table shows six fields across five systems, with owners.
- [ ] Add a **notice**: in the policy form, a notice `n-core` version `3`, effective `2026-01-01`, categories `phone, email`, systems `order-service, support-ticketing, noisy-service`. Saving keeps the owners and the other fields (they must not disappear).
- [ ] The policy history shows versions and you can open an older one.

## 6. Send data: an agent, and the events API

In the browser, **Agents**, **Issue Registration Key**, choose `demo_corp`. Copy the key. Then:

```bash
KEY=<the key>
TOKEN=$(curl -sk -X POST https://localhost:8000/agent/register -H 'Content-Type: application/json' \
  -d "{\"registration_key\":\"$KEY\",\"source_label\":\"checklist\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["auth_token"])')
send() { curl -sk -X POST https://localhost:8000/v1/demo_corp/events -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"source_type\":\"log\",\"source_system\":\"$1\",\"raw_snippet\":\"$2\"}" -o /dev/null -w "%{http_code}\n"; }
send order-service "order 1001 shipped, customer phone 9876543210"
send support-ticketing "ticket 7 callback to 9876543210 aadhaar 2345 6789 0124 mail asha.rao@example.com"
send marketing-service "campaign sent to asha.rao@example.com"
send order-service "Ravi Kumar called about order 1001"
```

- [ ] Each call prints `200`.
- [ ] **Agents** lists the agent with a heartbeat time after a minute.
- [ ] **Live Stream** shows findings arriving (the WebSocket dot is green and says connected).
- [ ] The last line produces a finding for a **name** (the real language model; a name is only found by the server, not by the recognizers).
- [ ] The finding for the Aadhaar number is flagged as a **possible breach candidate**.

Optional, for the agent itself: install `veritas-agent_${VER}_arm64.pkg` and follow Part 2 of `docs/MACOS.md`, pointing it at a log file.

## 7. Findings become incidents (Audit Ledger)

Send many near-identical lines so grouping shows:

```bash
for i in $(seq 1 300); do send noisy-service "debug cache refresh for tenant $i took $((i*3)) ms trace $RANDOM customer phone 9876543210" >/dev/null; done
```

- [ ] **Audit Ledger** opens on **Incidents**, with a summary like "about 300 findings → a handful of incidents".
- [ ] A row shows severity, a template with placeholders (no phone number), the owning team from the policy, the findings count and a 24-hour sparkline.
- [ ] **Findings** on a row expands the findings behind it. **All findings** shows the full list: nothing was removed.
- [ ] **Acknowledge**, then **Resolve** an incident: the status changes and a toast confirms.
- [ ] Send the same noisy line again: after the grace period (1 hour by default) the incident reopens marked **recurred**. (To test sooner: add `VERITAS_INCIDENT_GRACE_SECONDS=30` to `/etc/veritas/config.env`, then `sudo veritas restart`.)
- [ ] Merge two incidents and split findings out of one: both work and are recorded.

## 8. Why did this fire, and the wording

- [ ] Open a finding's **Details**. A **Why this fired** panel lists the rule and its version, each condition with a tick or cross and a detail (system, field), and the severity.
- [ ] The text says *possible control failure*, not "violation", and the statute reference reads as context. No raw phone number, Aadhaar or e-mail appears anywhere on the page.
- [ ] Older findings (none yet on a fresh install) would say they predate the trace.

## 9. Prevention at the source (agent redaction)

- [ ] Configure the agent with a `redaction:` block as in `docs/AGENT_REDACTION.md` (`mode: monitor`, categories `aadhaar: mask`, `phone: hash`, `email: mask`), point it at a file, restart it, and append a line containing a phone, an Aadhaar and an e-mail.
- [ ] **Agents** shows the Redaction column as *mixed*; hovering shows the details.
- [ ] The finding in the ledger reads `[AADHAAR_REDACTED]`, `[PHONE#…]`, `[EMAIL_REDACTED]`. The masked copy file (if configured) holds no raw value.
- [ ] A malformed redaction setting makes the agent refuse to start with a clear message.

## 10. Data map

- [ ] **Data map** shows one node per system seen, coloured: everything declared, an undeclared kind of data, an open incident, declared but not observed.
- [ ] Click a node: a panel shows the kinds of data observed and the open incidents.
- [ ] **Record (CSV)** and **Record (PDF)** download files that open and list the systems. They hold counts, never values.
- [ ] **Notice coverage** lists notice `n-core` as current, and names the systems and kinds of data **not** covered (for example `marketing-service`, `aadhaar`).

## 11. Database schema watch

```bash
send kyc-service "ALTER TABLE customers ADD COLUMN aadhaar_no varchar(12);" 
```

(as an event with `"source_kind":"schema"` in the JSON; or use the `db_schema_log` agent source in `docs/SCHEMA_WATCH.md`)

- [ ] A finding appears: a database change adds a column that looks like Aadhaar data and the policy does not declare it, with the system's owner.
- [ ] **Data map**, *Database schema changes* lists the column as undeclared.
- [ ] `ALTER TABLE customers DROP COLUMN aadhaar_no;` is recorded as dropped and raises nothing.

## 12. API payloads (Payload Tap) and the pipeline gate

- [ ] Follow `docs/PAYLOAD_TAP.md` to wrap a small Python (FastAPI) service with the tap, call a route whose response holds a phone number in an undeclared field. A finding names the route's field (for example `user.phone`) and the service is never blocked or slowed noticeably.
- [ ] The Data map shows the system as seen in an **API**.
- [ ] **Gate, API examples:** `python3 veritas-sdk/python/veritas_gate.py openapi.json` fails (exit 1, values masked) on a spec with a phone number in an example, passes on a clean one.
- [ ] **Gate, migrations:** put `CREATE TABLE users (id int, phone text);` in `m/001.sql` and `ALTER TABLE users ADD COLUMN passport_number text;` in `m/002.sql`; export the policy from **Policy** to `policy.json`;
  `python3 veritas-sdk/python/veritas_gate.py --migrations m --policy policy.json`
  - [ ] it exits 1 and names `users.passport_number` (not declared);
  - [ ] adding `ALTER TABLE users DROP COLUMN passport_number;` as `m/003.sql` makes it pass.

## 13. Retention review

- [ ] In the policy, give one field a short retention (for example 30 days) and a `data_since` older than that, keep sending data to that system.
- [ ] **Data map**, retention panel lists it as **overdue**, with the due date and owner.
- [ ] Open a retention task for it: an owner task appears under **Rights requests** (type retention); confirming closes it.
- [ ] If the data keeps arriving afterwards, the review shows it again.

## 14. Streaming receivers

```bash
curl -sk -X POST https://localhost:8000/v1/demo_corp/otlp/logs -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"otel-demo"}}]},"scopeLogs":[{"logRecords":[{"body":{"stringValue":"callback to 9876543210"}}]}]}]}'
```

- [ ] A finding appears for system `otel-demo`.
- [ ] A protobuf body is refused with 415 and a message saying JSON only.
- [ ] Syslog: see `docs/STREAMING_RECEIVERS.md` for the agent's syslog source; a message sent with `logger` is judged like any log line.

## 15. Rights requests

- [ ] **Rights requests**, **Look up an identifier**: category phone, `9876543210`. The result lists the systems where it was observed. The identifier does not stay in the page afterwards.
- [ ] **New request** (erasure) with a reference and that identifier: one task per system, each with its owner.
- [ ] **Confirm** each task. When the last is confirmed the request closes.
- [ ] **Record (PDF)** and **Record (signed JSON)** download. The PDF opens and shows chain references, never the identifier.
- [ ] Send the same phone number again: an **ERASURE_001** finding appears (HIGH).
- [ ] A viewer account cannot look up or open requests.

## 16. Evidence you can verify yourself

- [ ] **Audit Ledger**, **Verify Cryptographic Hash Chain**: says the chain is intact.
- [ ] **Download audit pack**: a zip downloads.
  - [ ] It holds `evidence.jsonl`, `checkpoints.jsonl`, `veritas.pub`, `SUMMARY.md`, `summary.json`, `VERIFY.md`, `verify.sh`, `verify.bat`, `MANIFEST.sha256`.
  - [ ] `SUMMARY.md` states the chain, open incidents, rules in force, and "what this pack does not prove". It holds no phone number, Aadhaar or e-mail.
  - [ ] Unzip it, copy `veritas-verify_*_darwin_arm64` into the folder as `veritas-verify`, run `./verify.sh`: it says **PASS**.
  - [ ] Change one character in `evidence.jsonl` and run it again: it **fails** and names the record.
- [ ] Anchoring (optional, `docs/ANCHORING.md`): with two witnesses configured, **Overview**, health card, Anchoring is green after a checkpoint, and checkpoints show as witnessed.

## 17. Breach-ready report

- [ ] On an incident flagged as a possible breach (the Aadhaar one), press **Breach report**: a zip downloads.
- [ ] `REPORT.md` shows what was observed, the response so far, a timeline with chain sequence numbers, and a section **To be completed by people** (nature, number affected, consequences, measures, DPO contact, dates).
- [ ] It says *draft, not legal advice*, and that findings are not a count of people. It holds no personal value.

## 18. Rules you can tune

- [ ] **Rules** lists six rules with what each looks at and the default severity.
- [ ] **Propose change** on `EXPOSURE_001`: tick *require review*, give a reason, submit. It appears under **Changes** as proposed.
- [ ] With only one administrator, **Approve** works and the change is marked **self-approved**. Create a second administrator (**Users**) and propose again: you cannot approve your own, the other can.
- [ ] After approval, a new `EXPOSURE_001` finding opens one **review task** for the system's owner under Rights requests; a second finding of the same incident does not open another.
- [ ] Propose lowering `EXPOSURE_001` severity to LOW and approve: a phone-number finding becomes LOW; an **Aadhaar** finding stays **HIGH** (the floor).
- [ ] **Propose an exception** for system `marketing-service`, rule `EXPOSURE_001`, with a reason, owner and an end date. It refuses a scope of everything and an end date more than 180 days away. After approval, new findings in that system are not stored, and **Exceptions in force** counts them ("findings covered"). An Aadhaar finding in that system is still raised.
- [ ] **End now** on the exception: findings are raised again.
- [ ] There is no setting to switch a core rule off, and no block action.
- [ ] Propose an overlay with *redact* for `phone: mask` and approve it. Within about 30 seconds an agent running in monitor mode starts masking phone numbers (the Agents page shows the change).
- [ ] The audit pack summary now lists the rules in force and any self-approved change.

## 19. Policy packs

```bash
# in the browser console on the dashboard, or with a session cookie:
fetch('/v1/policy-packs').then(r=>r.json())
fetch('/v1/demo_corp/policy-packs/ecommerce/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'}).then(r=>r.json())
```

- [ ] Three packs are listed (fintech, healthtech, ecommerce), each marked **DRAFT** with no reviewer.
- [ ] The preview lists what would be added, each field with a retention period **and the reason for it**, notice suggestions and "watch for" items. It saves nothing.
- [ ] Applying without `acknowledge_unreviewed` is refused (409); with it, the fields are added and existing ones are not changed. Applying twice adds nothing.

## 20. Roles and safety

- [ ] A **viewer** can read the dashboard but cannot change an incident, propose or approve a rule, create a request or download an audit pack.
- [ ] An **auditor** can download the audit pack and breach report and cannot change anything.
- [ ] **System Audit Log** shows entries for: audit pack downloaded, breach pack downloaded, rule change proposed/approved, policy changes. No entry holds a raw value.

## 21. Operations

- [ ] `sudo veritas backup`, then `sudo veritas backups` lists it and `sudo veritas verify-backup <file>` says it is good.
- [ ] `sudo veritas restart` brings it back and your data is still there.
- [ ] After a restart, **Verify Cryptographic Hash Chain** is still intact.
- [ ] `sudo veritas uninstall` removes the program and service and keeps your data; `sudo veritas uninstall --purge-data` removes everything, including the service account (`dscl . -read /Users/_veritas` fails afterwards).

---

## Results

| Section | Pass | Fail | Notes |
|---|---|---|---|
| 1-3 Install, license, setup | | | |
| 4 Dashboard | | | |
| 5-6 Policy and sending data | | | |
| 7-8 Incidents, why it fired | | | |
| 9 Redaction | | | |
| 10-11 Data map, schema watch | | | |
| 12 Payload tap, gate | | | |
| 13-14 Retention, receivers | | | |
| 15 Rights requests | | | |
| 16 Evidence, audit pack | | | |
| 17 Breach report | | | |
| 18 Rules | | | |
| 19 Policy packs | | | |
| 20-21 Roles, operations | | | |

## Known limits (these are not bugs)

- Detection is probabilistic. Names are found only by the server's language model; the agent and the Payload Tap never find names.
- Veritas never deletes data and never blocks traffic.
- The notice check only compares the policy with what was observed. It cannot read a notice or judge it.
- The statute references, the breach-report wording and the three policy packs have not been reviewed by a lawyer.
- Schema watch reads PostgreSQL and MySQL DDL; it guesses a column's kind from its name.
- A `redact` rule reaches agents only, not the Payload Tap, and only makes them stricter.
- Escalation uses the alert channels you have configured; with none configured nothing is sent.
- The packages are not signed by Apple: install with `sudo installer`, not by double-clicking.
