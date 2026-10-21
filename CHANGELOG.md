# Changelog

What changed in each release, in plain language. The newest release is first. Every release is built and install-tested by CI on clean machines for each platform.

## 1.0.31

Fixes from a hands-on test of 1.0.30 on a real Mac (`docs/MAC_TEST_FINDINGS.md`).

- **A restore is now visible.** `veritas restore` leaves a marker; the next start writes a signed `RESTORE_EVENT` into each organization's evidence chain, a `RESTORE` entry into the audit log (who, which backup, how many records the live system dropped), and raises a floor so a checkpoint number is never used twice. `veritas-verify` reads the event and reports the checkpoints that described the set-aside history as `RESTORED_HISTORY` (information, PASS) instead of a witness divergence. Before, a legitimate restore looked exactly like tampering and left no trace. See `docs/ANCHORING.md`.
- **Refused requests are audited.** Every role or organization refusal on an authenticated route is recorded as `ACCESS_DENIED` with the result `DENIED` (one entry per person and route every 10 seconds). The identifier-lookup refusal is no longer recorded as a success. The audit log now records the caller's address; a forwarded address is believed only when `VERITAS_TRUSTED_PROXY=true`, and the rate limiter no longer trusts an `X-Forwarded-For` header from anyone.
- **Anchoring off is now loud.** Administrators and auditors see a banner on every page until anchoring is configured, saying what is at risk. The audit pack's `VERIFY.md` gives the exact verifier downloads for the release, and the pack includes the verifier when the install ships one.
- **Rules:** an exception's scope is compared ignoring case and says "nothing matched yet" when it covers no finding; the form no longer auto-capitalises.
- **Breach report** names the kind of data (from the findings' traces) and its labels read properly.
- **Grouping:** a name the detector found and one it missed are the same place, so one line shape no longer splits into two incidents. (Incidents with a detected name get a new fingerprint: after the upgrade such an incident starts afresh once.)
- **Pipeline gate:** `user@example.com` and the other reserved example domains are placeholders, not personal data; the summary counts undeclared columns as columns. **Payload Tap:** `register` accepts `--ca-cert`, reads `VERITAS_TAP_CA_CERT`, and `--fetch-cert` saves the server's own certificate, so it works against a default install.
- **Interface:** the navigation wraps on narrow windows instead of being cut off; one clean outline on form fields; the incident table keeps its columns and compact times; Rights requests have filters (rights, retention, review tasks) so review tasks no longer bury real requests; the new-request form says "Date received" and "Respond by" and refuses a received date in the future; small header text is easier to read.

## 1.0.30

- **New dashboard look:** a lavender page with a floating cream panel, white rounded cards, pill navigation across the top, and a palette of lime, orange, violet, cream and near-black. A dark theme with lime accents is one click away; light is the default. The sign-in and first-run pages match.
- **New logo and favicon** in the header, the browser tab and the sign-in pages.
- No behaviour changed: every page, button and setting works as in 1.0.29, which carries everything built since 1.0.28 (see below).
- A step-by-step Mac test checklist for the whole release: `docs/MAC_FEATURE_TEST_CHECKLIST.md`.

## 1.0.29

This release carries everything built since 1.0.28: the trust, visibility and prevention features, the problem-statement features (schema watch, payload tap, retention review, notice registry, streaming receivers), the audit pack, migration gate, breach pack and policy packs, and configurable rules with approvals. Sections below, newest work first.

### Rules you can tune, with guardrails
- **Six core rules as data** (`docs/RULES.md`): what each looks at, its default severity, evidence kept and wording, shown on a new **Rules** page and by `GET /v1/{org}/rules`.
- **Overlays and exceptions, approved by a second person** and recorded in the chain (`RULE_EVENT`): raise severity freely, lower it only to a floor (Aadhaar, PAN, card, passport and voter stay HIGH); exceptions name a scope, a reason, an owner and an end date, still count what they cover, and never cover a possible breach candidate. Core rules cannot be switched off.
- **Actions:** `require_review` (a task for the owner), `escalate` (an alert if unacknowledged), `redact` (agents are told to mask, hash or drop, stricter only). No block action.
- **Why this fired:** every finding records each condition of its rule, answered, and the severity before and after the organization's setting. Shown in the finding's Details and by `GET /v1/{org}/findings/{n}/why`.
- **Wording:** findings are *possible control failures*, with the related section of the Act as context, never a conclusion. Counsel should review.
- The audit pack lists the rules in force and any self-approved change. See `docs/RULES_STATUS.md` (customer-written rules were not built).

### Standing out: proof, prevention, breach readiness, industry packs
- **Audit pack** (`GET /v1/{org}/audit-pack`, dashboard button): one zip with the evidence, signed checkpoints, public key, a plain summary, verify scripts and (optionally) the verifier, checkable offline. See `docs/AUDIT_PACK.md`.
- **Pipeline gate for migrations:** `veritas_gate.py --migrations DIR --policy FILE` fails a build when a migration leaves a personal-data column the policy does not declare; a GitHub Action wraps it. See `docs/PIPELINE_GATE.md`.
- **Breach pack** (`GET /v1/{org}/incidents/{id}/breach-pack`): a draft report built from the chain, with blanks for the DPO and counsel. Not legal advice. See `docs/BREACH_PACK.md`.
- **Industry policy packs** (fintech, healthtech, e-commerce; preview and apply, API only): draft, unreviewed by counsel. See `docs/POLICY_PACKS.md`.
- The end-to-end scenario now checks all four, including the real verifier accepting the audit pack and rejecting an edited copy.

Work towards full alignment with the problem statement (`docs/PS_ALIGNMENT_PLAN.md`; the score and the evidence are in `docs/PS_ALIGNMENT_STATUS.md`). The demo (`docs/DEMO.md`) has new moments for the schema change, the leaky API, retention and notices.

- **Phase A, groundwork:** fields named by a path, as API payloads name them (`user.phone`, `items[0].mobile`), now match the declared field and its validator. Events can say how they arrived (`source_kind`: log, api, schema or otlp) and the data map records it. The rule id `NOTICE_001` is reserved for the notice check (Phase E). `scope.md` now says what is observed in telemetry and what is not.
- **Phase B, Schema Watch:** the agent has a new `db_schema_log` source that keeps only whole `CREATE`, `ALTER` and `DROP TABLE` statements from a database log (everything else is dropped on the host). The server parses them (PostgreSQL and MySQL), guesses from each column's name whether it holds personal data, and compares that with the policy: a personal-data column the policy does not declare is a `PURPOSE_001` finding with an owner and an incident, and the Data map shows the kind of data and how it was seen. The policy can correct the guess (`schema_hints`). Statements that carry values are never stored. New API `GET /v1/{org}/schema`. See `docs/SCHEMA_WATCH.md`.
- **Phase C, Payload Tap:** a library for Python (ASGI and WSGI: FastAPI, Starlette, Flask, Django) and Node (Express) that finds personal data in JSON API requests and responses, **masks it inside the service**, and reports the route, the field's path (`user.phone`) and a placeholder, never a value. It never delays, changes or fails a request (background sending, bounded queue, circuit breaker). The server judges each reported field by the policy as the field it is (`user.phone` as `phone`), so an undeclared field is a `PURPOSE_001` finding, and the Data map shows the kind of data and that it was seen in an API. Hashed identifiers reach the lookup index. `veritas_gate.py` fails a pipeline when an OpenAPI document or sample payloads contain personal data. The Node library is held to the same golden corpus as the Python one. See `docs/PAYLOAD_TAP.md`.
- **Phase D, Retention review:** for every field the policy declares, when its retention period runs out and whether data of that kind is still being seen in that system (within, due soon, overdue, past but not seen, not observed), on the Data map page and at `GET /v1/{org}/retention`. The daily run raises alerts for overdue and due-soon periods. A compliance administrator can open a retention task for a system's owner (a rights-request-style task, recorded in the evidence chain, with a downloadable record); if the data keeps arriving after the task closes, the field is overdue again. Veritas never deletes anything and does not see data at rest, and says so. See `docs/RETENTION_REVIEW.md`.
- **Phase E, Notice registry:** the policy can list the privacy notices in force (`notices:`, with an optional `notice_id` on each field), and the Policy form edits them. Veritas shows which declared fields and observed kinds of data a current notice covers (on the Data map page and at `GET /v1/{org}/notices`), reports notices that are retired, not yet effective or past their review date, and raises `NOTICE_001` once per gap when a kind of data is observed that no current notice covers (also checked daily). It checks coverage only: it cannot read a notice, judge its adequacy, or know it was shown. Nothing changes for an organization that records no notices. See `docs/NOTICE_REGISTRY.md`.
- **Fix:** saving the policy in the dashboard used to rebuild it from the form and so dropped the owners (added with incidents); it now keeps every section the form does not edit.
- **Phase F, streaming receivers:** the server accepts OpenTelemetry logs (`POST /v1/{org}/otlp/logs`, OTLP/HTTP with a JSON body; the resource's `service.name` is the source system) and the agent has a `syslog` source (UDP and TCP, RFC 3164, 5424 and 6587 framing). Both are judged by the same detection and rules as a file line and shown on the data map as seen through OpenTelemetry or syslog. See `docs/STREAMING_RECEIVERS.md`.

### Trust, visibility and prevention (the earlier part of this release)

- **Evidence format (foundation for the trust features):** records written from now on use a defined, versioned format (`hash_version` 1, documented in `docs/EVIDENCE_FORMAT.md`) so that an independent program can check them; status changes and comments are recorded as events in the chain (who, when, from, to), and the status column is only a cache that the chain check recomputes. Existing records are never rehashed; the first new record continues the old chain. A database is migrated when the server starts, after a private copy is made in the `backups` folder. An older program refuses to start on migrated data (it cannot read the new records).
- **Anchoring and a stand-alone verifier:** the server can write signed checkpoints of the evidence chain to witnesses it cannot alter (a file share, your SIEM over syslog), and `veritas-verify` checks an evidence export against them with no server and no network, naming the first broken record, a removed tail, a forged or missing checkpoint or a diverging witness. Off until configured (`docs/ANCHORING.md`). New API: `GET /v1/{org}/evidence/export`, `GET /v1/{org}/anchors`, `POST /v1/{org}/anchors/run`, `GET /v1/{org}/anchors/export` and `/pubkey`. The dashboard's health card shows Anchoring and a banner appears if witnessing falls behind. Releases include `veritas-verify` builds for Linux, macOS (Apple silicon) and Windows.
- **Incidents:** thousands of findings from one noisy line become a short list of incidents (same rule, system, field and wording of the log line, with numbers, ids, times and quoted values ignored and no personal value kept). Each incident has a count, first and last time seen, the highest severity, a 24-hour sparkline, a code location when the line names one, and the owning team from the organization settings (`owners:`). The Audit Ledger opens on the incident list; "All findings" is one click away and every finding is still in the evidence chain. Acknowledging or resolving an incident, a reopening when the same finding comes back after a grace period (`recurred`), a merge and a split are events in the chain. New API under `/v1/{org}/incidents`. Findings stored before this release are grouped on first start by rule, system and field. `VERITAS_INCIDENTS=off` turns grouping off; `VERITAS_INCIDENT_GRACE_SECONDS` (default 3600) sets the grace period. See `docs/INCIDENTS.md`.
- **Observed processing map:** a *Data map* page shows which systems produced which kinds of personal data, set against the declared policy (green: all declared; amber: a kind of data seen that is not declared; red: an open incident; grey: declared, never seen), with edges to other systems and to outside hosts when a log names a destination (host name only). Counts only, never values. *Record (CSV / PDF)* and `GET /v1/{org}/flows/export` produce a "Record of observed processing". New API: `GET /v1/{org}/flows`. `VERITAS_FLOWS=off` stops counting. See `docs/FLOWS.md`.
- **Shared recognizer pack:** the rules for Aadhaar (checksum), PAN, Indian mobile numbers, e-mail and payment cards (Luhn check) now live in one standard-library file used by both the server and the agent, with a golden corpus that both sides must reproduce (`docs/RECOGNIZERS.md`). The server's detection is built from it, so the rules cannot drift. `+91 9876543210` is now matched as one number (the `+` used to stay outside). Groundwork for masking in the agent.
- **Agent-side redaction:** an agent can now mask, hash or drop Aadhaar, PAN, phone, e-mail and card numbers (per kind) before a line leaves the host, with a fail-closed default, a line-size limit that never leaves half a number behind, and an optional masked copy for a log shipper (`redaction:` in the agent configuration, off by default; `docs/AGENT_REDACTION.md`). The server accepts a new event format (schema 2) next to the old one, turns the agent's placeholders into findings so incidents and the Data map keep working, and the Agents page shows each agent's mode, how much it masked or dropped, and warns when its rules differ from the server's. It cannot find names and does not change the application's own log files. Mac, Ubuntu and container agents ship the recognizer pack.
- **Identifier lookup and rights requests:** *where was this identifier observed?* without keeping it. Veritas stores only a keyed hash (HMAC-SHA256 under a per-organization key, with the key's id so rotation never breaks old tokens) of each structured identifier it sees, counted per system. Compliance administrators can look an identifier up (rate limited, every lookup audited with a token prefix only), open a rights request (access, erasure, correction) that makes one task per system where it was observed, and close it when owners confirm; each step is an entry in the evidence chain. After an erasure request closes, the identifier is watched: seeing it again raises the new finding `ERASURE_001`. A signed record (PDF and JSON, Ed25519) lists what was observed where and the chain entries it rests on. Agents in hash mode receive the organization's key from the server. It reports where Veritas observed an identifier; it is not a certificate of erasure. New *Rights requests* page. See `docs/SUBJECT_LOOKUP.md`.
- **More anchoring witnesses:** a checkpoint can also be e-mailed to a mailbox outside the server, signed by an RFC 3161 time-stamp authority (the token is kept as the receipt), or written to a daily PDF digest for printing or archiving (`docs/ANCHORING.md`).
- **End-to-end scenario, demo and measurements:** `tools/trust_e2e.py` runs the five features as one story (masking agent, 6,000-line flood, map, recurrence, rights request and resurrection, anchoring and a tampering attempt that only the stand-alone verifier catches, and the upgrade of a database from the previous release) against a real server, real agents and the real verifier; CI runs it on Ubuntu with the real language model (`.github/workflows/trust-e2e.yml`). `docs/DEMO.md` is the 15-minute demo with sample data (`tools/demo_logs.py`, `docs/demo/`, `tools/demo_tamper.py`), and `docs/PERFORMANCE.md` records what the features cost (`tools/bench_trust.py`).

## 1.0.28

- **Documentation:** administrator runbook (`docs/RUNBOOK.md`), security overview for customer questionnaires (`docs/SECURITY_OVERVIEW.md`), and drafts of the license agreement, support policy and data handling statement (`docs/legal/`, for legal review).

## 1.0.27

- **Ubuntu upgrades no longer replace your settings (important):** the Ubuntu server package shipped `/etc/veritas/config.env`, and the agent package shipped `/etc/veritas-agent/config.yaml`, as part of the package, so every upgrade put the default file back. For the agent that meant the address and registration key were gone and the agent stopped ("veritas_address is still a placeholder"); for the server it meant alert, mail, metrics and capacity settings were lost. Both files are now created once from an example under `/usr/share` and never touched again; the first upgrade from an older package keeps a copy of your file and puts it back. The install tests upgrade from the real previous release and check the file is unchanged. **If you upgraded an Ubuntu agent or server to 1.0.26 or earlier, check these files.** (The macOS packages were not affected.)
- **Ubuntu: the program belongs to root.** On Ubuntu the server and agent programs (`/opt/veritas`, `/opt/veritas-agent`) were owned by the service account, so a compromised service could rewrite the code it runs from. They are now owned by root, as they already were on macOS; data, logs and settings stay with the service account. The install tests check it.
- **Ubuntu agent upgrade fixed:** upgrading the agent package stopped the agent and never started it again, so an upgraded agent sat silent until someone noticed. An agent that has registered is now started again after an upgrade, and the install test checks it: same identity, same configuration, running, and still delivering. (The Mac agent package already did this.)
- **Mac agent and Docker:** when the agent cannot reach Docker it now says what to do (on a Mac: write the container's logs to a file and use a file source).
- **No outside requests:** the browser test now fails if the dashboard ever asks for anything from outside the machine (fonts, scripts, analytics), which is what an air-gapped customer needs; today it asks for nothing.

## 1.0.26

(Measured on a shared 4-core test machine: about 90 events per second with detection in one thread, about 185 with 2 worker processes and about 300 with 3; nothing lost. See docs/OPERATIONS.md, Capacity.)

- **Detection worker pool:** finding personal data now runs in several worker processes (`VERITAS_DETECTION_WORKERS`, default `auto`), so a server with more cores takes more events per second, and the dashboard stays responsive while events are processed. A bounded queue (`VERITAS_DETECTION_QUEUE`) answers "busy, retry" (HTTP 503 with `Retry-After`) instead of letting waits grow without limit; the agent honours `Retry-After` on 503 as it already did on 429, and loses nothing. Workers never read the organization settings: they are handed what they need with each event, so a policy change applies at once. Health card, `/metrics` and the install tests cover the pool.
- **Faster ingest, found by profiling the server under load:** the two biggest costs of taking an event were disk syncs. The evidence and agent databases now use write-ahead logging (one sync per commit instead of three; the dashboard's reads no longer wait for writes) and the per-agent event counter is written in batches. Backups are still one self-contained file per database, and a restore keeps any leftover log file in its safety copy. The dashboard's overview counts (`/api/<org>/stats`) are now taken by the database from summary columns instead of decrypting every finding, which used to happen on every new finding; the evidence-chain check also verifies those columns against the signed record, so a changed count is reported as tampering. Existing databases are upgraded when the server starts.

## 1.0.25

- **macOS settings file fixed:** `/etc/veritas/config.env` is now readable by the service account (through an access-control entry, because that account has no group of its own) and by no other user. In 1.0.24 it was owned by `wheel`, so the service ignored it. The install test now checks that the service account can read it and another account cannot.

## 1.0.24

- **macOS settings file:** settings now live in `/etc/veritas/config.env` (as on Linux), created once with a commented example and never replaced, so they survive upgrades. **In this release the file's permissions were wrong on macOS: the service account could not read it, so settings in it were ignored. Use 1.0.25.** Settings in the service definition still win. A leftover `Path` import that broke the new one-shot commands in the packaged build is fixed.
- **Dashboard:** the health card shows whether alerts and metrics are set up.

- **Alerts:** Veritas can tell people by webhook (Slack, Teams, Mattermost, your own) and e-mail when HIGH findings arrive (batched, one message a minute per organization) and when a backup fails, the evidence chain breaks, the license or certificate is about to expire, or the disk is nearly full. `veritas test-alert` checks the setup. Messages never contain personal data.
- **Metrics:** `GET /metrics` in the Prometheus format (license days, certificate days, disk, database sizes, backup age, broken chains, agents and findings per organization). Off until you set `VERITAS_METRICS_TOKEN`.
- **Support bundle:** `sudo veritas support-bundle` writes one ZIP for the vendor: version, license status, checks, settings, recent logs with secrets and personal identifiers removed; never a database, key or license file.
- New `docs/EVIDENCE_RETENTION.md`: how the evidence database grows and the options for retiring old evidence (decision needed).

- **Security fix (dashboard):** names that an agent or API caller chooses (source system, field name) were shown in the live stream, ledger and case view without escaping, so a malicious agent token could run script in an administrator's browser. Every value from the server is now escaped, names containing `< > " ' & \``are refused where they enter, and the browser test checks both.
- **Security fix (backups):** the backup-verify call took a path; it now takes only a file name.
- **Dependencies:** python-jose (advisory without a fix) is replaced by PyJWT; cryptography is raised to 50 (three advisories). Existing sessions keep working.
- **Supply chain:** each release carries a software bill of materials, `SHA256SUMS` and a signature that can be checked with `cosign`; a dependency audit blocks a release and runs weekly, with a Go vulnerability check and a secret scan.
- **CI no longer uses the production license key:** tests sign licenses with a separate test key, and the release is checked to embed only the production key.
- New `docs/SECURITY_REVIEW.md`: threat model and review package.

- **Upgrades:** installing a new release now backs up your data first (with the release that is still installed) and, on Ubuntu, starts the service again afterwards. A failed backup is reported but does not stop the upgrade.
- **Downgrades are refused:** installing an older release over a newer one stops with a clear message, because the newer release may have changed the data. To do it on purpose, `sudo touch /var/lib/veritas/ALLOW_DOWNGRADE` first (it allows one downgrade).
- **Data format check:** each database carries a format number. A release that finds data written by a newer one refuses to start (once, with the reason) instead of running on it.
- CI now installs the previous release, creates data, upgrades to the new build and checks the data, license and evidence chain survive, on Ubuntu and Apple-silicon macOS.

## 1.0.23

- **macOS:** the server now rotates its own log (`veritas-app.log`, 10 MB at a time, 5 compressed copies kept) so the log folder no longer grows without limit. `sudo veritas logs` follows it.
- **Restore:** `veritas restore` now waits until the server answers before it says "Restore complete", and says clearly if it does not start. (Linux and macOS.)
- **Backups:** `veritas verify-backup` and `veritas restore` accept the bare file name that `veritas backups` prints, not only a full path.
- Package maintainer address is the same in the server and agent `.deb` packages.

## 1.0.22

- **Restore:** `veritas restore <file>` brings back a backup safely. It checks the file and its databases first (a bad file costs no downtime), keeps what it replaces in `backups/pre-restore-<time>`, keeps the current license unless you ask for the backup's, and rolls back if the swap fails.
- New commands: `veritas backup`, `backups`, `verify-backup`.
- Tested on clean Ubuntu and Apple-silicon macOS machines in CI.

## 1.0.21

- **macOS agent:** a self-contained `.pkg` (no Python needed), a launchd service and a `veritas-agent` command (start, stop, logs, grant-read, fetch-cert, uninstall).
- **macOS hardening:** logs are private to the service account, the program belongs to root, and `setup-code` and `logs` ask for `sudo` with a clear message.
- The dashboard's health card fills in at start-up.

## 1.0.20

- **macOS server:** machine fingerprint v2 (from the Mac's hardware identifier), the full `veritas` command, and an install test that builds from the commit.
- **Sign-in:** per-account lockout after repeated failures (15 minutes), and an offline administrator password reset (`veritas reset-password`).
- Fixes from the Ubuntu test: the dead page after a session ended, a visible sign-out, live password hints, certificate name checks and a quieter agent log.
- The agent stops with a clear message if `veritas_address` or `registration_key` still holds a placeholder.

Earlier releases (1.0.18 and before) are in the git history.
