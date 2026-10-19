# Changelog

What changed in each release, in plain language. The newest release is first. Every release is built and install-tested by CI on clean machines for each platform.

## Unreleased (1.1.0)

- **Evidence format (foundation for the trust features):** records written from now on use a defined, versioned format (`hash_version` 1, documented in `docs/EVIDENCE_FORMAT.md`) so that an independent program can check them; status changes and comments are recorded as events in the chain (who, when, from, to), and the status column is only a cache that the chain check recomputes. Existing records are never rehashed; the first new record continues the old chain. A database is migrated when the server starts, after a private copy is made in the `backups` folder. An older program refuses to start on migrated data (it cannot read the new records).
- **Anchoring and a stand-alone verifier:** the server can write signed checkpoints of the evidence chain to witnesses it cannot alter (a file share, your SIEM over syslog), and `veritas-verify` checks an evidence export against them with no server and no network, naming the first broken record, a removed tail, a forged or missing checkpoint or a diverging witness. Off until configured (`docs/ANCHORING.md`). New API: `GET /v1/{org}/evidence/export`, `GET /v1/{org}/anchors`, `POST /v1/{org}/anchors/run`, `GET /v1/{org}/anchors/export` and `/pubkey`. The dashboard's health card shows Anchoring and a banner appears if witnessing falls behind. Releases include `veritas-verify` builds for Linux, macOS (Apple silicon) and Windows.
- **Incidents:** thousands of findings from one noisy line become a short list of incidents (same rule, system, field and wording of the log line, with numbers, ids, times and quoted values ignored and no personal value kept). Each incident has a count, first and last time seen, the highest severity, a 24-hour sparkline, a code location when the line names one, and the owning team from the organization settings (`owners:`). The Audit Ledger opens on the incident list; "All findings" is one click away and every finding is still in the evidence chain. Acknowledging or resolving an incident, a reopening when the same finding comes back after a grace period (`recurred`), a merge and a split are events in the chain. New API under `/v1/{org}/incidents`. Findings stored before this release are grouped on first start by rule, system and field. `VERITAS_INCIDENTS=off` turns grouping off; `VERITAS_INCIDENT_GRACE_SECONDS` (default 3600) sets the grace period. See `docs/INCIDENTS.md`.

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
