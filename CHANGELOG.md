# Changelog

What changed in each release, in plain language. The newest release is first. Every release is built and install-tested by CI on clean machines for each platform.

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
