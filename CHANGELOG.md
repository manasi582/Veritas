# Changelog

What changed in each release, in plain language. The newest release is first. Every release is built and install-tested by CI on clean machines for each platform.

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
