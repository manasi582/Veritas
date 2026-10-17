# Operating Veritas

What the appliance does by itself, what you should watch, and the few things an administrator does from time to time. Commands assume the Linux package (`sudo veritas …`). The same commands work on macOS; the differences (file locations, how settings are changed, the agent) are in [MACOS.md](MACOS.md).

## What Veritas does by itself

| Task | How often | Where to see it |
|---|---|---|
| Backup of all data (databases, license, organization policies, certificates, secrets) | every 24 h, first run 10 min after the service starts; the last 7 are kept | Dashboard → Overview → System Health → *Backups & Chain*; files in `/var/lib/veritas/backups/` |
| Check that each organization's evidence hash chain is intact | with every backup | same place; a broken chain turns the panel red and shows a banner |
| Warning when the license, the TLS certificate or free disk space is running out | continuously (banner at the top of the dashboard) | dashboard banner; license warnings are also written to the service log |

Backups use SQLite's online backup, so they are consistent while Veritas is receiving telemetry. Backup files are readable only by the service account because they contain the user database and signing secrets.

### Settings (environment of the service)

| Setting | Default | Meaning |
|---|---|---|
| `VERITAS_BACKUP_INTERVAL_HOURS` | 24 | hours between backups; `0` turns the schedule off |
| `VERITAS_BACKUP_KEEP` | 7 | how many backups to keep |
| `VERITAS_BACKUP_DIR` | `<data dir>/backups` | where backups go |

Set them with `sudo systemctl edit veritas` (add `[Service]` and `Environment=VERITAS_BACKUP_KEEP=14`), then `sudo systemctl restart veritas`. On macOS, add them to the `EnvironmentVariables` section of `/Library/LaunchDaemons/com.veritas.daemon.plist` and run `sudo veritas restart`; an upgrade replaces that file, so re-apply them afterwards (see MACOS.md).

### Keep a copy off the machine

A backup on the same disk does not survive losing the disk. Point `VERITAS_BACKUP_DIR` at another disk or a network mount, or copy `/var/lib/veritas/backups/` elsewhere on a schedule (for example with `rsync` from your backup system). A backup contains secrets: store copies as carefully as the server itself.

### Backing up and restoring

| Command (needs `sudo`) | What it does |
|---|---|
| `sudo veritas backup` | Make a backup now (the service keeps running; a backup also runs every 24 hours) |
| `sudo veritas backups` | List the backups |
| `sudo veritas verify-backup <file>` | Check that a backup file is complete and undamaged |
| `sudo veritas restore <file> --dry-run` | Check a backup and show what would be restored; changes nothing |
| `sudo veritas restore <file>` | Restore it: stops Veritas, replaces the data, starts Veritas again |

The backup file can be anywhere (a USB drive, a network share, your home folder).

What `restore` does, so it is safe to use:

- It checks the file first (checksums, that every database inside is healthy, that the file was not made by a *newer* Veritas than the one installed). A damaged or unsuitable backup is refused **before anything is changed**.
- It refuses to run while the service is answering, because replacing databases under a running server corrupts them. The command stops the service for you.
- What it replaces is copied to `backups/pre-restore-<time>/` inside the data folder first. If anything fails part-way, everything is put back automatically. Delete the `pre-restore-*` folder when you are satisfied (it holds old secrets and certificates).
- The license currently installed is **kept**; the backup's license is not restored over it (so a restore cannot bring back an older or expired license). Use `--restore-license` to restore the backup's license as well.
- After a restore, Veritas starts again and checks the evidence chain at its next pass; you can also press **Verify Cryptographic Hash Chain** on the Audit Ledger page.

Moving to a new machine: install Veritas there, install a license issued for **that** machine's fingerprint (`veritas fingerprint`), then `sudo veritas restore <file>`. The secrets that protect the databases travel inside the backup, so the restored data stays readable.

## Capacity: how many events per second

Finding personal data in a line is the costly step, and it runs in **detection workers**: separate processes, each holding its own copy of the language model (about 1 GB of memory each).

| Setting | Meaning |
|---|---|
| `VERITAS_DETECTION_WORKERS` | `auto` (default), a number, or `0`. `auto` uses one worker per spare core, as many as the memory allows, at most 4, and none on a machine with fewer than 3 cores or about 5 GB of memory (detection then runs in one background thread, the original behaviour). |
| `VERITAS_DETECTION_QUEUE` | How many events may wait for a free worker before new ones are refused with "busy, retry" (HTTP 503 with `Retry-After`). Default 50 per worker. |

**What to expect.** Measured on a shared 4-core, 15 GB test machine (GitHub's standard Linux runner; 30% of the lines held personal data; the load generator ran on the same machine, so a dedicated server does better):

| Detection workers | Events per second | Wait for one event, 20 agents (median) |
|---|---|---|
| 0 (one background thread) | about 90 | about 200 ms |
| 2 | about 185 | about 100 ms |
| 3 | about 300 | about 60 ms |

Nothing was lost in any run, every finding the server reported was stored, and the evidence chain verified. Events arrive one line each, so one busy application can use a whole worker alone. Throughput grew almost in step with the workers, up to the cores available. These are one machine's figures on one day (the same test varied by up to 40% between runs on shared hardware): measure your own with `tools/loadtest.py`, or the manual **Load test** workflow, before relying on a number.

When the server is busier than it can handle, nothing is lost: an agent keeps its lines in memory (1,000 by default), is told to wait a second, and tries again. Only a source that stays above the server's rate for long enough to fill that buffer drops lines, and the agent reports how many (`dropped_buffer_full` in the dashboard's Agents tab). The dashboard's health card, `/metrics` (`veritas_detection_*`) and `GET /api/system/health` show the workers, the queue and the number refused.

## Telling people when something is wrong (alerts)

Veritas can send a message when something needs a person, so nobody has to watch the dashboard. Set one or both channels in the service's settings (`/etc/veritas/config.env` on Linux and macOS, then `sudo veritas restart`):

| Setting | Meaning |
|---|---|
| `VERITAS_ALERT_WEBHOOK_URL` | An incoming-webhook address (Slack, Microsoft Teams, Mattermost, or your own receiver). Veritas POSTs JSON: `{"text": "...", "veritas": {...}}`. |
| `VERITAS_ALERT_EMAIL_TO` and `VERITAS_SMTP_HOST` | Recipients (comma separated) and the mail server. Optional: `VERITAS_SMTP_PORT` (587), `VERITAS_SMTP_USER`, `VERITAS_SMTP_PASSWORD`, `VERITAS_SMTP_FROM`, `VERITAS_SMTP_SECURITY` (`starttls`, `ssl` or `none`). |
| `VERITAS_ALERT_MIN_SEVERITY` | `HIGH` (default), `MEDIUM` or `LOW`: the lowest severity of finding that is sent. A breach-notification candidate is always sent. |
| `VERITAS_PUBLIC_URL` | For example `https://veritas.example.com:8000`: adds a link to the dashboard. |

Check it: `sudo veritas test-alert` sends a test message and prints, for each channel, `sent` or the reason it failed.

What is sent:

- **New findings.** One message a minute per organization, however many findings arrived, with counts, rules, field names and violation numbers. Never a personal data value, an explanation text or a secret.
- **Conditions that need action:** a failed scheduled backup, a broken evidence chain, an overdue backup, a license or TLS certificate that expires within 30 days, an invalid license, a disk with less than 10% free. Each is sent once, repeated after 24 hours while it lasts, and sent again if it returns after being fixed.

A channel that fails (wrong address, mail server down) is logged and does not affect Veritas.

## Monitoring (metrics)

For your own monitoring system, Veritas serves metrics in the Prometheus text format at `GET /metrics`. It is **off** until you set `VERITAS_METRICS_TOKEN` (at least 16 characters, chosen by you); the request must carry `Authorization: Bearer <token>`. Example Prometheus scrape job:

```yaml
scrape_configs:
  - job_name: veritas
    scheme: https
    tls_config: { insecure_skip_verify: true }   # or ca_file: with the server certificate
    authorization: { credentials: "<your token>" }
    static_configs: [{ targets: ["veritas.example.com:8000"] }]
```

Metrics: `veritas_info{version}`, `veritas_license_valid`, `veritas_license_days_remaining`, `veritas_tls_certificate_days_remaining`, `veritas_disk_free_percent`, `veritas_disk_free_bytes`, `veritas_database_bytes{database}`, `veritas_backup_last_ok`, `veritas_backup_age_seconds`, `veritas_evidence_chains_broken`, `veritas_agents{org,status}`, `veritas_findings{org,status}`, `veritas_alert_channel_configured{channel}`. Useful alerts: `veritas_license_days_remaining < 30`, `veritas_backup_age_seconds > 172800`, `veritas_evidence_chains_broken > 0`, `veritas_disk_free_percent < 10`.

## Asking for help (support bundle)

`sudo veritas support-bundle` writes one ZIP file (in the current folder, or the path you give) for your Veritas contact. It contains the release, license status, the acceptance check, disk space, the names and sizes of the data files, the settings in effect (secret values hidden) and the recent log lines with tokens, keys and personal identifiers removed. It **does not** contain a database, key, certificate, license file or password. Read it before you send it if you like: it is a plain ZIP of text files.

## Upgrading

Install the newer package over the old one (`sudo apt install ./veritas_<version>_amd64.deb`, or `sudo installer -pkg veritas_<version>_arm64.pkg -target /` on a Mac). Your data, license and accounts are kept.

What the upgrade does for you:

- **It backs up first.** Before anything is replaced, it makes a backup with the release that is still installed. The line "backing up your data before upgrading" shows it, and `sudo veritas backups` lists it. If that backup fails the upgrade goes on (your data is not touched by an upgrade) and the failure is printed.
- **It starts the service again** when it is done (a first install waits for a license instead).
- **It refuses to install an older release over a newer one.** A newer release can change how data is stored, and an older one may not understand it. The message names both versions. To go back on purpose, run `sudo touch /var/lib/veritas/ALLOW_DOWNGRADE` and install the older package again; the marker allows exactly one downgrade. The safest way back is to restore a backup that the older release made.
- **If an older program is started on newer data** (for example after a manual file copy) it stops once with "DATA FORMAT ERROR" and says what to do, instead of running on data it cannot read.

To go back after a bad upgrade: install the previous package with the marker above, then `sudo veritas restore <the backup the upgrade made>`.

## TLS certificate

Veritas creates a self-signed certificate on first start (valid about 2 years). Browsers show a warning and agents need the certificate (`VERITAS_CA_CERT`). To use a certificate from your own CA or a public CA:

```bash
sudo veritas install-cert /path/to/server-chain.pem /path/to/server-key.pem
```

- The first certificate in the file must be the server certificate; intermediate certificates may follow.
- The key must not be protected by a passphrase (`openssl pkey -in key.pem -out key-nopass.pem`).
- Veritas refuses a key that does not match, a certificate that has expired or is not valid yet, and anything that is not PEM; in that case nothing is changed.
- The previous certificate and key are kept next to the new ones (`server.crt.<timestamp>`).
- The service restarts to load it. The name agents connect to must be listed in the certificate; agents must trust the issuer.

When the certificate has 30 days left the dashboard shows a banner. Renew it with the same command.

## License

The dashboard banner appears 30 days before the license ends (red in the last 7). To renew: send the same machine fingerprint (`sudo veritas fingerprint`) to your Veritas contact, then `sudo veritas license /path/to/new.vlic`.

If a license expires while Veritas is running, the service **keeps running and keeps collecting evidence** (a compliance record should not stop because of paperwork) and shows a red banner. The next restart refuses to start without a valid license.

## Users and passwords

Administrators manage accounts under **Users** (SUPER ADMIN only): add users, change roles, give access to organizations, disable accounts, reset passwords. Passwords need at least 10 characters, must not be a common password and must not contain the username or email name. A reset gives a temporary password shown once; the user must choose their own at the next sign-in. Changing or resetting a password signs that account out everywhere else. At least one active SUPER ADMIN must always remain.

### Lost administrator password

If no administrator can sign in, on the server run:

```bash
sudo veritas reset-password <username>
```

It prints a temporary password. That user must choose a new one at the next sign-in; their other sessions end. The reset is written to the audit log (`PASSWORD_RESET`, by "system (command line)").

### Failed sign-ins

Five wrong passwords for the same account name lock that name for 15 minutes, whatever address they come from (and the same applies to names that do not exist, so nothing is revealed about which accounts exist). The lock is recorded as `ACCOUNT_LOCKED` in the audit log and ends by itself. Sign-in is also limited per address (10 attempts per 5 minutes).
