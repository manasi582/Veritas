# Veritas administrator runbook

When something is wrong, find the symptom below. Each entry says what it usually means, how to confirm it, and what to do. Install and day-to-day use are in [INSTALL.md](../INSTALL.md) and [OPERATIONS.md](OPERATIONS.md); the Mac specifics are in [MACOS.md](MACOS.md).

**Commands.** On Linux and macOS, `veritas` is the command. Anything that reads private files needs `sudo`. On Linux the service log is also in `journalctl -u veritas`.

## First, in one minute

```bash
veritas status                 # running or not, and the health answer
sudo veritas check             # the product's own acceptance check: license, certificate, disk, keys, databases
sudo veritas logs              # follow the log (Ctrl+C to stop); the last reason the service stopped is here
sudo veritas support-bundle    # one file for the vendor, with no secrets or database in it (see the end)
```

In the dashboard, the **health card** on the overview shows backups, license, certificate, disk, alerts and detection at a glance.

---

## The service will not start or keeps stopping

| What you see | What it means | What to do |
|---|---|---|
| `veritas status` says not running right after install | Normal until a license is installed. The service stops once, with the reason in the log. | `sudo veritas logs`, then install the license (below). |
| Log: **LICENSE ERROR**, "not valid for this machine" | The license was issued for a different machine, or the machine's hardware identity changed. | `veritas fingerprint`, send the line (starts `v2:`) to your Veritas contact, install the new file with `sudo veritas license <file>`. |
| Log: license "expired" | The license date has passed. | Ask for a renewal (the vendor reissues; the same command installs it). |
| Log: **DATA FORMAT ERROR** "written by a newer version" | An older program was started on data from a newer release (a downgrade or a copied folder). The program stops once and changes nothing. | Install the newer release again, or restore a backup made by this version (`sudo veritas restore <file>`). |
| Log: port 8000 already in use | Another program has the port. | Stop it, or set `VERITAS_PORT` in `/etc/veritas/config.env` and `sudo veritas restart`. |
| Takes about a minute to answer after a start | The language model loads, once for the server and once per detection worker. | Wait; `veritas status` says `running` before the dashboard answers. Agents are told to retry meanwhile. |
| The machine runs out of memory | Each detection worker holds about 1 GB. | Set `VERITAS_DETECTION_WORKERS=0` (or a smaller number) in `/etc/veritas/config.env`, `sudo veritas restart`. |
| After an upgrade the service did not return | The upgrade stopped it and could not start it (for example the license no longer matches). | `sudo veritas logs`; on Linux `sudo journalctl -u veritas -n 50`. |

## License

- **Check:** the dashboard shows the license in the header; `sudo veritas check` prints "Valid — org · tier · expires …".
- **Warnings:** the dashboard and an alert warn 30 days before the end. Ask for the renewal early: it needs the machine fingerprint, not a new purchase of anything else.
- **New machine:** a license is tied to one machine. Send the new machine's `veritas fingerprint` and install the reissued file there.
- **The file is not accepted at all:** make sure you copied the whole file (the text between `BEGIN VERITAS LICENSE` and `END VERITAS LICENSE`), not a screenshot or a re-typed copy.

## Signing in

| Problem | Cause and fix |
|---|---|
| "Invalid username or password" | Check the user name (it is case-sensitive). Five wrong passwords for one name lock that name for 15 minutes, even for the right password. |
| Everyone is refused with "too many attempts" (HTTP 429) | The address you sign in from made too many attempts (10 in 5 minutes). Wait 5 minutes. |
| The administrator's password is lost | `sudo veritas reset-password <username>` prints a temporary password that works once; the person must then choose their own. |
| "Choose a new password" after a reset | Expected: an administrator-set password must be replaced at the first sign-in. |
| Signed out suddenly | Changing a password ends that account's other sessions, and sessions expire. Sign in again. |
| Password refused | It needs at least 10 characters, must not be a common password, and must not contain the user name or the first part of the e-mail address. The page shows what is missing as you type. |
| A user was added but sees nothing | Give the user access to the organization (Users tab). Viewers and auditors only see organizations they were added to. |

## The dashboard

| Problem | Cause and fix |
|---|---|
| Browser warns about the certificate | Veritas made its own certificate. Mac: `sudo veritas trust-cert` removes the warning on that Mac. For everyone, install your company certificate: `sudo veritas install-cert <cert.pem> <key.pem>`. |
| The page does not load at all | `veritas status`; then `sudo veritas logs`. Check the firewall allows the port (8000). |
| The live stream stays empty but findings exist in the ledger | The browser lost its live connection (a proxy that blocks WebSockets, or the page was idle). Reload the page. Behind a reverse proxy, allow WebSocket upgrades on `/ws/`. |
| The health card shows a red or yellow item | Open it: license (renew), TLS (certificate near its end), disk (free space), backups (see Data), alerts (none set up is yellow, not a fault). |

## Agents

| Problem | Cause and fix |
|---|---|
| The agent does not appear | `sudo veritas-agent status`, then `sudo veritas-agent logs`. Look for "Registered as VERITAS-AGENT-…". Check `veritas_address` and `registration_key` in `/etc/veritas-agent/config.yaml`. A key works once and lasts 30 minutes; issue a new one (Agents, Issue Registration Key). |
| Log: "veritas_address is still a placeholder" | The configuration still holds the example text. Edit `/etc/veritas-agent/config.yaml`. (If this appears after an upgrade from an older Ubuntu package, the upgrade replaced your file: put your settings back. Fixed from 1.0.27.) |
| A source shows "Permission denied" in the dashboard | The agent's account cannot read that file. Linux: add the `veritas-agent` user to the file's group (often `adm`) or give it read access. Mac: `sudo veritas-agent grant-read <file>`. Files in Desktop, Documents or Downloads on a Mac cannot be read by a service; keep the log elsewhere. |
| Source shows "waiting for the file" | The file does not exist yet; the agent starts reading it from its start when it appears. |
| Key refused ("already used" or "expired") | Issue a new key. The agent does not retry a refused key in a loop; it stops once with the reason. |
| Agent shows **Outdated** | The server needs a newer agent than this one. Upgrade the agent package on that machine (`sudo apt install ./veritas-agent_<version>_all.deb`, or the Mac `.pkg`); it keeps its identity and configuration. |
| Dashboard shows dropped lines for an agent | The agent's buffer (1,000 lines) filled while the server was down or busy. Check the server (Capacity, below), and raise the server's workers. |
| Agent log: HTTP 503 "busy" | The server's detection queue is full; the agent waits a second and retries, and loses nothing. If it persists, add workers or cores. |
| Docker container logs on a Mac | Not supported by the Mac agent. Write the logs to a file (`docker logs -f NAME >> /var/log/myapp/NAME.log`) and read the file. |

## Findings look wrong

| Problem | Cause and fix |
|---|---|
| Nothing is detected | Is there an organization policy? An event for an unknown organization is refused (404). Check the agent's `source_system` names match the policy's systems. Check with a test line in the **Simulate** tab. |
| An Aadhaar number is not recognised | Aadhaar numbers are checked by their checksum: a made-up 12-digit number is not an Aadhaar. Test with a real-format valid number. |
| Names are missed or over-reported | Name detection uses a language model and is probabilistic. A finding is evidence to investigate, not a conclusion. |
| A finding is a mistake | Acknowledge or resolve it with a note; the record stays in the evidence chain by design. |

## Capacity

- **Speed:** see Capacity in [OPERATIONS.md](OPERATIONS.md). One server takes roughly 90 events a second with detection in a single thread and more with `VERITAS_DETECTION_WORKERS`; measure your own machine with `tools/loadtest.py`.
- **Signs of overload:** the health card's detection item, `veritas_detection_refused_total` in `/metrics`, agents reporting "busy".
- **What to do:** more cores plus workers (about 1 GB each); fewer, more selective log sources; split organizations across servers.

## Data: backups, disk, evidence

| Problem | Cause and fix |
|---|---|
| Alert or health card: **backup failed** / **overdue** | `sudo veritas logs` shows why (usually disk space or a permission on `VERITAS_BACKUP_DIR`). Fix it, then `sudo veritas backup` and `sudo veritas backups` to confirm. |
| Disk nearly full | Backups and the evidence database are the big items. Move backups with `VERITAS_BACKUP_DIR` (another disk), lower `VERITAS_BACKUP_KEEP`, or add space. |
| **Evidence chain broken** | The stored evidence no longer matches its hashes: a file was changed or damaged. Do **not** delete anything. Run `sudo veritas support-bundle` and contact your Veritas contact. To go back to a known good state: `sudo veritas verify-backup <file>`, then `sudo veritas restore <file>` (it keeps the current data in `backups/pre-restore-<time>` first). |
| Restore | `sudo veritas backups`, `sudo veritas verify-backup <file>`, `sudo veritas restore <file> --dry-run` to see what changes, then `sudo veritas restore <file>`. The service stops and starts for you. The license stays as it is unless you add `--restore-license`. |
| Moving to a new machine | Install Veritas there, get a license for that machine, then restore a backup. Backups contain the keys: treat the file like the server itself. |

## Upgrades

- Install the newer package over the old one. It makes a backup first, keeps your data, license, accounts and settings, and starts the service again.
- **"refusing to install … over the newer …"**: you tried an older package. To go back on purpose: `sudo touch /var/lib/veritas/ALLOW_DOWNGRADE`, install again, then restore a backup made by the older release.
- **After an upgrade from 1.0.26 or earlier on Ubuntu**, check that `/etc/veritas/config.env` (server) and `/etc/veritas-agent/config.yaml` (agent) still hold your settings; older upgrades could put the defaults back.
- To roll back a bad upgrade: install the previous package with `ALLOW_DOWNGRADE`, then `sudo veritas restore` the backup the upgrade made (`sudo veritas backups`, newest first).

## Alerts and metrics

- **No alerts arrive:** `sudo veritas test-alert` prints, for each channel, `sent` or the reason. Check the webhook address, the mail server, and `VERITAS_ALERT_MIN_SEVERITY` (default HIGH).
- **Too many alerts:** raise the threshold, or send only to a channel people read. Findings are sent as one message a minute per organization.
- **`/metrics` answers 401:** metrics are off until `VERITAS_METRICS_TOKEN` (16 characters or more) is set, and the request needs `Authorization: Bearer <token>`; a signed-in session does not count.

## Sending the vendor what they need

```bash
sudo veritas support-bundle        # writes veritas-support-<time>.zip in the current folder
```

The file holds the version, license status, the acceptance check, disk space, the names and sizes of the data files, the settings (secret values hidden) and recent log lines with tokens, keys and personal identifiers removed. It holds no database, key, certificate, license file or password. It is a plain ZIP of text: read it before you send it if you wish. Add: what you were doing, what you expected, what happened, and when.

## Removing Veritas

| | Removes the program, keeps data and settings | Removes everything: databases, license, accounts, settings |
|---|---|---|
| **Ubuntu** | `sudo apt remove veritas` | `sudo apt purge veritas` |
| **macOS** | `sudo veritas uninstall` | `sudo veritas uninstall --purge-data` |

The agent is removed the same way (`apt remove` / `apt purge veritas-agent`, or `sudo veritas-agent uninstall [--purge-data]` on a Mac). Backups made earlier are separate files: delete them yourself if they should not remain.
