# Veritas on macOS

Install and run the Veritas server, and the Veritas agent, on a Mac. This page covers what is specific to macOS. The things that work the same on every platform (dashboard, organizations, users, backups, certificates, licenses) are in [OPERATIONS.md](OPERATIONS.md) and [../INSTALL.md](../INSTALL.md).

## What you need

- A Mac with **Apple silicon** (M1 or newer) running **macOS 12 or later**. Intel Macs are not supported. The automated tests run on a current macOS release; older versions are expected to work but are not tested on every release.
- An administrator account (you will type your password for `sudo`).
- Server: 4 GB RAM recommended (2 GB minimum), 2 GB free disk. The agent needs almost nothing.
- A license for **this Mac** (see step 3). The license is tied to the Mac's hardware.

> **The packages are not signed by Apple.** Install them from Terminal with `sudo installer` as shown below. Double-clicking an unsigned `.pkg` that was downloaded in a browser makes macOS show "cannot be opened because it is from an unidentified developer". Files downloaded with `curl` carry no such mark, so the Terminal route is the supported one.

## Part 1: The Veritas server

### 1. Download and install

Replace `1.0.22` with the current release shown on the [releases page](https://github.com/shreyaaassss/Veritas/releases/latest).

```bash
curl -L -C - -o ~/Downloads/veritas.pkg \
  https://github.com/shreyaaassss/Veritas/releases/download/v1.0.22/veritas_1.0.22_arm64.pkg
sudo installer -pkg ~/Downloads/veritas.pkg -target /
veritas version
```

The file is about 450 MB. `-C -` lets you re-run the same command to resume if the connection drops. The installer ends with "The install was successful", and `veritas version` prints the release.

Veritas starts at once and stops itself a few seconds later because it has no license yet. That is expected: the log says exactly what is missing (`sudo veritas logs`).

### 2. Get this Mac's fingerprint

```bash
veritas fingerprint
```

It prints one line starting with `v2:`. It comes from the Mac's hardware identifier, so renaming the Mac, changing Wi-Fi or reinstalling macOS does not change it. It changes only if the logic board is replaced. Macs cloned from the same virtual-machine image can share an identifier; ask for a new license if that applies to you.

Send that line to your Veritas contact.

### 3. Install the license

You receive a file ending in `.vlic`.

```bash
sudo veritas license ~/Downloads/your-license.vlic
```

The command copies it into place, starts Veritas and waits until the server answers. The first start takes up to a minute while the language model loads. If the license is for a different Mac, the command says so and prints this Mac's fingerprint.

### 4. Create the administrator

```bash
sudo veritas setup-code
```

Open **https://localhost:8000/setup** and enter the code, then choose a username, an email address and a password.

- The password needs at least 10 characters, must not be a common password and must not contain your username or the first part of your email address. The page shows what is still missing as you type.
- The setup page works only until the first administrator exists. The code is deleted then.

Your browser shows a certificate warning because Veritas makes its own certificate. To trust it on **this Mac** only, run:

```bash
sudo veritas trust-cert
```

and reload the page. Other computers still show the warning unless you install a company certificate (`sudo veritas install-cert`, see OPERATIONS.md).

### 5. Check it

```bash
sudo veritas check
```

This is the product's own acceptance check (license, certificate, disk space, database encryption key and more). Fix anything it marks as failed. Warnings are advice.

### Day to day

All of these need `sudo` except `status` and `version`.

| Command | What it does |
|---|---|
| `veritas status` | Whether the service is running, and its health |
| `sudo veritas start` / `stop` / `restart` | Control the service |
| `sudo veritas logs` | Follow the service logs (Ctrl+C to stop) |
| `sudo veritas license <file>` | Install a new or renewed license |
| `sudo veritas backup`, `backups`, `verify-backup <file>`, `restore <file>` | Backups; see OPERATIONS.md |
| `sudo veritas reset-password <user>` | Give a user a temporary password (lost administrator password) |
| `sudo veritas install-cert <cert> <key>` | Use a company TLS certificate |
| `sudo veritas trust-cert` | Make this Mac trust Veritas's own certificate |
| `sudo veritas uninstall [--purge-data]` | Remove Veritas (see below) |

Veritas starts by itself when the Mac starts. It is a background service: nobody needs to be logged in. A Mac that is asleep does not receive telemetry or run backups, so use a Mac that stays on (set **System Settings, Battery or Energy, prevent automatic sleeping**) for anything beyond testing.

The service restarts itself only after a crash. A problem that restarting cannot fix, such as a missing or wrong license, stops it once with a clear message in `sudo veritas logs`.

### Where things are

| What | Where |
|---|---|
| Program | `/opt/veritas/` (owned by root) |
| Data: databases, license, secrets, certificates, backups | `/var/lib/veritas/` (private to the service account `_veritas`) |
| Logs | `/var/log/veritas/veritas-app.log` (the server's own log) plus `veritas.log` and `veritas-error.log` (start-up and crash output). All private; read with `sudo veritas logs` |
| Settings | `/etc/veritas/config.env` (kept across upgrades) |
| Service definition | `/Library/LaunchDaemons/com.veritas.daemon.plist` |
| Command | `/usr/local/bin/veritas` |

### Settings (AI mode, port, backup schedule, alerts, metrics)

Settings live in `/etc/veritas/config.env`, the same file as on Linux, with a commented example of every setting. The package creates it once and **never replaces it**: upgrades keep it, and `sudo veritas uninstall` keeps it too (only `--purge-data` removes it). It is readable by root and the service account only (an access-control entry for the service account; `ls -le /etc/veritas` shows it), because it can hold a mail password or a token.

```bash
sudo nano /etc/veritas/config.env      # one NAME=value per line, # for comments
sudo veritas restart
```

For example, to keep 14 backups: `VERITAS_BACKUP_KEEP=14`. The settings are listed in OPERATIONS.md. A setting in the service definition (`/Library/LaunchDaemons/com.veritas.daemon.plist`) still wins over the file, so earlier plist edits keep working; but the upgrade replaces the plist, so move them into `config.env`.

### Upgrading

Install the newer package over the old one. Your data, license and accounts are kept and the service starts again by itself:

```bash
sudo installer -pkg ~/Downloads/veritas-NEW.pkg -target /
veritas version
```

The upgrade makes a backup of its own first (see [OPERATIONS.md](OPERATIONS.md#upgrading)), and refuses to install an older release over a newer one.

### Uninstalling

```bash
sudo veritas uninstall                 # removes the program and service; keeps your data
sudo veritas uninstall --purge-data    # removes everything, including the database, license and accounts
```

A plain uninstall followed by installing again finds your data.

## Part 2: The Veritas agent

The agent reads log files on a machine and sends them to the Veritas server. On a Mac it is a single self-contained program: **no Python is needed**. You can install it on the same Mac as the server or on any other Apple-silicon Mac.

### 1. Install

```bash
curl -L -o ~/Downloads/veritas-agent.pkg \
  https://github.com/shreyaaassss/Veritas/releases/download/v1.0.22/veritas-agent_1.0.22_arm64.pkg
sudo installer -pkg ~/Downloads/veritas-agent.pkg -target /
veritas-agent version
```

The package is about 9 MB. It does **not** start the agent: it still needs to know where the server is.

### 2. Get a registration key

In the dashboard open **Agents**, then **Issue Registration Key**. The key works once and expires after 30 minutes.

### 3. Configure

```bash
sudo nano /etc/veritas-agent/config.yaml
```

Set at least:

```yaml
veritas_address: https://your-veritas-server:8000   # the address people use for the dashboard
registration_key: "PASTE-THE-KEY-HERE"
source_label: marketing-mac-1                        # the name shown in the dashboard
sources:
  - type: file
    path: /var/log/myapp/app.log
    source_system: my-app
```

Placeholder values left in the file (such as `<HOST>` or `your-veritas-server`) are refused with a clear message at start, so a forgotten edit is caught. To pin the server's certificate instead of trusting it on first contact:

```bash
sudo veritas-agent fetch-cert https://your-veritas-server:8000
```

then uncomment `ca_cert` in the config.

### 4. Let the agent read the log files

The agent runs as its own unprivileged account (`_veritas-agent`), which can read nothing private. For each file it should read:

```bash
sudo veritas-agent grant-read /var/log/myapp/app.log
```

This gives that one account read access to that one file (and lets it pass through the folders on the way). It changes nothing else and does not change who owns the file.

**Folders macOS protects** (Desktop, Documents, Downloads, iCloud Drive and similar in a user's home) cannot be opened by a background service even with permission. If `grant-read` reports that the account still cannot read the file, keep the log somewhere else, such as `/var/log/myapp/`.

### 5. Start and check

```bash
sudo veritas-agent start
sudo veritas-agent logs        # look for "Registered as VERITAS-AGENT-..."
```

The agent appears under **Agents** in the dashboard within seconds, with its version, queue, and the state of each file ("reading", "waiting for the file", or an error such as "Permission denied").

### Day to day

| Command | What it does |
|---|---|
| `veritas-agent status` | Whether the agent is running |
| `sudo veritas-agent start` / `stop` / `restart` | Control the agent |
| `sudo veritas-agent logs` | Follow the agent log |
| `sudo veritas-agent grant-read <file>` | Allow the agent to read one more file |
| `sudo veritas-agent fetch-cert <url>` | Save the server's certificate for pinning |
| `sudo veritas-agent uninstall [--purge-data]` | Remove the agent; `--purge-data` also removes its identity and config |

After the first registration the agent keeps its permanent identity in `/var/lib/veritas-agent/` (private); the key is not needed again. Do not delete that folder unless you want to enroll the agent again with a new key. Upgrading with a newer package keeps the identity and your config.

How it behaves:

- It follows log rotation, both a file that is renamed and replaced, and a file that is emptied in place. No lines are lost or repeated.
- If the server is unreachable it keeps the newest 1,000 lines in memory and delivers them when the server returns.
- A key that is wrong, already used or expired stops the agent once with the reason in `sudo veritas-agent logs`. Fix the config and run `sudo veritas-agent start`. (It does not retry in a loop.)
- Where files are: program `/opt/veritas-agent/`, config `/etc/veritas-agent/config.yaml`, log `/var/log/veritas-agent/agent.log`, service `/Library/LaunchDaemons/com.veritas.agent.plist`.

**Not supported by the Mac agent package yet:** reading Docker container logs (the agent's account cannot reach Docker Desktop's socket). Use log files.

## Troubleshooting

| Problem | What to do |
|---|---|
| `veritas status` says the service is not running right after install | Normal until a license is installed. `sudo veritas logs` shows what is missing. |
| "License ... not valid for this machine" | The license was issued for another Mac. Run `veritas fingerprint`, send the line to your Veritas contact and ask for a license for this Mac. |
| `sudo veritas setup-code` says to use sudo, or says there is no code | Use `sudo`. "No code" means setup is already done, or the service has not started yet. |
| The browser shows a certificate warning | Expected with the built-in certificate. `sudo veritas trust-cert` removes it on this Mac. |
| The page does not load at all | `veritas status`; then `sudo veritas logs`. Another program using port 8000 stops Veritas from starting. |
| "installer: ... damaged" or a very small file | The download was cut short. Run the same `curl -L -C -` command again to finish it. |
| macOS refuses to open the package when you double-click it | Expected for an unsigned package. Use `sudo installer -pkg ... -target /`. |
| `veritas logs` says "needs administrator rights" | Logs are private to the service. Use `sudo veritas logs`. |
| Agent: "Permission denied" shown for a source in the dashboard | `sudo veritas-agent grant-read <file>`, then `sudo veritas-agent restart`. |
| Agent: stopped right after start | `sudo veritas-agent logs`: a used key or a missing address. Fix `/etc/veritas-agent/config.yaml` and start again. |
| Agent: key refused ("already used" or "expired") | Issue a new key in the dashboard (Agents, Issue Registration Key) and put it in the config. |

## Known limits on macOS

- Apple silicon only; packages are not signed or notarized by Apple.
- The server rotates its own log (10 MB at a time, 5 compressed copies kept). The agent's log (`/var/log/veritas-agent/agent.log`) is not rotated yet.
- The Mac server is tested on a clean Apple-silicon machine for install, license, upgrade over the same version, backup and restore, and uninstall. Long-running behavior (weeks of uptime, a sleeping laptop) has not been measured yet.
