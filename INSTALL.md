# Veritas DPDPA Compliance Platform — Installation & Setup Guide

**Version:** 1.0.22  
**Supported OS:** Ubuntu 22.04+, macOS 12+ (Apple Silicon), Windows Server 2019/2022 / Windows 10/11

---

## Table of Contents

1. [Overview](#overview)
2. [Before You Install](#before-you-install)
3. [Linux Installation (Ubuntu / Debian)](#linux-installation)
4. [macOS Installation](#macos-installation)
5. [Windows Installation](#windows-installation)
6. [First-Boot Setup](#first-boot-setup)
7. [Agent Deployment](#agent-deployment)
8. [License Management](#license-management)
9. [CLI Reference](#cli-reference)
10. [Troubleshooting](#troubleshooting)

---

## Overview

Veritas runs entirely on your infrastructure — no data leaves your network except optional AI investigation calls (which send no raw PII). Two components:

| Component | Purpose | Installs on |
|---|---|---|
| **Veritas Server** | Compliance dashboard, PII detection, evidence store | Your compliance hub (1 machine) |
| **Veritas Agent** | Lightweight log forwarder | Every server you want to monitor |

---

## Before You Install

### System Requirements

| | Server | Agent |
|---|---|---|
| **OS** | Ubuntu 22.04+ / macOS 12+ (Apple silicon) / Windows 10+ | Ubuntu 18.04+ or any Linux; macOS 12+ (Apple silicon) |
| **RAM** | 2 GB minimum, 4 GB recommended | 128 MB |
| **Disk** | 2 GB free | 50 MB |
| **Network** | Outbound HTTPS (optional, for AI) | Outbound to Veritas server |

### Get Your License

Veritas requires a machine-bound license. Workflow:

1. Install Veritas (steps below)
2. Run `veritas fingerprint` (Linux/macOS) or `veritas fingerprint` (Windows)
3. Send the line it prints (on Linux and macOS it starts with `v2:`) to your Veritas contact
4. You receive a `veritas.vlic` file
5. Install it with `sudo veritas license /path/to/veritas.vlic` (on Linux and macOS this also starts the service)

---

## Linux Installation

### Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/shreyaaassss/Veritas/main/install.sh | sudo bash
```

### Manual Install

```bash
wget https://github.com/shreyaaassss/Veritas/releases/download/v1.0.22/veritas_1.0.22_amd64.deb
sudo dpkg -i veritas_1.0.22_amd64.deb
```

### Complete Setup Flow

```bash
# 1. Get machine fingerprint — send output to your Veritas contact
sudo veritas fingerprint

# 2. Install your license file (received from Veritas contact)
sudo veritas license /path/to/veritas.vlic

# 3. Start the service
sudo veritas start

# 4. Check status
sudo veritas status

# 5. Open dashboard in browser
# https://localhost:8000/setup  (first time — create admin account; asks for the code from: sudo veritas setup-code)
# https://localhost:8000        (after setup)
```

### Service Management

```bash
sudo veritas start       # Start
sudo veritas stop        # Stop
sudo veritas restart     # Restart
sudo veritas status      # Status
sudo veritas logs        # Stream live logs (Ctrl+C to stop)
sudo veritas check       # Run health checks
```

### Configuration

Edit `/etc/veritas/config.env` then restart:

```bash
sudo nano /etc/veritas/config.env
sudo veritas restart
```

```env
# TLS (auto-generated self-signed cert by default)
# VERITAS_TLS=false       # Disable TLS (dev only)

# AI Investigation (optional — no raw PII is ever sent)
# ANTHROPIC_API_KEY=sk-ant-...
# VERITAS_AI_MODE=external

# Port (default: 8000)
# VERITAS_PORT=8000
```

### Accessing the Dashboard

The server runs on HTTPS with a self-signed certificate.

- In Chrome: navigate to `https://localhost:8000` → type **`thisisunsafe`** on the warning page
- In Firefox: click **Advanced → Accept Risk**
- In Safari: click **Show Details → visit this website**

---

## macOS Installation

Apple silicon (M1 or newer), macOS 12 or later. The package is **not signed by Apple**, so install it from Terminal (a double-click on a browser-downloaded unsigned package is blocked by macOS). The full guide, including the agent, troubleshooting and the file locations, is in **[docs/MACOS.md](docs/MACOS.md)**. In short:

```bash
# 1. Download and install (replace 1.0.22 with the current release; ~450 MB, re-run the same curl to resume)
curl -L -C - -o ~/Downloads/veritas.pkg \
  https://github.com/shreyaaassss/Veritas/releases/download/v1.0.22/veritas_1.0.22_arm64.pkg
sudo installer -pkg ~/Downloads/veritas.pkg -target /

# 2. Get this Mac's fingerprint (a line starting with v2:) and send it to your Veritas contact
veritas fingerprint

# 3. Install the license you receive; this starts the service and waits until it answers
sudo veritas license ~/Downloads/your-license.vlic

# 4. Get the one-time setup code, then open https://localhost:8000/setup and create the administrator
sudo veritas setup-code

# 5. Run the acceptance check
sudo veritas check
```

Before step 3 the service stops itself a few seconds after install because it has no license: that is expected.

Day to day: `veritas status`, `sudo veritas start|stop|restart`, `sudo veritas logs`. Logs are in `/var/log/veritas/` (private; read them with `sudo veritas logs`). The service starts when the Mac starts and restarts only after a crash.

The one-line installer (`curl ... install.sh | sudo bash`) does the download and install of step 1; the other steps follow.

---

## Windows Installation

### Install

1. Download **`veritas_1.0.22_windows_amd64.exe`** from [GitHub Releases](https://github.com/shreyaaassss/Veritas/releases/latest)
2. Right-click → **Run as Administrator**
3. Follow the setup wizard:
   - Choose install directory (default: `C:\Program Files\Veritas\`)
   - Select your `.vlic` license file when prompted *(or skip and install later)*
4. The installer registers Veritas as a Windows Service (auto-start on boot)

> **Note:** If you skip the license during install, place your `.vlic` file at
> `C:\Program Files\Veritas\veritas.vlic` then restart the service.

### Get Machine Fingerprint

Open **Command Prompt as Administrator**:

```cmd
"C:\Program Files\Veritas\veritas-launcher.exe" fingerprint
```

Or run the standalone fingerprint tool:

```powershell
python tools\fingerprint.py
```

### Install License After Setup

```powershell
# Copy license to install directory
Copy-Item "C:\path\to\veritas.vlic" "C:\Program Files\Veritas\veritas.vlic"

# Restart the service
Restart-Service -Name "VeritasService"
```

### Service Management

Via **Services panel** (`services.msc`): look for **Veritas DPDPA Platform**

Or via command line (as Administrator):

```cmd
net start VeritasService
net stop VeritasService
```

Or via the Go launcher:

```cmd
cd "C:\Program Files\Veritas"
veritas-launcher.exe start
veritas-launcher.exe stop
veritas-launcher.exe status
```

### Access Dashboard

Open your browser: **http://localhost:8000/setup**

> Windows uses HTTP by default. TLS can be enabled by setting `VERITAS_TLS=true`
> in the environment before starting the service.

### Logs Location

```
C:\Program Files\Veritas\veritas.log
C:\Program Files\Veritas\veritas-error.log
```

Or view via Windows Event Viewer → Application logs.

---

## First-Boot Setup

After starting Veritas for the first time on any platform:

1. Get the **setup code**. It proves you have access to this server, so that nobody else who can reach the page first can create the administrator:
   - Linux / macOS: `sudo veritas setup-code`
   - Any platform: it is also printed in the service log when Veritas starts (look for `SETUP CODE`; on Linux `sudo journalctl -u veritas | grep "SETUP CODE"`), and stored in `secrets/setup_code` inside the data directory (`/var/lib/veritas` on Linux and macOS, the installation folder on Windows).
   - Automated installs can set the code themselves with the `VERITAS_SETUP_CODE` environment variable (then nothing is written to disk).
2. Open **https://localhost:8000/setup** (Linux/macOS) or **http://localhost:8000/setup** (Windows)
3. Enter the setup code and create your administrator account:
   - Username (min 3 characters)
   - Email address
   - Password (min 10 characters; not a common password; must not contain your username or the first part of your email address — the page shows what is still missing as you type)
4. Click **Create Administrator Account**
5. Log in at `https://localhost:8000`

> The setup code is created when the service first starts, stays the same across restarts until it is used, and is deleted as soon as the administrator exists. The `/setup` page only works while no users exist. After 10 attempts in 10 minutes from one address the page refuses further tries.

### Upload Your Organisation Config

1. Log in → **Settings → Org Config**
2. Upload your `org_config.yaml` defining which fields to monitor, retention policies, and source systems

---

## Agent Deployment

Install the Veritas Agent on each server you want to monitor. The agent is a lightweight log forwarder (~9 KB package, no ML models).

### Step 1 — Install the Agent

**Ubuntu / Debian:**

```bash
wget https://github.com/shreyaaassss/Veritas/releases/download/v1.0.22/veritas-agent_1.0.22_all.deb
sudo dpkg -i veritas-agent_1.0.22_all.deb
```

Dependencies (`python3`, `python3-requests`, `python3-yaml`) are installed automatically.

### Step 2 — Issue a Registration Key

On the Veritas **dashboard**:
1. Go to **Agents** tab
2. Click **Issue Registration Key**
3. Select your org ID
4. Copy the key (format: `XXXXXXXXXXXXXXXXXXXXXXXX`, one-time use)

### Step 3 — Fetch the Server TLS Certificate

```bash
sudo veritas-agent fetch-cert https://your-veritas-server:8000
```

This downloads the server certificate to `/etc/veritas-agent/server.crt`.

> Skip if your server runs without TLS and set `verify: false` in the config.

### Step 4 — Configure the Agent

```bash
sudo nano /etc/veritas-agent/config.yaml
```

```yaml
# Veritas server address
veritas_address: https://your-veritas-server:8000

# Registration key from the dashboard (one-time use, valid 30 minutes, consumed on first connect)
registration_key: "AkBOPDQygiU4fjZTdXAI4w"

# TLS verification. The agent downloads and remembers the server certificate on
# first contact. To pin the certificate from Step 3 instead, uncomment ca_cert.
tls:
  # ca_cert: /etc/veritas-agent/server.crt
  verify: true

# Label shown in the dashboard
source_label: production-web-server

# Log sources to monitor
sources:
  - type: file
    path: /var/log/app/application.log
    source_system: web-app

  - type: file
    path: /var/log/nginx/access.log
    source_system: nginx

  # Docker container logs:
  # - type: docker
  #   container: my-api-container
  #   source_system: api-service
```

### Step 5 — Start the Agent

```bash
sudo veritas-agent start
```

### Step 6 — Verify

```bash
sudo veritas-agent status
sudo veritas-agent logs        # expect "Registered as VERITAS-AGENT-..." and "Tailing file: ..."
```

The agent appears in the Veritas dashboard under **Agents** within seconds.

The **Agents** tab also shows each agent's health, reported with every heartbeat (every 30 seconds): its version, the queue of lines waiting to be sent, lines dropped, and the state of each log source (reading, waiting for the file, or an error such as "Permission denied"). An agent with no heartbeat for 90 seconds is marked stale, and agents that are stale, dropping lines or have a source in error are counted under **Needs Attention**. Hover over the health text for details.

### How the agent works on Linux

- **Identity:** after registering, the agent keeps its permanent identity (agent ID and token) in `/var/lib/veritas-agent/` (owner-only). The one-time key is not needed again. If you delete that folder the agent needs a new key.
- **Log access:** the service runs as the `veritas-agent` user with the `adm` group, which can read most files under `/var/log`. For log files owned by other users or groups, give `veritas-agent` read access (for example `setfacl -m u:veritas-agent:r /path/to/app.log`). To read Docker container logs, add the user to the `docker` group.
- **Configuration errors stop the service once.** A used or expired key, an unwritable state folder or a missing config makes the agent exit with code 78, and systemd does not restart it. Read the reason with `sudo veritas-agent logs`, fix it, then `sudo systemctl start veritas-agent`.
- **Log rotation is handled.** The agent follows both kinds of rotation: a file renamed and replaced (logrotate default), and a file truncated in place (`copytruncate`). It reads the rest of the old file first, so no lines are lost or repeated. It sends a line only once the line is complete.
- **A bad event cannot block the others.** If the server rejects one event (for example a line larger than 100,000 characters), the agent drops that event, counts it and moves on. Outages and slow responses are retried with backoff, and a bounded in-memory buffer (1,000 lines) keeps the newest lines if the outage is long.

---

### macOS agent

The agent for Apple-silicon Macs is a single self-contained program (no Python needed, about 9 MB):

```bash
curl -L -o ~/Downloads/veritas-agent.pkg \
  https://github.com/shreyaaassss/Veritas/releases/download/v1.0.22/veritas-agent_1.0.22_arm64.pkg
sudo installer -pkg ~/Downloads/veritas-agent.pkg -target /
sudo nano /etc/veritas-agent/config.yaml       # veritas_address, registration_key, source_label, sources
sudo veritas-agent grant-read /path/to/each/log/file
sudo veritas-agent start
sudo veritas-agent logs                         # expect "Registered as VERITAS-AGENT-..."
```

The agent runs as its own unprivileged account, so each log file it should read needs `grant-read`. Get the registration key as in Step 2 above. Details, file locations and troubleshooting: **[docs/MACOS.md](docs/MACOS.md)**.

---

## License Management

### How Licensing Works

1. Veritas computes a **machine fingerprint**.
   - **Linux:** `v2:` followed by a SHA-256 of the machine's `/etc/machine-id` (falling back to the disk serial if there is none). It does not depend on hostname, IP or network cards, so renaming the server or changing networking does not affect the license.
   - **macOS:** `v2:` followed by a SHA-256 of the Mac's hardware identifier (`IOPlatformUUID`, falling back to the hardware serial number). Hostname, IP and network cards are not used, so renaming the Mac or changing Wi-Fi does not affect the license.
   - **Windows:** SHA-256 of disk serial + MAC address + hostname (to be moved to the same scheme).
2. You send the fingerprint (`sudo veritas fingerprint`) to Veritas
3. Veritas signs a `.vlic` file with an RSA-2048 private key (never leaves Veritas)
4. The binary validates the signature and fingerprint on every startup

### License File Locations

| Platform | Path |
|---|---|
| Linux | `/var/lib/veritas/veritas.vlic` |
| macOS | `/var/lib/veritas/veritas.vlic` |
| Windows | `C:\Program Files\Veritas\veritas.vlic` |

### Transferring a License (New Machine)

On Linux the fingerprint changes if the OS is reinstalled (a new `machine-id` is generated) or the server is migrated to a new VM. Machines **cloned from a template or image share the same `machine-id`**: regenerate it on each clone (`sudo rm /etc/machine-id && sudo systemd-machine-id-setup`) before requesting a license. Contact your Veritas representative with the new machine's fingerprint to receive a replacement license.

---

## CLI Reference

### Server CLI (`veritas`)

| Command | Description |
|---|---|
| `sudo veritas start` | Start the service |
| `sudo veritas stop` | Stop the service |
| `sudo veritas restart` | Restart the service |
| `sudo veritas status` | Show service status |
| `sudo veritas logs` | Stream live logs |
| `sudo veritas fingerprint` | Print machine fingerprint for license |
| `sudo veritas license <file>` | Install a `.vlic` file and restart |
| `sudo veritas check` | Run production acceptance checks |
| `sudo veritas setup-code` | Print the one-time code the setup page asks for |
| `sudo veritas backup` / `backups` | Make a backup now / list backups |
| `sudo veritas verify-backup <file>` | Check a backup file |
| `sudo veritas restore <file> [--dry-run] [--restore-license]` | Restore a backup (stops and starts the service) |
| `sudo veritas reset-password <user>` | Temporary password for a user (lost administrator password) |
| `sudo veritas install-cert <cert> <key>` | Install a company TLS certificate |
| `sudo veritas trust-cert` | macOS only: trust Veritas's own certificate on this Mac |
| `sudo veritas uninstall [--purge-data]` | macOS only: remove Veritas (data is kept unless `--purge-data`) |
| `veritas version` | Print version |

### Agent CLI (`veritas-agent`)

| Command | Description |
|---|---|
| `sudo veritas-agent start` | Start the agent |
| `sudo veritas-agent stop` | Stop the agent |
| `sudo veritas-agent restart` | Restart the agent |
| `sudo veritas-agent status` | Show service status |
| `sudo veritas-agent logs` | Stream live logs |
| `sudo veritas-agent fetch-cert <url>` | Download server TLS certificate |
| `sudo veritas-agent grant-read <file>` | macOS only: let the agent read one log file |
| `sudo veritas-agent uninstall [--purge-data]` | macOS only: remove the agent |
| `veritas-agent version` | Print version |

---

## Troubleshooting

### "License not found" at startup

If the license is missing or invalid the service stops after printing one clear message and does **not** retry (see `sudo veritas logs`). Run `sudo veritas fingerprint`, send it to your Veritas contact, install the `.vlic`:
```bash
sudo veritas license /path/to/veritas.vlic
```

### "License uses the old machine fingerprint format"

The license was issued before the Linux fingerprint changed to `v2:`. Send the fingerprint shown in the message (or from `sudo veritas fingerprint`) to your Veritas contact for a reissued license.

### "This license was issued for a different server"

The machine fingerprint changed (hardware change, VM migration). Request a new license with the current fingerprint from `sudo veritas fingerprint`.

### Dashboard not loading (browser shows security warning)

The server uses a self-signed TLS certificate. Accept it in your browser:
- **Chrome:** type `thisisunsafe` on the warning page
- **Firefox:** Advanced → Accept Risk
- **Safari:** Show Details → Visit Website

### Dashboard returns 500 on /setup or /login

You are likely running an older version. Update to v1.0.12+:
```bash
curl -sSL https://raw.githubusercontent.com/shreyaaassss/Veritas/main/install.sh | sudo bash
```

### PII scan returns 500 Internal Server Error

Update to v1.0.12+. Earlier versions had a missing `presidio_analyzer/conf/` directory in the PyInstaller bundle.

### Agent not appearing in dashboard

1. `sudo veritas-agent status` — is the agent running?
2. Check config: `cat /etc/veritas-agent/config.yaml` — correct `veritas_address` and `registration_key`?
3. Registration keys are **one-time use**. Issue a new key from the dashboard if needed.
4. `sudo veritas-agent fetch-cert https://your-server:8000` — refresh TLS cert
5. `sudo veritas-agent logs` — check for connection errors

### Linux: Service crashes with "Could not create temporary directory"

This is fixed in v1.0.7+. If upgrading from an older version:
```bash
sudo mkdir -p /etc/systemd/system/veritas.service.d
sudo tee /etc/systemd/system/veritas.service.d/override.conf <<EOF
[Service]
Environment=TMPDIR=/var/lib/veritas/tmp
ProtectSystem=false
EOF
sudo systemctl daemon-reload && sudo systemctl restart veritas
```

### License file permissions error (Linux/macOS)

```bash
sudo chown veritas:veritas /var/lib/veritas/veritas.vlic   # Linux
sudo chown _veritas:staff  /var/lib/veritas/veritas.vlic   # macOS
sudo chmod 640 /var/lib/veritas/veritas.vlic
sudo systemctl restart veritas   # Linux
sudo veritas restart             # macOS
```

---

*Veritas DPDPA Compliance Platform · v1.0.22 · For support, contact your Veritas representative.*
