# Veritas — Installing from source (advanced)

> Customers install Veritas from the packages (`.deb`, `.pkg`, Windows installer): see `INSTALL.md`.
> These scripts install the server **from a source checkout** on Debian/Ubuntu or macOS, for development and unusual setups.

## Requirements

- Debian/Ubuntu-based Linux (64-bit)
- Python 3.10+
- 4 GB RAM recommended (spaCy NLP model uses ~400 MB)
- Network access on first install (to download Python packages and spaCy model)

---

## First Install

From the repository root, run once as root:

```bash
sudo bash deploy/install.sh
```

This will:
1. Create a dedicated `veritas` system user
2. Copy the project to `/opt/veritas/dpdpa-agent/`
3. Create a Python virtual environment at `/opt/veritas/venv/`
4. Install all dependencies and download the spaCy language model
5. Install and enable the `veritas` systemd service
6. Start Veritas immediately

Installation takes **5–15 minutes** (mostly the spaCy model download).

---

## After Install

| Task | Command |
|------|---------|
| Open dashboard | http://`<device-ip>`:8000 |
| Check service health | `systemctl status veritas` |
| Follow live logs | `journalctl -u veritas -f` |
| Restart service | `systemctl restart veritas` |
| Stop service | `systemctl stop veritas` |
| Disable auto-start | `systemctl disable veritas` |

---

## Updating Veritas

Re-running the installer is safe — it syncs the latest project files and restarts the service. Your evidence store and agent registrations are preserved.

```bash
sudo bash deploy/install.sh
```

---

## LLM Investigation (Optional)

The breach investigation feature (`@01 What happened?`) requires an OpenAI API key. Without one, the system falls back to deterministic template explanations — all other features work normally.

To enable:

```bash
sudo nano /opt/veritas/dpdpa-agent/.env
```

Add:

```
OPENAI_API_KEY=sk-...
```

Then restart:

```bash
sudo systemctl restart veritas
```

---

## Acceptance Test

Verify Veritas starts automatically after a reboot:

```bash
sudo reboot
```

Wait ~30 seconds, then:

```bash
curl http://localhost:8000/v1/orgs
# Expected: {"org_ids": ["retail_co", ...]}
```

Or open `http://<device-ip>:8000` in a browser — the dashboard should load without any manual intervention.

---

## File Locations (after install)

| Path | Contents |
|------|----------|
| `/opt/veritas/dpdpa-agent/` | Veritas source code |
| `/opt/veritas/venv/` | Python virtual environment |
| `/opt/veritas/dpdpa-agent/.env` | Secrets (OPENAI_API_KEY etc.) — create manually |
| `/opt/veritas/dpdpa-agent/evidence_store/evidence.db` | Tamper-evident audit ledger (SQLite) |
| `/opt/veritas/dpdpa-agent/agent_store/agents.db` | Registered agents (SQLite) |
| `/opt/veritas/dpdpa-agent/org_config/configs/` | Organisation configurations (YAML) |
| `/etc/systemd/system/veritas.service` | systemd unit file |

---

## Troubleshooting

**Service fails to start:**
```bash
journalctl -u veritas -n 100 --no-pager
```

**Port 8000 already in use:**
```bash
sudo fuser -k 8000/tcp
sudo systemctl start veritas
```

**Out of memory on Pi:**
The spaCy model requires ~400 MB. If the Pi runs out of memory, check:
```bash
free -h
journalctl -u veritas | grep -i "killed\|oom"
```
Consider closing other services or using a machine with more memory (4 GB or more is recommended).
