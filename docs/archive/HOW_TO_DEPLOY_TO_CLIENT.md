# Veritas — How to Deploy to a Client

Complete step-by-step guide for onboarding a new client onto Veritas.
Covers: license generation, installation, and agent setup.

---

## What You Need Before Starting

- Access to the Veritas License Portal (your Vercel deployment)
- `VeritasSetup-1.0.0.exe` (from `installer/output/`)
- Client's Windows PC / server ready

---

## STEP 1 — Get the Client's Machine Fingerprint

Send the client this file:
```
tools/fingerprint.py
```

They run it on the machine where Veritas will be installed:
```bash
python tools/fingerprint.py
```

They send you back the 64-character hex hash it prints. Looks like:
```
cbcebd427dc4e6785a7cc3670002ee31b1b0575613b87ae06a485824519a9337
```

> **If the client doesn't have Python:** compile `tools/fingerprint.py` with PyInstaller
> into `veritas-fingerprint.exe` and send that instead — no Python required.

---

## STEP 2 — Generate the License (via Portal)

1. Open your Veritas License Portal:
   ```
   https://veritas-license-portal.vercel.app
   ```
   *(or whatever your Vercel URL is)*

2. Enter your **Admin Secret**

3. Fill in the form:

   | Field | What to enter |
   |-------|--------------|
   | Organisation ID | Client's org identifier, e.g. `acme_bank` (lowercase, no spaces) |
   | Tier | `starter` / `professional` / `enterprise` (per their plan) |
   | Expiry Date | License end date, e.g. `2027-01-01` |
   | Machine Fingerprint | Paste the 64-char hash from Step 1 |

4. Click **Generate License**

5. Click **Download `acme_bank.vlic`**

You now have the client's license file.

---

## STEP 3 — Send the Client Two Files

```
VeritasSetup-1.0.0.exe     ← the Windows installer
acme_bank.vlic             ← their machine-bound license
```

Send via email, WeTransfer, Google Drive — any file transfer method.

---

## STEP 4 — Client Installs Veritas (they do this)

1. Right-click `VeritasSetup-1.0.0.exe` → **Run as Administrator**
2. Click through the wizard:
   - Welcome → Next
   - License Agreement → I Accept → Next
   - Install Location → keep default (`C:\Program Files\Veritas\`) → Next
   - **License File** → Browse → select their `.vlic` file → Next
   - Click **Install**
3. Installation takes 1-2 minutes (registers Windows Service, starts Veritas)
4. On the Finish screen → check **"Open Veritas Dashboard"** → Finish

Veritas is now running. It will **auto-start on every Windows boot** — no manual step ever needed again.

---

## STEP 5 — Client Opens the Dashboard

Open any browser and go to:
```
http://localhost:8000
```

First time: the **Welcome Screen** appears → click **Configure Organisation** → fill in org details → Submit.

---

## STEP 6 — Setup the Data Forwarder (Veritas Agent)

The Agent forwards the client's application logs to Veritas for analysis.

### 6a — Issue a Registration Key (client does this from dashboard)

1. Open dashboard → **Agents** tab
2. Click **Issue Registration Key**
3. Copy the key (valid for 30 minutes, single-use)

### 6b — Configure the Agent

Create `agent-config.yaml` on the machine where the Agent will run:

```yaml
veritas_address: http://localhost:8000   # if Agent runs on same machine as Veritas
                                          # OR use the PC's IP: http://192.168.1.X:8000

registration_key: PASTE_KEY_FROM_DASHBOARD_HERE

source_label: production-server

sources:
  # Tail a log file
  - type: file
    path: C:\path\to\your\application.log
    source_system: your-app-name      # must match what's in org config

  # Tail a Docker container (if using Docker)
  - type: docker
    container: your-container-name
    source_system: your-app-name
```

### 6c — Run the Agent

**Option A — Python (quick test)**
```bash
cd veritas-agent
pip install -r requirements.txt
python agent.py
```

**Option B — Docker (recommended for production)**
```bash
cd veritas-agent
docker build -t veritas-agent:latest .
docker run -d \
  -v ./agent-config.yaml:/app/agent-config.yaml:ro \
  -v veritas-state:/app \
  -v /var/log:/var/log:ro \
  --restart unless-stopped \
  veritas-agent:latest
```

**Option C — Kubernetes**
```bash
# Fill in agent-config.yaml values then:
kubectl apply -f veritas-agent/k8s/agent-secret.yaml
kubectl apply -f veritas-agent/k8s/agent-configmap.yaml
kubectl apply -f veritas-agent/k8s/agent-deployment.yaml
```

### 6d — Verify Agent is Connected

Back in the dashboard → **Agents** tab → agent should appear as **ACTIVE** within seconds.

---

## STEP 7 — Verify Everything Works

1. **Agent ACTIVE** — visible in Agents tab with green badge
2. **Events flowing** — Live Stream tab shows incoming events
3. **Violations detected** — if the client's logs contain PII in wrong places, violations appear automatically
4. **Chain verification** — Audit Ledger tab → click **Verify Cryptographic Hash Chain** → shows `VERIFIED ✓`

---

## Summary Flow

```
You                                    Client
───                                    ──────
Ask for machine fingerprint →
                                       Runs fingerprint.py → sends hash
Open License Portal →
Enter org, tier, expiry, hash →
Download client.vlic →
Send VeritasSetup.exe + client.vlic →
                                       Runs installer (as Admin)
                                       Browses to .vlic when prompted
                                       Clicks Install → Veritas starts
                                       Opens http://localhost:8000
                                       Configures organisation
                                       Issues Agent registration key →
                                       Configures agent-config.yaml
                                       Runs Veritas Agent
                                       Agent shows ACTIVE in dashboard
                                       Violations appear live ✓
```

---

## Revoking a License

From the dashboard → **Agents** tab → click **Revoke** on any agent.
The agent is blocked immediately (HTTP 403 on next event submission).

To fully expire a client's access: simply do not renew their `.vlic` — the software stops accepting events after the expiry date.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Installer says "Unknown Publisher" | Click "More info" → "Run anyway" (no code signing yet) |
| Dashboard not loading | Wait 60s — spaCy model takes time on first boot |
| Agent not appearing in dashboard | Check `agent-config.yaml` — `veritas_address` must be reachable from agent machine |
| License rejected on install | Re-run `fingerprint.py` on the **exact machine** that will run Veritas — fingerprint must match |
| Veritas stops after reboot | Open Services (`services.msc`) → find "Veritas" → set Startup type to Automatic |
