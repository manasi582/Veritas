# Veritas — Production Windows Application Roadmap

## Current State — Updated

| Phase | Status |
|-------|--------|
| Phase 1 — RSA licensing + machine fingerprint | ✅ Complete |
| Phase 2 — PyInstaller → veritas-runtime.exe (671 MB) | ✅ Complete |
| Phase 3 — Go launcher + Windows Service | ✅ Complete |
| Phase 4 — Inno Setup Windows installer | ✅ Complete |
| Phase 5 — Code signing | Optional (skip for finals) |

**Additional deliverables:**
| Item | Status |
|------|--------|
| Data Residency doc (`docs/DATA_RESIDENCY.md`) | ✅ Complete |
| Privacy Guarantee (`docs/PRIVACY_GUARANTEE.md`) | ✅ Complete |
| Kubernetes Agent manifests | ⏳ Remaining |

`dist/` currently contains:
- `veritas-launcher.exe` — 4 MB Go binary (RSA check + Windows Service + supervisor)
- `veritas-runtime.exe` — 671 MB PyInstaller bundle (Python engine + dashboard)
- `veritas.vlic` — license file

## Target State
A proper Windows application: signed installer (.exe), RSA-protected license (.vlic), machine-bound, runs as a Windows Service, client opens a browser to the dashboard. Same model as Grafana Enterprise, Portainer, Jellyfin — server software distributed as a Windows-installable product.

---

## What the Client Experience Looks Like

```
1. Client receives: VeritasSetup-1.0.0.exe + their veritas.vlic license file
2. Runs VeritasSetup-1.0.0.exe → standard Windows installer wizard
3. Wizard asks: "Browse to your .vlic license file"
4. Installs to C:\Program Files\Veritas\
5. Veritas registers as a Windows Service → starts automatically
6. Client opens browser → http://localhost:8000 → Veritas dashboard
7. Topbar shows: ● Acme Bank · Professional · exp 2027-01-01

On next Windows boot:
→ Veritas Service starts automatically
→ No terminal, no manual step, no Python visible anywhere
```

---

## Language Decisions (per component)

| Component | Language | Why |
|-----------|----------|-----|
| Compliance engine (PII detection, rules, evidence, dashboard) | **Python** (keep) | Too complex + well-tested to rewrite. 337 tests. |
| Python packaging | **PyInstaller** | Bundles Python + all deps into a single opaque binary. `.py` files never shipped. |
| License validator + Windows Service launcher | **Go** | Compiles to a single `.exe` with zero deps. Opaque binary. RSA and WMI available. Same language as Docker, Kubernetes, Terraform. |
| Windows installer | **Inno Setup** (Pascal) | Free, industry-standard. Used by 7-Zip, VS Code, many enterprise products. |
| Dashboard frontend | **HTML/CSS/JS** (keep) | Served by Python backend. No change needed. |
| License key generator (internal Veritas tool) | **Go** | Same RSA key used by launcher. CLI tool only Veritas runs. |

---

## Phase 1 — RSA Asymmetric Licensing + Machine Fingerprinting
**Language: Python (upgrade existing license.py)**

### Goal
Replace HMAC (symmetric — secret ships with code) with RSA (asymmetric — only public key ships). Bind each license to a specific machine so the same `.vlic` cannot be copied to another server.

### Key Generation (one-time, Veritas internal)
```bash
python tools/keygen.py
# → tools/private_key.pem  (NEVER ship this, keep on Veritas's machines)
# → tools/public_key.pem   (embed as a string constant in license.py)
```

### License File Format (.vlic)
```
-----BEGIN VERITAS LICENSE-----
Base64(JSON_payload):Base64(RSA_SHA256_signature)
-----END VERITAS LICENSE-----
```

Payload:
```json
{
  "org":         "acme_bank",
  "tier":        "professional",
  "expiry":      "2027-01-01",
  "issued":      "2026-09-06",
  "fingerprint": "a3f9c2d1e8b47f..."
}
```

`fingerprint` = SHA-256(Windows disk serial + MAC address + hostname)

### Machine Fingerprint Flow
1. Client runs `veritas-fingerprint.exe` on their target machine → prints a hash
2. Emails the hash to Veritas with their order
3. Veritas generates a `.vlic` bound to that hash
4. Only that machine can run Veritas with that license

### Files changed
| File | Change |
|------|--------|
| `tools/keygen.py` | NEW — generates RSA key pair |
| `tools/generate_license.py` | Rewrite — RSA signing, accepts `--fingerprint`, `--key` |
| `tools/fingerprint.py` | NEW — prints machine fingerprint (Windows WMI) |
| `dpdpa-agent/license.py` | Rewrite — RSA verification + fingerprint check |

---

## Phase 2 — PyInstaller: Package Python as Windows Executable
**Language: PyInstaller**

### Goal
Compliance engine is never distributed as `.py` files. It becomes `veritas-runtime.exe`.

### How it works
- Bundles: Python interpreter + FastAPI + uvicorn + spaCy + Presidio + SQLite + all source (compiled to bytecode)
- Output: single `veritas-runtime.exe` (~300-500 MB, self-contained)
- The `.py` source is NOT included — only compiled `.pyc` bytecode in a compressed archive

### Key file: `veritas.spec`
```python
a = Analysis(
    ['run_pipeline.py'],
    datas=[
        ('dashboard/index.html',              'dashboard'),
        ('org_config/configs',                'org_config/configs'),
        ('llm_explainer/statute_snippets.json','llm_explainer'),
        ('LICENSE',                           '.'),
    ],
    hiddenimports=['presidio_analyzer', 'spacy', 'en_core_web_lg'],
)
exe = EXE(a.pure, a.scripts, a.binaries, a.zipfiles, a.datas,
          name='veritas-runtime',
          console=True,
          icon='assets/veritas.ico')
```

### Output
```
dist/veritas-runtime.exe    ← self-contained Windows binary
```

---

## Phase 3 — Go Launcher + Windows Service
**Language: Go**

### Goal
A compiled Go binary that:
1. Acts as the Windows Service entry point
2. Validates the RSA license + machine fingerprint (in compiled code — far harder to bypass)
3. Starts `veritas-runtime.exe` as a managed subprocess
4. Restarts it on crash (like systemd `Restart=always`)

### Why Go for this layer
- Compiles to a single `veritas-launcher.exe`, zero runtime deps
- The RSA validation logic is in compiled machine code — not readable like Python
- Native Windows Service support via `golang.org/x/sys/windows/svc`
- Industry standard: HashiCorp Vault, Consul, Docker Desktop all use this pattern

### Project structure
```
veritas-launcher/
├── go.mod
├── main.go        ← entry point: install/start/stop/uninstall/run
├── service.go     ← Windows Service lifecycle
├── license.go     ← RSA + fingerprint validation (Go)
└── launcher.go    ← subprocess management for veritas-runtime.exe
```

### Service commands
```
veritas-launcher.exe install    → register as Windows Service
veritas-launcher.exe start      → start service
veritas-launcher.exe stop       → stop service
veritas-launcher.exe uninstall  → remove service
```

---

## Phase 4 — Inno Setup: Professional Windows Installer
**Language: Inno Setup Script (Pascal)**

### Goal
`VeritasSetup-1.0.0.exe` — a standard Windows installation wizard.

### Installer wizard steps
```
1. Welcome — "Veritas DPDPA Compliance Platform v1.0.0"
2. License Agreement — EULA
3. Install Location — C:\Program Files\Veritas\
4. License File — "Browse to your veritas.vlic file"
5. Installing...
   - Copies: veritas-launcher.exe, veritas-runtime.exe, veritas.vlic
   - Registers Windows Service: "Veritas"
   - Creates Start Menu: Veritas > Open Dashboard / Stop Service / Uninstall
   - Creates Desktop shortcut: "Veritas Dashboard" → opens browser
6. Finish — "Installation complete. Opening dashboard..."
```

### Output
```
VeritasSetup-1.0.0.exe    ← single file distributed to clients
```

---

## Phase 5 — Code Signing (Optional)
**Tool: Windows SDK signtool.exe**

Without signing: Windows shows "Unknown publisher — run anyway?" warning.
With signing: Windows shows "Verified publisher: Veritas Technologies Pvt Ltd."

Requires an EV Code Signing Certificate (~$300-500/year, DigiCert or Sectigo).
Can be skipped for finals — software still runs, just one extra click for the user.

---

## Final Deliverable

```
What Veritas ships to a client:
  VeritasSetup-1.0.0.exe    ← the installer (everything bundled)
  acme_bank.vlic            ← machine-bound license file

What gets installed to C:\Program Files\Veritas\:
  veritas-launcher.exe      ← Go binary: Windows Service + RSA license check
  veritas-runtime.exe       ← PyInstaller bundle: Python engine + dashboard
  veritas.vlic              ← client's license (RSA signed, machine bound)
  logs\                     ← service logs

Windows Service: "Veritas"  ← starts automatically with Windows
Dashboard: http://localhost:8000  ← desktop shortcut opens browser
```

---

## Build Pipeline (how Veritas produces a release)

```bash
# Step 1: Generate RSA keys (once ever)
python tools/keygen.py

# Step 2: Package Python engine
pyinstaller veritas.spec
# → dist/veritas-runtime.exe

# Step 3: Build Go launcher
cd veritas-launcher && go build -ldflags="-H windowsgui" -o ../dist/veritas-launcher.exe
# → dist/veritas-launcher.exe

# Step 4: Build installer
iscc veritas-installer.iss
# → dist/VeritasSetup-1.0.0.exe

# Step 5: Per client — generate machine-bound license
python tools/generate_license.py \
  --org acme_bank \
  --expiry 2027-01-01 \
  --tier professional \
  --fingerprint <hash from client> \
  --key tools/private_key.pem \
  --out acme_bank.vlic
# → Send VeritasSetup-1.0.0.exe + acme_bank.vlic to client
```

---

## Implementation Priority for Finals

| Phase | What | Language | Priority |
|-------|------|----------|----------|
| 1 | RSA licensing + machine fingerprint | Python | **Must have** |
| 2 | PyInstaller → .exe binary | PyInstaller | **Must have** |
| 3 | Go launcher + Windows Service | Go | High |
| 4 | Inno Setup Windows installer | Inno Setup | High |
| 5 | Code signing | signtool | Nice to have |

**Phases 1-2** = proper binary + real licensing (no Python visible)
**Phases 3-4** = professional install experience (the full product story)
**Phase 5** = polish

---

## What This Compares To

This is the same distribution model as:
- **Grafana Enterprise** — Python/Go backend, browser dashboard, .deb/.rpm/.exe installer, RSA-signed license files
- **HashiCorp Vault** — Go binary, browser UI, license key system
- **Portainer Business** — Go backend, browser dashboard, machine-bound license
- **Elasticsearch Platinum** — Java backend, browser dashboard, signed license files

Veritas follows established, credible enterprise software packaging practice.
