# Veritas

**On-premise compliance monitoring for India's Digital Personal Data Protection Act (DPDPA) 2023.**

Veritas reads an organization's application logs and API traffic, finds personal data (names, Aadhaar, PAN, phone numbers and more) being handled against the organization's own declared policy, records every finding in a tamper-evident evidence chain, and gives compliance staff a live dashboard to investigate and resolve each case. It runs entirely inside the customer's network: no data leaves it, and the only optional outside call (an AI explanation) never carries raw personal data.

The product is enterprise software that you install on your own infrastructure. It is not tied to any particular hardware.

## What is in the box

| Component | What it does | Where it runs |
|---|---|---|
| **Veritas server** | Detects personal data, evaluates the DPDPA rules, stores evidence, serves the dashboard and API | One server or VM per organization |
| **Veritas agent** | Follows log files (and Docker or Kubernetes container logs) and forwards each line to the server, buffering through outages | Every machine you want to monitor |
| **Dashboard** | Live stream, audit ledger, case handling, agents, policy, users, audit log, evidence export | In the browser, served by the server |
| **License portal** | Issues the signed license file for each customer. A separate repository: [`veritas-license-portal`](https://github.com/shreyaaassss/veritas-license-portal) | The vendor (Vercel and Supabase) |

## Platforms

| | Server | Agent |
|---|---|---|
| **Ubuntu** | `.deb` (22.04 and later; other Debian-based systems are expected to work but only Ubuntu is tested) | `.deb` (needs Python 3 and two libraries, installed automatically) |
| **macOS** | `.pkg` for Apple silicon, macOS 12 and later | `.pkg`, self-contained (no Python needed) |
| **Windows** | Installer (`.exe`), Windows 10 and later | Not packaged yet (the agent runs from Python) |
| **Containers** | n/a | Docker image on GHCR and Kubernetes manifests (one agent per node) |

Get them from the [releases page](https://github.com/shreyaaassss/Veritas/releases/latest). Every release is built and install-tested by CI on clean machines for each platform.

## Getting started

1. **Install the server** and get this machine's fingerprint (`veritas fingerprint`).
2. **Get a license** for that machine from your Veritas contact and install it (`sudo veritas license <file>`). This starts the service.
3. **Create the administrator** at `https://localhost:8000/setup`, using the one-time code from `sudo veritas setup-code`.
4. **Describe your data** (an organization with the fields each system holds, their purpose, consent scope and retention) in the dashboard.
5. **Install an agent** on each machine to monitor, using a registration key from the dashboard's **Agents** tab.

Step-by-step guides:

| Read this | For |
|---|---|
| [INSTALL.md](INSTALL.md) | Installing on Linux, macOS and Windows; the agent; licensing; the command reference; troubleshooting |
| [docs/MACOS.md](docs/MACOS.md) | Everything specific to macOS, server and agent |
| [docs/OPERATIONS.md](docs/OPERATIONS.md) | Running it: backups and restore, certificates, license renewal, users and passwords, failed sign-ins |
| [docs/CUSTOMER_ONBOARDING.md](docs/CUSTOMER_ONBOARDING.md) | For the vendor: onboarding a customer from fingerprint to first agent |
| [docs/UBUNTU_TEST_CHECKLIST.md](docs/UBUNTU_TEST_CHECKLIST.md) | An end-to-end acceptance test someone can run on an Ubuntu machine |
| [docs/RUNBOOK.md](docs/RUNBOOK.md) | What to do when something is wrong, by symptom |
| [docs/SECURITY_OVERVIEW.md](docs/SECURITY_OVERVIEW.md) | For a customer's security team: how Veritas handles data, access and releases |
| [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) | Threat model and review package for a security reviewer |
| [docs/legal/](docs/legal/README.md) | Drafts of the license agreement, support policy and data handling statement (for legal review) |

## How it works, in one paragraph

An agent sends each new log line to the server with its own revocable token. The server detects personal data in it, compares what it found with the organization's declared policy using four rules (exposure, purpose, retention, linkage), and records a verdict with a severity and the statute reference. Every verdict is appended to a per-organization SHA-256 hash chain that can be verified at any time, and pushed live to the dashboard. See [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) for the architecture and a worked example.

## Security and operations at a glance

- Local accounts with four roles; passwords of 10 or more characters that are not common and do not contain the username or email; forced change after a reset; sign-in lockout after repeated failures; sessions end when a password changes.
- TLS by default (self-signed, or install your company certificate); the session cookie is HttpOnly, Secure and SameSite; API documentation is not exposed.
- Licenses are signed files checked offline; a license works only on the machine it was issued for.
- Daily verified backups with `veritas backup`, `verify-backup` and `restore`; the evidence chain is checked with every backup.
- Warnings in the dashboard before the license or the TLS certificate runs out, and when the disk is filling.

## Repository layout

```
dpdpa-agent/            the server (detection, rules, evidence store, dashboard, API, licensing)
veritas-agent/          the agent (Python), Dockerfile and Kubernetes manifests
veritas-launcher/       Go service wrapper and license check (Windows service)
package/                .deb and .pkg packaging (server and agent) and their install scripts
installer/              Windows installer script
tools/                  license generation and fingerprint tools
veritas-demo/           simulated services and the plan for a simulated enterprise environment
docs/                   guides: macOS, operations, onboarding, telemetry spec, Ubuntu test checklist
.github/workflows/      CI, the release build and the per-platform install tests
INSTALL.md              installation guide
PROJECT_OVERVIEW.md     status, architecture and how it works
IMPLEMENTATION_ORDER.md the roadmap: what was done, what is open
```

The license portal lives in its own repository and is not part of this one.

## Working on the code

The server is Python 3.11 (FastAPI, SQLite, Presidio and spaCy). From `dpdpa-agent/`:

```bash
pip install -r requirements.txt
pip install https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.8.0/en_core_web_lg-3.8.0-py3-none-any.whl
VERITAS_TLS=false python -m pytest            # the server tests
```

The agent tests run from `veritas-agent/` with `python -m pytest`. The server refuses to start without a valid license for the machine; CI makes a test license with a private key held as a repository secret, and `tools/generate_license.py` is the tool that does it.

Pushing to `main` runs the cross-platform tests (Linux, macOS, Windows) and, depending on what changed, the install tests: a clean Ubuntu runner for the `.deb`, a clean Apple-silicon runner for the `.pkg` and the Mac agent, a Windows runner for the installer, and a real browser driving the dashboard. Pushing a tag `v*` builds and publishes the release packages and runs the install tests again.

## Status

Latest release: see the [releases page](https://github.com/shreyaaassss/Veritas/releases/latest). The server and agents are installed, run, backed up, restored and uninstalled in CI on clean machines for Ubuntu and Apple-silicon macOS, and the Ubuntu package has also been tested by hand on a separate Ubuntu machine.

Not done yet, and worth knowing before a large deployment:

- **Load and long-run behavior is untested.** One server process with SQLite is suitable for a pilot and mid-sized deployments; the planned ingest queue and worker pool are not built.
- The macOS packages are **not signed or notarized** (install with `sudo installer`, see [docs/MACOS.md](docs/MACOS.md)).
- **Windows** is installed and tested in CI only; it still uses the older machine fingerprint and has no agent package.
- No outside security review has been done.
- License revocation is not possible by design (licenses are files checked offline and expire by date).

The full list, with the reasoning, is in [IMPLEMENTATION_ORDER.md](IMPLEMENTATION_ORDER.md).
