# Veritas — Packaged Product Completion Plan

## Where We Are

The compliance engine, dashboard, agent, simulation, auto-startup, onboarding, and security are all **done and working**. The product functions end-to-end. What's missing is the packaging that makes it a **sellable licensed product** rather than an open-source tool anyone can copy.

---

## End Goal

> A licensed enterprise DPDPA compliance software product that Veritas (the company) sells to organisations. The organisation installs Veritas Runtime on their own infrastructure. The Veritas Agent (forwarder) is deployed into their production systems — Kubernetes, Docker, or bare-metal. Their data never leaves their network. Veritas holds the license key. Without a valid key, the software does not run.

---

## 3 Things Left to Build

---

### ITEM 1 — License Key System

**What it is:** A signed license key that Veritas (you) generate per customer. The Runtime checks the key on every startup. Without a valid key it refuses to run. Keys carry expiry dates and org-name bindings.

**Why it matters:** Right now anyone can copy `dpdpa-agent/` and run it for free forever. A license key closes that gap and makes the product story credible at finals.

**What needs to be built:**

1. **Key generation script** (`tools/generate_license.py`) — run by Veritas internally
   - Inputs: `org_name`, `expiry_date`, `tier` (starter / professional)
   - Output: signed license string (HMAC-SHA256 of payload, base64 encoded)
   - Example: `VRT-eyJvcmciOiJhY21lX2JhbmsiLCJleHBpcnkiOiIyMDI3LTAxLTAxIn0.abc123`

2. **License validator** (`dpdpa-agent/license.py`) — runs on client's machine
   - Reads `LICENSE` file from project root
   - Verifies HMAC signature using a hardcoded secret
   - Checks org_name and expiry_date
   - If invalid/expired → prints error and exits

3. **Startup check** in `run_pipeline.py`
   - Call `validate_license()` before anything else starts
   - On failure: `"Veritas license invalid or expired. Contact support@veritas.io"`

4. **Dashboard header badge** in `index.html`
   - Small indicator: `Licensed to: Acme Bank | Valid until: 2027-01-01`
   - New `/api/license` endpoint in `server.py`

**Files:**
- NEW: `tools/generate_license.py`
- NEW: `dpdpa-agent/license.py`
- MODIFY: `dpdpa-agent/run_pipeline.py`
- MODIFY: `dpdpa-agent/dashboard/server.py`
- MODIFY: `dpdpa-agent/dashboard/index.html`

---

### ITEM 2 — Kubernetes Agent Deployment Manifests

**What it is:** Ready-to-apply Kubernetes YAML files so enterprise clients running K8s can deploy the Veritas Agent with a single `kubectl apply`.

**Why it matters:** Most enterprises run Kubernetes. The manifests make the "install the forwarder into their cluster" story real and ops-team credible.

**What needs to be built:**

1. **`k8s/agent-secret.yaml`** — registration key as a K8s Secret
2. **`k8s/agent-configmap.yaml`** — `agent-config.yaml` as a ConfigMap (veritas_address + sources)
3. **`k8s/agent-deployment.yaml`** — Agent as a Deployment (single instance, persistent state volume)
4. **`k8s/agent-daemonset.yaml`** — Alternative: one Agent per node (for host-level log tailing)
5. **`k8s/README.md`** — how to fill in the secret and apply

**Files:**
- NEW: `veritas-agent/k8s/agent-secret.yaml`
- NEW: `veritas-agent/k8s/agent-configmap.yaml`
- NEW: `veritas-agent/k8s/agent-deployment.yaml`
- NEW: `veritas-agent/k8s/agent-daemonset.yaml`
- NEW: `veritas-agent/k8s/README.md`

---

### ITEM 3 — Data Residency & Privacy Guarantee Document

**What it is:** A short, clear, auditor-readable document proving client data never leaves their infrastructure. The most important trust document for a DPDPA product.

**Why it matters:** Compliance officers and CTOs will ask "does our PII leave our network?" before signing anything. You need a written, specific, architecture-backed answer.

**What the documents must cover:**

1. **Data flow diagram** — every network boundary annotated
   - Client services → Agent → Runtime → Dashboard: all within client network
   - What crosses the internet: **NOTHING** (except optional LLM call, disclosed)

2. **What Veritas (company) can and cannot access**
   - Cannot: client's production systems, log data, PII, evidence store
   - Can: nothing — Veritas ships software, not infrastructure

3. **What is stored and where**
   - Evidence store (SQLite): client's machine only, never transmitted
   - Org config (YAML): client's machine only
   - Agent state (JSON): client's machine only

4. **The LLM exception — disclosed honestly**
   - If client sets `OPENAI_API_KEY`, violation explanations are sent to OpenAI
   - The request contains: rule type, field name, statute text — **NO raw PII**
   - Can be disabled entirely — all features work without it

5. **DPDPA compliance mapping**
   - How Veritas's operation complies with DPDPA as a data processor
   - Data minimisation, purpose limitation, no retention of client data

**Files:**
- NEW: `docs/DATA_RESIDENCY.md` — technical document for CTOs / architects
- NEW: `docs/PRIVACY_GUARANTEE.md` — plain-English for compliance officers

---

## Build Order

```
Item 1 (License)        → most important for "sellable product" story at finals
Item 3 (Docs)           → can be written in parallel, no code dependency
Item 2 (K8s manifests)  → quick to write, high enterprise credibility
```

---

## How to Test

**License system:**
```bash
python tools/generate_license.py --org "acme_bank" --expiry "2027-01-01"
# → drops LICENSE file

python run_pipeline.py    # valid license → starts normally
echo "INVALID" > dpdpa-agent/LICENSE
python run_pipeline.py    # invalid → exits with error message

python tools/generate_license.py --org "acme_bank" --expiry "2020-01-01"
python run_pipeline.py    # expired → exits with expiry message
```

**Kubernetes manifests:**
```bash
kubectl apply -f veritas-agent/k8s/
kubectl get pods -l app=veritas-agent
kubectl logs deployment/veritas-agent
# Agent should register, heartbeat appears in Agents tab
```

**Data residency docs:**
- Review every claim against actual code
- Verify no network call exits client's network except optional OpenAI call
- Have someone not on the team read the plain-English version

---

## The Finals Demo Pitch

> *"Veritas is a licensed, on-premise DPDPA compliance platform.*
>
> *You buy a license. We install the Veritas Runtime on your infrastructure — a VM, server, or Raspberry Pi.*
>
> *We deploy the Veritas Agent as a Kubernetes service inside your cluster. It reads your application logs and forwards them — locally, within your own network — to the Veritas Runtime.*
>
> *Your data never leaves your infrastructure. Not to our servers. Not to any cloud.*
>
> *On your dashboard, you see every DPDPA violation as it happens. You investigate, acknowledge, resolve. You download a tamper-evident PDF audit report. Your evidence chain is cryptographically verified.*
>
> *This is DPDPA compliance — automated, auditable, and entirely yours."*
