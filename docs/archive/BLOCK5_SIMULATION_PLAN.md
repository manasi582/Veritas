# Block 5 — Simulated Production Environment

## Context
The demo needs realistic production traffic hitting the Veritas Agent so violations appear live on the dashboard. The simulation runs as a separate Docker Compose stack — four Python services write to log files on a shared volume, the Veritas Agent tails them and forwards each line to the appliance.

This is completely separate from the existing in-process ingestion generators (which are disabled in production with `--violation-rate 0`). This is external infrastructure that behaves like a real org's application estate.

---

## Architecture

```
veritas-demo/
  order-service     → /logs/order-service.log         ─┐
  support-service   → /logs/support-ticketing.log      ├─→ shared volume
  marketing-service → /logs/marketing-analytics.log    │     ↓
  delivery-service  → /logs/delivery-partner-service.log ─┘  Veritas Agent
                                                             ↓
                                                     POST /v1/blinkit/events
                                                             ↓
                                                       Veritas Appliance
                                                             ↓
                                                       Live dashboard
```

---

## Directory

```
veritas-demo/                    ← new top-level directory, sibling to dpdpa-agent/
├── docker-compose.yml
├── agent-config.yaml.example   ← operator fills in veritas_address + registration_key
├── README.md
└── services/
    ├── Dockerfile              ← shared across all 4 services
    ├── common.py               ← shared fake data helpers (names, phone, aadhaar, PAN)
    ├── order_service.py        ← EXPOSURE_001 via order-service
    ├── support_service.py      ← EXPOSURE_001 via support-ticketing
    ├── marketing_service.py    ← PURPOSE_001 via marketing-analytics
    └── delivery_service.py     ← RETENTION_001 via delivery-partner-service
```

---

## Exact Source Systems (must match registry exactly)

| Service | `source_system` value | Violation Type | Severity |
|---------|----------------------|----------------|----------|
| order-service | `order-service` | EXPOSURE_001 | HIGH |
| support-service | `support-ticketing` | EXPOSURE_001 | HIGH |
| marketing-service | `marketing-analytics` | EXPOSURE_001 (raw phone in deidentified-only scope) | HIGH |
| delivery-service | `delivery-partner-service` | RETENTION_001 (aadhaar 240 days old, > 180-day limit) | HIGH |

---

## Exact PII Patterns (must match detection engine)

| Type | Pattern | Example |
|------|---------|---------|
| Aadhaar | `\d{4} \d{4} \d{4}` | `5521 8890 3347` |
| PAN | `[A-Z]{5}[0-9]{4}[A-Z]` | `ABCDE1234F` |
| Indian Phone | `[6-9]\d{9}` (10 digits) | `9876543210` |
| Stale Partner | DP-4471, Suresh K., `5521 8890 3347` | seeded, 240 days old |

---

## common.py — shared fake data

```python
import random
from datetime import datetime, timezone

FIRST_NAMES = ["Priya","Rahul","Ananya","Vikram","Sneha","Arjun","Kavya","Rohan",
               "Meera","Aditya","Isha","Karan","Divya","Siddharth","Pooja","Aman"]
LAST_NAMES  = ["Sharma","Nair","Patel","Reddy","Iyer","Singh","Gupta","Menon",
               "Rao","Kulkarni","Verma","Joshi","Chatterjee","Desai","Bhat"]

def fake_name():   return f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}"
def fake_phone():  return f"{random.choice('6789')}{random.randint(10**8, 10**9-1)}"
def fake_aadhaar():return f"{random.randint(1000,9999)} {random.randint(1000,9999)} {random.randint(1000,9999)}"
def fake_pan():
    letters = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ', k=5))
    digits  = random.randint(1000, 9999)
    holder  = random.choice('ABCFGHJLPT')
    return f"{letters}{digits}{holder}"
def fake_address():
    flat  = f"Flat {random.randint(1,12)}{random.choice('ABCD')}"
    bldg  = random.choice(["Green Meadows","Sunrise Apartments","Palm Residency","Silver Oaks"])
    area  = random.choice(["Koramangala","Baner","Andheri West","Indiranagar","Whitefield"])
    city  = random.choice(["Bengaluru","Pune","Mumbai"])
    return f"{flat}, {bldg}, {area}, {city}"
def fake_order_id(): return f"BLK-{random.randint(100000, 999999)}"
def fake_ticket_id(): return f"TKT-{random.randint(10000, 99999)}"
def fake_partner_id(): return f"DP-{random.randint(1000, 9999)}"
def ts(): return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
```

---

## Log Line Formats (exact patterns that trigger each rule)

### order_service.py → `order-service` → EXPOSURE_001

```
# Clean (90%):
[2026-09-06T10:00:01Z] INFO order-service: order BLK-583927 status updated to 'delivered'
[2026-09-06T10:00:03Z] INFO order-service: order BLK-291034 assigned to zone KG-4, ETA 24min
[2026-09-06T10:00:05Z] INFO order-service: payment completed for order BLK-102938, amount ₹847

# Violation (10%):
[2026-09-06T10:00:07Z] DEBUG order-service: fetched customer record {name: "Priya Sharma", phone: "9876543210", address: "Flat 3A, Green Meadows, Koramangala, Bengaluru"}
```

### support_service.py → `support-ticketing` → EXPOSURE_001

```
# Clean (90%):
[2026-09-06T10:00:02Z] INFO support-ticketing: ticket TKT-83920 opened, category: delivery_issue
[2026-09-06T10:00:08Z] INFO support-ticketing: ticket TKT-83920 resolved by agent A-14
[2026-09-06T10:00:12Z] INFO support-ticketing: SLA breach risk: TKT-83921 open 47min

# Violation (10%):
[2026-09-06T10:00:15Z] DEBUG support-ticketing: agent note: customer Rahul Sharma called, phone 9123456789, requesting status on order BLK-291034
```

### marketing_service.py → `marketing-analytics` → PURPOSE_001 (raw phone in deidentified-only scope)

```
# Clean (90%):
[2026-09-06T10:00:04Z] INFO marketing-analytics: {"event":"marketing_engagement","hashed_customer_id":"hcid_3f7b1a2c","campaign_segment":"high_value_reorder","event_type":"push_click"}

# Violation (10%):
[2026-09-06T10:00:06Z] INFO marketing-analytics: {"event":"marketing_engagement","hashed_customer_id":"hcid_3f7b1a2c","campaign_segment":"dormant_30d","event_type":"email_open","phone":"9876543210"}
```

### delivery_service.py → `delivery-partner-service` → RETENTION_001 (seeded stale partner)

```
# Clean (80%):
[2026-09-06T10:00:09Z] INFO delivery-partner-service: partner DP-2341 profile OK, status: active, onboarded 45 days ago
[2026-09-06T10:00:14Z] INFO delivery-partner-service: partner DP-8812 KYC verified, documents current

# Violation (20%):
[2026-09-06T10:00:18Z] INFO delivery-partner-service: {"event":"partner_profile_fetch","partner_id":"DP-4471","name":"Suresh K.","aadhaar":"5521 8890 3347","onboarded_at":"2026-01-23T00:00:00Z","status":"inactive"}
```

---

## Service Script Structure (all 4 services follow this pattern)

```python
import os, random, time
from common import <fake data helpers>, ts

LOG_FILE = "/logs/{source_system}.log"
RATE     = float(os.getenv("VIOLATION_RATE", "0.10"))
INTERVAL = float(os.getenv("EMIT_INTERVAL", "2.0"))

def clean_line() -> str:      ...  # realistic clean log line
def violation_line() -> str:  ...  # PII-containing violation line

if __name__ == "__main__":
    print(f"Starting, violation_rate={RATE}, interval={INTERVAL}s", flush=True)
    with open(LOG_FILE, "a", buffering=1) as f:   # line-buffered
        while True:
            line = violation_line() if random.random() < RATE else clean_line()
            f.write(line + "\n")
            time.sleep(INTERVAL)
```

---

## Emit Intervals & Violation Rates (env-configurable)

| Service | Default EMIT_INTERVAL | Default VIOLATION_RATE | Why |
|---------|----------------------|----------------------|-----|
| order-service | 2.0s | 10% | Main order traffic, fast |
| support-service | 3.0s | 10% | Less frequent support events |
| marketing-service | 2.5s | 10% | Regular marketing engagement |
| delivery-service | 5.0s | 20% | Infrequent profile fetches, higher violation rate |

Result: ~1 violation every 20-25 seconds at default settings — enough for live demo without flooding.

---

## Dockerfile (shared across all services)

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY common.py order_service.py support_service.py marketing_service.py delivery_service.py .
CMD ["echo", "specify a service via docker-compose command:"]
```
No pip install needed — pure Python stdlib + common.py.

---

## docker-compose.yml

```yaml
version: "3.9"

services:

  order-service:
    build: ./services
    command: python order_service.py
    volumes:
      - logs:/logs
    environment:
      - VIOLATION_RATE=0.10
      - EMIT_INTERVAL=2.0
    restart: unless-stopped

  support-service:
    build: ./services
    command: python support_service.py
    volumes:
      - logs:/logs
    environment:
      - VIOLATION_RATE=0.10
      - EMIT_INTERVAL=3.0
    restart: unless-stopped

  marketing-service:
    build: ./services
    command: python marketing_service.py
    volumes:
      - logs:/logs
    environment:
      - VIOLATION_RATE=0.10
      - EMIT_INTERVAL=2.5
    restart: unless-stopped

  delivery-service:
    build: ./services
    command: python delivery_service.py
    volumes:
      - logs:/logs
    environment:
      - VIOLATION_RATE=0.20
      - EMIT_INTERVAL=5.0
    restart: unless-stopped

  veritas-agent:
    image: veritas-agent:latest      # built from veritas-agent/ directory
    volumes:
      - ./agent-config.yaml:/app/agent-config.yaml:ro
      - agent-state:/app
      - logs:/logs:ro               # read-only — agent tails, services write
    restart: unless-stopped
    depends_on:
      - order-service
      - support-service
      - marketing-service
      - delivery-service

volumes:
  logs:        # shared between all services (write) and agent (read)
  agent-state: # persists agent registration across restarts
```

---

## agent-config.yaml.example

```yaml
# Fill in before running the simulation
veritas_address: http://192.168.1.50:8000   # IP of the Veritas appliance
registration_key: YOUR_ONE_TIME_KEY_HERE     # from dashboard → Agents → Issue Key
source_label: simulated-production

sources:
  - type: file
    path: /logs/order-service.log
    source_system: order-service

  - type: file
    path: /logs/support-ticketing.log
    source_system: support-ticketing

  - type: file
    path: /logs/marketing-analytics.log
    source_system: marketing-analytics

  - type: file
    path: /logs/delivery-partner-service.log
    source_system: delivery-partner-service
```

---

## Files to Create

| File | Purpose |
|------|---------|
| `veritas-demo/docker-compose.yml` | Wires all 4 services + agent |
| `veritas-demo/agent-config.yaml.example` | Template for operator |
| `veritas-demo/README.md` | Setup and run instructions |
| `veritas-demo/services/Dockerfile` | Shared image for all services |
| `veritas-demo/services/common.py` | Shared fake data helpers |
| `veritas-demo/services/order_service.py` | EXPOSURE_001 via order-service |
| `veritas-demo/services/support_service.py` | EXPOSURE_001 via support-ticketing |
| `veritas-demo/services/marketing_service.py` | PURPOSE_001 via marketing-analytics |
| `veritas-demo/services/delivery_service.py` | RETENTION_001 via delivery-partner-service |

**Nothing in `dpdpa-agent/` is modified.**

---

## End-to-End Demo Script

```bash
# 1. On the Veritas appliance (or dev machine), start Veritas
python run_pipeline.py --violation-rate 0

# 2. In the dashboard, create blinkit org (if not exists) and issue a registration key
#    Dashboard → Agents → Issue Registration Key → copy key

# 3. Configure the agent
cp veritas-demo/agent-config.yaml.example veritas-demo/agent-config.yaml
# Edit: set veritas_address and registration_key

# 4. Build the veritas-agent image (first time only)
cd veritas-agent && docker build -t veritas-agent:latest . && cd ..

# 5. Start the simulation
cd veritas-demo
docker compose up --build

# 6. Watch violations appear live at http://localhost:8000
#    - Every ~20-25 seconds a violation should appear on the Live Stream tab
#    - Check Agents tab: simulated-production agent shows ACTIVE + heartbeat ticking
#    - Check Audit tab: EXPOSURE_001 (order, support), PURPOSE_001 (marketing), RETENTION_001 (delivery)
```

---

## Acceptance Criteria

- [ ] All 4 services start and write to log files continuously
- [ ] Veritas Agent registers, shows ACTIVE in dashboard
- [ ] EXPOSURE_001 appears (from order-service or support-ticketing)
- [ ] PURPOSE_001 appears (from marketing-analytics, raw phone in deidentified scope)
- [ ] RETENTION_001 appears (from delivery-partner-service, DP-4471 / Suresh K.)
- [ ] ~90% of events are clean (no violation on dashboard)
- [ ] Evidence chain verifies after 10+ violations: `VERIFIED ✓`
- [ ] `docker compose down && docker compose up` — agent re-registers from state file, violations resume
