# Reference Repos — Real-Time DPDPA Compliance Monitoring Agent (PSE11)

Curated list of open-source projects relevant to building the ingestion pipeline, rule-evaluation engine, and live dashboard for the DPDPA Compliance Monitoring Agent.

---

## 1. PII Detection Engines (rule-evaluation core)

### [microsoft/presidio](https://github.com/microsoft/presidio)
The de facto standard for PII detection and anonymization. Pluggable NER + regex + checksum-based recognizers, supports custom entity types, ships with an Analyzer and Anonymizer service, and exposes a REST API.
- **Why it matters:** You can extend it with custom recognizers for Aadhaar, PAN, and GSTIN — this is likely the strongest base layer for the "PII in logs" detection requirement.
- Supports both batch and streaming pipelines; used in ETL jobs, log scrapers, and API gateways.

### [HydroXai/pii-masker](https://github.com/HydroXai/pii-masker)
ML-based PII detector using DeBERTa-v3 for high-precision detection and masking.
- **Why it matters:** A good alternative/complement to Presidio's regex+NER approach if you want a pure ML detection layer.

### [rpgeeganage/pII-guard](https://github.com/rpgeeganage/pII-guard)
An LLM-powered tool that detects and manages PII in logs, exploring how LLMs (via local Ollama model, e.g. gemma:3b) can identify PII more intelligently than regex-based approaches — including obfuscated or embedded PII.
- **Why it matters:** Good reference for adding an "agent"-style LLM reasoning layer on top of a rule engine, which ties directly into the "autonomous agent" framing of the problem statement.

---

## 2. Streaming Ingestion Pipeline (closest architectural match)

### [confluentinc/tutorials — pii-detection](https://github.com/confluentinc/tutorials)
A Kafka + Faust + Presidio pipeline: a raw data topic is consumed by a PII detection app, which analyzes and redacts messages before publishing them into an anonymized topic — while simultaneously sending alerts to a separate topic detailing where and what PII was redacted.
- **Why it matters:** This is the best structural template for your system. The pattern of *raw stream → rule evaluation → alert stream + clean stream* maps almost directly onto your ingestion pipeline + live dashboard requirement.

---

## 3. DPDPA / India-Specific Context

### [Ansvar-Systems/india-law-mcp](https://github.com/Ansvar-Systems/india-law-mcp)
A searchable database of Indian law, including full DPDPA text, IT Act, cybercrime, corporate law, and Aadhaar legislation, with full-text search and MCP server access.
- **Why it matters:** Lets your agent cite actual statutory sections when flagging a violation, adding credibility and explainability for judges (ties into the "Explainable AI" angle of the problem statement).

### [amjadali-110/DPDPA-Checklist](https://github.com/amjadali-110/DPDPA-Checklist)
A plain-language DPDPA compliance checklist covering consent, DPO appointment, DPIA, data integrity, breach policy, cross-border transfer, and children's data.
- **Why it matters:** Good source for defining your rule taxonomy — i.e., the categories of violations your rule engine should detect and flag.

### Related topic pages worth browsing
- [github.com/topics/dpdp-compliance](https://github.com/topics/dpdp-compliance)
- [github.com/topics/dpdp](https://github.com/topics/dpdp)

Several recent (2026) hackathon-style projects on these pages cover audit logging, consent management, and breach detection for DPDPA specifically — worth skimming for UI/dashboard patterns others have used for similar problem statements.

---

## 4. Adjacent DLP / Scanner Tools (for schema-log ingestion)

Search the **[hipaa](https://github.com/topics/hipaa)** and **[pii](https://github.com/topics/pii)** GitHub topic pages for fast, Go-based PII/PHI filesystem and database scanners. Several MIT-licensed CLI tools walk filesystems/DBs and flag sensitive columns — relevant to the "database schema logs" part of your ingestion pipeline.

---

## Suggested Starting Stack

| Component | Recommendation |
|---|---|
| **Entity detection** | Presidio, extended with Aadhaar/PAN/GSTIN regex recognizers |
| **Ingestion pipeline** | Kafka/Faust redact-and-alert pattern (Confluent tutorial) |
| **Explainability layer** | india-law-mcp, to cite the specific DPDPA section violated |
| **Rule taxonomy** | DPDPA-Checklist categories (consent, DPIA, breach policy, cross-border transfer, children's data) |

This combination covers ingestion, rule evaluation, and explainability in one coherent stack, and differentiates the project from generic GDPR clones since it's grounded in actual DPDPA statutory text rather than a generic PII regex list.
