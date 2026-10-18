# Veritas security overview

For a customer's security team and procurement. It describes what Veritas does and does not do, in plain terms, and is written to answer a vendor questionnaire. Technical detail for a reviewer is in [SECURITY_REVIEW.md](SECURITY_REVIEW.md). Where something is not provided, this document says so.

*Version of the product described: 1.0.27. [Contact for security questions: to be added.]*

## 1. In one page

- **It runs on your machines.** Veritas is software you install on a server you own. Your logs, findings and users stay there. The vendor does not host, see or receive your data.
- **It does not store the personal data it finds.** Detection runs in memory. What is recorded for each finding is the rule, severity, field name, source system, time, statute reference and an explanation, never the personal value itself.
- **Nothing leaves your network unless you turn it on.** The optional AI explanation (off by default) receives masked text only. Alerts go to the webhook or mail server you name. The license is checked offline.
- **Findings are tamper-evident.** Each is chained to the one before it with SHA-256, and the chain is verified on request and with every backup.
- **No accounts are created for you.** There is no default password; the first administrator is created with a one-time code that only someone with administrator rights on the server can read.

## 2. How it fits into your network

```
 your application servers          your Veritas server                  your people
 ┌───────────────────┐  HTTPS     ┌─────────────────────────┐  HTTPS   ┌────────────┐
 │ Veritas agent     │ ─────────► │ detection, rules,       │ ◄─────── │ browser    │
 │ (reads log files) │  token     │ evidence database,      │  cookie  └────────────┘
 └───────────────────┘            │ dashboard, API          │
                                  └───────────┬─────────────┘
                                              │ optional, only if you configure them
                                  alert webhook / mail server · AI provider (masked text)
```

| Connection | Direction | Port | Purpose |
|---|---|---|---|
| Browser to server | Inbound | 8000 (configurable), HTTPS | Dashboard and API |
| Agent to server | Inbound to the server | 8000, HTTPS | Log lines, heartbeat |
| Server to your webhook or mail server | Outbound, optional | Your choice | Alerts |
| Server to an AI provider | Outbound, optional, off by default | 443 | Explanations from masked text |

There is no connection to the vendor. The product does not phone home, collect usage statistics or check for updates.

## 3. Data

| Question | Answer |
|---|---|
| Where is data stored? | On the server, in the data folder (`/var/lib/veritas` on Linux and macOS): four SQLite databases, the license, certificates and keys. |
| What does the vendor receive? | Nothing automatically. If you send a support bundle, it contains the version, license status, health checks, file names and sizes, settings with secrets hidden, and recent log lines with tokens, keys and personal identifiers removed. |
| What personal data is stored? | Usernames, e-mail addresses and password hashes of the people who use Veritas. The evidence database holds findings, not the personal values found. Free text that staff type into case comments is stored as typed, so staff should not paste personal data into it. |
| Encryption in transit | TLS between browser and server and between agent and server. Veritas creates its own certificate, or you install your own. The agent can pin the server certificate. |
| Encryption at rest | Evidence records are encrypted with a key held on the same server (field-level encryption). Whole-disk encryption is the customer's choice and recommended. |
| Backups | A verified backup runs daily (configurable) into a folder you choose. Backups contain the keys: protect them like the server and copy them off the machine. |
| Retention and deletion | Evidence is kept until you remove the installation. Retiring old evidence, if you need it, will be an administrator-run command (design in `EVIDENCE_RETENTION.md`). `uninstall --purge-data` removes everything. |
| Data location and residency | Wherever you install it. |
| Sub-processors | None. The optional AI provider is yours to choose and receives masked text only. |

## 4. Access control

| Question | Answer |
|---|---|
| Authentication | Local accounts. Passwords are hashed with bcrypt. Policy: 10 or more characters, not a common password, not containing the user name or e-mail name. |
| Brute-force protection | Five wrong passwords lock that account name for 15 minutes; sign-in attempts are also limited per address. |
| Single sign-on, multi-factor | **Not provided** in this version. |
| Roles | Four: super administrator, compliance administrator, auditor, viewer. Every route declares its minimum role and a test fails if one is added without it. Viewers cannot change anything. |
| Organization separation | A user sees only the organizations they were added to; every request is checked against that. |
| Sessions | A signed cookie (HttpOnly, SameSite, Secure) that expires; changing a password ends the account's other sessions. |
| Agents | Each agent has its own token, shown once and revocable from the dashboard. Registration keys are single-use (or reusable on purpose), expire in 30 minutes and can be revoked. |
| Service accounts | The server and the agent run as their own unprivileged accounts. The program files belong to root. Data and logs are private to the service account. |
| Administrator actions | Recorded in an audit log (sign-ins, user changes, key issuing, backups, restores, policy changes). |

## 5. Integrity and monitoring

- **Evidence integrity.** SHA-256 chain per organization; "Verify chain" in the dashboard; checked with every backup; a failure raises an alert.
- **Health and alerts.** License, certificate and disk expiry, failed backups and broken chains raise alerts to a webhook or e-mail you configure; a Prometheus-format metrics endpoint is available, off until you set a token.
- **Logging.** Operational logs are private to the service account and rotate by size on macOS (Ubuntu uses the system journal). Logs do not contain personal data values; a log filter removes recognizable identifiers.

## 6. Software supply chain and release process

| Question | Answer |
|---|---|
| Source and builds | Every release is built by an automated workflow from the tagged source. |
| Testing | Each release is installed, run and exercised on clean Ubuntu and Apple-silicon macOS machines (and Windows), including upgrade from the previous release, backup and restore, a real browser driving the dashboard, and a real agent. |
| Dependencies | A vulnerability audit of dependencies and a scan for committed secrets run on changes and weekly; a known-vulnerable dependency blocks a release. A software bill of materials ships with each release. |
| Release integrity | Each release has `SHA256SUMS` signed by the build workflow itself (verifiable with `cosign`). |
| Code signing | **Not provided** for macOS (packages are not notarized by Apple; install with `sudo installer`). Ubuntu packages are not signed by a repository key. |
| Licensing | A signed license file checked offline on the machine; no license server. |
| Penetration testing | **No independent test has been done yet.** The threat model and test results are in `SECURITY_REVIEW.md` for a reviewer. |
| Certifications | None claimed (no ISO 27001 or SOC 2 report). |

## 7. Availability and recovery

- One server per organization; no clustering. Detection can use several worker processes on one machine for throughput.
- Recovery: restore a verified backup (`veritas restore`), which stops and starts the service and keeps the replaced data in a safety copy.
- Capacity: roughly 90 events per second with one detection thread and more with workers, measured on a shared 4-core test machine; the figures and how to measure your own are in `OPERATIONS.md`.
- Agents buffer 1,000 lines through an outage and retry; beyond that they drop the oldest and report the count.

## 8. Vulnerability handling and incidents

[To be completed by the vendor: security contact address, how fast a report is acknowledged, how fixes are announced and delivered, and the customer notification process after an incident that affects them.]

Releases are cumulative: a security fix is shipped as a new release listed in `CHANGELOG.md`, installed with the normal upgrade, which backs up your data first.

## 9. Known limits (so they are not a surprise)

- No multi-factor authentication or single sign-on.
- No outside penetration test yet.
- The dashboard's content-security policy still allows inline scripts; user-supplied names are escaped and refused if they contain markup (defence in depth is planned).
- Whole-database encryption is not provided; evidence records are encrypted individually.
- Personal-data detection is probabilistic. A finding is evidence to investigate, not a legal conclusion, and data the detector does not recognize is not reported.
- Backups contain the encryption keys.
