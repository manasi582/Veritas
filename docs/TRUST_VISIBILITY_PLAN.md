# Trust, Visibility and Prevention: delivery plan

Source: "Veritas Feature Design Spec: Trust, Visibility and Prevention" (23 pages, the five features F1 to F5 and a foundation step). This plan maps the spec onto the repository as it is today, splits the work into phases that each end in something working end to end, and defines the one integrated scenario that proves the five features work together. Status of each phase is kept in the table in section 4.

## 1. What is being built, in one paragraph each

| | Feature | What the customer gets |
|---|---|---|
| T0 | **Foundation** | A versioned, canonical record format; status changes and comments recorded as events in the chain; forward-only migrations; golden test vectors shared with the Go verifier. Nothing changes for the user, but F1 to F4 stand on it. |
| F1 | **External anchoring + offline verifier** | Signed checkpoints of the chain head are copied to places the server's administrator cannot edit (a share, syslog, e-mail). A small standalone program (`veritas-verify`) proves an evidence export is intact, or names the first broken record. |
| F2 | **Live data-flow map + processing record** | A picture of which systems produce which categories of personal data, compared with the declared policy, exportable as a "record of observed processing". |
| F3 | **Incident grouping** | Thousands of findings become a short list of incidents with counts, owners and recurrence tracking. Work is done at the incident level. |
| F4 | **Data-principal lookup (HMAC)** | "Where did this person's identifier appear?" without storing the identifier; a rights-request tracker with tasks per system owner; a watch that alerts if an erased identifier reappears; a signed record. |
| F5 | **Agent-side redaction** | The agent masks, hashes or drops personal data on the host before the line leaves it; an optional masked copy for the customer's own log stack. |

## 2. The repository against the spec's questions (section 11 of the spec)

| Question | Answer from the code (checked 2026-10-19) |
|---|---|
| What exact bytes does the chain hash? | `sha256( json.dumps(payload, sort_keys=True, default=str) + previous_hash )`, where `payload` is the 15 immutable fields of an `ExplainedVerdict` built in `evidence_store/store.py::_serialize_immutable`, and `previous_hash` is the previous row's hash of the **same organization** (`GENESIS_HASH = "DPDPA-AGENT-GENESIS-2026"` for the first). The hash is computed on the plaintext; the stored `payload_json` is encrypted (`enc:` Fernet). This is `hash_version: 0`. Note `default=str` and `sort_keys=True` with Python's default separators (`", "` and `": "`), not compact JSON, so the v0 bytes are Python-specific and the Go verifier must reproduce them for old records. |
| Is `status` updated in place? | Yes. `update_status` changes `remediation_status` and `remediation_updated_at` columns directly; it is the only mutable field. Case comments are rows in `case_comments` with no hashing. The audit log (`audit.db`) is a plain table, not chained. |
| Where does the "queue worker" sit? | There is no queue worker. The API handler calls `store.append()` directly, serialized by the store's own threading lock in the single server process (SQLite, write-ahead logging since 1.0.26). So the spec's "new writers go through the single writer" becomes: **new writers use the store's lock and connection** (or a small writer module that does). Detection is now offloaded to worker processes, but they never write. |
| Are the agent's dependencies pinned? Can a shared library ship in all packages? | Agent requirements are ranges (`requests>=2.31`, `pyyaml>=6`, `docker>=7`), not pins. The agent is `agent.py` (+ `manage.py`) copied into the `.deb`, a PyInstaller spec for the Mac `.pkg`. A shared pure-Python module needs adding to: the agent `.deb` build script, the Mac agent spec, the server's PyInstaller specs and the Windows build. The Windows agent is not packaged (it runs from Python). |
| PDF library for exports? | None on the server. The dashboard already ships jsPDF (browser, offline) for the audit report. F2's export can use jsPDF. F4's **signed** record needs server-side generation: add one small pure-Python library (`fpdf2`, no native parts) to the server requirements and the PyInstaller specs. |
| Does the fingerprint change affect key derivation here? | No. All keys (database key, session secret, and the new signing and lookup keys) are random files in the data directory, not derived from the machine fingerprint. |

Two further facts the spec does not state: (a) the Go launcher lives in `veritas-launcher/` and builds on Windows, Linux and macOS in CI, so a Go verifier fits the existing toolchain; (b) `docs/SECURITY_REVIEW.md` records that **evidence holds no personal data values**, which is the property every new table below must keep.

## 3. Rules every phase obeys (from spec section 2 and 10)

- Evidence is append-only; nothing that changes state is a silent edit.
- New tables hold counts and keyed tokens, never raw personal data. A scan test proves it.
- New writers go through the store's lock; every endpoint checks role and organization on the server (the organization comes from the URL and the user's memberships only).
- Every table or record-format change is versioned and has a migration test, run from a database made by the previous release (and from a v1.0.16 database where the spec asks).
- Each feature is behind a config switch, **off until its tests pass**; the switch is documented in `config.env`.
- Sensitive actions (exports, lookups, key operations, anchoring runs) go to the audit log.
- Each feature ends with: dashboard page or indicator, a docs page that carries the spec's "honest limits" wording, CI coverage on Ubuntu and macOS (Windows where relevant), a rehearsed demo script.

## 4. Phases

Order follows the spec's build table, with the shared recognizer library pulled forward because F5 and F4's hash mode need it, and with an integrated acceptance phase at the end. Sizes are the spec's (S 1 to 2 days, M 3 to 5, L 1 to 2 weeks).

| Phase | Work | Depends on | Size | Release | Status |
|---|---|---|---|---|---|
| **T0** | **Foundation.** Document and freeze v0 with golden vectors (`tests/vectors/`; the migration test uses the real 4,233-row old database that is in the repository); define `hash_version: 1` (canonical JSON, domain-separated input); add per-organization `seq`, `record_type`, `hash_version` columns; STATUS_CHANGE and COMMENT events chained; status column kept as a cached projection; `schema_version` table and forward-only migrations with an automatic backup; migration and chain tests from a v1.0.x database. | none | M | 1.1.0 | **Built (2026-10-19), local, tests pass**; see `docs/EVIDENCE_FORMAT.md` |
| **T1** | **F1 anchoring.** Ed25519 signing key; `checkpoints` and `checkpoint_receipts`; scheduler (5 minutes or 100 records); file and syslog sinks; export endpoints (`evidence/export` JSONL, `anchors/export`); `veritas-verify` in Go with all result codes; dashboard indicator and red banner; CI builds and runs the verifier on every platform and attaches it to releases. | T0 | M | 1.1.x | **Built (2026-10-19), tests pass**; see `docs/ANCHORING.md`. Email, timestamp-authority and PDF-digest sinks wait for T7 |
| **T2** | **F3 incidents.** Template normalisation and fingerprint; `incidents`, `verdict_incident`, `incident_buckets`; grouping at ingest; regression (reopen after grace); status at incident level writing events; owners in the org config; incident list as the Audit Ledger default with drill-down; split and merge. | T0 | M | 1.2.0 | **Built (2026-10-20), local**; see `docs/INCIDENTS.md`. Browser and ingest tests run in CI only |
| **T3** | **F2 flows and processing record.** `observed_flows` counters flushed in batches; phase 1 (nodes) then phase 2 (edges from parseable destinations); `/flows` API; SVG map; CSV and PDF export titled "Record of observed processing". | T0 (T2 optional for open-case links) | M | 1.3.0 | **Built (2026-10-20), local**; see `docs/FLOWS.md`. PDF record is built in the browser (jsPDF), CSV and JSON on the server |
| **T4** | **Shared recognizer library.** Extract regex plus validators (Aadhaar Verhoeff, PAN, Luhn, phone, email) into one pure-Python package used by agent and server; golden corpus proving identical results; packaged into the `.deb`, `.pkg` and Windows builds. | none | S/M | 1.3.x | |
| **T5** | **F5 agent redaction.** Modes monitor / mask / hash / drop per category; fail-closed; line-size limit; redacting tee; event schema v2 (`redaction_mode`, `recognizer_pack_version`, `agent_detections`) accepted next to v1; heartbeat reports mode and pack; dashboard indicators and mismatch warning; throughput benchmark. | T4 | M | 1.4.0 | |
| **T6** | **F4 lookup and rights workflow.** Per-organization lookup key and `key_id`; tokens aggregated per system; normalisation table; lookup endpoint (COMPLIANCE_ADMIN, rate-limited, audit-logged, identifier never logged); requests and tasks with events in the chain; watch list and `ERASURE_001`; signed PDF record (`fpdf2`); agent hash-mode key distribution. | T0, T4, T5 for hash mode | L | 1.5.0 | |
| **T7** | **F1 extras and the integrated scenario.** E-mail sink, optional timestamp-authority sink, PDF digest; the end-to-end CI scenario of section 5; pitch demo script and sample data; documentation pass; performance measurements recorded (map 2 s / 50 systems / 30 days; 100,000 verdicts under a few hundred incidents; agent CPU budget). | T1 to T6 | S/M | 1.6.0 | |

Parallel work: T1, T2, T3, T4 can proceed side by side once T0 is merged. Do the load test (`tools/loadtest.py`) with incident grouping on before the F3 demo.

## 5. The integrated end-to-end workflow

One story, run by one CI scenario (`trust-e2e`) on a clean machine, so the five features are proven to work together and not only one at a time.

1. **Setup.** Fresh server with anchoring (file sink plus a second sink), incidents, flows and lookup enabled; an organization with declared systems and owners; two agents, one in `monitor` and one in `mask`/`hash` mode for phone numbers.
2. **Redaction (F5).** The masking agent reads a log line with a phone number and an Aadhaar number. Assertion: the server's database and a capture of the traffic contain no raw value for the masked categories; the dashboard shows the agent's mode.
3. **Detection and grouping (F3).** A noisy service writes 12,000 near-identical lines with changing numbers and ids. Assertion: the ledger shows a handful of incidents with the right counts, owners and a sparkline; every verdict is still in the chain.
4. **Flow map (F2).** A previously undeclared category appears on `marketing-service`. Assertion: the node turns amber, then red when the purpose rule fires; clicking it lists the incident; the processing record export contains no raw values.
5. **Resolution and recurrence (F3).** Resolve an incident, wait out the grace period, emit a matching line. Assertion: it reopens as "recurred"; the status changes are chain events.
6. **Rights request (F4).** An erasure request for the phone number from step 2 is created and a lookup is run (COMPLIANCE_ADMIN). Assertion: the lookup finds the systems and counts through the hash token; the audit log has an entry with only a token prefix; tasks are generated per owner; owners confirm; the request closes; the PDF record references chain entries.
7. **Resurrection (F4).** The same phone number appears again. Assertion: `ERASURE_001` fires and an alert is sent.
8. **Anchoring (F1).** Checkpoints are produced and witnessed by both sinks. Export the evidence and the checkpoints.
9. **Tamper (F1).** Stop the server; edit one verdict directly in the database and recompute every later hash with a script; delete the last records of another organization. Assertion: the dashboard's own verify may pass; **`veritas-verify` against the witness copies fails**, naming `CHECKPOINT_HEAD_MISMATCH` and the record, and `TAIL_TRUNCATED` for the second case, with no network and no server.
10. **Upgrade.** Restore a database made by the previous release, migrate, verify the full chain, append, verify again; all five features stay off by default after the upgrade.

The same story is the pitch demo, in the order the spec's "demo moments" give it.

## 6. New endpoints and who may call them

| Endpoint | Role | Notes |
|---|---|---|
| `GET /v1/{org}/anchors`, `anchors/export` | AUDITOR and above | read |
| `POST /v1/{org}/anchors/run` | COMPLIANCE_ADMIN | forces a checkpoint |
| `GET /v1/{org}/evidence/export` | AUDITOR and above | audit-logged, streamed |
| `GET /v1/{org}/incidents`, `/{id}` | VIEWER and above | |
| `POST /v1/{org}/incidents/{id}/status`, `/split`, `/merge` | COMPLIANCE_ADMIN (AUDITOR for status per role table) | writes events |
| `GET /v1/{org}/flows`, `flows/export` | VIEWER and above | counts only |
| `POST /v1/{org}/subjects/lookup` | COMPLIANCE_ADMIN | rate-limited, audit-logged |
| `POST/GET /v1/{org}/requests`, `.../tasks/{task}/confirm` | COMPLIANCE_ADMIN | events in the chain |
| `GET /v1/{org}/requests/{id}/record.pdf` | AUDITOR views, COMPLIANCE_ADMIN creates | |

Every one is added to the route-access table (`api/test_route_access.py`), which fails if a route has no declared access.

## 7. Risks and how the plan handles them

- **Breaking existing chains** (the one unforgivable failure). T0 never rehashes old records; golden vectors from a real database; migration test from older releases in CI; automatic backup before migration.
- **Python and Go disagreeing on bytes.** One set of vectors both load in CI; v1 canonical JSON avoids floats.
- **A weak claim.** Each docs page and slide uses the spec's wording: "observed processing map", "observed in these systems, not erased everywhere", "protects Veritas and downstream tools, not your original logs", "integrity as of the last checkpoint".
- **Scope.** Each feature is behind a switch and a separate release, so a late feature never blocks a finished one.
- **Performance.** Anchoring and flow counters run off the request path; incident grouping is measured with the load test before it is released.

## 8. Decisions needed from you

1. **Version numbers.** T0 changes the evidence format (additive and migrated), so I propose releasing it as **1.1.0** and each feature as a following minor release, as in the table.
2. **Server-side PDF** for the signed rights record: add `fpdf2` (small, pure Python). Alternative: produce the record in the browser, which cannot be signed by the server.
3. **Default witness count.** The spec says default 1, recommend 2. I propose the dashboard shows an amber "only one witness" until two are configured.
4. **DPDPA response deadlines** in the rights tracker: the spec says to confirm the current Rules first. I propose no default deadline, as written, until you or counsel supply the period.
5. **Incident view as the default Audit Ledger** (spec 6.5): this changes what existing users see after the switch is turned on. I propose the old verdict list stays one click away.
6. **Windows:** the verifier is built for Windows too, but the agent on Windows is not packaged; F5 on Windows would run from Python only. Fine?
