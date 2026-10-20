# Plan: full alignment with the problem statement

**Problem statement (as given).** *The Real-Time DPDPA Compliance Monitoring Agent:* an autonomous, real-time agent that **ingests streaming system telemetry, API payloads and database schema logs**, **dynamically evaluates them against core DPDPA rules** (protect personal data, enforce purpose limitation, maintain transparent notice frameworks, prevent unauthorized exposure or retention of PII) and **immediately flags discrepancies on a live dashboard**; delivered as a **modular system with an ingestion pipeline** and further parts that are cut off in the copy we have.

**Status:** plan, nothing built yet. Written 2026-10-21. Effort figures are rough estimates for a team of four.

---

## 1. What "100% aligned" will mean

It means every requirement written in the statement has a **working, tested, demonstrable path** in the product, each with an automated acceptance test named below. It does **not** mean perfect detection, legal certification, or covering requirements that the copy of the statement does not show. Where the statement asks for something our own `scope.md` rules out, this plan says so and asks for a decision (section 2).

### Requirement matrix (current score and what closes the gap)

| # | Requirement in the statement | Now | After this plan | Closed by | Acceptance test (automated) |
|---|---|---|---|---|---|
| R1 | Autonomous, real-time monitoring agent | 100% | 100% | built | existing `trust_e2e` |
| R2 | Ingest streaming system telemetry | 100% | 100% | built; Phase F adds standard protocols | existing, plus `test_streaming_receivers` |
| R3 | Ingest **API payloads** | 50% | 100% | **Phase C** | `test_payload_tap`, e2e step "an API response leaks a phone number" |
| R4 | Ingest **database schema logs** | 25% | 100% | **Phase B** | `test_schema_watch`, e2e step "a new undeclared column" |
| R5 | Evaluate: unauthorized exposure | 100% | 100% | built | existing |
| R6 | Evaluate: purpose limitation | 100% | 100% | built | existing |
| R7 | Evaluate: retention | 75% | 100% | **Phase D** | `test_retention_review`, e2e step "a field passes its window" |
| R8 | Evaluate: transparent notice frameworks | 0% | 100% (coverage, not legal adequacy) | **Phase E** | `test_notice_registry`, e2e step "processing with no current notice" |
| R9 | Prevent exposure or retention of PII | 50% | 90% | built (agent masking) plus **Phase D** tasks to closure | retention task closes; recurrence reopens |
| R10 | Flag discrepancies immediately on a live dashboard | 100% | 100% | built; each new finding must reach the live stream | live-feed assertion in each phase's e2e step |
| R11 | Modular system with an ingestion pipeline | 100% | 100% | built; each phase adds a module, not a rewrite | module boundaries listed per phase |

Equal weights: now 8.0 of 11 (73%); after this plan 10.9 of 11 (about 99%). R9 stays below 100% by design: Veritas detects, explains and evidences; it never modifies production systems (`dpdpa-agent/docs/scope.md`). If a reviewer reads "prevent" as "auto-delete", we are not aligned and should say so openly rather than build something that contradicts the product's stated principle.

**The statement is cut off after "an ingestion pipeline,"**: the rest of the objective (probably more modules) is missing. Paste it and add rows to this table before Phase A starts.

---

## 2. Decisions needed before building (with my defaults)

| # | Decision | Default I will use if you do not decide |
|---|---|---|
| D1 | Is the **notice framework check** in scope? It reverses a line in `scope.md` ("consent-notice validity" is out of scope). | **Yes, as coverage only** (is there a current notice that lists this kind of data for this system?), never as a judgement of legal adequacy. `scope.md` is updated to say so. |
| D2 | Retention tasks: reuse the rights-request machinery or a separate screen? | **Reuse** (a request type `retention`), so confirmations are chain events with no new evidence code. |
| D3 | Payload Tap languages. | **Python (ASGI and WSGI) first, then Node/Express.** Java only on demand. |
| D4 | Databases for Schema Watch. | **PostgreSQL and MySQL.** |
| D5 | Should new features default on or off? | Schema Watch and Retention Review **on** (they only read what is already sent); Payload Tap **opt-in** (a library the customer installs); Notice Registry **off until the policy has `notices:`**. |
| D6 | Version. | **1.2.0**, after 1.1.0 (T0 to T7). Tag only when you say so. |

---

## 3. Phases

Order is by value against the statement and by dependency. Every phase ends with: tests green, one new step in `tools/trust_e2e.py`, a docs page, a CHANGELOG entry, and **green CI before the next phase starts** (the rule that has worked so far).

### Phase A: shared groundwork (about 3 days)

Small changes that Phases B to E all need.

| Task | Where |
|---|---|
| Field **leaf matching**: a field named `user.phone` or `items[0].mobile` matches the policy field `phone` / `mobile` | `dpdpa-agent/registry/loader.py` (`get_registry_entry`) and `detection/engine.py` (`_scan_fields`, `_resolve_validation_status`); one helper `field_leaf()` used by both |
| Raise or reshape the 50-field cap for API events (only fields with personal data or personal-data-looking names are sent, so 50 stays enough) | `api/integration.py` (`IngestEventRequest._validate_fields_size`) |
| An optional `source_kind` on events (`log`, `api`, `schema`, `otlp`) carried into flow counters and incidents so the dashboard can filter | `api/integration.py`, `evidence_store/flows.py` |
| Rule-id scaffolding for the new rule (`NOTICE_001`): the five edits we know | `schemas/models.py` `RuleId`, `schemas/verdict_schema.json`, `llm_explainer/statute_snippets.json`, `llm_explainer/explainer.py` fallback text, `rules/test_phase4_generalization.py` naming test |
| Update `scope.md` for D1 and for what is now observable | `dpdpa-agent/docs/scope.md` |

**Acceptance:** all existing tests still pass; leaf matching has unit tests (dotted, indexed, nested, no false match on `phone_backup`); `scope.md` reviewed by the team.

### Phase B: Schema Watch (R4), about 1.5 to 2 weeks

**Workflow:** a DDL statement reaches a database log (PostgreSQL `log_statement=ddl` or pgaudit; MySQL audit log) or a migration file; the agent forwards the line; the server parses it, classifies the column, compares it with the policy, and a personal-data column that is not declared becomes a `PURPOSE_001` finding with an owner, a map change and an incident.

| Task | Where |
|---|---|
| New agent source type `db_schema_log` (reads like any log source; no parsing on the host) | `veritas-agent/agent.py`: `validate_sources`, dispatch in `main()`, example config in `agent-config.yaml.example` and the packaging examples |
| DDL parser: `CREATE TABLE`, `ALTER TABLE ADD/DROP/RENAME COLUMN`, `ALTER COLUMN TYPE`, for PostgreSQL and MySQL; tolerant of comments, quoting, schema prefixes, multi-statement lines | new `dpdpa-agent/schema_watch/parser.py` |
| Column classifier: names and types to the recognizer pack's kinds (phone, mobile, aadhaar, pan, email, dob, address, card, account...), with a small configurable synonym list | new `schema_watch/classify.py`, `org_config` optional `schema_hints:` |
| Evaluation: undeclared personal-data column gives a verdict via the existing unregistered-field path (`PURPOSE_001`); declared column is quiet; `DROP COLUMN` is recorded | `schema_watch/evaluate.py`, called from `api/integration.py` `_process_event` for schema events (the same place the erasure hook sits) |
| Record the observed kind against the system in the flow counters, so the Data map reflects it | `evidence_store/flows.py` `record` |
| API and view: `GET /v1/{org}/schema` (recent changes, declared or not), a "Schema changes" list in the Data map panel | new `api/schema_watch.py`, `dashboard/index.html`; add to `api/test_route_access.py` |

**Tests:** parser (about 40 statement shapes per dialect, including hostile and malformed input), classifier (true and false cases), end to end through `/events`, tenant isolation, and that no statement text containing a literal personal value is stored (a `INSERT`-looking line is ignored, not echoed).

**Acceptance (R4):** adding an undeclared `mobile_no` column in a test database log produces, within seconds, a `PURPOSE_001` finding, an amber node, an incident with the system's owner, and a live-stream message; declaring the column in the policy stops new findings.

**Risks and limits to state:** it sees structure, not data; names like `col_7` are missed; ORMs that run DDL outside the logged channel are invisible.

### Phase C: Payload Tap (R3), about 2 to 3 weeks

**Workflow:** a small library in the customer's service sees request and response bodies after they are built, masks personal data in-process with the shared recognizer pack, and reports "response of `GET /customers/{id}` contains Aadhaar" with the route, never the value.

| Task | Where |
|---|---|
| Python middleware (ASGI and WSGI): flatten JSON bodies to dotted paths, size cap, sampling, route template, status; send after the response, **never block or fail the request**; drop the sample if masking fails | new `veritas-sdk/python/veritas_tap.py`, a copy of `veritas_recognizers.py` kept in sync (extend `tools/sync_recognizers.py` and its identity test) |
| Event shape: `source_type: "api"`, `fields` as dotted paths (only fields with personal data or personal-data-looking names, up to the cap), the route in `raw_snippet`, and the schema 2 fields `redaction_mode` and `agent_detections` | server accepts this already; Phase A adds leaf matching |
| Node/Express middleware with the same behaviour and a shared test corpus | `veritas-sdk/node/` |
| **CI gate:** a documented pipeline step that runs OpenAPI example payloads through `veritas_scan_cli.py` and fails the build on findings | `docs/PAYLOAD_TAP.md` plus an example workflow; reuses the existing CLI and `/scan` |
| Config and keys: the tap uses an agent registration key like an agent does; hash mode uses the delivered org key (already built) | `api/agents.py` unchanged |

**Tests:** the shared golden corpus of payloads (nested, arrays, unicode, huge bodies, binary); proof that masking happens before any network call (the test makes the network call fail and checks no raw value was in the call arguments); proof that a slow or down server never slows the application's response (latency test with a stub); load test of overhead per request (target under 1 ms added at p99 for a 4 KB body, measured and recorded in `docs/PERFORMANCE.md`).

**Acceptance (R3):** a demo service returning a phone number in a response produces a finding naming the route, with no raw value anywhere in the server's database, API or logs; the CI gate fails a pipeline whose example payload contains an Aadhaar number.

**Risks and limits to state:** it only sees what the library sees; encrypted or binary bodies are skipped; installing it is a one-line change per service but still a change.

### Phase D: Retention Review (R7, part of R9), about 1.5 weeks

**Workflow:** policy says phone numbers in `support-ticketing` may be kept 90 days. On day 76 the owner is warned; on day 91, while that system is still handling phone numbers, it is overdue with a task, a due date and a confirmed outcome in the chain; if the data keeps appearing after confirmation, the incident reopens as recurred.

| Task | Where |
|---|---|
| Review calculation: for each (system, field) from the policy (`retention_days`, `data_since`) and the flow counters (first and last seen), compute within window / due soon (default 14 days) / overdue **and still observed in the last N days** | new `dpdpa-agent/retention_review/` |
| Daily run plus on-demand; results cached | `maintenance.py` (`run_once` and `_loop`), settings `VERITAS_RETENTION_WARN_DAYS`, `VERITAS_RETENTION_OBSERVED_DAYS` |
| Alerts: "due soon" and "overdue" through the existing channels | `alerts.py` (`current_problems`, `evaluate_conditions`) |
| Tasks: a request type `retention` takes systems instead of identifiers; one task per owner; confirmation is a chain event | `subject_lookup/rights.py` (`TYPES`, a `create_retention_review` function), `evidence_store/canonical.py` unchanged (reuses `RIGHTS_EVENT`) |
| API and UI: `GET /v1/{org}/retention`, `POST /v1/{org}/retention/tasks`; a Retention panel in the Data map | new `api/retention.py`, `dashboard/index.html`; route-access tests |

**Tests:** boundary arithmetic (day 0, 76, 90, 91 with `data_since` set and unset), "overdue but no longer observed" stays quiet, task and confirmation chain replay, recurrence reopening, tenant isolation, alert de-duplication.

**Acceptance (R7, R9):** with a clock set past the window, an overdue item appears with an alert and a task; confirming closes it; a new matching finding reopens it.

**Limits to state:** Veritas does not see data at rest, so "overdue" means "past its window and still seen in the logs". It never deletes anything. "Closed" means the owner confirmed and the data was not seen again.

### Phase E: Notice Registry (R8), about 1 to 1.5 weeks (depends on D1)

**Workflow:** the policy lists the current privacy notices; Veritas shows which declared fields and observed kinds of data are covered by a current notice, and raises `NOTICE_001` for processing observed that no current notice covers.

| Task | Where |
|---|---|
| Policy model: `notices:` (id, version, effective date, review date, data categories, systems, languages) and an optional `notice_id` on each field | `org_config/schema.py`, `org_config/validator.py` (rules: unknown `notice_id`, duplicate ids, past review date) |
| Coverage at upload: fields with no notice, notices past review, systems with no notice | policy upload response and the Policy tab |
| Coverage at run time: observed (system, category) with no current notice listing it | `flows/build.py` (a coverage field per node); a daily check in `maintenance.py` raises `NOTICE_001` verdicts (with the owner) when a new gap appears |
| Notice changes are chain events (version added, retired) | reuse `RIGHTS_EVENT`-style recording or a small `POLICY_EVENT` (decide in the phase; default: record in the audit log and the chain note) |
| UI | Policy tab editor for notices; "notice coverage" in the Data map panel |

**Tests:** coverage matrix cases (no notice, expired notice, right notice, wrong system), `NOTICE_001` de-duplication through incident grouping, policy validation errors, upgrade of an old policy file with no `notices:` (feature stays off).

**Acceptance (R8):** a policy with a notice for phone numbers in `order-service`, then a log line with an e-mail address in `order-service`, produces an uncovered finding; adding the notice resolves it.

**Limits to state:** coverage, not legal adequacy; Veritas cannot know whether a notice was shown to the person. The statute citation for the rule needs your lawyer.

### Phase F: Streaming receivers (optional, R2), about 1.5 weeks

Only if a reviewer or customer means "streaming" as syslog or OpenTelemetry rather than tailing files.

| Task | Where |
|---|---|
| Server endpoint `POST /v1/{org}/otlp/logs` (OTLP/HTTP JSON): resource `service.name` becomes `source_system`, body to `raw_snippet`, attributes to `fields` | new `api/otlp.py` |
| Agent `syslog` source: UDP and TCP listener with a size limit | `veritas-agent/agent.py` |

**Acceptance:** an OTLP log record and a syslog message each produce the same finding as the equivalent file line.

### Phase G: integration, demo and release 1.2.0 (about 1 week)

- **`tools/trust_e2e.py`:** four new steps, one per feature (undeclared column, API response leak, retention window, notice gap), each asserting the live stream, the incident and the chain; the scenario stays under 45 minutes in CI.
- **`docs/DEMO.md`:** a new moment ("the schema change and the leaky API") before the data map.
- **`docs/PERFORMANCE.md` and `tools/bench_trust.py`:** record the tap overhead, parser throughput and retention review time for 50 systems.
- **Docs index and CHANGELOG;** the requirement matrix above is re-scored with evidence links.
- **Release:** a 1.2.0 candidate; tag only when you say so.

---

## 4. Cross-cutting rules (the same for every phase)

- **Evidence stays one mechanism.** New events are chain events or reuse existing ones; the chain check and the verifier must pass after each phase (a replay case is added for any new record type, as for incidents and requests).
- **Privacy:** no feature stores a personal value. Each phase has a test that scans the database, logs and API output for a planted value.
- **Roles and routes:** every new route is added to `api/test_route_access.py`; reads need an organization role, changes need `COMPLIANCE_ADMIN`.
- **Upgrade safety:** new tables are `CREATE IF NOT EXISTS`; an old database must open and verify; tested with the legacy fixture already used by `trust_e2e`.
- **Switches:** every feature has an environment variable to turn it off, documented in `docs/OPERATIONS.md`.
- **Performance budget:** nothing may reduce ingest below today's measured rate by more than 10% (checked by `test_trust_performance.py` and the load test).
- **Packaging:** the agent changes (Phases B and F) go into the Ubuntu, Mac and container builds; the install workflows run on the commit before the phase is called done.

## 5. Schedule for four people

| Weeks | A | B | C | D |
|---|---|---|---|---|
| 1 | Phase A | Phase B start | Phase C start | e2e extensions, docs |
| 2 | Phase B | Phase B finish | Phase C | e2e, `scope.md` |
| 3 | Phase D | Phase C (Node) | Phase C finish and CI gate | Phase D tests |
| 4 | Phase E | Phase E | Phase F (optional) | Phase G |
| 5 to 6 | buffer for CI failures, review, demo rehearsal | | | |

Milestones: end of week 2 Schema Watch demoable; end of week 3 Payload Tap and Retention demoable; end of week 5 all phases green in CI; release candidate in week 6.

## 6. Risks

| Risk | Mitigation |
|---|---|
| DDL formats vary by database version and logging setup | start with documented formats for two databases, ship a "unrecognised statement" counter so gaps are visible, keep the parser permissive and the tests adversarial |
| The tap slows or breaks a customer's service | async send after the response, strict timeouts, a circuit breaker that stops sending after repeated failures, latency tests, "fail open for the app, fail closed for masking" |
| Classifier false positives annoy owners | the same incident grouping and split/merge controls; a configurable synonym list; a way to declare a column as "not personal" in the policy |
| The retention view is mistaken for deletion evidence | the wording on every screen: "observed", "confirmed by owner", never "deleted" |
| Scope creep from the cut-off problem statement | add rows to the requirement matrix and re-estimate before building |
| Four people, many parallel parts | phase gates with green CI, one owner per phase, the e2e scenario as the shared definition of done |

## 7. Explicitly not in this plan

Consent capture and preference management; discovery of personal data at rest in databases and documents; automatic deletion or modification of production data (against `scope.md`); judging whether a notice is legally adequate; breach notification to the regulator; certifications and an independent penetration test (important for selling, tracked separately).

## 8. What to do now

1. Decide D1 to D6 (defaults above are fine).
2. Paste the rest of the problem statement so the matrix is complete.
3. Say go for Phase A; I will build and push phase by phase and report after each, as before.
