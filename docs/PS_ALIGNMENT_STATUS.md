# Alignment with the problem statement: status

Scored 2026-10-21 against the requirement matrix in [PS_ALIGNMENT_PLAN.md](PS_ALIGNMENT_PLAN.md) (the plan itself is unchanged). A requirement counts as **met** when there is a working, tested path for it, shown by an automated step in the end-to-end scenario (`tools/trust_e2e.py`, run in CI on a clean Ubuntu machine with the real language model, agents and verifier; workflow `trust-e2e.yml`). "Met" does not mean perfect detection, legal certification, or more than the caveat in the last column.

The problem statement as we have it **stops after "an ingestion pipeline,"**; anything after that is not scored.

| # | Requirement | Before | Now | How it is met | Evidence in the end-to-end scenario | Caveat that stays true |
|---|---|---|---|---|---|---|
| R1 | Autonomous, real-time monitoring agent | 100% | 100% | agents on the hosts and a server with a live feed and alerts | every step | |
| R2 | Ingest streaming system telemetry | 100% | 100% | file, container, Kubernetes and **syslog** sources in the agent; **OpenTelemetry logs** at the server | "streaming receivers" step | OTLP only as JSON; syslog is not authenticated; metrics and traces are not read |
| R3 | Ingest **API payloads** | 50% | 100% | Payload Tap libraries for Python (ASGI, WSGI) and Node (Express), masking in the service, plus the pipeline gate | "payload tap" step | needs one line in each service; sees only traffic that passes through it; JSON up to 64 KB; no names |
| R4 | Ingest **database schema logs** | 25% | 100% | the `db_schema_log` agent source, a PostgreSQL and MySQL DDL parser, a column classifier, policy comparison | "schema watch" step | structure only, guessed from names; statements that never reach the log are invisible; two dialects |
| R5 | Evaluate: unauthorized exposure | 100% | 100% | exposure rule | detection and grouping step | detection is probabilistic |
| R6 | Evaluate: purpose limitation | 100% | 100% | purpose rule, now also for API fields and schema columns | schema, payload tap steps | |
| R7 | Evaluate: retention | 75% | 100% | **Retention review**: each declared period against what is still seen, alerts, owner tasks closed in the chain, reopening if the data keeps arriving | "retention review" step | does not see data at rest; never deletes; the clock starts when Veritas first saw the data unless `data_since` is set |
| R8 | Evaluate: transparent notice frameworks | 0% | 100% (coverage) | **Notice registry**: notices in the policy, coverage of declared and observed data, `NOTICE_001` once per gap | "notice registry" step | coverage only: cannot read a notice, judge it legally adequate, or know it was shown; statute citation needs a lawyer |
| R9 | Prevent exposure or retention | 50% | 90% | masking, hashing or dropping in the agent and in the tap before data leaves; retention tracked to a confirmed close | redaction and retention steps | never deletes or changes production data (`scope.md`): "prevent" here means stop it travelling and make it someone's task, not remove it |
| R10 | Flag discrepancies immediately on a live dashboard | 100% | 100% | live stream, incident list, alerts | every step | the new daily checks (retention, notices) are daily, not instant |
| R11 | Modular system with an ingestion pipeline | 100% | 100% | each phase added a module (`schema_watch`, `retention_review`, `notice_registry`, SDK libraries, receivers) beside the existing pipeline | | |

**Equal weights:** 10.9 of 11, about **99%**, against 73% before. R9 is the one below 100% by design.

## What this does not claim

- That detection is complete or accurate on a customer's data: it is probabilistic, and names are found only by the server's language model.
- That a notice is adequate, or that a policy is compliant. Veritas checks coverage and records; it does not give legal conclusions.
- That anything is deleted. It never deletes.
- That it sees data at rest, in databases or documents.
- That the parts of the problem statement we cannot see are met.

## The evidence

- **End-to-end scenario:** passes in CI on a clean Ubuntu machine with the real language model, agents and verifier (the workflow named "Trust end-to-end"). It covers the five features from the trust plan and now the six from this plan, in one story.
- **Unit and API tests:** per module (parser, classifier, evaluator, tap, gate, retention arithmetic, notice coverage, receivers), including privacy scans that no raw value is stored or returned.
- **Browser test:** includes the policy form keeping owners and notices when saved.
- **Measurements:** `docs/PERFORMANCE.md` (tap overhead about 0.3 ms per request, schema parse about 10 µs, retention and notice review of 50 systems 19 ms and 3 ms).

## Decisions taken on defaults

The six decisions in the plan (section 2) were all taken at their stated defaults: notice check as coverage only; retention tasks reuse the rights-request machinery; Payload Tap for Python and Node; Schema Watch for PostgreSQL and MySQL; Schema Watch and Retention Review on by default, Payload Tap opt-in, Notice Registry off until the policy lists notices; version 1.2.0, tagged only on your word.

## Next

Release 1.2.0 is a candidate: nothing is tagged. The open items are in the project's status notes (a lawyer's review of the legal drafts and of the `ERASURE_001` and `NOTICE_001` statute citations, real support and security e-mail addresses, an independent penetration test, signed installers).
