# Veritas — Production Readiness & Robustness Implementation Checklist

## Purpose

This document is an implementation-oriented review brief for the Veritas development agent.

The objective is to inspect the **current codebase first**, compare the implementation against the requirements below, and then make the necessary changes required to move Veritas toward a robust, production-ready, locally deployed enterprise application.

**Important:** Do not assume that any item below is missing. For every item, first inspect the existing implementation and determine whether it is:

- Already implemented correctly
- Partially implemented
- Implemented in a weaker/unsafe form
- Missing
- Implemented but insufficiently tested

Where something already exists, prefer improving/refactoring it over creating a parallel implementation.

The primary goal is to preserve the current strengths of Veritas—local processing, data minimization, the Agent/Runtime architecture, the rule engine, evidence generation, and deployment simplicity—while closing the security, privacy, reliability, and operational gaps required for production use.

---

# 1. Start With a Full Codebase Audit

Before changing code, inspect the repository end-to-end.

Please verify:

- Backend architecture and module boundaries
- Frontend architecture and state management
- Agent implementation
- Runtime/API implementation
- PII detection pipeline
- Rules/policy engine
- Evidence storage and hashing
- Organization/tenant handling
- Authentication and authorization
- WebSocket/live-feed implementation
- Database schema and migrations
- Configuration/environment handling
- Logging
- Error handling
- File handling
- External dependencies
- AI/LLM integration points
- Tests
- Build/deployment configuration
- Service/installer configuration
- Documentation

Do not rewrite stable components simply for architectural preference.

At the end of the audit, establish a short implementation matrix:

| Area | Current State | Gap | Required Change | Tests Required |
|---|---|---|---|---|
| Authentication | | | | |
| RBAC | | | | |
| Agent transport | | | | |
| PII detection | | | | |
| Evidence | | | | |
| Live feed | | | | |
| Organization management | | | | |
| Offline deployment | | | | |
| Database | | | | |
| Testing | | | | |

---

# 2. Human Authentication

Please verify whether the current dashboard and administrative APIs have proper human authentication.

The existing Agent authentication should be preserved if it is already sound, but human users must not rely on simply selecting an `org_id` in the browser.

Check whether:

- Users have actual identities/accounts
- Login/session/token handling is secure
- Passwords, if applicable, are securely hashed
- Sessions/tokens expire appropriately
- Tokens can be revoked
- Authentication is enforced on every protected API
- WebSocket connections are authenticated
- Authentication state cannot be bypassed by manipulating frontend state
- Administrative endpoints require authentication
- Organization creation/configuration endpoints require appropriate authentication
- API error responses do not leak sensitive information

If human authentication is missing or incomplete, implement it in a way that works for a local/on-premise deployment.

Do not introduce a cloud identity dependency just to solve authentication.

---

# 3. Role-Based Access Control (RBAC)

Please determine whether Veritas currently has real authorization or only organization scoping.

Implement authorization if necessary.

At minimum, consider roles such as:

- **Administrator** — organization configuration, agents, policies, users
- **Auditor/Investigator** — investigations, violations, evidence
- **Viewer** — read-only dashboard access

Verify that authorization is enforced server-side.

A user must never gain access to another organization's data merely by changing:

- `org_id`
- URL parameters
- request payloads
- local storage
- browser state
- API parameters

Check every endpoint individually.

Do not treat frontend hiding/disabling of buttons as authorization.

---

# 4. Multi-Tenant / Organization Isolation

Inspect the current organization/tenant implementation.

Verify:

- Every organization-scoped database query is actually scoped
- Every organization-scoped API verifies the authenticated user's membership
- Agent tokens are scoped to the correct organization
- Users cannot enumerate organizations they do not belong to
- IDs cannot be manipulated to access another tenant
- WebSocket/live-feed subscriptions are tenant-scoped
- Evidence and investigation data cannot cross tenant boundaries
- Organization deletion/deactivation has safe semantics
- Organization creation is protected by appropriate permissions

Also verify the previously requested frontend capability:

> There should be a proper frontend flow/button for adding an organization if backend support already exists.

Do not expose organization creation to unauthorized users.

---

# 5. Agent → Runtime Transport Security

This is one of the highest-priority areas.

Inspect how Agents currently communicate with Runtime.

If raw log lines can currently travel over plain HTTP, determine whether this creates unnecessary exposure even though everything is inside the organization's infrastructure.

The preferred production architecture should be:

```text
Application
    ↓
Veritas Agent
    ↓
Local/edge processing where appropriate
    ↓
Authenticated + encrypted transport
    ↓
Veritas Runtime
```

Please evaluate:

- HTTPS/TLS support
- Certificate validation
- Secure configuration of certificates
- Agent authentication
- Token rotation/revocation
- Replay protection where appropriate
- Request signing where appropriate
- Secure failure behavior
- Connection retry behavior
- Certificate expiration handling
- Configuration of trusted CA/certificates

The production deployment should not silently fall back to insecure transport.

If HTTP is retained for local development, make it explicitly a development-only option.

---

# 6. Evaluate Moving PII Detection Toward the Agent

Please investigate whether PII detection can safely be performed at the Agent/edge before transmitting events to Runtime.

The desired privacy-preserving architecture is:

```text
Application
    ↓
Veritas Agent
    ↓
Local PII detection
    ↓
Raw PII discarded
    ↓
Sanitized/minimized event
    ↓
TLS
    ↓
Veritas Runtime
    ↓
Rules + Evidence
```

Do not blindly move the entire detection stack to the Agent.

Instead evaluate:

- CPU/memory impact on application hosts
- Detection accuracy
- Model/package size
- Agent startup time
- Offline behavior
- Failure modes
- Queueing
- Backpressure
- Version compatibility between Agent and Runtime
- Whether the Agent can reliably discard raw values
- Whether Runtime still needs a second-stage detector

If practical, implement an architecture where Runtime does not need to receive raw PII for normal ingestion.

If edge detection is too expensive or risky for the current version, document the reason and retain authenticated TLS as the minimum requirement.

---

# 7. PII Detection Robustness

Audit the current Presidio/spaCy/custom-recognizer pipeline.

Verify coverage for currently supported PII, including:

- Name
- Email
- Phone
- Indian phone
- PAN
- Aadhaar

Then identify gaps in important categories such as:

- Passport
- Date of birth
- Address
- Financial/account identifiers
- Health information
- Biometric-related identifiers
- Other organization-specific identifiers

Do not simply add recognizers without evaluating false positives.

For every recognizer:

- Define confidence thresholds
- Add positive test cases
- Add negative test cases
- Test realistic log formats
- Test malformed values
- Test values embedded in JSON
- Test values embedded in free text
- Test multiple PII types in one event

---

# 8. Aadhaar / High-Risk Identifier Validation

Inspect the current Aadhaar implementation carefully.

If generic 12-digit detection is currently used with a relatively low confidence threshold, determine whether unrelated IDs could trigger false positives.

If Verhoeff validation exists but is not part of realtime detection, evaluate integrating validation into the actual detection path.

Do not increase detection sensitivity at the cost of unacceptable false positives.

Create tests for:

- Valid identifiers
- Invalid checksum identifiers
- Random 12-digit numbers
- IDs with spaces
- IDs with separators
- IDs embedded in logs
- Repeated identifiers
- Partial identifiers

Document confidence/validation behavior.

---

# 9. Data Minimization — Preserve and Strengthen This

One of the strongest properties of the current system is that matched PII should not be persisted in the evidence store.

Do not regress this.

Verify that:

- `matched_text` is not persisted
- Raw log lines are not unnecessarily stored
- Evidence contains only the minimum information required
- API responses do not accidentally return raw matched values
- Logs do not print detected PII
- Exceptions do not include raw PII
- Debug logging cannot expose raw PII in production
- WebSocket messages do not expose unnecessary PII

Where useful, store:

- Rule ID
- Violation ID
- Organization
- Source system
- Field name
- Timestamp
- Severity
- Confidence
- Explanation
- Statute/policy reference
- Aggregated counts
- Safe hashes/identifiers where justified

Be precise in terminology:

**PII non-persistence/data minimization is not the same thing as masking.**

Masking should be used where raw values genuinely need to be displayed in a controlled interface, while persistence should remain minimized.

---

# 10. API Response Safety

Audit every API response for accidental PII exposure.

Especially inspect:

- `/scan`
- ingestion endpoints
- violation APIs
- investigation APIs
- live feed APIs
- WebSocket events
- debug endpoints
- admin/configuration APIs

Determine whether any endpoint returns raw logs, matched text, request bodies, or other sensitive information unnecessarily.

Add regression tests proving that sensitive values are not returned where they should not be.

---

# 11. Evidence Ledger and Integrity

Inspect the current SHA-256 hash-chain evidence mechanism.

Verify:

- Hash inputs are deterministic
- Previous-hash chaining is correct
- Tampering with a prior record is detectable
- Record ordering is deterministic
- Concurrent writes cannot corrupt the chain
- Database transactions are used correctly
- Integrity verification can be executed independently
- Verification failures are surfaced clearly

Be careful with terminology:

The hash chain is **tamper-evident**, not automatically tamper-proof or immutable.

Implement an explicit integrity verification mechanism if one does not already exist.

Add tests for:

- Modified evidence
- Deleted evidence
- Reordered evidence
- Inserted evidence
- Broken previous hash
- Concurrent evidence creation

---

# 12. Retention and Erasure Semantics

Inspect how retention is currently represented and enforced.

Do not add a simplistic DELETE mechanism to a tamper-evident evidence ledger without considering audit integrity.

Determine:

- What data must be retained
- What can expire
- What must be immutable
- What metadata can be deleted
- How retention policies are configured
- How evidence expiration should work
- How an erasure request should interact with audit evidence

Clearly separate:

1. Original personal data
2. Raw telemetry
3. Minimized evidence
4. Audit/integrity metadata

The absence of raw PII in evidence should be preserved.

---

# 13. Live Feed

Audit the live feed end-to-end.

Verify that:

- It starts correctly when ingestion is running
- It reflects current pipeline activity
- Events are organization-scoped
- WebSocket connections are authenticated
- Disconnects/reconnects work
- Duplicate events are handled
- Backpressure exists
- The frontend does not freeze under event bursts
- Sensitive data is not pushed to the browser unnecessarily
- Pipeline failures are visible
- Stale connections are cleaned up

Test the live feed using realistic ingestion traffic.

The live feed should not become a secondary path through which raw PII leaks.

---

# 14. Agent Reliability

Inspect the Agent carefully.

Verify:

- File tailing is reliable
- Docker log ingestion is reliable
- Queueing works under temporary Runtime outages
- Events are not silently lost
- Duplicate delivery is handled safely
- Retry logic has bounded backoff
- Queue size is bounded
- Disk usage cannot grow indefinitely
- Shutdown is graceful
- Restart recovery works
- Corrupt input does not crash the Agent
- Runtime version incompatibility is handled
- Configuration errors are clear

Consider an explicit event identifier/idempotency key where appropriate.

Test:

```text
Application → Agent → Runtime
```

under:

- Runtime unavailable
- Network interruption
- Runtime restart
- Agent restart
- High event volume
- Malformed log lines
- Large log lines
- Disk-full conditions

---

# 15. Runtime Reliability

Inspect the FastAPI Runtime.

Verify:

- Input validation
- Request size limits
- Timeouts
- Concurrency handling
- Exception handling
- Graceful startup/shutdown
- Database transaction safety
- Background task failure handling
- WebSocket lifecycle handling
- Resource cleanup
- Protection against malformed input
- Protection against unbounded memory growth

No unhandled exception should expose stack traces or sensitive internal details to users in production.

---

# 16. Database Robustness

The current SQLite-based design should not automatically be replaced.

First determine whether SQLite is sufficient for the intended deployment model.

Benchmark realistic workloads:

- Events/second
- Violations/second
- Evidence writes
- Concurrent Agents
- Concurrent dashboard users
- Live-feed traffic
- Investigation queries

If SQLite performs adequately, preserve it because deployment simplicity is a product advantage.

If scale requirements justify PostgreSQL, design the migration carefully rather than prematurely introducing it.

Regardless of database choice:

- Add migrations
- Add indexes where justified
- Verify transaction boundaries
- Handle concurrent writes
- Add backup/restore procedures
- Test database corruption/recovery scenarios
- Ensure tenant scoping is enforced

---

# 17. Encryption at Rest

Inspect what is currently stored on disk.

Even though raw PII should not be persisted, determine whether the following require protection:

- Evidence metadata
- User information
- Agent token hashes
- Configuration
- Credentials/secrets
- Policy configuration
- Investigation metadata

Evaluate:

- Database encryption options
- Filesystem-level encryption assumptions
- Secret storage
- Key management
- Backup encryption

Do not implement custom cryptography.

If full database encryption is impractical for the current release, document the deployment requirement for encrypted host/storage volumes and ensure secrets are not stored insecurely.

---

# 18. Secrets and Configuration

Audit all configuration handling.

Verify:

- Secrets are not committed to Git
- Secrets are not hardcoded
- Production defaults are safe
- `.env` handling is documented
- API tokens are not logged
- Certificates/private keys are protected
- Debug mode cannot accidentally be enabled in production
- CORS is restrictive
- Host binding is deliberate
- Allowed origins are configurable
- Sensitive configuration values are not exposed through APIs

Provide a clear production configuration template.

---

# 19. Logging and Audit Trail

Separate:

### Application logs
Technical operational logs.

### Security/audit logs
Records of user/admin actions.

The system should avoid putting raw PII into either.

Determine whether the following user actions are auditable:

- Login/logout
- User creation
- Role changes
- Organization creation
- Organization configuration changes
- Agent registration/revocation
- Policy changes
- Investigation access
- Violation acknowledgement
- Violation resolution
- Evidence access
- Configuration changes

If this is missing, implement an appropriate audit trail.

The audit trail itself should be minimized and protected from tampering.

---

# 20. Investigation / Case Management

The current violation lifecycle is relatively basic.

Inspect whether the current:

```text
OPEN → ACKNOWLEDGED → RESOLVED
```

workflow is sufficient.

Consider whether production use requires:

- Assigned owner
- Investigator
- Priority
- Due date
- Notes
- Root cause
- Remediation action
- Reviewer
- Resolution reason
- Escalation
- Related violations
- Evidence references
- Activity history

Do not overbuild this if the existing MVP does not need it.

Implement the minimum workflow necessary for a credible enterprise investigation process.

---

# 21. Organization Management

Verify the complete organization lifecycle.

The frontend should support appropriate organization administration where authorized:

- Create organization
- View organization
- Configure organization
- Manage agents
- Manage users
- Configure policies
- Disable/archive organization

Check that the backend validates every operation.

Do not trust the frontend organization selector as a security boundary.

---

# 22. Offline / Air-Gapped Readiness

The current architecture is strongly suited to local/offline deployment.

Now verify whether the entire product actually works without Internet access.

Inspect for:

- Google Fonts
- CDN JavaScript
- CDN CSS
- External APIs
- External telemetry
- Remote assets
- External authentication
- External LLM calls
- Runtime downloads
- Package installation requirements

Bundle all frontend assets required for normal operation.

The product should have an explicit **offline/air-gapped deployment mode**.

If AI is unavailable locally, the core Veritas functionality must continue to work normally.

---

# 23. AI / LLM Architecture

The current automatic ingestion pipeline should remain independent of an external LLM.

Verify that:

- PII detection does not require an external LLM
- Rule evaluation does not require an external LLM
- Evidence generation does not require an external LLM
- Core monitoring works with AI disabled

For investigation assistance, consider an explicit configuration such as:

```text
AI Mode:
- Disabled
- External provider
- Local model
```

If an external provider is used:

- Never send raw PII unless explicitly required and authorized
- Prefer metadata/minimized evidence
- Make external transmission explicit
- Make it configurable
- Provide an offline-disabled mode

If a local LLM is introduced, keep it optional and isolated from the core detection path.

Do not add a local LLM merely for the sake of having one.

---

# 24. Error Handling and Secure Failure

Review all major failure paths.

The application should fail safely.

Examples:

- If authentication fails → deny access
- If authorization cannot be verified → deny access
- If TLS configuration is invalid → do not silently downgrade
- If PII detection fails → clearly classify the event/error rather than silently claiming success
- If evidence cannot be persisted → surface the failure
- If the database is unavailable → fail predictably
- If the AI provider fails → core Veritas functionality continues
- If Runtime is unavailable → Agent queues/retries according to policy

Avoid silent failure.

---

# 25. Rate Limiting and Resource Protection

Determine whether production APIs need:

- Request rate limits
- Maximum request body size
- Maximum log-line size
- Maximum events per batch
- WebSocket connection limits
- Agent registration limits
- Investigation query limits
- Pagination
- Query timeouts

Implement appropriate safeguards against accidental or malicious resource exhaustion.

---

# 26. Frontend Production Hardening

Audit the frontend for:

- Authentication state
- Authorization-aware UI
- Secure routing
- API error handling
- WebSocket reconnect behavior
- Loading states
- Empty states
- Pagination
- Large violation lists
- Large live-feed volumes
- Organization switching
- Session expiry
- Sensitive data rendering
- XSS risks
- Unsafe HTML rendering
- Debug information
- Production build configuration

Do not rely on the frontend for authorization.

---

# 27. Dependency and Supply-Chain Hygiene

Inspect dependencies.

Verify:

- Lockfiles are present
- Versions are reproducible
- Unused dependencies are removed
- Known vulnerable dependencies are identified
- Production dependencies are separated where practical
- Frontend dependencies are bundled for offline operation
- Container/base images are pinned appropriately
- Build artifacts are reproducible where practical

Do not blindly upgrade every package.

Prefer tested, intentional upgrades.

---

# 28. Testing Strategy

The existing automated test suite is a strong foundation. Do not reduce it.

Expand testing beyond unit tests.

Required categories:

### Unit tests
PII recognizers, rules, utilities, evidence hashing.

### Integration tests
Agent → Runtime → DB.

### API tests
Authentication, authorization, tenant isolation.

### Security tests
- IDOR attempts
- Cross-tenant access
- Missing authentication
- Privilege escalation
- Token misuse
- Malformed requests
- Oversized requests

### Privacy tests
Confirm raw PII does not appear in:

- Database
- Logs
- API responses
- WebSocket events
- Error messages

### E2E tests
Critical frontend workflows.

### Live-feed tests
Connection, reconnect, event delivery, isolation.

### Deployment tests
Fresh installation and startup.

### Offline tests
Disable network access and verify core functionality.

### Load tests
Determine actual SQLite/Runtime limits before deciding on database architecture changes.

### Adversarial tests
Malformed logs, unexpected identifiers, high-volume events, partial failures.

---

# 29. Deployment / Installer Validation

The product is intended for local/on-premise deployment.

Test the actual deployment artifacts, not just source code.

Verify:

- Fresh install
- Upgrade
- Uninstall
- Service startup
- Service restart
- Reboot recovery
- Configuration persistence
- Database persistence
- Agent registration
- Runtime startup
- Frontend availability
- Offline operation
- Certificate configuration
- Backup/restore

Test on the operating systems currently supported by the project.

---

# 30. Health Checks and Observability

Add/verify operational endpoints and dashboards for:

- Runtime health
- Database health
- Agent connectivity
- Queue depth
- Event throughput
- Detection failures
- WebSocket status
- Storage usage
- Version information

Health checks must not expose secrets or sensitive data.

Distinguish:

- Liveness
- Readiness
- Dependency health

---

# 31. Performance and Scalability

Do not optimize based on assumptions.

Measure:

- Events/sec
- Detection latency
- Rule evaluation latency
- DB write latency
- Live-feed latency
- Memory usage
- CPU usage
- Agent resource usage

Establish reasonable limits for the current release.

If performance is insufficient, optimize the existing architecture first.

Only introduce architectural complexity such as:

- PostgreSQL
- Redis
- message brokers
- microservices

when measurements demonstrate a need.

---

# 32. Preserve the Modular Monolith Unless Scale Requires Otherwise

The current architecture benefits from being relatively simple to deploy.

Do not split the application into microservices just because this is an enterprise product.

A robust modular monolith is acceptable if:

- Components have clean boundaries
- Failures are handled correctly
- Tests are strong
- Scaling characteristics are understood
- Deployment is reliable

Prioritize operational simplicity for on-premise customers.

---

# 33. Security Headers / Web Security

Inspect the HTTP layer and verify appropriate security controls where applicable:

- HTTPS
- Secure cookies if cookies are used
- HttpOnly cookies
- SameSite policy
- CSP
- X-Content-Type-Options
- Frame protections
- Referrer policy
- Strict transport security when HTTPS is enforced

Configure CORS explicitly rather than permissively.

---

# 34. API Versioning and Compatibility

Inspect Agent ↔ Runtime API compatibility.

Define a versioning strategy so that:

- Older Agents do not unexpectedly break
- Runtime upgrades are manageable
- Unsupported versions fail clearly
- Schema changes are backward compatible where practical

Add compatibility tests for supported Agent/Runtime combinations.

---

# 35. Backup and Recovery

Design a practical local backup strategy.

Determine what needs backup:

- Evidence database
- Policies
- Organization configuration
- Users/roles
- Agent configuration
- Certificates/configuration where appropriate

Document:

- Backup frequency
- Backup location
- Encryption
- Restore procedure
- Disaster recovery expectations

Test an actual restore.

A backup that has never been restored should not be considered validated.

---

# 36. Production Security Defaults

Verify that production defaults are secure.

Examples:

- Debug disabled
- Authentication required
- Authorization enforced
- HTTPS required
- Restrictive CORS
- Secure cookies
- No sensitive request logging
- No raw PII logging
- Safe error messages
- Strong token handling
- Safe default ports/bind addresses
- No default admin password
- No insecure fallback modes

Development conveniences must not silently become production behavior.

---

# 37. Documentation Required After Implementation

Update documentation to explain:

- Architecture
- Deployment
- Local/offline mode
- Air-gapped mode
- Authentication
- RBAC
- Organization management
- Agent registration
- TLS setup
- Backup/restore
- Retention
- Evidence integrity
- PII handling
- AI configuration
- Security model
- Known limitations
- Supported platforms
- Upgrade procedure
- Troubleshooting

Do not make legal/compliance claims that the implementation cannot substantiate.

The product should be described as supporting privacy/data-protection controls rather than automatically making an organization legally compliant.

---

# 38. Important Product/Security Principle

Preserve this architectural principle throughout the implementation:

> **The organization’s raw data should not need to be sent to Veritas.**

The preferred design is:

```text
Customer Application
        ↓
Veritas Agent
        ↓
PII detection / minimization
        ↓
RAW PII DISCARDED
        ↓
Authenticated TLS
        ↓
Veritas Runtime
        ↓
Policy / Rules Engine
        ↓
Minimized Evidence
        ↓
Tamper-Evident Ledger
        ↓
Authenticated Dashboard
```

This is the strongest privacy property of the system and should not be weakened by future feature additions.

---

# 39. Priority Order

Please implement/review in approximately this order:

## P0 — Critical

1. Human authentication
2. Server-side RBAC
3. Cross-tenant isolation validation
4. Secure Agent → Runtime transport
5. Secure production defaults
6. Prevent raw PII leakage through logs/API/WebSockets
7. Evidence integrity verification
8. Critical security/integration tests

## P1 — High

9. Agent reliability and retry/queue behavior
10. Live-feed hardening
11. Audit trail for user/admin actions
12. Offline/air-gapped packaging
13. PII detection improvements
14. Aadhaar validation integration
15. API/resource limits
16. Backup/restore
17. Deployment/installer testing
18. Frontend production hardening

## P2 — Important

19. Investigation/case workflow improvements
20. Encryption-at-rest strategy
21. Health/operational observability
22. Performance/load testing
23. Agent/Runtime version compatibility
24. Expanded PII recognizers
25. Optional local AI architecture

## P3 — Only If Evidence Requires It

26. PostgreSQL migration
27. Redis/message broker
28. Microservices
29. Local LLM deployment
30. Other architectural complexity

Do not implement P3 items simply because they sound enterprise-grade.

---

# 40. Definition of Done

Do not consider this work complete merely because the code compiles or existing tests pass.

Before declaring the system production-ready, verify:

- [ ] Human authentication works
- [ ] RBAC is enforced server-side
- [ ] Cross-tenant access attempts are rejected
- [ ] Agent authentication remains secure
- [ ] Agent → Runtime communication is securely encrypted
- [ ] Production cannot silently downgrade to insecure transport
- [ ] Raw PII is not persisted unnecessarily
- [ ] Raw PII does not leak through logs/errors/API/WebSockets
- [ ] PII detection has meaningful positive and negative tests
- [ ] Evidence is tamper-evident and independently verifiable
- [ ] Live feed is authenticated, tenant-scoped, and resilient
- [ ] Agent retries/queues safely
- [ ] Runtime handles malformed/high-volume input safely
- [ ] Organization administration is properly authorized
- [ ] Offline mode works without Internet access
- [ ] External CDN dependencies are removed/bundled
- [ ] Core functionality works with AI disabled
- [ ] Backup and restore have been tested
- [ ] Installer/deployment artifacts have been tested
- [ ] E2E tests cover critical workflows
- [ ] Security tests cover authentication/authorization/tenant isolation
- [ ] Load testing has established current capacity
- [ ] Documentation reflects actual behavior
- [ ] No unsupported legal/compliance claims are embedded in the product
- [ ] Existing functionality has not regressed

---

# 41. Required Final Report From the Agent

After implementing the changes, provide a concise but concrete engineering report containing:

## A. What Was Already Correct

List components that were inspected and intentionally left unchanged because they were already adequate.

## B. What Was Changed

For each change:

- File/module
- Problem
- Change made
- Why it was necessary

## C. Security Improvements

List authentication, authorization, transport, tenant isolation, secret handling, and privacy improvements.

## D. Privacy Improvements

Explain exactly where raw PII can and cannot exist after the changes.

## E. Reliability Improvements

Explain Agent, Runtime, database, WebSocket, and failure-handling improvements.

## F. Testing Performed

Report:

- Existing tests
- New tests
- Integration tests
- Security tests
- E2E tests
- Load tests
- Offline tests
- Deployment tests

Include actual results.

Do not claim tests were run if they were not.

## G. Remaining Limitations

Be explicit about anything that is still not production-ready.

## H. Recommended Next Steps

Separate truly necessary next steps from optional future improvements.

---

# Final Instruction

**Inspect first. Change second. Test third. Report last.**

Do not rewrite working code unnecessarily.

Do not introduce architectural complexity without evidence.

Do not weaken Veritas's local-first privacy model.

Do not persist raw PII merely to simplify implementation.

Do not rely on frontend controls for security.

Do not claim production readiness unless the relevant behavior has actually been tested.

The goal is not to make Veritas “look enterprise-grade.”

The goal is to make the existing Veritas architecture **actually robust, secure, privacy-preserving, testable, deployable, and maintainable in a real on-premise environment.**
