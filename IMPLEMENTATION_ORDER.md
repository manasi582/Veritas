# Implementation Order

Status (2026-10-14), latest release **v1.0.22**:

| Milestone | State |
|---|---|
| 1. Linux works | **Done.** Released; install test passes in CI; a separate Ubuntu machine ran the whole acceptance checklist (v1.0.19) |
| 2. License portal | **Done and live** (own repository `veritas-license-portal`, Vercel and Supabase). Verified end to end against the real database, including a four-way reissue race. Left by decision: no real revocation. Open: a separate signing key for CI |
| 3. Architecture changes | Not started. Waits for load-test numbers (load and long-run testing is the next big item) |
| 4. Enterprise agent and telemetry alignment | Phases A to C and E **done** (agent hardening, packaging and health, operations, housekeeping). Phase D (sanitization mode B) waits for design decisions |
| 5. macOS to the Ubuntu level | **Done** except: M4 (install the latest release on a real, clean Mac, in progress) and M5 (signing and notarization, parked until an Apple Developer account exists). Mac server, Mac agent, `veritas` commands, CI install tests and the Mac guide (`docs/MACOS.md`) are in. Server log rotation is done (the server rotates its own log); open backlog: a settings file that survives upgrades |
| Simulation | A teammate builds it from `veritas-demo/SIMULATION_PLAN.md` |

Goal of the first milestone: **a Linux `.deb` that installs, activates with a license, and runs reliably**, verified by an automated install test. Everything else comes after.

## Milestone 1: Linux works (do first, in this order)

| # | Change | Why this order | Size |
|---|---|---|---|
| 0 | **Commit hygiene.** Review and commit the customer-code cleanup. Normalize line endings (`.gitattributes`), fix the broken portal submodule link. | 88 files show as modified from line-ending churn; real changes are hidden in it. Do this before piling on more diffs. Needs your OK to commit. | S |
| 1 | **Fingerprint v2.** `v2:` + hash of `/etc/machine-id` (fallback: disk serial). No MAC, no hostname. One implementation (the runtime, `--fingerprint`); the Go launcher and the `veritas fingerprint` CLI both use it. | Root cause of the Linux test failure. Blocks every license test, and the portal's fingerprint validation depends on this format. | M |
| 2 | **No-license behaviour.** Exit with a distinct code and make systemd stop retrying (`RestartPreventExitStatus`), so a missing or invalid license shows one clear message instead of a crash loop. | Seen in the Linux test; confusing for a first install. | S |
| 3 | **Linux packaging polish.** `veritas` CLI no longer needs host `python3`/`lsblk`. Consistent http/https messages. Update `INSTALL.md` version, `control` email and deps. Print the fingerprint during install. | Removes the other install-time surprises from the test. | S |
| 4 | **Linux install CI test** (`test-linux-install.yml`): install the `.deb` in a clean Ubuntu runner, check CLI fingerprint == runtime fingerprint, activate a bound and an unbound license, start, `/health`, restart, kill/auto-restart, missing-license message. | Gives the same safety net macOS and Windows already have. Without it each Linux fix is untested. | M |
| 5 | **Release v1.0.16 and re-run the Ubuntu test** from the checklist, on your hardware and one cloud VM. | The milestone gate. | S |

## Milestone 2: License portal (starts after step 1, can run in parallel with 2 to 5)

| # | Change | Notes |
|---|---|---|
| 6 | New Supabase project, new key you provide, and a fresh `licenses` table (you said the old database must be deleted). **Row-level security on.** | Needs the new keys from you. Old data discarded. |
| 7 | Fingerprint format validation (`v2:` + hex), reject bad input before signing. | Needs step 1's final format. |
| 8 | Save failures reported to the admin instead of swallowed; the license is returned but flagged "not recorded", or issuing fails. | Small. |
| 9 | Remove the portal from the parent repo as a gitlink (or make it a real submodule). | Done as part of step 0 if you choose. |

**Status (2026-10-13), portal 2.1 committed in `veritas-license-portal` (63aafad, not pushed):**
decided with the owner: no real revocation ("Delete record" says what it does), one hardened shared secret, tier stays informational, owner creates the Supabase project.
Done and tested: fingerprint validation (`v2:` + 64 hex, or legacy 64 hex) before signing; a license is never returned unless saved (and none without a database unless `ALLOW_UNRECORDED=1`); license `id` inside every license; Reissue (old record marked Replaced, same org only, cannot replace twice, duplicate active license for an org needs confirmation); re-download of a stored license; `license_events` audit log (issue, reissue, download, delete); admin secret only in a header, constant-time compare, 16-character minimum, 8 failures block an address for 15 minutes; new `supabase-setup.sql` with row-level security on and no policies, input checks in the schema; strict expiry date check (a unit test caught `2027-02-30` being accepted). 20 unit tests. Checked with the real private key against both product verifiers: unbound and this Mac's `v2:` license accepted by `license.py`, another machine refused; Go `validateLicense` accepts the new license and refuses another machine. (A first draft used the wrong PSS salt length and would have been rejected by the Python verifier: the signing now matches `generate_license.py`.)
**Verified against the real Supabase project (2026-10-14):** 16-step end-to-end run (issue, duplicate refused, bad fingerprint refused, list without license text, download identical, reissue marks the old record Replaced, no double replace, audit rows, delete record keeps history) all passed; a license issued by the portal for this Mac is accepted by `license.py`; the public (anon) key is refused (401) for read, insert, update and delete on both tables. Found on the way: a reissue is several database calls, so a process that dies between saving the new license and marking the old one leaves two active licenses (left as a known limitation until it is made a single database function). Secrets had been pasted into the tracked `.env.local.example`; moved to the ignored `.env.local` before any commit.
Done 2026-10-14: portal pushed to its own repo (github.com/shreyaaassss/veritas-license-portal, commit eb1a42a) and Vercel built it; step 9 resolved as **separate repositories**: the submodule link and `.gitmodules` were removed from this repo and the folder is git-ignored here (it stays on the owner's disk as its own clone). Still needed: set the four variables in the Vercel project (ADMIN_SECRET, SUPABASE_URL, SUPABASE_SERVICE_KEY, VERITAS_PRIVATE_KEY; until then the live portal answers 503 "ADMIN_SECRET must be set", which is the intended fail-closed behaviour), redeploy, a live end-to-end test, and the separate CI signing key.

Left aside for now (your call): revocation, renewal/reissue, multi-user login, license id, tier limits. All were listed in the portal review of 2026-10-05, which is no longer in the repository (see the git history); the decisions taken are recorded below.

## Milestone 3: Architecture changes (after Milestone 1 passes)

These change runtime behaviour, so they come after the install path is proven and a baseline exists.

| # | Change | Why after Milestone 1 |
|---|---|---|
| 10 | **Baseline load measurement** using the simulation driver (Mode A): 10, 25, 50, 100 events/s against the unchanged server. | Needed to prove the queue is worth it and to measure the gain. Needs your teammate's driver. |
| 11 | **Ingest queue + worker pool**; `/events` returns 202 quickly. SQLite WAL mode; evidence chain written by one worker. | Biggest scalability gain; touches the hot path, so it needs the baseline and the install test first. |
| 12 | **Offline hardening:** bundle fonts and jsPDF locally; re-check license expiry while running. | Required for air-gapped customers; independent of 11. |
| 13 | **Metrics:** queue depth, events/s, detection latency, agent last-seen. | Most useful once the queue exists. |
| 14 | **Structure and docs:** split `server.py` into routers and `index.html` into modules; rewrite the technical audit and `architecture.md`. | Pure refactor and docs; do last so it doesn't block anything. |

## Milestone 4: Enterprise agent and telemetry alignment (next)

Source: the product spec "Enterprise Telemetry, Agent & Compliance Flow", stored at `docs/ENTERPRISE_TELEMETRY_SPEC.md` (agent is a thin telemetry bridge, all compliance logic stays in Core, Kubernetes via DaemonSet, plain servers as OS services, sanitization optional and later).

### Where we stand against that spec (assessed 2026-10-06)

| Spec area | State |
|---|---|
| Thin agent, intelligence in Core | Aligned |
| Blank dashboard, then create org, policy, key, agent | Aligned in code (no bundled orgs). The empty-dashboard screen itself still needs a visual check |
| One-time-key registration | Aligned |
| Core pipeline (ingest, PII, four rules, violations, evidence, dashboard, cases, audit) | Aligned |
| Modes A and C (Veritas does not store raw logs; customer's own logging is untouched) | Effectively in place. Core stores verdicts and metadata only, not raw text |
| Security and reliability basics (TLS, token, revoke, heartbeat, retry, bounded buffer) | Mostly aligned. Token saved as plain JSON; buffer in memory only; no Core ingest queue yet |
| Plain Linux/Windows/Docker agent | Partly. The Linux `.deb` very likely cannot save its identity or read logs; no log-rotation handling |
| Kubernetes DaemonSet | **Not aligned.** Shipped manifests are broken (see Phase B) |
| Mode B (sanitize and forward downstream) | Not built |

Findings behind the "not aligned" rows come from reading the manifests and agent code; **nothing has been run on a cluster**. Phase B starts by reproducing them.

### Phase A: Agent reliability and the Linux server path (do first; spec priorities 2, 3, 5)

| # | Task | Notes |
|---|---|---|
| A1 | **Done (2026-10-06, not yet released).** Fix the agent `.deb`: writable state location (identity file), read access to application logs, correct post-install text (`veritas_address`, not `server_url`), identity file mode 0600 | `ProtectSystem=strict` makes `/opt/veritas-agent` read-only, so `.veritas_state.json` cannot be written, and the one-time key is consumed anyway. Log files are usually `root:adm 0640`. Reproduced locally with a read-only working directory: the server accepted the registration, the identity save failed, the retry got "key already used". Fixed with a state directory (`VERITAS_STATE_DIR`, systemd `StateDirectory`), a writability check before the key is used, atomic owner-only save, `SupplementaryGroups=adm`, exit code 78 plus `RestartPreventExitStatus=78` for unfixable config errors, corrected package text and docs; 14 unit tests added and run in CI |
| A2 | **Done (2026-10-06, not yet released).** Log rotation: detect rotation/truncation and reopen the file | Today the agent holds the old file open and silently misses new lines. Implemented as a testable `FileFollower`: drains the old file, then follows the new one; handles `copytruncate`; sends only complete lines; a file that appears late is read from the start; unreadable files log a clear permission message and keep retrying. 11 tests plus a real-agent check |
| A3 | **Done (2026-10-06, not yet released).** Do not let one failing event block the queue: bounded retries for non-auth errors, then drop and count | Today any non-401/403 error (including a persistent 422) retries the same event forever. New policy: outages, timeouts, 408/429/502/503/504 retry without limit; other 5xx retry 6 times then drop; other 4xx and 401/403 drop at once; every outcome is counted (`AgentStats`, reported in A4); logs never contain event text and are rate limited. 20 tests plus a real-server check (oversized line dropped, the line behind it delivered) |
| A4 | **Done (2026-10-06, not yet released).** Heartbeat carries basic health: sources being read, queue depth, lines dropped, agent version. Show it in the dashboard Agents tab | Spec: "report basic health/status". Agent sends `health` (version, uptime, queue depth/capacity, counters, per-source state reading/waiting/error with a short reason; never event text) with every heartbeat, the first one immediately at start. Server validates and bounds it, stores it (migration for existing databases) and returns it from `GET /agents`. Agents tab shows Version, Health (queue, dropped, source errors, tooltip with details), a stale-heartbeat flag after 90 s, and a Needs Attention count; refreshes every 15 s. Old agents without a report still work. Contract test loads the real `agent.py` and feeds its report to the server |
| A5 | **Done (2026-10-06, not yet released).** Agent Docker image and `.deb` report their real version | The agent reads `$VERITAS_AGENT_VERSION`, else a `VERSION` file next to `agent.py`, else `dev`. The `.deb` build writes the VERSION file from the release tag; `veritas-agent version` and `agent.py --version` print it; the Dockerfile takes `--build-arg VERSION`. The server's own `/health` version is still C4 |
| A6 | **Done (2026-10-06): green on its first run** (exact counts 2, 4, 5, 6, 7, 8, 11 at each step; same agent id after restart; chain valid with 11 records). CI test for the agent: install the agent `.deb` on a runner next to a started server, register with a key, tail a file, append PII lines, rotate the file, assert violations in the ledger | `test-agent-install.yml` builds the agent `.deb`, installs it next to a server run from source (real self-signed TLS) and checks: package layout and version; an invalid key stops the service once (exit 78, no restart loop, no identity saved); real registration with a root-only unreadable file reported as `Permission denied` and a group-`adm` file read under the real systemd restrictions; identity file owner-only and the key never logged; exact violation counts through rename rotation, `copytruncate`, an oversized line, a late-appearing file and a restart (no loss, no duplicates); a server outage buffered and delivered afterwards; evidence chain valid; uninstall and purge. Helpers: `.github/scripts/agent_e2e.py` and `agent_ci_lib.sh` (tested locally against a real server and agent). Also fixed in the existing Linux install workflow: `! command` lines never failed a step under `set -e`, now explicit checks |
| A7 | Release v1.0.18 and retest on the Ubuntu machine | Gate for Phase A |

**Also fixed during A4 (security):** agent management endpoints did not check organization membership. A user with no organization could list every organization's agents (now including their health details), and an administrator of one organization could issue keys for, or revoke agents of, another. `GET /agents`, `GET /agents/{id}`, `POST /agents/issue-key` and `POST /agents/{id}/revoke` now enforce organization access (an agent of another organization looks like "not found"). 8 isolation tests; confirmed to fail without the fix.

**Acceptance:** on a clean Ubuntu machine the agent `.deb` registers, survives a restart and a log rotation, and violations appear in the dashboard; the CI agent test is green.

### Phase B: Kubernetes agent (spec priority 4)

Start by reproducing the defects on a local `kind` cluster, then fix them.

| # | Task | Notes |
|---|---|---|
| B1 | **Done (2026-10-06, not yet released).** **Reusable enrollment keys** on the server (maximum uses, expiry, org-scoped, revocable) plus the dashboard control to issue one | A DaemonSet registers one agent per node; today one key is shared by every node and the first node uses it up |
| B2 | **Done (2026-10-06, not yet released).** **Wildcard log paths** in sources (for example `/var/log/containers/order-*.log`) and parsing of the container runtime's line format | Pod log file names change on every redeploy; stdout logs are the main source on containerd clusters, which have no Docker socket |
| B3 | **Done (2026-10-06, not yet released).** **`source_system` naming rules** for node logs (map namespace/pod/container name patterns to a `source_system` in the agent config) | Needed so the org policy applies to the right system. Decision pending, see below |
| B4 | **Done (2026-10-06).** Rewrite the manifests: state at its own mount path (not over `/app`), config and key in a Secret, key delivered through an environment variable or init step (today the `${VERITAS_REGISTRATION_KEY}` placeholder is never substituted), one agent per node | Shipped `agent-deployment.yaml` and `agent-daemonset.yaml` mount state over `/app`, hiding `agent.py` |
| B5 | **Written (2026-10-06); runs on the next tag.** Publish the agent image to a registry (GHCR) in the release workflow | Today only a local `veritas-agent:latest` exists |
| B6 | **Done (2026-10-06): green in CI and on a local two-node kind cluster.** CI test on `kind` with 2 nodes: DaemonSet registers both agents with one reusable key; a pod writing PII to stdout produces a violation mapped to the right `source_system` | `test-kubernetes-agent.yml`: two-node kind cluster, server run from source (certificate covers the pods' address), the repository's own DaemonSet. Checks: one reusable key (5 uses) enrols both nodes' agents (key shows 2 of 5); exactly 12 violations, all under `order-service` (5 Aadhaar lines and one 16 KiB-split phone line per node; `cart-*` pods have no rule and add nothing); the ignored pods are reported; revoking the key blocks a new registration with HTTP 400 while existing agents stay active; deleting the agent pods brings back the same agent ids without using the key again |
| B7 | **Done (2026-10-06).** Rewrite `veritas-agent/k8s/README.md` to match | |

**Acceptance:** one command deploys the DaemonSet; both nodes appear ACTIVE; stdout PII from a test pod shows up as a violation under the expected source system; the `kind` CI test is green.

### Phase C: Complete the customer flow (revised 2026-10-06 after Phase B)

The first version of this phase mixed polish with items that need measurements or carry privacy cost. It was reshaped as follows.

| # | Task | Notes |
|---|---|---|
| C1 | **Done (2026-10-06, not yet released).** **Route-access test.** A test that lists every route and fails if a non-public route can be reached without authentication, or an organization route without organization access; an explicit, reviewed list of public routes. Fix whatever it finds. | The agent-management leak found in A4 shows the pattern can recur. A test stops it for every future route too. `api/test_route_access.py` (138 tests) lists every route from the API schema and checks it against reviewed tables: anonymous callers get exactly 401 except an explicit public list; every route that changes something has a declared minimum role (a new route without one fails the test); roles below the minimum get 403, the minimum gets through; organization routes refuse users outside the organization; the live-feed WebSocket follows the same rules; the public endpoints reveal nothing internal. Run against the code of v1.0.18 it fails 11 tests, which are the six problems it found and C1 fixed: **(1)** the live-feed WebSocket let any logged-in user, including one in no organization or one an administrator had disabled, watch any organization's live violations; **(2)** `/api/license` needed no login (customer name, tier, expiry); **(3)** `/api/system/health` showed server-wide detail (agent count across all organizations, certificate fingerprint, secret file names, platform) to every user; **(4)** `/ready` returned internal error text including the license file path; **(5)** `/api/openapi.json` published the full API schema; **(6)** `/api/version` published the internal endpoint map. The dashboard now stops retrying a refused live feed. The role rules themselves were found to be sound: viewers are read-only everywhere, auditors can only comment, investigate and scan, user management and backups are administrator-only. |
| C2 | **Done (2026-10-06, not yet released).** **Passwords and the user management screen.** | Password policy (10+ characters, common-password blocklist, no username or email name) on setup, create, change and reset. `POST /api/auth/change-password` (any user, rate limited) and `POST /api/auth/users/{id}/reset-password` (SUPER_ADMIN; generates a temporary password shown once, or takes a chosen one). A password change or reset ends every other session of that account (`token_version` in the session token). A new user or a reset account must choose their own password before anything else works (everything but change-password, logout and me answers 403 `PASSWORD_CHANGE_REQUIRED`; the live feed refuses too). The last active SUPER_ADMIN cannot be disabled or demoted. Audit entries for password changes, resets and user changes. Dashboard: **Users** tab (add user, change role, disable or enable, grant or remove organization access, reset password), account dialog from the user badge, and a blocking dialog for the forced change. 38 new tests, route-access tables updated. |
| C3 | **Done (2026-10-06, not yet released).** **`data_since` in the Add Organization form and the Policy tab.** | Per-field date picker in the form, shown in the Policy table, explained in the form. **Edit Policy used to open a blank form** (saving would have replaced the policy with an empty one); it now opens filled in with the organization fixed and saves a new version. A test proves the date is stored, returned and makes old data overdue. |
| C4 | **Done (2026-10-06, not yet released).** **Version reporting and compatibility.** | The server knows its release (`VERSION` file written by the release build and bundled by the three PyInstaller specs, or `$VERITAS_VERSION`, else `dev`). Registration and heartbeat answers carry `server_version`, `min_agent_version` and `agent_outdated`; the agent warns once when it is older than the minimum (1.0.18); the Agents tab marks outdated agents and counts them as needing attention; the sidebar shows the server release (it used to show a made-up `v3.0.0-generic`). The public `/health` still shows only the API version. |
| C5 | **Done (2026-10-06, not yet released).** **First-run experience.** | Looked at in a real browser (Playwright). **Found a real bug:** on a fresh install the welcome screen (z-index 300) covered the Add Organization form (211), so clicking *Configure Organisation* opened the form invisibly and the first-run path was stuck. The welcome screen now steps aside and comes back if the form is cancelled; accounts with no organization get a plain "ask your administrator" message instead of a setup prompt they cannot use. Also removed the invented version label. |
| C6 | **Done (2026-10-06, not yet released).** **Browser smoke tests in CI.** | `.github/scripts/browser_smoke.py` + `test-browser-smoke.yml`: a fresh server, then in headless Chromium: wrong then right setup code, sign in, welcome screen, create organization with a data-since date and an identifier, issue a key in the UI, an agent registers with it and sends an Aadhaar line, the violation appears, acknowledge and resolve, verify the hash chain, Policy shows the date, Edit Policy is pre-filled, add a user and give organization access, reset password, the new user is forced to choose a password (weak one refused), a viewer sees no admin screens. Fails on any uncaught JavaScript error; screenshots of each stage are attached to the run. Passes locally. |
| C7 | **Done (2026-10-06, not yet released).** **Operations basics.** | `maintenance.py`: a daily backup (last 7 kept, directory configurable) and an evidence-chain check per organization, outcome stored and shown in System Health; a failed backup or broken chain turns it red. Backups now use SQLite's online backup (a plain file copy of a live database can be torn) and are owner-only. `veritas install-cert <cert> <key>` (and `--install-cert`) validates and installs a company certificate, keeps the old one. Dashboard banner for: license ending (30 days, red at 7) or expired, certificate ending or expired, backup or chain problem, low disk. **Decision taken, please confirm:** an expired license while running does not stop the service (evidence collection continues, red banner); the next restart refuses to start. Documented in `docs/OPERATIONS.md`. 25 new tests. |

**Moved out of Phase C**
- **Ingest queue and worker pool:** stays in Milestone 3 (step 11), gated on the simulation's load baseline (spec section 13: only when measured traffic needs it).
- **On-disk spool in the agent: deferred, with conditions.** Today the agent never writes log content to disk, only its identity. A spool would put raw log lines, which can contain Aadhaar or phone numbers, on every application server. If a customer needs it: opt-in, owner-only permissions, a size cap and encryption at rest. Until then keep the in-memory buffer (1,000 lines) and make its size configurable.

**Acceptance:** the route-access test is green and part of CI; a customer administrator can onboard users, change passwords and describe existing data without curl; the dashboard is covered by a browser smoke test.

### Phase D: Sanitization and downstream forwarding, Mode B (spec priority 7, deliberately last)

1. Write a short design first: output actions `raw`, `sanitized`, `compliance-metadata-only`; per-organization setting; connectors (syslog, HTTP, object storage) and where redaction runs (Core).
2. Build only after Phases A to C are stable. Not a prerequisite for the Agent.

### Phase E: Housekeeping

- ~~Remove Raspberry Pi wording from docs and install scripts~~ Done 2026-10-14: removed from the install-from-source scripts and their README; the old planning documents that mentioned it were deleted from the repository (they remain in the git history). `docs/ENTERPRISE_TELEMETRY_SPEC.md` keeps the decision itself (enterprise software, not an appliance requirement).
- ~~Update `PROJECT_OVERVIEW.md` and `INSTALL.md`~~ Done 2026-10-14, together with a new `README.md`, `docs/MACOS.md` and `docs/CUSTOMER_ONBOARDING.md`.
- ~~Store the enterprise telemetry spec in the repo~~ Done: `docs/ENTERPRISE_TELEMETRY_SPEC.md`.

### Decisions needed before Phase B

| Decision | Recommendation |
|---|---|
| How a node log line gets its `source_system` | Mapping rules in the agent config, for example "namespace `shop`, pod `order-*` becomes `order-service`", with a clear warning for unmapped logs |
| Reusable enrollment keys | Yes: maximum uses plus expiry, shown once, revocable from the dashboard |
| Agent buffer in the first release | Keep in memory for Phase A; add the disk spool in Phase C (C6) |
| Agent token storage | File mode 0600 on servers; Kubernetes Secret plus a writable state volume in the cluster |

### Order and dependencies

1. Phase A, then release v1.0.18 and the Ubuntu retest.
2. Phase B (needs A2's rotation and A3's queue behavior; B1 touches the server).
3. Phase C in parallel with B where it does not touch the same files (C1 to C4 are independent).
4. Phase D after A to C are stable.
5. The simulation and Milestones 2 and 3 run alongside; the simulation's Mode B should use the v1.0.18 agent once it exists.

## In parallel from now (teammate)

Simulation: Phase 0 baseline, then Mode A driver and ground-truth checker, then Mode B with real agents. It depends only on the finished customer-code cleanup, not on the steps above. Its load results feed step 10 and 11.

## What I need from you

1. OK to commit the cleanup (step 0) and how you want it split (one commit, or cleanup / fixtures / docs).
2. The new Supabase URL and service key when you are ready (step 6). Don't paste them here: put them in the portal's `.env.local` and Vercel, and I'll work from the variable names.
3. Confirm Milestone 1 as the first thing to build.

## Milestone 5: macOS to the same level as Ubuntu (decided 2026-10-07: Apple Silicon only, unsigned package, installed from the command line)

| # | Task | Status |
|---|---|---|
| M1 | **Fingerprint v2 for macOS** | **Done (not yet released).** Anchored on the hardware UUID from `ioreg` (`IOPlatformUUID`, fallback hardware serial); hostname and MAC address are no longer used. `license.py` and `tools/fingerprint.py` agree (tested, and compared on a real Mac). Old-format Mac licenses are refused with a reissue message (none exist for customers). |
| M2 | **Command and package parity** | **Done (not yet released).** The Mac `veritas` command is now a real file (`package/macos/veritas-cli`), not a heredoc: real version (a `VERSION` file in the package), `fingerprint` calls the runtime (one source of truth), `check`, `reset-password`, `install-cert`, `trust-cert` (adds the certificate to the system keychain), `uninstall [--purge-data]`, `status` with exit code, `license` waits for the service and reports a refused license, HTTPS messages. `postinstall` typo fixed, macOS `._*` metadata kept out of the package. |
| M3 | **CI that matches Linux** | **Written, not yet run on GitHub.** `test-macos-install.yml` now builds the runtime and the `.pkg` from the current commit (the release method), so it no longer waits for release assets (the old race is gone). It installs on a clean macOS runner and checks: version, service stops by itself without a license, fingerprint v2 stable and equal in command and runtime and unchanged by a hostname change, a license for another machine is refused with the reason, the right license starts the service, the dashboard browser test, a real agent forwarding a log line, restart keeps data and chain, company certificate install (and a mismatched key refused), lost-password reset, uninstall keeps data, reinstall finds it, `--purge-data` removes everything. The redundant `build-mac.yml` (loose dependency versions, different Python) was removed. Expect a few CI iterations. |
| M4 | **Install on a real Mac** | Open. This development Mac has an old leftover install from Sep 2026 (`/opt/veritas`, `/usr/local/bin/veritas`, user `_veritas`); a clean Mac or VM is better. |
| M5 | **Signing and notarization** | Parked: needs an Apple Developer account. Until then customers install with `sudo installer -pkg ... -target /` (a double-click shows the unidentified-developer block). |
| M6 | **Mac agent** | **Written, not yet run on GitHub.** Single-file arm64 binary (`veritas-agent-mac.spec`, 13 MB, no Python needed; built and started locally) in `veritas-agent_<version>_arm64.pkg` (`package/macos/build-agent-pkg.sh`). LaunchDaemon `com.veritas.agent` as the hidden account `_veritas-agent` (not an administrator), config `/etc/veritas-agent/config.yaml` (never overwritten on upgrade), identity in `/var/lib/veritas-agent` (0700), log `/var/log/veritas-agent/agent.log`. `veritas-agent` command: start, stop, restart, status, logs, fetch-cert, `grant-read <file>` (macOS ACL, replaces Linux group `adm`), `uninstall [--purge-data]`, version. Release job added. New CI test `test-macos-agent.yml` mirrors the Ubuntu agent test: package contents, bad key stops once without looping, unreadable file reported then readable after `grant-read`, exact violation counts, rotation, truncation, late file, restart keeps identity, server outage buffered, evidence chain, upgrade keeps identity and config, uninstall and purge. Difference from Linux: launchd cannot exclude exit code 78 from restarts, so the agent restarts only after a crash (`KeepAlive Crashed`). |
| M7 | **Docs** | **Done (2026-10-14).** `docs/MACOS.md`: server install and first start, fingerprint, license, setup, trust-cert, check, day-to-day commands, file locations, upgrade, uninstall, the Mac agent (install, key, config, `grant-read`, behavior), troubleshooting, known limits. `INSTALL.md` brought up to date (version, `v2:` fingerprints on Linux and macOS, 10-character passwords, macOS section and macOS agent, CLI reference with backup/restore/reset-password/install-cert), `docs/OPERATIONS.md` points to it and gives the macOS way to set options, `install.sh` next-step messages corrected (they said http and skipped the license). Found while writing: macOS has no settings file that survives an upgrade (Linux has `/etc/veritas/config.env`); options are set in the launchd plist, which an upgrade replaces. Added to the backlog. |

Backlog from this milestone: a macOS settings file that survives upgrades (done: `/etc/veritas/config.env`); log rotation for `/var/log/veritas` (done: launchd keeps its files open, so plain `newsyslog` would not work and the server rotates its own `veritas-app.log`); Windows still uses the old fingerprint.

## Backlog: changes to make later

| Item | Notes |
|---|---|
| Support email | No support mailbox exists yet. The product says `support@veritas.io` (license errors in `license.py`, `license.go`, `tools/fingerprint.py`) and the `.deb` control file says `support@veritas.app`. Create the real address, then replace all of them with one value (ideally one constant). |
| CI signing key | CI tests sign licenses with the production private key stored in the `VERITAS_PRIVATE_KEY_B64` secret. Move to a separate test keypair and a test build that embeds its public key. |
| Reissue of old licenses | Test licenses from before v2 are invalid on Linux by design. No customer licenses exist, so nothing to migrate. |
| Portal: revocation, renewal/reissue, license id, multi-user login, tier limits | Decided 2026-10-13: no real revocation (the portal says "Delete record"), tier stays informational, one hardened shared admin secret. Reissue and the license id are done. |
| Go launcher gofmt | `license.go` and `main_linux.go` already fail `gofmt -l` (comment formatting). Cosmetic. |
| Docker log source reconnect | `tail_docker` ends silently when the container restarts or the stream drops (the source is now shown as "error: log stream ended" in the dashboard, but it is not re-attached). Add a reconnect loop with backoff. |
| Agent API org scoping elsewhere | After the agent-management fix, audit the remaining routes that take `org_id` in a query or body rather than the path for the same missing membership check. |
| Publish the agent image as a public package | The release workflow pushes `ghcr.io/shreyaaassss/veritas-agent` but GitHub creates a new package as private. After the first push, make it public once in GitHub (package settings), or customers cannot pull it. |
| Multi-line log messages | Stack traces arrive as separate lines. A per-source "line starts with" pattern could join them. |
| Windows: files held open without delete sharing | Python's `open()` on Windows does not allow other processes to rename or delete a file while the agent has it open, so an application's own log rotation (rename or delete) can fail with a sharing violation while the agent tails the file. Open log files with `FILE_SHARE_DELETE` on Windows. Found when a deletion test failed on the Windows CI runner. |
| ~~First-administrator claim on a fresh install~~ | **Done (2026-10-06, not yet released).** `POST /api/auth/setup` now needs a one-time setup code (`XXXX-XXXX-XXXX`) created when the service first starts, printed in the start-up banner, shown by `veritas setup-code` (Linux and macOS), stored owner-only in the data directory, kept across restarts, deleted once the administrator exists, presettable with `VERITAS_SETUP_CODE` for automation. Setup is limited to 10 attempts per 10 minutes. Windows has no `setup-code` command yet: read `secrets\setup_code` in the installation folder. |
| Config upload answers 200 for a rejected config | `POST /v1/orgs/{org}/config` returns HTTP 200 with `{"status":"error"}` when validation fails. Callers must read the body; a 4xx status would be safer for scripts. |
| ~~Lost administrator password~~ | **Done (2026-10-06, not yet released).** `veritas reset-password <user>` (runtime `--reset-password`) sets a temporary password, forces a change, ends the user's sessions, is audited. |
| ~~Per-account login lockout~~ | **Done (2026-10-06, not yet released).** 5 failures per account name lock it for 15 minutes from any address, applies to unknown names too (no enumeration), audited as `ACCOUNT_LOCKED`. |
| Backup restore is CLI-only | Restore needs `python backup.py restore` from the source tree; the packaged runtime has no restore command. Add `veritas restore <file>` (stops the service, verifies, restores, starts). |
| Browser smoke test: Firefox/Safari | Only Chromium is driven. |
| Ubuntu test findings (2026-10-07, v1.0.19) | All fixed in the next release: **(1)** the agent retried forever when `veritas_address` still held `<HOST>`; it now exits 78 with the reason (also for a placeholder key); **(2)** an open dashboard page stayed dead after its session ended (password reset, sign-out elsewhere); every refused request now sends the page to sign-in, and a pending forced password change reloads it; **(3)** sign-out was hidden behind the user pill; there is now a Sign out button; **(4)** no feedback on password rules while typing; setup, add-user and change-password now show a strength bar and the rules live; **(5)** `install-cert` accepted a certificate for the name `<HOST>`; it now refuses placeholder names and warns when the certificate does not cover the machine's name; **(6)** `InsecureRequestWarning` flooded the agent log with `tls.verify: false`; the agent now warns once. |
| **The macOS package could not create an administrator or sign anyone in (found 2026-10-07 by the new macOS install test)** | `veritas-mac.spec` did not bundle `passlib.handlers.bcrypt`, `jose` and `anyio._backends`, which are loaded by name and so invisible to PyInstaller. In the packaged server, `POST /api/auth/setup` failed with `No module named 'passlib.handlers.bcrypt'`; sign-in and the session cookie would fail the same way. Every released macOS `.pkg` up to v1.0.19 has this. Linux and Windows specs were fine. Fixed in the spec, and `dpdpa-agent/test_pyinstaller_specs.py` now fails if a required module is missing from any spec or the specs drift apart. **Do not give out a macOS package older than the next release.** |

## Production plan after the real-Mac test (2026-10-15)

Scope: everything short of Windows, long-run testing and Mac notarization. Order matters: each phase unblocks the next customer concern.

| Phase | What | Status |
|---|---|---|
| 1. Release hygiene | Mac log rotation, restore waits for the server, bare backup names, changelog feeding the release notes, one support address | **Done**, released as 1.0.23 (support address still a placeholder: needs the real mailbox) |
| 2. Upgrade safety | Backup before upgrade, downgrade guard, N-1 to N upgrade test in CI (Ubuntu and Mac), schema versioning, macOS settings file that survives upgrades | **Done** (v1.0.22 to v1.0.25) |
| 3. Security hardening | Dependency and secret scanning in CI, SBOM, checksums and signed releases, threat model and review package, separate CI license key, stored-XSS fix, PyJWT and cryptography 50 | **Done** (v1.0.24). Open: removing `unsafe-inline` from the content-security policy (about a day); an outside review |
| 4. Operability | `veritas support-bundle` (redacted), alerts (webhook/email) for HIGH findings, failed backups and expiring license, certificate or disk, a metrics endpoint, data-growth handling and an evidence retention design | **Done** (alerts, metrics, support bundle, health card, retention note; retiring evidence only on an administrator's command, not built) |
| 5. Load behavior (short) | A repeatable burst test to size the single process; the ingest queue and worker pool only if it falls short | **Done (2026-10-17)**: load test measured about 90 events/s for one thread; the detection worker pool (bounded queue, 503 + Retry-After) gives about 185/s with 2 workers and about 300/s with 3 on a 4-core runner. Profiling found disk syncs were the next cost: write-ahead logging, a batched agent counter and database-counted stats followed. Not yet released |
| 6. Product completeness | Sanitization Mode B (decisions needed), offline fonts and metrics, Mac agent Docker logs or an explicit "not supported", agent upgrade path, portal backups and renewal workflow | Open |
| 7. Documentation and sales readiness | Administrator runbook, security overview for customer questionnaires, licence agreement, support policy and data-handling statement (templates) | Open |

Notes from the real-Mac test of 1.0.22: server, license, setup, four roles, detection and masking, evidence chain, backup, verify, restore and the Mac agent all worked. One bug was found (the bare file name printed by `veritas backups` was rejected by `verify-backup` and `restore`), fixed in Phase 1. `/health` reports the API version (`1.0.0`) on purpose: the release number stays out of an unauthenticated page.
