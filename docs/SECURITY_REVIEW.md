# Veritas: threat model and security review package

For an outside reviewer, a customer's security team, or anyone deciding how far to trust the product. It says what is protected, from whom, how, and what is **not** covered. Statements here describe what the code and its tests do; where something is a decision or a gap it says so.

## 1. What it is, and where it runs

One Veritas server per organization, on that organization's own machine (Ubuntu or Apple-silicon macOS; Windows is installed and tested in CI only). Nothing leaves the network except an optional AI explanation call, which receives masked text only. Agents on other machines send log lines to the server over HTTPS. People use the dashboard in a browser.

```
 monitored machine                      the Veritas server                        people
 ┌──────────────┐  HTTPS, agent token  ┌───────────────────────────────┐  HTTPS, cookie  ┌──────────┐
 │ Veritas agent│ ───────────────────► │ API + detection + rules       │ ◄────────────── │ browser  │
 └──────────────┘                      │ SQLite files (4) + secrets    │                 └──────────┘
                                       │ evidence hash chain           │
        vendor (offline, by e-mail)    └───────────────────────────────┘
        signs license files ───────────► license file checked offline
```

## 2. What is worth protecting

| Asset | Why it matters |
|---|---|
| The findings and their context (which rule, which field, which system, when, and the explanation text) | Sensitive because they describe where a customer's personal data is mishandled. The product is built so that **raw personal data values are not stored**: detection runs in memory, the evidence record (`schemas/models.py` `Verdict`) has no matched text, and responses show masked text. The record is also encrypted at field level (Fernet). Free text typed by staff (case comments, investigation questions) is stored as typed, so staff should not paste personal data into it. |
| The evidence chain | Its value is that nobody, including an administrator, can quietly change a finding. Each record carries a SHA-256 hash of the one before. |
| Accounts and sessions | An administrator can create users, issue agent keys and read all evidence. |
| Agent tokens | A stolen token lets someone send events for that organization. |
| The signing key for licenses | Held by the vendor, never in a package. Whoever has it can mint licenses. |
| Backups | They contain the databases **and the encryption and signing secrets** (`secrets/`). A backup file is as sensitive as the live server. |

## 3. Who we defend against

1. **A person on the network** with no account.
2. **A holder of an agent token** (a compromised monitored machine, or a malicious insider with a registration key): can send events and set names such as a source system.
3. **A low-privilege dashboard user** (viewer, auditor) trying to do more, or to see another organization.
4. **An administrator of one organization** trying to reach another.
5. **A website the administrator visits** (cross-site attacks on a signed-in browser).
6. **A local user on the server machine** who is not the service account.
7. **The software supply chain**: a vulnerable or tampered dependency or download.

Not defended against: root on the server machine, physical access, and a compromised vendor signing key. A rogue administrator of their own organization can do what the role allows (the audit log records it).

## 4. Threats and what stands in the way

| # | Threat | Controls (and where to look) | Residual |
|---|---|---|---|
| T1 | Guessing or stealing passwords | bcrypt; 10-character policy with common-password and username checks; per-account lockout (15 minutes after repeated failures) and per-address rate limit; generic error text; sessions end on password change (`token_version`). `api/auth.py`, `rate_limit.py`, tests in `api/test_security.py`, `api/test_passwords.py` | No second factor, by decision. Lockout is a denial-of-service lever for one account name. |
| T2 | Taking over a fresh install | No default account. The first administrator needs a one-time setup code that only root can read; the page works once. `setup_code.py`, `api/test_setup_code.py` | The code is readable by anyone with root on the machine, by design. |
| T3 | Forged or stolen session | Signed JWT (HS256, algorithm pinned, secret 64 bytes generated per install) in an HttpOnly, SameSite, Secure cookie; expiry. `api/auth_deps.py`; forged-token tests in `api/test_session_tokens.py`, `api/test_route_access.py` | A stolen cookie works until it expires or the password changes. |
| T4 | A user reading or changing what their role should not | Every route declares its minimum role, and a test fails when a route is added without one (`api/test_route_access.py`); organization membership is checked on every organization route and on the live-feed WebSocket. | Roles are coarse (four). |
| T5 | One organization seeing another's data | `tenant_id` on every record, taken from the URL and the user's memberships, never from the body; isolation tests in `api/test_integration.py` and `evidence_store/test_multi_tenant.py`. | Same database file for all organizations. |
| T6 | **Script injection through names an agent controls** (stored XSS) | Fixed in this review cycle. The dashboard escapes every server-supplied value it puts in the page (`escapeHtml` in `dashboard/index.html`); names with `< > " ' & \`` or control characters are refused where they enter (`labels.py`, used by event ingest, scan and agent registration); a browser test checks both (`.github/scripts/browser_smoke.py`). | The content-security policy still allows inline script (see section 6). |
| T7 | Cross-site requests from a page the administrator visits | SameSite cookie, no wildcard CORS (only the server's own origin), JSON bodies. `api/test_hardening.py` | Login form posts are not token-protected (SameSite covers it). |
| T8 | Stolen or abused agent token | Token per agent, revocable from the dashboard; registration keys are one-time (or reusable on purpose), expire in 30 minutes, and can be revoked; the agent can pin the server certificate. `api/agents.py`, `api/agent_auth.py` | An agent that was never revoked stays valid. |
| T9 | Reading data from the files on the server | Program owned by root; data folder `0700` and logs `0600` owned by the service account; field-level encryption of evidence records; secrets folder hardened at start. `package/*/scripts`, CI "files are private" steps | Databases are not encrypted as a whole; the encryption key sits on the same disk (the usual trade-off without a hardware key store). Because values are not stored, a stolen database reveals field names, rules and timestamps, not the personal data. |
| T10 | Tampering with evidence | SHA-256 chain, verified by a button, by every backup and on request (`/api/{org}/verify-chain`). | An attacker who can rewrite the whole chain from some point forward is detected only if someone holds an older head hash. |
| T11 | A file name that escapes a folder (backup verify, restore archives) | Backup verify takes a file name, not a path (`dashboard/server.py`); restore accepts only archive entries inside known folders and never overwrites with a path outside them (`backup.py`, `_safe_arcname`). `api/test_hardening.py`, `test_maintenance.py` | |
| T12 | Using an old or tampered program | Release files are listed in a signed `SHA256SUMS` (signature made by the release workflow itself, checkable with `cosign`); a software bill of materials ships with each release; upgrades refuse to downgrade. | Mac packages are not signed or notarized by Apple (decision); `.deb` has no repository signature. |
| T13 | Vulnerable dependency | A dependency audit blocks a release and runs weekly; `govulncheck` for the launcher; a secret scan of the history. `.github/workflows/security.yml`. Found and fixed: python-jose (advisory, no fix) replaced by PyJWT, cryptography raised to 50. | New advisories appear between audits. |
| T14 | Minting licenses from a leaked CI secret | CI uses its own test key; test builds are patched to trust it, release builds are checked to embed only the production key (`.github/scripts/check_release_key.py`, `dpdpa-agent/test_license_key_is_production.py`). CI no longer reads the production private key at all. The upgrade tests need the previous release to start, so one any-machine license signed with the production key (org `ci-upgrade-test`, expires 2028-10-15) is kept as a CI secret. | That license file, if leaked, runs Veritas on any machine until it expires. Renew it before then. The old `VERITAS_PRIVATE_KEY_B64` repository secret is unused and should be deleted once CI is green. |
| T15 | Abuse of the AI explanation feature | Off by default; when on, only masked text is sent; no raw personal data leaves. | Depends on the provider's terms. |

## 5. Things a reviewer should know

- **Backups hold the keys.** `veritas backup` archives include `secrets/` (database key, session secret) and the certificate key, so a backup restored elsewhere is fully readable. Treat backup files like the server: private folder, encrypted off-machine copy.
- **Default certificate is self-signed.** Browsers warn; agents trust on first contact unless `ca_cert` pins it. A company certificate can be installed (`veritas install-cert`).
- **Login is local accounts only.** No single sign-on.
- **Agents see only the log lines they are told to read**, as an unprivileged account; on macOS the agent needs a per-file read grant.
- **Detection is probabilistic** (Presidio and spaCy plus checksum validators for Aadhaar and PAN); a finding is evidence to investigate, not a legal conclusion.

## 6. Open items, in priority order

1. **Content-security policy.** It allows inline script and style (`'unsafe-inline'`) because the dashboard is one large page with inline handlers and styles. With the escaping above this is defence in depth, not the primary control. Removing it means moving the script out, replacing about 80 inline handlers with event listeners and about 220 inline styles with classes. Planned.
2. **Outside review.** None has been done. This document and the test suites are the starting package.
3. **Load behavior** is not measured, so denial-of-service resistance beyond rate limits is unknown.
4. **No second factor** (decision, recorded).
5. **Whole-database encryption** is not provided; field-level only.

## 7. Running the checks yourself

```bash
cd dpdpa-agent
pip install -r requirements.txt && pip install <spaCy model, see README>
VERITAS_TLS=false python -m pytest api/test_security.py api/test_route_access.py \
  api/test_hardening.py api/test_label_entry_points.py api/test_session_tokens.py \
  api/test_rbac.py api/test_passwords.py test_maintenance.py test_labels.py -v
pip install pip-audit && pip-audit -r requirements.txt          # dependency advisories
```

The install tests (`.github/workflows/test-*-install.yml`) exercise the packaged product on clean Ubuntu and Apple-silicon runners, and `test-browser-smoke.yml` drives the dashboard in a real browser. Reporting a vulnerability: the real security contact address is still to be set (the support mailbox does not exist yet); until then write to the vendor contact you received the license from and include the version from `veritas version`.
