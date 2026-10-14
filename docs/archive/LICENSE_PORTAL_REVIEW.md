# License Portal Review

Status: review only. No portal code has been changed yet.

Scope: `veritas-license-portal/` (Next.js 14 on Vercel, Supabase for records), compared against the verifiers in `dpdpa-agent/license.py` and `veritas-launcher/license.go`.

## Verdict on signing logic: correct

Tested, not assumed. The signing code from `app/api/generate/route.js` was replayed in Node with the real `tools/private_key.pem`, and the resulting `.vlic` files were fed to both verifiers:

| Check | Result |
|---|---|
| `tools/public_key.pem` matches `private_key.pem` | yes |
| Public key embedded in `license.py` and `license.go` | both match |
| Portal-signed unbound license, Python verifier | VALID |
| Portal-signed unbound license, Go launcher verifier | VALID |
| Portal-signed license with a non-matching fingerprint, both verifiers | rejected: "not valid for this machine" |

Payload format (sorted compact JSON, base64, RSA-PSS SHA-256 over the base64 text) is compatible with `tools/generate_license.py` and both verifiers.

## Problems found

| # | Severity | Problem |
|---|---|---|
| 1 | High | **"Revoke" does not revoke anything.** It deletes the row in Supabase. A `.vlic` is a self-contained signed file and the product never calls the portal, so a "revoked" license keeps working until expiry. The button and the confirm text ("cannot be undone") imply otherwise. |
| 2 | High | **No reissue or renewal flow.** Each issue creates an unrelated row. Replacing a license after a fingerprint change (needed now that the fingerprint is changing to `v2:`) or renewing one means filling the whole form again and leaves duplicate active rows for one org. |
| 3 | High | **Fingerprint is not validated.** Any string is accepted into a bound license. A typo or a pasted-with-whitespace/wrong value yields a valid-looking license that can never match. Expected format is 64 lowercase hex today and `v2:` + hash after the fix. |
| 4 | High | **Supabase row-level security is disabled** (`supabase-setup.sql`). Anyone holding the project's anon key and URL can read the table through the REST API, including `license_text`, which contains complete signed licenses. Unbound licenses work on any machine. Enable RLS with no policies; the service key bypasses it. |
| 5 | Medium | **Database failures are swallowed.** If the Supabase insert fails, the license is still returned and the user is never told, so it is untracked. |
| 6 | Medium | **Single shared admin secret**, compared with `!==`, sent as a JSON field or header on every call, no rate limiting or lockout, no per-user identity, no audit of who issued what. |
| 7 | Medium | **No re-download.** `license_text` is stored but the list API does not return it, so a lost `.vlic` cannot be fetched again from the table view. |
| 8 | Medium | **Parent repo records the portal as a broken submodule.** The portal is a separate git repo nested in `Veritas/`; the parent stores it as a gitlink at the initial commit (`936c8a6`) with no `.gitmodules`. Anyone cloning the parent gets an empty `veritas-license-portal/` and `git status` shows it as modified. |
| 9 | Low | Payload carries only `org`, `tier`, `expiry`, `issued`, `fingerprint`. No license id, so a license cannot be tied back to its database row; no product version or feature limits (e.g. agent count) though tiers exist. |
| 10 | Low | The `tier` has no enforced effect in the product (verified only as an informational string). |
| 11 | Low | Product error messages point to `support@veritas.io` while the `.deb` control file uses `support@veritas.app`. |

## Open decisions

1. Revocation: accept that licenses are expiry-based and rename "Revoke" to "Delete record", or add real revocation (a signed revocation list the product fetches or imports). Offline customers cannot reach a portal, so a file-based list is the realistic option.
2. License id in the payload (recommended) so records, reissues and revocation lists can reference it.
3. Multi-user admin login (e.g. Supabase auth or SSO) instead of one shared secret.
4. Whether tiers should limit anything (agents, orgs, users).
