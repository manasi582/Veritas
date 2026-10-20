# Policy packs

A blank policy is the slowest part of onboarding. A **policy pack** is a starting policy for an industry: the fields such a company typically holds, in the systems it typically has, each with a purpose, a consent scope, a retention period **and the reason for that value**, plus suggested notices and a list of things to watch for.

Packs today: `fintech` (lending and payments), `healthtech` (clinics and health apps), `ecommerce` (online retail). They live in `dpdpa-agent/policy_packs/packs/*.json`.

## Status: draft, no lawyer has reviewed them

Every pack says `status: DRAFT` and `reviewed_by: null`. The retention periods and purposes are starting values written by the Veritas team, each with a note ("commonly cited minimum, confirm") and none is legal advice. Applying a draft pack needs an explicit acknowledgement in the request. When counsel reviews a pack, set `status`, `reviewed_by` and `reviewed_on` in its file and raise `version`: the acknowledgement is then no longer asked for. **Counsel owns the content; the code only applies it.**

## Using one

| Step | Call | Who |
|---|---|---|
| List | `GET /v1/policy-packs` | any signed-in user |
| Read one, with the reason for every value | `GET /v1/policy-packs/{id}` | any signed-in user |
| Preview (saves nothing) | `POST /v1/{org}/policy-packs/{id}/preview` | AUDITOR, COMPLIANCE_ADMIN |
| Apply | `POST /v1/{org}/policy-packs/{id}/apply` | COMPLIANCE_ADMIN, audit-logged (`POLICY_PACK_APPLIED`, pack id and version) |

Body (all optional): `system_map` renames the pack's generic systems to yours (`{"kyc-service": "kyc-prod"}`); with a map, **only mapped systems are used**. `owners` gives an owner for each of your systems that has none. `acknowledge_unreviewed: true` is required while the pack is a draft.

## Rules that keep it safe

- **Only adds.** A field already in the policy (same system and field name) is never changed; applying twice adds nothing.
- **Never invents a notice.** A notice is a fact the organization must state (it took effect on a date). The preview lists `notice_suggestions`; you record each notice you have really published.
- **Same validation as an upload.** The result must pass the validator, or nothing is saved.
- **Linkage rules** are added only when all their fields are present.
- The preview shows what is added, what was skipped, and `watch_for`: what Veritas will now report in that industry (for example, Aadhaar in the analytics warehouse, because nothing declares it there).

## Not built

There is no screen for packs yet (API only), no custom-pack editor, and no sector rule library beyond these three files.

## Tests

`policy_packs/test_policy_packs.py`: every pack validates and explains each value; a second apply adds nothing and leaves the organization's edits alone; system mapping; linkage rules; preview saves nothing; draft needs acknowledgement; roles; audit log. The end-to-end scenario previews a pack and checks that nothing was saved.
