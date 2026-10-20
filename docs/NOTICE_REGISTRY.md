# Notice registry

The policy can list the privacy notices the organization has published. Veritas then shows which declared fields and which observed kinds of data **a current notice covers**, flags a notice that is overdue for review, and raises `NOTICE_001` when it observes a kind of data in a system that no current notice covers.

This is **coverage, not adequacy.** Veritas cannot read a notice, judge whether it is legally adequate, or know that it was shown to anyone (`dpdpa-agent/docs/scope.md`). It checks that you have recorded a current notice that says it covers this kind of data for this system.

## Recording notices

In the policy (*Policy, Edit Policy, Privacy notices*, or the `notices:` section of the policy file):

```yaml
notices:
  - notice_id: customer-privacy
    version: "3"
    title: Customer privacy notice
    effective_from: 2026-01-01
    review_by: 2027-01-01          # optional
    data_categories: [phone, email, aadhaar]
    systems: ["*"]                 # or a list of source systems
    languages: [en, hi]            # optional, informational
```

A field may name the notice that covers it: `notice_id: customer-privacy`. If it does not, any current notice that lists the field's kind of data for its system covers it. A notice that is `retired: true` (keep the old one, add a new id for a new version) or not yet effective does not cover anything; a notice past its `review_by` still covers, but is reported as **review overdue**.

## What you see

*Data map, Notice coverage*: the notices and their status, the observed kinds of data **not covered**, the declared fields not covered (with the reason), and the systems with no current notice. API: `GET /v1/{org}/notices` (any role of the organization).

## The finding

`NOTICE_001` (MEDIUM, "DPDPA 2023 § 5 — Notice") is raised when a kind of data is observed in a system and no current notice covers it, **once per gap**: not on every event. When a notice is recorded that closes the gap, the gap is closed; if the notice is later withdrawn or lapses and the data is still observed, it is raised again. A daily check also raises gaps that appear without new data (for example a notice passing its review date or being retired). Nothing is raised unless the policy lists at least one notice, so existing organizations are unaffected until they opt in.

The statute citation and the wording of the finding are for your lawyer to confirm.

## Limits, said plainly

- It checks your records, not the notice itself, and not whether the person saw it.
- "Kinds of data" are those Veritas can observe: phone, e-mail, Aadhaar, PAN, card, and what database column names and API field names suggest. A kind it cannot see cannot be flagged.
- It does not check purposes against a notice's text; purposes are checked by the policy's own `PURPOSE_001` rule.
