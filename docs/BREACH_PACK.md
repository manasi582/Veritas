# Breach pack

When an incident is a possible breach, the people who must act (the Data Protection Officer and counsel) need the facts fast and in one place. `GET /v1/{org}/incidents/{id}/breach-pack` returns a zip with a **draft** report for that incident (roles AUDITOR and COMPLIANCE_ADMIN and above; each download is audit-logged). The dashboard shows a **Breach report** button on incidents flagged as possible breaches.

| File | Content |
|---|---|
| `REPORT.md` | The draft report: what was observed, response so far, timeline, blanks for people |
| `report.json` | The same, for machines |
| `timeline.csv` | Every signed status event, with its chain sequence number |

## What comes from the chain

Rule, severity, system and field; first seen, last seen, how long it was active; number of findings; kinds of data involved; recurrences; owner from the policy; time to acknowledge and to resolve; each status event with who did it and why. Each event is a signed record in the evidence chain, and the report carries the chain head so the audit pack ([AUDIT_PACK.md](AUDIT_PACK.md)) proves it is the same history.

## What is left blank on purpose

Nature of the breach, number of people affected, likely consequences, measures taken and planned, the DPO's contact, when the organization became aware, and whether the Board and the Data Principals were told. Veritas cannot know these. The report never presents the number of findings as a number of people.

## What it is not

A draft, not a filing and not legal advice. The deadlines for notifying the Data Protection Board and the people affected, and what each notice must contain, come from the Act and the Rules: **counsel must confirm them** before the pack is relied on. It carries no personal value, only counts, kinds of data, and system and field names.

## Tests

`breach_pack/test_breach_pack.py`: contents and chain events, the blank sections and the disclaimer, no raw value, roles and audit log.
