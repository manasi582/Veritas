# Support policy

> **DRAFT for review.** `[Bracketed]` items are decisions to make; the numbers shown are suggestions, not commitments. Not legal advice.

## 1. What is covered

Support for the Veritas software during the license term: installation and upgrade help, questions about using it, diagnosing problems, and fixes delivered as new releases. It covers the **current release and the one before it** [confirm]. For an older release the answer may be "upgrade first".

Not covered: the customer's own servers, network, operating system or applications; custom development; training [or: available at the rate card]; recovery of data without a backup.

## 2. How to reach support

| Channel | Details |
|---|---|
| E-mail | [support address] |
| Telephone | [number, for severity 1 only] |
| Hours | [for example 09:00 to 18:00 India time, Monday to Friday, excluding [country] holidays] |

Please send, every time: what you were doing, what you expected, what happened and when, the product version (`veritas version`), and the **support bundle** (`sudo veritas support-bundle`). The bundle contains no passwords, keys, databases or personal data (see the Data Handling Statement).

## 3. Severity and targets

| Severity | Meaning | First response | Target |
|---|---|---|---|
| 1 Critical | Veritas is down or evidence cannot be recorded or verified, and there is no workaround | [4 business hours] | Workaround or fix plan within [1 business day] |
| 2 Major | A main feature is unusable but there is a workaround, or detection is badly wrong | [1 business day] | [3 business days] |
| 3 Minor | A question, a cosmetic fault, or a problem that does not stop work | [2 business days] | In a later release or by answer |

Targets are for the vendor's first response and plan, not for a complete fix, which depends on the problem. [Counsel and management: confirm whether these are commitments, and any credits.]

## 4. Releases and fixes

- Fixes and improvements ship as numbered releases listed in the changelog. Install them with the normal upgrade, which backs up your data first.
- Security fixes are announced to customers [how, within what time].
- A license renewal is a new license file for the same machine, issued on request [lead time: please ask at least 30 days before expiry; the product warns from 30 days].

## 5. Customer responsibilities

Keep regular backups and test a restore; keep the server and agents on a supported release; give the vendor the information in section 2; tell the vendor promptly about any suspected security problem.

## 6. Security reports

Send to [security address]. Include the product version and steps to reproduce. The vendor will acknowledge within [2 business days] and will not take action against good-faith reports.
