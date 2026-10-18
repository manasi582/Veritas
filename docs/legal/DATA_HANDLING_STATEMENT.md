# Data handling statement

> **DRAFT for legal review.** `[Bracketed]` items are to be completed. Not legal advice.

**Product:** Veritas DPDPA compliance monitoring, version [current]. **Vendor:** [vendor legal name, address].

## 1. Summary

Veritas is software the customer installs and operates on its own infrastructure. The vendor does not host the product and does not receive, store or process the customer's data in the course of the customer using it. On that basis the vendor is **not a processor of the customer's personal data** in the ordinary operation of the product. [Counsel to confirm this characterization under the Digital Personal Data Protection Act 2023, and for any support activity in section 5.]

## 2. What the product does with data (on the customer's systems)

| Item | Treatment |
|---|---|
| Log lines read by agents | Sent over TLS to the customer's own Veritas server, examined in memory for personal data, and not stored. |
| Findings | Stored on the customer's server: organization, rule, severity, field name, source system, time, statute reference, explanation text, and a hash chaining each finding to the previous. **No personal data value is stored in a finding.** |
| User accounts | User name, e-mail address and a password hash, for the customer's staff who use the product. |
| Case notes | Free text typed by the customer's staff, stored as typed. The customer should instruct staff not to enter personal data. |
| Backups | Copies of the above and of the product's encryption keys, kept where the customer chooses. |
| Optional alerts | Messages to the customer's own webhook or mail server containing counts, rule names, field names and violation numbers; no personal data values. |
| Optional AI explanations (off by default) | If the customer turns it on and supplies its own provider key, masked text is sent to that provider. The provider is the customer's choice and subject to the customer's agreement with it. [Counsel: confirm vendor has no role.] |
| Optional forwarding of sanitized logs (planned) | Not available in the current version. |

## 3. What the vendor receives and holds

| When | What | Why | Kept for |
|---|---|---|---|
| Issuing a license | Organization name, customer name, the machine fingerprint (a hash of the machine's hardware identifier), license tier and expiry date, notes | To produce the license file and support renewals | [period] in the vendor's license portal |
| Support | A support bundle, **only if the customer sends one** | To diagnose a problem | [period], then deleted |
| Contracting | Contact names and business e-mail addresses | Account management | [period] |

The product never sends any of this to the vendor by itself: it makes no connection to the vendor, collects no usage statistics and does not check for updates.

## 4. The support bundle

Contains: product version, license status, the product's own health checks, disk space, names and sizes of data files, settings with secret values hidden, and recent log lines from which tokens, keys and recognizable personal identifiers have been removed. It does **not** contain: databases, evidence records, encryption keys, certificates, the license file, or passwords. The customer can read it (it is a ZIP of text files) before sending it.

## 5. Security of data on the customer's systems

Described in the Security Overview. The customer is responsible for the security of the server (physical and network access, operating system, disk encryption, backups).

## 6. Retention, deletion and return

The customer controls retention on its own systems. Removing the product with its purge option deletes all of its data on that machine. On request the vendor deletes the license records for the customer from its portal [within N days], keeping [what must be kept by law].

## 7. Personal data of the customer's staff held by the vendor

Business contact details only (section 3). The vendor's privacy notice is at [URL].

## 8. Changes

The vendor will tell customers before any release changes what data the product sends outside the customer's network. The current version sends none.
