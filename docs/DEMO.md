# The demo: trust, visibility and prevention

A 15-minute walk through five features in the order that tells the story. Each moment says what to do, what the screen shows, what to say, and what **not** to claim. The same story runs unattended in CI (`tools/trust_e2e.py`), so every step below is known to work.

## Before the meeting (20 minutes)

1. A Veritas server with a license, reachable at `https://veritas.demo.example:8000`, signed in as a compliance administrator. Take a backup first (`sudo veritas backup`): the tamper moment changes the database, and the backup puts it right.
2. Anchoring on, with two witnesses (a folder and your SIEM, or two folders): `docs/ANCHORING.md`. Check *Overview, health card, Anchoring* is green.
3. Load the policy: *Compliance Policy, Edit Policy*, paste `docs/demo/demo-corp.json` (or `POST /v1/orgs/demo_corp/config`). It declares five systems and their owners.
4. Sample logs: `python tools/demo_logs.py /tmp/demo-logs`.
5. Three agents on the demo machine (Agents, *Issue Registration Key*, one each), each reading one of the files in `/tmp/demo-logs`:
   - `order-service` reading `order-service.log` (plain),
   - `noisy-service` reading `noisy-service.log` (plain),
   - `support-ticketing` reading `support-ticketing.log` with **redaction**:
     ```yaml
     redaction:
       mode: monitor
       categories: {aadhaar: mask, phone: hash, email: mask}
       tee_file: /var/log/veritas-agent/masked.log
     ```
   Start the noisy agent last. Keep `marketing-service.log`, `recurrence.log` and `resurrection.log` aside.
6. Open the dashboard in one window, a terminal in another. Have `veritas-verify` (from the release assets) on the machine.

## 1. Prevention: the agent masks before the line leaves (2 min)

- **Do:** show the support agent's config (the `redaction:` block) and `cat /tmp/demo-logs/support-ticketing.log`: a phone number, an Aadhaar number, an e-mail address. Then open **Agents**: the Redaction column says *mixed*; hover for the details (masked, hashed, fail-closed, masked copy, rules version). Open **Live Stream** or the findings: the line reads `[AADHAAR_REDACTED]`, `[PHONE#…]`, `[EMAIL_REDACTED]`. `cat /var/log/veritas-agent/masked.log`: the copy a log shipper would read.
- **Say:** "The agent removes the personal data on the host, before anything travels. If masking ever fails, the line is dropped, not sent."
- **Do not say:** that it cleans your logs (the application's own file is untouched, `cat` it), or that it finds names (it does not: names stay with the server's detection).

## 2. Visibility: 12,000 findings become a short list (3 min)

- **Do:** *Audit Ledger* opens on incidents. Point at the summary line (**about 12,000 findings → a short list of incidents**: nine with a clean run, a few more if the detector mistakes some numbers in the lines for phone numbers, as it did in the CI run: 6,039 findings became 13), the owning team on each row, the 24-hour sparkline. Expand one: the findings are all there; click *Details* on one. Switch to *All findings* to show nothing was removed. Then **Acknowledge**, **Resolve**, and append the recurrence line to the noisy log (`cat /tmp/demo-logs/recurrence.log >> /tmp/demo-logs/noisy-service.log`). After the grace period (1 hour by default; set `VERITAS_INCIDENT_GRACE_SECONDS=30` for the demo) the incident **reopens as recurred**.
- **Say:** "One debug statement used to mean twelve thousand rows for a person to wade through. It is a dozen problems at most, each with an owner. And if a fix does not hold, Veritas tells you."
- **Do not say:** that the grouping is perfect. If asked: "A template that is too loose merges two problems; you can split and merge, and both are recorded."

## 3. The data map: who handles what, against the policy (2 min)

- **Do:** *Data map*. Append `marketing-service.log` to the marketing agent's file (or POST the line): an e-mail address reaches a system whose policy declares only phone. The node turns **amber, then red** once the finding opens. Click it: what was observed, the owner, the open incident; *Open in the Audit Ledger*. Download **Record (PDF)**.
- **Say:** "This is the observed processing map: what Veritas has seen, against what you declared."
- **Do not say:** "complete data map". It shows what was observed in the logs received, not everything that exists (the page says so).

## 4. A rights request, from lookup to record (3 min)

- **Do:** *Rights requests, Look up an identifier*: phone, `+91 98765 43210`. It lists the systems (the support system through its hash token, the order system in clear) with counts. Close it. *New request*: erasure, a ticket number as the reference, the same phone. Tasks appear, one per system, with owners. Confirm each. The request closes. Download **Record (PDF)**: it lists the chain entries the facts rest on and carries a signature.
- Then append `resurrection.log` to the support log (the number again, written differently, and hashed by the agent): a **`ERASURE_001`** finding appears: "an identifier whose erasure request was closed was observed again" (and the alert goes to your webhook within a minute).
- **Say:** "Veritas never stored the number: only a keyed hash. It can tell you where it saw it, and tell you if it comes back."
- **Do not say:** "certificate of erasure" or "erased everywhere". The record says where Veritas *observed* the number and who confirmed their system. Say that a deadline appears only when you set one.

## 5. Trust: evidence an auditor can check without trusting us (4 min)

- **Do:** *Audit Ledger, Verify Cryptographic Hash Chain*: intact. Export the evidence and checkpoints (`GET /v1/demo_corp/evidence/export`, `anchors/export`, `anchors/pubkey`), run `veritas-verify`: **OK**. Now `sudo veritas stop`, then `sudo python tools/demo_tamper.py --data-dir /var/lib/veritas --org demo_corp`, `sudo veritas start`. Click *Verify chain*: **it still passes**: someone with the file recomputed every hash. Export again and run `veritas-verify`: **FAIL, `CHECKPOINT_HEAD_MISMATCH`, naming the record**, with no server and no network.
- **Say:** "The server's own check cannot catch someone who controls the server. The witnesses' copies can. This is what makes the evidence worth showing a regulator."
- **Do not say:** tamper-proof. It is tamper-*evident*: tampering is detected, and the deletion of the very last records is detected once a later checkpoint exists.
- **Afterwards:** `sudo veritas restore <the backup made before the demo>`.

## Close (1 min)

"Prevention at the source, visibility without drowning, evidence an outsider can verify. All on your own servers; nothing leaves your network." Then the honest list: no names in the agent, observed (not complete) data map, no certificate of erasure, no outside penetration test yet, macOS packages unsigned.

## If something does not go to plan

- The noisy log produces more or fewer incidents than you said: the sample lines come from nine kinds of line, and the real detector sometimes reads a number in a line (a tenant or batch number) as a phone number, which gives that line its own incident. Say "a short list", not an exact number, and check the count in a rehearsal.
- *Recurred* does not appear: the grace period has not passed (`VERITAS_INCIDENT_GRACE_SECONDS`).
- `ERASURE_001` does not appear: the request must be **closed** (every task confirmed) and it must be an *erasure* request.
- The verifier says `CHECKPOINT_GAP` or `UNANCHORED_TAIL` before the tamper: take a checkpoint first (`POST /v1/demo_corp/anchors/run`, or wait the interval) so the latest records are covered.
