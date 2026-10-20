# Veritas: pitch draft

*A first draft for the team to edit. Everything in `[square brackets]` is a placeholder that only you can fill (market size, pricing, traction, names). Statements about the product are true of the current build and are backed by `docs/DEMO.md`, `docs/PERFORMANCE.md` and the end-to-end test. Statements about the law and the market are marked **verify** because they must be checked against current sources before you say them to an investor.*

---

## 1. The product in plain words

**One line.** Veritas shows a company where personal data is leaking into its own systems, helps it fix and prove it, and keeps evidence that an outsider can check. It runs on the customer's own servers, so their data never leaves their network.

**The problem it solves.** India's Digital Personal Data Protection Act (DPDPA, 2023) puts duties on every company that handles personal data: protect it, use it only for the purpose it was collected for, delete it when asked or when it is no longer needed, and tell people and the regulator when something goes wrong. Most companies cannot even answer the first question: *where is our customers' personal data right now?* It sits in application logs, debug output, support tickets and third-party tools, in places nobody declared. Existing tools are either heavy enterprise suites, or they send logs to a vendor's cloud, which is itself a compliance problem.

**What Veritas does, in five moves.**

| Move | What it does | The customer's words |
|---|---|---|
| **Detect** | Agents read the customer's own log files and the server finds Aadhaar numbers, PAN, phone numbers, e-mail and cards, plus names. It records *that* personal data was found, where and when, never the value itself. | "Show me where it is leaking." |
| **Prevent** | An agent on the host can mask, hash or drop personal data *before the line leaves the machine*, and can write a masked copy for the company's log shipper. | "Stop it at the source." |
| **Make it manageable** | Thousands of findings from one noisy line become a short list of *incidents*, each with an owner, a trend, and a flag if a fixed problem comes back. A data map shows which systems handle which kinds of data against what the company declared. | "Don't drown me in alerts." |
| **Act on a person's request** | Find where one person's phone number or e-mail was *observed*, open an access or erasure request, assign a task to each system's owner, record each step, and **watch** for the number reappearing after erasure. The result is a signed record. | "A customer asked us to delete their data. Prove we did our part." |
| **Prove it** | Every finding is chained to the one before it. Signed checkpoints are copied to places the server cannot alter. A small independent program can check the evidence with no access to the server, and it catches tampering that the product's own dashboard cannot. | "Show a regulator or auditor this is real." |

**What makes it different.**
1. **On-premise by design.** Installed on the customer's machine (Ubuntu, macOS, Windows; also containers). No data leaves; no account with us is needed to operate it. For banks, insurers and health companies this removes the first objection.
2. **It keeps no personal values.** It stores findings, not the data. A person's identifier is stored only as a keyed hash, which is what makes "where was this seen?" answerable without creating a new database of personal data.
3. **Evidence that does not depend on trusting us or the customer's admin.** The independent verifier is the part a skeptical auditor or investor remembers.
4. **Honest about its limits.** It says "observed", not "complete"; "tamper-evident", not "tamper-proof".

**What it is not (say this before you are asked).** It does not find everything: detection is probabilistic, and the agent's masking cannot find names. The data map shows what Veritas has *observed in the logs it received*, not every place data exists. An erasure record says where Veritas observed the identifier and who confirmed their system; it is not a certificate that data was erased everywhere. It is not legal advice, and it does not certify a company as compliant. There has been no independent penetration test yet. [Add the current state of certifications.]

---

## 2. How a company in an industry uses it

### Example: a digital lending company ("fintech")

**Who they are.** A regulated lender with a mobile app and a web portal, about 400 employees, a platform of roughly 25 internal services (onboarding, KYC, loan servicing, collections, a support ticket system, a marketing tool). They hold Aadhaar and PAN numbers, phone numbers and bank details of customers, and must show regulators and partners (banks, rating agencies, auditors) that they handle them lawfully.

**Why they need it.** Their risk is not the database, which is guarded. It is the *exhaust*: every service writes logs; developers add debug lines; support staff paste customer details into tickets; a log shipper copies everything into a third-party analytics tool. Personal data ends up in places nobody declared.

**How it is deployed.** A single Veritas server on a machine inside their network (a licensed install; one server per organization). The company's compliance lead uploads a *policy*: for each system, which personal data it is allowed to process, for what purpose, and for how long (for example "kyc-service may hold Aadhaar for onboarding, 365 days"), and who owns each system. A small *agent* is installed next to the services that write logs. It reads the log files, and for the most sensitive systems it is set to mask before sending.

**How it is used, week to week.**

| Who | What they do in Veritas |
|---|---|
| **Compliance lead** | Watches the incident list (a handful of problems, each with an owner); reviews the data map for systems that handle data they did not declare; opens and closes rights requests; exports the record of processing for an auditor. |
| **Engineering owners** | Receive incidents for their own service (with the code location when the log line names one), fix them, mark them resolved, and get told if the problem comes back. |
| **Security / IT** | Installs agents, rotates keys, keeps backups, and gives auditors the evidence export and the independent verifier. |
| **Internal audit or an outside auditor** | Receives the evidence and checkpoints and checks them with the independent verifier, with no access to the live system. |
| **Data protection / legal** | Handles requests from customers to access, correct or erase their data, using the lookup and the signed record. |

**A concrete month.**
- *Week 1:* agents go on 6 services. The first day shows 14,000 findings. The incident view reduces them to 11 problems, three of them in a single debug line in the collections service.
- *Week 2:* engineering fixes the debug line; the incident is resolved. A release two weeks later reintroduces it and Veritas marks it *recurred*.
- *Week 3:* the support ticket system is switched to masking mode, so the log shipper that feeds their analytics tool never receives raw phone numbers or Aadhaar numbers.
- *Week 4:* a customer asks for erasure. The compliance lead looks the number up (it was observed in four systems), opens a request, four owners confirm, the request closes, and a signed record is filed. Three weeks later the number appears again in a marketing export and Veritas raises a finding.
- *Quarter end:* an auditor receives the record of processing and the evidence export, and verifies the evidence independently.

**What the customer gets, in terms they report upward.** Fewer places where personal data is exposed; a short list of owned problems instead of an inbox of alerts; a defensible process for data-principal requests; and evidence that stands up when someone asks "how do you know?".

*The same pattern applies to health tech (patient identifiers in logs), insurance (claims and KYC), e-commerce and edtech (customer and student data in support and analytics tooling), and any company with a platform team and a compliance function.*

---

## 3. The story (to open the pitch): "The Tuesday audit"

**Format.** Told in the first person by one team member playing the customer, with the live demo running quietly behind. About seven minutes. The characters are invented.

### Characters
- **Meera**, head of compliance at a lending company. Capable, outnumbered, personally accountable.
- **Arjun**, a backend engineer. Good at his job; he added a debug line months ago and forgot it.
- **The new CTO**, who asks the question that matters.
- *Veritas* is never a character. It appears only as something Meera can finally do.

### Scene 1: "Please delete my data" (the setup)
> *(Narrator)* It's a Tuesday. Meera opens her inbox and finds one email, from a customer. It says: "Please delete my personal data."
>
> *(Meera)* It sounds simple. But I'd have to know where that number is. Our app, yes. But also our logs, our support tickets, our analytics tool. I don't know. Nobody does. The law says I must act on this, and I can't even say where to start.

*(On screen: an empty search box. Hold the silence for a beat.)*

### Scene 2: "Twelve thousand alerts" (visibility)
> *(Meera)* My old tool did send alerts. Twelve thousand of them, last week. I stopped reading on the second day.
>
> *(Narrator)* Here is what those twelve thousand were: one debug line, written months ago by Arjun, who needed to see why a payment was slow. It prints the customer's phone number every time it runs.

*(Demo: the Audit Ledger. The summary line reads "12,000 findings → 9 incidents". Point at the owner on each row and the sparkline.)*

> *(Meera)* Nine problems. Each with an owner. This one belongs to Arjun's team. I send it to him with the place in the code.
>
> *(Arjun, briefly)* Fixed. Marked resolved.
>
> *(Narrator)* Two weeks later a release brings the line back. Meera isn't watching. Veritas is.

*(Demo: the incident reopens, marked "recurred".)*

### Scene 3: "Where does it actually go?" (the data map)
> *(Meera)* My real fear isn't one log line. It's the systems I don't know about.

*(Demo: the Data map. One system, "marketing-service", turns amber, then red. Click it: what was seen, who owns it, the open incident.)*

> *(Meera)* Marketing was never meant to touch phone numbers. The map shows what we *observed* against what we *declared*. I can't see everything. But for the first time I can see something, and it's honest about the difference.

### Scene 4: "Prove you did your part" (the request)
> *(Meera)* Back to the customer's email.

*(Demo: Rights requests, look up the phone number. It lists the systems and counts.)*

> *(Meera)* Four systems saw this number. It never stored the number itself, only a keyed fingerprint, so the answer doesn't create a new copy of the problem. I open a request. A task goes to each owner. They confirm. It closes, and I download a signed record: where it was seen, who confirmed, when.
>
> *(Narrator)* Three weeks later the same number, written differently, shows up in a marketing export.

*(Demo: a finding appears: "an identifier whose erasure request was closed was observed again".)*

> *(Meera)* I didn't find that. Veritas did.

### Scene 5: "How do we know?" (the twist, and the part investors remember)
> *(New CTO)* Fine. But how do I know nobody edited these records? Your own tool says everything's intact. Why would I trust it?
>
> *(Meera)* That's the right question.

*(Demo, the tamper moment. The driver stops the server and edits one finding, changing a high-severity record to low, and recomputes the chain. The dashboard's "Verify chain" still says intact. Then run the independent verifier on the evidence and the witnesses' copies. It fails and names the record.)*

> *(Narrator)* That program doesn't talk to the server. It doesn't need to. The copies it checks against live somewhere the server can't change. Tampering by someone with full access to the machine is not preventable. It is **detectable**, by anyone, without us.

### Scene 6: Resolution
> *(Meera)* Compliance used to be a promise I made. Now it's something an outsider can check.

*(Beat. Then the narrator takes over: "Veritas. Prove it.")*

### Delivery notes
- Keep Meera's language human. No "PII", no "hash chain" until the twist; the verifier is shown, not explained.
- The demo is the story. Rehearse it so the driver never speaks; the narrator never apologizes for the screen.
- If the live demo fails, keep the recorded run (`tools/trust_e2e.py` proves the sequence works) and play it silently under the same lines.

---

## 4. The pitch (12 minutes, with speaker notes)

*Suggested roles for four people: **Narrator and closer**, **Meera** (the customer's voice), **Driver** (runs the demo), **Numbers** (market and business model, and the skeptical CTO in Scene 5). Adjust to your real strengths.*

### Slide 1: Title (15 s)
**Veritas. Prove it.** [Company name] · [Logo] · one line: *Personal-data compliance that runs on your own servers and can be verified by anyone.*

### Slide 2: The hook (90 s)
Tell the five-year-old log fable, or open straight into Scene 1. Goal: the room feels Meera's helplessness.

### Slide 3: The problem (60 s)
- Personal data leaks through *exhaust*: logs, tickets, analytics tools, not through the database.
- DPDPA makes the company accountable for it. **Verify** the current penalty ceilings, commencement dates and breach-notification duties before quoting them; do not rely on memory.
- Today's choices: heavyweight enterprise suites, or tools that ship your logs to someone else's cloud.

### Slide 4: Why now (45 s)
- A new law with real penalties, being phased in. **Verify** the dates.
- Enterprise customers and partners (banks, insurers, global clients) now ask suppliers for evidence.
- Engineering teams are drowning in alerts; the incident view is a relief they feel on day one.
- [Your own insight: what changed that makes this possible now?]

### Slides 5 to 9: The product, shown (7 min, runs as the story)
Scenes 2 to 6 with the live demo. One slide per scene is optional; the demo is the content.

### Slide 10: How a company uses it (45 s)
The lending-company month from section 2. One diagram: *agents on services → Veritas server in the customer's network → compliance, engineering and audit users*. Say the sentence: **"Nothing leaves their network."**

### Slide 11: Market and business model (90 s) [Numbers]
- Customers: regulated and data-heavy companies with a platform team: lending and payments, insurance, health, e-commerce, edtech, SaaS serving enterprises. [Number of target companies: **fill in and source it**.]
- Sales motion: [direct to compliance and security leaders / through auditors and consultancies / through system integrators].
- Pricing: [per-organization annual license, tiered by systems or event volume. **Fill in.**]
- Deployment: per-customer on-premise license, verified offline, so there is no hosting cost for us.
- [Unit economics and expected sales cycle: **fill in**, or say you will learn them in the pilot phase.]

### Slide 12: Traction and proof (45 s)
- What exists today (true now): the working product on Ubuntu, macOS, Windows and containers; five major capabilities; automated install and end-to-end tests on clean machines; measured performance (100,000 findings grouped into a few hundred incidents, a data map of 50 systems built in milliseconds, a lookup in a 200,000-entry index in under a millisecond).
- [Pilots, design partners, letters of intent, conversations. **Only list real ones.**]

### Slide 13: Honest limits (30 s)
Say it yourself, plainly: observed not complete; tamper-evident not tamper-proof; masking cannot find names; not a certification; no outside penetration test yet. Then: "Here is what we are doing about each." [Fill in your plan: independent penetration test, certifications, signed installers.]

### Slide 14: The team (30 s)
Four people, four roles. [Names, one proof point each: what each has built or run before.]

### Slide 15: The ask (30 s)
[Amount], for [18 months], to reach [specific milestones: for example three paying customers, an independent security assessment, signed Mac installers, a sales hire]. One sentence on what the money changes.

### Slide 16: Close (15 s)
Return to Meera. **"Compliance used to be a promise. Now it's something an outsider can check."**

---

## 5. Questions investors will ask, and straight answers

| Question | Answer |
|---|---|
| Why on-premise in the age of SaaS? | The customers with the strictest rules (finance, health) cannot send logs to a vendor, and a compliance product that creates a new copy of personal data in someone else's cloud defeats its own purpose. On-premise is a requirement for them, not a preference. It also means we carry no hosting or data-liability cost. |
| What stops a big vendor from doing this? | [Your honest answer. Candidate points: they are built for the cloud and for large enterprises; the independent verifier and the keep-no-values design are architectural choices that are hard to retrofit; we move faster for mid-market. Add only what you can defend.] |
| Does it store personal data? | No personal values. It stores findings (rule, field, system, time) and, for lookups, keyed hashes. Keys are encrypted at rest and never exported. A backup contains the keys, so backups must be protected like the server. |
| How accurate is the detection? | It is probabilistic. Structured identifiers (Aadhaar with its checksum, PAN, phone, e-mail, cards) are reliable; names are weaker. A finding is evidence to investigate, not a legal conclusion. Say so. |
| Can the evidence really not be forged? | It can be forged by someone with full access to the machine; that cannot be prevented. It can be **detected**, because checkpoints are copied to places the server cannot alter. We demonstrate it live. |
| What does a customer need to run it? | One server and an agent per host that writes logs. Install packages exist for Ubuntu, macOS and Windows, plus a container for the agent. |
| What are you not building? | Consent management, data discovery in databases, and automated legal conclusions. The scope is deliberately logs and the evidence around them. [Confirm this is how you want to position it.] |
| What is the biggest risk? | [Be honest: for example, sales cycle length for compliance purchases, the pace at which the law is enforced, or dependence on a few early customers.] |

---

## 6. Before you present: a checklist

- [ ] Verify every legal statement against current official sources (penalty amounts, commencement dates, breach-notification and data-principal rights provisions, and the response periods). The product shows a due date only if the customer sets one, for exactly this reason.
- [ ] Fill every `[placeholder]` or delete the line. Never present a number you cannot source.
- [ ] Do not claim traction, pilots, certifications or customers you do not have.
- [ ] Run the demo end to end on the machine you will use, twice, following `docs/DEMO.md`; take a backup first (the tamper moment edits the database).
- [ ] Have a recorded fallback of the demo.
- [ ] Decide who answers which question, and agree that "we don't know yet" is an acceptable answer.
- [ ] Lawyer review of the legal drafts in `docs/legal/` before anyone is asked to sign.

*Source documents in this repository: `docs/DEMO.md` (the step-by-step demo), `docs/PERFORMANCE.md` (measurements), `docs/SECURITY_OVERVIEW.md` (answers for a customer's security team), `docs/ANCHORING.md`, `docs/INCIDENTS.md`, `docs/FLOWS.md`, `docs/AGENT_REDACTION.md`, `docs/SUBJECT_LOOKUP.md`.*
