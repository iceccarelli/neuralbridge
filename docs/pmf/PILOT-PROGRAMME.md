# Paid-pilot and customer-discovery programme

**Status: unvalidated.** Nothing in this file is customer evidence. As of
2026-10-21 NeuralBridge has no paying customer, no pilot, no recorded customer
conversation, and no deployed production service (see `HANDOFF.md` §4.4). This
file is a plan for finding out, written so that a "no" is cheap to hear.

Evidence ladder — only the last rung is traction:

1. The regulatory or operational problem exists. *(Sourced, see below.)*
2. A buyer recognises it and will discuss a solution. *(Not yet observed.)*
3. A buyer pays, and keeps using it. *(Not yet observed.)*

## 1. The hypothesis, stated so it can fail

> A machine manufacturer or robot-system integrator with a repeated deployment
> of safety-relevant configurations will pay a recurring fee to learn, after a
> software change or supplier advisory, **which of their safety evidence has
> stopped describing the machine**, and to keep the re-verification and the
> named human decision on record.

The strongest competing explanation, from the research pass: they already do
this with Siemens F-signatures / Rockwell FactoryTalk AssetCentre drift
detection, a functional-safety engineer's checklist and the notified-body
process, and it is cheap enough. **If that is true we should hear it in the
first three conversations.**

## 2. What the research supports, and what it does not

Source quality: the research pass reached search-result excerpts only, not the
primary EUR-Lex / ENISA pages. Items below marked *verify* must be checked
against the primary text before they appear in anything customer-facing.

| Statement | Basis |
|---|---|
| CRA (EU) 2024/2847 Art. 14: early warning within 24 h of awareness of an actively exploited vulnerability, notification within 72 h, final report within 14 days of a corrective measure; applies from 11 Sep 2026 | EUR-Lex consolidated text via search excerpt — *verify* |
| Art. 14 reporting applies to products placed on the market before 11 Dec 2027 (Art. 69) | secondary source — *verify* |
| ENISA Single Reporting Platform launched 11 Sep 2026; web interface only at launch, **no API**; needs EU Login MFA | ENISA news + FAQ excerpts — *verify* |
| Machinery Reg. (EU) 2023/1230 Annex III 1.1.9: safety-related software is identified and protected; the machine collects evidence of legitimate or illegitimate intervention in software or configuration | EUR-Lex excerpt — *verify*; application date 20 Jan 2027 is from secondary sources only |
| Annex III 1.1.9 is a **design requirement on the machine**. An external ledger helps a manufacturer *evidence* a process; it does not by itself make a machine conform | inference — and `HANDOFF.md` §1 overstated this; it has been corrected |
| Price comparables | Almost none public. Safexpert subscriptions 99/199/264 per month (currency unstated); one GRC tool listed at €399/month (not CRA). OT-security and SBOM vendors are quote-only. €390 and €1,290 per month remain **assertions** |

Gap claim (inference, shallow search): no tool found that maps a change or
advisory to the specific safety functions whose evidence lapses, with
re-verification and a named human closure. The gap is thin on one side —
Siemens, Rockwell and Copia already own change *detection* and could add
tagging — and on the other, SBOM/VEX vendors already hold the CRA budget
conversation.

## 3. Who to talk to (archetypes, not prospects)

No organisation below has been contacted. Named companies, if added, must be
labelled "inferred from public information".

1. Collaborative-robot-cell integrators — champion: functional-safety engineer.
2. Mid-size machine builders shipping to the EU with a safety PLC — product compliance.
3. Packaging / palletising / handling OEMs with field service — service engineering.
4. Robot OEMs with a PSIRT — product security officer.
5. Safety-component and sensor makers whose advisories reach integrators (the supplier side; do **not** sell this yet).
6. CE / risk-assessment consultancies (a possible channel, not the user).

Unknown, to be learned in conversation: who owns the budget, who signs, how long
procurement takes. Do not assume the functional-safety engineer can buy.

## 4. Discovery conversation (30 minutes, no demo until minute 20)

Goal: falsify, not pitch. Ask about the last time it happened.

1. Last time a safety controller / PLC project / scanner zone changed after
   commissioning: what did you do, who was involved, how long did it take?
2. How did you decide which risk-assessment items and verification records still
   applied? Where is that written down? Show me.
3. When a supplier advisory arrives: how do you learn which of your machines are
   affected? How long does that take?
4. Who in your organisation is asking about CRA Art. 14 / Machinery 1.1.9 today?
   What have they asked you to produce?
5. What do you use now (AssetCentre, TIA Portal signatures, spreadsheets,
   a consultancy)? What does it cost in hours per quarter?
6. If this cost you €X per month, what would have to be true to buy it? Who would
   you need to ask? (Do not anchor on €390 / €1,290.)
7. Would you run the **offline kit** on one machine's exports this month? (This
   is a real commitment: a yes means a date.)

Record each conversation in `pilot-ledger.csv` the same day. A conversation
counts as **qualified** only if the person owns or influences the problem and
can name a budget owner.

## 5. The paid pilot (hypothesis — price to be discovered, not set here)

*Machine Baseline & Evidence Assessment*: a fixed-scope, fixed-fee engagement on
one product line.

- Scope: offline kit run on N machines' exports → baseline, noise probe
  (`collect probe`), staleness join against their declared safety functions,
  one report in their hands. Optionally one real change replayed as a case.
- Customer data never leaves their disk unless they explicitly choose the hosted
  path. The kit's network guard record is part of the deliverable.
- Success is agreed in writing **before** work starts, e.g.: "finds at least
  one evidence item or safety function the customer had not already flagged" and
  "one real change case taken to a named-human closure".
- The fee is whatever the buyer will actually invoice. A prepayment, a signed
  order or a PO is the only evidence of willingness to pay. A kind email is not.
- Do not offer discounts, a free "pilot with intent to buy", or per-incident
  pricing. Do not promise universal vendor support: state exactly which export
  formats were handled (`deploy/assurance/COLLECT.md`).

## 6. Metrics

Source column says where the number can come from today. "Manual" means a
person writes it in `pilot-ledger.csv`; do not pretend it is instrumented.

| Metric | Definition | Source |
|---|---|---|
| Qualified conversations | see §4 | manual |
| Paid pilots / cash collected | invoices paid, EUR, date | manual (Stripe or bank) |
| Time to first useful result | first contact on exports → first report with ≥1 finding | manual + ledger timestamps |
| Onboarding hours / delivery hours | founder + engineer hours per pilot | manual |
| Manual interventions per customer | fixes the product should have made | manual |
| Successful repeated observations | `watch.observation` entries with status ≠ uncollectable, per machine | ledger |
| Failed / incomplete observations | share of watch runs `degraded` or machines `uncollectable` | ledger (`watch.run`) |
| Unverified outcomes | share of cases whose re-verification is `unchecked` / `incomplete` | change cases |
| Cases opened → closed by a named human | counts and median days | change cases |
| Findings the customer did not already know | count, confirmed by the customer in writing | manual |
| Conversion to recurring | pilot → subscription | manual |
| Renewal / churn / expansion | per account | manual → Stripe |
| Gross margin and support burden | delivery + hosting cost vs. cash | manual |

Not traction, do not report as such: interviews, page views, GitHub stars,
positive demo feedback, "interested" replies.

## 7. Stop / continue rules (set before the data arrives)

- After 10 qualified conversations: if fewer than 3 describe a recent concrete
  instance of the problem, the problem is not acute for this segment — change
  the segment or the problem, not the copy.
- If 3 or more say an existing tool + checklist is sufficient, narrow to the
  supplier-advisory-to-fleet path or stop.
- If a pilot runs and the customer will not invoice, the product is a nice
  report, not a business.
- A fixed price must not be set until at least three pilot invoices exist.

## 8. Outreach

**Not sent. No email, message or form has been sent to any organisation.** A
founder-approved first message must (a) name the specific change-assurance
problem, (b) state that nothing is deployed commercially yet and the kit runs
offline on their own disk, (c) ask for a 30-minute conversation about their last
firmware change, (d) never claim certification, customers or compliance.
