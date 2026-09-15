# HANDOFF — Industrial Autonomous Assurance

For the next agent. Written 2026-09-15. Everything here is checkable against the
repository; where something is unproven or unsold it says so, because a handoff
that flatters the work is worse than no handoff.

**Repository** `github.com/iceccarelli/neuralbridge` — one branch `main`, zero
tags, 16 assurance commits, 734 tests passing on Python 3.11 / 3.12 / 3.13 / 3.14.

---

## 1. What this is

Evidence infrastructure for machines whose software can hurt someone.

A robot cell ships with a Declaration of Conformity, a risk assessment and a
sign-off. Then somebody updates the safety controller firmware, reshapes a
scanner zone, or patches a PLC project — and every one of those documents
quietly stops describing the machine on the floor. Nothing says so. The
paperwork still looks correct, which is worse than looking wrong.

Two regulations turned that from a quality problem into a legal one:

| | |
|---|---|
| **Reg. (EU) 2024/2847** CRA Art. 14 | Applies since **11 Sep 2026**. Actively exploited vulnerability → **24 hours** to file an early warning naming the Member States of availability. Art. 69(3) extends to products placed on market before 11 Dec 2027. |
| **Reg. (EU) 2023/1230** Machinery Annex III 1.1.9 | Applies **20 Jan 2027**. The machine must identify safety-relevant software and record evidence of intervention. |

Neither is satisfiable from a spreadsheet. Both are satisfiable from a
hash-chained record of what is on each machine, what was verified against it,
and when.

**Objective chain:** CUSTOMER VALUE → PAID TRANSACTION → REPEATABILITY →
PRODUCT → RECURRING REVENUE → SCALE.
**Primary metric:** cash collected per founder-hour.

---

## 2. Repository state

```
0fa947c  assurance.watch: draft the Article 14 intake, and decide nothing     (016)
572f7c5  assurance.watch: watch the suppliers, not just the machines          (015)
363ae96  assurance.supplier: sign the advisory, the forged one reflashes a robot (014)
97c28a1  Sell what was built: README, a cold-start CI job, no image per push  (013)
18d081c  assurance.kit: the offline enrolment kit, and a guard proving it stayed offline (012)
c9f053f  assurance.attest: sign the head, a chain does not detect deletion    (011)
6c8b9a4  assurance.watch: the component that runs when nobody is looking      (010)
e1f61ad  Close the connection leak, bridge a supplier advisory to Art. 14     (009)
...      report (008), collect (007), fleet (006), machinery (005),
         machine (004), billing (003), baseline 001+002
```

- `src/assurance/` — **the product**. 20,165 lines.
- `tests/test_assurance_*.py` — 7,420 lines, 734 tests.
- `src/neuralbridge/` — the integration platform this grew out of. Adapters are
  *evolving* unless the README marks them Supported. Do not market them.
- `src/dashboard/` — Next dashboard. **Not integrated with assurance.**

### Working agreement

Patches are uploaded to the **repo root** as `00NN-name.patch` and applied:

```bash
cd /workspaces/neuralbridge && git pull --ff-only \
  && git am --3way 00NN-name.patch && pytest tests/ -q && git push origin main
```

`&&` is load-bearing: a failed apply stops before the tests, a failed test stops
before the push. Nothing red reaches `main`. On failure: `git am --abort`.

**Before every patch, state:** WHY / WHAT / CUSTOMER VALUE / RISK / ROLLBACK /
TESTS / SUCCESS CONDITION.
**After every patch:** tests, ruff, mypy. **Never claim success if tests fail.**
Every patch reversible, testable, small, reviewable. **Never a giant migration
patch simply because two things are related.**

### Definition of done

```bash
pytest tests/ -q          # 734 passing
ruff check src/ tests/
python -m assurance kit check plant/kit.json
uvicorn assurance.api.service:app
```

---

## 3. What is built, and the finding each piece produces

The test of whether a module is worth money is not "does it run" — it is
**"does it produce a statement a competent engineer could not have produced from
the same files in an afternoon."** Each row names that statement.

| Module | Command | The finding nobody else produces |
|---|---|---|
| `core` | — | Content addressing, evidence objects, and assurance tiers **computed from the weakest input, never passed in**. A datasheet figure can never later be presented as a measured one. |
| `evidence` | — | Hash-chained append-only ledger. `BEGIN IMMEDIATE` spans tail-read and append, so a second writer cannot fork the chain. `export()` refuses to emit a bundle that does not verify. |
| `collect` | `assurance collect probe` | **Three of four items in the shipped example produce false drift every week** from the vendor tool's own timestamps. `probe` finds them from two exports of an unchanged machine and suggests the exclusions. A rule that drops bytes must carry a note or is refused. |
| `machine` | `assurance machine verify` | ISO/TS 15066 §5.5.4 separation with `Sh` over **Tr + Ts** — the classic metre-short error. `Ss` flagged when the requested speed exceeds the speed the stopping distance was measured at. `unchecked` is a first-class outcome; `Verdict` can be `incomplete`. |
| `machinery` | `assurance machinery coverage` | **The staleness join.** A February sign-off, a March firmware change, and the named safety functions whose evidence stopped applying — dated by `trace_started_at`, not by filing time. |
| `fleet` | `assurance fleet advisory` | **`HASH_MISMATCH`** — the label says 3.9.0 and the supplier's published hash for 3.9.0 does not match the bytes on the machine. Neither affected nor clear, and reported as exactly that. No version-range arithmetic, ever. |
| `fleet` | `assurance fleet declaration` | A Declaration of Conformity bound to a configuration hash, so the day it stopped describing the machine is a date, not an argument. Makes **no legal judgement** and says so. |
| `report` | `assurance report` | Self-contained HTML, no scripts, no network, ~20 KB. Chain status is the first thing on the page. *"What this report does not establish"* is a numbered section carrying every `checks_skipped` verbatim. |
| `attest` | `assurance attest sign` | **A hash chain detects editing, not deletion.** Delete forty records, rebuild from genesis, and `verify_chain()` returns `True`. Ed25519 head attestation closes it; `save()` refuses to write the key into the ledger's directory. |
| `kit` | `assurance kit run` | One command inside the plant. Their ledger, their disk, no account, no upload. A **socket-layer guard** refuses every outbound connection including DNS, records any attempt *with the line of code that made it*, and seals that record into their own ledger. |
| `watch` | `assurance watch run` | Runs when nobody is looking. Exit **0 quiet, 1 findings, 2 degraded** — "I could not look" never shares a code with "nothing moved". |
| `supplier` | `assurance supplier publish` | Signed advisories on a chained feed. A supplier **cannot silently un-publish**; a withdrawal is a publication, not a deletion; an **empty feed does not verify**. |
| `watch` (015) | `assurance watch run` | **Both machines unchanged, and the world moved underneath them.** A stop-use advisory matched against a still fleet. A broken feed sync is DEGRADED, never quiet. A withdrawal is announced once: *"you were told about this one."* |
| `watch` (016) | `assurance watch run` | The Art. 14 intake, drafted from the fleet — and **awareness never decided**. What it reports instead: *"this has been outstanding 39 hours and nobody has made the determination."* |
| `bridge` | `assurance bridge` | Field 5 (Member States) assembled from serial numbers. `srp_prefill()` deliberately omits `notification_type` and `awareness_datetime`. |
| `api` | `uvicorn assurance.api.service:app` | 42 endpoints. Entitlements read on **every** request; 402 (not 403) when authenticated but unentitled, because the obstacle is payment. |

---

## 4. Proving this is worth money

### 4.1 What is gated in code today

```
free      free              register=False  export=False  attest=False  machine=False
register  €390 / month      register=True   export=True   attest=False  machine=False
cell      €1,290 / month    register=True   export=True   attest=True   machine=True
```

`GET /v1/plans` is generated **from those enforced flags**. The rule the whole
codebase runs on: **if it is not gated in code, it is not on the pricing page.**
Patch 002 removed fabricated SBOM hashes and a hardcoded
`"integrity": "hash_chain_verified"`; patch 011 existed because the Cell plan
advertised "signed head attestation" and nothing in the codebase signed
anything. That defect class is now closed and must stay closed.

Live Stripe sandbox `acct_1Th7Xc0yoqnS42mn`:

| Price ID | |
|---|---|
| `price_1UFNce0yoqnS42mnOq2mDiVx` | €390 / month — Register |
| `price_1UFNcm0yoqnS42mnS0SvfsT3` | €3,900 / year — Register |
| `price_1UFNco0yoqnS42mnmcNcKMf2` | €1,290 / month — Cell |

### 4.2 Why a buyer pays — the argument per tier

**Free (Validator + kit).** Not charity. It is the **procurement bypass**. The
blocker on an industrial pilot is not price or features — it is the eleven weeks
to get an unknown tool past a plant's IT department. The kit does not ask to be
let through: it runs on the inside and *proves* it stayed there. `kit check`
lists every file a run would open and touches nothing; that output is a security
review answered in one terminal paste. The artefact it produces then argues for
the paid tier by **naming precisely what one offline run cannot establish** —
no watch, no advisory fan-out, no signature on the head, no verified physical
behaviour — with each line naming the thing that closes it.

**Register €390/mo.** The Art. 14 register for one manufacturer. The thing being
bought is not storage; it is *both deadline clocks computed correctly*, the
awareness record with the reasoning that defends it, and an export that refuses
to emit if the chain does not verify. The alternative is a spreadsheet and a
24-hour legal exposure.

**Cell €1,290/mo.** Machine safety verification, Annex III manifests, fleet
advisory fan-out, declarations bound to a configuration hash, and counter-signed
attestation. The thing being bought is **the staleness join and `HASH_MISMATCH`** —
two findings a customer cannot produce by hand across a fleet, and cannot defend
without a dated record.

### 4.3 The moat, stated honestly

The code is **not** the moat. It is MIT-licensed and legible; a competent team
with an agent could rebuild the mechanics. What is not copyable:

1. **Accumulated evidence.** A hash-chained ledger whose earliest records are two
   years old cannot be created retroactively by anyone, including us. A customer
   who switches vendors abandons the only artefact that proves history.
2. **The two-sided market.** A supplier publishes one signed advisory; every
   integrator with that component *enrolled here* learns which serial numbers it
   touches. That fan-out is worth nothing to a supplier with no enrolled
   integrators, and worth a great deal once there are some. First mover holds it.
3. **Being the counter-signer.** In the hosted attestation the customer holds the
   ledger and we hold the key. Neither party can rewrite the story alone. That is
   a *relationship*, not a feature, and a competitor cannot retroactively become
   the second party to a signature made last year.

### 4.4 What is NOT proven — read this before quoting any of the above

- **Zero revenue. Zero customers. Zero pilots.** No one has paid anything.
- **No ICP list, no outreach, no first conversation.** The product is real; the
  pipeline is empty.
- `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` are **not set**. Checkout has
  never processed a live payment.
- **Nothing is deployed.** fly.io config exists; the service has never run
  anywhere but a laptop and CI.
- **The €390 / €1,290 prices are assertions**, not findings. No customer has
  confirmed them and no competitor set has been benchmarked.
- **MIT licence.** Everything above is currently free for anyone to take. This
  directly contradicts the stated fear that a team with an agent could copy it.
  Changing the licence does not retract what is already public. **This is a
  capital decision and it is unmade.**

---

## 5. What still needs to be built

Ordered by proximity to cash, not by interest.

### P0 — Nothing here converts without these

1. **Deploy.** `fly deploy` from `deploy/assurance/`. Set `ASSURANCE_API_KEYS`,
   `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `ASSURANCE_ATTEST_KEY_PEM`,
   `ASSURANCE_PRICE_*`. `max_machines_running = 1` is **load-bearing** — a second
   writer forks the chain. Verify `/healthz` does not report `auth_mode: open`.
2. **One paid transaction.** Not a feature. Until a euro moves, every claim in
   §4.2 is a hypothesis.
3. **ICP list and outreach.** Target: system integrators and machine builders
   shipping collaborative cells into the EU, 10–200 machines in the field. The
   attachment is the kit's own `report.html` — theirs, from their data, in one
   command. Nothing else in the sales motion is needed yet.

### P1 — The second payer

4. **Supplier API and monetisation.** `assurance supplier` is CLI-only. There is
   no `/v1/supplier/*`, no hosted feed, no plan entitlement, no discovery. A
   supplier cannot pay us today even if they want to. Needs: `POST /v1/supplier/advisory`
   (gated), `GET /v1/supplier/feed/{id}` (free), a `supplier` tier, and a
   directory an integrator can subscribe from.
5. **Feed sync.** The advisory watch reads a *local file*. Whatever fetches the
   supplier's feed is outside the system, and `checks_skipped` says so. A
   `assurance supplier fetch` with loud failure closes the last gap in the
   recurring-revenue story.

### P2 — Deepening the product

6. **Attestation in the report.** The HTML report still says "chain verified",
   which is the *weaker* claim. It should show the last counter-signature and its
   fingerprint. Small patch, completes the story the buyer reads.
7. **CLI test coverage.** `collect/cli.py`, `machine/cli.py`, `machinery/cli.py`,
   `report/cli.py` are at **0%**. Four command-line surfaces a customer touches,
   untested.
8. **Dashboard integration.** `src/dashboard/` knows nothing about assurance. The
   fleet table, the coverage view and the advisory inbox are the three screens
   that would make this sellable to a non-engineer.
9. **Palletizer extraction.** A 3,165-line authorization attack suite exists in
   another repository and has never been extracted. It is the strongest available
   evidence for the security claims and is currently invisible.
10. **`assurance value`** — an analysis over the customer's own ledger: how many
    items are hash-identifiable versus name-only, what the worst-case blind spot
    is, what an advisory published today could and could not answer. Computed
    from their data, which makes it the strongest possible conversion argument.

### P3 — Open questions

11. **Licence.** See §4.4.
12. **Repo identity.** The product is "Industrial Autonomous Assurance"; the repo
    is `neuralbridge` with a Next dashboard and adapters. The README now leads
    with the product (patch 013), but the URL still says middleware.
13. **DERIM and GridOS must NOT be merged into the first commercial release.**

---

## 6. Invariants — do not break these

- **Offline kit writes to the operator's disk.** No account, no upload, no DNS
  while the guard is armed. Never open an outbound socket from the kit path.
- **One ledger writer.** `max_machines_running = 1`. A hash chain with two
  writers is two chains.
- **If it is not gated in code, it is not on the pricing page.**
- **`unchecked` is a valid answer.** Never fill a gap with plausible compliance
  language. Never invent ISO/TS 15066 pass language the verifier did not emit.
- **Never fabricate compliance data.** This is why patch 002 exists.
- **Tiers are computed from the weakest input, never passed in.**
- **Every engine declares what it did not check**, and that list travels verbatim
  into the report.
- **Awareness and the track are decisions.** Software drafts; a person decides.
- **Sell what was built.** Do not market the roadmap as GA. Do not claim
  universal enterprise middleware, CRA product certification, or a finished
  adapter marketplace.

---

## 7. Fastest way to see it work

```bash
pip install -e '.[assurance-attest]'

# A supplier signs an advisory
python -m assurance supplier keygen --out psirt.pem
python -m assurance supplier publish CTRL-2026-11.json \
    --feed psirt-feed.jsonl --key psirt.pem --identity identity.json

# A plant enrols two cells offline, with the network provably untouched
python -m assurance kit init plant/
python -m assurance kit check plant/kit.json
python -m assurance kit run plant/kit.json --out plant/out

# The watch joins the two
python -m assurance watch run watch.json --ledger plant/out/evidence.db
```

Expected — and this is the demo that closes a sale, because **both machines are
unchanged**:

```
plant-1 — FINDINGS — something changed since the last run
  [ok   ] CELL-0412  unchanged at e0045e0e1110
  [ok   ] CELL-0501  unchanged at 6ec7ca52368e

  suppliers: 1 STOP-USE advisory(ies) match this fleet; 1 new

  ** STOP USE ** CTRL-2026-11 (controlco) — Authentication bypass in safety controller firmware
       machines: Grimaldi/AR-7#CELL-0412, Grimaldi/AR-7#CELL-0501

  Article 14: 1 newly drafted
    drafted    CTRL-2026-11
               0 confirmed affected (matched by hash)
               2 machine(s) in NEITHER column — a person has to look
               field 5: CANNOT BE COMPLETED
```

That last block is the product in four lines: the world moved, the fleet is
named, the regulatory form is half-filled, and the two things only a person may
decide are left undecided and labelled.

---

## 8. Documentation index

| File | |
|---|---|
| `README.md` | Leads with the product. Every CLI verb checked against `--help` before it was written down. |
| `deploy/assurance/README.md` | fly.io, Stripe, what to check after deploying, backups |
| `deploy/assurance/KIT.md` | The offline kit and the airgap guard |
| `deploy/assurance/ATTEST.md` | Local signing and hosted counter-signature |
| `deploy/assurance/SUPPLIER.md` | The forged-advisory attack and how signing closes it |
| `deploy/assurance/WATCH.md` | The machine watch, the advisory watch, and the Art. 14 draft |
| `deploy/assurance/{MACHINE,MACHINERY,FLEET,COLLECT,BRIDGE}.md` | One per engine |
