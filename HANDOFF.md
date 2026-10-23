# HANDOFF — Industrial Autonomous Assurance

For the next agent. Written 2026-09-15; §0 added 2026-10-21. Everything here is
checkable against the repository; where something is unproven or unsold it says
so, because a handoff that flatters the work is worse than no handoff.

**Repository** `github.com/iceccarelli/neuralbridge` — zero tags. Test counts
below were observed on 2026-10-21, not carried forward from older text.

---

## 0.0 Changes on 2026-10-23 (supersede §0.1 where they differ)

Branch `claude/serene-gauss-va283c`, not merged. Verified locally against PostgreSQL 16;
each step below was mutation-checked and then reviewed by an agent that did not write it
(the review found real defects in the first round, fixed in the second; the second round has
had no further independent review).

- **Declared provenance can no longer lift a tier** (`machine/provenance_trust.py`, engine 5).
  Whoever files a trace declares its `provenance`, so every verification is capped at
  `community` with `provenance_basis: declared_by_filer`. `LIFTING_BASES` is empty: **no
  machine verification can be `validated` today**, and the public bundle checker rejects any
  bundle that says otherwise. A signed recorder attestation (not built) is the intended way
  to lift it. Consequence, deliberate and a **founder decision before merge**: a required
  re-verification can no longer clear a change case by evidence; it is closed only by a
  named decider's `waive_reverification` (reads `waived`). `blocked_reason` explains this in
  the service, API, CLI, MCP and workspace; plan copy and the claims registry were reworded to
  match. Passports with community-tier cover read `INDETERMINATE`/`LOW`, and legacy
  engine-4 `validated` rows in a ledger are read as `community`.
- **Sealed machine-bundle actor is bound to the credential** like change routes (operator key
  records the operator; a differing body `actor` is 403). Still attribution, not identity proofing.
- **Exports carry a completeness check**: optional signed head anchor (server-read attestation
  only), `verify_export(trusted_key=, anchors=)`, `completeness` = `anchored` /
  `anchored_partial` / `not_checked` / `failed`. `ok` is never "complete". An anchor over an
  empty head, or the exporter's own unsigned head, never anchors. Subject bundles can carry a
  skeleton of the account's other entries (opt-in: it discloses their ids, kinds and times).
  Same-party limit stands: whoever holds the ledger and signing key can re-sign a shorter ledger;
  a hosted export has no anchor until an operator signs into the tenant's attestation log.
- **Watch replay**: `manifest_relayed` is honoured only for a manifest (or same-configuration
  baseline) the account's ledger holds; server `received_at`, `observed_at_skew`, and
  `basis: client_reported` on every observation; `relay_basis` says how freshness was obtained.
  **The server cannot prevent a key holder planting a manifest and relaying it** (a labelled
  non-refusal, because the honest `watch push` does the same); copy says so.
- **Attestation log** writes are serialised (thread lock + flock) and fsynced.
- Sitemap no longer lists the noindex `/checkout/success`.

**Known and not fixed:** no recorder-attestation signer or trust format exists, so `validated`
is unreachable; the ledger has no monotonic-timestamp check (a clock rollback gives
out-of-order `at`); a compromised watch holding the account key can fabricate current-looking
observations; a hosted ledger and its signing key are held by the same party; the Art. 14
export route returns 503 rather than 401 when no operator keys are configured; nothing in this
branch has been deployed or run against real Stripe.

---

## 0.1 Changes on 2026-10-22 (supersede the lines they contradict below)

Verified by running the suite against a local PostgreSQL 16: **4262 passed, 0 skipped**.

- **Limits tables reach `validated` only through an independent signed review**
  (`machine/limits_review.py`, engine 4). A table's own `verified_by` / `verified_on`
  text is the author's claim and never lifts the tier. The review is an Ed25519
  signature over the table's content hash and edition by a key in a trust list the
  *verifier* supplies (`--limits-trust`; the API seals only against the server-configured
  `ASSURANCE_LIMITS_REVIEW_TRUST`). The review is sealed into the bundle and re-assessed
  on replay under the checker's own trust; bundles from engine 3 that carry
  `validated` on a limits table are flagged. It attests that a key holder checked those
  bytes, not that the values are right.
- **Hosted case decisions need an individual operator** (`api/operator_routes.py`,
  `AccountStore.operators`): `decider` operator keys make `decision`, `resume`,
  `resolve-decision`, `waive-reverification`; account-level keys (agents, MCP, watch)
  get 403; a body `actor` that differs from the key's operator is refused; disabling an
  operator revokes its keys. Ledger actors record operator id, role, key prefix, account
  and `attribution=` basis. Older entries keep their declared label. Still no identity
  proofing, and the first operator can be created by an account-level key, so an
  account holder must create it before handing a key to an agent.
- **Trusted supplier advisories** (`supplier/trust.py`, `/v1/supplier/trust/*`,
  `/v1/fleet/advisory/signed`): per-account pinned keys with rotation/revocation, separate
  states (readable / signature / key trust / chain / duplicates / conflicts / withdrawals),
  attributed manual override, classified fleet impact (hash / version-only / name-only /
  contradictory / unknown). The watch runner passes the trust store, so an untrusted
  advisory is inspect-only and opens no case. `fleet advisory --unsigned-anyway` now needs
  `--override-actor` and never lets failed-signature records drive the verdict.
- **Re-verification** refuses a newest manifest that was declared rather than read off the
  unit, a bundle whose trace cannot be dated, and one trace filed for two machines.
- **`assurance value report`** / `GET /v1/value`: the account's assurance position from its
  own ledger (facts with references, unknowns, assumptions, ranked recommendations under a
  printed fixed rule; no score or estimate).
- **Report** states head-attestation status apart from the chain (none / unchecked without a
  key / verified under the reader's key, basis, unsigned tail). `report build --attestations
  --attest-key`.
- **Watch push** carries the local run's supplier findings (with trust state), case ids,
  stale observations and skipped checks as `client_reported_watch_run`; no Article 14
  awareness or classification is sent. Read-only CLI verbs refuse a missing ledger (exit 2)
  instead of creating an empty one.

**Known and not fixed in §0.1 (see §0.0 above for what changed):** provenance, tail truncation, replayed manifests and the attestation log lock were listed here and have been addressed on the branch described in §0.0.

---

## 0. State on 2026-10-21 (read this first; later sections predate it)

**Observed, by running it:** `python -m pytest tests/ -q --no-cov` with a local
PostgreSQL 16 → **all tests pass, 0 skipped** (without Postgres the `/ai` tests
skip honestly); `ruff check src/ tests/` clean; `npx tsc --noEmit` and
`npm run build` clean; `scripts/e2e-assurance.sh` (real API, real per-account
ledgers, real Next server, Chromium) 7/7; `scripts/verify-buyer-path.sh` against
a real local stack passes. Exact counts are in the PR description.

**What changed since the section-5 priorities were written:**

| Was open | Now |
|---|---|
| P0 launch truth: "Unlimited cases" vs a 50/day field nothing enforced | Removed end to end. Cases are **not metered** on Register or Cell; `cases_per_day` / `product_families` no longer exist. `tests/test_assurance_plans_parity.py` parses `app/lib/plans.ts` and fails if the backend catalogue, the frontend fallback or the claims registry drift, or a stale claim returns. `docs/claims-registry.md` maps each public claim to its enforcing code. |
| One global ledger: any paying account could read/write every other account's cases | **Per-account ledger files** (`tenants/<account id>.db`), chosen in exactly one place (`api/deps.py:get_register`). The shared ledger is operator-only; anonymous callers get no ledger. Same for attestation logs and supplier feeds. |
| Webhook merged accounts by email; non-idempotent; wrong status mapping | Accounts bind to the Stripe customer id only; events are deduplicated in the same transaction as their effects; stale and same-second events are ordered (cancel wins ties); `past_due` keeps access (Stripe dunning decides) and is flagged; `paused`/`incomplete` lose it; unpaid waits for `async_payment_succeeded`; sessions that are not ours are acknowledged, not retried. |
| Plaintext key staging forever; no revoke | 24 h TTL, deleted on collection, `Cache-Control: no-store`; `GET/POST /v1/keys`, `POST /v1/keys/revoke`. |
| Watch did not open cases (§5 item 8a) | **Done.** `run_watch` opens and keeps `ChangeAssuranceCase`s itself for drift, supplier advisories and interventions, idempotently. See `deploy/assurance/CHANGE.md` for exactly what is automated and what is not. |
| Hosted workspace showed no Watch run, failure or stale machine | Opt-in `assurance watch push` → `POST /v1/watch/report` → `GET /v1/fleet/observations` and `/assurance`. A failed look never counts as an observation; reports are unverified claims by the key holder; hosted Watch still does not exist. `deploy/assurance/WATCH.md`. |
| Case closure only as strong as its status field | Closure requires post-trigger re-verification evidence **for the machine and function named**, no open human question, and a human actor (`person`, a visible name, not a reserved word). The only way to close without evidence is the explicit, human-only `waive_reverification`, which reads `waived`, never `current`. A case's state is reconstructable from the ledger alone (`assurance change replay`) and the replay rejects forged transitions. Independent adversarial review found and we fixed: cross-machine and pre-change evidence clearing a case, advisory cases closing on `never_verified`, a transient partial collection reopening a human-closed case, replay accepting a forged `ready_to_close`. |
| A hosted Cell customer could not finish a case (no API route for `resume`, `resolve-decision`, `waive-reverification`, `assess-intervention`; an unknown case was 404 on GET but 409 on POST; CLI/API `machine verify` could not file evidence under a machine, so nothing a CLI or API customer produced could clear a case) | All four routes exist (`api/change_routes.py`), plus `GET .../export` and `.../replay`; unknown case is 404 / CLI exit 2 on every verb (`CaseNotFoundError`); `machine verify --subject` / `"subject"` files a bundle under the machine key. MCP deliberately has no tool that decides, waives, resumes or resolves (`tests/test_interfaces_mcp.py` pins the tool list to `CHANGE.md`). One sequence — kit enrolment, firmware change, `watch run`/`push`, assess, claim, advance, re-verify, waive, resolve, defer/resume, close — is run through the library, the CLI, the HTTP API (two accounts) and MCP, and must agree on case id, states, refusals and evidence hashes (`tests/test_interfaces_parity.py`). Case reads and writes refuse a ledger whose chain does not verify (`CaseStore.require_intact`; API 500 `ledger_integrity`, CLI exit 2); `fleet list` leads with the failure; `evidence verify` no longer calls an empty subject bundle VERIFIED. Offline path run in a fresh interpreter under a Python audit hook: no socket, no HTTP client (`tests/test_interfaces_offline.py`). Divergences that remain on purpose are listed in `deploy/assurance/CHANGE.md` (Surfaces). |
| `/ai` control plane had no tenancy: any caller could list and read another account's bound Postgres connection; `/api/v1/logs` was public and listed every tenant's audit events; the raw `adapters/postgres:<id>/execute` route ran SQL on another account's connection | Every connection, plan and audit entry is owned by the account that made it (`neuralbridge/ai/tenancy.py`); a foreign id is a 404 on every route, including the raw adapter routes. `/logs` needs a key and is owner-filtered (export is operator-only); the legacy `/connections` router is operator-only. The **shared seeded demo database is now read-only for paid accounts by default** (it let any paying account `DROP` tables for everyone); `NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID=1` re-enables it for a **local** dev stack only (`scripts/verify-buyer-path.sh` needs it). The `/ai` audit log is in memory and cleared on restart; plan proposals are not audit events — the copy now says so instead of "full audit trail". |
| No customer-facing view (§5 item 8) | `/assurance` (Next.js): fleet, evidence freshness, case queue, case detail with who/when for every history item, the human decisions (claim, advance, answer a question, waive a re-verification, decide, resume), ledger replay, a supplier-advisory panel (paste/upload an advisory or feed, or load a hosted feed; impact over the enrolled fleet; an explicit "Open assurance case"), an intervention assessment form, and a plan/usage panel from `GET /v1/me`. Every panel is its own request with its own loading, refusal (401/402/403/404/409/413/422/429/unreachable/5xx, with the server's remedy text) and "as of" state. It calls the real API with the caller's own key; the server decides what is shown or allowed. *(Superseded by §0.1: pinned supplier keys and trust-evaluated feeds exist server-side.)* The checkout success page reads the plan from `GET /v1/me` and hands the key to the workspace through sessionStorage. Browser e2e: `scripts/e2e-assurance.sh` (workspace, advisories, lifecycle, checkout hand-off, API-client outcomes, site links). |
| No way for an outsider to check an exported bundle | `assurance evidence verify <bundle.json>` — offline, no account. Proves internal consistency; **does not** prove the bundle is the operator's ledger (that needs a signed head attestation). |
| The free verifiers had no website path, and the offline verifier accepted evidence carrying fields outside its seal | `/verify` (Next.js) and `POST /v1/evidence/verify`: anonymous, stateless, 20/day per address (own counter), 4 MiB cap on that path only. Detects a ledger export, machine bundle or attestation log and returns `verified` facts, `assumptions` and `not_checked` limits - never a bare "valid"; attestation signatures are checked only against a public key the caller supplies (header, never the URL) - without one the result is never `ok`. An independent red-team review proved and we fixed: an 85 MB answer from a 4 MiB body (answers are now capped, 2 concurrent analyses, 503 when busy), resealed machine bundles recording tiers the engine cannot produce, and an unsigned attestation log reading as a pass. `verify_export` now also rejects unsealed extra fields, unsupported format versions and non-integer `seq`. Real-browser e2e: `tests-e2e/evidence-verify.spec.ts`. **Not hosted anywhere; the page says so when no API is configured.** Same change set, from an independent review of the SQLite first-open fix (PR #32): `restore_check backup` silently wrote empty snapshots for a data directory with `#`/`?` in its path and could wait forever on a locked source; `verify_chain` raised on damaged pages instead of reporting; the Watch ingest lock waited unboundedly and was one lock for every tenant (now per ledger, 30 s, `503 ingest_busy`). 12-32 process first-open races found nothing. |
| Entitlements driven only by webhooks (a lost webhook silently locks out a payer or keeps a canceller) | `python -m assurance.billing.reconcile` reports drift against Stripe (categories, a drift count as the SLI) and, with `--apply`, corrects existing accounts only — never creates accounts or keys, never overrides a newer webhook. `past_due` now has a local limit it is reconciled against. **Verified against a fake Stripe transport only; never run against real Stripe — run with a test-mode key first.** |
| Entitlements were scattered: no test said which routes are gated, a lapsed customer got 402 on their own evidence, a quota refusal did not say when it renews, usage was a bare daily counter, nothing could be billed per use | **One contract, read from the live app:** `tests/test_assurance_entitlements.py` fails on any `/v1` route that touches tenant data without a gate (`deps.ENTITLEMENT_GATES`) and on any gating plan flag no route carries. **A lapsed customer keeps read/verify/export of their own evidence** (`GET /v1/cases[/{id}[/export]]`, `GET /v1/ledger/verify`, header `X-Assurance-Access: evidence-readout-only`) and nothing else; 429s carry `Retry-After`/`resets_at`. **Durable metering:** `usage_events` is written in the same transaction as the quota check, idempotent per `Idempotency-Key`, only for work that succeeded; `GET /v1/usage`, `POST /v1/usage/limits` (units per UTC month, default 0). **Pay-as-you-go exists in code and is OFF** (`ASSURANCE_PRICE_PAYG` + `ASSURANCE_PAYG_METER_EVENT`, test-mode key): Stripe meter-event outbox reporter, drift reconciliation in the existing reconcile report. **Verified against a fake Stripe transport only; the founder must create the Meter and metered Price in Stripe test mode and schedule the reporter** (`deploy/assurance/README.md`). Also fixed: `stripe_gateway._post` passed a list of tuples as httpx form data, so checkout and the billing portal raised `TypeError` before sending anything. |
| Backups covered only the shared ledger | `python -m assurance.evidence.restore_check backup|verify` snapshots and checks accounts, operator ledger, every tenant ledger, attestation logs and supplier feeds. **No restore has been rehearsed against a deployed service — none exists.** |

**Verification history (so you can judge how much to trust this):** three independent adversarial reviews were run by agents that did not write the code, against the real diff, with reproductions. They proved real defects in what had just been built — all fixed with failing-first tests and mutation checks: closure on another machine's or pre-change evidence; advisory cases closing on never-verified evidence; a stale run or a forged manifest clearing a case (reverify now binds to the ledger's own manifest for the machine); replay accepting a forged `ready_to_close`; a transient partial collection reopening a closed case; cross-tenant leaks in `/ai` and `/logs`; an unauthenticated memory-pressure lever on the webhook; non-ASCII headers causing 500s. **The final round of fixes (reverify ledger-binding, name rules, `/logs`, demo default) was mutation-checked by its authors but has not had a further independent review.** Because of the ledger-binding, advisory and intervention cases now require the machine to be re-collected and sealed *after* the case opened before it can be re-verified (CHANGE.md).

**Still true / still not done (do not claim otherwise):**
- Zero revenue, zero customers, zero pilots. Nothing deployed. Stripe has never
  processed a payment; webhook handling is tested with locally signed payloads
  only. `docs/pmf/PILOT-PROGRAMME.md` is a plan; no outreach has been sent.
- The hosted API does not run Watch. Watch runs in the customer's kit/cron; the
  workspace's "last sealed manifest" is a record date, not a live observation.
- Hosted decisions are attributed to an authenticated operator credential (§0.1);
  CLI and open-mode actors are declared names. Nothing is identity-proofed.
- A hosted deployment that previously let accounts write to the shared ledger
  would hide that data from those accounts after this change; there is no
  migration tool (no production deployment exists).
- `src/dashboard/` (Vite) is still not wired to the assurance API. `/assurance`
  is the working surface.
- Unreviewed/untested against reality: real Stripe behaviour (event ordering,
  endpoint auto-disable, portal plan-switching configuration — `already_subscribed`
  sends upgrades to the billing portal, which must be configured to allow plan
  changes), the `Fly-Client-IP` path, Postgres failure text with real credentials,
  and a restore of a deployed volume.
- Open design risks: the checkout-success key handover is claimable by anyone
  holding the Stripe session id for up to 24 h; the reconciliation tool exists
  but nothing schedules it (there is no deployment to run it from), so until it
  is run on a timer a lost webhook endpoint can still leave `past_due` or a
  cancellation standing; the crash window in
  `run_watch` can leave one orphan divergence record (case itself is not
  duplicated).
- Regulatory framing was corrected in §1: Annex III 1.1.9 is a design
  requirement on the machine and Art. 14 a reporting process; the ENISA Single
  Reporting Platform has no API at launch, so our Art. 14 output is a prefill a
  person keys in. Primary EUR-Lex/ENISA text was not read directly in the
  research pass — verify before quoting.

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

Annex III 1.1.9 is a *design requirement on the machine*; Art. 14 requires a
*reporting process*. Neither is made satisfied by software of ours. What a
hash-chained record of what is on each machine, what was verified against it,
and when can do is let a manufacturer **evidence** its process — and show a
reviewer which records stopped applying. (Corrected 2026-10-21: an earlier
version said both were "satisfiable from" the ledger, which overstated it. The
ENISA Single Reporting Platform also has no API at launch, so Art. 14 output
here is a prefill the person keys in, not a submission.)

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

Changes are made on a branch and shipped as a PR against `main`:

```bash
cd /workspaces/neuralbridge && git checkout -b your-branch \
  && git commit -m "..." && pytest tests/ -q && git push -u origin your-branch
```

CI must be green before merge. Nothing red reaches `main`.

The repository used to be developed as a chain of root-level `00NN-name.patch`
files applied with `git am`; that ended once the product landed on main. The
archived chain is under `assets/historical-patches/` for reference only —
`./nb rebuild` and `./nb apply` are deprecated and refuse to run.

**Before every change, state:** WHY / WHAT / CUSTOMER VALUE / RISK / ROLLBACK /
TESTS / SUCCESS CONDITION.
**After every change:** tests, ruff, mypy. **Never claim success if tests fail.**
Every change reversible, testable, small, reviewable. **Never a giant migration
change simply because two things are related.**

### Definition of done

```bash
pytest tests/ -q          # all passing; see §0 for the observed count
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
| `change` | `assurance change list` / `assurance change show` | **The queue nothing else in this codebase produces.** A `ChangeAssuranceCase` opened from a drift, an advisory or an intervention, carrying which safety function is affected and why, moved through re-verification, and closable only by a named human once the underlying evidence — not a status field — says it may be. See `deploy/assurance/CHANGE.md`. |
| `api` | `uvicorn assurance.api.service:app` | 57 operations (`/openapi.json`); one ledger per account. Entitlements read on **every** request; 402 (not 403) when authenticated but unentitled, because the obstacle is payment. |

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
5. ~~**Feed sync.**~~ **Closed 2026-09-27.** `assurance supplier fetch <url>
   --out <path> [--public-key <key>]` downloads a hosted feed
   (`GET /v1/supplier/feed/{id}`) and writes it to the local path a `watch`
   config's `feed:` field names. Loud failure: a network error or bad HTTP
   status raises rather than reading as an empty feed, and a feed that fails
   `verify_feed` is refused rather than overwriting the last good copy. The
   watch itself still only reads a local file — that stays true on purpose,
   see `checks_skipped` in `deploy/assurance/WATCH.md`. What is still open:
   nobody has wired this into a scheduler (cron, systemd timer) ahead of
   `watch run`, and there is still no supplier-tier price for anyone to pay
   for the hosted feed this downloads from.

### P2 — Deepening the product

6. **Attestation in the report.** The HTML report still says "chain verified",
   which is the *weaker* claim. It should show the last counter-signature and its
   fingerprint. Small patch, completes the story the buyer reads.
7. **CLI test coverage.** `collect/cli.py`, `machine/cli.py`, `machinery/cli.py`,
   `report/cli.py` are at **0%**. Four command-line surfaces a customer touches,
   untested.
8. **Dashboard integration.** *(Partly closed 2026-10-21: `/assurance` shows the fleet, the case queue, case detail/history and exports against the real API — see §0. Still missing: advisory inbox, a fleet-wide staleness view beyond the per-machine counts, re-verification evidence upload beyond pasting JSON.)* `src/dashboard/` knows nothing about assurance. The
   fleet table, the coverage view and the advisory inbox are the three screens
   that would make this sellable to a non-engineer — now joined by a fourth:
   the Active Assurance Cases queue (`GET /v1/change/cases`,
   `assurance change list`), which today only renders as a CLI table and
   JSON, not a page.
8a. ~~**Watch -> case wiring.**~~ **Closed 2026-10-21 — see §0 and CHANGE.md.** *(Original text follows.)* `assess_drift`/`assess_advisory`
    (`src/assurance/change/service.py`) take exactly the objects
    `assurance.watch.runner.run_watch` already produces, but the watch does
    not call them itself. Today a case is opened by running
    `assurance change assess-drift`/`assess-advisory` against the watch's own
    output by hand; closing that gap turns "a case exists" into "a case opens
    itself the day the change happens," which is the whole point. See
    `deploy/assurance/ADR-0002-change-assurance.md`.
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
