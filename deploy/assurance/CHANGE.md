# Continuous Machine Change Assurance

OBSERVATION OR ADVISORY -> EVIDENCE ASSESSMENT -> CHANGE CASE -> RESPONSIBLE
ACTION -> RE-VERIFICATION -> HUMAN DECISION -> VERIFIABLE CLOSURE.

## The gap this closes

Every other module in `assurance.machinery` and `assurance.fleet` answers one
question and stops: `compare()` says a manifest drifted, `assess_coverage()`
says a function is stale, `assess_impact()` says an advisory now touches this
fleet. Each is correct and each leaves the reader to do the same manual work:
figure out what it means, decide who has to act, track whether they did, and
remember to check again before calling it closed. That tracking — not the
detection — is where a spreadsheet actually lives today, and it is invisible
to every other report this product produces.

A `ChangeAssuranceCase` is that tracking, made a first-class, ledger-backed
object instead of somebody's inbox.

## What it is not

- Not a new source of truth. Every fact on a case is copied from
  `assurance.machinery.divergence.compare`,
  `assurance.machinery.staleness.assess_coverage`,
  `assurance.fleet.impact.assess_impact`, or an
  `assurance.machinery.intervention.Intervention` record. See
  `src/assurance/change/service.py` for exactly which field comes from which
  engine.
- Not a ticketing system. There is no free-text status, no arbitrary field,
  no "any of these ten values" — the six ordinary states and two human
  dispositions are the whole vocabulary, and a transition that the required
  evidence does not support is refused, not merely discouraged.
- Not a compliance verdict. Nothing in this module ever writes `compliant`,
  `safe` or `certified`. The strongest thing it says is `ready_to_close`, and
  turning that into `closed` needs a named human and a reason they wrote.

## Who does what

| | Detects and records | Decides |
|---|---|---|
| `assurance watch run` (automation actor) | opens a case; folds a repeat observation into it; reopens a closed one on a genuine recurrence; puts a supplier's withdrawal to the owner | never |
| A named person (`--actor`, or `actor` in the API body) | claims, advances, submits a re-verification | `decide` (close / reject / defer), `resume`, `resolve-decision`, `waive-reverification` |

`decide`, `resume`, `resolve_decision` and `waive_reverification` refuse any
actor that is not a named person, in the domain layer (`_require_human`), so
the CLI, API and MCP all inherit it:

- `Actor.kind` must be exactly `person` — no case or whitespace tolerance. A
  scheduled watch is `automation`; so is a caller who gave no name; `service`
  and `agent` are refused too.
- The name is normalised (NFKC) and refused if it has no visible letter or
  digit, contains any format/control/line-separator character (Cf, Cc, Zl, Zp)
  or one of the blank "filler" code points (U+115F, U+1160, U+3164, U+FFA0,
  U+2800), or is one of the labels automation goes by (`automation`, `watch`,
  `agent`, `service`, `system`, `bot`, `assistant`, `operator`, `ai`;
  case-insensitive). The same name rules apply to a case's `owner`.
  A name is reserved when every word in it that is not a number is a reserved
  word, after NFKC, accent stripping, case folding and mapping a short list of
  lookalike Cyrillic/Greek/Latin letters to Latin: `agent.`, `system:`,
  `bot-7`, `automation bot` and `аutomation` (with a Cyrillic а) are refused;
  `Agent Smith`, `Watch Dog` and `Botticelli` are somebody's name and pass.
  Limits: the confusables list is short, not Unicode's; a reserved word fused
  into one token (`automationbot`) or spelled with digits (`syst3m`) is not
  caught; and nothing here can tell that a plausible name is a real person's.

The reasoning is the product's whole position: detecting and reporting can be
automated, deciding that the evidence stands again cannot.

**What that does and does not prove.** Over the hosted API a decision
(`decision`, `resume`, `resolve-decision`, `waive-reverification`) needs a key
issued to an individual **operator** of the account with the `decider` role
(`POST /v1/operators`). The server attributes the action to that operator by
credential: a different `actor` in the body is refused (403 `actor_mismatch`),
an account-level key — what an agent, MCP client or watch holds — is refused
(403 `operator_required`), and a disabled operator's keys stop authenticating.
The ledger records the operator id, role, key prefix and account in the actor's
`role` with `attribution=authenticated_operator`. Steps that are not decisions
(`claim`, `advance`, `reverification`) accept an account-level key with a
*declared* name, recorded as `attribution=declared_by_account_key`; entries
written before this change keep that honest label and are not upgraded.
What it still does not prove: that the operator is a particular real-world
person (there is no identity proofing, only a credential-to-name binding), or
that the holder of the key is the person it was issued to. The first operator
of an account can be created with an account-level key, so create it before
handing a key to an agent; after that only a `decider` can create or disable
operators. The local CLI and open mode still take a declared `--actor`.

## The three triggers

| Trigger | Built from | Opens a case when |
|---|---|---|
| Machine drift | `Divergence` (from `compare()`) + `CoverageReport` | `verdict == "safety_relevant_drift"` |
| Supplier advisory | `ImpactReport` (from `assess_impact()`) | `verdict != "clear"` |
| Intervention | `Intervention` + `CoverageReport` | the intervention invalidated at least one function's coverage |

`assurance watch run` opens all three without anyone running anything by hand
(see `deploy/assurance/WATCH.md`). `assess-drift`, `assess-advisory` and
`assess-intervention` remain for one-off use and for deployments that do not
run the watch.

**Behaviour changes to know about when upgrading** (they affect scripts):
- `assess-advisory` and `POST /v1/change/assess/advisory` used to open a case from a bare
  advisory as "automation" when no actor was given. They now refuse that (exit 1 / HTTP 409);
  pass `--actor NAME` / `actor`.
- A pre-work re-look at an *advisory* case (open, or in review with nothing re-verified) is now
  additive for every advisory: it never drops a machine or a link to the advisory it was
  opened on. Drift and intervention cases are unchanged.
- Cases already in a ledger keep their ids and carry no marker. A bare file whose advisory id
  matches such a case does not update it (it says so and exits non-zero).
- `POST /v1/fleet/advisory/signed` rows for an unsigned import are inspect-only
  (`automated_consequences_permitted: false`) even under a pinned key.

**An advisory nobody has authenticated opens a case only for a named person.**
`assess-advisory --advisory FILE` and `POST /v1/change/assess/advisory` take the
advisory as a file or a body, so it carries no signature: both refuse it unless
`--actor` / `actor` names a person (not "automation", "agent" and the like), and
the case's provenance says `advisory_trust: unauthenticated_file` /
`unauthenticated_input` and who accepted it. An advisory that is an **unsigned
import** (`assurance fleet import-csaf`, see `FLEET.md`) needs more: the
explicit override `--accept-unsigned` (API: `accept_unsigned: true`, with an
optional `reason`). Its case has its own id (the advisory id, its trust class
and its publisher), so it cannot merge into or rewrite the case of a signed
advisory that reuses a tracking id, it carries `advisory_partial`,
`advisory_dropped_products`, `advisory_severity_source`, `advisory_tlp` and the
rest of the translation record in its provenance and its export, and it opens
with a human decision to confirm the advisory against the publisher (and, when
the translation dropped products, a second one naming them). The watch
runner never does this: it treats an unsigned import as untrusted, whatever
feed it is in.

## A repeat observation, a recurrence, and what each does

One case per trigger: `_case_id` is a hash of `(trigger_type, trigger_id)`,
where the id is the observed configuration hash (drift), the advisory id, or
the intervention id. What happens when the same trigger is seen again is
decided by the case's state, in `assurance.change.service._open_or_update`:

| Existing case | A repeat observation of the same trigger | Ledger |
|---|---|---|
| none | open it | 1 `opened` entry |
| `open`, or `in_review` with nothing re-verified | refresh the **facts** the fresh reading re-reads; the **work** (re-verifications, actions, questions), the **machines** and the **links to evidence** can only grow, a repeat look never drops what is outstanding or what the case already names | an `updated` entry **only if something differs** |
| `awaiting_action` and later (`awaiting_reverification`, `ready_to_close`) | **additive only**: new machines, new functions, new questions are added; a function already tracked is never re-inflated; if the addition makes `ready_to_close` untrue the case steps back | an `updated` entry only if something was added |
| `closed` | nothing — **unless** it genuinely recurred (below) | nothing, or 1 `reopened` entry |
| `rejected` | nothing for an identical trigger. A different trigger id (a different configuration, a different advisory) is a different case and opens normally. An **advisory** that now exposes a machine the rejection did not name reopens it, exactly as for `closed` | nothing, or 1 `reopened` entry |
| `deferred` | not reopened and not worked, until a person calls `resume` — but an advisory whose exposure grew has the new machine **added** and a question put to the owner, recorded once; it stays deferred | nothing, or 1 `updated` entry per newly exposed machine |

"Identical input twice" therefore writes **nothing** the second time: no ledger
entry, no history row. This is tested by counting ledger entries.

**A genuine recurrence of a closed (or, for advisories, rejected) case**, and only these:

- *drift* (closed only; a rejected drift stays rejected): the machine was
  recorded in a **different, complete** configuration after the closure, and has now come back to the closed one (A -> B closed, B -> A,
  A -> B again). The evidence is the ledger's own manifests ordered by chain
  position, not by anybody's clock. A watch that sees the closed configuration
  merely persist reports `observed`, never `changed`, and a direct
  `assess-drift` re-run with the same pair finds no intervening manifest.
- *advisory*: the advisory now reaches a machine the closed or rejected case
  did not name.
- *intervention*: never. An intervention is one event; a new one is a new
  trigger.

**An incomplete collection is not a configuration.** When a watch run does not
find or read every item its plan names, the manifest it seals carries
`[collection incomplete: …]` in its `notes` and the observation records
`complete: false` and the missing item ids. Such a manifest never counts as the
machine having "left" a configuration, so a transient missing export cannot
reopen a case a person closed. It can still open a case (the drift it shows is
real, and the existing warning says the hash covers less than the plan), and it
never advances or closes one.

Reopening appends one `assurance.change.reopened` entry. The closing (or
rejecting) entry is not touched and stays in the chain; the case's `history` is carried forward and
extended; `prior_closures` records who decided, the disposition, when, why, and the
**ledger hash of that entry**, and a `concerns` link carries that hash into the
new cycle. Owner, reviewer and decision are cleared: the new cycle needs a new
claim and a new decision. A reopened case is `open`.

## The lifecycle

```
OPEN -> IN_REVIEW -> AWAITING_ACTION -> AWAITING_REVERIFICATION -> READY_TO_CLOSE -> CLOSED
   \________________ REJECTED / DEFERRED (from any open status) ________________/
DEFERRED --resume--> IN_REVIEW          CLOSED --recurrence--> OPEN
```

`claim()`, `advance()`, `reverify()`, `resolve_decision()`,
`waive_reverification()`, `decide()` and `resume()` in
`assurance.change.service` are the only ways a case moves.

**`READY_TO_CLOSE` and `CLOSED` cannot be reached with work outstanding.** Three
independent layers:

1. `advance()` and `reverify()` only choose `ready_to_close` when
   `required_reverifications` and `human_decisions_required` are both empty.
   `advance()` leaves `awaiting_reverification` only once that list is empty.
2. `decide(..., "closed")` demands `ready_to_close` **and** re-checks, as a
   separate test, that both lists are empty, from a named person.
3. `CaseStore` refuses to seal a `ready_to_close` or `closed` snapshot that
   names outstanding work, whoever called it.

**What clears a re-verification entry.** `reverify()` clears an entry only when
every one of these holds, each read from the sealed record and not from the
caller:

- the manifest is for a machine the case concerns, and the entry is that
  machine's. Advisory cases span machines, so their entries (and their
  `evidence_before` / `evidence_current` keys) are `machine/function`; one
  machine's bundle never clears another's, and the case is ready only when
  every named machine's every function is cleared. Drift and intervention cases
  concern one machine and keep bare function ids;
- the manifest agrees with the **ledger**. The machine's declared functions and
  checks, and its current configuration, are read from the newest manifest
  *sealed in the ledger* for that machine; the caller's manifest only has to
  carry the same configuration hash (or, for a drift case, the one the case was
  opened on). With no manifest sealed for the machine, the re-verification is
  refused. The newest sealed manifest must also have been taken at or after the
  case's trigger, so the machine has to be re-collected after the change;
- the cited verification is among the ones the coverage check ran against, was
  **sealed after the case's current cycle began** (ledger position, not clock),
  and its run describes a state at or after the case's trigger. The trigger is
  the observed manifest's `taken_at` (drift), the intervention's `occurred_at`,
  or — for an advisory, which has no observation time — **the case's own
  opening time**, stamped by the case and never supplied by a caller. A bundle
  that already existed when the change was found cannot be evidence about it;
- **that one bundle** passed **every** check the function declares (a newer
  bundle for one check plus an older one for another does not clear it);
- that bundle's tier is **at least `validated`** (`assurance.core.tiers`). Below
  it, the entry stays required, reads `below_validated:<tier>` in
  `evidence_current`, the case records why in `checks_skipped`, and only a person's
  waiver closes it. **That is every verification whose trace has no accepted
  recorder attestation:** a trace's provenance is declared by whoever files it, so
  the engine caps it at `community` (`deploy/assurance/MACHINE.md`, "Why a declared
  provenance does not count"). **A `validated` verification requires a recorder
  attestation accepted under the verifier's own recorder trust list**
  ("Recorder attestation" there): a signed statement, by a key the verifier trusts,
  over these exact trace bytes. It does not show the recording is physically true or
  that the machine is safe. Without one a re-verification clears no entry by itself
  and a `decider` operator waives it; **a waiver is still a waiver**, recorded as one
  and never read as current. The tier is read the way the public bundle checker reads
  it, not from the stored word: `VerificationRecord.from_ledger` takes a sealed
  `validated` as `validated` only when the body is engine 6 or later, its
  `provenance_basis` is `recorder_attested` **and** the accepted attestation is
  recorded beside it; given the reader's own trust list
  (`from_ledger(..., recorder_trust=)`) it also re-assesses that attestation, so a
  revoked key stops supporting the tier. An engine-4 or engine-5 `validated` bundle
  already in a ledger, or a resealed body that only says `recorder_attested`, is read
  as `community`; and
- `assess_coverage` reads the function `current`.

An entry that fails stays required, with the reason (`stale`, `unknown`,
`no_new_evidence`, `below_validated:<tier>`, …) in `evidence_current`. A function the manifest no longer
declares stays required.

**A 200 from `reverify` means the submission was recorded, not that it cleared
anything.** While the case still awaits re-verification the result carries a
`blocked_reason` (`assurance.change.service.blocked_reason`, derived from the case's
own `evidence_current`): `code` is `below_validated_tier` (the evidence is under the
`validated` floor, which is every trace-derived verification today) or
`evidence_not_current` (coverage does not read the entry current at all), with
`tier_floor`, the `entries` and the reason per entry, and a sentence saying that a
recorder attestation is what would lift the cap and that a `decider` operator may
waive. The HTTP route returns it beside the case, the CLI prints `blocked: <code>`
and the sentence and **exits 3** (`assurance change reverify` exits 0 only when the
case has nothing left to re-verify; 3 means "recorded, not cleared", the same code
`assurance evidence verify` uses for "nothing wrong found, but something asked for is
not established", and 1 stays "refused": a script reading `$?` cannot take an
uncleared case for a cleared one), the MCP tool
relays the route's body, and `/assurance` shows the same sentence under the case. The
key is absent when nothing is blocked.

**Every function an advisory reaches needs evidence** — not only those that were
current until now. A function that was never verified or was already stale is
not supported by anything either, so it is on `required_reverifications` too.
The one way to close without evidence is `waive-reverification`: a named person,
a reason, the entry kept in `resolved_decisions` and read as `waived` (never
`current`) in `evidence_current`.

A case with an open `human_decisions_required` (a contradictory or low-confidence
advisory match, or a supplier withdrawal) goes to `awaiting_action` after
re-verification, not `ready_to_close`. A person answers each question with
`resolve-decision`; the answer is kept in `resolved_decisions`, and a later
look at the same advisory does not ask it again. Without that, such a case could
only ever be rejected or deferred.

`advance()` still does not check that an action was *done* — nothing in this
codebase observes a person doing paperwork. It checks that the work lists the
engines produced are empty where they should be.

## Persistence and reconstruction

No case table. Every transition is sealed as its own `Evidence` object in the
same hash-chained `EvidenceLedger` everything else in this product writes to,
under `subject=case_id`, carrying a full snapshot of the case at that point.
Kinds: `opened`, `updated`, `transition`, `reverification`, `decision`,
`reopened`.

`assurance.change.replay.reconstruct_case(ledger, case_id)` (CLI:
`assurance change replay`) rebuilds a case's current state **from the ledger
alone** and replays every step against the state machine. It verifies each
entry's sealed evidence and the chain, and reports — by ledger sequence number —
any entry that: does not verify; makes a move its kind of entry cannot make
(e.g. `open -> closed`); records `ready_to_close`/`closed` with work outstanding;
rewrote the case's history rather than appending; altered a prior closure;
removed required work on an entry that cannot remove it (only a
`reverification`, a person's recorded resolution or waiver, or a reopening can;
a repeat observation never can); is a `reverification` that cites
no `supports` evidence, or evidence that is not a sealed verification, was
sealed before the case's current cycle, or is for a machine the case does not
concern; is sealed as a different kind than the ledger files it under;
changed the trigger; or records a decision by something that is not a named
person. It reports; it does not repair. `replay.case` equals `CaseStore.get`
whenever every entry verifies. This is what "reconstructable from the
authoritative record" means here, as a function that can fail.

**A ledger that does not verify shows no case and takes no write.** The store
skips an entry whose sealed evidence no longer verifies, which is right for a
replay that reports it and wrong for a screen: a case whose newest entry was
edited would read as the state before the edit. So `CaseStore.require_intact()`
runs before every write and before every read an interface presents as the case:
HTTP answers `500 {"error": "ledger_integrity"}` (also from `POST
/v1/watch/report`, which records nothing onto a broken chain) and the CLI prints
`THE LEDGER CHAIN DOES NOT VERIFY` to stderr first, prints nothing to stdout and
exits 2. `replay` and `export` keep their own behaviour (a report of the
violations; a refusal), and both always walk the whole chain.

**The check is incremental, and what that costs in detection.** A full walk is
~55 microseconds per record (1 s at 20 000), too much for every request, so
`EvidenceLedger.verify_cached()` (`assurance/evidence/chain_cache.py`) remembers
per ledger file (resolved path + inode + device, so replacing the file
invalidates it) the head a full walk verified, and on each call (a) re-reads that
head record and confirms it is unchanged and still hashes, which catches
truncation, a rewind and a replacement at the head, and (b) verifies completely
every record appended since, which catches garbage appended after the head.
Measured on a 20 000-record ledger on a loaded machine: a full walk 1.9-2.5 s;
the incremental check 1.0 ms unchanged and 2.4 ms after 5 appends. The
trade-off, plainly: **an in-place edit of an *old* record by someone with write
access to the database file is seen at the next full pass, not on every read.**
A full pass happens at the first check in each process, whenever the last one is
older than `ASSURANCE_CHAIN_RECHECK_SECONDS` (default 60; `0` = every check is a
full walk), and on every `verify_chain` (export, replay, `GET /v1/ledger/verify`,
fleet reads). An incremental pass never extends the age of the full pass it rests
on, a failure is never remembered as a pass, and a failing full walk forgets the
cache. The cache is per process. A chain rebuilt to be self-consistent is caught
by neither kind of pass; that is what a signed head attestation
(`assurance attest`) is for.

Two guards sit on top of that. **Human decisions never use the cached check:**
`decide` (close / reject / defer), `resume`, `resolve-decision` and
`waive-reverification` walk the whole chain before they seal, so an in-place edit
inside the window is refused at the moment a person is about to rely on the case.
And **a case write is a compare-and-swap**: `CaseStore.get` remembers the
ledger position of the newest entry of the case, and the append is refused
(`CaseConflictError`, HTTP 409 `case_conflict`, CLI `finding:`, nothing written)
inside the ledger's own write transaction if another writer has appended to that
case since, so a close can never land on top of a move made after the person
read the case. Machine-driven writers (assess, watch ingest, advisory
withdrawal) re-read and recompute instead; people are told and decide again.

## Exporting a case: completeness and the anchor

An export is internally consistent: its chain recomputes. That does not show that
nothing was removed. Three things decide what a verifier can say:

* **`skeleton`** (off by default; `?skeleton=true`, `--skeleton`): lists the
  position, kind, subject and time of every *other* entry of the account's ledger,
  so a verifier can see a removed entry. It discloses those to whoever receives the
  file, which is why it is opt-in. Without it completeness is `not_checked`.
* **`anchor`**: a signed head attestation the verifier checks under the signer's
  public key, which it must obtain elsewhere. Records after the anchor are covered
  by no signature.
* **Who made the anchor.** The hosted export embeds the newest attestation the
  service *read from the account's own ledger* (`read_from_ledger`). **No customer
  route creates one**: only the operator, with `assurance attest sign` against the
  hosted ledger (procedure in `ATTEST.md`, section 3). The `declared_by_holder`
  records a customer writes with `POST /v1/ledger/attest` describe the customer's
  own ledger and are never embedded. So until the operator has signed an account's
  ledger, its exports carry no `anchor` and their completeness is not checked;
  do not tell a customer otherwise.

Refusals are part of the contract (`public/openapi.json`):

| status | body `error` | meaning |
|---:|---|---|
| 401 / 402 | | no key / the plan does not include export |
| 404 | `case_not_found` | the ledger holds no entry of a case kind under this id |
| 409 | `anchor_contradicts_ledger` | the embedded attestation does not match this ledger (shorter, or another history at a signed position): a rewind signal, nothing exported. `?anchor=false` exports without it and does not make the finding go away |
| 500 | `ledger_integrity` | the account's chain does not verify |
| 500 | `attestation_log_damaged` | the attestation log cannot be read, so the anchor cannot be chosen; the export is refused, never silently unanchored |

The CLI (`assurance change export --attestations LOG`) and the API choose the
anchor with one rule (`assurance.attest.select_anchor`): the newest
`read_from_ledger` record. A log of only declared heads is accepted on the CLI
because a person named it; the bundle's `anchor.basis` says `declared_by_holder` and
the CLI says the head was declared and not read from the ledger.

## Surfaces

```
assurance change assess-drift | assess-advisory | assess-intervention
                 list | show | claim | advance | reverify
                 resolve-decision | waive-reverification | decide | resume
                 replay | export

POST /v1/change/assess/drift                       {baseline, observed, actor?}
        # the baseline is the newest manifest the account's ledger holds for the
        # machine in another configuration; the body's is used only if none is
        # sealed. The response says which (baseline_source: ledger | request).
POST /v1/change/assess/advisory                    {advisory, actor, accept_unsigned?, reason?}
        # actor must name a person for an advisory handed over as a body; an
        # unsigned import also needs accept_unsigned (409 otherwise).
POST /v1/change/assess/intervention                {manifest, intervention_id, actor?}
GET  /v1/change/cases[?status=]                    {cases: [row], summary}
GET  /v1/change/cases/{case_id}
GET  /v1/change/cases/{case_id}/export[?skeleton=][&anchor=]
        # a bundle `assurance evidence verify` checks. See "Exporting a case" below.
GET  /v1/change/cases/{case_id}/replay             the case rebuilt from the ledger alone
POST /v1/change/cases/{case_id}/claim              {owner, actor}
POST /v1/change/cases/{case_id}/advance            {actor}
POST /v1/change/cases/{case_id}/reverification     {manifest, verification_content_hash, actor}
        # 200 = recorded. `blocked_reason` is present while the case still waits (see above).
POST /v1/change/cases/{case_id}/resolve-decision   {decision, resolution, actor}
POST /v1/change/cases/{case_id}/waive-reverification {entry, reason, actor}
POST /v1/change/cases/{case_id}/decision           {disposition, reason, actor}
POST /v1/change/cases/{case_id}/resume             {reason, actor}
```

Cell-tier only — see `deploy/assurance/ADR-0002-change-assurance.md` for why
no new plan was added. 401 with no or an invalid key, 402 when authenticated but
not entitled, always from the account's own ledger.

MCP tools (exactly these): plans, capabilities, spec_validate, machine_verify, machine_check, evidence_verify, machinery_coverage, machinery_passport_check, fleet_report, register_cases, services, machine_assurance_check, fleet_machine_assurance, change_cases, change_case, change_export, change_claim, change_advance, change_reverify, change_assess_drift, change_assess_intervention

The change tools are thin relays to the routes above, with no local logic:
`change_cases`, `change_case` and `change_export` read; `change_claim`,
`change_advance`, `change_reverify`, `change_assess_drift` and
`change_assess_intervention` write. The two assess tools open a case from a machine's
own manifests; there is **no tool that assesses an advisory** (third-party content: a case
opened from an unsigned one is the attack the signed feed exists to stop). There is **deliberately no MCP
tool for `decide`, `resume`, `resolve-decision` or `waive-reverification`** (nor
for closing, rejecting or deferring): the MCP server is the surface an agent
drives, and those are the decisions an agent must not make.
`tests/test_interfaces_mcp.py` fails if a tool is added without this line being
updated, and shows from the outside that no tool, whatever it is passed, reaches
those routes (case ids are percent-encoded as one path segment).

CLI, API and MCP call the same `assurance.change.service` functions, and the
parity tests (`tests/test_interfaces_*.py`) run one sequence through the
library, the command line, the HTTP API and the MCP read tools and compare.
What is the same on every interface:

| | |
|---|---|
| unknown case id | HTTP `404` `{"detail": {"error": "case_not_found", "case_id"}}` on every verb; CLI exit `2` on every verb (`show`, `claim`, ..., `replay`, `export`). The Article 14 register's `GET /v1/cases/{id}/export` and `art14 export` answer the same way (they used to export an empty bundle) |
| a refused transition (wrong state, non-person actor on a decision, nothing outstanding) | HTTP `409` with the domain sentence; CLI exit `1`, `finding: ...` on stderr |
| invalid input | HTTP `422`; CLI exit `2` |
| the actor rules (`_require_human`), the waiver and resolution rules | one implementation, in the service; no interface re-implements them |
| the queue | `GET /v1/change/cases` and `assurance change list --json` print the same document: `cases` (rows) and `summary` (`open`, `safety_relevant`, `awaiting_reverification`, `ready_to_close`, `degraded`, `deferred`, from `queue_summary`) |

What is **intentionally different**, so nobody mistakes it for a bug:

- `assurance change list` (the table) prints the work queue: open cases only,
  plus a count of deferred ones, and exits `1` while any case is open (a cron
  job can alert on it). The API and `list --json` return every case, or those
  with `status`; `open` in the summary never includes deferred cases.
- A command line with no `--actor` runs as automation: it may claim, advance and
  reverify, and is refused (`exit 1`) on `decide`, `resume`, `resolve-decision`
  and `waive-reverification`. The HTTP API requires a non-blank `actor` on every
  write that moves a case (`422` otherwise), because the hosted record names
  both the person and the account that vouched for them. `assess/*` may omit it
  (recorded as automation).
- `resolve-decision`: the CLI takes `--number` (position as `show` lists it);
  the API takes `decision`, the question's exact text, so a position that moved
  because someone else answered a question cannot answer the wrong one.
- The API records `role` as "reviewer via account <id>"; the CLI records the
  role only.
- A verification only counts as evidence for a unit when it is filed under the
  machine's key. `assurance machine verify --subject <manufacturer/model#serial>`
  and `POST /v1/machine/verify {"subject": ...}` do that (without it a bundle is
  filed under `product@version`, a product line, and `reverify` will not find
  it). The API response carries the hash to cite as `content_hash`.

**Reserved case fields.** `reviewer` and `last_valid_verification` exist on the
model but nothing sets them (the owner claims; several people may advance,
resolve or waive, each recorded in `history` and `resolved_decisions`), so they
are not emitted by the API, `show --json` or the text view while empty. They are
not data; do not build on them.

## What is not solved here

- **The hosted API does not run the watch.** `assurance watch run` runs where
  the exports are — in the customer's kit, from cron — against the customer's
  ledger. The API serves, and lets a person work, the cases that ledger holds;
  it never collects from a machine. A customer may opt in to *report* a run to
  their own hosted ledger with `assurance watch push` (see `WATCH.md`); the
  hosted side then opens cases through the same `assess_drift`.
- **The workspace is a client of the API.** `/assurance` (the Next.js app)
  calls the routes above with the caller's own key; the CLI queue
  (`assurance change list`) is the offline equivalent.
- **No "action completed" tracking.** See above.
- **Re-verification needs a newer bundle, and that is a choice.** A bundle that
  genuinely describes the machine after the change, but was sealed before the
  watch first saw the change, is refused; run the checks again.
- **A crash between the case and the new manifest can leave one orphan
  divergence entry.** The next run re-detects the drift, lands on the same case
  and seals a fresh divergence; the earlier one, if it was sealed before the
  crash, stays in the ledger. The case is never duplicated or lost.
- **A withdrawn advisory only becomes a question to the owner.** If the case is
  already closed, nothing is raised.
- **A change made and reverted between two watch runs** leaves no trace, and so
  no case. The watch compares against the last sealed manifest.
- **Identity.** Hosted decisions are attributed to an authenticated operator
  credential, not an identity-proofed person; CLI/open-mode actors are declared
  names. See "Who does what".
