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

**What that does and does not prove.** "Named person" means *a name declared by
an authenticated account holder*, not an identity-proofed human. The kind and
name are set by the layer that calls the domain function; the CLI and the hosted
API set `person` when an actor name is supplied, and neither can authenticate
that the name belongs to a human — the API's principal is an account, not a
person. An agent given an API key and told to pass `"actor": "v.grimaldi"`
would be accepted. The MCP server therefore exposes no tool that decides (see
Surfaces), but a deployment that wants more than this has to put identity in
front of the API itself.

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

## A repeat observation, a recurrence, and what each does

One case per trigger: `_case_id` is a hash of `(trigger_type, trigger_id)`,
where the id is the observed configuration hash (drift), the advisory id, or
the intervention id. What happens when the same trigger is seen again is
decided by the case's state, in `assurance.change.service._open_or_update`:

| Existing case | A repeat observation of the same trigger | Ledger |
|---|---|---|
| none | open it | 1 `opened` entry |
| `open`, or `in_review` with nothing re-verified | replace the facts and work list with the fresh reading (no progress to protect) | an `updated` entry **only if something differs** |
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
- that bundle passed **every** check the function declares; and
- `assess_coverage` reads the function `current`.

An entry that fails stays required, with the reason (`stale`, `unknown`,
`no_new_evidence`, …) in `evidence_current`. A function the manifest no longer
declares stays required.

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
`reverification`, a person's recorded resolution or waiver, a fresh reading
before any work started, or a reopening can); is a `reverification` that cites
no `supports` evidence, or evidence that is not a sealed verification, was
sealed before the case's current cycle, or is for a machine the case does not
concern; is sealed as a different kind than the ledger files it under;
changed the trigger; or records a decision by something that is not a named
person. It reports; it does not repair. `replay.case` equals `CaseStore.get`
whenever every entry verifies. This is what "reconstructable from the
authoritative record" means here, as a function that can fail.

## Surfaces

```
assurance change assess-drift | assess-advisory | assess-intervention
                 list | show | claim | advance | reverify
                 resolve-decision | waive-reverification | decide | resume | replay

POST /v1/change/assess/drift
POST /v1/change/assess/advisory
GET  /v1/change/cases
GET  /v1/change/cases/{case_id}
POST /v1/change/cases/{case_id}/claim
POST /v1/change/cases/{case_id}/advance
POST /v1/change/cases/{case_id}/reverification
POST /v1/change/cases/{case_id}/decision
```

Cell-tier only — see `deploy/assurance/ADR-0002-change-assurance.md` for why
no new plan was added.

MCP: `change_cases`, `change_case` (read), and `change_claim`, `change_advance`,
`change_reverify` (thin relays to the routes above, no local logic). There is
**deliberately no MCP tool for `decide`, `resume` or `resolve-decision`**: the
MCP server is the surface an agent drives, and those are the decisions an agent
must not make.

CLI, API and MCP call the same `assurance.change.service` functions. Known
divergences, not fixed here: an unknown case id is `404` on `GET
/v1/change/cases/{id}` but `409` on every `POST` (the service raises
`CaseTransitionError`, which the routes map to 409); and the API has no route
yet for `resume`, `resolve-decision` or `assess-intervention` — those are CLI
and watch only.

## What is not solved here

- **The hosted API does not run the watch.** `assurance watch run` runs where
  the exports are — in the customer's kit, from cron — against the customer's
  ledger. The API serves, and lets a person work, the cases that ledger holds;
  it never collects from a machine. A customer may opt in to *report* a run to
  their own hosted ledger with `assurance watch push` (see `WATCH.md`); the
  hosted side then opens cases through the same `assess_drift`.
- **No dashboard.** The customer-facing surface today is the CLI queue
  (`assurance change list`) and the API's `GET /v1/change/cases`.
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
- **Identity.** "Named person" is a name declared by an authenticated account
  holder. See "Who does what".
