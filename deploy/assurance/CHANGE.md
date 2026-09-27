# Continuous Machine Change Assurance

CHANGE -> IMPACT -> REQUIRED ACTION -> RE-VERIFICATION -> HUMAN DECISION ->
EVIDENCE-BACKED CLOSURE.

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

## The three triggers

| Trigger | Built from | Opens a case when |
|---|---|---|
| Machine drift | `Divergence` (from `compare()`) + `CoverageReport` | `verdict == "safety_relevant_drift"` |
| Supplier advisory | `ImpactReport` (from `assess_impact()`) | `verdict != "clear"` |
| Intervention | `Intervention` + `CoverageReport` | the intervention invalidated at least one function's coverage |

One case per distinct trigger — a repeat observation of the same drift or the
same advisory updates the existing open case rather than opening a duplicate;
see `assurance.change.service._case_id` and `_open_or_update`.

## The lifecycle

```
OPEN -> IN_REVIEW -> AWAITING_ACTION -> AWAITING_REVERIFICATION -> READY_TO_CLOSE -> CLOSED
                  \-> REJECTED / DEFERRED (from any open status)
```

`claim()`, `advance()`, `reverify()` and `decide()` in
`assurance.change.service` are the only ways a case moves. `advance()` never
guesses which stop is next — it reads the case's own `required_actions` and
`required_reverifications`, which were computed by an engine, not typed in by
whoever opened the case. `decide(..., disposition="closed")` is refused
outside `READY_TO_CLOSE`, no matter who calls it.

## Persistence

No case table. Every transition is sealed as its own `Evidence` object in the
same hash-chained `EvidenceLedger` everything else in this product writes to,
under `subject=case_id`, carrying a full snapshot of the case at that point.
Reading a case is "take the last verifying entry for this subject" — see
`assurance.change.store.CaseStore`. This means a case's history is exactly as
tamper-evident, exportable and reconstructable as a machine passport already
is, because it is the same ledger.

## Surfaces

```
assurance change assess-drift | assess-advisory | list | show | claim | advance | reverify | decide

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
no new plan was added. MCP: `change_cases`, `change_case` — thin wrappers over
the same routes, no local simulation, matching every other tool in
`assurance.mcp.server`.

## What is not solved here

- **No watch integration yet.** `assess_drift`/`assess_advisory` take the
  exact objects `compare()`/`assess_impact()` already produce; wiring
  `assurance.watch.runner` to call them automatically on every run — so a
  case opens without anyone running `assess-drift` by hand — is the next
  piece, not this one.
- **No dashboard.** The customer-facing surface today is the CLI queue
  (`assurance change list`) and the API's `GET /v1/change/cases`. A rendered
  `/assurance` page in `src/dashboard` does not exist; `ROADMAP.md` already
  says dashboard integration with the assurance product broadly is not
  started, and this does not change that.
- **No "action completed" tracking.** `advance()` moves a case off
  `AWAITING_ACTION` on the caller's say-so; nothing here checks that a
  required action was actually done, because nothing in this codebase
  observes a human doing paperwork.
