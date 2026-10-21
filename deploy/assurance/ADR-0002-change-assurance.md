# ADR-0002: Continuous Machine Change Assurance — a case, not a new plan

**Status:** Accepted, shipped; amended by the S2 addendum. **Date:** 2026-09-27.

## The problem

HANDOFF.md and this repo's own README describe a product built entirely out
of point-in-time answers: a divergence report, a coverage report, an impact
report, an intervention record. Each is correct and each is silent about what
happens next. A customer who runs `assurance machinery coverage` on Monday and
sees `SF-01: STALE` has no record that anyone was told, no owner, no way to
tell a colleague "this one is being handled," and nothing that says the
matter was ever closed rather than merely forgotten. That gap is not a missing
feature of any one engine — every engine already does its own job correctly —
it is a missing layer above all of them.

## Why this, and not a bigger rebuild

The obvious wrong move was a generic case-management or ticketing system:
free-text status, arbitrary fields, an LLM summarising "what to do next."
That would have been faster to build and worth less, for the same reason the
rest of this codebase refuses free-text compliance language: a status a human
typed is not evidence, and a next-action an LLM invented is not something a
notified body can rely on. `ChangeAssuranceCase` instead has exactly the
states the underlying engines can justify, and every field describing the
machine or its evidence is copied from an engine's own output — see
`deploy/assurance/CHANGE.md`.

## Why no new plan

The Cell plan already includes machine verification, Annex III manifests and
coverage, and fleet advisory fan-out — the three engines a case is built from.
Selling "the workflow on top of the thing you already bought" as a separate
SKU would be exactly the kind of unpriced fragmentation this codebase's own
pricing doctrine refuses ("if it is not gated in code, it is not on the
pricing page" cuts both ways: gating something *new* behind a *new* price
with no market evidence that a buyer would pay it separately is the same
mistake in reverse). `/v1/change/*` is gated behind the existing `Machine`
dependency (`require_machine`, Cell-tier), the same door as `/v1/machine` and
the coverage half of `/v1/machinery`. No Stripe price was added; none was
needed.

## What was NOT done in this cycle, and why

- **Watch integration — done in slice S2 (see the addendum below).**
  This cycle shipped the case layer alone, so that the watch's own test suite
  stayed the safety net for the watch's behaviour.
- **A rendered UI.** The customer-facing surface shipped this cycle is the
  CLI queue and the JSON API. `src/dashboard` (Next.js) is not touched;
  `ROADMAP.md` already lists "dashboard integration with the assurance
  product" as not started, for the product as a whole, not only for this
  feature. Building a dashboard page against an API that had not yet been
  designed would have meant guessing the API's shape twice.
- **No pricing experiment.** Section 17 of the brief this ADR responds to
  asks what a customer would pay for continuous assurance specifically. No
  evidence was gathered this cycle to answer that (no customer conversation,
  no pilot) — reusing the Cell boundary is the only claim this ADR makes, and
  it is a claim about *where this fits*, not about *what it is worth
  separately*, which remains as unproven as every other price in this
  codebase (see HANDOFF.md §4.4).

## Tests

`tests/test_assurance_change.py` — 19 tests: the domain lifecycle over real
`compare()`/`assess_coverage()`/`assess_impact()` output (not fixtures
invented for this file — the manifest/intervention/advisory builders are
copied from `test_assurance_machinery.py` and `test_assurance_fleet.py`), the
CLI end to end, and the HTTP surface including the 402 boundary and the 409 a
premature `decide(..., "closed")` produces. `tests/test_assurance_mcp.py`
extended to cover the two new tools.

## Addendum (S2): the watch keeps the cases

`assurance watch run` now opens and updates cases itself: material drift,
advisories that are `new` or `outstanding`, and recorded interventions that
invalidated evidence. Decisions taken, and why:

- **No second lifecycle, no new table.** The runner calls the same
  `assess_drift` / `assess_advisory` / `assess_intervention`. The only new
  persistence is one more ledger kind, `assurance.change.reopened`.
- **Case first, manifest second.** The manifest the runner seals becomes the
  next run's baseline. Sealing it before opening the case let a crash between
  the two hide the drift for good. Opening first makes a crash recoverable —
  the next run re-detects and lands on the same case — and both orders of
  failure are tested.
- **A repeat observation writes nothing unless it differs**, and a case past
  review is merged additively, never re-inflated. Previously every re-look
  appended an `updated` entry and overwrote the work lists.
- **Explicit reopen/resume rules** (table in CHANGE.md): a closed drift case
  reopens only when the ledger shows the machine left that configuration after
  the closure and returned; a closed advisory only for a machine it did not
  name; rejected stays rejected, a new trigger id is a new case; deferred has a
  `resume`. The closure entry is never altered.
- **Only a named person decides.** `decide`, `resume` and `resolve_decision`
  refuse any actor whose `kind` is not `person`, in the domain layer, so the
  CLI, API and MCP inherit it. The watch is `automation`. Limit: the kind is
  set by the caller; the hosted API cannot prove a supplied name is a human.
  The MCP server exposes no deciding tool for that reason.
- **Failing to observe is not progress.** An uncollectable machine leaves its
  cases exactly where they are and names them in the run.
- **Reconstruction is a function that can fail** (`reconstruct_case`), not a
  claim.

Still not done: the hosted API does not run the watch (it runs in the
customer's kit or cron); no dashboard; no completed-action tracking; function
ids are not machine-qualified within a multi-machine advisory case; API routes
for `resume`, `resolve-decision` and `assess-intervention` do not exist.

Tests: `tests/test_assurance_watch_cases.py` (real-engine end to end, crash
window, reopen over the watch, signed-feed advisory path, uncollectable
machines, interventions) and the S2 classes in `tests/test_assurance_change.py`.
