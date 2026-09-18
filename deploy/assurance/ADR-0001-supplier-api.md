# ADR-0001: A hosted API for supplier advisories

**Status:** Accepted, minimal implementation shipped. **Date:** 2026-09-19.

## The problem

HANDOFF.md §5 P1 names this precisely: `assurance supplier` is CLI-only.
There is no `/v1/supplier/*` route, no hosted feed, no plan entitlement, no
discovery. A component supplier — the second class of buyer this product
could have, distinct from the manufacturers and integrators who buy
Register/Cell — cannot pay us today even if they want to, because there is
nothing to buy.

## Why a supplier is a different customer

The manufacturer/integrator side sells evidence *about a fleet you own*.
The supplier side would sell *reach*: one signed advisory, discoverable by
every integrator who enrolled a machine using that component. The value is
network effect, not per-seat access — HANDOFF.md's own §4.3 names this as
one of the three things that are not copyable ("a supplier publishes one
signed advisory; every integrator with that component enrolled here learns
which serial numbers it touches").

## What we did NOT do, and why

**We did not invent a price.** There is no Stripe price for a Supplier tier,
and doctrine is explicit: no fabricated euros. The `supplier` entry in
`PLANS` (`src/assurance/billing/plans.py`) has `price_label="Contact sales"`
and is deliberately excluded from `public_catalogue()` — `GET /v1/plans`
still returns exactly the three cards the marketing site renders. Granting
the entitlement today is a manual, sales-assigned account-tier change, not a
checkout flow.

**We did not build a hosted signing service.** `assurance supplier publish`
already signs locally with a key that never leaves the supplier's machine —
correctly: a service that held suppliers' private keys would be a much
larger liability than the problem it solves, and would contradict the whole
model's premise (a key checked only against what it signs proves nothing
about who holds it). The API accepts an **already-signed** record — the
supplier runs the same signing step they always would, then POSTs the
resulting JSON here to be hosted instead of self-hosting a file.

**We did not re-implement the feed invariants.** `POST /v1/supplier/advisory`
loads the body through `SignedAdvisory.from_dict` (the exact structural
validation the CLI and `verify_feed()` use) and re-checks the same
continuity rules `assurance.supplier.publish._next()` enforces: one feed
belongs to one `supplier_id`, sequence numbers are contiguous, `previous`
matches the current head's content hash, and an `advisory_id` cannot be
republished. Getting this wrong would mean the hosted feed and a
self-hosted file behave differently under the same input, which is exactly
the kind of drift the rest of this codebase refuses to allow.

## What is shipped

- `POST /v1/supplier/advisory` — gated behind the `supplier_publish`
  entitlement (`require_supplier` in `deps.py`, same 401/402 pattern as
  `require_machine` and `require_attestation`). Appends a validated,
  chain-consistent signed record to `<ASSURANCE_SUPPLIER_FEEDS>/<account_id>.jsonl`.
- `GET /v1/supplier/feed/{account_id}` — free, no account, forever. Serves
  the raw NDJSON feed. The audience for a supplier's advisory is every
  integrator who might be affected, not a paying subscriber — same reasoning
  as every other free-forever verification route in this product.

Feeds are keyed by the server-issued account id, not the supplier-chosen
`supplier_id` string inside the advisory — the account id is already a safe
token, so this sidesteps trusting a customer-chosen string as a filename or
URL path segment.

## What is explicitly NOT solved by this ADR

- **Discovery.** An integrator still has to know an account id to subscribe
  to a feed. A directory (something like `GET /v1/supplier/directory`) is
  future work, not shipped here.
- **Feed sync into the watch engine.** `assurance.watch` still reads a local
  file; wiring it to poll a hosted feed via HTTP is a separate, real piece of
  work (HANDOFF.md P1 item 5, "feed sync").
- **A real price.** Someone has to decide what a supplier tier costs, sell
  it, and only then does a Stripe price and a self-serve checkout path make
  sense. This ADR unblocks that decision; it does not make it.

## Tests

`tests/test_assurance_supplier_api.py` covers: unauthenticated →401,
authenticated-without-entitlement →402 (never 403 — the obstacle is
payment, matching every other gate in this codebase), an unsigned record
→422, a first record establishing a feed →201, sequence/identity/chain
violations →409, and reading a feed that does not exist →404. Every failure
mode fails closed; nothing here defaults to permissive.
