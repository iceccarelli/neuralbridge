# NeuralBridge AI — Commercial Map

Who pays for what, and what must stay free. Source: `src/assurance/billing/plans.py`
(the single entitlements table), `docs/pricing.md`, `README.md`, `deploy/assurance/ADR-0001-supplier-api.md`
(referenced, not fully read this pass). `app/checkout/success/page.tsx` and
live Stripe status are **[LIVE-SITE: UNVERIFIED]** — network to neuralbridge.io
is blocked from this session, and `app/status/page.tsx`'s own checklist
(all ops items `done: false`) indicates the product is not yet deployed
regardless.

## The three public tiers (plus one non-public)

| Tier | Price | Gated capabilities (`Plan` fields, all enforced in `deps.py`) | Daily quotas |
|---|---|---|---|
| **Validator** (`free`) | free | Everything free-tier: Art.14 draft spec validation, ISO/TS 15066 separation calculator, manifest diff, advisory check, Declaration check, bundle re-verification, attestation verification, offline enrolment kit | `validations_per_day=20`, `separations_per_day=20`, `diffs_per_day=10` |
| **Register** (`register`) | €390/mo | `register=True` — Article 14 register for one manufacturer: unlimited cases, both deadline clocks, hash-chained ledger with verifiable export, 25 product families | `cases_per_day` per plan config |
| **Cell** (`cell`) | €1,290/mo | Everything Register plus `machine_verification=True` (ISO/TS 15066 safety-envelope verification), Annex III manifests/passports, fleet advisory fan-out, Declarations bound to a configuration hash, `signed_attestation=True` (counter-signed head attestation) | inherits Register's, plus machine-verification volume (not fully enumerated in this pass) |
| **Supplier** (`supplier`, not in `public_catalogue()`) | sales-assigned, no self-serve Stripe price | `supplier_publish=True` — publish signed advisories to a hosted feed via `POST /v1/supplier/advisory`. Per the code comment, this is "the second payer HANDOFF.md's P1 names — a component supplier, not a manufacturer." Deliberately excluded from the public pricing table pending ADR-0001. | n/a |

## What is free forever, by explicit design

`README.md`'s own framing: *"Verification is free at every tier and always
will be: the audience for a piece of evidence is a regulator, an insurer or
a customer's-customer, none of whom will ever hold an API key here. Evidence
only a paying customer can check is worth nothing."* Concretely, per
`plans.py`'s per-route docstring comments, verification-side routes are
**deliberately kept outside the entitlement gates** even though they sit
next to gated write routes:
- The separation calculator and the bundle re-checker are outside the
  `machine_verification` gate (only the write side — sealing a new
  verified bundle — is Cell-gated).
- The verification side of attestation is outside the `signed_attestation`
  gate (only *signing* a new attestation is Cell-gated; *verifying* an
  existing one is free).
- `GET /v1/plans` itself is free, no key, and — per the README — generated
  live from the same `PLANS` table the API enforces, so the pricing page
  cannot drift from what's actually gated.

## Enforcement mechanism (why this table is trustworthy)

`plans.py`'s own docstring states the rule the rest of the codebase is
built to: **"If it is not gated in code, it is not on the pricing page. A
feature list that the software does not enforce is marketing."**
Concretely:
- `Plan.purchasable` is derived from whether a Stripe price env var
  (`price_env`) is actually set — a plan with no price configured cannot be
  bought, rather than silently appearing purchasable.
- `Plan.to_public_dict()` is the literal payload `GET /v1/plans` returns —
  there is no separate marketing-copy pricing table to drift from this one.
- Entitlement checks in `api/deps.py` (`require_register`,
  `require_machine`, `require_attestation`, `require_supplier`) read
  `principal.plan.<field>` directly off this same `Plan` dataclass and
  return **402 Payment Required** (not a vague 403) when a caller is
  authenticated but under-tiered — naming the actual blocker.

This is real, and it's the pattern any Phase 1 entitlement-awareness
requirement should imitate rather than reinvent: **Phase 1's `/ai` agent
must read entitlements from this same `PLANS`/`deps.py` mechanism, not
introduce a second, parallel notion of what a plan includes.**

## What must stay free (and therefore out of scope for Phase 1 gating)

Per the design above, none of the following should ever require a paid
plan, and Phase 1's agent orchestrator must not accidentally gate them
behind an entitlement check that doesn't already exist in `deps.py`:
- `GET /v1/plans`
- `POST /v1/spec/validate`
- ISO/TS 15066 separation calculation
- manifest diff / bundle re-verification / attestation verification
- the offline enrolment kit (`assurance kit check` / `kit run`, entirely
  local, no account needed at all)

## What is currently unpriced / not gated (platform side)

The `src/neuralbridge/` half of the repo — connections, adapters, the MCP
gateway — has **no billing or entitlement concept at all**. There is no
`Plan`/tier notion for adapter usage, connection count, or MCP tool calls
anywhere in `src/neuralbridge`. This is consistent with the platform
README's own framing (a narrower, currently-free integration layer) but it
means Phase 1 must decide explicitly whether the new `/ai` surface:
(a) stays entirely free/ungated (simplest, matches current platform
reality), or (b) introduces its own entitlement concept for AI-agent usage
of the platform. Given the brief's requirement that the agent be
"entitlement-aware: cannot bypass paid gates," and given that the *only*
paid gates that exist today live in `src/assurance/`, the honest Phase 1
scope is: the `/ai` agent must respect `src/assurance` gates when it
touches assurance capabilities, and platform-side capabilities (the
PostgreSQL read) remain ungated because nothing gates them today — not
because Phase 1 invented a new gate for them.

## Billing plumbing present but not confirmed live

- `billing/stripe_gateway.py` and `billing/accounts.py` exist and are
  referenced consistently from `deps.py`/`billing_routes.py` (not read in
  full this pass).
- `DEPLOY_NOW.md` documents the exact Stripe secrets (`sk_live_...`,
  `whsec_...`, `price_...`) that must be set on Fly.io for checkout to
  work, and frames this as an unexecuted runbook step ("Set the Fly
  secrets... Replace `REPLACE_*`... no other code change is needed").
- `app/status/page.tsx`'s checklist (Fly secrets set / Stripe webhook
  registered) is `done: false` as checked into the repo.
- **Conclusion: live billing is not yet confirmed active.** Do not state or
  imply in any Phase 1 deliverable that checkout/billing is live —
  `app/checkout/success/page.tsx` exists in code but its live behavior is
  unverified, and the repo's own ops checklist says the prerequisites
  aren't done yet. This matches the task brief's explicit prohibition on
  "live billing claims" for Phase 1.
