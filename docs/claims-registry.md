# Claims registry

Every public commercial claim, mapped to the code that enforces it. The rule
(from `src/assurance/billing/plans.py`): **if it is not gated in code, it is not
on the pricing page.** A row marked `NOT ENFORCED — removed` is a claim this
site used to make and no longer does.

Verified by reading `src/assurance/billing/plans.py` and
`src/assurance/api/deps.py` (plus the route modules named below), as they exist
after the backend change that removes `cases_per_day` and `product_families`.
Public wording lives in `app/lib/plans.ts` (copied from `plans.py`), the
homepage, `README.md`, `docs/index.md`, `docs/pricing.md` and `public/llms.txt`.

## Enforced claims

| Public claim | Tier | Enforced at |
|---|---|---|
| Article 14 draft validation, free, 20 a day per address | Validator | `plans.py:PLANS["free"].validations_per_day=20`; metered by `api/routes.py:post_validate` → `api/deps.py:spend`. Register and Cell: `None` (unmetered) |
| ISO/TS 15066 separation calculator, 20 a day per address | Validator | `plans.py:separations_per_day=20`; `api/machine_routes.py:separation` → `spend` |
| Manifest diff and advisory check, free (10 a day per address on Validator) | Validator | `plans.py:diffs_per_day=10`; `api/machinery_routes.py` (diff) and `api/fleet_routes.py:advisory_check` → `spend`. Not stated in the plan card text, so no public number to drift |
| Bundle, Declaration, passport and attestation re-verification are always free | all | Routes use the `Anyone` dependency and never call `spend`: `machine_routes.py:check_bundle`, `fleet_routes.py` (declaration check), `machinery_routes.py:check_passport`, `attest_routes.py` (`/verify`, `/key`) |
| Offline enrolment kit, no account, no upload | all | `src/assurance/kit/` (runs locally; no API route involved) |
| Article 14 register (open cases, triage, filings, both clocks) | Register, Cell | `api/deps.py:require_register` (401 no key, 402 `plan_does_not_include_register`) via `plan.register`; applied as `api/routes.py:router` dependency. Clocks: `security/art14/clock.py:Deadlines` (computation, not an entitlement) |
| Hash-chained ledger with verifiable export; export refuses if the chain does not verify | Register, Cell | `api/routes.py:get_case_export` → `evidence/ledger.py:Ledger.export`; reachable only through `require_register`. `plan.export` is reported by `GET /v1/plans` as `verifiable_export` but has no separate gate — it is `True` exactly where `register` is |
| `/ai` control plane: writes, extra connections, full audit trail | Register, Cell | `neuralbridge/ai/entitlements.py:require_ai_control_plane` via `plan.ai_control_plane`; also on the raw adapter and MCP paths (`neuralbridge/ai/guard.py`) |
| `/ai` discover + read, 30 a day | Validator | `plans.py:ai_reads_per_day=30`; `neuralbridge/ai/entitlements.py:spend_ai_read` |
| `/ai` reads unlimited | Register, Cell | `ai_reads_per_day=None` → `AccountStore.consume` treats `None` as no limit |
| Machine safety verification, `POST /v1/machine/verify` | Cell | `api/deps.py:require_machine` via `plan.machine_verification` (`machine_routes.py`) |
| Annex III manifests, interventions, coverage, passport | Cell | `require_machine` on `machinery_routes.py` (manifest, intervention, coverage, passport) |
| Fleet ranking, advisory fan-out, fleet report, Declarations bound to a configuration hash | Cell | `require_machine` on `fleet_routes.py` (`/machines`, `/advisory`, `/report`, `/declare`) |
| Change-assurance cases over `/v1/change/*`; closure is a named human decision | Cell | `api/change_routes.py` — every route takes the `Machine` dependency (`require_machine`). Closure: `POST /v1/change/cases/{case_id}/decision`; `change/service.py:decide` requires a non-empty `reason`, refuses `closed` unless the case is `ready_to_close`, and no engine closes a case. **Partial:** `actor` is optional in `DecisionIn`; if omitted, `change_routes.py:_actor` records `operator` with kind `automation`, so the API records a decider but does not force a named person |
| Counter-signed head attestation, `POST /v1/ledger/attest` | Cell | `api/deps.py:require_attestation` via `plan.signed_attestation` (`attest_routes.py`) |
| Supplier tier publishes signed advisories; sales-assigned, unlisted | Supplier | `api/deps.py:require_supplier` via `plan.supplier_publish`; `plans.py:public_catalogue()` returns only `free`, `register`, `cell`, so Supplier is not served by `GET /v1/plans` |
| Checkout is disabled, not faked, until a Stripe price exists | Register, Cell | `plans.py:Plan.purchasable` (price env var set); `api/billing_routes.py:post_checkout` returns 503 `price_not_configured` otherwise |
| Prices €390 / month, €1,290 / month (no annual price appears in code or copy) | Register, Cell | Labels only: `plans.py:price_label`. The charged amount lives in Stripe. **These are unvalidated launch hypotheses, not market-tested numbers.** |

## Not enforced — removed

| Former claim | Status |
|---|---|
| "Unlimited cases" / "Unlimited Article 14 cases" / "Unlimited product families and cases" | NOT ENFORCED — removed. Replaced everywhere by **"Cases are not metered — no per-case cap or charge"**, which is a statement about the absence of a meter, not a promise of capacity |
| "Up to 25 product families" / "25 product families" | NOT ENFORCED — removed. `product_families` is gone from the plan model and from `GET /v1/plans` `limits`; nothing ever read it |
| "50 cases/day on Register" (sizing calculator, plan limits) | NOT ENFORCED — removed. `cases_per_day` is gone from the plan model; no route called `spend` with it. The calculator no longer sizes by volume |
| "Priority response" (Cell) | NOT ENFORCED — removed. No SLA, queue or support tier exists in code |
| Hosted Watch (scheduled drift checks run for you) | NOT PROVIDED. `src/assurance/watch/runner.py:run_watch` runs in the customer's kit or cron. The hosted API serves cases (`/v1/change/assess/drift` takes a baseline and an observed manifest the caller supplies); it has no scheduler |
| Customers, certifications, market-size figures | NOT PRESENT. Public pages name no customers, hold no certification claim, and quote no market numbers; the only commercial numbers are the prices above |

## Claims that could not be tied to code

None remain on the public pages. `GET /v1/plans` is the live check: if a string
on a plan card is not in `plans.py`, it should not be on the page.
