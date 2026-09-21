# NeuralBridge AI — Phase 3: "First Euro" — closing the trust hole, proving the one-key story

> **Second pass note (this session):** items D and F, the Playwright run,
> and a nav/SEO audit — all previously flagged below as not done — were
> completed in a follow-up session on the same branch. See the new
> sections **D**, **F**, **Nav/SEO audit**, and **Allow-list sanity
> check** below (which replace the old "Not built this phase" text for D
> and F), and the updated **Verification** section. The "Follow-ups"
> list at the bottom has been trimmed to only what's genuinely still
> open.

Phase 2 made `/ai` a paid capability and closed the free god-mode bypass for
the one adapter `/ai` itself supports (postgres). This phase does two
things: closes the same bypass for every *other* adapter (the real
enterprise-trust hole Phase 2 named explicitly as future work), and proves,
with tests and not just prose, that a single paid key buys something real
across both products this repo sells.

## A. Free vs. paid — the matrix, and what actually enforces it

| Capability | Free / no key | Register or Cell key |
|---|---|---|
| Assurance: `GET /v1/plans`, `POST /v1/spec/validate` | yes | yes |
| Assurance: `POST /v1/cases/{id}/signal` (open a case) | **401** (`require_register`) | yes — real ledger write, `content_hash`/`ledger_seq` returned |
| Assurance: `POST /v1/machine/verify` | 402 (Cell-only) | Cell: yes |
| `/ai` READ (`list_tables`/`query`/...) | yes, 30/day | yes, unlimited |
| `/ai` WRITE (`POST /ai/plan` → approve) | **402** (`require_ai_control_plane`) | yes — plan → approve → receipt |
| Postgres WRITE via raw adapters route or MCP gateway | **402**, same gate `/ai` uses | yes, real actor on audit trail |
| **Non-postgres adapter WRITE/RPC via raw adapters route or MCP gateway** | **402 — new this phase** (`guard.py::_SAFE_DISCOVERY_OPS`) | gate passes; adapter's own real/mock status is unchanged by the gate |
| Non-postgres adapter discovery ops (`list_*`, `get_*`, `health_check`, ...) | free, both surfaces | free |

Proven by `tests/test_ai_buyer_journey.py` (item below) and the extended
`tests/test_ai.py::TestGolden010NonPostgresAdapterGate` — against a real
Postgres and a real `AccountStore`, not asserted in prose.

## B. The adapter-execute bypass — closed for every adapter, not just postgres

Phase 2's `src/neuralbridge/ai/guard.py::enforce_write_gate` explicitly
scoped itself to `postgres` and said extending it further was "future work,
not this PR's scope." This phase does that work.

**What changed** (`src/neuralbridge/ai/guard.py`): for any adapter type
other than `postgres`, the gate now checks a real, per-adapter allow-list
of discovery operations — `_SAFE_DISCOVERY_OPS`, built by reading each of
the ~20 non-postgres adapters' actual `supported_operations` in
`src/neuralbridge/adapters/` (Slack, Discord, Teams, Telegram, email,
Gmail, Notion, S3, GCS, Azure Blob, MySQL, Snowflake, MongoDB, BigQuery,
Salesforce, SAP, SOAP, OData, REST, GraphQL, and the custom adapter
template — not guessed from a naming convention, read from source). An
operation on that list (e.g. `list_channels`, `get_object`, `health_check`,
`query` on a read-only-shaped call) proceeds free. Everything else —
`send_message`, `put_object`, `execute_rfc`, `call_bapi`, `create_record`,
an unrecognised operation name — now requires the same `ai_control_plane`
entitlement postgres WRITE requires (402 for an under-entitled caller).
`postgres` keeps its own detailed SQL-aware policy gate unchanged.

**Where it applies**: both surfaces that already shared the guard —
`api/routes/adapters.py` (`POST /adapters/{type}/execute`) and
`core/gateway.py` (the MCP gateway's `tools/call`) — needed no route-level
changes, since both already call `enforce_write_gate` before dispatch; only
the gate's own logic changed. The `/ai` orchestrator itself was checked and
confirmed to only ever dispatch `postgres` (`orchestrator.py` refuses any
other `adapter_type` outright), so it needed no change.

**What this does *not* claim**: clearing the gate proves the caller is
paid. It says nothing about whether a given adapter has a real backend
behind it — most of the ~20 non-postgres adapters are documented
mock/stub implementations (see each adapter's own docstring, e.g. Slack's
"A mocked adapter... It does not make any real network requests," and the
capability matrix's Status column). This phase closed the *entitlement*
hole; it did not rewrite ~20 adapters to be honest about being mocks —
that is a separate, larger effort, tracked as a follow-up below, not
silently claimed as done here.

**Tests** (`tests/test_ai.py::TestGolden010NonPostgresAdapterGate`, 7 new
tests, run against real Postgres for the entitlement store):
- free caller 402'd writing to a non-postgres adapter via the raw route
  and via the MCP gateway;
- free caller still passes a real discovery operation via both surfaces
  (asserted by confirming the response is *not* a 402 — the adapter itself
  may still legitimately fail with a 400/404 "not registered" in a test
  app that never registered it, which is the honest behavior, not a
  fabricated success);
- an operation name the gate has never seen for that adapter is refused
  the paid way, not assumed safe;
- a paid (Cell-tier, via `AccountStore`) caller clears the gate on both
  surfaces, with a real, non-`mcp_client` actor on the audit trail.
- The one Phase 2 test that documented the old postgres-only scope
  (`test_other_adapter_types_are_unaffected_by_this_gate`) was updated,
  not deleted, to assert the new behavior — its old assertion (`400`,
  gate did not intercept) is now provably false and would fail if the
  gate regressed.

`reports/NEURALBRIDGE-AI-CAPABILITY-MATRIX.md` got a short note at the top
flagging the rows this phase changed as stale for the two paths it covers,
without rewriting that report's historical narrative.

## C. "One key, two paid surfaces" — proven, not asserted

`tests/test_ai_buyer_journey.py` mints a single Cell-tier API key through
the *real* `AccountStore` (`upsert_account` + `issue_key` — the same path a
Stripe webhook uses to provision a real customer, not a hand-typed test
literal) and, in one test session against a real Postgres and one shared
`ASSURANCE_ACCOUNTS` file:

- shows the free/no-key case refused on both surfaces first (401 on the
  assurance route, 402 on `/ai` write);
- uses that one key to open a real case on the assurance register
  (`POST /v1/cases/{id}/signal`, a real `content_hash`/`ledger_seq` back,
  confirmed present on `GET /v1/cases`), then uses the *same* key to
  unlock `/ai`'s WRITE path (plan → approve → receipt).

`docs/buyer-journey.md` walks the same path with curl, entirely local, no
live Stripe — explicit about that in its own closing section.

## D. Sales demo pack

**Built and run end to end against a real local stack** (real Postgres,
real `assurance.api.service:app`, real `neuralbridge.main:app`, real Next
dev server — no mocking of the backend anywhere in this section):

- `scripts/seed_demo.py` mints a Cell-tier demo key through the real
  `AccountStore` (the same class a Stripe webhook uses to provision a
  paying customer) and opens a sample Register case over the real
  assurance API — idempotent on rerun, and it fails loudly (non-zero
  exit, the real error on stderr) if the store or API isn't reachable,
  never printing a fake "seeded" line for a step that didn't happen.
- `docker-compose.demo.yml` is an overlay on `docker-compose.ai.yml`
  adding both FastAPI services plus a one-shot `seed` job that runs
  `seed_demo.py` once both are healthy. `docker compose config` validated
  the merged file; it was **not** exercised against a live `docker
  compose up` in this environment (no Docker daemon available here — the
  same constraint Phase 1/2 already noted for `docker-compose.ai.yml`
  itself). The equivalent direct-uvicorn path (what `docs/ai-local-setup.md`
  documents) *was* run live — see Verification below.
- `scripts/demo-walkthrough.sh` runs the golden path end to end: free
  caller refused on both surfaces (401/402), one Cell key opens a real
  ledger case (`content_hash`/`ledger_seq` asserted, `GET /v1/cases`
  confirmed) and unlocks `/ai`'s WRITE path (plan → approve → a real
  execution receipt with `provenance.mocked: false`). `set -euo pipefail`
  plus explicit assertions on every response — any unexpected status
  fails the script immediately rather than faking a pass. **Run and
  passed** against the live local stack while writing this phase.
- `reports/demo/*.png` — seven real screenshots from
  `scripts/screenshot_demo_pack.py` (Playwright driving the actual
  running Next dev server + both APIs, not a mocked page): pricing, the
  free-tier 402 upgrade card, the key-paste auto-retry, the execution
  receipt, the checkout-success next-step panel (with a mocked
  `checkout/complete` response standing in for a real Stripe redirect —
  no live Stripe involved anywhere in this repo), and `/connectors/mcp`.
  `.gitignore`'s blanket `demo/` rule got a `!reports/demo/**` exception
  so these stay tracked.

### What a buyer gets for €390 (Register) / €1,290 (Cell), concretely

Everything below is what `scripts/demo-walkthrough.sh` and
`scripts/verify-buyer-path.sh` (item F) actually exercised against a live
local stack, not aspirational copy:

- **Register (€390/mo):** a real hash-chained case on the Article 14
  register — `POST /v1/cases/{id}/signal` with your key returns a real
  `content_hash`/`ledger_seq` from `assurance.evidence.ledger.EvidenceLedger`
  (`reports/demo/06-checkout-success-next-steps.png` shows the exact next
  step), both regulatory clocks running, and unlimited cases. Free
  (Validator) callers get a `401` on this route — proven in both
  `scripts/demo-walkthrough.sh` and `tests/test_ai_buyer_journey.py`.
- **Cell (€1,290/mo):** everything in Register, plus the `/ai` control
  plane's WRITE path unlocked with the *same* key — discover a real
  connection, propose a write, approve it, get a real execution receipt
  (`reports/demo/05-ai-execution-receipt.png`), and the same key clears
  the entitlement gate for a non-postgres adapter call (item B/allow-list
  below) — plus machine safety verification, Annex III manifests, fleet
  advisory fan-out, and attestation, none of which this phase re-verified
  (unchanged from Phase 1/2).
- Pasting a key mid-session — e.g. right after checkout — retries the
  exact write that was just 402'd, with no reload and no retyping
  (`reports/demo/04-ai-key-pasted-auto-retry-approval.png`, proven live
  in `tests-e2e/phase3-first-euro.spec.ts`).

## E. Website — post-purchase UX and pricing honesty

- `app/checkout/success/SuccessClient.tsx`: a "next step" panel after the
  key is shown, with two concrete actions — the exact `POST
  /v1/cases/{id}/signal` curl (linked to `docs/buyer-journey.md`), and a
  pointer to `/ai`'s existing API-key field. No fake login theater — both
  are described as plain header/session-storage paste, honestly.
- `app/components/AiWorkspace.tsx`: closed a real gap in `/ai`'s retry
  story. A propose-time 402 (`POST /ai/plan`) previously lost the original
  write request entirely — the upgrade card had nothing to retry, so a
  buyer who pasted a key mid-session had to retype their request from
  scratch. The upgrade card now carries the original
  `connection_id`/`operation`/`params` and a "Retry now with your key"
  button that re-sends the exact same write, reading the live `apiKey`
  state — no page reload, no retyping. (An approve-time 402 already
  worked without changes — the original approval card's Approve button
  stays live and picks up a freshly-pasted key on the next click; this was
  verified by reading the existing code, not assumed.)
- `app/components/PricingPlans.tsx`: a one-line "first 10 minutes"
  sentence under Register and Cell, computed from that plan's own live
  `limits.register_access`/`limits.ai_control_plane` fields (from `GET
  /v1/plans`, or the fallback table that mirrors it) rather than
  hand-typed copy — it cannot say more than the gate enforces because it
  is read from the same booleans the gate reads.
- `app/status/page.tsx` was **not touched** — still reports the same
  honest, unexecuted deploy checklist.
- `npm run build` passes (type-checked, all 40 routes render) after every
  change in this section.

## F. MCP + connector copy, `scripts/verify-buyer-path.sh`

**Connector copy reviewed line by line** against the real code:
`app/connectors/mcp/page.tsx` and `app/connectors/cursor/page.tsx`'s tool
names, env vars, and gating claims were checked against
`src/assurance/mcp/server.py`'s and `src/neuralbridge/mcp/server.py`'s
actual `@mcp.tool()` functions (`plans`, `spec_validate`, `machine_verify`,
`register_cases` on the assurance side; `ai_list_connections`,
`ai_capabilities`, `ai_read`, `ai_plan_write`, `ai_approve`, `ai_deny`,
`ai_audit` on the neuralbridge-ai side) — every tool name, package name
(`assurance-mcp`/`neuralbridge-ai-mcp`), and free-vs-paid claim on both
pages matches the real code exactly. No overclaiming found; no copy
changes were needed.

**`scripts/verify-buyer-path.sh`** — scripts the buyer path end to end
against a real local stack:
1. `GET /v1/plans` — asserts the real Validator/Register/Cell tiers come
   back.
2. `POST /v1/checkout` — asserts it refuses honestly. Run live against
   this repo's actual current state (no `ASSURANCE_PRICE_REGISTER` set):
   got a real `503`/`price_not_configured`, not a crash and not a
   fabricated checkout URL.
3. The register + `/ai` golden path with a real Cell-tier key minted
   through `AccountStore` — free/no-key refused first (401/402), then a
   real case write, then the same key unlocking `/ai`'s plan → approve
   path with a real execution receipt.

`set -euo pipefail` plus explicit field assertions on every response —
including a check that a *successful* checkout would itself be a failure
condition (it would mean this deployment is silently taking money for a
plan it can't provision). **Run and passed** against the live local
stack while writing this phase (see the exact output captured in this
session's work). Cross-linked from `docs/buyer-journey.md` and
`DEPLOY_NOW.md`.

`tests/test_assurance_mcp.py` and `tests/test_neuralbridge_mcp.py` were
reviewed rather than extended: both already run a free-tool 402
(`test_machine_verify_surfaces_a_real_402_not_a_fake_success`,
`test_plan_write_surfaces_a_real_402_not_a_fake_success`) and a paid
plan→approve loop with a real actor
(`test_paid_plan_approve_loop_with_real_actor`) against a live local
uvicorn + Postgres, matching what this task asked for — judged adequate
as-is rather than adding a near-duplicate test.

## Allow-list sanity check (second pass)

Before touching anything else, `_SAFE_DISCOVERY_OPS` in
`src/neuralbridge/ai/guard.py` was re-checked against every adapter's
real `supported_operations` in `src/neuralbridge/adapters/` (all ~20
non-postgres adapter modules read directly, not from memory or the
report prose above). Finding: **not clean.** Every op the allow-list
lists for every adapter *is* a real subset of that adapter's own
`supported_operations` (no name-level drift), but two allow-listed ops
carry a payload the adapter itself does not restrict to reads, once a
real (non-mock) backend is behind it:

- `mysql`/`bigquery` `"query"`: both adapters execute whatever raw SQL
  string is in `params["sql"]` verbatim
  (`MySQLAdapter._query`/`BigQueryAdapter._exec_query`) — no SELECT-only
  check in the adapter. A free caller sending `operation: "query"` with
  `sql: "DELETE FROM ..."` would have had it executed once a real backend
  is connected.
- `graphql` `"query"`: `GraphQLAdapter._do_execute` dispatches
  `operation="query"` and `operation="mutation"` to the exact same
  handler, trusting the GraphQL document text over the operation name — a
  free caller could send `operation: "query"` with a mutation document.

`src/neuralbridge/ai/guard.py` now also inspects the payload for these
specific ops (`_payload_looks_safe`, keyed by adapter+op to a regex over
the relevant param) and requires `ai_control_plane` entitlement unless
the text itself looks read-shaped — closing both without touching the
adapters themselves or inventing a second SQL parser.
`tests/test_ai.py::TestGolden011SafeDiscoveryAllowlistSanity` (7 new
tests) proves the fix and adds a standing assertion that
`_SAFE_DISCOVERY_OPS` stays a real subset of each adapter's own
`supported_operations`, so this can't silently drift again. `snowflake`'s
own `"query"` op is currently 100% mocked (returns canned rows regardless
of SQL text) so it had no live exploit today, but the same guard was
applied there too for when a real Snowflake connector replaces the mock.

## Nav/SEO audit (second pass, `app/` only)

Enumerated every route under `app/` and every link out of
`app/Header.tsx` and `app/layout.tsx`'s footer. Two real gaps found and
fixed:

- **`app/sitemap.ts`** was missing `/ai` and `/status` — both real,
  shipped pages with their own `<title>`/`description`/canonical
  metadata already in place. Added both.
- **Footer** (`app/layout.tsx`, Developers column) linked
  `/connectors/mcp` but not `/connectors/cursor` or `/ai` — both real,
  shipped pages, previously reachable only via cross-links from other
  pages (e.g. `/connectors/mcp` links to `/connectors/cursor`), not from
  the header or footer directly. Added both.
- **`public/llms.txt`** and **`public/.well-known/agent.json`** didn't
  mention `/ai` anywhere, despite it being the paid capability this and
  the previous phase are about — added a line to each, in the same
  factual, no-new-claims style those files already use.

Everything else checked out clean: every other real page — the pricing
anchor/homepage, `/docs`, `/console`, `/security`, `/roadmap`,
`/privacy`, `/contact` (via the `SALES` constant, linked from the header
CTA and the pricing mega menu), `/status`, `/developers`, `/solutions/*`,
`/applications`, `/cli` — was already reachable from the header and/or
footer. `/checkout/success` correctly stays out of all navigation (it's
post-purchase only, reached only via a Stripe redirect) while remaining
in the sitemap from a prior phase — left as-is, not this pass's call to
change. No orphaned pages found, and no placeholder/stub page was found
linked as if finished. `app/status/page.tsx`'s deploy-readiness content
was not touched, per instruction.

## Playwright (second pass)

Both existing Phase 2 specs were run against the live local stack this
time — Next dev server + real `neuralbridge.main:app` (Postgres-backed)
+ real `assurance.api.service:app` — desktop and mobile projects, per
`playwright.config.ts`'s own two-project setup:

```
tests-e2e/ai.spec.ts + tests-e2e/ai-entitlement.spec.ts
  desktop-chromium: 5 passed
  mobile-chromium:  5 passed
```

No failures, no fixes needed. A new spec,
`tests-e2e/phase3-first-euro.spec.ts`, covers this phase's own new
browser-visible behavior — the checkout-success next-step panel and the
`/ai` key-paste auto-retry of a previously-blocked write — and also
passed on both projects (3/3 each). The sales demo pack's screenshot
script (item D) is a separate, non-assertive capture tool and doesn't
duplicate this coverage.

## G. Verification

```
pytest tests/ -q          # 797 passed
ruff check src/ tests/    # All checks passed!
npm run build              # compiles, type-checks, all 40 routes render
```

Local verification environment for this phase: PostgreSQL 16 running
locally, plus the full local stack live for the duration of this
session — `uvicorn assurance.api.service:app` on :8001, `uvicorn
neuralbridge.main:app` on :8000, and `npm run dev` on :3000, all
pointed at each other via `NEXT_PUBLIC_*` env vars — used to run
`scripts/demo-walkthrough.sh`, `scripts/verify-buyer-path.sh`, and both
Playwright projects, all passing. No Docker daemon was available in this
environment (same constraint as the first pass), so
`docker-compose.demo.yml` was validated with `docker compose config`
but not exercised with a live `docker compose up`; the equivalent direct-
uvicorn path was run live and is what produced every number above.

## Founder leftovers still open (unrelated to this PR, not executed)

- `DEPLOY_NOW.md`'s Fly/Stripe steps — still unexecuted; this phase only
  added a cross-link to `scripts/verify-buyer-path.sh` as a post-secrets
  verification step, no secrets touched or requested.
- GitHub Pages, the stale `neuralbridge.vercel.app` project — unchanged,
  still need a human with dashboard access, per Phase 2's report.

## Follow-ups not completed this phase (for a future session)

1. **Adapter honesty pass**: most non-postgres adapters are still
   documented mocks (see item B's "what this does not claim"). Making
   each one honestly report its own real-vs-mock status at runtime (not
   just in a docstring) is a larger, adapter-by-adapter effort out of
   this phase's scope.
2. **`docker-compose.demo.yml` against a live Docker daemon**: written
   and config-validated this session, but never actually brought up with
   `docker compose up` for lack of a daemon in this environment — worth
   a founder or CI run before relying on it as the canonical demo path.
3. A dedicated MCP smoke test for a **non-postgres** adapter tool over
   the gateway specifically (the existing `tests/test_ai.py` gateway
   tests use Slack; `tests/test_neuralbridge_mcp.py`'s own tool surface
   is postgres-only via `/ai`) — not a known enforcement gap (the gate
   itself is adapter-agnostic and tested), just untested from that one
   additional angle.
