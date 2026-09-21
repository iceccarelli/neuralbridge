# NeuralBridge AI — Phase 2: making the control plane sellable

Turns the `/ai` control plane and the platform dispatch path it sits on
into a paid capability, enforced in code the same way the assurance
product's own Register/Cell gates are — not a second entitlement engine,
the same one, reused directly (`src/assurance/billing/plans.py` +
`src/assurance/api/deps.py`).

## A. What is now paid, what stays free

| Capability | Validator (free) | Register / Cell |
|---|---|---|
| Open `/ai`, see session, honest UI | yes | yes |
| Discover the seeded demo connection | yes | yes |
| READ (`list_tables`/`describe_table`/`query`/`health_check`) | yes — **30/day**, metered via the same `AccountStore.consume()` the assurance validator uses | yes, unlimited |
| WRITE: propose (`POST /ai/plan`) and approve (`.../approve`) | **402**, with a real upgrade payload (`error`, `tier`, `remedy`) | yes |
| Bind an additional connection (`POST /ai/connections`, new this phase) | **402** | yes |
| Full audit trail (`GET /ai/audit`) | limited to the **last 3** events | full, up to `limit` |
| Same via the raw adapters REST route or the MCP gateway | **402/403**, same gate — see Part B | yes, real actor |

`assurance.billing.plans.Plan` gained two fields: `ai_control_plane: bool`
(False on Validator, True on Register/Cell) and `ai_reads_per_day: int |
None` (30 on Validator, unlimited elsewhere). Both are in
`to_public_dict()`'s `limits`, so `GET /v1/plans` — and the pricing page,
which renders live from it — cannot drift from what's enforced. The
free tier's `included` list now states the read/write split explicitly;
Register/Cell's states the write capability explicitly. The static
fallback table (`app/components/PricingPlans.tsx`'s `FALLBACK_PLANS`, used
when the live API isn't reachable) and the hand-typed comparison table on
the homepage were both updated to match — two sources that must stay
honest, not one.

**402, never a bare 403**, for every under-entitled `/ai` caller — key or
no key — because Validator is a real, no-account-needed tier elsewhere in
this product (`spec_validate`, `plans`); an anonymous READ-only caller
hitting a WRITE-shaped request should see "upgrade," not "log in." This is
a deliberate, documented divergence from `assurance.api.deps.require_register`
(401 for no key at all, 402 only once a key proves insufficient) — see
`src/neuralbridge/ai/entitlements.py::require_ai_control_plane`'s docstring.

## B. The free god-mode bypass — closed

Phase 1 left `api/routes/adapters.py` and `core/gateway.py` (the MCP
gateway) enforcing nothing: a free, even anonymous, caller could skip
`/ai` entirely and mutate the Postgres database directly through either
path. Closed by extracting one shared guard
(`src/neuralbridge/ai/guard.py::enforce_write_gate`) that both paths now
call — not a second policy engine, the same `neuralbridge.ai.policy.evaluate`
`/ai` itself uses, plus the same `require_ai_control_plane` gate:

- **`api/routes/adapters.py`** (`POST /adapters/{type}/execute`) now takes
  a real `Actor` and `Principal` dependency, calls `enforce_write_gate`
  before dispatch, and passes the real actor into `RequestRouter.route()`.
- **`core/gateway.py`** (the MCP gateway's `tools/call`) now resolves a
  `Principal` per call (from an `api_key` tool argument, or a
  session-level `NEURALBRIDGE_MCP_API_KEY`), applies the same guard, and
  passes a real actor (`actor` tool argument, or `NEURALBRIDGE_MCP_ACTOR`,
  or a generated `mcp-session:<id>` — never the bare literal `mcp_client`)
  into `RequestRouter.route()`. The gateway's own session-level audit
  entries (`mcp_request`/`mcp_error`) were fixed the same way while this
  was open.
- **Scope, stated plainly**: the guard only classifies `postgres`
  operations — the one adapter `/ai` itself supports. Every other adapter
  (~20 of them, all Experimental/evolving per the capability matrix) is
  unaffected; extending real policy/entitlement coverage to them is future
  work, not this PR's scope.

Golden tests (`tests/test_ai.py::TestGolden008BypassClosedViaRawAdaptersRoute`,
`::TestGolden009BypassClosedViaMcpGateway`) prove, against a real Postgres:
a free caller is blocked (402) writing via the raw adapters route and via
the MCP gateway; a free caller can still read via both; a paid caller
writes via both with a real actor recorded on the audit trail; an
exfiltration-shaped payload (`COPY ... TO PROGRAM`) is refused (403) via
the raw route regardless of entitlement; a non-postgres adapter
(`slack`) is unaffected by the gate (still 400s the pre-existing way, not
402'd).

## C. Persistence — plans and connections survive a restart

`src/neuralbridge/ai/store.py::AiStore` — SQLite, `BEGIN IMMEDIATE`
transactions, a schema-version guard, same pattern as
`assurance.billing.accounts.AccountStore` (not hash-chained — this is
operational state, not the evidence ledger). Path from
`NEURALBRIDGE_AI_STORE` (default `neuralbridge-ai.db`). Replaces the
in-memory dicts `connections.py` and `orchestrator.py` used in Phase 1.

What survives a restart: every connection record; every plan
(pending/approved/denied/executed), including its exact SQL, so an
operator restarting mid-review still sees exactly what they were about to
approve. What does **not**, by design: credentials for operator-bound
additional connections (`POST /ai/connections` never persists a password —
same rule Phase 1's connection store followed). After a restart such a
connection's record is still listed, but its live adapter is gone; a call
against it returns a clear 409 ("re-bind it with `POST /ai/connections`"),
not a confusing 500 or a silent no-op. The seeded demo connection is
exempt — its credentials live in env vars, so it re-registers itself
automatically on first use after a restart.

`tests/test_ai.py::TestGolden007PersistenceAcrossRestart` proves this
against a real Postgres and a real file-backed store: create a pending
plan and a connection, drop every module-level singleton (simulating a
process restart), reopen the app against the same store file, confirm the
connection id and the pending plan (full status, not just presence)
survive, and that the plan can still be approved after the "restart" —
the whole loop survives, not a status flag.

## D. MCP parity — `neuralbridge-ai-mcp`

A second installable MCP server (`src/neuralbridge/mcp/server.py`,
`pip install -e '.[neuralbridge-ai-mcp]'`, console script
`neuralbridge-ai-mcp`), same shape as `assurance.mcp.server`: every tool
is a thin, honest `httpx` wrapper around the real `/ai` HTTP API — no
local simulation, fails closed with a structured "not configured" error
if `NEURALBRIDGE_API_URL` is unset. Deliberately one platform MCP package
story alongside the existing low-level `core.gateway` (which Part B fixed
but did not redesign — it remains the generic adapter-dispatch transport
`/ai`'s own HTTP layer sits on top of).

Seven tools: `ai_list_connections`, `ai_capabilities`, `ai_read` (free,
rate-limited server-side same as `/ai/read`), `ai_plan_write`,
`ai_approve`, `ai_deny`, `ai_audit` (paid — return the API's real 402
otherwise). Actor identity via `NEURALBRIDGE_AI_ACTOR` (never allowed to
default to `system`/`mcp_client`); entitlement via `NEURALBRIDGE_AI_API_KEY`.

`tests/test_neuralbridge_mcp.py` — 5 tests against a real `uvicorn`
instance (mirroring `tests/test_assurance_mcp.py`'s own pattern) and a
real Postgres: tool list matches; the not-configured fallback is honest;
free tools call the real API; `ai_plan_write` surfaces a real 402 for a
free caller; the full plan → approve loop works for a paid caller with a
real actor on the receipt.

`/connectors/mcp` gained an `neuralbridge-ai-mcp` install section
(commands, Cursor `mcp.json` snippet) alongside the existing
`assurance-mcp` one; `/connectors/cursor` gained a one-line pointer to it.
No GitHub-blob-only documentation — both live on pages that already exist.

## E. Website — sell it without lying

- **Pricing** (`app/components/PricingPlans.tsx`): the `/ai control
  plane` line now appears in every tier's `includes` list, rendered live
  from `GET /v1/plans` when reachable (this is the same mechanism the
  page already used — no second, hand-maintained feature table invented).
  The static fallback data and the homepage's hand-typed comparison table
  were both updated to match, with two new rows (`/ai` read vs. write).
- **`/ai` itself**: the Context pane now shows the caller's real plan
  (`GET /ai/session`, which now also returns `tier`/`ai_control_plane`/
  `ai_reads_per_day`), an optional API-key field (same
  session-storage-only pattern as `/console`'s), and an inline upgrade
  hint when on the free tier. A 402 from a plan/approve attempt renders as
  a distinct **upgrade card** — "Register or Cell required," the API's own
  `remedy` text, and "See pricing"/"Talk to sales" links to `/#pricing` —
  never a bare error, and never implying a charge just happened.
- **No live-checkout claim added.** The upgrade card explicitly says "Not
  a live checkout in this message — no charge happens here" and links to
  the real pricing section, which itself still only shows "Buy" once the
  live API says a price is `purchasable` (unchanged from before this
  phase). `app/status` was not touched and still reports the same
  unexecuted deploy checklist.

Screenshots (sent alongside this report): free-tier context + the 402
upgrade card for a write attempt; paid context (after pasting a Cell-tier
key) + the approval card + the real execution receipt; the pricing cards
showing the `/ai control plane` line on all three tiers.

## F. Verification

- `pytest tests/ -q` — **782 passed** (was 763 after Phase 1; +19 from
  Phase 2's entitlement/bypass/persistence/MCP tests), against a real
  `postgres:16`, no mocking. `ruff check src/` and
  `mypy src/neuralbridge/ --ignore-missing-imports` — clean.
- `npm run build` — compiles and type-checks the updated `/ai` page and
  pricing components.
- Playwright (`tests-e2e/ai.spec.ts`, `tests-e2e/ai-entitlement.spec.ts`)
  — **10 passed**, desktop + mobile, against the live stack: the paid
  golden loop (discover → read → plan → approve → receipt), the deny
  path, the honest disabled-API state, the free-tier upgrade card, and
  pasting a paid key mid-session unlocking the write path.
- CI: `.github/workflows/ci.yml`'s existing `postgres:16` service
  container (added in Phase 1) already covers every new test file — no
  workflow changes were needed this phase.

## Limitations, stated plainly

- **The policy/entitlement gate stays Postgres-only**, by design — see
  Part B. A free caller reaching a *different* adapter (Salesforce, S3,
  ...) through the raw adapters route or MCP gateway still hits no gate at
  all, same as before this phase; those adapters were never `/ai`-gated
  either. Real coverage for them is future work.
- **`ai_reads_per_day` quota is per-`Principal.subject`** (account id, or
  `ip:<address>` for anonymous callers) via the same `AccountStore` the
  assurance validator uses — an anonymous caller behind a shared IP or
  proxy shares one 30/day allowance with everyone else behind it. Same
  tradeoff the existing `validations_per_day` free quota already accepts.
- **Additional connections lose their live adapter on restart** (Part C)
  — an accepted consequence of never persisting credentials, not an
  oversight, but worth remembering before demoing a restart with a
  non-seeded connection.
- **No LLM wired in** — unchanged from Phase 1, still explicitly out of
  scope; the Conversation pane's intent parser is still deterministic
  string matching.

## Founder leftovers still open (unrelated to this PR)

- `DEPLOY_NOW.md` — still an unexecuted runbook; this PR asked for and
  needed no Fly/Stripe secrets.
- GitHub Pages — still not enabled per `app/status/page.tsx`'s checklist.
- Stale `neuralbridge.vercel.app` (the old v0.dev prototype) — still not
  retired; still needs a human with Vercel dashboard access.

## Branch hygiene

This PR's branch is `claude/neuralbridge-ai-phase2`, deleted after merge
per instructions. The two prior phase branches
(`claude/awesome-bardeen-6ondvv`, `claude/neuralbridge-ai-phase1`) were
already merged; deleting their local copies succeeded, but deleting the
matching **remote** branches returned an HTTP 403 (no delete permission
from this session) — the founder should delete
`claude/awesome-bardeen-6ondvv` and `claude/neuralbridge-ai-phase1` on
GitHub directly.
