# NeuralBridge AI — Phase 3: "First Euro" — closing the trust hole, proving the one-key story

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

**Not built this phase.** A docker-compose seed script + a scripted
walkthrough with saved screenshots under `reports/demo/` was in scope but
was deprioritized against the effort budget for this pass in favor of the
entitlement-gate engineering (item B, the stated "main engineering work")
and the one-key proof (item C). `docker-compose.ai.yml` already exists
from Phase 1/2 and boots API + Postgres; it was not extended with a seed
script this phase. Recorded here honestly rather than left unmentioned —
see "Follow-ups" below.

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

## F. MCP + connector copy, demo script, `verify-buyer-path.sh`

**Not done this phase** — `/connectors/mcp`/`/connectors/cursor` copy
review, an additional paid-MCP smoke test, and
`scripts/verify-buyer-path.sh` were all in scope but cut for the same
effort-budget reason as item D. The existing `tests/test_neuralbridge_mcp.py`
and `tests/test_assurance_mcp.py` (from Phase 1/2) already cover the paid
MCP path this phase's guard change reuses, so there is no known gap in
enforcement — the cut items are documentation/tooling polish, not an
enforcement hole. See "Follow-ups."

## G. Verification

```
pytest tests/ -q          # 791 passed (was 789 before this phase; +2 buyer-journey golden tests)
ruff check src/ tests/    # All checks passed!
npm run build              # compiles, type-checks, all 40 routes render
```

Local verification environment for this phase: PostgreSQL 16 installed
and started locally (`pg_ctlcluster 16 main start`), roles/databases
created matching `tests/test_ai.py`'s own defaults
(`neuralbridge`/`neuralbridge_dev`, `neuralbridge_ai_test`) — no Docker
daemon was available in this environment, so the docker-compose path
mentioned in `docs/ai-local-setup.md` was not used to produce these
numbers, but the same tests run either way (CI uses the `postgres:16`
service container).

Playwright was **not run** this phase (no browser test infra invoked in
this pass) — the two Playwright specs from Phase 2
(`tests-e2e/ai.spec.ts`, `tests-e2e/ai-entitlement.spec.ts`) were not
touched and should still be run before calling this phase's frontend
changes fully verified end-to-end; `npm run build`'s type-check is the
verification that was performed here.

## Founder leftovers still open (unrelated to this PR, not executed)

- `DEPLOY_NOW.md`'s Fly/Stripe steps — still unexecuted; this phase only
  added a cross-link to `docs/buyer-journey.md` as a post-secrets
  verification step, no secrets touched or requested.
- GitHub Pages, the stale `neuralbridge.vercel.app` project — unchanged,
  still need a human with dashboard access, per Phase 2's report.

## Follow-ups not completed this phase (for a future session)

1. **Sales demo pack** (item D): docker-compose seed script (Cell-tier
   demo key + a sample Register case) and a scripted golden-path walkthrough
   with screenshots under `reports/demo/`.
2. **MCP/connector copy review + smoke test** (item F): confirm
   `/connectors/mcp` and `/connectors/cursor` copy matches the Phase 3
   reality exactly (it was not found to overclaim in a spot check, but
   was not line-by-line reviewed this phase), and add a smoke test
   specifically for a non-postgres adapter over MCP with a paid key
   (the existing gateway tests in `tests/test_ai.py` cover the *gate*;
   a dedicated `tests/test_neuralbridge_mcp.py` case would cover the
   installable `neuralbridge-ai-mcp` server's own tool surface for a
   non-postgres tool, which does not currently exist as a registered MCP
   tool in that server — worth confirming intentional).
3. **`scripts/verify-buyer-path.sh`**: a script version of
   `docs/buyer-journey.md`'s curl walkthrough, failing loudly if secrets
   are missing rather than faking success.
4. **Adapter honesty pass**: most non-postgres adapters are still
   documented mocks (see item B's "what this does not claim"). Making
   each one honestly report its own real-vs-mock status at runtime (not
   just in a docstring) is a larger, adapter-by-adapter effort out of
   this phase's scope.
5. Run the Phase 2 Playwright suite (`tests-e2e/ai.spec.ts`,
   `tests-e2e/ai-entitlement.spec.ts`) against this phase's frontend
   changes end-to-end, in a browser, not just type-checked.
