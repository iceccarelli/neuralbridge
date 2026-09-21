# NeuralBridge AI — Phase 1 vertical slice

What landed, against a real PostgreSQL, on top of the existing platform
code — not a new dispatch path, not a demo faking success.

## What landed

**Backend — `src/neuralbridge/ai/`**
- `identity.py` — a real, non-`"system"` actor on every request
  (`X-NB-Actor`/`X-NB-Session` headers, safely defaulted, never falls back
  to the forbidden placeholders `system`/`mcp_client`/`anonymous`).
- `policy.py` — the minimal gate the brief asked for: classifies every
  Postgres operation as READ / WRITE / DESTRUCTIVE, requires approval for
  anything that writes, and refuses outright (403, never silently) a
  request whose parameters match an exfiltration/prompt-injection shape
  (`COPY ... TO PROGRAM`, `dblink`, `pg_read_file`, an embedded "ignore
  previous instructions", or a bare URL — no tool in this slice ever
  legitimately needs one).
- `schemas.py` — `Provenance`, `Capability`, `Plan`, `ApprovalCard`,
  `ExecutionReceipt` shared 1:1 between the API and the frontend cards.
  `Provenance.mocked` exists specifically because `PostgresAdapter` falls
  back to canned mock data when it can't connect
  (`adapters/databases/postgres.py::_get_mock_response`) — the orchestrator
  surfaces that instead of hiding it.
- `connections.py` — reuses the *existing* `_connections` store from
  `api/routes/connections.py` rather than inventing a second one; seeds
  exactly one Postgres connection from `NEURALBRIDGE_AI_PG_*` env vars if
  none exists, honestly labelled `source: "seeded_from_env"`.
- `orchestrator.py` — plan → approve → execute → verify over
  `RequestRouter.route()`. No endpoint both proposes and executes a write
  in one call.
- `api/routes/ai.py` — `GET /ai/session`, `GET /ai/connections`,
  `GET /ai/capabilities`, `POST /ai/read`, `POST /ai/plan`,
  `GET /ai/plan/{id}`, `POST /ai/plan/{id}/approve`,
  `POST /ai/plan/{id}/deny`, `GET /ai/audit`. Mounted at `/api/v1/ai` in
  `main.py`.

**Frontend — `app/ai/`, `app/components/AiWorkspace.tsx`**
- Conversation / Context two-pane layout (Context holds connection,
  permissions, and last audit events — folding "Workspace" cards into the
  conversation stream itself rather than a third column, since every
  result already renders as a self-contained card there).
- A deterministic capability router in the browser (`parseIntent`) maps
  recognised phrasing ("list tables", "describe table X", a SELECT, an
  UPDATE/INSERT/DELETE) to the right backend call. **This is not an LLM
  call** — the slice ships with no external model credentials by design,
  consistent with "LLM is not system of record." Unrecognised input gets
  an honest "I did not recognise that" response, never a guess.
  External content (e.g. text sitting in a table row) is never treated as
  an instruction — only the operator's own message is ever parsed into a
  tool call (see `TestGolden004DenyMaliciousExfil` in `tests/test_ai.py`).
- Every result card shows its `Provenance` line (connection, tool,
  timestamp, request id) and flags `MOCK DATA` in red if the adapter ever
  falls back to canned data instead of a real connection.
- `POST /connections/{id}/test` and `/health/ready` (documented as
  fake/tautological in Phase 0) are never called by this UI — nothing here
  cites them as evidence of anything.
- Linked from the header's Platform mega-menu, the command palette
  ("finder"), and the mobile nav drill-down.
- Responsive: `.ai-grid` collapses to one column under 860px (same
  breakpoint pattern as `/console`); verified with Playwright at both
  desktop and Pixel 7 viewports.

## Security fixes made to the existing router/audit path (required, not optional)

1. **`RequestRouter.route()`'s docstring lied.** It claimed to validate
   "RBAC + rate-limit checks"; the method body never did. Rather than
   bolt a second, undocumented enforcement point onto a router three other
   callers (`api/routes/adapters.py`, `core/gateway.py`) already depend on,
   the docstring now says exactly what the method does — nothing — and
   points at `src/neuralbridge/ai/policy.py` as where that check actually
   lives for this surface. This matches the brief's second listed option
   ("strip the lie and implement a minimal gate in the AI layer").
2. **Every audit event now carries a real `actor`.** `route()` gained an
   `actor: str = "system"` parameter (default preserved for the two
   existing callers that haven't been updated to pass one — that default
   is itself flagged in the docstring as a gap, not a design choice); both
   `log_event()` calls inside `route()` now use it instead of the literal
   string `"system"`. Every call the `/ai` orchestrator makes passes
   `actor.as_audit_string()`, e.g. `human_session:demo-operator` — see
   `TestGolden005FetchAudit`, which asserts no audit event from this
   surface is ever `"system"` or `"mcp_client"`.
3. **The FastAPI app description's overclaim was removed** while touching
   `main.py` to mount the new router — it previously advertised "Universal
   Enterprise Middleware... securely connect ANY AI agent to ANY system...
   zero-trust security," which is exactly the stale claim Phase 0 flagged
   in the README's own self-correction. It now describes what's actually
   here, plus points at `/ai`.

`api/routes/adapters.py` and `core/gateway.py` were **not** changed beyond
the docstring/actor-default fix — they still don't enforce anything, same
as Phase 0 found. Wiring real auth into those is out of this slice's scope;
`/ai` does not depend on them.

## Golden tasks — `tests/test_ai.py`, real PostgreSQL, no mocking

11 tests, all passing against a live `postgres:16`, not a stub:
- **001** — a real connection is listed, never invented.
- **002** — `list_tables` and `query` hit the actual database; provenance
  says `mocked: false`.
- **003** — `execute_sql` via `/ai/read` is rejected (400); the same call
  via `/ai/plan` → `/ai/plan/{id}/approve` performs a real `UPDATE`,
  verified by re-reading the row; a plan cannot be approved twice (409);
  the deny path leaves the row untouched.
- **004** — `COPY ... TO PROGRAM` and an embedded "ignore previous
  instructions" payload are refused (403) before ever reaching the
  database; separately, a row containing adversarial text is read back
  without triggering any auto-executed follow-up action.
- **005** — every audit event fetched carries the real actor string, never
  `system`/`mcp_client`.

CI: added a `postgres:16` service container to `.github/workflows/ci.yml`'s
`test` job so these run for real in CI across all three Python versions,
not skip. Locally, `tests/test_ai.py` skips itself with an honest reason
if no Postgres is reachable — see `docs/ai-local-setup.md` (also covers
`docker-compose.ai.yml` for a one-command local database, and how to point
the frontend at a running API via `NEXT_PUBLIC_NEURALBRIDGE_API_URL`).

**Playwright smoke** — `tests-e2e/ai.spec.ts`, `playwright.config.ts`
(desktop + Pixel 7 projects): discover → real read → plan write → approve
→ receipt; deny path leaves nothing executed; an unreachable API renders
an honest disabled state rather than a fake success. All 6 pass locally
against the live stack (screenshots captured and sent alongside this
report: discover, real read, the approval card, and the execution
receipt, desktop and mobile).

`pytest tests/ -q` — **763 passed**. `ruff check src/` and
`mypy src/neuralbridge/ --ignore-missing-imports` — clean. `npm run build`
— compiles and type-checks `/ai` along with the rest of the site.

## Limitations (said plainly, not hidden)

- **Plans and seeded connections are in-memory**, same tradeoff as the
  existing `connections.py` store this slice reuses — restart the API
  process and both are gone. A production follow-up should back this with
  a real store, the way the assurance product's evidence ledger is backed
  by SQLite; explicitly out of scope here.
- **The policy gate is deliberately minimal**, exactly as the brief asked:
  one adapter (postgres), pattern-matching for injection/exfil rather than
  a general policy engine, no per-operator permission model beyond "an
  actor exists." It refuses cleanly rather than guessing when it doesn't
  know what it's looking at (unknown adapter, unknown operation) — but it
  is not a substitute for real RBAC.
- **No LLM is wired in.** The Conversation pane's intent parser is
  deterministic string matching, not natural-language understanding — it
  will miss phrasings a real model would catch. This was a deliberate
  choice (no external model credentials needed, "LLM is not system of
  record" taken literally), not an oversight; a future phase that adds a
  real model should keep its output advisory-only and route every actual
  tool call through this same policy gate rather than trusting the model's
  own claim about what it decided to do.
- **`api/routes/adapters.py` and `core/gateway.py` still enforce nothing.**
  Phase 1 did not touch their authorization posture — only `/ai`'s own
  call path gets the policy gate. An agent reaching adapters through the
  MCP gateway or the raw adapters REST route instead of `/ai` bypasses
  this slice's protections entirely; that gap is inherited from Phase 0,
  not introduced by Phase 1, but it is not closed either.
- **Single adapter, single connection.** By design (PostgreSQL only, one
  seeded connection) — not a partial implementation of something broader.

## Founder leftovers (still open, unrelated to this PR)

- `DEPLOY_NOW.md` — still an unexecuted runbook; this slice needs no Fly
  or Stripe secrets and doesn't touch it.
- GitHub Pages — still not enabled per `app/status/page.tsx`'s checklist
  (unrelated to `/ai`).
- Stale `neuralbridge.vercel.app` (the old v0.dev prototype) — still not
  retired; still needs a human with Vercel dashboard access, per Phase 0.

None of the above block `/ai` — this slice runs entirely against a local
or self-hosted Postgres and the platform API, independent of the
assurance product's deployment state.
