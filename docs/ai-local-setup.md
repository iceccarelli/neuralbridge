# Running /ai locally against a real PostgreSQL

The `/ai` slice (`src/neuralbridge/ai/`, `app/ai/`) only ever shows data it
actually read from a real system — see
`reports/NEURALBRIDGE-AI-CAPABILITY-MATRIX.md` for why that matters here
specifically (`PostgresAdapter` silently falls back to mock data if it
can't connect; the AI layer refuses to treat that as a real fact). That
means there is no way to see it do anything without a real Postgres to
point it at.

## Option A — Docker

```bash
docker compose -f docker-compose.ai.yml up -d
export NEURALBRIDGE_AI_PG_HOST=127.0.0.1
export NEURALBRIDGE_AI_PG_PORT=5432
export NEURALBRIDGE_AI_PG_USER=neuralbridge
export NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev
export NEURALBRIDGE_AI_PG_DATABASE=neuralbridge_ai
```

## Option B — a locally installed PostgreSQL

```bash
sudo -u postgres createuser --login neuralbridge
sudo -u postgres psql -c "ALTER ROLE neuralbridge WITH PASSWORD 'neuralbridge_dev';"
sudo -u postgres createdb -O neuralbridge neuralbridge_ai
sudo -u postgres psql -d neuralbridge_ai -f deploy/ai/seed.sql
export NEURALBRIDGE_AI_PG_HOST=127.0.0.1
export NEURALBRIDGE_AI_PG_PORT=5432
export NEURALBRIDGE_AI_PG_USER=neuralbridge
export NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev
export NEURALBRIDGE_AI_PG_DATABASE=neuralbridge_ai
```

## Start the backend

```bash
pip install -e ".[dev]"
uvicorn neuralbridge.main:app --reload --port 8000
```

`GET http://localhost:8000/api/v1/ai/connections` should return one
`postgres` connection with `"source": "seeded_from_env"` — that means
`src/neuralbridge/ai/connections.py` found your env vars and registered a
real `PostgresAdapter`. If it returns `[]`, the env vars above aren't set
in the shell running uvicorn.

## Point the frontend at it

`app/ai` (the Next.js page) talks to the backend over
`NEXT_PUBLIC_NEURALBRIDGE_API_URL`, the platform-side equivalent of
`NEXT_PUBLIC_ASSURANCE_API_URL` used by `/console`:

```bash
export NEXT_PUBLIC_NEURALBRIDGE_API_URL=http://localhost:8000/api/v1
npm run dev
# open http://localhost:3000/ai
```

## Phase 2: entitlement (Register/Cell for writes)

The write path (`/ai/plan`, approve/deny, binding an additional
connection, the full audit trail) is gated the same way the assurance
product's own paid routes are — see `src/neuralbridge/ai/entitlements.py`,
which reuses `assurance.api.deps`/`assurance.billing.accounts` directly
rather than a second entitlement engine. To try the paid path locally:

```bash
export ASSURANCE_API_KEYS=my-local-operator-key   # resolves to a Cell-tier principal
export ASSURANCE_ACCOUNTS=./accounts.db            # same account store the assurance API reads
```

With no key presented, `/ai` treats the caller as the free Validator tier
(reads work, rate-limited to `ai_reads_per_day`; writes return a real
`402 Payment Required` with an upgrade payload — never a bare 403). In the
UI, paste the key into the "API key" field in the Context pane; over the
API or MCP, send it as `X-API-Key` / `NEURALBRIDGE_AI_API_KEY`.

To test as a real Register/Cell *account* rather than the blanket operator
key, use `assurance`'s own account tooling against the same
`ASSURANCE_ACCOUNTS` file (see `docs/assurance/index.md`) — any account
whose plan has `ai_control_plane=True` (Register or Cell — see
`src/assurance/billing/plans.py`) works here too, since it's the same
store.

## Phase 2: persistence

Connections and plans are durable — `neuralbridge.ai.store.AiStore`,
SQLite, path from `NEURALBRIDGE_AI_STORE` (default `neuralbridge-ai.db` in
the working directory). Restarting `uvicorn` keeps every connection
record and every plan (pending, approved, denied, executed) — nothing is
lost, matching the assurance product's own durable-by-default posture.
Credentials are still never persisted (only the seeded demo connection,
whose credentials live in env vars, re-registers itself automatically
after a restart; an operator-bound additional connection needs its
credentials re-supplied via `POST /ai/connections` if the process
restarts — see that endpoint's docstring).

## MCP: neuralbridge-ai-mcp

A second installable MCP server, alongside `assurance-mcp`, wrapping
`/ai` itself rather than the assurance API:

```bash
pip install -e '.[neuralbridge-ai-mcp]'
export NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1
export NEURALBRIDGE_AI_API_KEY=my-local-operator-key   # optional — write tools only
export NEURALBRIDGE_AI_ACTOR=your-agent-name            # real identity for the audit trail
neuralbridge-ai-mcp
```

See `/connectors/mcp` on the marketing site for the full tool list and a
Cursor `mcp.json` snippet.

## Running the golden-task tests

```bash
export NEURALBRIDGE_AI_PG_HOST=127.0.0.1
export NEURALBRIDGE_AI_PG_PORT=5432
export NEURALBRIDGE_AI_PG_USER=neuralbridge
export NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev
export NEURALBRIDGE_AI_PG_TEST_DATABASE=neuralbridge_ai_test  # separate DB — tests create/drop their own table
pytest tests/test_ai.py -v
```

`tests/test_ai.py` skips itself (not a fake pass) if it can't reach that
database — the same "unchecked is a valid answer" rule the rest of this
repo follows. CI runs it for real against a `postgres:16` service
container (`.github/workflows/ci.yml`). `tests/test_neuralbridge_mcp.py`
covers the `neuralbridge-ai-mcp` server the same way, against a real
`uvicorn` instance and a real Postgres — same skip-if-unreachable rule.

## What this does *not* set up

Nothing here touches Fly.io, Stripe, or the assurance product's evidence
ledger — this is local-only, platform-side, and unrelated to
`DEPLOY_NOW.md`.
