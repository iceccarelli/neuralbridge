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

## The demo role must be a plain read-only role

`/ai/read` on the seeded demo connection is free and open to anonymous callers. Its policy
(`src/neuralbridge/ai/policy.py`) admits a single `SELECT`/`WITH`/`SHOW`/`EXPLAIN`/`VALUES` statement and
refuses file, large-object, program and session-control SQL, but a `READ ONLY` transaction does not stop
`COPY ... TO PROGRAM` or `pg_read_file`, so the database role itself is the last line of defence. Use a role
that is **not** a superuser and is **not** a member of `pg_execute_server_program`, `pg_read_server_files` or
`pg_write_server_files`, with `SELECT` on the demo tables only:

```sql
CREATE ROLE nb_demo_ro LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '...';
GRANT CONNECT ON DATABASE neuralbridge_ai TO nb_demo_ro;
GRANT USAGE ON SCHEMA public TO nb_demo_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO nb_demo_ro;
```

If the configured role is privileged the backend still starts (CI's own Postgres service user is a
superuser) but says so: a `ai_demo_role_privileged` warning in the startup log, and an `ai_demo_role` object
plus a `warnings` entry on `GET /api/v1/health/ready` (status stays 200). The local `neuralbridge` dev role
above is a throwaway superuser for tests; do not expose such a deployment.

## Start the backend

The seeded demo connection is shared by every caller, so by default a paid
account can only READ it; it proposes/approves writes on connections it binds
itself (`POST /ai/connections`). For the local single-user demo (the buyer
path in `docs/buyer-journey.md`, `scripts/verify-buyer-path.sh`) that writes
the demo database, export this in the shell running uvicorn:

```bash
export NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID=1   # LOCAL DEVELOPMENT ONLY — never in production
```

Without it a paid account's plan on the demo connection gets a real `403`
("demo connection is read-only").

```bash
python -m pip install -e ".[dev]"
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
connection, the account's audit log) is gated the same way the assurance
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
restarts — see that endpoint's docstring). `POST /ai/connections/{id}/rotate`
(body `{user, password}`) is exactly that re-supply: the new credentials are
checked against the target before the live adapter is swapped, and a refused
rotation leaves the working ones in place. `POST /ai/connections/{id}/revoke`
is permanent and takes effect on the very next call from any worker process
(the status lives in the store, which every request re-reads); pending plans
on it are denied. Both, like `DELETE`, work for an account whose plan lapsed.

### The audit trail is durable too

The platform audit trail (`/api/v1/ai/audit`, `/api/v1/logs`) is an
append-only, hash-chained SQLite file, `neuralbridge-audit.db` next to the
store above. Configure it with:

| Variable | Meaning |
|---|---|
| `NEURALBRIDGE_AUDIT_DB` | path of the SQLite file (default: `neuralbridge-audit.db` in the directory of `NEURALBRIDGE_AI_STORE`) |
| `NEURALBRIDGE_AUDIT_BACKEND` | `sqlite` (default), `postgres` (needs `NEURALBRIDGE_AUDIT_PG_DSN`, a secret; table `nb_audit_log`) or `memory` (explicit opt-in; lost on restart) |

Several worker processes may share the file (WAL, atomic chained append). If
the sink cannot be written the app refuses to start, `/api/v1/health/ready`
answers 503 `degraded`, and adapter calls and credential/plan operations are
refused with 503 rather than run unrecorded. Nothing deletes or rotates
records: archive the file at a documented cut-over when your retention
policy requires it. Existing deployments need no migration; the file is
created on first start (before this change the trail was in memory and was
lost on every restart).

### Resource controls (per process)

`NEURALBRIDGE_MAX_BODY_BYTES` (1 MiB; 413), `NEURALBRIDGE_RATE_LIMIT_PER_MINUTE`
(120 per tenant, 0 = off; 429 + `Retry-After`), `NEURALBRIDGE_MAX_CONCURRENT_CALLS`
(32) and `NEURALBRIDGE_MAX_CONCURRENT_PER_ADAPTER` (8) (503 + `Retry-After`),
`NEURALBRIDGE_ADAPTER_CALL_TIMEOUT` (60 s; 504). They apply identically to the
raw adapters route, `/ai` and the MCP gateway. With several worker processes
each process has its own counters.

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
