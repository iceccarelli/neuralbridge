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

```bash
cd src/dashboard  # not used by app/ai — see note below
```

`app/ai` (the Next.js page) talks to the backend over
`NEXT_PUBLIC_NEURALBRIDGE_API_URL`, the platform-side equivalent of
`NEXT_PUBLIC_ASSURANCE_API_URL` used by `/console`:

```bash
export NEXT_PUBLIC_NEURALBRIDGE_API_URL=http://localhost:8000/api/v1
npm run dev
# open http://localhost:3000/ai
```

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
container (`.github/workflows/ci.yml`).

## What this does *not* set up

Nothing here touches Fly.io, Stripe, or the assurance product's evidence
ledger — this is local-only, platform-side, and unrelated to
`DEPLOY_NOW.md`.
