# The buyer journey, locally, with no live Stripe

This walks through what a paying customer's *first ten minutes* actually
unlock, entirely on your own machine: mint a real Cell-tier key the same
way `AccountStore` mints one for a paying customer, then use that one key
against both paid surfaces — the assurance register and the `/ai` control
plane. **No live Stripe/checkout is involved anywhere in this doc** — see
"What this is not" at the bottom.

This is the same path `tests/test_ai_buyer_journey.py` proves automatically
(run it yourself: `pytest tests/test_ai_buyer_journey.py -v`, real Postgres
required — see `docs/ai-local-setup.md`). `scripts/verify-buyer-path.sh` is
a scripted version of this same walkthrough (plus a `GET /v1/plans` check
and confirming `POST /v1/checkout` refuses honestly without a Stripe price
configured) that you can run against your own local stack in one command
instead of following the steps below by hand — see that script's own
header for its env vars. `scripts/demo-walkthrough.sh` in `docker-
compose.demo.yml`'s sales demo pack runs the same golden path against a
seeded demo key rather than one you mint yourself.

## 0. Prerequisites

```bash
pip install -e ".[dev]"
```

A real local PostgreSQL, reachable at the `NEURALBRIDGE_AI_PG_*`
coordinates `/ai` expects — see `docs/ai-local-setup.md` for the two
supported ways to get one (Docker or a local install). The assurance
side of this walkthrough needs no Postgres — it's SQLite.

## 1. Mint a Cell-tier key from the real AccountStore

Not a fixture shortcut — the same `AccountStore` class the assurance API
reads on every request:

```bash
export ASSURANCE_ACCOUNTS=./buyer-journey-accounts.db
python3 - <<'PY'
from assurance.billing.accounts import AccountStore
store = AccountStore("buyer-journey-accounts.db")
account = store.upsert_account(email="you@example.com", tier="cell", company="Your Company")
key = store.issue_key(account.id, label="buyer-journey")
print(key)
PY
```

Copy the printed key — it's shown once, only its hash is kept
(`AccountStore.issue_key`'s own docstring). Export it:

```bash
export BUYER_KEY=<the key printed above>
```

## 2. Start the assurance API and open your first Register case

```bash
export ASSURANCE_LEDGER=./buyer-journey-ledger.db
uvicorn assurance.api.service:app --port 8001 &
```

Without a key, a write is refused (401, not a charge, not a fake pass):

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8001/v1/cases/demo-1/signal \
  -H 'Content-Type: application/json' \
  -d '{"received_at":"2026-09-21T10:00:00Z","channel":"customer_or_integrator","received_by":"ops@example.com","description":"test","product_name":"Line 4 welder","actor":{"identifier":"ops@example.com","role":"operator"}}'
# 401
```

With the Cell key from step 1, the same request opens a real case in the
hash-chained ledger:

```bash
curl -s -X POST http://127.0.0.1:8001/v1/cases/demo-1/signal \
  -H "X-API-Key: $BUYER_KEY" -H 'Content-Type: application/json' \
  -d '{"received_at":"2026-09-21T10:00:00Z","channel":"customer_or_integrator","received_by":"ops@example.com","description":"Unexpected outbound connection","product_name":"Line 4 welder","actor":{"identifier":"ops@example.com","role":"operator"}}'
```

The response's `content_hash` and `ledger_seq` are real — they come from
`assurance.evidence.ledger.EvidenceLedger`, not an echo of what you sent.
Confirm it's really on the register:

```bash
curl -s http://127.0.0.1:8001/v1/cases -H "X-API-Key: $BUYER_KEY"
# ["demo-1"]
```

## 3. Start `/ai` and unlock the WRITE path with the SAME key

```bash
export NEURALBRIDGE_AI_STORE=./buyer-journey-ai.db
# (plus the NEURALBRIDGE_AI_PG_* vars from docs/ai-local-setup.md, and
# ASSURANCE_ACCOUNTS from step 1 — /ai reads the same account store)
uvicorn neuralbridge.main:app --port 8000 &
```

Without a key, `/ai` treats you as free/Validator — reads work
(rate-limited), a write attempt gets a real `402`, never a bare failure:

```bash
CID=$(curl -s http://127.0.0.1:8000/api/v1/ai/connections | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8000/api/v1/ai/plan \
  -H 'Content-Type: application/json' \
  -d "{\"connection_id\":\"$CID\",\"operation\":\"execute_sql\",\"params\":{\"sql\":\"SELECT 1\"}}"
# 402
```

Paste the SAME `BUYER_KEY` and the write path opens — propose, then
approve:

```bash
PLAN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/ai/plan \
  -H "X-API-Key: $BUYER_KEY" -H 'Content-Type: application/json' \
  -d "{\"connection_id\":\"$CID\",\"operation\":\"execute_sql\",\"params\":{\"sql\":\"SELECT 1\"}}")
echo "$PLAN"
PLAN_ID=$(echo "$PLAN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["plan"]["id"])')
curl -s -X POST "http://127.0.0.1:8000/api/v1/ai/plan/$PLAN_ID/approve" -H "X-API-Key: $BUYER_KEY"
```

The approve response is a real execution receipt (`provenance.mocked:
false`), audited on `GET /api/v1/ai/audit` with your key.

In the browser, `http://localhost:3000/ai` has an API-key field in the
Context pane (session-storage only — see that page's own copy for the
exact wording) that does the same thing without curl.

## 4. What you just proved

One key, minted once, unlocked:

- a real evidence-ledger write on the assurance side (`/v1/cases/.../signal`)
- the `/ai` control plane's WRITE path (plan → approve), on the platform side
- the same key also passes the entitlement gate for a non-postgres adapter
  call via the raw adapters route or the MCP gateway (see
  `src/neuralbridge/ai/guard.py`) — though most of those adapters are
  still mock/stub implementations behind that gate (see the capability
  matrix); the gate proves you're paid, not that every adapter has a real
  backend wired up yet.

## What this is not

- **No live Stripe or checkout ran.** `ASSURANCE_API_KEYS`/`AccountStore`
  is the same entitlement engine a real purchase would populate via the
  Stripe webhook (`billing_routes.py`), but nothing here talks to Stripe.
- **Not a claim that checkout is live on neuralbridge.io.** See
  `app/status/page.tsx` for the actual, honestly-stated deploy checklist —
  this doc is a local dev/demo path only.
- **Not "certified."** Nothing here implies CRA/Machinery Regulation
  certification of any kind.
