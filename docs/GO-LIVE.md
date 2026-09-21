# Go-live rehearsal — Phase 5

Two halves, strictly ordered. **Do not start the post-secrets half until every
check in the preflight half passes.** The preflight half needs no Stripe key,
no Fly account, and no live secret of any kind — it proves the code is
honest; the post-secrets half proves the deployment is.

This doc extends `DEPLOY_NOW.md` and `SMOKE.md` — it does not repeat their
command sequences. `DEPLOY_NOW.md` is the Fly/Stripe deploy runbook;
`SMOKE.md` is the five-check browser smoke test to run after every deploy;
this doc is what to run *before* touching Fly or Stripe, plus what to add to
`SMOKE.md`'s post-secrets pass for the two things it doesn't cover (the
Console/`{ai}` buyer flow end-to-end, and the Cell-tier machine-verification
path landing in parallel).

## Preflight (no secrets, run anywhere)

All four items below were executed in this rehearsal against a real local
stack — Postgres 16, a real `assurance.api.service:app`, a real
`neuralbridge.main:app`, no mocking anywhere. Exact output is under
**What was actually run and its output**.

### 1. Bring up the local stack

```bash
# Postgres (adjust to however Postgres runs in your environment)
pg_ctlcluster 16 main start   # or: docker run -p 5432:5432 postgres:16

# One-time: create the role/db docs/ai-local-setup.md documents
psql -h 127.0.0.1 -U postgres -c \
  "CREATE ROLE neuralbridge LOGIN PASSWORD 'neuralbridge_dev';"
psql -h 127.0.0.1 -U postgres -c \
  "CREATE DATABASE neuralbridge_ai OWNER neuralbridge;"
psql -h 127.0.0.1 -U postgres -c \
  "CREATE DATABASE neuralbridge_ai_test OWNER neuralbridge;"
PGPASSWORD=neuralbridge_dev psql -h 127.0.0.1 -U neuralbridge \
  -d neuralbridge_ai -f deploy/ai/seed.sql

pip install -e '.[dev]'

# Assurance API — ASSURANCE_API_KEYS (or ASSURANCE_ALLOW_UNAUTHENTICATED=1)
# is required for a no-key request to come back 401 instead of a "this
# instance isn't configured at all" 503 — see the Failure modes table below,
# row "auth_mode unconfigured".
ASSURANCE_LEDGER=/tmp/nb-demo/art14.db \
ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
ASSURANCE_API_KEYS=local-operator-key \
uvicorn assurance.api.service:app --host 127.0.0.1 --port 8001 &

# /ai API (same ASSURANCE_ACCOUNTS path — this is what makes one key work
# on both surfaces)
NEURALBRIDGE_AI_PG_HOST=127.0.0.1 NEURALBRIDGE_AI_PG_PORT=5432 \
NEURALBRIDGE_AI_PG_USER=neuralbridge NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev \
NEURALBRIDGE_AI_PG_DATABASE=neuralbridge_ai \
ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
uvicorn neuralbridge.main:app --host 127.0.0.1 --port 8000 &
```

Or, with a Docker daemon available: `docker compose -f docker-compose.ai.yml
-f docker-compose.demo.yml up -d` (see `docker-compose.demo.yml`'s own
header). **This rehearsal had no Docker daemon available**, same constraint
`reports/NEURALBRIDGE-FIRST-EURO.md` already logged — the compose file was
not exercised with a live `docker compose up` here either. The direct-uvicorn
path above was used instead and is what produced every result in this doc.

### 2. `scripts/verify-buyer-path.sh`

```bash
ASSURANCE_API_URL=http://127.0.0.1:8001 \
NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
./scripts/verify-buyer-path.sh
```

Must exit 0. Checks, in order: `GET /v1/plans` returns the real tiers;
`POST /v1/checkout` refuses honestly (4xx/5xx, never a fabricated checkout
URL) when no Stripe price is configured; a Cell-tier key minted through the
real `AccountStore` opens a real register case and then unlocks `/ai`'s
plan→approve path with the same key.

### 3. `scripts/demo-walkthrough.sh` (optional, same shape as #2 with screenshots-pack framing)

```bash
ASSURANCE_API_URL=http://127.0.0.1:8001 \
NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
./scripts/demo-walkthrough.sh
```

Covers the same golden path as #2 via `scripts/seed_demo.py`, with `GET
/v1/cases` cross-checked. Redundant with #2 for a go-live gate — run either,
not required to run both — kept here because it's the one
`docker-compose.demo.yml`'s `seed` job also calls.

### 4. `pytest tests/test_ai_buyer_journey.py -v`

```bash
NEURALBRIDGE_AI_PG_HOST=127.0.0.1 NEURALBRIDGE_AI_PG_PORT=5432 \
NEURALBRIDGE_AI_PG_USER=neuralbridge NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev \
NEURALBRIDGE_AI_PG_TEST_DATABASE=neuralbridge_ai_test \
pytest tests/test_ai_buyer_journey.py -v --no-cov
```

Must show 2 passed (`test_free_caller_blocked_on_both_paid_surfaces`,
`test_one_cell_key_unlocks_both_paid_surfaces`). Needs a real Postgres for
the `/ai` slice's entitlement store — there is no SQLite fallback for this
test file, so a founder without Postgres locally cannot run it and should
rely on CI or a throwaway `postgres:16` container instead.

### 5. Playwright smoke (`tests-e2e/*.spec.ts`)

**Not run in this rehearsal.** `playwright.config.ts` needs a live Next dev
server on `:3000` plus both APIs above, and this rehearsal's sandbox was a
shared, multi-tenant container already running other work on the same
ports/filesystem — driving a browser against it here would have produced
results contaminated by unrelated sessions, not a clean read on this branch.
Run it yourself, on a single-tenant machine, with the stack from step 1 up
and `npm run dev` also running on `:3000`:

```bash
npx playwright install --with-deps chromium   # once, if not already installed
npx playwright test
```

Expect all five specs to pass (`ai.spec.ts`, `ai-entitlement.spec.ts`,
`console-first-case.spec.ts`, `phase3-first-euro.spec.ts`,
`phase4-visual-qa.spec.ts`) — `phase3-first-euro.spec.ts` has a
Postgres-backed sub-case that self-skips without a local Postgres (see
`reports/NEURALBRIDGE-PHASE4-SURFACE.md`'s note on that). Note from
`reports/NEURALBRIDGE-PHASE4-SURFACE.md`: run against `http://localhost:3000`,
not `http://127.0.0.1:3000` — the assurance API's CORS allowlist defaults to
`localhost` only (`ASSURANCE_ALLOWED_ORIGINS`), so `127.0.0.1` fails CORS in
a real browser even though the backend is healthy.

### What was actually run and its output (this rehearsal)

Local stack: Postgres 16 (`neuralbridge`/`neuralbridge_dev`@`neuralbridge_ai`
and `neuralbridge_ai_test`), `assurance.api.service:app` on `:8011` (moved
off the documented `:8001` only because this shared sandbox already had
another process bound there — no code or config reason), `neuralbridge.main:app`
on `:8000`.

```
$ ASSURANCE_API_URL=http://127.0.0.1:8011 \
  NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
  ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
  ./scripts/verify-buyer-path.sh
== 1. GET /v1/plans — the real, enforced pricing table ==
== GET /v1/plans: OK (3 tiers). ==
== 2. POST /v1/checkout refuses honestly without a real Stripe price configured ==
== POST /v1/checkout: HTTP 503 (honest refusal, as expected on an instance with no Stripe price configured). ==
== 3. Register + /ai golden path with a real Cell-tier fixture key ==
== Minted a real Cell-tier fixture key via AccountStore. ==
== Free/no-key caller refused on both surfaces (401 / 402), as required. ==
== Register case write: OK ({"case_id":"verify-buyer-path-4224","content_hash":"ccd1db97eb...","kind":"art14.signal","ledger_seq":1,...}) ==
== /ai plan -> approve with the SAME key: OK ({"plan_id":"fcfb5816-...","success":true,...,"provenance":{...,"mocked":false},...}) ==
== ALL CHECKS PASSED — plans is real, checkout refuses honestly without Stripe, and one Cell-tier key opens both paid surfaces. ==
$ echo $?
0
```

```
$ NEURALBRIDGE_AI_PG_HOST=127.0.0.1 NEURALBRIDGE_AI_PG_PORT=5432 \
  NEURALBRIDGE_AI_PG_USER=neuralbridge NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev \
  NEURALBRIDGE_AI_PG_TEST_DATABASE=neuralbridge_ai_test \
  pytest tests/test_ai_buyer_journey.py -v --no-cov
tests/test_ai_buyer_journey.py::TestGoldenOneKeyTwoSurfaces::test_free_caller_blocked_on_both_paid_surfaces PASSED [ 50%]
tests/test_ai_buyer_journey.py::TestGoldenOneKeyTwoSurfaces::test_one_cell_key_unlocks_both_paid_surfaces PASSED [100%]
======================== 2 passed, 2 warnings in 0.92s =========================
```

(A first attempt with the default `--cov` flags on produced a spurious error
on the second test's teardown — a coverage-report file contention from
another process writing to this same shared checkout at the same time, not a
real test failure. `--no-cov` reproduces cleanly; note this if CI ever shows
the same one-off error with no code change behind it.)

`docker-compose.demo.yml`: not exercised with a live `docker compose up` —
no Docker daemon in this rehearsal's environment (`docker compose version`
answers, but there is no daemon behind it here). `docker compose -f
docker-compose.ai.yml -f docker-compose.demo.yml config` was run and
succeeded cleanly (exit 0, valid merged config — no daemon needed for that
command), confirming the overlay is at least syntactically sound; that is
not the same as a real `up`, so still worth a founder or CI run with an
actual daemon before relying on it as the canonical demo path.

Playwright: not run (see item 5 above — reason given, not skipped silently).

## Post-secrets checklist (founder's own machine only)

Everything below needs real Stripe test-mode keys/price IDs and a deployed
API — do this only after every preflight check above passes, and only with
your own Stripe test-mode account, never this sandbox. It extends
`SMOKE.md`'s five browser checks; where a check already lives in `SMOKE.md`
it is cross-referenced, not repeated.

1. **Plans show `purchasable: true`** (extends `SMOKE.md` #1/#2).
   ```bash
   curl -s https://<your-fly-app>.fly.dev/v1/plans | python3 -m json.tool
   ```
   Register and Cell must each show `"purchasable": true` once
   `ASSURANCE_PRICE_REGISTER`/`ASSURANCE_PRICE_CELL` are set as Fly secrets
   (`purchasable` is computed from `price_id`, which reads straight from
   those env vars — see `src/assurance/billing/plans.py`). If either is
   still `false`, the pricing page will still show "Talk to sales" instead
   of "Buy" — that is `SMOKE.md` check #2's own symptom for the same root
   cause.

2. **Create and complete a Stripe test-mode checkout session.**
   ```bash
   curl -s -X POST https://<your-fly-app>.fly.dev/v1/checkout \
     -H 'Content-Type: application/json' \
     -d '{"tier":"register","email":"you@yourcompany.com","company":"Rehearsal"}'
   ```
   Must return a real `checkout_url` (a `checkout.stripe.com` link), not a
   503. Open it, pay with `4242 4242 4242 4242` (any future expiry/CVC) —
   this is `SMOKE.md` check #4, run from curl first so a checkout failure is
   diagnosed before it's a browser mystery.

3. **Confirm the webhook fires and a key appears on the success page.**
   After paying, `https://neuralbridge.io/checkout/success?session_id=...`
   should show a key within a few seconds (`SMOKE.md` #4's own pass
   condition). If it instead keeps showing "not ready yet" past ~30s, poll
   the same thing curl-side to see the exact stuck state:
   ```bash
   curl -s "https://<your-fly-app>.fly.dev/v1/checkout/complete?session_id=<id>"
   ```
   A `202 {"status":"pending",...}` forever means the webhook never landed —
   see the Failure modes table below.

4. **That key opens a First Register case in Console, and does an `/ai` write.**
   Not currently covered by `SMOKE.md` — added here because
   `reports/NEURALBRIDGE-PHASE4-SURFACE.md`'s Console `FirstCase` flow and
   the `/ai` write path are both real paid surfaces a buyer reaches within
   minutes of paying.
   - In a browser, go to `/console#first-case` (or follow the
     `/checkout/success` deep link, which pre-fills the key). Submit the
     guided first case. Must return a real `content_hash`/`ledger_seq`, not
     a 401/402/503 and not a client-side fake success.
   - Paste the same key into `/ai`'s key field, propose a write, approve it.
     Must return a real execution receipt (`provenance.mocked: false`).
   - curl equivalent, if the browser result is ambiguous — same calls
     `docs/buyer-journey.md` and `scripts/verify-buyer-path.sh` already use,
     just against the live host and the real key from step 3 instead of a
     locally-minted fixture key:
     ```bash
     curl -s -X POST https://<your-fly-app>.fly.dev/v1/cases/first-case/signal \
       -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
       -d '{"received_at":"...","channel":"customer_or_integrator","received_by":"you@yourcompany.com","description":"go-live check","product_name":"...","actor":{"identifier":"you@yourcompany.com","role":"operator"}}'
     ```

5. **Cell-tier machine-verification path** (Agent C's parallel work —
   `POST /v1/machine/verify` and the Console's Cell verification card,
   expected anchor `#cell-verify`; not present in this branch as of this
   rehearsal, so this step is written for whenever that PR lands, not
   re-verified here).
   ```bash
   curl -s -X POST https://<your-fly-app>.fly.dev/v1/machine/verify \
     -H "X-API-Key: $CELL_KEY" -H 'Content-Type: application/json' \
     -d @<a real machine-run envelope — see machine_routes.py's schema>
   ```
   A Register-tier key must get the same `402` a free caller gets (Cell-only,
   per `src/assurance/api/machine_routes.py`'s own docstring: "`POST
   /v1/machine/verify` is the product. It needs the Cell plan."); a Cell key
   must get a real `200` with a verification verdict, not a mocked one. In
   the browser, confirm the Console's Cell verification card (`#cell-verify`
   once that surface ships) renders the same real verdict, not a stub.
   **Do not sign off this step until Agent C's PR has actually merged** —
   until then, `/v1/machine/verify` on `main` is unaffected by this
   rehearsal and this step is a placeholder, not a passed check.

## Failure modes table

| Symptom | Root cause | Fix |
|---|---|---|
| `POST /v1/checkout` returns `503 price_not_configured` | `ASSURANCE_PRICE_REGISTER`/`ASSURANCE_PRICE_CELL` unset or pointing at a price ID that doesn't exist in the Stripe account/mode Fly is configured for (`plan.purchasable` is just `bool(price_id)`, read straight from the env var — see `src/assurance/billing/plans.py`) | `fly secrets set ASSURANCE_PRICE_REGISTER=price_... ASSURANCE_PRICE_CELL=price_...` with real **test-mode** price IDs from the correct Stripe account, then `fly deploy` (secrets need a redeploy to take, per `DEPLOY_NOW.md` §2). Re-check with `GET /v1/plans`. |
| No-key request to `POST /v1/cases/{id}/signal` returns `503` instead of the expected `401` | Neither `ASSURANCE_API_KEYS` nor `ASSURANCE_ALLOW_UNAUTHENTICATED=1` is set, so `auth_mode()` is `"unconfigured"` — `require_register` in `src/assurance/api/deps.py` refuses to guess whether the deployment intends open access or key-gated access, and 503s rather than picking one silently | Set `ASSURANCE_API_KEYS` (an operator key, comma-separated for more than one) as a Fly secret for a production deployment; `ASSURANCE_ALLOW_UNAUTHENTICATED=1` only for local/demo, never on a deployment that takes real Stripe payments |
| A paid write from the browser (Console or `/ai`) comes back `401`/`402` even though the key is valid and the plan should permit it | `CORSMiddleware` in `src/assurance/api/service.py` doesn't include the caller's origin in `allowed_origins()` (reads `ASSURANCE_ALLOWED_ORIGINS`, comma-separated; defaults to `https://neuralbridge.io`, `https://www.neuralbridge.io`, `http://localhost:3000` only — see `src/assurance/api/deps.py`) — the browser silently drops the `X-API-Key` header on the preflight-failed request, so the API sees an anonymous caller, not a rejected key. Invisible to curl/pytest; only a real browser enforces CORS preflight. `127.0.0.1:3000` also fails this even in local dev, since it's a different origin from `localhost:3000` (see `reports/NEURALBRIDGE-PHASE4-SURFACE.md`) | `fly secrets set ASSURANCE_ALLOWED_ORIGINS=https://neuralbridge.io,https://www.neuralbridge.io` (add any other real deployed origin, comma-separated, no trailing slash), redeploy. Confirm with `SMOKE.md` check #5's `OPTIONS` curl — must echo the calling origin back in `access-control-allow-origin`. |
| Checkout succeeds in Stripe but the customer never lands anywhere useful, or `success_url`/`cancel_url` point at the wrong host (e.g. `127.0.0.1:8000` in a real redirect) | `ASSURANCE_PUBLIC_URL`/`ASSURANCE_MARKETING_URL` unset or wrong — `marketing_url()` in `src/assurance/api/deps.py` defaults to `https://neuralbridge.io` only if `ASSURANCE_MARKETING_URL` is unset, and `post_checkout` builds `success_url`/`cancel_url` straight from it | `fly secrets set ASSURANCE_MARKETING_URL=https://neuralbridge.io ASSURANCE_PUBLIC_URL=https://<your-fly-app>.fly.dev`, redeploy, re-run a test checkout and confirm the redirect lands on the real success page |
| `/checkout/success` shows "not ready yet" (`202 pending`) indefinitely, even minutes after a completed Stripe payment | The Stripe webhook endpoint either isn't registered, is registered at the wrong URL, or `STRIPE_WEBHOOK_SECRET` doesn't match the endpoint's actual signing secret — `post_webhook` in `src/assurance/api/billing_routes.py` verifies the signature and silently 400s an unverified payload (Stripe then retries and eventually gives up; the key is never staged) | In the Stripe dashboard, confirm an endpoint exists at `https://<your-fly-app>.fly.dev/v1/billing/webhook` subscribed to `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted` (`DEPLOY_NOW.md` §3); confirm `STRIPE_WEBHOOK_SECRET` on Fly matches that exact endpoint's signing secret (each endpoint has its own); check Stripe's webhook delivery log for the event and its response code — a `400` there confirms a secret mismatch, not a networking problem |
