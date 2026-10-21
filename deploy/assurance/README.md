# Deploying the assurance register

The service is one process with two SQLite files on one volume. That is a
deliberate limit, not an oversight: the evidence ledger is a hash chain, and a
second writer on a second machine forks it. Scale vertically until the stores
move to Postgres.

## fly.io

```bash
fly launch --no-deploy --copy-config --config deploy/assurance/fly.toml
fly volumes create assurance_data --size 1 --region fra

fly secrets set \
  ASSURANCE_API_KEYS="$(openssl rand -hex 24)" \
  STRIPE_SECRET_KEY=sk_test_... \
  STRIPE_WEBHOOK_SECRET=whsec_... \
  ASSURANCE_PRICE_REGISTER=price_... \
  ASSURANCE_PRICE_CELL=price_...

fly deploy --config deploy/assurance/fly.toml --dockerfile deploy/assurance/Dockerfile
```

Set `ASSURANCE_PUBLIC_URL` to the deployed hostname — checkout redirects are
built from it, and a wrong value sends paying customers to a dead page.

`ASSURANCE_ALLOWED_ORIGINS` defaults to `https://neuralbridge.io`,
`https://www.neuralbridge.io` and `http://localhost:3000` — the marketing
site's known origins. A browser enforces CORS on the *caller's* side, so
this is invisible to `curl` and to every test that isn't a real browser;
without it, the pricing page's live plan fetch, the checkout buttons and the
free Validator playground silently fail once deployed even though the API
itself works. Override with a comma-separated list only if the marketing
site is served from a different origin (a Vercel preview URL, a staging
domain).

## Stripe

Create the webhook endpoint at `https://<app>.fly.dev/v1/billing/webhook`,
subscribed to:

- `checkout.session.completed` — grants the plan and mints the API key
- `checkout.session.async_payment_succeeded` — the same grant, for delayed
  payment methods (SEPA debit): the session completes as `unpaid` and nothing
  is granted until this event says the money arrived
- `customer.subscription.updated` — reactivation, `past_due` flagging, and
  loss of entitlement for `canceled`/`unpaid`/`incomplete_expired`/`paused`/
  `incomplete`
- `customer.subscription.deleted` — downgrade to free
- `invoice.payment_failed` — flags the account `past_due`. Access **continues**
  while Stripe retries the card (a single failed payment must not cut a
  manufacturer off from a register with a 24-hour clock); `/v1/me` shows a
  `warning`. Stripe's retry schedule decides when the subscription ends, and
  says so with `customer.subscription.updated`/`deleted`. Configure that
  schedule in Stripe (Billing → Settings → Subscriptions and emails).

Deliveries are idempotent: each event id is recorded in the same transaction
as its effects, so Stripe's retries cannot mint a second key, and a
subscription event older than the newest one already applied is ignored.
A subscription event that arrives before its `checkout.session.completed` is
held for up to seven days and applied when the account exists.

The signing secret Stripe shows you is `STRIPE_WEBHOOK_SECRET`. Without it the
endpoint refuses every event, which is the correct behaviour: an unverified
webhook is a way for anyone to grant themselves a subscription.

## Connect the marketing site

The Next.js site in `app/` reads `NEXT_PUBLIC_ASSURANCE_API_URL` at **build
time** (it is inlined into the client bundle, so setting it only in
production and not preview builds is fine, but it cannot be changed without a
rebuild). Set it in Vercel → Project Settings → Environment Variables to the
deployed Fly hostname (e.g. `https://assurance-register.fly.dev`, no trailing
slash) and redeploy the site. Once set:

- The pricing section fetches `GET /v1/plans` live and shows a "Live from
  GET /v1/plans" note; without it, the page falls back to a static table
  that matches `plans.py` exactly — never a dead or stale-looking page.
- "Buy Register" / "Buy Cell" appear only when the live `purchasable` flag is
  true (i.e. the matching `ASSURANCE_PRICE_*` secret is set); otherwise the
  button stays "Talk to sales".
- The free Validator playground on the landing page calls
  `POST /v1/spec/validate` for real instead of showing "not deployed yet".

Unset (the default until this is deployed), the site never fails or shows a
broken component — it degrades to the honest static/offline state described
above.

## What to check after deploying

```bash
curl https://<app>.fly.dev/                       # what the service is
curl https://<app>.fly.dev/healthz                # auth_mode must not be "open"
curl https://<app>.fly.dev/v1/plans               # purchasable must be true
curl https://<app>.fly.dev/v1/ledger/attest/key   # 503 means no signing key set
curl -i -X OPTIONS https://<app>.fly.dev/v1/plans \
     -H 'Origin: https://neuralbridge.io' -H 'Access-Control-Request-Method: GET' \
     | grep -i access-control-allow-origin      # must echo the marketing site's origin
curl -X POST https://<app>.fly.dev/v1/spec/validate \
     -H 'content-type: application/json' \
     -d '{"track":"actively_exploited_vulnerability","stage":"early_warning",
          "payload":{"product_name":"x","member_states_available":["DE","CH"]}}'
```

The last one is the free tier, and the thing to put in front of a prospect: it
returns what is missing, what exceeds a character limit, and that Switzerland
is not an EU Member State — without an account, and recording nothing.

`/healthz` reporting `auth_mode: "open"` on a public host means
`ASSURANCE_ALLOW_UNAUTHENTICATED=1` is set and anyone can write to the
register. Unset it.

## Tenancy, proxy and request limits

**One ledger per customer account.** Every account's evidence lives in its own
SQLite file at `$ASSURANCE_TENANT_LEDGERS/<account-id>.db` (default: a
`tenants/` directory beside `ASSURANCE_LEDGER`, so `/data/tenants` on the
volume; the Dockerfile sets it explicitly). Operator keys
(`ASSURANCE_API_KEYS`) and open mode keep using the shared
`ASSURANCE_LEDGER`. Back up the whole `/data` directory, not just the shared
file, and treat `tenants/` as customer records.

Records written to the shared ledger by a customer account *before* this change
stay in the shared ledger and are not visible to that customer's key any more.
No production deployment predates this change, so no migration tool ships; if
you have one, export them with an operator key before upgrading.

**Free-tier quota behind Fly.** Behind Fly's proxy every socket peer is the
proxy, so the per-address quota would be one bucket for the whole internet. Set
`ASSURANCE_TRUST_FLY_PROXY=1` (in `fly.toml`'s `[env]`) and the quota is keyed
on `Fly-Client-IP`, which Fly's proxy sets. Set it **only** where every request
arrives through that proxy: on any other host the header is client-controlled
and would let a caller mint themselves a fresh quota per request. Without the
variable the socket peer is used, which is correct for a directly exposed host.

**Request bodies** on `/v1` writes are capped at `ASSURANCE_MAX_BODY_BYTES`
(default 1 MiB; 413 above it). `POST /v1/machine/verify` takes recorded traces
and has its own cap, `ASSURANCE_MAX_TRACE_BODY_BYTES` (default 32 MiB). The
Stripe webhook is exempt.

**Keys.** `GET /v1/keys`, `POST /v1/keys` and `POST /v1/keys/revoke` let an
account list, add and revoke its own keys (at most 10 live). Operator keys are
rotated in `ASSURANCE_API_KEYS`.

**`/healthz`** is unauthenticated and cheap: it confirms both stores open and
reports the shared ledger's entry count, and nothing about the host. Chain
verification is `GET /v1/ledger/verify`, with a key.

## Backups

```bash
fly ssh console -C "sqlite3 /data/art14-register.db .dump" > ledger-$(date +%F).sql
```

The ledger is append-only and self-verifying, so a restored copy can be checked
with `GET /v1/ledger/verify` rather than trusted.

That check answers "was anything **edited**?" and not "was anything
**removed**?" — a chain rebuilt without the inconvenient records verifies
perfectly. Closing that is what `ATTEST.md` is for, and it is the difference
between a backup and an alibi. Set `ASSURANCE_ATTEST_KEY_PEM` and put
`POST /v1/ledger/attest` on a timer before you tell a customer their evidence
is tamper-proof.
