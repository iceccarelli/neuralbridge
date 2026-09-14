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

## Stripe

Create the webhook endpoint at `https://<app>.fly.dev/v1/billing/webhook`,
subscribed to:

- `checkout.session.completed` — grants the plan and mints the API key
- `customer.subscription.updated` — reactivation, and `past_due` suspension
- `customer.subscription.deleted` — downgrade to free

The signing secret Stripe shows you is `STRIPE_WEBHOOK_SECRET`. Without it the
endpoint refuses every event, which is the correct behaviour: an unverified
webhook is a way for anyone to grant themselves a subscription.

## What to check after deploying

```bash
curl https://<app>.fly.dev/                       # what the service is
curl https://<app>.fly.dev/healthz                # auth_mode must not be "open"
curl https://<app>.fly.dev/v1/plans               # purchasable must be true
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

## Backups

```bash
fly ssh console -C "sqlite3 /data/art14-register.db .dump" > ledger-$(date +%F).sql
```

The ledger is append-only and self-verifying, so a restored copy can be checked
with `GET /v1/ledger/verify` rather than trusted.
