# Deploy now

For the founder's laptop or CI with real network access. **Not for Claude Code
Remote or any sandboxed agent session** — `api.fly.io` is blocked there at
the network proxy level (403 on `CONNECT`), independent of any token. Do not
paste Fly tokens into an agent chat to try to work around this; it will not
work, and the token will just be sitting there unused.

Do these in order. Each step names the exact command and what "done" looks
like — no step is optional, and skipping one silently breaks a later one.

## 0. Revoke any Fly token that appeared in agent chat

If a Fly.io API token was ever pasted into a Claude Code Remote session (it
was, during Stage B — see that session's transcript), revoke it now at
<https://fly.io/user/personal_access_tokens>. It could not be used from that
environment, so leaving it live serves no purpose and is a real credential
sitting somewhere it does not need to.

## 1. Deploy the API to Fly.io

From a machine with real network access:

```bash
cd neuralbridge
fly launch --no-deploy --copy-config --config deploy/assurance/fly.toml
fly volumes create assurance_data --size 1 --region fra
```

`max_machines_running = 1` in `deploy/assurance/fly.toml` is load-bearing —
do not raise it. The evidence ledger is a hash chain; a second writer forks
it. Full detail: `deploy/assurance/README.md`.

## 2. Set the Fly secrets

Every name below is documented in `.env.example` under "ASSURANCE PRODUCT",
alongside what each one does and what happens when it's left unset — that
file is the full reference; this is the exact command. Replace `REPLACE_*`
and `sk_live_...`/`whsec_...`/`price_...` with real values — no other code
change is needed.

```bash
fly secrets set \
  ASSURANCE_API_KEYS="$(openssl rand -hex 24)" \
  STRIPE_SECRET_KEY=sk_live_... \
  STRIPE_WEBHOOK_SECRET=whsec_... \
  ASSURANCE_PRICE_REGISTER=price_... \
  ASSURANCE_PRICE_CELL=price_... \
  ASSURANCE_ALLOWED_ORIGINS="https://neuralbridge.io,https://www.neuralbridge.io" \
  ASSURANCE_MARKETING_URL="https://neuralbridge.io"
```

Get the Stripe price IDs from the "Grimaldi Engineering Sandbox" account
(`acct_1Th7Xc0yoqnS42mn`) for testing, or the live Stripe account for real
money — do not mix them. `ASSURANCE_ALLOWED_ORIGINS` defaults to the right
values already, but set it explicitly here so it is not silently relying on
a default someone might change later.

```bash
fly deploy --config deploy/assurance/fly.toml --dockerfile deploy/assurance/Dockerfile
```

Set `ASSURANCE_PUBLIC_URL` to the deployed Fly hostname (e.g.
`https://assurance-register.fly.dev`) as a secret too — checkout redirects
that go wrong send paying customers to a dead page.

## 3. Register the Stripe webhook

In the Stripe dashboard (same account whose keys you set in step 2), create
a webhook endpoint at `https://<your-fly-app>.fly.dev/v1/billing/webhook`,
subscribed to:

- `checkout.session.completed`
- `customer.subscription.updated`
- `customer.subscription.deleted`

Copy the signing secret it shows you into `STRIPE_WEBHOOK_SECRET` (step 2) if
you have not already, and redeploy (`fly deploy`) if you set it after the
first deploy.

## 4. Point the marketing site at the live API

In Vercel → the `neuralbridge` project → Settings → Environment Variables,
set:

```
NEXT_PUBLIC_ASSURANCE_API_URL = https://<your-fly-app>.fly.dev
```

This is a **build-time** variable — it gets baked into the client bundle.
Set it for Production (and Preview if you want previews to hit the live API
too), then trigger a redeploy of the marketing site. Until this is set, the
site correctly shows its honest offline/fallback state everywhere — that is
by design, not a bug to work around.

## 5. Kill the stale `neuralbridge.vercel.app` project

This is Vercel-dashboard-only work; no PR can do it. Find the old "v0
Human-like Neural Interface" project (a different Vercel project than the one
this repository deploys to) and either delete it or, if you want the URL to
keep working, add a redirect from it to `https://neuralbridge.io`. Confirm
by visiting `https://neuralbridge.vercel.app` afterward and checking it no
longer shows the fabricated old content.

## 6. Smoke test — do this before telling anyone the site is live

See `SMOKE.md` for the five browser checks (live plans, Buy appears,
playground Validate, checkout success, CORS). If all five pass, the product
takes real money. If any fails, do not announce it as live — go back to the
matching step above.

## After this

- `deploy/assurance/README.md` has the fuller reference (backups, what
  `/healthz` should say, how to check the ledger verifies).
- `deploy/assurance/ADR-0001-supplier-api.md` documents the second-payer
  (component supplier) API surface that exists in code but has no self-serve
  price yet — read it before deciding whether/how to sell that tier.
- HANDOFF.md §5 has the fuller list of what is still ahead of this, ordered
  by proximity to cash.
