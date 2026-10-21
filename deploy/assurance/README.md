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

## Reconciliation

> **Verified against a fake transport only; run with a Stripe test-mode key
> first.** `assurance.billing.reconcile` has never been run against real Stripe.
> Its tests use an injected fake gateway and `httpx.MockTransport`. Before
> trusting it, run it dry (no `--apply`) with a `sk_test_…` key against a
> test-mode account store and read the report.

Entitlements follow webhooks, and webhooks get lost: the endpoint was down,
Stripe auto-disabled it after repeated failures, a deploy left a gap. A paying
customer then silently loses access, or a cancelled one silently keeps it.
Reconciliation compares every account that has a Stripe customer id with what
Stripe says today and reports the disagreements as one number, the **drift
count**: how many accounts (and orphan subscriptions) disagree with Stripe. It
should be 0; it is the SLI to alert on.

```bash
# report only; the account store is opened read-only
fly ssh console -C "python -m assurance.billing.reconcile"
# machine-readable, for a scheduler or an alert
fly ssh console -C "python -m assurance.billing.reconcile --json"
# correct what can be corrected safely (after reading a dry run)
fly ssh console -C "python -m assurance.billing.reconcile --apply"
```

It reads `STRIPE_SECRET_KEY` and `ASSURANCE_ACCOUNTS` from the environment like
the service does, and never prints either. Run it where the volume is (the
account store is SQLite with one writer at a time; it takes the same write lock
as the webhook for each correction). A dry run opens the store **read-only**: it
does not migrate an older database. `--apply` runs the same additive migration
the service runs at start-up. `--past-due-days N` (default 30) is how long a
`past_due` that Stripe has not recovered may stand.

`--apply` with a **live** key (`sk_live_…`/`rk_live_…`) is refused unless you also
pass `--i-have-run-this-in-test-mode`, because this tool has only been verified
against a fake transport. A live key may always dry-run.

| Exit | Meaning |
|---|---|
| 0 | every eligible account was compared and agrees with Stripe |
| 1 | drift found (with or without `--apply`: it reports what it found, then what it corrected), **or** some account was *deferred* (a newer webhook exists, so it was not compared). A deferred account is unverified, not in sync: the text says `NOT FULLY CHECKED`, and run again |
| 2 | could not run, or could not finish (no key, no store, a Stripe error). **Nothing was written.** |

The JSON carries `drift_count` and `deferred_count` separately, and
`fully_checked` (true only when nothing was deferred or unchecked). Alert on
`drift_count > 0` for a correctness problem and on a persistent
`deferred_count > 0` for an account that never gets verified.

Output lists the drift count, a count per category, and the **account ids**
affected (ids only, no email addresses, no keys). Scheduling it (a daily Fly
scheduled machine or a cron on the host) and alerting on exit 1 or 2 is the
operator's to set up; nothing here schedules it.

What it reports:

| Category | Meaning | `--apply` |
|---|---|---|
| `stripe_active_but_we_deny` | Stripe has the customer paying (or in dunning) and we block them | restores access, tier from the price id |
| `stripe_ended_but_we_grant` | Stripe's subscription is over (canceled, unpaid, expired, paused, incomplete) and we still grant a paid tier | ends the grant, **unless** the customer also has a live subscription we cannot classify (then `ambiguous`). If Stripe has **no** subscription of ours for the customer, reported for a human and not changed. A `free` account is never drift here: it is granted nothing paid |
| `tier_mismatch` | both entitled, different tier (price id → plan via `plan_for_price`) | sets the tier to the price's |
| `status_mismatch` | `active` vs `past_due`; no entitlement change, only the `/v1/me` warning | sets the status |
| `past_due_too_long` | `past_due` for more than N days and Stripe still has not recovered it. This closes the open risk that `past_due` has no local expiry. Evidence needed: our timer is over N days **and** Stripe's oldest still-**open invoice** of that subscription (`GET /v1/invoices?status=open`) is over N days old. Our timer alone is stale after a lost `active` webhook between two dunning episodes, so it never decides | status → `cancelled` (tier kept, so a later `active` restores it) only with the invoice evidence; with none (Stripe returns no open invoice) it is reported and not applied |
| `unknown_in_stripe` | the account's customer id is not known to Stripe (a test key against a live store, or the wrong account, looks exactly like this) | never |
| `stripe_subscription_without_account` | a paying subscription of ours whose customer has no account | never. **Report only**: no account and no API key is ever created here; an account comes from a signed checkout event |
| `ambiguous` | an unknown Stripe status, two live subscriptions disagreeing on the tier, a tier named only by subscription metadata (which a payload can write) rather than a price id we recognise, **or any entitled/past_due subscription on a price we do not recognise** beside the one that would be revoked (a customer on a legacy price, or who also buys another product on this Stripe account, stays `ambiguous` until a human looks) | never. Nobody is upgraded, and nobody is revoked, on an incomplete picture |

It uses the same status mapping as the webhook (`billing/subscription_state.py`),
so it cannot "correct" what the webhook set correctly.

Safety properties, each pinned by a test:

- **Dry run by default.** Only `--apply` writes. It changes `status` and `tier`
  of existing accounts and nothing else; never the operator, never an account
  with no customer id, never a sales-assigned tier (`supplier`).
- **Each correction is one transaction with its audit row** in
  `entitlement_reconciliations` (run id, account id, old and new status/tier, the
  Stripe subscription id and status, the snapshot time; no email). The table is
  created `IF NOT EXISTS`; the schema version is unchanged and an older database
  still opens.
- **A newer webhook wins.** Stripe subscriptions carry no "updated" timestamp,
  so the snapshot instant is the start of the run (or a later Stripe-side time if
  Stripe's clock is ahead, **never more than 60 seconds later**: a test clock or a
  corrupt future timestamp is clamped, because the value is written into
  `last_event_at` and a far-future one would make every real webhook look stale)
  less a 60-second skew margin. An account whose newest
  applied webhook is later is *deferred*, not compared; the check is repeated
  inside the write transaction, so a webhook that lands mid-run also wins. After
  a correction the account's `last_event_at` moves up to the snapshot, so a
  delayed older webhook retry cannot undo it.
- **All Stripe reads happen before any write.** Any Stripe error leaves the
  store untouched; the report is marked incomplete (`complete: false`, exit 2)
  and still lists what could be read. One account whose lookup fails therefore
  blocks `--apply` for the whole run until it is fixed.
- **A revocation re-reads the customer first.** Before ending a grant (including
  `past_due_too_long`), the customer's whole subscription list is read again; if
  it differs from the picture the decision was made on (a new subscription whose
  webhook was lost), that account is skipped as `changed_since_read`.
- **Idempotent.** A second `--apply` finds nothing to do. A `past_due` ended by
  this tool is not re-granted while Stripe still reports it `past_due`; it
  returns when Stripe reports `active`.

Known limits: the local `past_due_since` is the time the *webhook* first marked
the account `past_due` and is only a prefilter (Stripe's open invoice decides);
accounts marked before this change fall back to their last event time, and a
`customer.subscription.updated` that re-marks a cancelled account `past_due`
restarts the clock. "No such customer" is recognised from Stripe's 404
`resource_missing`, and the open-invoice evidence from `GET /v1/invoices`; those
response shapes are assumptions until run against Stripe. Accounts whose newest
webhook is within a minute of the run are deferred to the next run (exit 1, not
0). **Rollback:** the additive `past_due_since` column and
`entitlement_reconciliations` table are ignored by an older build, but an older
build never clears `past_due_since`, so after a rollback and a later roll-forward
an account can carry a stale value (the invoice evidence above is why that alone
cannot cut anyone off).

### Usage in the reconciliation report

`python -m assurance.billing.reconcile` also prints a **usage** section when the
store holds billable usage or pay-as-you-go is configured (`--usage` forces it;
otherwise a deployment that does not use pay-as-you-go sees the report it always
saw). It is read-only unless `--apply`, opens the store read-only on a dry run,
reads Stripe before writing anything and refuses a live key for `--apply`
without `--i-have-run-this-in-test-mode`, exactly like the rest. It lists, per
account, the pay-as-you-go drift categories below and adds its own
`usage.drift_count`; any usage drift makes the exit code 1, an unreadable
Stripe makes it 2. See the "Pay as you go" section below.

## Pay as you go (off by default)

> **Verified against a fake Stripe transport only.** No request has ever been
> made to Stripe for any of this, and nothing in the tests proves that Stripe
> behaves as the fake does. Do the founder steps below in Stripe **test mode**
> and read a dry run before believing any of it.

**What exists.** A verification operation (draft validation, separation
calculation, manifest diff, advisory check) beyond the free daily allowance can
be billed, one unit per *successful* call, for an account on the `payg` tier
that has set a monthly spend limit above zero. Cases, change cases, machine
verification, attestation and every register write are never metered.

**What is exposed.** `GET /v1/plans` lists the `payg` plan, and the pricing page
renders it with a button, **only when all of these hold**:

| Needed | Variable |
|---|---|
| a metered Stripe Price id | `ASSURANCE_PRICE_PAYG` |
| the Billing Meter's event name | `ASSURANCE_PAYG_METER_EVENT` |
| a test-mode Stripe key (a live key switches it off unless `ASSURANCE_PAYG_ALLOW_LIVE=1`) | `STRIPE_SECRET_KEY` |

Unset or half-set, `payg` is not in `/v1/plans`, `POST /v1/checkout` answers 503
`payg_not_available`, no account can be billed past its allowance, and the
reporter refuses to send. Optional: `ASSURANCE_PAYG_METER_ID` (the `mtr_…` id)
lets the reconciliation compare our totals with the meter's own.

**What the founder must do in Stripe test mode before any of it works**
(nothing here can be done from this repository):

1. Create a Billing Meter: event name = the value you will put in
   `ASSURANCE_PAYG_METER_EVENT`, `sum` aggregation, customer mapping on the
   payload key `stripe_customer_id`, value on the payload key `value`.
2. Create a **metered Price** attached to that meter, in the currency and at
   the unit price you choose. This service never learns the price; it counts
   units and Stripe multiplies. (Prices are the founder's to set.)
3. Set `ASSURANCE_PRICE_PAYG` to that Price's id, `ASSURANCE_PAYG_METER_EVENT`
   and, if you want the drift check, `ASSURANCE_PAYG_METER_ID`.
4. Make sure the customer portal allows moving between the pay-as-you-go price
   and the plans (an existing subscriber is sent to the portal, not to a second
   checkout).
5. **Schedule the reporter.** Nothing in the product runs it:

   ```bash
   fly ssh console -C "python -m assurance.billing.payg report --json"   # e.g. every 5 minutes
   fly ssh console -C "python -m assurance.billing.reconcile --json"     # daily; alert on exit 1 or 2
   ```

   Until it runs, usage accumulates unreported (never lost, never double-sent);
   the usage report shows `unreported_units` and the reconciliation flags
   `stale_unreported` after 24 hours.

   A rotated or restricted key (401/403), a wrong meter path (404) or a wrong
   meter event name (400) aborts the run with exit 2 and leaves every row
   `pending`: fix the configuration and the next run bills them. Only a refusal
   of the event itself (an unknown customer, say) marks that one event
   `rejected`, and nothing retries a rejected event by itself; once a person has
   resolved the cause, `python -m assurance.billing.payg requeue --all-rejected`
   (or `--event-id ID`, `--dry-run` to list) puts them back to `pending`.

**How a unit is counted.** At one moment only: when the route has computed its
whole answer, immediately before it returns. A 422, a refusal by the domain, or
a crash before that records nothing, and so does a request refused for quota.
The count and the quota check are one SQLite transaction
(`AccountStore.record_usage`). Send an `Idempotency-Key` header and a retry is
never counted or billed twice (the key is bound to the request: the same key
with a different body is a 409 `idempotency_key_reused` and is not served);
without one every call is its own unit. At the
limit, or when the allowance is gone and billing is not on for the account, the
API answers 429 with `Retry-After`, `resets_at` and a remedy, and records nothing.

**How a unit is reported.** `usage_events` is the outbox. The reporter claims
pending rows (marking them `sending`, before any network), sends each as one
meter event whose `identifier` and `Idempotency-Key` are our event id, and marks
it `billed` only when Stripe echoes that identifier. A crash anywhere leaves a
row the next run picks up with the same identifier, which Stripe counts once.
Stripe dedupes identifiers for "at least 24 hours"; we stop re-sending at 20 h:
a row not proven received by then becomes `ambiguous` and is **not** sent again.
`--apply` of the reconciliation settles an ambiguous row only when the meter's
total proves which way it went (equals the billed units → re-queue; equals
billed + ambiguous → mark billed).

| Usage drift category | Meaning |
|---|---|
| `provider_has_fewer_than_billed` | the meter holds less than we marked billed (Stripe dropped events after acknowledging them: it validates asynchronously) |
| `provider_has_more_than_sent` | the meter holds more than we ever sent (something else writes to it, or a double count) |
| `stale_unreported` | billable events older than 24 h still unsent: the reporter is not running |
| `needs_attention` | an event is `rejected` (Stripe refused it for good) or `ambiguous` |
| `ack_mismatch` | marked billed without Stripe echoing the identifier |
| `no_customer` | billable usage on an account with no Stripe customer |

**Known gaps (none of these are guesses to be papered over).** The
`Stripe-Version` for meter calls (`2024-09-30.acacia`), the exact response
shape of a duplicate identifier, and the event-summaries endpoint are from
Stripe's published contract as remembered, never exercised. The spend limit is
in **units per UTC calendar month**, which need not line up with a Stripe invoice
period; currency amounts are not enforced because the price lives in Stripe.
A budget alert is a flag in `GET /v1/usage`; no email is sent. A `past_due`
account is not billed further. Checkout for the `payg` tier sends a metered line
item with no quantity; that, the webhook mapping and the portal switch are
untested against Stripe.

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

Everything the service remembers is on the `/data` volume: `accounts.db` (accounts,
key hashes, billing events), `art14-register.db` (the operator-only shared
ledger) and `tenants/<account id>.db` (**one ledger per customer** — their
evidence). Backing up only the shared ledger, as an earlier version of this page
suggested, would back up none of a customer's records.

On the machine that holds the volume (single writer, so run it where the app
runs):

```bash
fly ssh console -C "python -m assurance.evidence.restore_check backup /data /data/backups/$(date +%F)"
fly ssh sftp get -r /data/backups/$(date +%F) ./backup-$(date +%F)   # off the volume, off the provider
python -m assurance.evidence.restore_check verify ./backup-$(date +%F)
```

`backup` takes a transactionally consistent snapshot of every database (a plain
file copy of a WAL database can miss its newest records). `verify` checks each
database's integrity and each ledger's hash chain, and that every tenant ledger
belongs to a known account. **Rehearse a restore before relying on it**: restore
the files to a scratch volume, point a throwaway service at them, and call
`GET /v1/ledger/verify` with a customer key. That rehearsal has not yet been
done against a deployed service — there is none.

That check answers "was anything **edited**?" and not "was anything
**removed**?" — a chain rebuilt without the inconvenient records verifies
perfectly. Closing that is what `ATTEST.md` is for, and it is the difference
between a backup and an alibi. Set `ASSURANCE_ATTEST_KEY_PEM` and put
`POST /v1/ledger/attest` on a timer before you tell a customer their evidence
is tamper-proof.
