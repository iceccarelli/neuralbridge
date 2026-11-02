# Deploy now — rehearse in Stripe TEST mode first

**Read this first.** Nothing in this repository has been deployed. The rehearsal
tool below has never been run against a hosted staging host; it has only been
exercised against local servers in `tests/test_staging_rehearsal.py` and
`tests/test_staging_rehearsal_hardening.py`. Every step here is yours, with your
own credentials. Standing facts (`HANDOFF.md` §4.4): zero revenue, zero customers,
zero pilots, no production deployment. The prices (€390 / €3,900 / €1,290) are
unvalidated assertions, and nothing here tells you to set a live Stripe key — live
mode is a separate, later decision that is yours.

For the founder's laptop or CI with real network access. **Not for Claude Code
Remote or any sandboxed agent session**: `api.fly.io` was blocked there at the
network proxy (403 on `CONNECT`) when this was written, independent of any
token. Do not paste Fly or Stripe credentials into an agent chat.

## The rehearsal, one command per phase

`scripts/staging_rehearsal.py` needs `httpx` and this repository's `src/` (it finds
`src/` itself, from the checkout it lives in): `pip install httpx` is enough to run it
from a checkout; `pip install -e .` also works but installs far more than it needs.
Credentials and the host come **only** from environment variables; nothing secret is
accepted on the command line, and nothing secret is printed, recorded or reported (the
redactor also covers URL-, base64-, hex- and JSON-encoded forms). It refuses anything
that looks like a live Stripe key, talks only to the host you gave it (it **ignores**
`HTTP_PROXY`/`HTTPS_PROXY`: a proxy would receive your register key; put a private CA
in `REHEARSAL_CA_BUNDLE`, and run it from a network that needs no proxy), never calls
Stripe, never creates a price, product, customer, charge or checkout session, and never
sends mail.

```bash
export REHEARSAL_BASE_URL=https://<your-staging-app>.fly.dev
export STAGING_CONFIRM=<your-staging-app>.fly.dev        # webhook-test only: must equal the host
export STAGING_STRIPE_MODE=test                          # webhook-test only: your statement
read -rs STRIPE_SECRET_KEY     && export STRIPE_SECRET_KEY      # sk_test_...  (not echoed, not in history)
read -rs STRIPE_WEBHOOK_SECRET && export STRIPE_WEBHOOK_SECRET  # whsec_... from the TEST-mode endpoint
export ASSURANCE_PRICE_REGISTER=price_...  ASSURANCE_PRICE_CELL=price_...   # TEST-mode price ids
# optional: a Register-only TEST key for the 402 check
read -rs REHEARSAL_REGISTER_KEY && export REHEARSAL_REGISTER_KEY

python scripts/staging_rehearsal.py config-check --checkout-expected   # before you set Fly secrets
python scripts/staging_rehearsal.py smoke --expect-purchasable register,cell
python scripts/staging_rehearsal.py webhook-test --i-am-testing-staging
python scripts/staging_rehearsal.py restore-drill --backup-dir "$BK"   # or --data-dir DIR (service stopped)
python scripts/staging_rehearsal.py report
```

Each step prints `PASS`, `FAIL`, `UNCHECKED` or `ATTESTED`. `UNCHECKED` means a
prerequisite (an environment variable, a plain-http target where TLS was to be read, a
source to compare against) was absent, so nothing was established. `ATTESTED` means the
step rests on **your statement** or on something a shell merely lacks, not on a
measurement (a webhook secret is a TEST secret; `ASSURANCE_ALLOW_UNAUTHENTICATED` is unset
in *this* shell, which says nothing about the host — only smoke's `/healthz` `auth_mode`
observes it). Neither is ever read as a pass.

Exit code: **0** only if every step passed; **3** if any step is `UNCHECKED` or
`ATTESTED` and none failed; **1** if any step failed (including a refused live key, or the
tool itself breaking); **130** if you interrupted it. So `config-check` and `webhook-test`
exit 3 by design even when everything they can measure passed, and a plain-http target
leaves `smoke` at 3; read the lines, not only the code.

**Records.** Every phase leaves a redacted `<phase>.json` (mode 0600, in a 0700 directory) in
`--record-dir`, else `$REHEARSAL_RECORD_DIR`, else `./.rehearsal` (gitignored). It writes an
`in_progress` record when it starts, so a run that fails, is interrupted or is killed replaces
an earlier pass instead of leaving it standing. `report` writes `rehearsal-report.json` and
`rehearsal-report.md` (redacted) and trusts only a **complete** set: every step of a phase
present, state `complete`, written by this script version, no older than `--max-age-hours`
(default 6), `config-check` → `smoke` → `webhook-test` recorded in that order, and one
host across `smoke` and `webhook-test`. A phase you did not run is `UNCHECKED` there, never
skipped silently; the report lists attested items apart under "attested by the operator, not
measured".

What each phase does, and what it cannot establish:

| Phase | Does | Cannot establish |
|---|---|---|
| `config-check` | Refuses live-mode Stripe config (`sk_live_`, `rk_live_`, `pk_live_`, `ek_live_`, `whsec_live`, hyphen, case and URL/base64/hex-encoded variants, any `STRIPE*LIVE*` variable, a Stripe variable that says `live`, `ASSURANCE_PAYG_ALLOW_LIVE`) in **any** variable, used or not. Checks the *names and shapes* of the test key, webhook secret, operator keys, public URL, site origin (a placeholder or the production site fails) and the two price ids, and lists which SKUs are purchasable (price variable set — nothing is looked up or created). | What the Fly app actually holds (`fly secrets list` shows names only). That a price id exists in Stripe. A webhook secret's mode: Stripe gives test and live signing secrets the same `whsec_` shape. |
| `smoke` | `/healthz` (ok, stores open, `auth_mode` is `api_key`), `/v1/plans` equals `billing/plans.py` (except `purchasable`), 401 with no key and with a made-up key, 402 for a Register key on a Cell route (needs `REHEARSAL_REGISTER_KEY`), CORS preflight for the marketing origin and a hostile one, TLS certificate verification and days to expiry, the http→https redirect (it must go to https on **exactly the same host**), and that no response contains a provided secret (in any common encoding) or a credential-shaped string. It also *notes* which security headers it saw (the API sets none itself). Every kind of request it sends is listed in `SMOKE.md`; the single plain-http one (port 80) carries no credentials. | Browser behaviour (CORS is enforced by browsers; see `SMOKE.md`). Anything behind a login the founder did not supply. **That a price id exists:** `/v1/plans` exposes only a boolean `purchasable`, so a placeholder price id on the host (the example file ships `price_REPLACE_REGISTER`) still reads as purchasable; only a real test checkout shows the price is real. |
| `webhook-test` | Refuses unless `--i-am-testing-staging`, `STAGING_CONFIRM` equals the URL's hostname, the host is not on the deny list (`neuralbridge.io`, `www.neuralbridge.io`, the `assurance-register` Fly name in `fly.toml`, plus `REHEARSAL_PRODUCTION_HOSTS`), `STRIPE_WEBHOOK_SECRET` is `whsec_`-shaped and `STAGING_STRIPE_MODE=test` (that step is ATTESTED). The deny list is a **speed bump**: it compares hostnames (a trailing dot, a non-ASCII look-alike or an encoded form is refused outright) and **cannot see a CNAME**, an alias or a vanity domain that points at production; the `STAGING_CONFIRM` ritual and your own care are the real guard. Then: a forged signature is refused, a correctly signed synthetic `checkout.session.completed` is accepted, redelivery is a duplicate, the key is handed over exactly once (and not cacheable), it works. **The test key is revoked in a `finally`** — also on Ctrl-C or any error — and if that cannot be confirmed the step FAILs saying "a live test key may remain on the host; revoke it by prefix …" (the first ten characters of the key, nothing more). | That Stripe itself delivers to the endpoint or that the dashboard's endpoint is configured. It creates one synthetic account (`rehearsal-…@example.invalid`, customer `cus_rehearsal_…`) on the staging host; `reconcile` will report it as `unknown_in_stripe`. Use a throwaway staging volume. If the response carrying the key is lost in transit, the key cannot be named and the cleanup cannot run: check the staging account store. |
| `restore-drill` | Copies a data directory to scratch (SQLite **never opens the source**), or takes a backup you fetched; wipes a scratch volume that really held the data, restores into it, checks the restored files equal the backup byte for byte, runs `restore_check.verify` (SQLite integrity, every hash chain, every tenant ledger has an account), compares restored counts with the copy, tampers with another copy to prove the verifier notices, and finally proves the source's listing and every file hash are unchanged (no `-wal`/`-shm` left behind). Refuses symlinks, a `--work-dir` that overlaps the data, and a directory with `-wal`/`-shm`/`-journal` files (a service may be writing) unless `--i-know-the-service-is-stopped`. | That nothing was *removed* by someone who rebuilt a chain (only a signed head attestation shows that). Counts against a hosted volume when you pass only `--backup-dir` (then they are `UNCHECKED`). That a *running* service's transactional backup is consistent: a file copy of a live database can be torn, which is why the drill wants it stopped. |
| `report` | Assembles the phase records (see Records above). | Anything a phase did not run. |

## Founder-only steps

Nothing in this repository can do these; none has been done.

- [ ] Stripe **test mode**: create the Register and Cell Products and recurring Prices (the amounts are your decision; `plans.py` carries only labels). Put the two `price_…` ids in `ASSURANCE_PRICE_REGISTER` / `ASSURANCE_PRICE_CELL`.
- [ ] Stripe **test mode**: create the webhook endpoint (§3) and copy its `whsec_…` into `STRIPE_WEBHOOK_SECRET`.
- [ ] Fly: create a **staging** app and its volume (§1), set the secrets (§2), deploy, confirm exactly one machine.
- [ ] Vercel: a preview/staging deployment of the site built with `NEXT_PUBLIC_ASSURANCE_API_URL` = the staging API (§4); set `ASSURANCE_MARKETING_URL` and `ASSURANCE_ALLOWED_ORIGINS` on the API to that site's origin.
- [ ] Run the five phases above; read the report.
- [ ] The five browser checks in `SMOKE.md`, with Stripe's test card.
- [ ] In the Stripe dashboard (test mode), *Send test webhook* or complete a test checkout, to show **real** delivery rather than a synthetic signed event.
- [ ] `fly ssh console -C "python -m assurance.billing.reconcile"` (dry run) against the TEST account; read the report.
- [ ] Optional: `ASSURANCE_ATTEST_KEY_PEM` (counter-signed attestation) and `ASSURANCE_RECORDER_TRUST` (without it nothing hosted rises above `community`). Where each comes from and how to rotate or revoke: `deploy/assurance/TRUST-RUNBOOK.md`.
- [ ] Revoke any Fly token that was ever pasted into an agent chat (§0).
- [ ] Enable GitHub Pages for the docs site if you want them public (not needed for the rehearsal).
- [ ] Anything involving live Stripe keys, real cards, a production Fly app, announcing, or outreach. None of it is in this document.

## 0. Revoke any Fly token that appeared in agent chat

If a Fly.io API token was ever pasted into a Claude Code Remote session, revoke
it now at <https://fly.io/user/personal_access_tokens>. It cannot be used from
that environment, so leaving it live serves no purpose. (Whether one was pasted
is not something this repository can show; the earlier version of this file said
it had happened during "Stage B". Check your own token list.)

## 1. Deploy the API to a *staging* Fly app

`deploy/assurance/fly.toml` names the app `assurance-register` and hard-codes its
`ASSURANCE_PUBLIC_URL`. Use a copy with your staging app's name, so a rehearsal
can never touch the name a production service would get:

```bash
sed -e 's/^app = .*/app = "<your-staging-app>"/' \
    -e 's#https://assurance-register.fly.dev#https://<your-staging-app>.fly.dev#' \
    deploy/assurance/fly.toml > deploy/assurance/fly.staging.toml   # untracked (gitignored); do not commit
fly launch --no-deploy --copy-config --config deploy/assurance/fly.staging.toml
fly volumes create assurance_data --size 1 --region fra --app <your-staging-app>
```

`max_machines_running = 1` in `fly.toml` is load-bearing — do not raise it. The
evidence ledger is a hash chain; a second writer forks it. Deploy with
`--ha=false` (Fly's default may start a spare machine) and check `fly status`
shows **one** machine. *(Fly CLI behaviour is not verifiable from this
repository; check `fly deploy --help`.)* Full detail: `deploy/assurance/README.md`.

## 2. Set the secrets — TEST keys only

Every name is documented in `.env.example` under "ASSURANCE PRODUCT". **Run
`config-check` first**, with the same variables exported in your shell, so a live
key or a placeholder is caught before it reaches Fly. The two site-origin values
below are deliberately invalid until you edit them (`config-check` refuses them):

```bash
export ASSURANCE_API_KEYS="$(openssl rand -hex 24)"      # the operator key; treat as a secret
export ASSURANCE_PUBLIC_URL=https://<your-staging-app>.fly.dev
export ASSURANCE_MARKETING_URL='REPLACE_WITH_STAGING_SITE_ORIGIN'    # edit: https://<staging site>
export ASSURANCE_ALLOWED_ORIGINS='REPLACE_WITH_STAGING_SITE_ORIGIN'  # edit: the same origin
python scripts/staging_rehearsal.py config-check --checkout-expected
```

Then set them **without a secret on any command line or in a heredoc** (a value on a command
line is visible in `ps` and in shell history; bash may stage a heredoc in a temporary file;
this pipe has neither, and `grep`'s arguments are names only). `fly secrets import` reads
`NAME=value` lines on stdin *(not verified here; check `fly secrets import --help`)*:

```bash
env | grep -E '^(ASSURANCE_API_KEYS|STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|ASSURANCE_PRICE_REGISTER|ASSURANCE_PRICE_CELL|ASSURANCE_MARKETING_URL|ASSURANCE_ALLOWED_ORIGINS)=' \
  | fly secrets import --app <your-staging-app>
fly deploy --config deploy/assurance/fly.staging.toml --dockerfile deploy/assurance/Dockerfile --ha=false
```

`ASSURANCE_PUBLIC_URL` is in `fly.toml`'s `[env]` (your copy above already has the
staging hostname), not a secret. `ASSURANCE_MARKETING_URL` is where Stripe sends a
paying customer afterwards (`/checkout/success`): for a rehearsal it must be the
**staging** site, whose build points at the **staging** API, not `neuralbridge.io`.
`ASSURANCE_ALLOWED_ORIGINS` must list that same origin, or the browser silently
refuses the pricing fetch and the buy button (§6, browser checks).

## 3. Register the Stripe TEST webhook

In the Stripe dashboard, **in test mode**, create a webhook endpoint at
`https://<your-staging-app>.fly.dev/v1/billing/webhook`, subscribed to exactly the
events the handler reads (`api/billing_routes.py:post_webhook`):

- `checkout.session.completed`
- `checkout.session.async_payment_succeeded` (delayed payment methods such as SEPA debit)
- `customer.subscription.updated`
- `customer.subscription.deleted`
- `invoice.payment_failed` (flags the account `past_due`; access continues while Stripe retries)

Copy the endpoint's signing secret into `STRIPE_WEBHOOK_SECRET`. `fly secrets import`
(like `set`) restarts the machine, so no separate redeploy is needed for it.

## 4. Point a staging copy of the site at the staging API

In Vercel, for a **preview** (or staging) deployment of the `neuralbridge`
project, set:

```
NEXT_PUBLIC_ASSURANCE_API_URL = https://<your-staging-app>.fly.dev
```

This is a **build-time** variable — baked into the client bundle — so redeploy
after setting it. Do not change the Production value for a rehearsal. Until it is
set the site correctly shows its honest offline/fallback state; that is by
design. A Vercel preview URL changes per deployment unless you use a stable alias;
whichever origin you use must also be in `ASSURANCE_ALLOWED_ORIGINS` (§2).

The site links to the source repository only when `NEXT_PUBLIC_REPO_PUBLIC` is
exactly `true` (build-time; unset or anything else means no repository links, which
is right while the repository is private). Leave it unset for every deployment
until a public release; if you do flip it, also run
`NEXT_PUBLIC_REPO_PUBLIC=true python scripts/export_site_static.py` so
`public/llms.txt` and `public/.well-known/agent.json` agree.

## 5. Kill the stale `neuralbridge.vercel.app` project

Vercel-dashboard-only work; no PR can do it. Find the old "v0 Human-like Neural
Interface" project (a different Vercel project than the one this repository
deploys to) and either delete it or add a redirect from it to
`https://neuralbridge.io`. Visit `https://neuralbridge.vercel.app` afterwards and
check it no longer shows the old content. Not needed for the rehearsal.

## 6. Smoke test — the rehearsal phases, then the browser

Run the five phases in "The rehearsal, one command per phase" above. For
`restore-drill` against the hosted volume, take and fetch the backup into a directory
that exists, then pass it as `--backup-dir` (the date in the path is expanded by *your*
shell; use the exact remote path the backup command printed if the machine's date may
differ):

```bash
BK=./backup-$(date +%F); mkdir -p "$BK"
fly ssh console -C "python -m assurance.evidence.restore_check backup /data /data/backups/$(date +%F)"
fly ssh sftp get -r /data/backups/$(date +%F) "$BK"          # (fly CLI: not verified here)
```

Read the live counts on the machine with
`fly ssh console -C "python -m assurance.evidence.restore_check verify /data"` to compare
by hand; the drill alone leaves that comparison `UNCHECKED`. Locally, on any **stopped**
data directory (a copy of a development one, say), `restore-drill --data-dir DIR` checks the
counts too.

Then do the five **browser** checks in `SMOKE.md` — they prove what the tool cannot:
CORS and the JS wiring as a browser enforces them. Only when the report has no
`FAIL`, you have read every `UNCHECKED` and `ATTESTED` line and the browser checks pass is the
*staging* rehearsal done. That is still not a go-live, and not evidence that anyone will pay.

`scripts/verify-buyer-path.sh` and `docs/buyer-journey.md` check the same buyer
path against your **own local stack** (a verification aid, not a substitute for
the above): they mint a Cell key through `AccountStore` and need
`ASSURANCE_API_URL`, `NEURALBRIDGE_API_URL`, `ASSURANCE_ACCOUNTS`.

## After this

- `deploy/assurance/README.md` has the fuller reference (backups, what `/healthz`
  should say, how to check the ledger verifies); `docs/assurance/deploy.md`
  includes it.
- `deploy/assurance/ADR-0001-supplier-api.md` documents the second-payer
  (component supplier) API surface that exists in code but has no self-serve
  price yet.
- `HANDOFF.md` §5 lists what is still ahead, ordered by proximity to cash.

## Not established by any of the above

- That the Docker image builds and boots on Fly: the image's Python dependencies were
  checked (it once lacked `cryptography`, so the service could not import; see
  `tests/test_assurance_dockerfile_deps.py`, which now also imports the service in an
  interpreter that has only the image's packages), but no image has been built or run here.
- That Stripe's real API accepts the checkout session this service creates
  (`stripe_gateway.create_checkout_session`, API version `2024-06-20`): every test uses a
  fake transport. The first test-mode checkout in a browser is what shows it.
- Pay-as-you-go, reconciliation and the customer portal against real Stripe (see the
  banners in `deploy/assurance/README.md`).
- That a price id on the host is a real Stripe price (see `smoke` above).
- Anything about a real customer, price acceptance or demand.
