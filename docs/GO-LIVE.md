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

Every command below was run, as written, against a real local stack: PostgreSQL 16, a real
`assurance.api.service:app`, a real `neuralbridge.main:app`, no mocking. The output is under
**What was actually run and its output**. If a command here does not work as written, that is a bug in this
document: fix the document.

### 1. Bring up the local stack (one command)

```bash
pip install -e '.[dev]'                  # once
scripts/local-stack.sh verify            # up, scripts/verify-buyer-path.sh against it, then ALWAYS down
```

`scripts/local-stack.sh` needs a PostgreSQL server whose role may create databases (default: the documented
dev role `neuralbridge` / `neuralbridge_dev` on `127.0.0.1:5432`; override with `NEURALBRIDGE_AI_PG_HOST`,
`_PORT`, `_USER`, `_PASSWORD`). It creates its own database `nb_local_<random>`, seeds it from
`deploy/ai/seed.sql`, starts the Assurance API on `:8001` and the platform API on `:8000` sharing one
`ASSURANCE_ACCOUNTS` file, with the local-only `NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID=1` and a generated
operator key of 32 or more characters that is written `0600` and never printed. It refuses to start if a
port is already serving. `scripts/local-stack.sh up` leaves it running, `down` removes everything it made
(and only that). If PostgreSQL is not running, start it first (`pg_ctlcluster 16 main start`, or
`docker run -p 5432:5432 -e POSTGRES_USER=neuralbridge -e POSTGRES_PASSWORD=neuralbridge_dev postgres:16`).

The same stack by hand, with the exact variables it needs, is in `docs/ai-local-setup.md`. Two traps that the
earlier version of this section fell into: `ASSURANCE_API_KEYS` must be **at least 32 characters** (the service
refuses to start with a shorter key; generate one with `python -c 'import secrets; print(secrets.token_urlsafe(32))'`,
do not type one), and without `NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID=1` the `/ai` plan call in the buyer path gets a real
`403` ("demo connection is read-only"). `ASSURANCE_API_KEYS` (or `ASSURANCE_ALLOW_UNAUTHENTICATED=1` with
`ASSURANCE_HOST=127.0.0.1`) is what makes a no-key request answer `401` instead of the "instance not configured" `503`
(Failure modes table, row "auth_mode unconfigured").

Or, with a Docker daemon available: `docker compose -f docker-compose.ai.yml -f docker-compose.demo.yml up -d`
(see `docker-compose.demo.yml`'s own header). **No Docker daemon was available in the rehearsal environment**, so the
compose files were not exercised with a live `docker compose up`; the direct-uvicorn path above is what produced
every result in this document.

### 2. `scripts/verify-buyer-path.sh`

`scripts/local-stack.sh verify` runs it for you. Against a stack you started yourself with `up`:

```bash
ASSURANCE_API_URL=http://127.0.0.1:8001 \
NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
scripts/verify-buyer-path.sh
```

Must exit 0. Every step makes real HTTP requests (the script counts them and refuses to pass with fewer than
8). Checks, in order: `GET /v1/plans` returns the real tiers; `POST /v1/checkout` answers exactly `503
price_not_configured` (any other status, and above all any 2xx, fails) while no Stripe price is configured; a request
with no key gets `401` on the Assurance API and `402` on `/ai`; a Cell-tier key minted through the real `AccountStore`
opens a real register case (a real `content_hash` and `ledger_seq`) and then unlocks `/ai`'s plan then approve path
with the same key (`pending_approval`, then a receipt with `success: true`). The script uses `PYTHON` (default
`python3`) to import `assurance`; it does not start any server and exits 1 with a reason if either API is unreachable.

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

### 4. `python -m pytest tests/test_ai_buyer_journey.py -v`

```bash
NEURALBRIDGE_AI_PG_HOST=127.0.0.1 NEURALBRIDGE_AI_PG_PORT=5432 \
NEURALBRIDGE_AI_PG_USER=neuralbridge NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev \
NEURALBRIDGE_AI_PG_TEST_DATABASE=<a database you created for tests> \
NEURALBRIDGE_REQUIRE_POSTGRES=1 \
python -m pytest tests/test_ai_buyer_journey.py -v --no-cov
```

Must show 2 passed (`test_free_caller_blocked_on_both_paid_surfaces`, `test_one_cell_key_unlocks_both_paid_surfaces`)
and 0 skipped. Use `python -m pytest`, not the bare `pytest` entry point, which may bind a different interpreter.
`NEURALBRIDGE_REQUIRE_POSTGRES=1` turns a missing server into a failure instead of a skip. Needs a real PostgreSQL for the
`/ai` slice's entitlement store: there is no SQLite fallback. The test creates and drops tables inside that database, so give it
a database of its own (`python scripts/local_stack_db.py create nb_local_mytests` makes one the same way
`local-stack.sh` does). `scripts/go-live-preflight.sh` runs #2 and #4 together against a stack that is already up.

### 5. Browser tests against isolated real services (`scripts/e2e-local.sh`)

`scripts/e2e-local.sh` starts everything itself on loopback with throwaway data and random
keys: the Assurance API, the NeuralBridge platform API (PostgreSQL-backed, seeded with a free
and a paid principal through the real entitlement mechanism, no bypass flag), and a production
`next build` / `next start` of the site. It then runs the default Playwright set for the
`desktop-chromium` and `mobile-chromium` projects, each with fresh databases. A throwaway
PostgreSQL is required (`NEURALBRIDGE_AI_PG_*`; without one the script exits 5 rather than
skipping, and `E2E_AI=0` runs the assurance-only subset on purpose).

```bash
npm ci                                   # once: the Playwright browser tests and the site build need node_modules
NEURALBRIDGE_AI_PG_HOST=127.0.0.1 NEURALBRIDGE_AI_PG_PORT=5432 NEURALBRIDGE_AI_PG_USER=neuralbridge \
NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev NEURALBRIDGE_AI_PG_TEST_DATABASE=<your own throwaway database> \
scripts/e2e-local.sh
```

The PostgreSQL role must be allowed to create roles (the seed makes a random-password customer role and
drops it again). The script binds `3000` (site), `8001` (Assurance API) and `8000` (platform API) and refuses
to start if any is serving, so stop `scripts/local-stack.sh up` first, or move the e2e run with `WEB_PORT`,
`API_PORT` and `PLATFORM_PORT`. `PYTHON=/path/to/python` selects an interpreter that has the repo's dependencies
(for a checkout that is not the one `pip install -e` points at, use that checkout's own virtual environment).
It prints Playwright's own totals per project (`N passed`, and `N skipped` / `N failed` when non-zero); the run is
green only if both projects exit 0.

Every spec fails on an uncaught page error, a console error or a failed first-party request;
allow-listing is per test with a reason in code. The `/ai` journey covers connection, plan,
human approval, exactly-one execution (counted in PostgreSQL, not read off the UI), receipt,
denial, a double-approve race from two tabs, the 401/402 states, and a scan that the
credential never appears in the DOM or network responses. CI runs the same script in the
`Browser tests (Playwright)` job with a `postgres:16` service. `deploy/assurance/E2E.md` has
the per-spec detail. `phase4-visual-qa` rewrites committed screenshots and is run explicitly
with `E2E_VISUAL_QA=1`.

### 6. `scripts/rehearse-local.sh` (the whole buyer path, no credentials, no network)

Starts the real API and, with `--with-site`, the built site on loopback with a locally generated
webhook signing secret and Stripe-shaped fixture events, and walks: checkout refusing honestly
(503 `price_not_configured`) when prices are unconfigured, webhook signature accept / reject /
replay / out-of-order handling, key issuance and one-time claim, 401 vs 402 entitlement
semantics, renewal, revocation, billing recovery from `past_due`, lapsed read-only access, and a
backup, restore and verify afterwards. **It is a local rehearsal, not a hosted staging proof:** it
calls no Stripe, no Fly and no GHCR. `scripts/staging_rehearsal.py` against a hosted staging host
with Stripe test-mode credentials is still the founder step in the post-secrets half below.

Two facts it surfaced that matter for a deployment with `--workers N`: a **bound** `/ai`
connection (`POST /ai/connections`) now works from every worker, because its credential is held
encrypted in the shared store (`neuralbridge/ai/credentials.py`, claims-registry row 42), **but only
when `NEURALBRIDGE_CREDENTIAL_KEYS` (or `NEURALBRIDGE_CREDENTIAL_KEY_FILE`) and
`NEURALBRIDGE_CREDENTIAL_JOURNAL` are set**: without them `POST /ai/connections` and `/rotate`
answer 503 `credential_custody_unconfigured` (see `docs/ai-local-setup.md` for generating them;
supply the key through the host's secret store, never in the repository), and the in-memory
rate limiters multiply by the number of workers. The seeded demo connection is registered in whichever worker
serves a request. `deploy/assurance/OPS.md` section 9 has the measurements and the limits.

### What was actually run and its output (this rehearsal)

Run on 2026-11-07 in a sandbox with PostgreSQL 16 on `127.0.0.1:5432`, Python 3.13, Node 22, Chromium from
`/opt/pw-browsers`. No Docker daemon, no Stripe, no Fly, no GHCR, no PyPI and no production credential were used. Secrets were
generated per run and are not shown; output below is shortened where marked `...`.

```
$ scripts/rehearse-local.sh
[PASS] plans.none_purchasable: 3 plans, purchasable=[]
[PASS] checkout.register_refused_honestly: HTTP 503 price_not_configured; no Stripe call is possible (no key set)
[PASS] webhook.reject_missing_header: HTTP 400            ... (forged, tampered, stale, malformed: all 400, nothing granted)
[PASS] webhook.replay_is_a_noop: HTTP 200 {'handled': 'checkout.session.completed', 'duplicate': True, ...}
[PASS] claim.second_collection_410: HTTP 410
[PASS] entitlement.no_key_401: HTTP 401
[PASS] entitlement.register_key_on_cell_route_402: HTTP 402 plan_does_not_include_signed_attestation
[PASS] lifecycle.key_revocation_is_immediate: before=201, revoke HTTP 200, after=401
[PASS] lifecycle.cancelled_can_still_read_verify_export: list 200, case 200, verify 200, export 200, header=evidence-readout-only
[PASS] restore.restored_volume_serves_same_entitlements: lapsed read 200, lapsed write 402, revoked key 401
[PASS] logs.no_secret_in_server_output: server logs hold no key, token or secret and no traceback
PASS: 39/39 steps. local rehearsal, not a hosted staging proof.          # exit 0

$ scripts/rehearse-local.sh --with-site
... the same 39 steps, plus [PASS] site.served_and_buyer_pages_answer
PASS: 40/40 steps. local rehearsal, not a hosted staging proof.          # exit 0
```

```
$ scripts/local-stack.sh verify
create nb_local_<random>: ok
local-stack: up. Assurance API :8001, platform API :8000, database nb_local_<random>, data /tmp/nb-demo
== GET /v1/plans: OK (3 tiers). ==
== POST /v1/checkout: HTTP 503 price_not_configured (honest refusal: no Stripe price is configured). ==
== Free/no-key caller refused on both surfaces (401 / 402), as required. ==
== Register case write: OK ({"case_id":"verify-buyer-path-...","content_hash":"c2553...","kind":"art14.signal","ledger_seq":1,...}) ==
== /ai plan -> approve with the SAME key: OK ({"plan_id":"4d5eefe2-...","success":true,...,"provenance":{...}}) ==
== 9 real HTTP requests made (no mocks). ==
== ALL CHECKS PASSED ... ==
local-stack: verify-buyer-path.sh exit status 0
drop nb_local_<random>: ok
local-stack: down; database nb_local_<random> dropped, /tmp/nb-demo removed                # exit 0
```

The same checks were also run (each exit 0) as the documented separate commands against `scripts/local-stack.sh up`:
`scripts/verify-buyer-path.sh` (9 requests), `scripts/demo-walkthrough.sh` (ends `GOLDEN PATH COMPLETE`), and
`scripts/go-live-preflight.sh` (`verify-buyer-path.sh: PASSED`, then `tests/test_ai_buyer_journey.py ... 2 passed`, 0 skipped); and
the "by hand" block of `docs/ai-local-setup.md` was extracted and run verbatim (`VERIFY_EXIT=0`).

```
$ scripts/e2e-local.sh        (own throwaway database; ports moved to 3100/8100/8101 only because another job shared the host)
=== project desktop-chromium ===
  118 passed (5.1m)
=== project mobile-chromium ===
  118 passed (5.6m)
e2e exit status 0                  # 236 passed, 0 failed, 0 skipped, 0 flaky, no E2E_AI=0
```

Earlier runs of the same script on the same commit on the same shared 4-core host (load average 13 to 19 from other jobs)
were not clean, and are recorded because they say what the suite is sensitive to: one run failed
`assurance-lifecycle.spec.ts:103` (desktop), `ai-race.spec.ts:40` and `assurance-trust.spec.ts:207` (mobile) under load; the next
failed `assurance-checkout.spec.ts:168` in both projects with a real `429` from `POST /v1/checkout/complete`, because that route
allows 20 requests per minute per address and the checkout specs, on a fast machine, exceed it. That one is a defect of the
harness, not of the product: `scripts/e2e-local.sh` now sets `ASSURANCE_RATE_CLAIM=1000` for its throwaway API only (production
default unchanged; its behaviour is covered by `tests/test_billing_rate_limits.py`), and the run above is the first with that
change. The three load-dependent failures did not recur in the final run and were not investigated further; if
they recur on an idle machine they are real.

`docker-compose.demo.yml` was not exercised with a live `docker compose up` (no daemon). Release tooling, run locally and
not published: `actionlint` (exit 0 over all four workflows), `shellcheck` (exit 0 over the release and local-stack
scripts), `scripts/build-dist.sh --out <dir> --expect-tag v0.1.1` (exit 0: `neuralbridge_middleware-0.1.1-py3-none-any.whl` and
`.tar.gz`, `twine check --strict` PASSED for both) and with `--expect-tag v9.9.9` (exit 1, refused before building);
`scripts/verify-release.sh` without a digest prints `UNCHECKED: --digest is required` (exit 2): no image has been published, so
there is no real digest to verify.

## Evidence level of the 2026-11 assurance-hardening change set

Branch `claude/adoring-ptolemy-4x59ey`, cut from main `2b41ddb`. **Nothing here is merged to main, deployed, or configured with a
real secret.** The levels, in the order the product's own ladder uses:

| Level | Status | What was run (2026-11-12/13, sandbox: Python 3.13, Node 22, PostgreSQL 16.15, Chromium 1243, no Docker daemon) |
|---|---|---|
| Implemented locally | yes | the changes in `docs/claims-registry.md`, section "Added with the 2026-11 assurance-hardening change set" |
| Tested against a real local stack | yes | main `2b41ddb` baseline: 10,991 tests, all pass once two *environment* gaps are closed (the Postgres role needs `SUPERUSER`, as CI's image gives it; one test is skipped when run as root and passes as an unprivileged user). Integrated tree: **12,114 passed, 1 skipped (that same root-only test, which passes as `nobody`: 15 passed in its file), 0 failed**, Postgres and network-namespace gates required, `NEURALBRIDGE_REQUIRE_NODE=1`. `ruff` 0.17.5 (the newest published, inside the repo's bound) clean on `src/ tests/`; `npx tsc --noEmit` exit 0; `npm run build` exit 0; `python -m assurance capabilities --check` agrees; browser E2E `scripts/e2e-local.sh` **236 passed (118 desktop + 118 mobile), 0 failed, 0 skipped** (a first attempt ran no browser at all because the pinned Playwright wants Chromium build 1254 and the sandbox has 1243; that is a gate that did not run, and the result above is the re-run with `PLAYWRIGHT_CHROMIUM_PATH`); `scripts/local-stack.sh verify` passes (9 real HTTP requests, checkout refuses with `503 price_not_configured`); `scripts/rehearse-local.sh` 39/39 (webhook forgery/replay, key issuance, lapse, backup/verify/restore). Independent stress repo against this branch: **1,702 passed, 6 skipped, 3 failed**; see the note on the 3 below |
| Deployed to staging | **no** | `docker compose` and the Fly/Kubernetes/Helm files were not exercised (no Docker daemon, no cluster, no Fly account) |
| Deployed to production | **no** | |
| Configured with real secrets | **no** | no Stripe key or price, no service signing key, no recorder trust list |
| Available to customers | **no** | the website still says so |

**The 3 stress failures are expected drift, not a defect.** `test_live_site.py` compares the files deployed at neuralbridge.io
(`/llms.txt`, `/openapi.json`, `/.well-known/agent.json`) with this source tree. They differ because this branch changed them
and nothing is deployed (the live `llms.txt` still carries an internal deployment note the source no longer has). They pass
again when the founder deploys the site from this source; do not loosen the test.

**Behaviour changes a deployer should know about.**
* Machine verification is engine **7**. Engine-6 bundles still verify and replay under engine 6's rules, but an *older verifier*
  rejects an engine-7 bundle as an unknown engine, and every engine-6 bundle checked by this build now returns a note in `limitations`.
* A damaged row anywhere in a watch ledger now stops `watch run` / `watch status` (exit 2) instead of carrying on.
* The incident one-month Article 14 deadline is earlier than before for about 1.67% of timestamps (up to 2 d 23 h 58 min); it is computed
  at read time, so a stored case can show a filing as late that was on time under the previous reading (flagged
  `late_only_under_earliest_reading`). Nothing sealed changes.
* `POST /v1/cases/{id}/measure` and `/user-notification` now require a decider operator (an account-level key gets 403).
* A key file must be exactly one PEM block (also the hosted `X-Issuer-Public-Key` header).
* The kit no longer seals an incomplete machine as its configuration (unless `--seal-incomplete`) and reports `recorded`, not `enrolled`.
* MCP `machine_verify` no longer records anything.

**Needs a decision or an action that is not an engineering one.**
* Founder: the JSON-LD price offers, the "talk to sales" wording, `/ai` 402-versus-401, and the "MCP gateway: Supported" label
  (see the end of the new registry section). Deploying the site; merging to main.
* A qualified lawyer: the five open Article 14 questions, which every case lists (`clock.OPEN_LEGAL_QUESTIONS`). The software shows
  the rule and never replaces the due time with another reading.
* A human with the standards: the ISO/TS 15066 / ISO 13855 constants remain unverified, and `deploy/assurance/MACHINE.md` lists the
  qualified-review points.
* A human diff of the ENISA single-reporting-platform glossary: pinned v1.3, live v1.6 (21 Oct 2026).
* A Docker-capable environment: the `/data` ownership of a Fly volume for the non-root image (a root-owned volume would make
  `/healthz` answer 503) was read in code, not run.

## Deployment topology: what the code enforces and what it needs

Read this before choosing a host, a volume or a machine count. Each line says where it comes from; a line
marked *not enforced* is a constraint the operator must hold, because nothing in the code refuses the
alternative.

| Constraint | Value | Source and status |
|---|---|---|
| Storage of the evidence ledger, per-account ledgers, accounts and attestation logs | SQLite in WAL mode (`PRAGMA journal_mode=WAL`, `synchronous=FULL`), one file per ledger on **one local volume** | `src/assurance/core/sqlite.py` (`enable_wal`), `src/assurance/evidence/ledger.py`, `src/assurance/billing/accounts.py` |
| Writers per ledger inside one file | one at a time: every append is one `BEGIN IMMEDIATE` transaction that spans the read of the tail and the write, so a second writer waits (up to 30 s, then an error) and chains onto the first | `ledger.py` module docstring; `tests/test_multiworker_real.py` |
| **Machines running ledger writers** | **1.** Two machines have two volumes and two chains from genesis that each verify and disagree; `restore_check verify --against-live` finds such a fork only afterwards | `deploy/assurance/fly.toml` (`min_machines_running = max_machines_running = 1`, `auto_stop_machines = false`). *Not enforced by the application:* the code cannot see a second machine |
| Processes (`uvicorn --workers N`) on that one machine | **Tested maximum: 4**, on one host and one local filesystem (`tests/test_multiworker_real.py` starts real `--workers 4` process trees and checks 48 concurrent appends: gapless sequence, valid links, SQLite `integrity_check` ok). More than 4 workers and sustained load were **not** tested. The assurance image ships `--workers 1`, the platform image `--workers 4` | `deploy/assurance/OPS.md` section 9, `deploy/assurance/Dockerfile`, `Dockerfile`. *Not enforced:* uvicorn accepts any N |
| Shared volume, NFS, SMB, EFS, a clustered or network filesystem | **Not supported.** SQLite WAL coordinates its readers and writers through a shared-memory `-shm` file and file locks, which require every process to be on the same host and a filesystem with working locking; on a network filesystem the chain's single-writer guarantee is not available. Not tested, and no code detects or refuses it | *Not enforced.* `OPS.md` section 9 lists "SQLite on a network filesystem" under "not tested" |
| Kubernetes `replicas`, Helm `replicaCount` | The shipped `deploy/k8s/deployment.yaml` and `deploy/helm/values.yaml` now say **1** (k8s with `strategy: Recreate`, so a rollout never overlaps two writers) and mount no volume. More than one replica is not a supported topology for the ledger or the account store (and `/ai`'s own SQLite store, `NEURALBRIDGE_AI_STORE`, is per replica). They remain unexercised examples: nothing was deployed from them and no cluster was available to apply them | Warning at the top of both files; `tests/test_container_static.py::test_the_shipped_orchestrator_examples_never_run_two_ledger_writers` pins replicas 1 and Recreate |
| Platform `/ai` bound connections under `--workers N` | A **bound** connection works on every worker through the encrypted credential vault, which **fails closed**: with no `NEURALBRIDGE_CREDENTIAL_KEYS` / `NEURALBRIDGE_CREDENTIAL_JOURNAL`, binding and rotating answer 503 `credential_custody_unconfigured`. `NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS=single-worker` restores the old per-process behaviour and is refused when `WEB_CONCURRENCY` > 1 | `src/neuralbridge/ai/credentials.py`, claims-registry row 42, `OPS.md` section 9 |

### Backup consistency and restore behaviour (what is true)

- `python -m assurance.evidence.restore_check backup DATA OUT` snapshots each SQLite file with SQLite's online backup API,
  so a backup taken while the service is running is transactionally consistent per file. A plain `cp`/`rsync` of a WAL database
  can lose its newest records and is not a backup. Different files (accounts, operator ledger, each tenant ledger) are
  snapshotted one after another, not at one instant; each is internally consistent.
- It writes `backup-manifest.json` (size, SHA-256, ledger length and head link per file). The manifest is checksums, not a signature:
  keep its `manifest_sha256` somewhere the backup's holder cannot rewrite. Checkout keys that were minted but not yet collected
  (`pending_keys`) are not copied. `ops cycle` does not back up the `/ai` store (`--ai-store` is a manual option).
- `restore_check restore BACKUP TARGET` verifies the backup first and refuses (exit 1, nothing written) anything that is not
  `ok`, a non-empty target, a symlink, or a path overlapping the backup. It never overwrites a live volume. It restores into a new
  directory, re-verifies against the manifest, then renames into place. Pending or approved `/ai` plans in a restored store are voided.
- The restore drill (`OPS.md` section 4) and `scripts/rehearse-local.sh` (backup, verify, restore, a second API process on
  the restored volume) were run on one local filesystem. Not shown: that a volume-level snapshot (for example a Fly volume
  snapshot) taken under load restores cleanly (SQLite recovers a WAL after a crash, but this was not tested here, so take
  `restore_check backup` as well and drill it); an off-host copy (the operator's to make); restore time on a large volume.

### Rate limits that are per process

These counters live in the memory of one worker process and are forgotten on restart. With `W` workers the effective limit is
up to `W x limit` (for the shipped platform image, `W = 4`), and the edge limit (Fly proxy, Cloudflare, a firewall) is the operator's
to set. Safe deployment constraint until a shared limiter exists: **run one worker per machine where the limit matters, or
divide the configured limit by the worker count, and put an edge limit in front of every public route.**

| Limiter | Default | Env override | Where |
|---|---|---|---|
| `POST /v1/checkout`, per client address | 5 per 60 s | `ASSURANCE_RATE_CHECKOUT` (`<count>[/<seconds>]`, `0` off) | `src/assurance/api/billing_routes.py` |
| `POST /v1/checkout/complete` (key claim), per client address | 20 per 60 s | `ASSURANCE_RATE_CLAIM` | same |
| Stripe checkout budget, per client address | 20 per 3600 s | `ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS` | same |
| Stripe checkout budget, all callers (one counter per process) | 120 per 3600 s | `ASSURANCE_STRIPE_CHECKOUT_BUDGET` | same. Many addresses can still exhaust it |
| Unmetered machine check, per client address | 60 per 60 s | `ASSURANCE_RATE_CHECK_MACHINE` | `src/assurance/api/check_routes.py` |
| Platform router calls (adapters, `/ai`, MCP gateway), per tenant | 120 per minute | `NEURALBRIDGE_RATE_LIMIT_PER_MINUTE` (`0` off) | `src/neuralbridge/security/limits.py`, `core/router.py` |
| Platform concurrency gate: in flight globally / per adapter | 32 / 8 | `NEURALBRIDGE_MAX_CONCURRENT_CALLS`, `NEURALBRIDGE_MAX_CONCURRENT_PER_ADAPTER` | same |
| `/ai` refusal audit events (a 402/403 row is written only if a token is left): per tenant / all callers | burst 30, +12 per minute / burst 100, +30 per minute | none | `src/neuralbridge/ai/audit_events.py` |
| Machine verification admission (running + waiting + per account) | per event loop, i.e. per worker | none | `src/assurance/api/machine_routes.py` |
| Hash-chain verification cache (not a limit, but per process): the full re-walk happens at most every `ASSURANCE_CHAIN_RECHECK_SECONDS` per process, so an in-place edit of an old record is seen within that interval (default 60 s; `0` = every check) and always on export and `GET /v1/ledger/verify` | per process | `ASSURANCE_CHAIN_RECHECK_SECONDS` | `src/assurance/evidence/chain_cache.py` |

**Not** per process (shared through the files, exact across workers, covered by `test_multiworker_real.py`): the free daily
allowance of unauthenticated or Validator-tier reads (48 concurrent calls against a limit of 20 gave exactly 20 `200` and 28
`429`), entitlements, and `/ai` plan approval (executes exactly once, counted in PostgreSQL).

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
   the same thing curl-side to see the exact stuck state. The session id is `cs_...` in the success URL.
   The claim token is **not** in that URL (Stripe stores the success URL on the Checkout Session, so a token
   there would be readable by anyone with Stripe access): `POST /v1/checkout` returns it, with the
   `session_id`, in its response only, and the site keeps it in the buying tab's `sessionStorage` under
   `nb-checkout-claim:<session_id>` (per tab: a different tab, browser or device does not have it). Whoever
   saw that response, or can read that tab's `sessionStorage`, holds the token. The session id and token go in
   the BODY, never the URL:
   ```bash
   curl -s -X POST "https://<your-fly-app>.fly.dev/v1/checkout/complete" \
     -H 'content-type: application/json' \
     -d '{"session_id":"<id>","claim_token":"<token from the POST /v1/checkout response>"}'
   ```
   A `202 {"status":"pending",...}` forever means the webhook never landed —
   see the Failure modes table below. A `403` means a key is waiting but this
   caller does not hold the claim token (the success page shows this to a buyer who returns in another
   tab or on another device); a `410` means it was already collected or expired (the operator recovery
   is `python -m assurance.billing.issue_key --discard-staged <id>`, then a re-issue). An uncollected key
   is revoked, not just made unclaimable, when its 24-hour hold ends.
   Checkout is also budgeted: each client address may start at most 20 Stripe checkouts per hour
   (`ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS`, `<count>[/<seconds>]`) inside the process-wide 120 per
   hour (`ASSURANCE_STRIPE_CHECKOUT_BUDGET`); 429 with `Retry-After` either way. Both are per process, and
   many addresses can still exhaust the process-wide cap: an edge limit (Fly proxy, Cloudflare, Vercel
   firewall) is yours to set. Start-up validation checks operator-key **length in characters**, not
   entropy, and `ASSURANCE_HOST` is a **declared** value, not the address actually bound (`uvicorn
   --host` is invisible to the service; the `Dockerfile` binds `0.0.0.0`): open mode is gated on what you
   declare, so declare it truthfully.

4. **That key opens a First Register case in Console, and does an `/ai` write.**
   Not currently covered by `SMOKE.md` — added here because
   the Console `FirstCase` flow and
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

5. **Cell-tier machine-verification path.** `POST /v1/machine/verify` (`src/assurance/api/machine_routes.py`) and the
   Console's Cell verification card (anchor `#cell-verify`, `app/components/FirstCell.tsx`) exist on this branch; the
   local browser suite exercises them against the real local API (`tests-e2e/console-first-cell.spec.ts`, section 5
   above). What it does not exercise is the hosted deployment, so run this against the deployed host:
   ```bash
   curl -s -X POST https://<your-fly-app>.fly.dev/v1/machine/verify \
     -H "X-API-Key: $CELL_KEY" -H 'Content-Type: application/json' \
     -d @<a real machine-run envelope, see the schema in machine_routes.py>
   ```
   A Register-tier key must get the same `402` a free caller gets (Cell-only, per the route's own docstring); a Cell key
   must get a real `200` with a verification verdict, not a mocked one. In the browser, confirm the Console's Cell
   verification card (`/console#cell-verify`) renders that same real verdict, not a stub.

## Failure modes table

| Symptom | Root cause | Fix |
|---|---|---|
| `POST /v1/checkout` returns `503 price_not_configured` | `ASSURANCE_PRICE_REGISTER`/`ASSURANCE_PRICE_CELL` unset or pointing at a price ID that doesn't exist in the Stripe account/mode Fly is configured for (`plan.purchasable` is just `bool(price_id)`, read straight from the env var — see `src/assurance/billing/plans.py`) | `fly secrets set ASSURANCE_PRICE_REGISTER=price_... ASSURANCE_PRICE_CELL=price_...` with real **test-mode** price IDs from the correct Stripe account, then `fly deploy` (secrets need a redeploy to take, per `DEPLOY_NOW.md` §2). Re-check with `GET /v1/plans`. |
| No-key request to `POST /v1/cases/{id}/signal` returns `503` instead of the expected `401` | Neither `ASSURANCE_API_KEYS` nor `ASSURANCE_ALLOW_UNAUTHENTICATED=1` is set, so `auth_mode()` is `"unconfigured"` — `require_register` in `src/assurance/api/deps.py` refuses to guess whether the deployment intends open access or key-gated access, and 503s rather than picking one silently | Set `ASSURANCE_API_KEYS` (an operator key, comma-separated for more than one) as a Fly secret for a production deployment; `ASSURANCE_ALLOW_UNAUTHENTICATED=1` only for local/demo, never on a deployment that takes real Stripe payments |
| A paid write from the browser (Console or `/ai`) comes back `401`/`402` even though the key is valid and the plan should permit it | `CORSMiddleware` in `src/assurance/api/service.py` doesn't include the caller's origin in `allowed_origins()` (reads `ASSURANCE_ALLOWED_ORIGINS`, comma-separated; defaults to `https://neuralbridge.io`, `https://www.neuralbridge.io`, `http://localhost:3000` only — see `src/assurance/api/deps.py`) — the browser silently drops the `X-API-Key` header on the preflight-failed request, so the API sees an anonymous caller, not a rejected key. Invisible to curl/pytest; only a real browser enforces CORS preflight. `127.0.0.1:3000` also fails this even in local dev, since it's a different origin from `localhost:3000` | `fly secrets set ASSURANCE_ALLOWED_ORIGINS=https://neuralbridge.io,https://www.neuralbridge.io` (add any other real deployed origin, comma-separated, no trailing slash), redeploy. Confirm with `SMOKE.md` check #5's `OPTIONS` curl — must echo the calling origin back in `access-control-allow-origin`. |
| Checkout succeeds in Stripe but the customer never lands anywhere useful, or `success_url`/`cancel_url` point at the wrong host (e.g. `127.0.0.1:8000` in a real redirect) | `ASSURANCE_PUBLIC_URL`/`ASSURANCE_MARKETING_URL` unset or wrong — `marketing_url()` in `src/assurance/api/deps.py` defaults to `https://neuralbridge.io` only if `ASSURANCE_MARKETING_URL` is unset, and `post_checkout` builds `success_url`/`cancel_url` straight from it | `fly secrets set ASSURANCE_MARKETING_URL=https://neuralbridge.io ASSURANCE_PUBLIC_URL=https://<your-fly-app>.fly.dev`, redeploy, re-run a test checkout and confirm the redirect lands on the real success page |
| `/checkout/success` shows "not ready yet" (`202 pending`) indefinitely, even minutes after a completed Stripe payment | The Stripe webhook endpoint either isn't registered, is registered at the wrong URL, or `STRIPE_WEBHOOK_SECRET` doesn't match the endpoint's actual signing secret — `post_webhook` in `src/assurance/api/billing_routes.py` verifies the signature and silently 400s an unverified payload (Stripe then retries and eventually gives up; the key is never staged) | In the Stripe dashboard, confirm an endpoint exists at `https://<your-fly-app>.fly.dev/v1/billing/webhook` subscribed to `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted` (`DEPLOY_NOW.md` §3); confirm `STRIPE_WEBHOOK_SECRET` on Fly matches that exact endpoint's signing secret (each endpoint has its own); check Stripe's webhook delivery log for the event and its response code — a `400` there confirms a secret mismatch, not a networking problem |
