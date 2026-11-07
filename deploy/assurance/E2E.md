# Running the browser end-to-end suite locally

`tests-e2e/` holds Playwright specs that drive the real Next.js site against the real
Assurance API, the real NeuralBridge platform API (the `/ai` control plane on PostgreSQL) and real
per-account ledgers. Nothing in either API is mocked.
CI runs them: the `e2e` job ("Browser tests (Playwright)" in the CI workflow, with its own `postgres:16` service) calls
`scripts/e2e-local.sh` (isolated Assurance API with SQLite ledgers in a temp dir, the platform API on PostgreSQL,
`next build` + `next start`, Chromium from `npx playwright install`).
Any failed spec fails the job; the report, traces and server logs are uploaded only on failure. Every spec also fails
on an uncaught page error, a console error, a failed first-party request or a 4xx/5xx first-party response
(`tests-e2e/support/fixtures.ts`; first party = the site, the Assurance API and the platform API); a spec that provokes
a refusal on purpose says so with `allowHealth({ status, url, why })`. No spec has a skip path: without the services
the script fails (exit 5 for a missing PostgreSQL), it does not pass vacuously. The job has not yet run on a GitHub-hosted runner.

## Run

```bash
npm ci --no-audit --no-fund
export NEURALBRIDGE_AI_PG_{HOST,PORT,USER,PASSWORD,TEST_DATABASE}=...   # a THROWAWAY PostgreSQL, owner may create roles
PYTHON=/path/to/python scripts/e2e-local.sh            # both projects
E2E_AI=0 PYTHON=... scripts/e2e-local.sh                # assurance-only subset, no PostgreSQL needed (on purpose)
API_PORT=18080 PLATFORM_PORT=18000 WEB_PORT=13000 PYTHON=... scripts/e2e-local.sh --reporter=list
PROJECTS=desktop-chromium SPECS=tests-e2e/site-routes.spec.ts PYTHON=... scripts/e2e-local.sh
```

`PYTHON` must be an interpreter with the repo's dependencies (FastAPI, uvicorn). The script:
makes a throwaway directory under `/var/tmp/e2e-data`, generates random keys, runs `next build`
(with `NEXT_PUBLIC_NEURALBRIDGE_API_URL` baked in) and `next start` on `WEB_PORT`, and for each Playwright project
(`desktop-chromium`, `mobile-chromium`) seeds fresh databases and starts a fresh Assurance API on `API_PORT` and a fresh
platform API (`neuralbridge.main:app`, own SQLite AI store, `NEURALBRIDGE_AI_PG_*` demo connection) on `PLATFORM_PORT`
(the specs mutate the seeded accounts, so a project cannot reuse another project's data).
`scripts/e2e_seed_ai.py` seeds the entitlements through the real `AccountStore` (the store both APIs read: Register
A and B, Cell, and a Validator account holding a real key, plus a key no account has), the shared `demo_customers`
table, and a throwaway PostgreSQL role with a random password that paid callers bind as their own connection
(`POST /api/v1/ai/connections`); it drops the role and table after each project. No bypass flag is set
(`NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID` stays unset, as in production). Server process
groups are stopped by recorded PID. It refuses a port that already serves something, sets no
Stripe key, opens no outbound connection, and exits non-zero if any project fails (data
directory kept for the logs). `scripts/e2e-assurance.sh` is the older variant (single API
for all projects, `python` from PATH).

Browser: set `PLAYWRIGHT_BROWSERS_PATH` (default `/opt/pw-browsers`), or
`PLAYWRIGHT_CHROMIUM_PATH` if the pinned `@playwright/test` cannot find its browser.

## What it covers

`/assurance` workspace (fleet, cases, advisories, supplier trust, case lifecycle, API outcomes,
checkout hand-off from a staged session), site internal links, route/status checks and the
honesty checks on public copy.

The `/ai` journey (`ai-journey`, `ai-entitlement`, `ai-race`) and the Console guided flows (`console-first-*`):
free caller reads the labelled seeded demo; a paid caller binds its own connection, proposes a write that is
NOT executed until a human approves, approves it and it executes exactly once (counted in PostgreSQL, not read
off the UI), receipt and audit; denial; another account gets 404 on the plan; approve-vs-approve and
approve-vs-deny races from two pages (the store's compare-and-set gives one winner, the other tab gets 409);
the customer database password is absent from the DOM, API bodies, requests and browser storage; the 402 upgrade
card for an anonymous and for a Validator-key caller, the 401 for an invalid key, the retry-after-pasting-a-key
loop, and the platform-unreachable state. Console: First Register case (401 / 402 / 201 and the key carrying to `/ai`)
and First Cell verification (401 / 402 / 200).

Known limits of the journey: the UI has no "bind a connection" control, so the spec binds through the product's own
route (the API call, then everything else through the UI). Page 2 of a race is shown the same plan by answering its
`POST /ai/plan` with the real response page 1 received (the product keeps plan cards in one tab's memory); the
approve/deny requests are real. The unreachable state aborts the browser's requests to the platform API.

## What it does not cover

- Checkout with live or test Stripe: a payment is *staged* through the real store, never faked
  through Stripe. No webhook signature path from Stripe is exercised.
- A deployed or hosted environment; only localhost.
- Browsers other than Chromium.
- `phase4-visual-qa.spec.ts` rewrites committed screenshots under `reports/demo/`; it is excluded in
  `playwright.config.ts` unless `E2E_VISUAL_QA=1`. Restore with `git checkout -- reports/` after running it.
