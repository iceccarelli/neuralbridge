# Running the browser end-to-end suite locally

`tests-e2e/` holds Playwright specs that drive the real Next.js site against the real
Assurance API and real per-account ledgers. Nothing in the assurance API is mocked.
CI runs them: the `e2e` job ("Browser tests (Playwright)" in the CI workflow) calls `scripts/e2e-local.sh`
(isolated API with SQLite ledgers in a temp dir, `next build` + `next start`, Chromium from `npx playwright install`).
Any failed spec fails the job; the report, traces and server logs are uploaded only on failure. Every spec also fails
on an uncaught page error, a console error, a failed first-party request or a 4xx/5xx first-party response
(`tests-e2e/support/fixtures.ts`); a spec that provokes a refusal on purpose says so with
`allowHealth({ status, url, why })`. The `/ai` specs need the platform API and a seeded Postgres and are not in the
default set. The job has not yet run on a GitHub-hosted runner.

## Run

```bash
npm ci --no-audit --no-fund
PYTHON=/path/to/python scripts/e2e-local.sh            # both projects, ~9 minutes
API_PORT=18080 WEB_PORT=13000 PYTHON=... scripts/e2e-local.sh --reporter=list
PROJECTS=desktop-chromium SPECS=tests-e2e/site-routes.spec.ts PYTHON=... scripts/e2e-local.sh
```

`PYTHON` must be an interpreter with the repo's dependencies (FastAPI, uvicorn). The script:
makes a throwaway directory under `/var/tmp/e2e-data`, generates random keys, runs `next build`
and `next start` on `WEB_PORT`, and for each Playwright project (`desktop-chromium`,
`mobile-chromium`) seeds fresh databases and starts a fresh API on `API_PORT` (the specs
mutate the seeded accounts, so a project cannot reuse another project's data). Server process
groups are stopped by recorded PID. It refuses a port that already serves something, sets no
Stripe key, opens no outbound connection, and exits non-zero if any project fails (data
directory kept for the logs). `scripts/e2e-assurance.sh` is the older variant (single API
for all projects, `python` from PATH).

Browser: set `PLAYWRIGHT_BROWSERS_PATH` (default `/opt/pw-browsers`), or
`PLAYWRIGHT_CHROMIUM_PATH` if the pinned `@playwright/test` cannot find its browser.

## What it covers

`/assurance` workspace (fleet, cases, advisories, supplier trust, case lifecycle, API outcomes,
checkout hand-off from a staged session), site internal links, route/status checks and the
honesty checks on public copy. Optional specs (`ai*`, `console-first-*`, `phase3-*`) skip
unless their own prerequisites exist (the /ai Postgres control plane, a paid test key).

## What it does not cover

- Checkout with live or test Stripe: a payment is *staged* through the real store, never faked
  through Stripe. No webhook signature path from Stripe is exercised.
- A deployed or hosted environment; only localhost.
- Browsers other than Chromium.
- `phase4-visual-qa.spec.ts` rewrites committed screenshots under `reports/demo/`; it is excluded in
  `playwright.config.ts` unless `E2E_VISUAL_QA=1`. Restore with `git checkout -- reports/` after running it.
