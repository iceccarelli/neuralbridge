#!/usr/bin/env bash
# Run the /assurance workspace e2e against a real local API + real Next server.
# Throwaway databases under $WORK; never touches a deployed service.
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="${WORK:-$(mktemp -d)}"
API_PORT="${API_PORT:-8001}"; WEB_PORT="${WEB_PORT:-3000}"
export ASSURANCE_LEDGER="$WORK/operator.db" ASSURANCE_ACCOUNTS="$WORK/accounts.db" ASSURANCE_SUPPLIER_FEEDS="$WORK/supplier-feeds"
export ASSURANCE_API_KEYS="$(python -c 'import secrets;print(secrets.token_hex(16))')"
export ASSURANCE_ALLOWED_ORIGINS="http://127.0.0.1:$WEB_PORT,http://localhost:$WEB_PORT"
export NEXT_PUBLIC_ASSURANCE_API_URL="http://127.0.0.1:$API_PORT"
export ASSURANCE_E2E_SEED="$WORK/seed.json"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"

for port in "$API_PORT" "$WEB_PORT"; do
  if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
    echo "port $port is already serving something; refusing to test against an unknown server" >&2
    exit 2
  fi
done

PYTHONPATH=src python scripts/e2e_seed_assurance.py "$ASSURANCE_E2E_SEED" "$WORK/work"
PYTHONPATH=src setsid python -m uvicorn assurance.api.service:app --port "$API_PORT" >"$WORK/api.log" 2>&1 & API=$!
# WEB_MODE=dev (default) serves with `next dev`; WEB_MODE=start builds for production and serves
# with `next start`, which is what ships (no dev-only origin checks, no HMR, minified client code).
# NEXT_PUBLIC_ASSURANCE_API_URL is read at build time, so it is exported above, before the build.
if [ "${WEB_MODE:-dev}" = "start" ]; then
  npx next build >"$WORK/build.log" 2>&1 || { echo "next build failed; see $WORK/build.log" >&2; tail -30 "$WORK/build.log" >&2; exit 3; }
  setsid npx next start -p "$WEB_PORT" >"$WORK/web.log" 2>&1 & WEB=$!
else
  setsid npx next dev -p "$WEB_PORT" >"$WORK/web.log" 2>&1 & WEB=$!
fi
# Each server runs in its own process group so the whole tree (npx -> next-server)
# is stopped, not just the wrapper.
trap 'kill -- -$API -$WEB 2>/dev/null || true' EXIT
for i in $(seq 1 60); do
  curl -fs "http://127.0.0.1:$API_PORT/v1/plans" >/dev/null && curl -fs "http://127.0.0.1:$WEB_PORT/assurance" >/dev/null && break
  sleep 2
done
# Account E's fleet arrives through the real `assurance watch push`, over HTTP.
PYTHONPATH=src python scripts/e2e_seed_assurance.py "$ASSURANCE_E2E_SEED" "$WORK/work" --report "http://127.0.0.1:$API_PORT"
# Workspace, advisories, checkout hand-off, the API client's outcomes, and the site's internal links.
# One worker: the specs share one API, one set of seeded accounts and one dev server.
PLAYWRIGHT_BASE_URL="http://127.0.0.1:$WEB_PORT" npx playwright test --workers=1 \
  tests-e2e/assurance-workspace.spec.ts tests-e2e/assurance-advisories.spec.ts \
  tests-e2e/assurance-checkout.spec.ts tests-e2e/assurance-outcomes.spec.ts tests-e2e/assurance-lifecycle.spec.ts \
  tests-e2e/assurance-trust.spec.ts \
  tests-e2e/site-links.spec.ts "$@"
