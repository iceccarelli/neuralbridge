#!/usr/bin/env bash
# Run tests-e2e/assurance-panels.spec.ts and assurance-coverage.spec.ts (Enrol; Public intelligence; Coverage) against a
# real local API and a production Next build. Throwaway databases under $WORK; never touches a
# deployed service. Three API phases on one data dir: intel store set; store env unset; store
# file unreadable. Extra arguments go to `playwright test`.
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="${WORK:-$(mktemp -d)}"
API_PORT="${API_PORT:-8001}"; WEB_PORT="${WEB_PORT:-3000}"
PY="${PY:-python}"
export ASSURANCE_LEDGER="$WORK/operator.db" ASSURANCE_ACCOUNTS="$WORK/accounts.db" ASSURANCE_SUPPLIER_FEEDS="$WORK/supplier-feeds"
export ASSURANCE_API_KEYS="$($PY -c 'import secrets;print(secrets.token_hex(16))')"
export ASSURANCE_ALLOWED_ORIGINS="http://127.0.0.1:$WEB_PORT,http://localhost:$WEB_PORT"
export NEXT_PUBLIC_ASSURANCE_API_URL="http://127.0.0.1:$API_PORT"
export PANELS_SEED="$WORK/seed.json"
export PYTHONPATH="$PWD/src"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"
unset ASSURANCE_INTEL_STORE

for port in "$API_PORT" "$WEB_PORT"; do
  if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
    echo "port $port is already serving something; refusing to test against an unknown server" >&2; exit 2
  fi
done
$PY scripts/e2e_seed_panels.py "$PANELS_SEED" "$WORK/work"
API='' WEB=''
trap 'kill -- ${API:+-$API} ${WEB:+-$WEB} 2>/dev/null || true' EXIT
start_api() {
  if [ -n "$API" ]; then kill -- "-$API" 2>/dev/null || true; wait "$API" 2>/dev/null || true; fi
  setsid $PY -m uvicorn assurance.api.service:app --port "$API_PORT" >"$WORK/api.log" 2>&1 & API=$!
  for i in $(seq 1 30); do curl -fs "http://127.0.0.1:$API_PORT/v1/plans" >/dev/null && break; sleep 1; done
}
npx next build >"$WORK/build.log" 2>&1 || { tail -30 "$WORK/build.log" >&2; exit 3; }
setsid npx next start -p "$WEB_PORT" >"$WORK/web.log" 2>&1 & WEB=$!
for i in $(seq 1 30); do curl -fs "http://127.0.0.1:$WEB_PORT/assurance" >/dev/null && break; sleep 1; done
run() { PLAYWRIGHT_BASE_URL="http://127.0.0.1:$WEB_PORT" npx playwright test --workers=1 tests-e2e/assurance-panels.spec.ts tests-e2e/assurance-coverage.spec.ts "$@"; }
STORE="$($PY -c 'import json,os;print(json.load(open(os.environ["PANELS_SEED"]))["intel_store"])')"
BAD="$($PY -c 'import json,os;print(json.load(open(os.environ["PANELS_SEED"]))["bad_store"])')"
rc=0
ASSURANCE_INTEL_STORE="$STORE" start_api
run --grep-invert '@nostore|@badstore' "$@" || rc=1
unset ASSURANCE_INTEL_STORE
start_api
run --grep '@nostore' "$@" || rc=1
ASSURANCE_INTEL_STORE="$BAD" start_api
run --grep '@badstore' "$@" || rc=1
exit $rc
