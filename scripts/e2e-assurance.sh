#!/usr/bin/env bash
# Run the /assurance workspace e2e against a real local API + real Next server.
# Throwaway databases under $WORK; never touches a deployed service.
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="${WORK:-$(mktemp -d)}"
API_PORT="${API_PORT:-8001}"; WEB_PORT="${WEB_PORT:-3000}"
export ASSURANCE_LEDGER="$WORK/operator.db" ASSURANCE_ACCOUNTS="$WORK/accounts.db"
export ASSURANCE_API_KEYS="$(python -c 'import secrets;print(secrets.token_hex(16))')"
export ASSURANCE_ALLOWED_ORIGINS="http://127.0.0.1:$WEB_PORT,http://localhost:$WEB_PORT"
export NEXT_PUBLIC_ASSURANCE_API_URL="http://127.0.0.1:$API_PORT"
export ASSURANCE_E2E_SEED="$WORK/seed.json"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"

PYTHONPATH=src python scripts/e2e_seed_assurance.py "$ASSURANCE_E2E_SEED" "$WORK/work"
PYTHONPATH=src python -m uvicorn assurance.api.service:app --port "$API_PORT" >"$WORK/api.log" 2>&1 & API=$!
npx next dev -p "$WEB_PORT" >"$WORK/web.log" 2>&1 & WEB=$!
trap 'kill $API $WEB 2>/dev/null || true' EXIT
for i in $(seq 1 60); do
  curl -fs "http://127.0.0.1:$API_PORT/v1/plans" >/dev/null && curl -fs "http://127.0.0.1:$WEB_PORT/assurance" >/dev/null && break
  sleep 2
done
PLAYWRIGHT_BASE_URL="http://127.0.0.1:$WEB_PORT" npx playwright test tests-e2e/assurance-workspace.spec.ts "$@"
