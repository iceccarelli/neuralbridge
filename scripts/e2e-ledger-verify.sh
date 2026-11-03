#!/usr/bin/env bash
# Run tests-e2e/assurance-ledger-verify.spec.ts (the "Ledger verify" panel) against a real local
# API with a throwaway service signing key, real per-account ledgers, and a production Next build.
# Throwaway data under $WORK; never touches a deployed service. Extra args go to `playwright test`.
set -euo pipefail
cd "$(dirname "$0")/.."
WORK="${WORK:-$(mktemp -d)}"
API_PORT="${API_PORT:-8001}"; WEB_PORT="${WEB_PORT:-3000}"
PY="${PY:-python}"
export ASSURANCE_LEDGER="$WORK/operator.db" ASSURANCE_ACCOUNTS="$WORK/accounts.db"
export ASSURANCE_TENANT_LEDGERS="$WORK/tenants" ASSURANCE_ATTEST_LOGS="$WORK/attestations"
export ASSURANCE_ATTEST_KEY="$WORK/secrets/service.pem"
mkdir -p "$WORK/secrets"
export ASSURANCE_ALLOWED_ORIGINS="http://127.0.0.1:$WEB_PORT,http://localhost:$WEB_PORT"
export NEXT_PUBLIC_ASSURANCE_API_URL="http://127.0.0.1:$API_PORT"
export LEDGER_VERIFY_SEED="$WORK/seed.json"
export PYTHONPATH="$PWD/src"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"
unset ASSURANCE_API_KEYS ASSURANCE_ALLOW_UNAUTHENTICATED

for port in "$API_PORT" "$WEB_PORT"; do
  if curl -s -o /dev/null "http://127.0.0.1:$port/"; then
    echo "port $port is already serving something; refusing to test against an unknown server" >&2; exit 2
  fi
done
$PY scripts/e2e_seed_ledger_verify.py "$LEDGER_VERIFY_SEED"
API='' WEB=''
trap 'kill -- ${API:+-$API} ${WEB:+-$WEB} 2>/dev/null || true' EXIT
setsid $PY -m uvicorn assurance.api.service:app --port "$API_PORT" >"$WORK/api.log" 2>&1 & API=$!
for i in $(seq 1 30); do curl -fs "http://127.0.0.1:$API_PORT/v1/plans" >/dev/null && break; sleep 1; done
npx next build >"$WORK/build.log" 2>&1 || { tail -30 "$WORK/build.log" >&2; exit 3; }
setsid npx next start -p "$WEB_PORT" >"$WORK/web.log" 2>&1 & WEB=$!
for i in $(seq 1 30); do curl -fs "http://127.0.0.1:$WEB_PORT/assurance" >/dev/null && break; sleep 1; done
PLAYWRIGHT_BASE_URL="http://127.0.0.1:$WEB_PORT" npx playwright test --workers=1 tests-e2e/assurance-ledger-verify.spec.ts "$@"
