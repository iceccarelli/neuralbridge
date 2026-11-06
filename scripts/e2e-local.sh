#!/usr/bin/env bash
# Reproducible local run of the Playwright e2e suite against a REAL local API + a production
# `next build` / `next start` site. Self-contained: throwaway data dir, throwaway random keys,
# no Stripe keys, no services other than the two local ports. Ports and data dir are configurable
# and a port that is already serving something is refused, so it can run beside another checkout.
#
#   PYTHON=/path/to/python scripts/e2e-local.sh [extra playwright args]
#
# Env (all optional): PYTHON (default python; must have the repo's deps), API_PORT (8001),
#   WEB_PORT (3000), E2E_ROOT (default /var/tmp/e2e-data; a fresh run.XXXXXX dir is made under it),
#   SPECS (space-separated spec paths; default = the set scripts/e2e-assurance.sh runs),
#   PROJECTS (default "desktop-chromium mobile-chromium"; each gets fresh databases and API),
#   PLAYWRIGHT_CHROMIUM_PATH (only if the pinned @playwright/test cannot find its browser),
#   E2E_REPORT_DIR (copy playwright-report/ and test-results/ of each FAILED project there; CI uploads it),
#   KEEP_WORK=1 to keep the data dir after a passing run (kept automatically on failure).
# Exit status: 0 only if every project passed; 2 = port busy; 3 = build failed; 4 = seed/servers failed.
# Server process groups are stopped by recorded PID, never by pattern.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
PYTHON="${PYTHON:-python}"
API_PORT="${API_PORT:-8001}"; WEB_PORT="${WEB_PORT:-3000}"
E2E_ROOT="${E2E_ROOT:-/var/tmp/e2e-data}"
mkdir -p "$E2E_ROOT"
WORK="$(mktemp -d "$E2E_ROOT/run.XXXXXX")"
PIDFILE="$WORK/pids"; : >"$PIDFILE"
KEEP="${KEEP_WORK:-0}"
API_PID=''

export PYTHONPATH="$ROOT/src" PYTHONDONTWRITEBYTECODE=1
export ASSURANCE_E2E_PYTHON="$PYTHON"   # specs shell out to the CLI; same interpreter as the API
export ASSURANCE_ALLOWED_ORIGINS="http://127.0.0.1:$WEB_PORT,http://localhost:$WEB_PORT"
export NEXT_PUBLIC_ASSURANCE_API_URL="http://127.0.0.1:$API_PORT"
export PLAYWRIGHT_BASE_URL="http://127.0.0.1:$WEB_PORT"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/opt/pw-browsers}"
unset STRIPE_SECRET_KEY STRIPE_WEBHOOK_SECRET

cleanup() {
  # setsid makes each recorded pid its own process-group id: stop the whole tree by that id.
  while read -r p; do [ -n "$p" ] && kill -- "-$p" 2>/dev/null; done <"$PIDFILE"
  if [ "$KEEP" = 1 ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

for port in "$API_PORT" "$WEB_PORT"; do
  if curl -s -o /dev/null --max-time 3 "http://127.0.0.1:$port/"; then
    echo "port $port is already serving something; refusing to test against an unknown server" >&2; exit 2
  fi
done

# NEXT_PUBLIC_ASSURANCE_API_URL is baked in at build time, hence exported above.
if ! npx next build >"$WORK/build.log" 2>&1; then
  echo "next build failed; tail of $WORK/build.log:" >&2; tail -30 "$WORK/build.log" >&2; KEEP=1; exit 3
fi
setsid npx next start -p "$WEB_PORT" >"$WORK/web.log" 2>&1 &
echo $! >>"$PIDFILE"

# The specs mutate the seeded accounts (cases opened, keys issued) and assume a pristine seed, so
# each Playwright project gets its own fresh databases, keys and API process.
start_api() {  # $1 = project name
  local d="$WORK/$1" up=0
  mkdir -p "$d"
  export ASSURANCE_LEDGER="$d/operator.db" ASSURANCE_ACCOUNTS="$d/accounts.db" ASSURANCE_SUPPLIER_FEEDS="$d/supplier-feeds"
  ASSURANCE_API_KEYS="$("$PYTHON" -c 'import secrets;print(secrets.token_hex(16))')"; export ASSURANCE_API_KEYS
  export ASSURANCE_E2E_SEED="$d/seed.json"
  if ! "$PYTHON" scripts/e2e_seed_assurance.py "$ASSURANCE_E2E_SEED" "$d/work" >"$d/seed.log" 2>&1; then
    cat "$d/seed.log" >&2; return 4
  fi
  setsid "$PYTHON" -m uvicorn assurance.api.service:app --port "$API_PORT" >"$d/api.log" 2>&1 &
  API_PID=$!; echo "$API_PID" >>"$PIDFILE"
  for _ in $(seq 1 60); do
    if curl -fs "http://127.0.0.1:$API_PORT/v1/plans" >/dev/null && curl -fs "http://127.0.0.1:$WEB_PORT/assurance" >/dev/null; then up=1; break; fi
    sleep 2
  done
  if [ "$up" != 1 ]; then echo "servers did not come up; see $d/api.log and $WORK/web.log" >&2; return 4; fi
  # Account E's fleet arrives through the real `assurance watch push`, over HTTP.
  if ! "$PYTHON" scripts/e2e_seed_assurance.py "$ASSURANCE_E2E_SEED" "$d/work" --report "http://127.0.0.1:$API_PORT" >>"$d/seed.log" 2>&1; then
    cat "$d/seed.log" >&2; return 4
  fi
}

SPECS="${SPECS:-tests-e2e/assurance-workspace.spec.ts tests-e2e/assurance-advisories.spec.ts tests-e2e/assurance-checkout.spec.ts tests-e2e/assurance-outcomes.spec.ts tests-e2e/assurance-lifecycle.spec.ts tests-e2e/assurance-trust.spec.ts tests-e2e/site-links.spec.ts tests-e2e/site-routes.spec.ts tests-e2e/site-honesty.spec.ts}"
rc=0
for proj in ${PROJECTS:-desktop-chromium mobile-chromium}; do
  echo "=== project $proj ==="
  start_api "$proj" || { KEEP=1; exit 4; }
  # shellcheck disable=SC2086
  if ! npx playwright test --workers=1 --project="$proj" $SPECS "$@"; then
    rc=1
    # Playwright clears test-results/ and playwright-report/ at the start of every run, so the
    # second project would erase the first one's traces. Keep each failed project's own copy.
    if [ -n "${E2E_REPORT_DIR:-}" ]; then
      mkdir -p "$E2E_REPORT_DIR/$proj"
      cp -r playwright-report test-results "$E2E_REPORT_DIR/$proj/" 2>/dev/null || true
    fi
  fi
  kill -- "-$API_PID" 2>/dev/null; wait "$API_PID" 2>/dev/null
done
[ "$rc" = 0 ] || KEEP=1
echo "e2e exit status $rc (data dir: $WORK)"
exit "$rc"
