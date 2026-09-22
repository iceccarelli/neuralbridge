#!/usr/bin/env bash
# Go-live preflight — the no-secrets half of docs/GO-LIVE.md, wrapped in one
# script. Requires a real local stack already up (this script does not start
# uvicorn/Postgres itself, and fails loudly with a clear reason if either API
# isn't reachable — see docs/GO-LIVE.md §Preflight step 1 for how to bring
# the stack up first).
#
# What this runs, in order, against the REAL local stack — no mocking, no
# live Stripe, no fabricated pass:
#   1. scripts/verify-buyer-path.sh — plans, checkout's honest refusal, and
#      the register + /ai golden path with a real Cell-tier fixture key.
#   2. pytest tests/test_ai_buyer_journey.py -v --no-cov — needs a real
#      Postgres for the /ai slice's entitlement store; this script does not
#      substitute a fake pass if Postgres is unreachable, it fails and says
#      so.
#
# Playwright is deliberately NOT wrapped here: it needs a live Next dev
# server on :3000, which this script cannot safely assume or start without
# risking colliding with whatever else is already running on that port (see
# docs/GO-LIVE.md's note on running it in a shared environment). Run it
# yourself: npx playwright test.
#
# Usage:
#   ASSURANCE_API_URL=http://127.0.0.1:8001 \
#   NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
#   ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
#   NEURALBRIDGE_AI_PG_HOST=127.0.0.1 NEURALBRIDGE_AI_PG_PORT=5432 \
#   NEURALBRIDGE_AI_PG_USER=neuralbridge NEURALBRIDGE_AI_PG_PASSWORD=neuralbridge_dev \
#   NEURALBRIDGE_AI_PG_TEST_DATABASE=neuralbridge_ai_test \
#   ./scripts/go-live-preflight.sh

set -euo pipefail

ASSURANCE_API_URL="${ASSURANCE_API_URL:-http://127.0.0.1:8001}"
NEURALBRIDGE_API_URL="${NEURALBRIDGE_API_URL:-http://127.0.0.1:8000/api/v1}"
ASSURANCE_ACCOUNTS="${ASSURANCE_ACCOUNTS:?Set ASSURANCE_ACCOUNTS to the shared account store path (e.g. /tmp/nb-demo/accounts.db)}"
NEURALBRIDGE_AI_PG_HOST="${NEURALBRIDGE_AI_PG_HOST:?Set NEURALBRIDGE_AI_PG_HOST (e.g. 127.0.0.1) — the /ai pytest slice needs a real Postgres, no SQLite fallback}"
NEURALBRIDGE_AI_PG_PORT="${NEURALBRIDGE_AI_PG_PORT:-5432}"
NEURALBRIDGE_AI_PG_USER="${NEURALBRIDGE_AI_PG_USER:?Set NEURALBRIDGE_AI_PG_USER}"
NEURALBRIDGE_AI_PG_PASSWORD="${NEURALBRIDGE_AI_PG_PASSWORD:?Set NEURALBRIDGE_AI_PG_PASSWORD}"
NEURALBRIDGE_AI_PG_TEST_DATABASE="${NEURALBRIDGE_AI_PG_TEST_DATABASE:-neuralbridge_ai_test}"

log() { echo "== $* ==" >&2; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log "0. Confirming both APIs are actually up before running anything"
curl -sf -o /dev/null "$ASSURANCE_API_URL/v1/plans" \
  || fail "assurance API not reachable at $ASSURANCE_API_URL — bring up the local stack first (docs/GO-LIVE.md §Preflight step 1)"
curl -sf -o /dev/null "$NEURALBRIDGE_API_URL/ai/connections" \
  || fail "/ai API not reachable at $NEURALBRIDGE_API_URL — bring up the local stack first"
log "Both APIs reachable."

log "1. scripts/verify-buyer-path.sh"
ASSURANCE_API_URL="$ASSURANCE_API_URL" \
NEURALBRIDGE_API_URL="$NEURALBRIDGE_API_URL" \
ASSURANCE_ACCOUNTS="$ASSURANCE_ACCOUNTS" \
"$(dirname "$0")/verify-buyer-path.sh" \
  || fail "verify-buyer-path.sh did not pass — see its own output above for which check failed"
log "verify-buyer-path.sh: PASSED"

log "2. pytest tests/test_ai_buyer_journey.py -v --no-cov (needs real Postgres)"
NEURALBRIDGE_AI_PG_HOST="$NEURALBRIDGE_AI_PG_HOST" \
NEURALBRIDGE_AI_PG_PORT="$NEURALBRIDGE_AI_PG_PORT" \
NEURALBRIDGE_AI_PG_USER="$NEURALBRIDGE_AI_PG_USER" \
NEURALBRIDGE_AI_PG_PASSWORD="$NEURALBRIDGE_AI_PG_PASSWORD" \
NEURALBRIDGE_AI_PG_TEST_DATABASE="$NEURALBRIDGE_AI_PG_TEST_DATABASE" \
python3 -m pytest tests/test_ai_buyer_journey.py -v --no-cov \
  || fail "pytest tests/test_ai_buyer_journey.py did not pass — see pytest output above. If the failure is a Postgres connection error, this is not a code regression, it means NEURALBRIDGE_AI_PG_* is wrong or Postgres isn't reachable, not that the buyer journey is broken."
log "pytest tests/test_ai_buyer_journey.py: PASSED"

log "PREFLIGHT PASSED — verify-buyer-path.sh and the /ai pytest slice both passed against the real local stack."
log "This does NOT cover Playwright (needs a live Next dev server — run 'npx playwright test' yourself, see docs/GO-LIVE.md) or anything in docs/GO-LIVE.md's post-secrets checklist (Stripe/Fly, founder-only)."
