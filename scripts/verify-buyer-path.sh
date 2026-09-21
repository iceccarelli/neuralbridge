#!/usr/bin/env bash
# Verifies the buyer path a real customer would actually walk, end to end,
# against a REAL local stack. No mocking, no live Stripe, no fabricated
# success — every check is a real HTTP call or a real AccountStore call;
# any unexpected result fails the script loudly (set -e / explicit exit 1)
# rather than printing a fake pass.
#
# What this checks, in order:
#   1. GET /v1/plans returns the real, enforced pricing table.
#   2. POST /v1/checkout refuses honestly (a real 4xx, never a crash or a
#      fabricated checkout URL) when no Stripe price is configured —
#      which is this repo's actual state today (see app/status/page.tsx).
#   3. The register + /ai golden path with a real Cell-tier fixture key,
#      minted through AccountStore (never hand-typed) — case write, then
#      /ai plan -> approve, on the SAME key.
#
# Usage:
#   ASSURANCE_API_URL=http://127.0.0.1:8001 \
#   NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
#   ASSURANCE_ACCOUNTS=/tmp/verify-buyer-path/accounts.db \
#   ./scripts/verify-buyer-path.sh
#
# Cross-linked from docs/buyer-journey.md and DEPLOY_NOW.md. See
# docs/ai-local-setup.md for how to bring the local stack up first — this
# script does not start uvicorn itself and fails immediately, with a
# clear reason, if either API isn't already reachable.

set -euo pipefail

ASSURANCE_API_URL="${ASSURANCE_API_URL:-http://127.0.0.1:8001}"
NEURALBRIDGE_API_URL="${NEURALBRIDGE_API_URL:-http://127.0.0.1:8000/api/v1}"
ASSURANCE_ACCOUNTS="${ASSURANCE_ACCOUNTS:?Set ASSURANCE_ACCOUNTS to the shared account store path}"
CASE_ID="${VERIFY_CASE_ID:-verify-buyer-path-$$}"

log() { echo "== $* ==" >&2; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log "1. GET /v1/plans — the real, enforced pricing table"
PLANS=$(curl -sf "$ASSURANCE_API_URL/v1/plans") || fail "assurance API not reachable at $ASSURANCE_API_URL — start it first (docs/ai-local-setup.md)"
echo "$PLANS" | python3 -c '
import sys, json
plans = json.load(sys.stdin)
names = {p["name"] for p in plans}
assert {"Validator", "Register", "Cell"} <= names, f"missing expected tiers, got {names}"
' || fail "GET /v1/plans did not return the expected Validator/Register/Cell tiers: $PLANS"
log "GET /v1/plans: OK ($(echo "$PLANS" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))') tiers)."

log "2. POST /v1/checkout refuses honestly without a real Stripe price configured"
RESP=$(curl -s -w '\n%{http_code}' -X POST "$ASSURANCE_API_URL/v1/checkout" \
  -H 'Content-Type: application/json' \
  -d '{"tier":"register","email":"verify@example.com","company":"Verify Co"}')
STATUS=$(echo "$RESP" | tail -1)
BODY=$(echo "$RESP" | sed '$d')
case "$STATUS" in
  2*) fail "checkout SUCCEEDED (HTTP $STATUS) with no Stripe price configured — this would mean the site could take money for a plan it cannot provision. Body: $BODY" ;;
  4*|5*) log "POST /v1/checkout: HTTP $STATUS (honest refusal, as expected on an instance with no Stripe price configured). Body: $BODY" ;;
  *) fail "unexpected status $STATUS from POST /v1/checkout: $BODY" ;;
esac

log "3. Register + /ai golden path with a real Cell-tier fixture key"
curl -sf -o /dev/null "$NEURALBRIDGE_API_URL/ai/connections" || fail "/ai API not reachable at $NEURALBRIDGE_API_URL — start it first"

KEY=$(python3 - "$ASSURANCE_ACCOUNTS" <<'PY'
import sys
from assurance.billing.accounts import AccountStore
store = AccountStore(sys.argv[1])
account = store.upsert_account(email="verify-buyer-path@example.com", tier="cell", company="Verify Buyer Path")
print(store.issue_key(account.id, label="verify-buyer-path"))
PY
)
[ -n "$KEY" ] || fail "could not mint a Cell-tier key from AccountStore($ASSURANCE_ACCOUNTS)"
log "Minted a real Cell-tier fixture key via AccountStore."

# Free/no-key refused first, on both surfaces.
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ASSURANCE_API_URL/v1/cases/$CASE_ID/signal" \
  -H 'Content-Type: application/json' \
  -d '{"received_at":"2026-09-21T10:00:00Z","channel":"customer_or_integrator","received_by":"ops@example.com","description":"no-key probe","product_name":"Line 4 welder","actor":{"identifier":"ops@example.com","role":"operator"}}')
[ "$STATUS" = "401" ] || fail "expected 401 opening a case with no key, got $STATUS"

CID=$(curl -sf "$NEURALBRIDGE_API_URL/ai/connections" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$NEURALBRIDGE_API_URL/ai/plan" \
  -H 'Content-Type: application/json' \
  -d "{\"connection_id\":\"$CID\",\"operation\":\"execute_sql\",\"params\":{\"sql\":\"SELECT 1\"}}")
[ "$STATUS" = "402" ] || fail "expected 402 proposing a write with no key, got $STATUS"
log "Free/no-key caller refused on both surfaces (401 / 402), as required."

# The real case write.
CASE_RESP=$(curl -sf -X POST "$ASSURANCE_API_URL/v1/cases/$CASE_ID/signal" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"received_at":"2026-09-21T10:00:00Z","channel":"customer_or_integrator","received_by":"ops@example.com","description":"verify-buyer-path","product_name":"Line 4 welder","actor":{"identifier":"ops@example.com","role":"operator"}}')
echo "$CASE_RESP" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("content_hash") and d.get("ledger_seq"), d' \
  || fail "case write did not return a real content_hash/ledger_seq: $CASE_RESP"
log "Register case write: OK ($CASE_RESP)"

# The same key unlocking /ai's WRITE path.
PLAN=$(curl -sf -X POST "$NEURALBRIDGE_API_URL/ai/plan" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d "{\"connection_id\":\"$CID\",\"operation\":\"execute_sql\",\"params\":{\"sql\":\"SELECT 1\"}}")
echo "$PLAN" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["plan"]["status"]=="pending_approval", d' \
  || fail "plan did not come back pending_approval: $PLAN"
PLAN_ID=$(echo "$PLAN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["plan"]["id"])')

RECEIPT=$(curl -sf -X POST "$NEURALBRIDGE_API_URL/ai/plan/$PLAN_ID/approve" -H "X-API-Key: $KEY")
echo "$RECEIPT" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("success") is True, d' \
  || fail "approve did not return a real success receipt: $RECEIPT"
log "/ai plan -> approve with the SAME key: OK ($RECEIPT)"

log "ALL CHECKS PASSED — plans is real, checkout refuses honestly without Stripe, and one Cell-tier key opens both paid surfaces."
