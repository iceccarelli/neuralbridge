#!/usr/bin/env bash
# Sales demo pack — the golden path, end to end, against a REAL local
# stack (real Postgres, real assurance API, real /ai API). No mocking, no
# live Stripe, no fabricated output: every step either prints a real
# response or the script fails loudly (set -e) and stops rather than
# printing a fake receipt for a step that didn't happen.
#
# What this proves, in order:
#   1. Free caller is refused on both paid surfaces (401 / 402 — real
#      gates, not a 200 with an error string).
#   2. A Cell-tier key, minted through the real AccountStore (via
#      scripts/seed_demo.py), opens a real case on the hash-chained
#      ledger — content_hash/ledger_seq come back real.
#   3. The SAME key unlocks /ai's WRITE path: propose -> 402 without the
#      key, 200 pending_approval with it, approve -> a real execution
#      receipt.
#
# Usage:
#   ASSURANCE_API_URL=http://127.0.0.1:8001 \
#   NEURALBRIDGE_API_URL=http://127.0.0.1:8000/api/v1 \
#   ASSURANCE_ACCOUNTS=/tmp/nb-demo/accounts.db \
#   ./scripts/demo-walkthrough.sh
#
# Requires: the two APIs already running (see docs/ai-local-setup.md /
# docker-compose.ai.yml + docker-compose.demo.yml), curl, python3.

set -euo pipefail

ASSURANCE_API_URL="${ASSURANCE_API_URL:-http://127.0.0.1:8001}"
NEURALBRIDGE_API_URL="${NEURALBRIDGE_API_URL:-http://127.0.0.1:8000/api/v1}"
ASSURANCE_ACCOUNTS="${ASSURANCE_ACCOUNTS:?Set ASSURANCE_ACCOUNTS to the shared account store path (e.g. /tmp/nb-demo/accounts.db)}"
DEMO_CASE_ID="${DEMO_CASE_ID:-walkthrough-case-1}"

log() { echo "== $* ==" >&2; }
fail() { echo "FAILED: $*" >&2; exit 1; }

log "0. Confirming both APIs are actually up"
curl -sf -o /dev/null "$ASSURANCE_API_URL/v1/plans" || fail "assurance API not reachable at $ASSURANCE_API_URL — start it first (see docs/ai-local-setup.md)"
curl -sf -o /dev/null "$NEURALBRIDGE_API_URL/ai/connections" || fail "/ai API not reachable at $NEURALBRIDGE_API_URL — start it first"
log "Both APIs reachable."

log "1. Free caller is refused on both paid surfaces"
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$ASSURANCE_API_URL/v1/cases/$DEMO_CASE_ID/signal" \
  -H 'Content-Type: application/json' \
  -d '{"received_at":"2026-09-21T10:00:00Z","channel":"customer_or_integrator","received_by":"ops@example.com","description":"free-caller probe","product_name":"Line 4 welder","actor":{"identifier":"ops@example.com","role":"operator"}}')
[ "$STATUS" = "401" ] || fail "expected 401 opening a case with no key, got $STATUS"
log "Assurance write with no key: $STATUS (refused, as required)."

CID=$(curl -sf "$NEURALBRIDGE_API_URL/ai/connections" | python3 -c 'import sys,json;print(json.load(sys.stdin)[0]["id"])')
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$NEURALBRIDGE_API_URL/ai/plan" \
  -H 'Content-Type: application/json' \
  -d "{\"connection_id\":\"$CID\",\"operation\":\"execute_sql\",\"params\":{\"sql\":\"UPDATE demo_customers SET plan='register' WHERE id=1\"}}")
[ "$STATUS" = "402" ] || fail "expected 402 proposing a write with no key, got $STATUS"
log "/ai write with no key: $STATUS (refused, as required)."

log "2. Minting a Cell-tier key and opening a sample case (scripts/seed_demo.py)"
KEY=$(DEMO_CASE_ID="$DEMO_CASE_ID" ASSURANCE_ACCOUNTS="$ASSURANCE_ACCOUNTS" ASSURANCE_API_URL="$ASSURANCE_API_URL" python3 scripts/seed_demo.py | tail -1)
[ -n "$KEY" ] || fail "seed_demo.py did not print a key"
log "Minted key: ${KEY:0:12}... (truncated)"

log "Confirming the case is really on the register (not just echoed back)"
CASES=$(curl -sf "$ASSURANCE_API_URL/v1/cases" -H "X-API-Key: $KEY")
echo "$CASES" | grep -q "$DEMO_CASE_ID" || fail "case $DEMO_CASE_ID not found on GET /v1/cases: $CASES"
log "GET /v1/cases confirms: $CASES"

log "3. Same key unlocks /ai's WRITE path"
PLAN=$(curl -sf -X POST "$NEURALBRIDGE_API_URL/ai/plan" \
  -H "X-API-Key: $KEY" -H 'Content-Type: application/json' \
  -d "{\"connection_id\":\"$CID\",\"operation\":\"execute_sql\",\"params\":{\"sql\":\"SELECT 1\"}}")
echo "$PLAN" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d["plan"]["status"]=="pending_approval", d' \
  || fail "plan did not come back pending_approval: $PLAN"
PLAN_ID=$(echo "$PLAN" | python3 -c 'import sys,json;print(json.load(sys.stdin)["plan"]["id"])')
log "Plan $PLAN_ID pending_approval."

RECEIPT=$(curl -sf -X POST "$NEURALBRIDGE_API_URL/ai/plan/$PLAN_ID/approve" -H "X-API-Key: $KEY")
echo "$RECEIPT" | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d.get("success") is True, d'
log "Approve receipt: $RECEIPT"

log "GOLDEN PATH COMPLETE — one Cell-tier key, both paid surfaces, real ledger writes and a real execution receipt."
