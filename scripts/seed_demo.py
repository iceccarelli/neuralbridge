"""Seed a demo Cell-tier account and a sample Register case for the sales
demo pack (reports/demo/, scripts/demo-walkthrough.sh,
docker-compose.demo.yml).

Real, not fixture-shaped: it mints the key through the exact same
``AccountStore`` class (``assurance.billing.accounts.AccountStore``) the
Stripe webhook uses for a paying customer (see
``src/assurance/api/billing_routes.py``'s ``handle_stripe_webhook``), the
same path ``tests/test_ai_buyer_journey.py`` and ``docs/buyer-journey.md``
already use — no test-only shortcut, no hand-typed key literal.

Env (all match the rest of this repo's own conventions):

  ASSURANCE_ACCOUNTS     path to the SQLite account store (required)
  ASSURANCE_API_URL      base URL of a running assurance API, to open the
                         sample case through the real HTTP route rather
                         than writing the ledger directly
                         (default: http://127.0.0.1:8001)
  DEMO_CASE_ID           case id to open (default: demo-case-1)

Usage:
    python scripts/seed_demo.py

Prints the minted key to stdout as the last line so a caller can capture
it (``KEY=$(python scripts/seed_demo.py | tail -1)``). Everything else
goes to stderr. Exits non-zero and prints the real error if the account
store can't be opened or the sample case can't be opened over HTTP — no
fake "seeded" message on a step that didn't actually happen.
"""

from __future__ import annotations

import os
import sys

import httpx

from assurance.billing.accounts import AccountStore

DEMO_EMAIL = "demo-buyer@example.com"
DEMO_COMPANY = "Acme Robotics (demo)"
DEMO_CASE_ID = os.environ.get("DEMO_CASE_ID", "demo-case-1")


def _log(msg: str) -> None:
    print(msg, file=sys.stderr)


def main() -> int:
    accounts_path = os.environ.get("ASSURANCE_ACCOUNTS")
    if not accounts_path:
        _log("ASSURANCE_ACCOUNTS is not set — refusing to seed against the default path silently.")
        return 1

    api_url = os.environ.get("ASSURANCE_API_URL", "http://127.0.0.1:8001")

    _log(f"Minting a Cell-tier demo key via AccountStore({accounts_path!r}) ...")
    store = AccountStore(accounts_path)
    account = store.upsert_account(email=DEMO_EMAIL, tier="cell", company=DEMO_COMPANY)
    key = store.issue_key(account.id, label="sales-demo-pack")
    _log(f"Minted key for account {account.id} (tier=cell).")

    _log(f"Opening sample case {DEMO_CASE_ID!r} on {api_url} with the minted key ...")
    try:
        resp = httpx.post(
            f"{api_url}/v1/cases/{DEMO_CASE_ID}/signal",
            headers={"X-API-Key": key},
            json={
                "received_at": "2026-09-21T10:00:00Z",
                "channel": "customer_or_integrator",
                "received_by": "ops@example.com",
                "description": "Unexpected outbound connection from line controller (sales demo seed)",
                "product_name": "Line 4 welder",
                "actor": {"identifier": "ops@example.com", "role": "operator"},
            },
            timeout=10,
        )
    except httpx.HTTPError as exc:
        _log(f"FAILED to reach {api_url}: {exc}")
        _log("The demo key was minted, but the sample case was NOT opened. Not reporting fake success.")
        return 1

    if resp.status_code == 409:
        _log(f"Case {DEMO_CASE_ID!r} already exists — reusing it (idempotent reseed).")
    elif resp.status_code != 201:
        _log(f"FAILED to open sample case: HTTP {resp.status_code} — {resp.text}")
        _log("The demo key was minted, but the sample case was NOT opened. Not reporting fake success.")
        return 1
    else:
        receipt = resp.json()
        _log(f"Opened case {DEMO_CASE_ID!r}: content_hash={receipt.get('content_hash')} ledger_seq={receipt.get('ledger_seq')}")

    _log("Seed complete. The demo Cell-tier key (last line of stdout):")
    print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
