"""Seed throwaway data for tests-e2e/assurance-ledger-verify.spec.ts.

Real engines, local files only: Cell accounts whose per-account ledgers are written through the
real API routes, one counter-signed by the real attestation code with a throwaway key, and one
then cut short with SQL (the tampering the panel must show loudly). Nothing is mocked and no
network is opened. Never run against a deployed service.

    ASSURANCE_ACCOUNTS=... ASSURANCE_TENANT_LEDGERS=... ASSURANCE_ATTEST_KEY=... \
    ASSURANCE_ATTEST_LOGS=... python scripts/e2e_seed_ledger_verify.py OUT.json
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from fastapi.testclient import TestClient  # noqa: E402

from assurance.api import attest_routes, deps  # noqa: E402
from assurance.attest import SigningKey, attest  # noqa: E402
from assurance.billing.accounts import AccountStore  # noqa: E402
from assurance.evidence import EvidenceLedger  # noqa: E402

ACTOR = {"identifier": "e2e.ledger.operator", "role": "Head of Engineering"}


def main(out: str) -> int:
    key_path = Path(os.environ["ASSURANCE_ATTEST_KEY"])
    if not key_path.exists():
        SigningKey.generate().save(key_path)
    store = AccountStore(deps.accounts_path())
    service = importlib.import_module("assurance.api.service")
    seed: dict[str, object] = {}

    def account(name: str, tier: str = "cell", customer: bool = True):
        acct = store.upsert_account(
            email=f"{name}@e2e.invalid", tier=tier, company=name,
            stripe_customer_id=f"cus_e2e_{name}" if customer else "",
            stripe_subscription_id=f"sub_e2e_{name}" if customer else "")
        return acct, store.issue_key(acct.id, label="e2e")

    def write(client, key, n, start=0):
        for i in range(start, start + n):
            r = client.post(f"/v1/cases/E2E-{i}/signal", headers={"X-API-Key": key}, json={
                "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
                "description": "Synthetic e2e signal", "reference": "T-1", "actor": ACTOR})
            assert r.status_code == 201, r.text

    def counter_sign(acct):
        ledger = EvidenceLedger(deps.tenant_ledger_path(acct.id))
        log = attest_routes._log_for(SimpleNamespace(subject=acct.id))
        attest(ledger, SigningKey.load(str(key_path)), log)

    with TestClient(service.create_app()) as client:
        _, seed["key_empty"] = account("lv-empty")
        _, seed["key_unanchored"] = account("lv-unanchored")
        write(client, seed["key_unanchored"], 3)
        b, seed["key_complete"] = account("lv-complete")
        write(client, seed["key_complete"], 3)
        counter_sign(b)
        write(client, seed["key_complete"], 1, start=10)
        c, seed["key_incomplete"] = account("lv-incomplete")
        write(client, seed["key_incomplete"], 3)
        counter_sign(c)
        db = sqlite3.connect(deps.tenant_ledger_path(c.id))
        db.execute("DELETE FROM chain WHERE seq > 1")
        db.commit()
        db.close()
        _, seed["key_free"] = account("lv-free", tier="free", customer=False)
    Path(out).write_text(json.dumps(seed, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
