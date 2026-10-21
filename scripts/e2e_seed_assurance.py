"""Seed a local Assurance API for the /assurance workspace e2e.

Uses the real engines end to end — AccountStore, the per-account tenant ledger,
collection plans over synthetic vendor exports, the Watch runner and its case
wiring — and writes nothing but local files. The output JSON holds keys for
three accounts: A (Cell, has a fleet and an open change case), B (Cell, empty)
and C (Register, not entitled to change assurance).

    ASSURANCE_LEDGER=... ASSURANCE_ACCOUNTS=... python scripts/e2e_seed_assurance.py OUT.json WORKDIR

These are local test credentials for a throwaway database. Never run against a
deployed service.
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from assurance.api.deps import accounts_path, tenant_ledger_path  # noqa: E402
from assurance.billing.accounts import AccountStore  # noqa: E402
from assurance.evidence.ledger import EvidenceLedger  # noqa: E402
from assurance.watch.config import WatchConfig  # noqa: E402
from assurance.watch.runner import run_watch  # noqa: E402
from tests.support import plan_dict, write_export  # noqa: E402
from tests.test_assurance_watch_cases import verify_machine  # noqa: E402

T0 = datetime(2026, 9, 14, 6, tzinfo=UTC)


def main(out: str, workdir: str) -> int:
    work = Path(workdir)
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    store = AccountStore(accounts_path())

    def account(name: str, tier: str) -> tuple[str, str]:
        acct = store.upsert_account(email=f"{name}@e2e.invalid", tier=tier, company=name,
                                    stripe_customer_id=f"cus_e2e_{name}",
                                    stripe_subscription_id=f"sub_e2e_{name}")
        return acct.id, store.issue_key(acct.id, label="e2e")

    id_a, key_a = account("alpha", "cell")
    _, key_b = account("bravo", "cell")
    _, key_c = account("charlie", "register")

    (work / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in ("0412", "0501"):
        write_export(work / serial, stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    (work / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-E2E", "max_age_hours": 168,
        "targets": [
            {"serial": "0412", "plan": "plan.json", "root": "0412", "site": "Plant 2", "country": "DE"},
            {"serial": "0501", "plan": "plan.json", "root": "0501", "site": "Plant 7", "country": "IT"},
        ],
    }))
    config = WatchConfig.from_json(work / "watch.json")
    ledger = EvidenceLedger(tenant_ledger_path(id_a))

    run_watch(config, ledger, now=T0)
    for key in ("Grimaldi/AR-7#0412", "Grimaldi/AR-7#0501"):
        verify_machine(ledger, key, when=T0 + timedelta(days=1))
    # Somebody reflashed the safety controller on 0412.
    shutil.rmtree(work / "0412")
    write_export(work / "0412", stamp="2026-09-21T06:12:41Z", operator="a.integrator",
                 seq="4199", fw=b"firmware 3.9.0")
    run = run_watch(config, ledger, now=T0 + timedelta(days=7))
    case_ids = [o.case_id for o in run.outcomes if getattr(o, "case_id", "")]
    if len(case_ids) != 1:
        print(f"expected exactly one case from the watch, got {case_ids}", file=sys.stderr)
        return 1
    Path(out).write_text(json.dumps({
        "key_a": key_a, "key_b": key_b, "key_register": key_c,
        "case_id": case_ids[0], "machines": ["Grimaldi/AR-7#0412", "Grimaldi/AR-7#0501"],
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
