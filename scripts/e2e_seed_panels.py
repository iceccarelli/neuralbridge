"""Seed a throwaway Assurance API for tests-e2e/assurance-panels.spec.ts.

Real engines, local files only: an AccountStore with one Cell account (entitled) and one Free
account (not entitled), a SYNTHETIC safety manifest in three variants, and an intel observation
store built from the contract fixtures in tests/fixtures/intel (the same builder the intel API
tests use; no network is opened). Never run against a deployed service.

    ASSURANCE_ACCOUNTS=... python scripts/e2e_seed_panels.py OUT.json WORKDIR
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from assurance.api.deps import accounts_path  # noqa: E402
from assurance.billing.accounts import AccountStore  # noqa: E402
from assurance.machinery.manifest import HashSource, ItemKind, SafetyItem  # noqa: E402
from tests.test_assurance_check import fw, manifest, zones  # noqa: E402
from tests.test_assurance_intel_api import build_store  # noqa: E402


def main(out: str, workdir: str) -> int:
    work = Path(workdir)
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    store = AccountStore(accounts_path())

    def account(name: str, tier: str) -> str:
        acct = store.upsert_account(email=f"{name}@e2e.invalid", tier=tier, company=name,
                                    stripe_customer_id=f"cus_e2e_{name}",
                                    stripe_subscription_id=f"sub_e2e_{name}")
        return store.issue_key(acct.id, label="e2e")

    base = manifest("E2E-0001", fw(), zones())
    changed = manifest("E2E-0001", fw(version="3.9.0"), zones())
    params = SafetyItem("ITM-PARAMS", ItemKind.SAFETY_CONFIGURATION, "Safety parameters", "1", "",
                        HashSource.DECLARED, supplier="ControlCo", implements=("SF-01",))
    no_hash = manifest("E2E-0002", fw(), zones(), params)
    build_store(work / "intel.db")
    (work / "not-a-store.db").write_bytes(b"this is not an sqlite database")
    Path(out).write_text(json.dumps({
        "key_cell": account("panels-cell", "cell"),
        "key_free": account("panels-free", "free"),
        "key_coverage": account("panels-coverage", "cell"),
        "key_coverage_empty": account("panels-coverage-empty", "cell"),
        "manifest": base.to_dict(),
        "manifest_changed": changed.to_dict(),
        "manifest_uncomparable": no_hash.to_dict(),
        "intel_store": str(work / "intel.db"),
        "bad_store": str(work / "not-a-store.db"),
        "cve_listed": "CVE-2021-44228",
        "cve_nvd_only": "CVE-2026-0001",
        "cve_nowhere": "CVE-1999-0001",
    }, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
