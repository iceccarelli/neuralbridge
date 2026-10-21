"""Seed a local Assurance API for the /assurance workspace e2e.

Uses the real engines end to end — AccountStore, the per-account tenant ledger,
collection plans over synthetic vendor exports, the Watch runner and its case
wiring — and writes nothing but local files. The output JSON holds keys for
five accounts: A (Cell, has a fleet and an open change case, written straight
into its ledger), B (Cell, empty), C (Register, not entitled to change
assurance), D (Cell, one hand-posted manifest and no Watch report ever) and
E (Cell, whose fleet arrives ONLY through the real ``assurance watch push``).

    ASSURANCE_LEDGER=... ASSURANCE_ACCOUNTS=... python scripts/e2e_seed_assurance.py OUT.json WORKDIR
    python scripts/e2e_seed_assurance.py OUT.json WORKDIR --report http://127.0.0.1:PORT

The second form runs once the API is up. It drives E's local plant through a
timeline (real Watch runs over synthetic exports into a plant-local ledger) and
reports it with the real ``watch push`` CLI, over HTTP, and then pushes the same
run again: the replay must change nothing.

These are local test credentials for a throwaway database. Never run against a
deployed service.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from assurance.api.deps import accounts_path, tenant_ledger_path  # noqa: E402
from assurance.billing.accounts import AccountStore  # noqa: E402
from assurance.collect.collector import collect  # noqa: E402
from assurance.collect.plan import CollectionPlan  # noqa: E402
from assurance.core.evidence import Actor  # noqa: E402
from assurance.evidence.ledger import EvidenceLedger  # noqa: E402
from assurance.machinery.manifest import ManifestSource  # noqa: E402
from assurance.machinery.record import record_manifest  # noqa: E402
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
    id_d, key_d = account("delta", "cell")
    _, key_e = account("echo", "cell")

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

    # D: a manifest somebody posted by hand, and no Watch report ever. The workspace
    # must say so rather than show a machine that looks quietly current.
    write_export(work / "0900", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    hand = collect(CollectionPlan.from_dict(plan_dict()), work / "0900", serial="0900",
                   taken_by=Actor("m.tech", "service technician"), site="Plant 9", country="DE",
                   source=ManifestSource.AS_FOUND, taken_at=T0)
    record_manifest(EvidenceLedger(tenant_ledger_path(id_d)), hand.manifest)

    Path(out).write_text(json.dumps({
        "key_a": key_a, "key_b": key_b, "key_register": key_c, "key_d": key_d, "key_e": key_e,
        "case_id": case_ids[0], "machines": ["Grimaldi/AR-7#0412", "Grimaldi/AR-7#0501"],
        "d_machine": "Grimaldi/AR-7#0900",
    }))
    return 0


E_SERIALS = ("7001", "7002", "7003")


def _push(config: Path, ledger: Path, url: str, key: str) -> str:
    """The real CLI, as an operator would run it. The key travels in the environment only."""
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", "watch", "push", str(config), "--ledger", str(ledger),
         "--api-url", url, "--key-env", "NB_E2E_PUSH_KEY", "--retry-wait", "0"],
        env={**os.environ, "NB_E2E_PUSH_KEY": key, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True, text=True, check=False)
    if proc.returncode != 0 or key in proc.stdout + proc.stderr:
        print(f"watch push failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}", file=sys.stderr)
        raise SystemExit(1)
    return proc.stdout


def report(out: str, workdir: str, api_url: str) -> int:
    """Account E's plant: three machines, reported through the real push path.

    7001 is looked at every time and reflashed between the two pushes (one case).
    7002 has not been collectable for two runs and was last seen ten days ago (stale).
    7003 was seen two days ago and failed the latest look (failed, not yet stale).
    """
    seed = json.loads(Path(out).read_text())
    plant = Path(workdir) / "plant-e"
    shutil.rmtree(plant, ignore_errors=True)
    plant.mkdir(parents=True)
    (plant / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in E_SERIALS:
        write_export(plant / serial, stamp="2026-10-01T06:00:00Z", operator="m.tech", seq="4181")
    (plant / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-E2E-PLANT", "max_age_hours": 168,
        "targets": [{"serial": s, "plan": "plan.json", "root": s, "site": "Plant E", "country": "DE"}
                    for s in E_SERIALS],
    }))
    config = WatchConfig.from_json(plant / "watch.json")
    local = EvidenceLedger(plant / "register.db")
    cfg, db, key = plant / "watch.json", plant / "register.db", seed["key_e"]
    now = datetime.now(UTC).replace(microsecond=0)

    run_watch(config, local, now=now - timedelta(days=10))           # everything seen
    _push(cfg, db, api_url, key)                                     # hosted baseline

    shutil.rmtree(plant / "7001")                                    # reflashed on the floor
    write_export(plant / "7001", stamp="2026-10-18T06:12:41Z", operator="a.integrator",
                 seq="4199", fw=b"firmware 3.9.0")
    shutil.rmtree(plant / "7002")                                    # export folder gone
    run_watch(config, local, now=now - timedelta(days=2))            # 7003 still fine
    shutil.rmtree(plant / "7003")
    run_watch(config, local, now=now - timedelta(hours=1))           # 7002, 7003 blind

    first = _push(cfg, db, api_url, key)
    again = _push(cfg, db, api_url, key)                             # a retry: must change nothing
    if "already recorded" not in again or "cases opened" in again:
        print(f"the replay was not a no-op:\n{again}", file=sys.stderr)
        return 1
    cases = [w for w in first.replace(",", " ").split() if w.startswith("case-")]
    seed.update({
        "machines_e": {"ok": "Grimaldi/AR-7#7001", "blind_stale": "Grimaldi/AR-7#7002",
                       "blind_fresh": "Grimaldi/AR-7#7003"},
        "case_e": cases[0] if cases else "",
    })
    if not seed["case_e"]:
        print(f"expected the push to open one case:\n{first}", file=sys.stderr)
        return 1
    Path(out).write_text(json.dumps(seed))
    return 0


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[3] == "--report":
        raise SystemExit(report(sys.argv[1], sys.argv[2], sys.argv[4]))
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
