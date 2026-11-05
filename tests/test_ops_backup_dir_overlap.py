"""A backup directory that overlaps the data directory copies its own backups.

Found by running three ``ops cycle`` passes over a config whose ``backup_dir`` sat inside
``data_dir``: every pass exited 0 and the data directory grew from 0.4 MB to 1.2 MB, each backup
containing the earlier ones. ``ops check`` already called it a failure; the cycle did not. Now
the backup step refuses, the cycle is degraded (exit 2) and nothing is written into the data
directory. Synthetic ledgers in a temp directory.
"""

from __future__ import annotations

import json

import pytest

from assurance.billing.accounts import AccountStore
from assurance.core import Actor, Evidence, Origin
from assurance.evidence import EvidenceLedger
from assurance.ops.config import load_config
from assurance.ops.cycle import run_cycle


def _volume(tmp_path):
    data = tmp_path / "data"
    (data / "tenants").mkdir(parents=True)
    ev = Evidence(kind="t.record", body={"n": 1}, actor=Actor("a.person", "engineer"),
                  origin=Origin("unit-test")).seal()
    EvidenceLedger(data / "art14-register.db").append(ev)
    store = AccountStore(data / "accounts.db")
    acct = store.upsert_account(email="a@x.invalid", tier="cell").id
    EvidenceLedger(data / "tenants" / f"{acct}.db").append(ev, subject="CASE-1")
    return data


def _cfg(tmp_path, backup):
    path = tmp_path / "ops.json"
    path.write_text(json.dumps({
        "ops_id": "t", "data_dir": str(tmp_path / "data"),
        "record": str(tmp_path / "rec" / "c.jsonl"), "backup_dir": str(tmp_path / backup)}))
    return load_config(path)


def _tree(root):
    return sorted((p.relative_to(root).as_posix(), p.stat().st_size)
                  for p in root.rglob("*") if p.is_file())


@pytest.mark.parametrize("backup", ["data/backups", "data"])
def test_a_cycle_whose_backup_dir_overlaps_the_data_dir_takes_no_backup(tmp_path, backup):
    data = _volume(tmp_path)
    before = _tree(data)
    doc = run_cycle(_cfg(tmp_path, backup), live=False)
    steps = {s["name"]: s for s in doc["steps"]}
    assert steps["backup"]["status"] == "failed" and "overlaps" in steps["backup"]["detail"]
    assert steps["backup.verify"]["status"] == "skipped"
    assert doc["exit_code"] == 2
    assert _tree(data) == before                    # nothing was written into the data directory
    assert any("outside data_dir" in a["action"] for a in doc["human_actions"])


def test_a_backup_dir_beside_the_data_dir_still_backs_up(tmp_path):
    _volume(tmp_path)
    doc = run_cycle(_cfg(tmp_path, "data-backups"), live=False)   # a name prefix is not nesting
    steps = {s["name"]: s for s in doc["steps"]}
    assert steps["backup"]["status"] in ("ok", "flagged")
