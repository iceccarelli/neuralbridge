"""A machine the watch could only partly read is never "quiet", however many runs it takes.

An incomplete FIRST look sets no baseline (a partial look is not a configuration the machine
was in). The first run reported it, because every safety function was newly uncovered; every
later run compared the same partial look with no baseline, found nothing "changed", and --
the functions no longer being *newly* uncovered, or the plan declaring none -- read
``quiet``/exit 0 for a machine nobody has ever fully seen. "Could not look" and "nothing
found" are different states: the run is ``degraded`` until a complete look exists.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.watch.cli import main
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export
from .test_assurance_watch import T0


def _setup(root, *, functions=True, drop="plc-project.zip"):
    pd = plan_dict()
    if not functions:
        pd["functions"] = []
        for item in pd["items"]:
            item["implements"] = []
    (root / "plan.json").write_text(json.dumps(pd))
    write_export(root / "m1", stamp="2026-09-14T06:00:00Z", operator="x", seq="4181")
    if drop:
        (root / "m1" / drop).unlink()
    (root / "watch.json").write_text(json.dumps({
        "watch_id": "W", "max_age_hours": 168,
        "targets": [{"serial": "1", "plan": "plan.json", "root": "m1", "site": "S",
                     "country": "DE", "read_from_machine": True}]}))
    return WatchConfig.from_json(root / "watch.json"), EvidenceLedger(root / "r.db")


@pytest.mark.parametrize("functions", [True, False], ids=["with-functions", "no-functions"])
def test_every_run_over_a_first_look_that_was_incomplete_is_degraded(tmp_path, functions):
    config, ledger = _setup(tmp_path, functions=functions)
    for day in range(3):
        run = run_watch(config, ledger, now=T0 + timedelta(days=day))
        [outcome] = run.outcomes
        assert outcome.status == "first_seen" and outcome.collection_complete is False
        assert run.verdict == "degraded", f"run {day} read {run.verdict!r}"
        assert [o.serial for o in run.incomplete] == ["1"]
        assert "INCOMPLETE" in run.summary()
        assert run.to_dict()["verdict"] == "degraded"


def test_the_cli_exits_2_not_0_for_it(tmp_path, capsys):
    config, ledger = _setup(tmp_path, functions=False)
    run_watch(config, ledger, now=T0)
    code = main(["run", str(tmp_path / "watch.json"), "--ledger", str(tmp_path / "r.db"),
                 "--json"])
    assert code == 2 and json.loads(capsys.readouterr().out)["verdict"] == "degraded"
    status = main(["status", str(tmp_path / "watch.json"), "--ledger", str(tmp_path / "r.db"),
                   "--json"])
    assert status == 2


def test_control_a_complete_first_look_is_still_quiet_afterwards(tmp_path):
    config, ledger = _setup(tmp_path, functions=False, drop=None)
    run_watch(config, ledger, now=T0)
    assert run_watch(config, ledger, now=T0 + timedelta(days=1)).verdict == "quiet"


def test_it_clears_once_a_complete_look_exists(tmp_path):
    config, ledger = _setup(tmp_path, functions=False)
    assert run_watch(config, ledger, now=T0).verdict == "degraded"
    write_export(tmp_path / "m1", stamp="2026-09-15T06:00:00Z", operator="x", seq="4182")
    first_whole = run_watch(config, ledger, now=T0 + timedelta(days=1))
    assert first_whole.outcomes[0].collection_complete is True
    assert run_watch(config, ledger, now=T0 + timedelta(days=2)).verdict == "quiet"
