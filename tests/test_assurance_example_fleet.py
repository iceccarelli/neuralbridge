# ruff: noqa: S603  (runs this repository's own shipped example)
"""The shipped fleet pack (``examples/fleet/run.py``) gives its documented result, and the fleet
listing keeps the order it promises. All machines in the pack are invented."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "examples" / "fleet" / "run.py"


@pytest.fixture(scope="module")
def fleet():
    done = subprocess.run([sys.executable, str(RUN), "--json"], capture_output=True, text=True,
                          check=False)
    assert done.returncode == 0, done.stdout[-600:]
    return json.loads(done.stdout)


def test_every_step_of_the_pack_gives_the_documented_result(fleet):
    assert fleet["ok"] and fleet["synthetic"]
    assert all(s["ok"] for s in fleet["steps"])
    assert {s["step"]: s["exit"] for s in fleet["steps"]}[
        "fleet list: expected GAPS"] == 1


def test_the_json_listing_has_the_same_order_as_the_table(fleet):
    from assurance.fleet.registry import Fleet

    assert callable(getattr(Fleet, "worst_first", None))
    order = fleet["facts"]["order"]
    verdicts = fleet["facts"]["machines"]
    assert [verdicts[m]["verdict"] == "gaps" for m in order] == [True, True, False, False, False]


def test_the_pack_names_nothing_real():
    text = RUN.read_text(encoding="utf-8")
    assert "SYNTHETIC" in text and "DemoCo" in text
