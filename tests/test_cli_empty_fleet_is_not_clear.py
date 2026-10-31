"""An advisory assessed against a fleet with no machines in it assessed nothing.

``fleet advisory`` used to exit 0 and print "CLEAR" for an empty ledger, which a script reads
as "this advisory does not touch us". It now exits 3 (incomplete), the report banner says
nothing was assessed, and the domain object's ``clear_is_complete`` is False.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from assurance.evidence.ledger import EvidenceLedger


def run(*args: str | Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "assurance", *map(str, args)],
        capture_output=True, text=True, cwd=cwd, timeout=120, check=False)


def test_fleet_advisory_on_an_empty_ledger_is_incomplete_not_clear(tmp_path):
    demo = tmp_path / "demo"
    assert run("report", "demo", "--out", demo, cwd=tmp_path).returncode == 0
    empty = tmp_path / "empty.db"
    EvidenceLedger(empty)
    r = run("fleet", "advisory", demo / "advisory.json", "--ledger", empty, "--json", cwd=tmp_path)
    body = json.loads(r.stdout)
    reports = body["advisories"]
    assert reports
    assert all(x["machines_in_fleet"] == 0 and x["clear_is_complete"] is False for x in reports)
    assert r.returncode == 3, (r.returncode, r.stdout[:300], r.stderr[:300])
