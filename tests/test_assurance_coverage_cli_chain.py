"""``machinery coverage`` is a gate: it must not assess a ledger whose chain is broken.

Regression: deleting the intervention that made a function stale left every remaining row
valid on its own, so the gate printed ``covered`` and exited 0 while ``fleet list`` and
``passport`` already refused the same ledger.
"""
from __future__ import annotations

import json
import sqlite3

from assurance.machinery.cli import main

MANIFEST = {
    "manifest_id": "M1", "machine": {"manufacturer": "A", "model": "B", "serial": "1"},
    "source": "as_found", "taken_at": "2026-01-01T00:00:00Z",
    "taken_by": {"identifier": "t", "role": "tech", "kind": "person"},
    "items": [{"item_id": "I", "kind": "firmware", "name": "fw", "version": "1",
               "content_hash": "a" * 64, "hash_source": "read_from_machine",
               "supplier": "S", "implements": ["SF"], "modifiable_in_field": False}],
    "functions": [{"function_id": "SF", "description": "d", "verified_by": ["c"]}],
}


def _record(tmp_path, name, manifest):
    path = tmp_path / name
    path.write_text(json.dumps(manifest))
    assert main(["record-manifest", str(path), "--ledger", str(tmp_path / "l.db")]) == 0
    return path


def test_coverage_refuses_a_ledger_with_a_broken_chain(tmp_path, capsys):
    first = _record(tmp_path, "a.json", MANIFEST)
    _record(tmp_path, "b.json", {**MANIFEST, "manifest_id": "M2",
                                 "machine": {**MANIFEST["machine"], "serial": "2"}})
    con = sqlite3.connect(tmp_path / "l.db")
    con.execute("DELETE FROM chain WHERE seq = 1")
    con.commit()
    con.close()
    capsys.readouterr()
    rc = main(["coverage", str(first), "--ledger", str(tmp_path / "l.db"), "--json"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "chain does not verify" in captured.err
    assert "covered" not in captured.out


def test_coverage_on_an_intact_ledger_is_unchanged(tmp_path, capsys):
    first = _record(tmp_path, "a.json", MANIFEST)
    capsys.readouterr()
    rc = main(["coverage", str(first), "--ledger", str(tmp_path / "l.db"), "--json"])
    assert rc == 1                       # declared function never verified: a gap, not a crash
    assert json.loads(capsys.readouterr().out)["verdict"] == "gaps"
