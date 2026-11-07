"""`assurance value` only reads: running it must leave the ledger file byte-for-byte unchanged."""

from __future__ import annotations

import hashlib
from pathlib import Path

from assurance.value.cli import main as value_main

from .support_sqlite import connect as sqlite_connect


def _digest(path: Path) -> tuple[str, int, int]:
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), len(data), path.stat().st_mtime_ns


def test_value_verb_does_not_mutate_the_ledger(tmp_path, capsys):
    from assurance.core.evidence import Actor, Evidence, Origin
    from assurance.evidence.ledger import EvidenceLedger

    path = tmp_path / "l.db"
    ledger = EvidenceLedger(path)
    ledger.append(Evidence(kind="t.record", body={"n": 1}, actor=Actor("a.person", "engineer"),
                           origin=Origin("unit-test")).seal())
    del ledger
    with sqlite_connect(path) as db:          # the DELETE-journal case a read used to switch to WAL
        db.execute("PRAGMA journal_mode=DELETE")
    before, listing = _digest(path), sorted(p.name for p in tmp_path.iterdir())
    assert value_main(["report", "--ledger", str(path), "--json"]) in (0, 1, 3)
    capsys.readouterr()
    assert _digest(path) == before and sorted(p.name for p in tmp_path.iterdir()) == listing
