"""The Article 14 CLI's read verbs read; they do not mint ids, create files or change bytes.

Red-team finding (workstream L): ``art14 case``, ``register`` and ``verify`` opened the ledger
with ``EvidenceLedger(path)``, which writes: it mints a ledger id on a ledger that has none,
and ``--ledger typo.db register`` created ``typo.db`` and exited 0 ("nothing to report").
"""

from __future__ import annotations

import hashlib
import sqlite3

import pytest

from assurance.core.identity import format_utc, parse_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14.cli import main

BY = ["--by", "t:analyst"]


def idless_ledger(tmp_path):
    """A one-case ledger as an older build left it: no ledger id, rollback-journal mode."""
    path = tmp_path / "old.db"
    assert main(["--ledger", str(path), "signal", "C1", *BY, "--description", "d",
                 "--at", format_utc(parse_utc("2026-09-19T05:00:00Z"))]) == 0
    db = sqlite3.connect(path)
    db.execute("DELETE FROM meta WHERE key = 'ledger_id'")
    db.commit()
    db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    db.execute("PRAGMA journal_mode=DELETE")
    db.close()
    return path


def snapshot(directory):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(directory.iterdir())}


@pytest.mark.parametrize("argv", [
    ["case", "C1"],
    ["case", "C1", "--json"],
    ["register"],
    ["register", "--json"],
    ["verify"],
    ["export"],
    ["export", "--case", "C1"],
])
def test_a_read_verb_leaves_every_byte_of_an_id_less_ledger_alone(tmp_path, argv):
    path = idless_ledger(tmp_path)
    before = snapshot(tmp_path)
    assert set(before) == {"old.db"}  # no sidecars to begin with
    main(["--ledger", str(path), *argv])
    assert snapshot(tmp_path) == before
    assert EvidenceLedger.open_readonly(path).ledger_id() is None


@pytest.mark.parametrize("argv", [
    ["register"], ["register", "--json"], ["case", "C1"], ["verify"], ["export"],
])
def test_a_read_verb_on_a_mistyped_path_is_exit_2_and_creates_nothing(tmp_path, argv, capsys):
    typo = tmp_path / "typo.db"
    assert main(["--ledger", str(typo), *argv]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert list(tmp_path.iterdir()) == []


def test_a_recording_verb_other_than_signal_does_not_create_a_ledger(tmp_path, capsys):
    typo = tmp_path / "typo.db"
    assert main(["--ledger", str(typo), "awareness", "C1", *BY, "--at", "2026-09-19T06:30:00Z",
                 "--started", "2026-09-19T06:30:00Z", "--completed", "2026-09-19T06:30:00Z",
                 "--track", "actively_exploited_vulnerability", "--because", "r"]) == 2
    assert list(tmp_path.iterdir()) == []


def test_signal_still_creates_the_register_on_first_use(tmp_path):
    new = tmp_path / "fresh.db"
    assert main(["--ledger", str(new), "signal", "C1", *BY, "--description", "d"]) == 0
    assert new.is_file()
    assert main(["--ledger", str(new), "register"]) in (0, 1)


def test_recording_into_an_id_less_ledger_still_works(tmp_path):
    path = idless_ledger(tmp_path)
    assert main(["--ledger", str(path), "signal", "C2", *BY, "--description", "d"]) == 0
    assert EvidenceLedger.open_readonly(path).ledger_id() is not None
