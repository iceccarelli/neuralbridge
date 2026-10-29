"""The Article 14 CLI answers an operator's mistake with a message and exit 2, not a traceback.

Regression: ``main`` had no error handling, so a second signal on a case, triage on a case with
no track, or a time that could not be read ended in an uncaught exception (exit 1). And
``art14 case ID`` for an id nothing was recorded under printed a report in state
``signal_received`` with exit 0, where ``art14 export`` and ``GET /v1/cases/{id}`` say it does
not exist.
"""
from __future__ import annotations

import pytest

from assurance.security.art14.cli import main

BY = ["--by", "t:analyst"]


@pytest.fixture()
def ledger(tmp_path):
    path = str(tmp_path / "l.db")
    assert main(["--ledger", path, "signal", "C1", *BY, "--description", "d"]) == 0
    return path


@pytest.mark.parametrize("args", [
    ["signal", "C1", *BY, "--description", "again"],
    ["triage", "C1", *BY],
    ["triage", "NOPE", *BY],
    ["signal", "C2", *BY, "--at", "not-a-time", "--description", "d"],
    ["signal", "C3", *BY, "--at", "2026-10-20T09:00:00", "--description", "d"],
])
def test_a_refused_command_is_exit_2_with_a_message(ledger, capsys, args):
    capsys.readouterr()
    assert main(["--ledger", ledger, *args]) == 2
    assert capsys.readouterr().err.startswith("error: ")


def test_a_refused_command_writes_nothing(ledger, capsys):
    import sqlite3
    count = lambda: sqlite3.connect(ledger).execute("SELECT COUNT(*) FROM chain").fetchone()[0]  # noqa: E731
    before = count()
    main(["--ledger", ledger, "signal", "C1", *BY, "--description", "again"])
    assert count() == before
    assert main(["--ledger", ledger, "verify"]) == 0


def test_an_unknown_case_is_an_error_not_a_case_in_some_state(ledger, capsys):
    capsys.readouterr()
    assert main(["--ledger", ledger, "case", "NOPE"]) == 2
    captured = capsys.readouterr()
    assert "signal_received" not in captured.out and "NOPE" in captured.err
    assert main(["--ledger", ledger, "case", "C1"]) == 0
