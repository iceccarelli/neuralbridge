"""A read that meets a transient SQLite I/O error is re-run; a persistent one still raises.

Hosted CI saw ``sqlite3.OperationalError: disk I/O error`` from ``EvidenceLedger.get`` (a plain
read) as a 500 under four uvicorn workers. Reads change nothing, so they are retried a bounded
number of times; writes are not touched by this.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from assurance.evidence import ledger as ledger_mod
from assurance.evidence.ledger import EvidenceLedger


class _FlakyConnect:
    def __init__(self, real, failures: int, message: str) -> None:
        self.real, self.left, self.message, self.calls = real, failures, message, 0

    def __get__(self, ledger, _owner=None):
        def connect():
            self.calls += 1
            if self.left > 0:
                self.left -= 1
                raise sqlite3.OperationalError(self.message)
            return self.real(ledger)
        return connect


def test_a_read_survives_transient_io_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led = EvidenceLedger(tmp_path / "l.db")
    flaky = _FlakyConnect(EvidenceLedger._connect, 3, "disk I/O error")
    monkeypatch.setattr(EvidenceLedger, "_connect", flaky)
    monkeypatch.setattr("time.sleep", lambda _s: None)
    assert led.get("0" * 64) is None
    assert flaky.calls == 4


def test_a_persistent_io_error_still_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led = EvidenceLedger(tmp_path / "l.db")
    flaky = _FlakyConnect(EvidenceLedger._connect, 10_000, "disk I/O error")
    monkeypatch.setattr(EvidenceLedger, "_connect", flaky)
    monkeypatch.setattr("time.sleep", lambda _s: None)
    with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
        led.get("0" * 64)
    assert flaky.calls == ledger_mod._VOIDED_READ_ATTEMPTS


def test_other_operational_errors_are_not_retried(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    led = EvidenceLedger(tmp_path / "l.db")
    flaky = _FlakyConnect(EvidenceLedger._connect, 10_000, "no such table: chain")
    monkeypatch.setattr(EvidenceLedger, "_connect", flaky)
    with pytest.raises(sqlite3.OperationalError, match="no such table"):
        led.get("0" * 64)
    assert flaky.calls == 1
