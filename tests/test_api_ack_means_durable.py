"""A 201 must name the ledger entry its own write produced, or not be a 201.

Independent review of the first-write data-loss fix found that the route answered
``ledger_seq: 0`` with HTTP 201 when it could not find the row (so a lost record still looked
acknowledged), and that it looked the row up by content hash, which the ledger does not keep
unique, so an identical repeat could be answered with the first record's number.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import HTTPException

from assurance.api import routes
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
from assurance.security.art14.engine import Art14Register


def _evidence(note: str) -> Evidence:
    return Evidence(kind="test.note", body={"note": note}, actor=Actor(identifier="a@example.invalid"),
                    origin=Origin(system="test", reference="r", method="m")).seal()


def test_identical_repeats_each_get_their_own_sequence_number(tmp_path: Path) -> None:
    ledger = EvidenceLedger(tmp_path / "l.db")
    first = ledger.append(_evidence("same"), subject="case-1")
    second = ledger.append(_evidence("same"), subject="case-1")
    assert first.content_hash == second.content_hash          # the premise: hashes are not unique
    assert (first.seq, second.seq) == (1, 2)
    assert ledger.get(second.content_hash).seq == 1           # why lookup-by-hash was wrong


def test_the_register_remembers_the_entry_of_the_last_append_on_this_thread(tmp_path: Path) -> None:
    register = Art14Register(EvidenceLedger(tmp_path / "l.db"))
    assert register.last_entry() is None
    evidence = register._append("case-1", "art14.signal", {"k": 1}, Actor(identifier="a@example.invalid"))
    entry = register.last_entry()
    assert entry is not None and entry.content_hash == evidence.content_hash and entry.seq == 1


def test_recorded_refuses_rather_than_answer_zero(tmp_path: Path) -> None:
    register = Art14Register(EvidenceLedger(tmp_path / "l.db"))
    never_written = _evidence("lost")
    with pytest.raises(HTTPException) as exc:
        routes._recorded(register, "case-1", never_written)
    assert exc.value.status_code == 500
    assert exc.value.detail["error"] == "ledger_write_unconfirmed"


def test_recorded_refuses_another_cases_entry(tmp_path: Path) -> None:
    register = Art14Register(EvidenceLedger(tmp_path / "l.db"))
    evidence = register._append("case-1", "art14.signal", {"k": 1}, Actor(identifier="a@example.invalid"))
    with pytest.raises(HTTPException) as exc:
        routes._recorded(register, "case-2", evidence)         # entry belongs to case-1
    assert exc.value.detail["error"] == "ledger_write_unconfirmed"
