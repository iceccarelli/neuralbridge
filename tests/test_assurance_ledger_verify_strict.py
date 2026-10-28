"""The ledger's own verifier must be as strict as the export verifier.

The service attests (signs the head of) a ledger only when ``verify_chain`` passes, so an
edit it missed was an edit the service would sign over. Three edits passed before:
rewriting the ``actor`` column (outside the link hash), adding an unsealed key to a
payload, and replacing a payload with a different, internally valid sealed evidence.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.security.art14 import (
    Art14Register,
    Awareness,
    Signal,
    SignalChannel,
    Track,
)

T0 = datetime(2026, 9, 19, 6, 30, tzinfo=UTC)
ACTOR = Actor("tester", "stress-test")


@pytest.fixture
def path(tmp_path):
    p = tmp_path / "ledger.db"
    reg = Art14Register(EvidenceLedger(p))
    reg.record_signal("c1", Signal(T0, SignalChannel.CVD_INBOX, "t", "d"), ACTOR)
    reg.record_awareness("c1", Awareness(T0, T0, T0, "t", "judged"), Track.INCIDENT, ACTOR)
    return p


def _edit(path, sql, args=()):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        db.execute(sql, args)
        db.commit()
    finally:
        db.close()


def _row(path, seq):
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    try:
        return db.execute("SELECT * FROM chain WHERE seq = ?", (seq,)).fetchone()
    finally:
        db.close()


def test_an_untouched_ledger_verifies(path):
    ok, problems = EvidenceLedger(path).verify_chain()
    assert ok and problems == []


def test_a_rewritten_actor_column_fails_verification(path):
    _edit(path, "UPDATE chain SET actor='mallory' WHERE seq=2")
    ok, problems = EvidenceLedger(path).verify_chain()
    assert not ok and any("recorded actor" in p for p in problems)


def test_an_unsealed_key_in_a_payload_fails_verification(path):
    payload = json.loads(_row(path, 2)["payload"])
    payload["injected"] = "approved by the CISO"
    _edit(path, "UPDATE chain SET payload=? WHERE seq=2", (json.dumps(payload),))
    ok, problems = EvidenceLedger(path).verify_chain()
    assert not ok and any("does not cover" in p for p in problems)


def test_a_payload_replaced_by_other_valid_evidence_fails_verification(path):
    _edit(path, "UPDATE chain SET payload=? WHERE seq=2", (_row(path, 1)["payload"],))
    ok, problems = EvidenceLedger(path).verify_chain()
    assert not ok and any("different evidence" in p for p in problems)


def test_the_cached_verifier_agrees_with_the_full_walk(path):
    ledger = EvidenceLedger(path)
    assert ledger.verify_cached()[0] is True
    _edit(path, "UPDATE chain SET actor='mallory' WHERE seq=2")
    assert ledger.verify_chain()[0] is False
    assert ledger.verify_cached()[0] is False
