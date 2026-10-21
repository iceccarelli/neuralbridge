"""Red-team hardening of the change lifecycle and its ledger.

Each class here is the regression for one finding, written to fail against the
code as it was before the fix.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from assurance.change import (
    CaseStatus,
    CaseStore,
    advance,
    decide,
    resolve_decision,
    resume,
    waive_reverification,
)
from assurance.change.store import ChainBrokenError
from assurance.evidence import chain_cache
from assurance.evidence.ledger import EvidenceLedger

from .test_assurance_change import (
    BOT,
    REVIEWER,
    drive,
)


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.delenv("ASSURANCE_CHAIN_RECHECK_SECONDS", raising=False)
    chain_cache.reset()
    yield
    chain_cache.reset()


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "hardening.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def edit_old_record_in_place(ledger: EvidenceLedger) -> None:
    """Change one byte of the first (non-head) record's payload, as someone with
    write access to the database file could."""
    db = sqlite3.connect(ledger.path)
    try:
        cur = db.execute("UPDATE chain SET payload = replace(payload, 'Grimaldi', 'Grimaldx') "
                         "WHERE seq = 1")
        assert cur.rowcount == 1
        db.commit()
    finally:
        db.close()


# =====================================================================
# 6. A closure is never sealed on the strength of the cached chain check
# =====================================================================

class TestHumanDecisionsVerifyTheWholeChain:
    def _warm(self, store):
        # The cached check has passed within the recheck window.
        store.require_intact()
        assert chain_cache.lookup(chain_cache.identity(store.ledger.path)) is not None

    def test_the_cache_really_does_miss_the_edit(self, ledger, store):
        """The premise of every test below: the cached check alone does not see it."""
        drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        self._warm(store)
        edit_old_record_in_place(ledger)
        store.require_intact()                         # passes: that is the window
        assert not ledger.verify_chain()[0]

    def test_a_close_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)
        assert store.get(case.case_id).status is CaseStatus.READY_TO_CLOSE

    @pytest.mark.parametrize("disposition", ["rejected", "deferred"])
    def test_a_reject_or_defer_is_refused_after_an_in_place_edit(
            self, ledger, store, disposition):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            decide(store, case.case_id, disposition=disposition, reason="r", actor=REVIEWER)

    def test_a_waiver_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            waive_reverification(store, case.case_id, entry=case.required_reverifications[0],
                                 reason="accepted", actor=REVIEWER)

    def test_resolving_a_decision_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        asked = store.update(replace(case, human_decisions_required=("Is this in scope?",)),
                             actor=BOT, detail="a question")
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            resolve_decision(store, asked.case_id, decision="Is this in scope?",
                             resolution="yes", actor=REVIEWER)

    def test_a_resume_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.DEFERRED)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            resume(store, case.case_id, reason="back on it", actor=REVIEWER)

    def test_sealing_a_decision_entry_walks_the_whole_chain_at_the_store(self, ledger, store):
        """Below the service: whatever called the store, a decision entry is not
        appended on the cached check."""
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            store.decide(replace(case, status=CaseStatus.REJECTED, decision="rejected",
                                 decision_reason="r", decision_by="v"),
                         actor=REVIEWER, detail="rejected: r")

    def test_a_clean_ledger_still_closes(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        self._warm(store)
        closed = decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)
        assert closed.status is CaseStatus.CLOSED

    def test_a_machine_driven_step_keeps_the_cheap_check(self, ledger, store, monkeypatch):
        """Only human decisions pay for a full walk: advancing a case is not one."""
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._warm(store)
        walks = []
        real = ledger.verify_full
        monkeypatch.setattr(ledger, "verify_full", lambda: walks.append(1) or real())
        advance(store, case.case_id, actor=REVIEWER)
        assert walks == []
