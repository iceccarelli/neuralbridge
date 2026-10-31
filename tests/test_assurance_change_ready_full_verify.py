"""Automation that can set a case READY_TO_CLOSE verifies the WHOLE chain first.

``reverify`` and ``advance`` are called by automation (watch runner, API, CLI).
The cached chain check can be blind for up to ``ASSURANCE_CHAIN_RECHECK_SECONDS``
to a deleted or edited OLD record; a case must never be recorded as ready to
close inside that window. Writes that cannot clear a case keep the cheap check.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace

import pytest

from assurance.change import CaseStatus, CaseStore, advance, claim, reverify
from assurance.change.store import ChainBrokenError
from assurance.evidence import chain_cache
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord

from .test_assurance_change import (
    LATER,
    MACHINE,
    REVIEWER,
    drive,
    seal_a_real_verification,
)


@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.delenv("ASSURANCE_CHAIN_RECHECK_SECONDS", raising=False)
    chain_cache.reset()
    yield
    chain_cache.reset()


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "ready.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def delete_row(ledger: EvidenceLedger, where: str) -> int:
    db = sqlite3.connect(ledger.path)
    try:
        n = db.execute(f"DELETE FROM chain WHERE {where}").rowcount  # noqa: S608
        db.commit()
        return n
    finally:
        db.close()


OLD_VERIFICATION = ("seq = (SELECT MIN(seq) FROM chain WHERE kind LIKE '%verification%' "
                    "OR kind LIKE '%bundle%')")


def edit_row(ledger: EvidenceLedger) -> None:
    db = sqlite3.connect(ledger.path)
    try:
        n = db.execute("UPDATE chain SET payload = replace(payload, "
                       "'workspace_containment', 'workspace_containmenx') "
                       f"WHERE {OLD_VERIFICATION}").rowcount
        assert n == 1
        db.commit()
    finally:
        db.close()


def _awaiting(ledger, store):
    case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
    bundle = seal_a_real_verification(ledger, when=LATER)
    store.require_intact()                        # warm: the cached check has passed
    assert chain_cache.lookup(chain_cache.identity(ledger.path)) is not None
    return case, observed, bundle


def _reverify(ledger, store, case, observed, bundle):
    return reverify(store, case.case_id, observed,
                    VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                    interventions_from_ledger(ledger, MACHINE.key),
                    verification_content_hash=bundle.content_hash, actor=REVIEWER)


class TestReverifyCannotReachReadyToCloseOnACachedCheck:
    def test_premise_the_cached_check_is_blind_to_a_deleted_old_row(self, ledger, store):
        _awaiting(ledger, store)
        assert delete_row(ledger, OLD_VERIFICATION) == 1
        store.require_intact()                    # passes: that is the window
        assert not ledger.verify_chain()[0]

    def test_a_deleted_old_verification_row_blocks_reverify(self, ledger, store):
        case, observed, bundle = _awaiting(ledger, store)
        assert delete_row(ledger, OLD_VERIFICATION) == 1
        store.require_intact()                    # blind inside the window
        with pytest.raises(ChainBrokenError):
            _reverify(ledger, store, case, observed, bundle)
        assert CaseStore(ledger).get(case.case_id).status \
            is CaseStatus.AWAITING_REVERIFICATION

    def test_an_edited_old_row_never_yields_ready_to_close(self, ledger, store):
        case, observed, bundle = _awaiting(ledger, store)
        edit_row(ledger)
        try:
            result = _reverify(ledger, store, case, observed, bundle)
        except ChainBrokenError:
            return
        # The edited verification no longer verifies, so it clears nothing: the
        # case stays where it was. What it must never do is read as ready.
        assert result.status is not CaseStatus.READY_TO_CLOSE

    def test_an_intact_chain_still_reaches_ready_to_close(self, ledger, store):
        case, observed, bundle = _awaiting(ledger, store)
        assert _reverify(ledger, store, case, observed, bundle).status \
            is CaseStatus.READY_TO_CLOSE


class TestTheStoreGuardsEveryWriteThatRecordsReadyToClose:
    def test_a_transition_to_ready_to_close_walks_the_whole_chain(self, ledger, store):
        case, _, _ = _awaiting(ledger, store)
        delete_row(ledger, "seq = 1")
        store.require_intact()                    # cached check still passes
        ready = replace(case, status=CaseStatus.READY_TO_CLOSE,
                        required_reverifications=(), required_actions=(),
                        human_decisions_required=())
        with pytest.raises(ChainBrokenError):
            store.transition(ready, actor=REVIEWER, detail="x")

    def test_advance_to_ready_to_close_walks_the_whole_chain(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        case = store.update(replace(case, required_actions=(), required_reverifications=(),
                                    human_decisions_required=()),
                            actor=REVIEWER, detail="nothing outstanding")
        store.require_intact()
        delete_row(ledger, "seq = 1")
        store.require_intact()                    # blind
        with pytest.raises(ChainBrokenError):
            advance(store, case.case_id, actor=REVIEWER)

    def test_a_write_that_cannot_clear_a_case_keeps_the_cheap_check(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.OPEN)
        store.require_intact()
        delete_row(ledger, "seq = 1")
        # claim moves OPEN -> IN_REVIEW; it cannot clear a case, so the documented
        # up-to-60 s window still applies and the cache is not bypassed.
        assert claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER).status \
            is CaseStatus.IN_REVIEW
