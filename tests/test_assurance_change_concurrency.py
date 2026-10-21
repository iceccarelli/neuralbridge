"""No lost update in the case store: read-modify-append is atomic per case.

Every ledger entry is a full snapshot of its case and the newest one *is* the
case. Without a compare-and-swap, a writer that read the case, was slow, and then
appended, silently overwrote whatever another writer appended in between (and
the chain still verified). These tests inject that interleaving at the append
point, deterministically, and then stress it with threads.
"""

from __future__ import annotations

import threading
from dataclasses import replace

import pytest

from assurance.change import (
    CaseStatus,
    CaseStore,
    CaseTransitionError,
    assess_advisory,
    claim,
    decide,
    note_advisory_withdrawn,
    reconstruct_case,
    resolve_decision,
)
from assurance.change.store import DECISION_KIND, REOPENED_KIND, CaseConflictError
from assurance.core.errors import LedgerConflictError, LedgerIntegrityError
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence import chain_cache
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.record import record_manifest

from .test_assurance_change import (
    BOT,
    REVIEWER,
    advisory,
    case_entries,
    drift,
    drive,
    fw,
    item,
    manifest,
)


@pytest.fixture(autouse=True)
def fresh_cache():
    chain_cache.reset()
    yield
    chain_cache.reset()


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "concurrency.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def race_before_next_append(ledger: EvidenceLedger, rival, monkeypatch) -> list[int]:
    """Make ``ledger``'s next ``append`` first let ``rival()`` run to completion.

    That is the interleaving the red team found: this writer has read the case,
    another writer appends, and only then does this writer's append happen.
    """
    real = ledger.append
    fired: list[int] = []

    def append(*args, **kwargs):
        if not fired:
            fired.append(1)
            rival()
        return real(*args, **kwargs)

    monkeypatch.setattr(ledger, "append", append)
    return fired


def other_writer(ledger: EvidenceLedger) -> tuple[EvidenceLedger, CaseStore]:
    """A second connection to the same file: another request, another process."""
    peer = EvidenceLedger(ledger.path)
    return peer, CaseStore(peer)


class TestLedgerCompareAndSwap:
    @staticmethod
    def _ev(n):
        return Evidence(kind="t.k", body={"n": n}, actor=Actor("a", "r"),
                        origin=Origin(system="t", reference="r")).seal()

    def test_an_expected_head_that_still_holds_appends(self, ledger):
        first = ledger.append(self._ev(1), subject="c")
        second = ledger.append(self._ev(2), subject="c", expect_subject_head=first.seq)
        assert second.seq == first.seq + 1

    def test_an_expected_head_that_moved_refuses_and_writes_nothing(self, ledger):
        first = ledger.append(self._ev(1), subject="c")
        ledger.append(self._ev(2), subject="c")
        before = len(ledger)
        with pytest.raises(LedgerConflictError):
            ledger.append(self._ev(3), subject="c", expect_subject_head=first.seq)
        assert len(ledger) == before
        assert ledger.verify_chain()[0]

    def test_zero_means_the_subject_has_no_entry_yet(self, ledger):
        ledger.append(self._ev(1), subject="c")
        with pytest.raises(LedgerConflictError):
            ledger.append(self._ev(2), subject="c", expect_subject_head=0)
        ledger.append(self._ev(3), subject="fresh", expect_subject_head=0)

    def test_only_the_named_kinds_count_towards_the_head(self, ledger):
        first = ledger.append(self._ev(1), subject="c")
        ledger.append(Evidence(kind="other.kind", body={}, actor=Actor("a", "r"),
                               origin=Origin(system="t", reference="r")).seal(), subject="c")
        ledger.append(self._ev(3), subject="c", expect_subject_head=first.seq,
                      expect_kinds=("t.k",))

    def test_no_expectation_appends_as_before(self, ledger):
        ledger.append(self._ev(1), subject="c")
        ledger.append(self._ev(2), subject="c")

    def test_a_conflict_is_not_an_integrity_failure(self):
        assert not issubclass(LedgerConflictError, LedgerIntegrityError)


class TestNoLostUpdate:
    def test_a_close_never_overwrites_a_move_made_after_it_read(
            self, ledger, store, monkeypatch):
        """The red team's repro: A reads READY_TO_CLOSE, B moves the case back to
        awaiting re-verification, A's closure used to be appended over it."""
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        _, peer = other_writer(ledger)

        def rival():
            current = peer.get(case.case_id)
            peer.update(replace(current, status=CaseStatus.AWAITING_REVERIFICATION,
                                required_reverifications=("SF-02",)),
                        actor=BOT, detail="a new look found SF-02 outstanding")

        fired = race_before_next_append(ledger, rival, monkeypatch)
        with pytest.raises(CaseConflictError):
            decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)
        assert fired
        now = CaseStore(EvidenceLedger(ledger.path)).get(case.case_id)
        assert now.status is CaseStatus.AWAITING_REVERIFICATION
        assert now.required_reverifications == ("SF-02",)
        assert not [e for e in case_entries(ledger, case.case_id) if e.kind == DECISION_KIND]
        assert reconstruct_case(ledger, case.case_id).ok
        assert ledger.verify_chain()[0]

    def test_the_conflicting_step_can_be_retried_on_what_is_now_true(
            self, ledger, store, monkeypatch):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        _, peer = other_writer(ledger)
        race_before_next_append(
            ledger,
            lambda: peer.update(
                replace(peer.get(case.case_id), status=CaseStatus.AWAITING_REVERIFICATION,
                        required_reverifications=("SF-02",)), actor=BOT, detail="moved"),
            monkeypatch)
        with pytest.raises(CaseConflictError):
            decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)
        # Re-reading now sees the truth, and the closure is correctly refused.
        with pytest.raises(CaseTransitionError, match="not ready_to_close"):
            decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)

    def test_two_assessments_of_a_recurrence_reopen_the_case_once(
            self, ledger, store, monkeypatch):
        case, _ = drive(ledger, store, CaseStatus.CLOSED)
        record_manifest(ledger, manifest(manifest_id="BACK-TO-A"))
        peer_ledger, peer = other_writer(ledger)
        back = manifest(manifest_id="BACK-TO-A")

        race_before_next_append(
            ledger, lambda: drift(peer, peer_ledger, baseline=back), monkeypatch)
        reopened, _ = drift(store, ledger, baseline=back)
        assert reopened.status is CaseStatus.OPEN
        kinds = [e.kind for e in case_entries(ledger, case.case_id)]
        assert kinds.count(REOPENED_KIND) == 1
        assert len(reopened.prior_closures) == 1
        assert reconstruct_case(ledger, case.case_id).ok

    def test_a_machine_driven_step_does_not_overwrite_a_humans(
            self, ledger, store, monkeypatch):
        """A supplier's withdrawal, computed from a read taken before a person
        rejected the case, must not land on top of the rejection."""
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
        case = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        _, peer = other_writer(ledger)
        fired = race_before_next_append(
            ledger,
            lambda: decide(peer, case.case_id, disposition="rejected", reason="not real",
                           actor=REVIEWER),
            monkeypatch)
        result = note_advisory_withdrawn(
            store, advisory().advisory_id, "retracted", actor=BOT)
        assert fired
        final = CaseStore(EvidenceLedger(ledger.path)).get(case.case_id)
        assert final.status is CaseStatus.REJECTED
        assert result.status is CaseStatus.REJECTED
        assert final.human_decisions_required == ()
        assert reconstruct_case(ledger, case.case_id).ok

    def test_threads_resolving_different_questions_lose_none(self, tmp_path):
        """Stress: each of N threads, with its own connection, resolves its own
        question on one case, retrying when told the case moved. None may be lost,
        and the case's history grows by exactly one entry per recorded step."""
        n = 10
        path = tmp_path / "stress.db"
        setup_ledger = EvidenceLedger(path)
        setup = CaseStore(setup_ledger)
        case, _ = drive(setup_ledger, setup, CaseStatus.IN_REVIEW)
        questions = tuple(f"question {i}?" for i in range(n))
        setup.update(replace(setup.get(case.case_id), human_decisions_required=questions),
                     actor=BOT, detail="questions")
        failures: list[BaseException] = []
        conflicts = [0]
        barrier = threading.Barrier(n)

        def worker(i: int) -> None:
            try:
                mine = CaseStore(EvidenceLedger(path))
                barrier.wait()
                for _ in range(500):
                    try:
                        resolve_decision(mine, case.case_id, decision=questions[i],
                                         resolution=f"answer {i}", actor=REVIEWER)
                        return
                    except CaseConflictError:
                        conflicts[0] += 1
                raise AssertionError("never got a turn")
            except BaseException as exc:  # noqa: BLE001 - reported below
                failures.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        assert not failures, failures
        final = CaseStore(EvidenceLedger(path)).get(case.case_id)
        assert final.human_decisions_required == ()
        assert {r["decision"] for r in final.resolved_decisions} == set(questions)
        lengths = [len(e.evidence().body["case"]["history"])
                   for e in case_entries(EvidenceLedger(path), case.case_id)]
        assert lengths == list(range(lengths[0], lengths[0] + len(lengths))), \
            "two snapshots were built on the same predecessor: an update was lost"
        assert conflicts[0] > 0, "the stress test never actually raced"
        assert reconstruct_case(EvidenceLedger(path), case.case_id).ok

    def test_threads_assessing_the_same_trigger_open_it_once(self, tmp_path):
        """Machine-driven writers retry on their own: N threads that all see a new
        drift at once end with one case and one opening."""
        n = 8
        path = tmp_path / "assess.db"
        EvidenceLedger(path)
        failures: list[BaseException] = []
        barrier = threading.Barrier(n)
        ids: list[str] = []

        def worker() -> None:
            try:
                ledger = EvidenceLedger(path)
                mine = CaseStore(ledger)
                barrier.wait()
                case, _ = drift(mine, ledger)
                ids.append(case.case_id)
            except BaseException as exc:  # noqa: BLE001 - reported below
                failures.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(120)
        assert not failures, failures
        assert len(set(ids)) == 1
        ledger = EvidenceLedger(path)
        entries = case_entries(ledger, ids[0])
        assert [e.kind for e in entries] == ["assurance.change.opened"]
        assert ledger.verify_chain()[0]


@pytest.fixture
def http(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from assurance.api import deps
    from assurance.api.service import create_app

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "l.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "a.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    with TestClient(create_app()) as c:
        accounts = deps.get_accounts()
        account = accounts.upsert_account(email="cell-concurrency@example.de", tier="cell")
        yield c, {"X-API-Key": accounts.issue_key(account.id)}
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


class TestConflictOverHttp:
    def test_a_step_that_lost_the_race_is_a_clear_409_and_records_nothing(
            self, http, monkeypatch):
        client, headers = http
        r = client.post("/v1/change/assess/drift", headers=headers, json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(item(content_hash="d" * 64),
                                 manifest_id="NOW").to_dict()})
        case_id = r.json()["case"]["case_id"]
        assert client.post(f"/v1/change/cases/{case_id}/claim", headers=headers,
                           json={"owner": "v.grimaldi", "actor": "v.grimaldi"}
                           ).status_code == 200

        real = EvidenceLedger.append
        fired: list[int] = []

        def append(self, evidence, subject="", **kw):
            if subject == case_id and not fired:
                fired.append(1)
                rival = CaseStore(EvidenceLedger(self.path))
                current = rival.get(case_id)
                rival.update(replace(current, owner="someone.else"), actor=BOT,
                             detail="rival write")
            return real(self, evidence, subject, **kw)

        monkeypatch.setattr(EvidenceLedger, "append", append)
        r = client.post(f"/v1/change/cases/{case_id}/decision", headers=headers,
                        json={"disposition": "rejected", "reason": "not real",
                              "actor": "v.grimaldi"})
        monkeypatch.setattr(EvidenceLedger, "append", real)
        assert fired
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "case_conflict"
        assert detail["case_id"] == case_id
        assert "Re-read" in detail["detail"]
        got = client.get(f"/v1/change/cases/{case_id}", headers=headers).json()
        assert got["status"] == "in_review" and got["owner"] == "someone.else"
