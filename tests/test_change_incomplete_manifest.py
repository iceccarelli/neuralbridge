"""A collection that did not look at everything is never proof of the machine's state.

Red-team findings B2 and B3, and the collector's half of B3. The principle: a failure to
check must not look like a successful check. A manifest marked ``[collection incomplete: ...]``
lacks items its plan names; it can omit the very item that changed.

* ``reverify`` used to take the newest sealed manifest as the post-change state, marked or
  not, so a partial look plus a later passing verification cleared a drift case with nothing
  left to re-verify.
* ``enrol_machine`` used to take an incomplete manifest as the machine's baseline.
* ``collect run --out`` / ``--seal-incomplete`` wrote the incomplete manifest with no marker,
  so every later reader saw a complete one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from assurance.change import (
    CaseStatus,
    CaseStore,
    CaseTransitionError,
    advance,
    assess_drift,
    claim,
    reverify,
)
from assurance.change.service import INCOMPLETE_COLLECTION_MARK
from assurance.collect.cli import main as collect_main
from assurance.collect.collector import collect
from assurance.collect.plan import CollectionPlan
from assurance.core.evidence import Actor
from assurance.core.identity import utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery import manifest as manifest_module
from assurance.machinery.divergence import compare
from assurance.machinery.enrol import EnrolmentError, enrol_machine
from assurance.machinery.record import (
    _PARTIAL_LOOK_MARK,
    MANIFEST_KIND,
    interventions_from_ledger,
    record_manifest,
)
from assurance.machinery.staleness import VerificationRecord

from .support import plan_dict, write_export
from .test_assurance_change import (  # noqa: F401  (the autouse clock fixture)
    ENG,
    MACHINE,
    REVIEWER,
    _pinned_clock,
    item,
    manifest,
    seal_a_real_verification,
)

PERSON = Actor("Anna Keller", "safety engineer", kind="person")
T_BASE = datetime(2026, 1, 20, tzinfo=UTC)
T_TRIGGER = datetime(2026, 2, 15, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "incomplete.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def _awaiting_reverification(store, ledger):
    """A drift case on the firmware, opened by a look taken at T_TRIGGER, ready for evidence."""
    base = manifest(manifest_id="BASE", taken_at=T_BASE)
    record_manifest(ledger, base)
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
    observed = manifest(item(content_hash="d" * 64), manifest_id="NOW", taken_at=T_TRIGGER)
    case = assess_drift(
        store, compare(base, observed), observed,
        VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
        interventions_from_ledger(ledger, MACHINE.key), actor=ENG)
    assert case is not None and case.required_reverifications
    case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
    case = advance(store, case.case_id, actor=REVIEWER)
    case = advance(store, case.case_id, actor=REVIEWER)
    assert case.status is CaseStatus.AWAITING_REVERIFICATION
    return case, observed


def _reverify(store, ledger, case, manifest_arg, bundle):
    return reverify(
        store, case.case_id, manifest_arg,
        VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
        interventions_from_ledger(ledger, MACHINE.key),
        verification_content_hash=bundle.content_hash, actor=REVIEWER)


def _partial(after, **kw):
    """A look that did not collect the firmware, marked incomplete the way the watch marks it."""
    return manifest(item("ITM-X", implements=(), content_hash="e" * 64), manifest_id="PART",
                    taken_at=after,
                    notes=f"{INCOMPLETE_COLLECTION_MARK}: ITM-FW not collected]", **kw)


class TestOneMarker:
    def test_the_marker_is_defined_once_and_keeps_its_stored_format(self):
        assert INCOMPLETE_COLLECTION_MARK == "[collection incomplete"
        assert _PARTIAL_LOOK_MARK == INCOMPLETE_COLLECTION_MARK
        assert manifest_module.INCOMPLETE_COLLECTION_MARK == INCOMPLETE_COLLECTION_MARK

    def test_the_shared_predicate_recognises_the_marker_the_watch_writes(self):
        assert manifest_module.manifest_is_incomplete(_partial(T_TRIGGER))
        assert not manifest_module.manifest_is_incomplete(manifest())
        assert not manifest_module.manifest_is_incomplete(manifest(notes="the technician's own note"))


class TestReverifyNeedsACompleteLook:
    def test_a_partial_look_that_omits_the_changed_item_clears_nothing(self, store, ledger):
        case, _ = _awaiting_reverification(store, ledger)
        after = utc_now() + timedelta(hours=1)
        part = _partial(after)
        record_manifest(ledger, part)
        bundle = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
        with pytest.raises(CaseTransitionError, match="(?i)predates|incomplete|complete"):
            _reverify(store, ledger, case, part, bundle)
        again = store.get(case.case_id)
        assert again.status is CaseStatus.AWAITING_REVERIFICATION
        assert again.required_reverifications == ("SF-01", "SF-02")

    def test_a_ledger_whose_newest_manifest_is_partial_does_not_clear_a_case_either(
            self, store, ledger):
        # The caller hands over a complete manifest with the case's configuration; the
        # newest thing in the ledger is the partial look. The ledger decides.
        case, observed = _awaiting_reverification(store, ledger)
        after = utc_now() + timedelta(hours=1)
        record_manifest(ledger, _partial(after))
        bundle = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
        with pytest.raises(CaseTransitionError):
            _reverify(store, ledger, case, observed, bundle)
        assert store.get(case.case_id).status is CaseStatus.AWAITING_REVERIFICATION

    def test_a_ledger_holding_nothing_but_partial_looks_is_refused_by_name(
            self, store, ledger):
        base = manifest(manifest_id="BASE", taken_at=T_BASE)       # in memory, never sealed
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW", taken_at=T_TRIGGER)
        case = assess_drift(store, compare(base, observed), observed, [], [], actor=ENG)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)
        assert case.status is CaseStatus.AWAITING_REVERIFICATION
        after = utc_now() + timedelta(hours=1)
        part = _partial(after)
        record_manifest(ledger, part)
        bundle = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
        with pytest.raises(CaseTransitionError, match="incomplete collection"):
            _reverify(store, ledger, case, part, bundle)

    def test_the_newest_complete_look_is_used_when_a_partial_one_follows_it(
            self, store, ledger):
        case, _ = _awaiting_reverification(store, ledger)
        t1 = utc_now() + timedelta(hours=1)
        complete = manifest(item(content_hash="d" * 64), manifest_id="AFTER", taken_at=t1)
        record_manifest(ledger, complete)
        record_manifest(ledger, _partial(t1 + timedelta(minutes=10)))
        # the run states the COMPLETE look's configuration (a partial look is not a configuration)
        bundle = seal_a_real_verification(ledger, when=t1 + timedelta(hours=1),
                                          configuration_hash=complete.configuration_hash())
        done = _reverify(store, ledger, case, complete, bundle)
        assert done.status is CaseStatus.READY_TO_CLOSE
        assert done.required_reverifications == ()

    def test_a_partial_manifest_handed_to_the_recheck_is_refused(self, store, ledger):
        case, _ = _awaiting_reverification(store, ledger)
        t1 = utc_now() + timedelta(hours=1)
        record_manifest(ledger, manifest(item(content_hash="d" * 64), manifest_id="AFTER",
                                         taken_at=t1))
        bundle = seal_a_real_verification(ledger, when=t1 + timedelta(hours=1))
        with pytest.raises(CaseTransitionError, match="incomplete"):
            _reverify(store, ledger, case, _partial(t1), bundle)

    def test_an_unmarked_manifest_that_does_not_list_the_changed_item_clears_nothing(
            self, store, ledger):
        case, _ = _awaiting_reverification(store, ledger)
        t1 = utc_now() + timedelta(hours=1)
        silent = manifest(item("ITM-X", implements=(), content_hash="e" * 64),
                          manifest_id="SILENT", taken_at=t1)   # no marker, no firmware
        record_manifest(ledger, silent)
        bundle = seal_a_real_verification(ledger, when=t1 + timedelta(hours=1))
        with pytest.raises(CaseTransitionError, match="ITM-FW"):
            _reverify(store, ledger, case, silent, bundle)


class TestEnrolmentNeedsACompleteBaseline:
    def test_an_incomplete_manifest_is_not_enrolled(self, ledger):
        with pytest.raises(EnrolmentError, match="incomplete"):
            enrol_machine(ledger, _partial(T_TRIGGER), actor=PERSON)
        assert list(ledger.entries(kind=MANIFEST_KIND)) == []

    def test_it_is_refused_even_when_the_machine_is_already_enrolled(self, ledger):
        enrol_machine(ledger, manifest(manifest_id="OK"), actor=PERSON)
        n = len(ledger)
        with pytest.raises(EnrolmentError, match="incomplete"):
            enrol_machine(ledger, _partial(T_TRIGGER), actor=PERSON)
        assert len(ledger) == n


class TestTheCollectorMarksWhatItDidNotReach:
    def _incomplete(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        (root / "controller-fw.bin").unlink()
        return CollectionPlan.from_dict(plan_dict()), root

    def test_the_manifest_of_an_incomplete_collection_carries_the_marker(self, tmp_path):
        plan, root = self._incomplete(tmp_path)
        result = collect(plan, root, serial="0412", taken_by=ENG)
        assert not result.complete
        assert manifest_module.manifest_is_incomplete(result.manifest)
        assert "ITM-FW" in result.manifest.notes

    def test_a_complete_collection_is_not_marked(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        result = collect(CollectionPlan.from_dict(plan_dict()), root, serial="0412",
                         taken_by=ENG)
        assert result.complete and not manifest_module.manifest_is_incomplete(result.manifest)

    def test_the_marker_is_not_written_twice(self, tmp_path):
        plan, root = self._incomplete(tmp_path)
        result = collect(plan, root, serial="0412", taken_by=ENG,
                         notes="[collection incomplete: ITM-FW not collected]")
        assert result.manifest.notes.count(INCOMPLETE_COLLECTION_MARK) == 1

    def test_collect_run_out_writes_the_marker_to_the_file(self, tmp_path, capsys):
        plan, root = self._incomplete(tmp_path)
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
        out = tmp_path / "manifest.json"
        code = collect_main(["run", str(plan_path), "--root", str(root),
                             "--serial", "0412", "--actor", "Anna Keller",
                             "--out", str(out)])
        assert code == 1   # incomplete
        written = json.loads(out.read_text(encoding="utf-8"))
        assert INCOMPLETE_COLLECTION_MARK in written["notes"]

    def test_a_sealed_incomplete_collection_is_a_partial_look_to_the_ledger(
            self, tmp_path, ledger):
        plan, root = self._incomplete(tmp_path)
        record_manifest(ledger, collect(plan, root, serial="0412", taken_by=ENG).manifest)
        sealed = next(iter(ledger.entries(kind=MANIFEST_KIND)))
        assert INCOMPLETE_COLLECTION_MARK in sealed.evidence().body["manifest"]["notes"]


class TestAMarkedLookDoesNotHideARemovalForever:
    """Read-only suspicion from the red team: a partial look's missing items are not read as
    removed (not collected is not gone). That must be about THAT look only."""

    def _removed_ids(self, ledger):
        return [i.item_id for i in interventions_from_ledger(ledger, MACHINE.key)
                if "removed" in i.reason]

    def test_a_later_complete_look_without_the_item_shows_the_removal(self, ledger):
        record_manifest(ledger, manifest(manifest_id="M1", taken_at=T_BASE))
        record_manifest(ledger, _partial(T_BASE + timedelta(days=1)))
        assert self._removed_ids(ledger) == []     # not collected is not gone
        record_manifest(ledger, manifest(
            item("ITM-X", implements=(), content_hash="e" * 64), manifest_id="M3",
            taken_at=T_BASE + timedelta(days=2)))
        assert self._removed_ids(ledger) == ["ITM-FW"]

    def test_the_partial_look_never_becomes_the_comparison_baseline(self, ledger):
        record_manifest(ledger, manifest(manifest_id="M1", taken_at=T_BASE))
        record_manifest(ledger, _partial(T_BASE + timedelta(days=1)))
        record_manifest(ledger, manifest(manifest_id="M3", taken_at=T_BASE + timedelta(days=2)))
        assert interventions_from_ledger(ledger, MACHINE.key) == []
