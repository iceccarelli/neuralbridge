"""The watch and a change a person has already ruled on.

The ledger now derives an implied change from a sealed manifest that shows one. The watch's
drift case owns that change; the watch must not open a second 'intervention' case for it
after a person has rejected or closed the first.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from assurance.change import CaseStatus, CaseStore, advance, claim, decide
from assurance.change.service import waive_reverification
from assurance.core.evidence import Actor
from assurance.machinery.divergence import compare
from assurance.machinery.record import interventions_from_ledger, record_manifest
from assurance.watch.runner import _assess_interventions, run_watch

from . import test_assurance_watch_cases as wc
from .test_assurance_staleness_integrity import (
    HASH_A,
    HASH_B,
    KEY,
    manifest,
    seal,
)
from .test_assurance_watch_cases import (
    KEY_0412,
    KEY_0501,
    PERSON,
    T0,
    WEEK,
    reexport,
    verify_machine,
)

work, config, ledger, store = wc.work, wc.config, wc.ledger, wc.store


def _drift(work, config, ledger, store):
    run_watch(config, ledger, now=T0)
    verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
    verify_machine(ledger, KEY_0501, when=T0 + timedelta(days=1))
    reexport(work, "0412", fw=b"firmware 3.9.0")
    run = run_watch(config, ledger, now=T0 + WEEK)
    out = next(o for o in run.outcomes if o.serial == "0412")
    assert out.case_id and out.intervention_case_ids == ()
    return store.get(out.case_id)


class TestARulingStands:
    def test_a_rejected_drift_case_does_not_spawn_a_second_case(
            self, work, config, ledger, store):
        case = _drift(work, config, ledger, store)
        decide(store, case.case_id, disposition="rejected", reason="not real", actor=PERSON)
        before = {c.case_id for c in store.list()}
        run_watch(config, ledger, now=T0 + 2 * WEEK)
        assert {c.case_id for c in store.list()} == before

    def test_a_waived_and_closed_drift_case_does_not_spawn_a_second_case(
            self, work, config, ledger, store):
        case = _drift(work, config, ledger, store)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=PERSON)
        while case.status is not CaseStatus.AWAITING_REVERIFICATION:
            case = advance(store, case.case_id, actor=PERSON)
        for entry in list(case.required_reverifications):
            case = waive_reverification(store, case.case_id, entry=entry, reason="accepted",
                                        actor=PERSON)
        while case.status is not CaseStatus.READY_TO_CLOSE:
            case = advance(store, case.case_id, actor=PERSON)
        decide(store, case.case_id, disposition="closed", reason="waived", actor=PERSON)
        before = {c.case_id for c in store.list()}
        run_watch(config, ledger, now=T0 + 2 * WEEK)
        assert {c.case_id for c in store.list()} == before


class TestTheOpenerForAnImpliedChange:
    ACTOR = Actor("watch", kind="automation")

    def _two_manifests(self, ledger):
        first, second = manifest(mid="M1", fw=HASH_A), manifest(mid="M2", fw=HASH_B)
        record_manifest(ledger, first)
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_manifest(ledger, second)
        return first, second

    def test_a_change_no_drift_case_owns_gets_exactly_one_case(self, ledger):
        _, second = self._two_manifests(ledger)
        store = CaseStore(ledger)
        opened = _assess_interventions(store, ledger, second, KEY, self.ACTOR)
        assert len(opened) == 1
        assert store.get(opened[0]).trigger_id.startswith("implied:")
        assert _assess_interventions(store, ledger, second, KEY, self.ACTOR) == ()

    def test_a_change_a_drift_case_already_owns_gets_none_whatever_its_status(self, ledger):
        from assurance.change import assess_drift

        first, second = self._two_manifests(ledger)
        store = CaseStore(ledger)
        # the drift case, assessed as the watch does (before the manifest was sealed)
        from assurance.machinery.staleness import VerificationRecord
        case = assess_drift(store, compare(first, second), second,
                            VerificationRecord.from_ledger(ledger, subject=KEY),
                            [i for i in interventions_from_ledger(ledger, KEY)
                             if not i.intervention_id.startswith("implied:")],
                            actor=self.ACTOR)
        assert case is not None
        decide(store, case.case_id, disposition="rejected", reason="no", actor=PERSON)
        assert _assess_interventions(store, ledger, second, KEY, self.ACTOR) == ()
