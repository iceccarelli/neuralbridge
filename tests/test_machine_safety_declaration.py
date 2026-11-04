"""A change to what a manifest says its safety functions are is a safety-relevant change.

Red-team findings B4 and B5, plus duplicate function ids.

``configuration_hash`` covers a manifest's items, not its functions, and it is in stored
ledgers so it cannot change. So emptying a function's ``verified_by``, swapping it for a
trivial check, or lowering its required performance level compared as ``matches``: no case,
no staleness. A separate, versioned ``safety_declaration_hash`` now covers the functions and
``compare`` reads it. And dropping an attribution (an item no longer ``implements`` a
function) no longer takes the item out of scope: the next change to its artefact still
disturbs the functions it used to carry, and a drift case never goes empty because the
observed manifest lost the function.
"""

from __future__ import annotations

from dataclasses import replace
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
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery import manifest as manifest_module
from assurance.machinery.divergence import ChangeKind, Severity, compare
from assurance.machinery.manifest import ManifestError, SafetyFunction
from assurance.machinery.record import interventions_from_ledger, record_manifest
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

from .test_assurance_change import (  # noqa: F401  (the autouse clock fixture)
    ENG,
    FUNCS,
    MACHINE,
    REVIEWER,
    _pinned_clock,
    item,
    manifest,
    seal_a_real_verification,
)

T0 = datetime(2026, 1, 20, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "declaration.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def _with_function(m, fid="SF-01", **over):
    fns = tuple(replace(f, **over) if f.function_id == fid else f for f in m.functions)
    return replace(m, functions=fns, manifest_id=m.manifest_id + "-F")


def _coverage(ledger, m):
    report = assess_coverage(
        m, VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
        interventions_from_ledger(ledger, MACHINE.key))
    return {f.function_id: f.coverage for f in report.functions}


class TestTheDeclarationHash:
    def test_the_configuration_hash_does_not_move(self):
        # It is in stored ledgers. Functions were never part of it and still are not.
        a = manifest()
        b = _with_function(a, verified_by=())
        assert a.configuration_hash() == b.configuration_hash()

    def test_the_declaration_hash_moves_with_what_verifies_a_function(self):
        a = manifest()
        assert a.safety_declaration_hash() != _with_function(a, verified_by=()).safety_declaration_hash()
        assert a.safety_declaration_hash() != _with_function(
            a, verified_by=("trivial",)).safety_declaration_hash()
        assert a.safety_declaration_hash() != _with_function(
            a, required_performance="PL a").safety_declaration_hash()

    def test_it_ignores_who_looked_and_the_order_of_checks(self):
        a = manifest()
        b = replace(a, manifest_id="OTHER", taken_at=T0 + timedelta(days=9),
                    functions=tuple(
                        replace(f, verified_by=tuple(reversed(f.verified_by)))
                        for f in reversed(a.functions)))
        assert a.safety_declaration_hash() == b.safety_declaration_hash()

    def test_it_is_versioned(self):
        assert manifest_module.SAFETY_DECLARATION_SCHEMA.endswith("/1")


class TestWeakeningADeclarationIsDrift:
    @pytest.mark.parametrize("over", [
        {"verified_by": ()},                      # emptied
        {"verified_by": ("trivial",)},            # swapped for a check that proves nothing
        {"required_performance": "PL a"},         # PL d -> a
        {"required_performance": "PL e"},         # raised: the earlier run was to a lower bar
    ], ids=["emptied", "swapped", "pl-lowered", "pl-raised"])
    def test_each_is_safety_relevant_not_a_match(self, over):
        base = manifest(manifest_id="BASE")
        d = compare(base, _with_function(base, **over))
        assert d.verdict == "safety_relevant_drift"
        assert not d.identical
        change = next(c for c in d.changes
                      if c.kind is ChangeKind.FUNCTION_DECLARATION_CHANGED)
        assert change.severity is Severity.SAFETY_RELEVANT
        assert change.functions == ("SF-01",)
        assert d.affected_functions == ("SF-01",)

    def test_the_same_manifest_still_matches(self):
        base = manifest(manifest_id="BASE")
        d = compare(base, replace(base, manifest_id="NOW"))
        assert d.verdict == "matches" and d.identical

    def test_a_reworded_description_is_notable_not_safety_relevant(self):
        base = manifest(manifest_id="BASE")
        d = compare(base, _with_function(base, description="Stop, reworded"))
        assert d.verdict == "drifted"
        assert [c.severity for c in d.changes] == [Severity.NOTABLE]

    def test_a_dropped_function_is_safety_relevant(self):
        base = manifest(manifest_id="BASE")
        gone = replace(base, manifest_id="NOW",
                       items=(item(implements=("SF-02",)),),
                       functions=tuple(f for f in base.functions if f.function_id == "SF-02"))
        d = compare(base, gone)
        removed = [c for c in d.changes if c.kind is ChangeKind.FUNCTION_REMOVED]
        assert [c.functions for c in removed] == [("SF-01",)]
        assert removed[0].severity is Severity.SAFETY_RELEVANT
        assert d.verdict == "safety_relevant_drift"

    def test_the_divergence_report_carries_both_declaration_hashes(self):
        base = manifest(manifest_id="BASE")
        d = compare(base, _with_function(base, verified_by=()))
        body = d.to_dict()
        assert body["baseline"]["safety_declaration"] == base.safety_declaration_hash()
        assert body["observed"]["safety_declaration"] != body["baseline"]["safety_declaration"]


class TestADeclarationChangeFlowsIntoCasesAndStaleness:
    def test_a_case_is_opened_for_a_declaration_only_change(self, store):
        base = manifest(manifest_id="BASE")
        observed = _with_function(base, required_performance="PL a")
        case = assess_drift(store, compare(base, observed), observed, [], [], actor=ENG)
        assert case is not None
        assert case.affected_functions == ("SF-01",)
        assert "SF-01" in case.required_reverifications

    def test_a_sealed_declaration_change_ends_the_verification_it_weakened(self, ledger):
        record_manifest(ledger, manifest(manifest_id="M1", taken_at=T0))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        before = manifest(manifest_id="M1")
        assert _coverage(ledger, before) == {"SF-01": Coverage.CURRENT,
                                              "SF-02": Coverage.CURRENT}
        later = _with_function(before, required_performance="PL a")
        record_manifest(ledger, replace(later, taken_at=T0 + timedelta(days=60)))
        now = _coverage(ledger, later)
        assert now["SF-01"] is Coverage.STALE
        assert now["SF-02"] is Coverage.CURRENT        # only the declaration that moved

    def test_a_declaration_change_is_not_explained_away_by_an_item_record(self, ledger):
        record_manifest(ledger, manifest(manifest_id="M1", taken_at=T0))
        later = _with_function(manifest(manifest_id="M1"), verified_by=("trivial",))
        record_manifest(ledger, replace(later, taken_at=T0 + timedelta(days=1)))
        implied = [i for i in interventions_from_ledger(ledger, MACHINE.key)
                   if i.item_id == "function:SF-01"]
        assert len(implied) == 1 and implied[0].explained_by == ""


class TestDroppingAnAttributionKeepsTheItemInScope:
    """The two-step: drop ``implements``, then change the firmware hash."""

    def test_step_one_is_safety_relevant_not_merely_notable(self):
        base = manifest(manifest_id="BASE")
        step1 = manifest(item(implements=()), manifest_id="S1")
        d = compare(base, step1)
        change = next(c for c in d.changes if c.kind is ChangeKind.ATTRIBUTION_CHANGED)
        assert change.severity is Severity.SAFETY_RELEVANT
        assert d.verdict == "safety_relevant_drift"
        assert set(d.affected_functions) == {"SF-01", "SF-02"}

    def test_a_new_attribution_alone_stays_notable(self):
        base = manifest(item(implements=("SF-01",)), manifest_id="BASE")
        wider = manifest(item(implements=("SF-01", "SF-02")), manifest_id="S1")
        d = compare(base, wider)
        assert [c.severity for c in d.changes] == [Severity.NOTABLE]

    def test_step_two_without_history_reads_only_the_two_manifests(self):
        step1 = manifest(item(implements=()), manifest_id="S1")
        step2 = manifest(item(implements=(), content_hash="9" * 64), manifest_id="S2")
        assert compare(step1, step2).verdict == "drifted"          # the gap, on its own

    def test_step_two_with_the_last_complete_attribution_is_safety_relevant(self):
        base = manifest(manifest_id="BASE")
        step1 = manifest(item(implements=()), manifest_id="S1")
        step2 = manifest(item(implements=(), content_hash="9" * 64), manifest_id="S2")
        carried = manifest_module.last_attribution([base, step1])
        assert carried == {"ITM-FW": ("SF-01", "SF-02")}
        d = compare(step1, step2, carried_attribution=carried)
        assert d.verdict == "safety_relevant_drift"
        assert set(d.affected_functions) == {"SF-01", "SF-02"}

    def test_last_attribution_skips_plans_and_partial_looks(self):
        base = manifest(manifest_id="BASE")
        partial = manifest(item(implements=("SF-02",)), manifest_id="P",
                           notes="[collection incomplete: x not collected]")
        assert manifest_module.last_attribution([base, partial])["ITM-FW"] == ("SF-01", "SF-02")

    def test_the_ledger_keeps_both_functions_stale_after_step_two(self, ledger):
        record_manifest(ledger, manifest(manifest_id="M1", taken_at=T0))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        m2 = manifest(item(implements=()), manifest_id="M2", taken_at=T0 + timedelta(days=60))
        record_manifest(ledger, m2)
        m3 = manifest(item(implements=(), content_hash="9" * 64), manifest_id="M3",
                      taken_at=T0 + timedelta(days=61))
        record_manifest(ledger, m3)
        cov = _coverage(ledger, m3)
        assert cov == {"SF-01": Coverage.STALE, "SF-02": Coverage.STALE}

    def test_the_ledger_does_not_cry_wolf_on_an_unrelated_item(self, ledger):
        extra = item("ITM-NOTE", implements=(), content_hash="1" * 64, name="release notes")
        record_manifest(ledger, manifest(item(), extra, manifest_id="M1", taken_at=T0))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        m2 = manifest(item(), replace(extra, content_hash="2" * 64), manifest_id="M2",
                      taken_at=T0 + timedelta(days=60))
        record_manifest(ledger, m2)
        assert set(_coverage(ledger, m2).values()) == {Coverage.CURRENT}


class TestADroppedFunctionNeverLeavesNothingToReverify:
    """Single step: the observed manifest loses the functions AND the firmware changed."""

    def _opened(self, store, ledger):
        record_manifest(ledger, manifest(manifest_id="BASE", taken_at=T0))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        base = manifest(manifest_id="BASE")
        observed = manifest(item(content_hash="d" * 64, implements=()), functions=(),
                            manifest_id="NOW", taken_at=T0 + timedelta(days=60))
        d = compare(base, observed)
        assert d.verdict == "safety_relevant_drift"
        case = assess_drift(
            store, d, observed,
            VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
            interventions_from_ledger(ledger, MACHINE.key), actor=ENG)
        return case, observed

    def test_the_case_requires_the_functions_the_observed_manifest_lost(self, store, ledger):
        case, _ = self._opened(store, ledger)
        assert case is not None
        assert set(case.required_reverifications) == {"SF-01", "SF-02"}
        assert case.required_actions
        assert case.evidence_current["SF-01"] == "unknown"

    def test_it_cannot_be_walked_to_ready_to_close(self, store, ledger):
        case, _ = self._opened(store, ledger)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)      # -> awaiting_action
        case = advance(store, case.case_id, actor=REVIEWER)      # -> awaiting_reverification
        assert case.status is CaseStatus.AWAITING_REVERIFICATION
        with pytest.raises(CaseTransitionError):
            advance(store, case.case_id, actor=REVIEWER)

    def test_a_verification_alone_does_not_clear_a_function_nobody_declares(
            self, store, ledger):
        case, observed = self._opened(store, ledger)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)
        record_manifest(ledger, observed)
        bundle = seal_a_real_verification(ledger, when=datetime.now(UTC) + timedelta(hours=1))
        done = reverify(
            store, case.case_id, observed,
            VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
            interventions_from_ledger(ledger, MACHINE.key),
            verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert done.status is CaseStatus.AWAITING_REVERIFICATION
        assert set(done.required_reverifications) == {"SF-01", "SF-02"}


class TestDuplicateFunctionIds:
    def test_two_declarations_of_one_function_are_refused(self):
        a = SafetyFunction("SF-01", "stop", "PL d", verified_by=("ssm_separation",))
        b = SafetyFunction("SF-01", "stop", "PL a", verified_by=())
        with pytest.raises(ManifestError, match="twice"):
            manifest(functions=(a, b, FUNCS[1]))

    def test_distinct_ids_are_fine(self):
        assert len(manifest().functions) == 2
