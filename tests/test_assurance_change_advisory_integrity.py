"""An advisory case must not lose what the advisory report said.

Findings this file pins (chain: advisory -> fleet -> case -> human decision -> closed record):

* an advisory whose only result is UNKNOWN used to open a case with "0 machines affected"
  and no required work, which reached ``ready_to_close`` with "Evidence is current" and was
  closed; the unknown machines were only generic ``checks_skipped`` text;
* a second supplier's advisory that REUSES an advisory id was swallowed by the closed case
  of the first (``[CLOSED] 1 machine(s) affected``, ``change list`` showing 0 open).
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.change.model import CaseStatus, ChangeAssuranceCase
from assurance.change.replay import reconstruct_case
from assurance.change.service import (
    CaseTransitionError,
    advance,
    advisory_case_id,
    assess_advisory,
    claim,
    decide,
    resolve_decision,
    waive_reverification,
)
from assurance.change.store import CaseStore
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
)
from assurance.fleet.impact import Exposure, FunctionExposure, ImpactReport, assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import record_manifest
from assurance.machinery.staleness import Coverage

PERSON = Actor("a.integrator", "safety engineer")
DECIDER = Actor("v.grimaldi", "safety lead")
BOT = Actor("watch", "automation", kind="automation")
AFFECTED = "a" * 64
SCAN_AFFECTED = "b" * 64

FUNCS = (
    SafetyFunction("SF-01", "Protective stop", "PL d", verified_by=("ssm_separation",)),
    SafetyFunction("SF-02", "Speed limit", "PL d", verified_by=("speed_limit",)),
)


def fw(*, version="3.8.2", content_hash=AFFECTED, source=HashSource.READ_FROM_MACHINE,
       supplier="ControlCo", name="Safety controller firmware"):
    return SafetyItem("ITM-FW", ItemKind.FIRMWARE, name, version, content_hash, source,
                      supplier=supplier, implements=("SF-01", "SF-02"))


def manifest(serial, item, *, country="DE"):
    return SafetyManifest(
        manifest_id=f"MAN-{serial}",
        machine=MachineIdentity("Grimaldi", "AR-7", serial, site="Plant 2", country=country),
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 9, 14, tzinfo=UTC),
        taken_by=PERSON, functions=FUNCS, items=(item,), method="synthetic")


def advisory(*, advisory_id="CTRL-2026-11", issued_by="ControlCo", supplier="ControlCo",
             name="Safety controller firmware", versions=("3.8.0", "3.8.1", "3.8.2"),
             hashes=(AFFECTED,), title="Watchdog may not trip", **over):
    kw = {
        "advisory_id": advisory_id, "issued_by": issued_by,
        "issued_at": datetime(2026, 9, 12, 8, tzinfo=UTC), "title": title,
        "summary": "The watchdog can fail to trigger the safety-rated stop.",
        "severity": AdvisorySeverity.SAFETY_RELEVANT,
        "affected": (AffectedArtefact(supplier=supplier, name=name, versions=versions,
                                      content_hashes=hashes),),
        "remedy": "Update to 3.9.0 and re-run the stop-performance test.",
        "reference": "https://example.invalid/advisory", "fixed_versions": ("3.9.0",),
        "fixed_hashes": ("3" * 64,),
    }
    kw.update(over)
    return ComponentAdvisory(**kw)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "fleet.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def impact_of(ledger, adv):
    return assess_impact(adv, Fleet.from_ledger(ledger))


def unknown_only(ledger):
    """Machine 0804: version spelled differently, no hash recorded: neither matched nor excluded."""
    record_manifest(ledger, manifest("0804", fw(version="V3.8.2", content_hash="",
                                                source=HashSource.DECLARED)))


# =====================================================================
# F2 — an unknown machine is a question for a person, not an absence
# =====================================================================

class TestUnknownMachinesAreNamedAndBlockClosure:
    def test_the_fixture_is_the_reported_shape(self, ledger):
        unknown_only(ledger)
        impact = impact_of(ledger, advisory())
        assert impact.machines_affected == ()
        assert impact.unknown_machines == ("Grimaldi/AR-7#0804",)
        assert impact.verdict == "needs_review"

    def test_the_case_names_the_unknown_machine_and_asks_a_question(self, ledger, store):
        unknown_only(ledger)
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        assert case is not None
        assert [u["machine"] for u in case.unknown_machines] == ["Grimaldi/AR-7#0804"]
        assert "no artefact hash was recorded" in case.unknown_machines[0]["reasons"][0]
        assert len(case.human_decisions_required) == 1
        assert "Grimaldi/AR-7#0804" in case.human_decisions_required[0]
        assert "could NOT be matched to or excluded" in case.human_decisions_required[0]

    def test_an_unknown_only_case_cannot_reach_ready_to_close(self, ledger, store):
        unknown_only(ledger)
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        claim(store, case.case_id, owner="a.integrator", actor=PERSON)
        moved = advance(store, case.case_id, actor=PERSON)
        assert moved.status is CaseStatus.AWAITING_ACTION       # was READY_TO_CLOSE
        with pytest.raises(CaseTransitionError, match="human"):
            advance(store, case.case_id, actor=PERSON)

    def test_it_cannot_be_closed_until_a_named_person_answers(self, ledger, store):
        unknown_only(ledger)
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        claim(store, case.case_id, owner="a.integrator", actor=PERSON)
        advance(store, case.case_id, actor=PERSON)
        with pytest.raises(CaseTransitionError, match="not ready_to_close"):
            decide(store, case.case_id, disposition="closed", reason="reviewed", actor=DECIDER)

        question = store.get(case.case_id).human_decisions_required[0]
        with pytest.raises(CaseTransitionError, match="named person"):
            resolve_decision(store, case.case_id, decision=question,
                             resolution="not affected", actor=BOT)
        resolve_decision(store, case.case_id, decision=question,
                         resolution="0804 runs the fixed 3.9.0, read off the controller "
                                    "on 2026-09-15 (service record SR-114).", actor=DECIDER)
        assert advance(store, case.case_id, actor=DECIDER).status is CaseStatus.READY_TO_CLOSE
        closed = decide(store, case.case_id, disposition="closed", reason="answered",
                        actor=DECIDER)
        assert closed.status is CaseStatus.CLOSED
        assert reconstruct_case(store.ledger, case.case_id).ok

    def test_a_repeat_look_does_not_ask_the_answered_question_again(self, ledger, store):
        unknown_only(ledger)
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        question = case.human_decisions_required[0]
        resolve_decision(store, case.case_id, decision=question, resolution="checked on site",
                         actor=DECIDER)
        again = assess_advisory(store, impact_of(ledger, advisory()), actor=BOT)
        assert again.human_decisions_required == ()
        assert [u["machine"] for u in again.unknown_machines] == ["Grimaldi/AR-7#0804"]

    def test_the_export_shows_the_unknown_machine(self, ledger, store):
        unknown_only(ledger)
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        bundle = ledger.export(subject=case.case_id)
        bodies = [json.dumps(e) for e in bundle["entries"]]
        assert any("unknown_machines" in b and "Grimaldi/AR-7#0804" in b for b in bodies)

    def test_the_detail_page_names_it(self, ledger, store):
        unknown_only(ledger)
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        assert "UNKNOWN machines" in case.summary()
        assert "Grimaldi/AR-7#0804" in case.summary()

    def test_an_unknown_machine_beside_an_affected_one_is_named_too(self, ledger, store):
        unknown_only(ledger)
        record_manifest(ledger, manifest("0412", fw()))
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        assert case.machines == ("Grimaldi/AR-7#0412",)
        assert [u["machine"] for u in case.unknown_machines] == ["Grimaldi/AR-7#0804"]
        assert any("0804" in q for q in case.human_decisions_required)

    def test_a_machine_that_is_clearly_not_affected_is_not_asked_about(self, ledger, store):
        record_manifest(ledger, manifest("0501", fw(version="3.9.0", content_hash="3" * 64)))
        record_manifest(ledger, manifest("0412", fw()))
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        assert case.unknown_machines == ()
        assert not any("0501" in q for q in case.human_decisions_required)

    def test_a_waiver_path_still_needs_a_person_and_reason(self, ledger, store):
        """The existing waive-reverification path is untouched by unknown machines."""
        unknown_only(ledger)
        record_manifest(ledger, manifest("0412", fw()))
        case = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        entry = case.required_reverifications[0]
        with pytest.raises(CaseTransitionError):
            waive_reverification(store, case.case_id, entry=entry, reason="skip", actor=BOT)


class TestAnOldCaseLoadsAndRendersAsItDid:
    def test_a_case_without_the_field_round_trips_without_gaining_it(self):
        d = {
            "case_id": "case-x", "trigger_type": "supplier_advisory", "trigger_id": "A-1",
            "status": "open", "machines": ["Grimaldi/AR-7#1"],
        }
        case = ChangeAssuranceCase.from_dict(d)
        assert case.unknown_machines == ()
        assert "unknown_machines" not in case.to_dict()
        assert "UNKNOWN machines" not in case.summary()


# =====================================================================
# F3 — a different advisory under a reused id is not the closed case
# =====================================================================

def two_suppliers_one_id(ledger):
    """One machine runs both ControlCo's firmware and ScanCo's zone set, each hash-confirmed."""
    zones = SafetyItem("ITM-ZONES", ItemKind.SAFETY_CONFIGURATION, "Safety scanner zone set",
                       "r4", SCAN_AFFECTED, HashSource.READ_FROM_MACHINE, supplier="ScanCo",
                       implements=("SF-01",))
    m = SafetyManifest(
        manifest_id="MAN-0412",
        machine=MachineIdentity("Grimaldi", "AR-7", "0412", site="Plant 2", country="DE"),
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 9, 14, tzinfo=UTC),
        taken_by=PERSON, functions=FUNCS, items=(fw(), zones), method="synthetic")
    record_manifest(ledger, m)
    cc = advisory(advisory_id="SA-1")
    sc = advisory(advisory_id="SA-1", issued_by="ScanCo", supplier="ScanCo",
                  name="Safety scanner zone set", versions=("r4",),
                  hashes=(SCAN_AFFECTED,), title="Zone set defect (ScanCo)",
                  fixed_versions=("r5",), fixed_hashes=("c" * 64,))
    return cc, sc


def close_it(store, case_id):
    claim(store, case_id, owner="a.integrator", actor=PERSON)
    c = store.get(case_id)
    # the cases here have verification work; waive it as a named person would
    for entry in c.required_reverifications:
        waive_reverification(store, case_id, entry=entry,
                             reason="verified out of band, SR-1", actor=DECIDER)
    while store.get(case_id).status is not CaseStatus.READY_TO_CLOSE:
        c = store.get(case_id)
        for q in c.human_decisions_required:
            resolve_decision(store, case_id, decision=q, resolution="seen", actor=DECIDER)
        advance(store, case_id, actor=DECIDER)
    return decide(store, case_id, disposition="closed", reason="done", actor=DECIDER)


class TestAReusedAdvisoryIdIsNotTheClosedCase:
    def test_a_second_suppliers_advisory_with_the_same_id_opens_its_own_case(
            self, ledger, store):
        cc, sc = two_suppliers_one_id(ledger)
        first = assess_advisory(store, impact_of(ledger, cc), actor=PERSON)
        closed = close_it(store, first.case_id)
        assert closed.status is CaseStatus.CLOSED

        second = assess_advisory(store, impact_of(ledger, sc), actor=PERSON)
        assert second.case_id != first.case_id
        assert second.status is CaseStatus.OPEN                  # was [CLOSED], swallowed
        assert second.machines == ("Grimaldi/AR-7#0412",)
        assert store.get(first.case_id).status is CaseStatus.CLOSED   # untouched
        assert [c.case_id for c in store.list() if c.is_open] == [second.case_id]
        assert "ScanCo" in second.trigger_id
        assert reconstruct_case(ledger, second.case_id).ok
        assert reconstruct_case(ledger, first.case_id).ok

    def test_the_case_id_of_the_first_advisory_is_the_one_it_always_had(self, ledger, store):
        cc, _ = two_suppliers_one_id(ledger)
        impact = impact_of(ledger, cc)
        assert assess_advisory(store, impact, actor=PERSON).case_id == advisory_case_id(impact)

    def test_assessing_either_advisory_again_duplicates_nothing(self, ledger, store):
        cc, sc = two_suppliers_one_id(ledger)
        first = assess_advisory(store, impact_of(ledger, cc), actor=PERSON)
        close_it(store, first.case_id)
        second = assess_advisory(store, impact_of(ledger, sc), actor=PERSON)
        before = len(ledger)
        for _ in range(2):
            a = assess_advisory(store, impact_of(ledger, cc), actor=BOT)
            b = assess_advisory(store, impact_of(ledger, sc), actor=BOT)
            assert a.case_id == first.case_id and a.status is CaseStatus.CLOSED
            assert b.case_id == second.case_id and b.status is CaseStatus.OPEN
        assert len(ledger) == before
        assert len(store.list()) == 2

    def test_an_open_case_is_not_the_other_suppliers_case_either(self, ledger, store):
        cc, sc = two_suppliers_one_id(ledger)
        first = assess_advisory(store, impact_of(ledger, cc), actor=PERSON)
        second = assess_advisory(store, impact_of(ledger, sc), actor=PERSON)
        assert first.case_id != second.case_id
        assert store.get(first.case_id).machines == ("Grimaldi/AR-7#0412",)
        # the first case still concerns only its own advisory
        assert len(store.get(first.case_id).linked_evidence) == 1

    def test_the_same_supplier_re_issuing_the_id_with_new_content_reopens_a_closed_case(
            self, ledger, store):
        cc, _ = two_suppliers_one_id(ledger)
        first = assess_advisory(store, impact_of(ledger, cc), actor=PERSON)
        close_it(store, first.case_id)
        reissued = advisory(advisory_id="SA-1", title="Watchdog may not trip (revised)",
                            remedy="Update to 3.9.1 instead.")
        assert reissued.content_hash() != cc.content_hash()
        again = assess_advisory(store, impact_of(ledger, reissued), actor=PERSON)
        assert again.case_id == first.case_id
        assert again.status is CaseStatus.OPEN
        assert "different document" in again.prior_closures[-1]["reopened_because"]

    def test_the_same_document_assessed_again_does_not_reopen_it(self, ledger, store):
        cc, _ = two_suppliers_one_id(ledger)
        first = assess_advisory(store, impact_of(ledger, cc), actor=PERSON)
        close_it(store, first.case_id)
        before = len(ledger)
        again = assess_advisory(store, impact_of(ledger, cc), actor=BOT)
        assert again.status is CaseStatus.CLOSED and len(ledger) == before


# =====================================================================
# F8 — the case keeps what the advisory report knew
# =====================================================================

class TestTheCaseRecordsTheAdvisoryAndThePreviousVerification:
    def test_the_advisory_is_recorded_on_the_case(self, ledger, store):
        record_manifest(ledger, manifest("0412", fw()))
        adv = advisory()
        case = assess_advisory(store, impact_of(ledger, adv), actor=PERSON)
        assert case.advisory == {
            "advisory_id": "CTRL-2026-11", "issued_by": "ControlCo",
            "title": "Watchdog may not trip", "severity": "safety_relevant",
            "reference": "https://example.invalid/advisory",
            "content_hash": adv.content_hash()}
        assert "advisory   CTRL-2026-11 from ControlCo" in case.summary()
        assert store.get(case.case_id).advisory == case.advisory      # survives the ledger

    def test_the_previous_verification_of_each_function_is_copied_from_the_report(
            self, store):
        # FunctionExposure carries last_verified_at / last_verified_hash; the case keeps them.
        adv = advisory()
        fx = FunctionExposure("SF-01", "Protective stop", Coverage.CURRENT, True,
                              last_verified_at="2026-08-01T00:00:00Z",
                              last_verified_hash="d" * 64)
        report = ImpactReport(
            advisory_id=adv.advisory_id, advisory_hash=adv.content_hash(),
            issued_by=adv.issued_by, severity=adv.severity, title=adv.title,
            reference=adv.reference, assessed_at="2026-09-15T00:00:00Z", machines_in_fleet=1,
            exposures=(Exposure("Grimaldi/AR-7#1", "Plant 2", "ITM-FW", "fw", "3.8.2",
                                MatchBasis.HASH, "x", (fx,)),),
            checks_skipped=())
        case = assess_advisory(store, report, actor=PERSON)
        assert case.previous_verifications == (
            {"entry": "Grimaldi/AR-7#1/SF-01", "last_verified_at": "2026-08-01T00:00:00Z",
             "last_verified_hash": "d" * 64},)
        assert "previously verified Grimaldi/AR-7#1/SF-01: 2026-08-01T00:00:00Z (dddddddddddd)" \
            in case.summary()

    def test_a_later_look_never_rewrites_the_advisory_the_case_was_opened_on(
            self, ledger, store):
        record_manifest(ledger, manifest("0412", fw()))
        first = assess_advisory(store, impact_of(ledger, advisory()), actor=PERSON)
        revised = advisory(title="Watchdog may not trip (revised)", remedy="3.9.1")
        record_manifest(ledger, manifest("0501", fw()))
        again = assess_advisory(store, impact_of(ledger, revised), actor=BOT)
        assert again.advisory == first.advisory


OLD = Path(__file__).parent / "fixtures" / "advisory_case_main_2b41ddb.json"


class TestACaseSealedBeforeTheseFieldsExistedStillWorks:
    """``advisory_case_main_2b41ddb.json`` is ``case.to_dict()`` as the unchanged main branch
    (2b41ddb) wrote it for this ledger world: one hash-confirmed machine (0412) and one
    unknown one (0804) that the old code left without a question."""

    def old(self):
        return json.loads(OLD.read_text(encoding="utf-8"))

    def test_it_loads_and_serialises_to_exactly_what_it_was(self):
        d = self.old()
        assert ChangeAssuranceCase.from_dict(d).to_dict() == d

    def test_it_renders_without_the_new_sections(self):
        text = ChangeAssuranceCase.from_dict(self.old()).summary()
        for absent in ("UNKNOWN machines", "advisory   ", "previously verified"):
            assert absent not in text
        assert "Grimaldi/AR-7#0412" in text

    def test_it_replays_and_a_new_look_adds_to_it_without_breaking_the_record(
            self, ledger, store):
        record_manifest(ledger, manifest("0412", fw()))
        unknown_only(ledger)
        old = replace(ChangeAssuranceCase.from_dict(self.old()), history=())
        sealed = store.open(old, actor=PERSON, detail="advisory CTRL-2026-11")
        assert reconstruct_case(ledger, sealed.case_id).ok
        assert sealed.unknown_machines == () and sealed.advisory == {}

        now = assess_advisory(store, impact_of(ledger, advisory()), actor=BOT)
        assert now.case_id == sealed.case_id
        # the old case gains the question it should always have had, and the advisory it
        # was opened on (the same document), and loses nothing
        assert [u["machine"] for u in now.unknown_machines] == ["Grimaldi/AR-7#0804"]
        assert any("0804" in q for q in now.human_decisions_required)
        assert now.advisory["content_hash"] == advisory().content_hash()
        assert set(sealed.machines) <= set(now.machines)
        assert reconstruct_case(ledger, sealed.case_id).ok
        bundle = ledger.export(subject=sealed.case_id)
        assert len(bundle["entries"]) == 2

    def test_a_different_document_is_not_recorded_as_the_one_the_old_case_was_opened_on(
            self, ledger, store):
        record_manifest(ledger, manifest("0412", fw()))
        old = replace(ChangeAssuranceCase.from_dict(self.old()), history=())
        store.open(old, actor=PERSON, detail="advisory CTRL-2026-11")
        revised = advisory(title="Watchdog may not trip (revised)")
        now = assess_advisory(store, impact_of(ledger, revised), actor=BOT)
        assert now.advisory == {}
