"""Tests for the advisory → Article 14 bridge.

The bridge exists to do one thing under a 24-hour clock: assemble the Member
State list that Article 14(2)(a) asks for. The tests that matter are the ones
proving it does exactly that and refuses everything else — because a filing
carrying a guessed track, a guessed awareness time or a wrong field 5 is worse
than a late one.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.bridge.art14 import (
    BridgeError,
    draft_from_advisory,
    open_case,
)
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestError,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import record_manifest
from assurance.security.art14.engine import Art14Register
from assurance.security.art14.model import SignalChannel

ENG = Actor("a.integrator", "safety engineer")
AFFECTED = "a" * 64
CLEAR = "b" * 64
RELABELLED = "c" * 64

FUNCS = (SafetyFunction("SF-01", "Protective stop", "PL d",
                        verified_by=("ssm_separation",)),)


def enrol(ledger, serial, *, country="DE", content_hash=AFFECTED, version="3.8.2"):
    manifest = SafetyManifest(
        manifest_id=f"MAN-{serial}",
        machine=MachineIdentity("Grimaldi", "AR-7", serial, site="Plant",
                                country=country),
        source=ManifestSource.AS_FOUND,
        taken_at=datetime(2026, 9, 1, tzinfo=UTC), taken_by=ENG,
        functions=FUNCS,
        items=(SafetyItem("ITM-FW", ItemKind.FIRMWARE,
                          "Safety controller firmware", version, content_hash,
                          HashSource.READ_FROM_MACHINE, supplier="ControlCo",
                          implements=("SF-01",)),))
    record_manifest(ledger, manifest)
    return manifest


def advisory(**over):
    kw = {
        "advisory_id": "CTRL-2026-11", "issued_by": "ControlCo",
        "issued_at": datetime(2026, 9, 12, 8, tzinfo=UTC),
        "title": "Watchdog may not trip under load",
        "summary": "The safety-rated stop may not occur within the specified time.",
        "severity": AdvisorySeverity.SAFETY_RELEVANT,
        "affected": (AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.2",), content_hashes=(AFFECTED,)),),
        "reference": "https://controlco.example/a/1",
    }
    kw.update(over)
    return ComponentAdvisory(**kw)


def draft_for(ledger, **over):
    fleet = Fleet.from_ledger(ledger)
    adv = over.pop("advisory_obj", advisory())
    kw = {"received_by": "a.integrator"}
    kw.update(over)
    return draft_from_advisory(adv, assess_impact(adv, fleet), fleet, **kw), fleet


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "l.db")


# =====================================================================
# the field that costs 24 hours
# =====================================================================

class TestMemberStates:
    def test_it_assembles_the_member_states_from_the_fleet(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0501", country="IT")
        enrol(ledger, "0777", country="FR")
        draft, _ = draft_for(ledger)
        assert draft.member_states == ("DE", "FR", "IT")
        assert draft.can_complete_field_5

    def test_a_non_eu_territory_does_not_go_in_field_5(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0620", country="CH")
        draft, _ = draft_for(ledger)
        assert draft.member_states == ("DE",)
        assert draft.other_markets == ("CH",)

    def test_an_unaffected_machine_contributes_no_territory(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0999", country="ES", content_hash=CLEAR, version="3.9.0")
        draft, _ = draft_for(ledger)
        assert draft.member_states == ("DE",)
        assert draft.machines == ("0412",)

    def test_a_machine_with_no_country_blocks_the_field(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0501", country="")
        draft, _ = draft_for(ledger)
        assert draft.machines_without_country == ("0501",)
        assert not draft.can_complete_field_5

    def test_and_says_so_as_a_decision_somebody_must_make(self, ledger):
        enrol(ledger, "0501", country="")
        draft, _ = draft_for(ledger)
        assert any("Which territories" in d for d in draft.decisions_required)

    def test_the_serials_the_list_was_built_from_are_the_evidence(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0501", country="IT")
        draft, _ = draft_for(ledger)
        assert draft.machines == ("0412", "0501")

    def test_a_bad_country_code_is_refused_at_the_manifest(self):
        with pytest.raises(ManifestError, match="alpha-2"):
            MachineIdentity("G", "AR-7", "1", country="DEU")


# =====================================================================
# what it refuses to decide
# =====================================================================

class TestItRefusesTheJudgement:
    def test_it_sets_no_track(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert "notification_type" not in draft.srp_prefill()
        assert any("actively exploited vulnerability, a severe incident, or "
                   "neither" in d for d in draft.decisions_required)

    def test_it_sets_no_awareness_timestamp(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert "awareness_datetime" not in draft.srp_prefill()
        assert any("awareness was established" in d
                   for d in draft.decisions_required)

    def test_the_signal_time_is_when_the_advisory_issued_not_now(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert draft.signal.received_at == datetime(2026, 9, 12, 8, tzinfo=UTC)

    def test_the_channel_records_that_it_came_from_a_supplier(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert draft.signal.channel is SignalChannel.SUPPLIER_ADVISORY

    def test_an_unattributed_receipt_is_refused(self, ledger):
        enrol(ledger, "0412")
        with pytest.raises(BridgeError, match="received_by is required"):
            draft_for(ledger, received_by="")

    def test_it_says_it_is_an_intake_and_not_a_filing(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert any("intake, not a filing" in c for c in draft.checks_skipped)

    def test_it_warns_the_ledger_is_not_the_same_as_awareness(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert any("not the same as what is in this ledger" in c
                   for c in draft.checks_skipped)


# =====================================================================
# only what is confirmed counts
# =====================================================================

class TestOnlyConfirmedCounts:
    def test_a_contradictory_match_is_excluded_from_the_counts(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0418", country="FR", content_hash=RELABELLED)
        draft, _ = draft_for(ledger)
        assert draft.machines == ("0412",)
        assert draft.member_states == ("DE",)
        assert draft.machines_needing_a_human == ("Grimaldi/AR-7#0418",)

    def test_and_is_raised_as_a_decision(self, ledger):
        enrol(ledger, "0418", content_hash=RELABELLED)
        draft, _ = draft_for(ledger)
        assert any("neither column" in d for d in draft.decisions_required)

    def test_an_advisory_matching_nothing_is_refused(self, ledger):
        enrol(ledger, "0999", content_hash=CLEAR, version="3.9.0")
        with pytest.raises(BridgeError, match="matches no machine"):
            draft_for(ledger)

    def test_a_label_only_match_does_not_count_as_affected(self, ledger):
        """No hash published by the supplier: the match rests on a label."""
        enrol(ledger, "0412", country="DE")
        adv = advisory(affected=(AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.2",)),))
        draft, _ = draft_for(ledger, advisory_obj=adv)
        assert draft.machines == ()
        assert draft.machines_needing_a_human == ("Grimaldi/AR-7#0412",)


# =====================================================================
# the product record
# =====================================================================

class TestProducts:
    def test_it_groups_the_machines_into_one_product(self, ledger):
        enrol(ledger, "0412", country="DE")
        enrol(ledger, "0501", country="IT")
        draft, _ = draft_for(ledger)
        assert len(draft.products) == 1
        p = draft.products[0]
        assert p.product_name == "Grimaldi AR-7"
        assert p.units_in_field == 2
        assert p.member_states == ("DE", "IT")

    def test_the_product_name_can_be_the_one_placed_on_the_market(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger, product_name="AR-7 Palletising Cell")
        assert draft.products[0].product_name == "AR-7 Palletising Cell"

    def test_the_version_range_is_what_was_found_not_what_was_claimed(self, ledger):
        enrol(ledger, "0412", version="3.8.2")
        draft, _ = draft_for(ledger)
        assert draft.products[0].version_range == "3.8.2"

    def test_the_evidence_source_names_the_advisory(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert "CTRL-2026-11" in draft.products[0].evidence_source

    def test_the_affected_component_is_carried(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        assert draft.products[0].components == (
            "ControlCo Safety controller firmware",)


# =====================================================================
# opening the case
# =====================================================================

class TestOpenCase:
    def test_it_seals_a_signal_and_the_availability(self, ledger):
        enrol(ledger, "0412", country="DE")
        draft, _ = draft_for(ledger)
        register = Art14Register(ledger)
        case_id, sealed = open_case(register, draft, ENG)
        assert case_id == "CASE-CTRL-2026-11"
        assert len(sealed) == 2
        assert all(e.verify() for e in sealed)

    def test_the_chain_still_verifies_afterwards(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        open_case(Art14Register(ledger), draft, ENG)
        ok, problems = ledger.verify_chain()
        assert ok, problems

    def test_the_case_has_a_signal_and_no_awareness(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        register = Art14Register(ledger)
        open_case(register, draft, ENG)
        case = register.case("CASE-CTRL-2026-11")
        assert case.signal is not None
        assert case.awareness is None

    def test_the_register_refuses_a_filing_until_a_person_decides(self, ledger):
        """The bridge does the inventory; the register enforces the order."""
        from assurance.security.art14.engine import CaseError
        from assurance.security.art14.model import Stage, Track

        enrol(ledger, "0412")
        draft, _ = draft_for(ledger)
        register = Art14Register(ledger)
        open_case(register, draft, ENG)
        with pytest.raises(CaseError):
            register.record_filing(
                "CASE-CTRL-2026-11", Track.VULNERABILITY, Stage.EARLY_WARNING,
                {}, ENG)

    def test_the_case_id_can_be_chosen(self, ledger):
        enrol(ledger, "0412")
        draft, _ = draft_for(ledger, case_id="CASE-2026-0044")
        assert draft.case_id == "CASE-2026-0044"


# =====================================================================
# CLI
# =====================================================================

class TestCli:
    def test_it_exits_non_zero_when_field_5_cannot_be_completed(
            self, ledger, tmp_path, capsys):
        import json

        from assurance.bridge.cli import main
        enrol(ledger, "0501", country="")
        path = tmp_path / "adv.json"
        path.write_text(json.dumps(advisory().to_dict()))
        code = main(["art14", str(path), "--ledger", str(ledger.path),
                     "--received-by", "a.integrator"])
        assert code == 1
        assert "FIELD 5 CANNOT BE COMPLETED" in capsys.readouterr().out

    def test_it_exits_zero_and_can_open_the_case(self, ledger, tmp_path, capsys):
        import json

        from assurance.bridge.cli import main
        enrol(ledger, "0412", country="DE")
        path = tmp_path / "adv.json"
        path.write_text(json.dumps(advisory().to_dict()))
        code = main(["art14", str(path), "--ledger", str(ledger.path),
                     "--received-by", "a.integrator", "--open"])
        assert code == 0
        out = capsys.readouterr().out
        assert "opened CASE-CTRL-2026-11" in out
        assert "refuse a filing" in out
