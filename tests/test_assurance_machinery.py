"""Tests for the safety software manifest, interventions, and coverage.

The test that matters most is
``test_a_firmware_change_invalidates_the_verification_that_preceded_it``.
Everything else in this package exists so that one inference is sound.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor, ValidationState
from assurance.core.tiers import AssuranceTier
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machinery.divergence import ChangeKind, Severity, compare
from assurance.machinery.intervention import (
    Authorization,
    Intervention,
    InterventionError,
    InterventionKind,
    Revalidation,
)
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
from assurance.machinery.record import (
    build_passport,
    interventions_from_ledger,
    record_intervention,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import (
    Coverage,
    VerificationRecord,
    assess_coverage,
)

ENG = Actor(identifier="a.integrator", role="safety engineer")
TECH = Actor(identifier="m.tech", role="service technician")

MACHINE = MachineIdentity(manufacturer="Grimaldi", model="AR-7", serial="0412")

FUNCS = (
    SafetyFunction("SF-01", "Protective stop on zone intrusion", "PL d",
                   verified_by=("ssm_separation", "stop_characterisation")),
    SafetyFunction("SF-02", "Speed limit in collaborative operation", "PL d",
                   verified_by=("speed_limit",)),
    SafetyFunction("SF-03", "Emergency stop", "PL d"),
)


def item(item_id="ITM-FW", **over):
    kw = {
        "item_id": item_id,
        "kind": ItemKind.FIRMWARE,
        "name": "Safety controller firmware",
        "version": "3.8.2",
        "content_hash": "a" * 64,
        "hash_source": HashSource.READ_FROM_MACHINE,
        "implements": ("SF-01", "SF-02"),
    }
    kw.update(over)
    return SafetyItem(**kw)


def manifest(*items, **over):
    kw = {
        "manifest_id": "MAN-1",
        "machine": MACHINE,
        "source": ManifestSource.AS_FOUND,
        "taken_at": datetime(2026, 1, 20, tzinfo=UTC),
        "taken_by": ENG,
        "items": items or (item(),),
        "functions": FUNCS,
        "method": "read via controller service port",
    }
    kw.update(over)
    return SafetyManifest(**kw)


def intervention(**over):
    kw = {
        "intervention_id": "INT-0007",
        "machine_key": MACHINE.key,
        "item_id": "ITM-FW",
        "kind": InterventionKind.UPDATE,
        "occurred_at": datetime(2026, 3, 14, 9, 30, tzinfo=UTC),
        "performed_by": TECH,
        "reason": "Vendor advisory: watchdog timeout under bus load.",
        "from_hash": "a" * 64,
        "to_hash": "d" * 64,
        "affects_functions": ("SF-01", "SF-02"),
    }
    kw.update(over)
    return Intervention(**kw)


def verification(seq=1, at=datetime(2026, 2, 9, tzinfo=UTC), verified=("ssm_separation",
                  "stop_characterisation", "speed_limit"), not_verified=()):
    return VerificationRecord(
        content_hash=f"{seq:064x}", effective_at=at, ledger_seq=seq,
        product="AR-7", product_version="2.4.1", verdict="pass", tier="validated",
        checks_verified=tuple(verified), checks_not_verified=tuple(not_verified),
    )


# =====================================================================
# the join — the reason this package exists
# =====================================================================

class TestCoverage:
    def test_a_verification_with_nothing_since_is_current(self):
        r = assess_coverage(manifest(), [verification()], [])
        assert r.functions[0].coverage is Coverage.CURRENT
        assert r.verdict == "gaps"  # SF-03 declares no checks

    def test_a_firmware_change_invalidates_the_verification_that_preceded_it(self):
        """The whole product in one assertion."""
        r = assess_coverage(manifest(), [verification()], [intervention()])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.STALE
        assert sf01.invalidated_by == "INT-0007"
        assert sf01.invalidating_item == "ITM-FW"
        assert sf01.last_verified_at.startswith("2026-02-09")
        assert sf01.invalidated_at.startswith("2026-03-14")

    def test_it_names_every_function_the_changed_item_implements(self):
        r = assess_coverage(manifest(), [verification()], [intervention()])
        stale = {f.function_id for f in r.stale}
        assert stale == {"SF-01", "SF-02"}

    def test_a_change_before_the_verification_does_not_invalidate_it(self):
        early = intervention(occurred_at=datetime(2026, 1, 3, tzinfo=UTC))
        r = assess_coverage(manifest(), [verification()], [early])
        assert all(f.coverage is not Coverage.STALE for f in r.functions)

    def test_a_later_verification_restores_coverage(self):
        after = verification(seq=2, at=datetime(2026, 4, 1, tzinfo=UTC))
        r = assess_coverage(manifest(), [verification(), after], [intervention()])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.CURRENT
        assert sf01.last_verified_hash == after.content_hash

    def test_a_change_to_an_unrelated_function_leaves_coverage_alone(self):
        other = intervention(item_id="ITM-ESTOP", affects_functions=("SF-03",))
        r = assess_coverage(manifest(), [verification()], [other])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.CURRENT

    def test_a_change_on_another_machine_is_ignored(self):
        elsewhere = intervention(machine_key="Grimaldi/AR-7#9999")
        r = assess_coverage(manifest(), [verification()], [elsewhere])
        assert not r.stale

    def test_a_function_with_no_checks_is_never_reported_as_covered(self):
        r = assess_coverage(manifest(), [verification()], [])
        sf03 = next(f for f in r.functions if f.function_id == "SF-03")
        assert sf03.coverage is Coverage.NOT_DEMONSTRABLE
        assert not sf03.coverage.is_covered

    def test_a_function_never_exercised_is_never_verified(self):
        r = assess_coverage(manifest(), [verification(verified=("speed_limit",))], [])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.NEVER_VERIFIED

    def test_a_check_that_ran_and_failed_is_failing_not_never_verified(self):
        v = verification(verified=("speed_limit",),
                         not_verified=("ssm_separation", "stop_characterisation"))
        r = assess_coverage(manifest(), [v], [])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.FAILING

    def test_no_verification_at_all_is_never_verified(self):
        r = assess_coverage(manifest(), [], [intervention()])
        assert {f.coverage for f in r.functions} == {
            Coverage.NEVER_VERIFIED, Coverage.NOT_DEMONSTRABLE}

    def test_an_intervention_that_revalidated_is_still_listed_honestly(self):
        reval = Revalidation(
            performed_at=datetime(2026, 3, 14, 14, 0, tzinfo=UTC),
            performed_by=ENG, description="re-ran the separation suite",
            evidence_hash="f" * 64)
        r = assess_coverage(manifest(), [verification()],
                            [intervention(revalidation=reval)])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.STALE
        assert sf01.intervention_revalidated is True
        assert "not in this ledger" in sf01.detail

    def test_unrevalidated_interventions_are_listed_by_id(self):
        r = assess_coverage(manifest(), [verification()], [intervention()])
        assert r.unrevalidated_interventions == ("INT-0007",)

    def test_with_no_interventions_it_says_it_saw_no_change_records(self):
        r = assess_coverage(manifest(), [verification()], [])
        assert any("no interventions were supplied" in c for c in r.checks_skipped)

    def test_days_uncovered_is_reported_for_a_stale_function(self):
        r = assess_coverage(manifest(), [verification()], [intervention()])
        sf01 = next(f for f in r.functions if f.function_id == "SF-01")
        assert sf01.days_uncovered is not None
        assert sf01.days_uncovered > 100

    def test_it_never_claims_the_manifest_is_complete(self):
        r = assess_coverage(manifest(), [verification()], [])
        assert any("does not confirm the manifest is complete" in c
                   for c in r.checks_skipped)


# =====================================================================
# manifests
# =====================================================================

class TestManifest:
    def test_a_machine_without_a_serial_is_refused(self):
        with pytest.raises(ManifestError, match="serial"):
            MachineIdentity(manufacturer="G", model="AR-7", serial="")

    def test_an_empty_manifest_is_refused(self):
        with pytest.raises(ManifestError, match="no items"):
            manifest(items=())

    def test_a_duplicate_item_id_is_refused(self):
        with pytest.raises(ManifestError, match="twice"):
            manifest(item(), item())

    def test_an_item_crediting_an_undeclared_function_is_refused(self):
        with pytest.raises(ManifestError, match="does not declare"):
            manifest(item(implements=("SF-99",)))

    def test_an_unhashed_item_must_declare_itself_as_declared(self):
        with pytest.raises(ManifestError, match="carries no hash"):
            item(content_hash="", hash_source=HashSource.READ_FROM_MACHINE)

    def test_a_declared_item_may_carry_no_hash_and_is_not_comparable(self):
        i = item(content_hash="", hash_source=HashSource.DECLARED, implements=())
        assert not i.is_comparable

    def test_one_declared_item_drags_the_whole_manifest_to_profile(self):
        m = manifest(item(),
                     item("ITM-HMI", kind=ItemKind.LIBRARY, name="HMI", version="9",
                          content_hash="", hash_source=HashSource.DECLARED,
                          implements=()))
        assert m.tier_ceiling is AssuranceTier.PROFILE

    def test_a_manifest_read_from_the_machine_reaches_validated(self):
        assert manifest().tier_ceiling is AssuranceTier.VALIDATED

    def test_a_vendor_supplied_hash_caps_at_community(self):
        m = manifest(item(hash_source=HashSource.SUPPLIED_BY_VENDOR))
        assert m.tier_ceiling is AssuranceTier.COMMUNITY

    def test_only_a_machine_read_describes_the_unit_in_front_of_you(self):
        assert HashSource.READ_FROM_MACHINE.describes_this_unit
        assert not HashSource.SUPPLIED_BY_VENDOR.describes_this_unit

    def test_the_configuration_hash_ignores_who_looked_and_when(self):
        a = manifest(taken_at=datetime(2026, 1, 1, tzinfo=UTC), manifest_id="A")
        b = manifest(taken_at=datetime(2026, 9, 1, tzinfo=UTC), manifest_id="B",
                     taken_by=TECH)
        assert a.content_hash() != b.content_hash()
        assert a.configuration_hash() == b.configuration_hash()

    def test_the_configuration_hash_moves_when_an_artefact_moves(self):
        a = manifest()
        b = manifest(item(content_hash="d" * 64))
        assert a.configuration_hash() != b.configuration_hash()

    def test_field_modifiable_safety_items_are_surfaced(self):
        m = manifest(item(modifiable_in_field=True))
        assert m.field_modifiable_safety_items[0].item_id == "ITM-FW"

    def test_functions_with_no_checks_are_surfaced(self):
        assert [f.function_id for f in manifest().undemonstrable_functions] == ["SF-03"]

    def test_checks_for_maps_functions_to_the_checks_that_exercise_them(self):
        assert manifest().checks_for({"SF-02"}) == {"speed_limit"}

    def test_it_survives_json(self, tmp_path):
        m = manifest()
        p = tmp_path / "m.json"
        p.write_text(json.dumps(m.to_dict()))
        assert SafetyManifest.from_json(p).content_hash() == m.content_hash()

    def test_an_item_can_be_hashed_from_a_file(self, tmp_path):
        f = tmp_path / "fw.bin"
        f.write_bytes(b"firmware image")
        i = SafetyItem.from_file(f, item_id="ITM-FW", kind=ItemKind.FIRMWARE,
                                 name="fw", version="1")
        assert len(i.content_hash) == 64
        assert i.hash_source is HashSource.READ_FROM_MACHINE


# =====================================================================
# divergence
# =====================================================================

class TestDivergence:
    def test_an_unchanged_machine_matches(self):
        d = compare(manifest(manifest_id="BASE"), manifest(manifest_id="NOW"))
        assert d.verdict == "matches"
        assert d.identical

    def test_a_changed_safety_artefact_is_safety_relevant_drift(self):
        d = compare(manifest(manifest_id="BASE"),
                    manifest(item(content_hash="d" * 64), manifest_id="NOW"))
        assert d.verdict == "safety_relevant_drift"
        assert d.changes[0].kind is ChangeKind.CONTENT_CHANGED
        assert d.affected_functions == ("SF-01", "SF-02")

    def test_a_silent_firmware_swap_is_caught_and_the_version_lie_is_named(self):
        """The artefact changed and the version string did not."""
        d = compare(manifest(manifest_id="BASE"),
                    manifest(item(content_hash="d" * 64), manifest_id="NOW"))
        assert "still reported as" in d.changes[0].detail

    def test_a_relabelled_version_over_an_identical_artefact_is_administrative(self):
        d = compare(manifest(manifest_id="BASE"),
                    manifest(item(version="3.8.3"), manifest_id="NOW"))
        assert d.changes[0].kind is ChangeKind.VERSION_RELABELLED
        assert d.changes[0].severity is Severity.ADMINISTRATIVE
        assert d.verdict == "drifted"

    def test_a_non_safety_item_changing_is_notable_not_safety_relevant(self):
        base = manifest(item(), item("ITM-HMI", kind=ItemKind.LIBRARY, name="HMI",
                                     version="9", content_hash="e" * 64,
                                     implements=()))
        now = manifest(item(), item("ITM-HMI", kind=ItemKind.LIBRARY, name="HMI",
                                    version="9", content_hash="f" * 64,
                                    implements=()), manifest_id="NOW")
        d = compare(base, now)
        assert d.verdict == "drifted"
        assert d.changes[0].severity is Severity.NOTABLE

    def test_an_added_safety_item_is_a_finding(self):
        base = manifest(manifest_id="BASE")
        now = manifest(item(), item("ITM-NEW", name="Added", content_hash="e" * 64,
                                    implements=("SF-01",)), manifest_id="NOW")
        d = compare(base, now)
        assert d.changes[0].kind is ChangeKind.ADDED
        assert d.changes[0].severity is Severity.SAFETY_RELEVANT

    def test_a_removed_safety_item_is_a_finding(self):
        base = manifest(item(), item("ITM-OLD", name="Old", content_hash="e" * 64,
                                     implements=("SF-01",)))
        d = compare(base, manifest(manifest_id="NOW"))
        assert d.changes[0].kind is ChangeKind.REMOVED

    def test_re_attributing_a_function_is_reported_separately(self):
        d = compare(manifest(manifest_id="BASE"),
                    manifest(item(implements=("SF-01",)), manifest_id="NOW"))
        kinds = {c.kind for c in d.changes}
        assert ChangeKind.ATTRIBUTION_CHANGED in kinds

    def test_an_unhashed_item_is_declared_uncomparable_not_unchanged(self):
        unhashed = item("ITM-HMI", kind=ItemKind.LIBRARY, name="HMI", version="9",
                        content_hash="", hash_source=HashSource.DECLARED,
                        implements=())
        d = compare(manifest(item(), unhashed), manifest(item(), unhashed,
                                                         manifest_id="NOW"))
        assert any("would not have been seen" in c for c in d.checks_skipped)

    def test_comparing_two_different_machines_is_refused(self):
        other = manifest(machine=MachineIdentity("Grimaldi", "AR-7", "9999"),
                         manifest_id="OTHER")
        with pytest.raises(ValueError, match="different machines"):
            compare(manifest(), other)

    def test_comparing_two_declarations_says_it_saw_no_machine(self):
        d = compare(manifest(source=ManifestSource.AS_DECLARED),
                    manifest(source=ManifestSource.AS_DECLARED, manifest_id="NOW"))
        assert any("says nothing about what is actually on the machine" in c
                   for c in d.checks_skipped)


# =====================================================================
# interventions
# =====================================================================

class TestIntervention:
    def test_an_unattributed_change_is_refused(self):
        with pytest.raises(InterventionError, match="names nobody"):
            intervention(performed_by=Actor(identifier="", role=""))

    def test_a_change_with_no_reason_is_refused(self):
        with pytest.raises(InterventionError, match="no reason"):
            intervention(reason="")

    def test_an_update_from_a_hash_to_itself_is_refused(self):
        with pytest.raises(InterventionError, match="Nothing changed"):
            intervention(to_hash="a" * 64)

    def test_a_safety_change_with_no_revalidation_is_a_finding(self):
        f = intervention().findings
        assert any("nothing was re-run" in x for x in f)

    def test_a_safety_change_with_no_authorisation_is_a_finding(self):
        assert any("no recorded authorisation" in x for x in intervention().findings)

    def test_a_revalidation_naming_no_evidence_is_a_finding(self):
        reval = Revalidation(performed_at=datetime(2026, 3, 14, 14, tzinfo=UTC),
                             performed_by=ENG, description="re-ran it")
        f = intervention(revalidation=reval).findings
        assert any("names no sealed evidence" in x for x in f)

    def test_a_properly_recorded_change_has_no_findings(self):
        iv = intervention(
            authorization=Authorization(authorised_by=ENG, reference="CR-2026-41",
                                        basis="vendor advisory"),
            revalidation=Revalidation(
                performed_at=datetime(2026, 3, 14, 14, tzinfo=UTC),
                performed_by=ENG, description="re-ran the separation suite",
                evidence_hash="f" * 64))
        assert iv.findings == ()
        assert iv.is_revalidated and iv.is_authorised

    def test_a_reconstructed_record_says_it_is_a_recollection(self):
        iv = intervention(kind=InterventionKind.RECONSTRUCTED)
        assert any("reconstructed after the fact" in x for x in iv.findings)

    def test_an_authorisation_with_no_reference_is_refused(self):
        with pytest.raises(InterventionError, match="reference"):
            Authorization(authorised_by=ENG, reference="")

    def test_it_survives_json(self, tmp_path):
        iv = intervention()
        p = tmp_path / "i.json"
        p.write_text(json.dumps(iv.to_dict()))
        assert Intervention.from_json(p).content_hash() == iv.content_hash()


# =====================================================================
# the ledger, and the passport
# =====================================================================

@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "machinery.db")


def seal_a_real_verification(ledger, *, when, speed=400.0, separation=2200.0):
    env = SafetyEnvelope(
        envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-11", "2026-01-18")),
        uncertainty=SensingUncertainty(100.0, 50.0,
                                       FigureBasis("measured", "CAL-003")),
        intrusion_distance_mm=850.0)
    run = Trace(trace_id=f"RUN-{when:%Y%m%d}", provenance=Provenance.FIELD,
                source_system="AR-7 fw", started_at=when, sample_rate_hz=50.0,
                samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0),
                                     tcp_speed=speed, mode=OperatingMode.SSM,
                                     separation=separation) for i in range(10)))
    return build_bundle(env, run, actor=ENG, ledger=ledger, subject=MACHINE.key)


class TestLedgerIntegration:
    def test_a_manifest_is_sealed_under_the_machine_key(self, ledger):
        record_manifest(ledger, manifest())
        assert ledger.entries(subject=MACHINE.key)[0].kind == "machinery.safety_manifest"

    def test_an_intervention_round_trips_through_the_ledger(self, ledger):
        record_intervention(ledger, intervention())
        back = interventions_from_ledger(ledger, MACHINE.key)
        assert [i.intervention_id for i in back] == ["INT-0007"]

    def test_an_unrevalidated_change_is_sealed_as_indeterminate_not_verified(self, ledger):
        e = record_intervention(ledger, intervention())
        assert e.validation_state is ValidationState.INDETERMINATE
        assert e.checks_skipped

    def test_the_findings_travel_with_the_sealed_record(self, ledger):
        e = record_intervention(ledger, intervention())
        assert any("nothing was re-run" in c for c in e.checks_skipped)

    def test_everything_together_still_verifies_as_one_chain(self, ledger):
        record_manifest(ledger, manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        record_intervention(ledger, intervention())
        ok, problems = ledger.verify_chain()
        assert ok, problems
        assert len(ledger) == 3

    def test_a_real_verification_is_found_by_the_coverage_assessment(self, ledger):
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        records = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert len(records) == 1
        assert records[0].effective_at == datetime(2026, 2, 9, tzinfo=UTC)
        assert "ssm_separation" in records[0].checks_verified

    def test_the_verification_is_dated_by_the_run_not_by_the_filing(self, ledger):
        """A run captured in February and filed today is evidence about February."""
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        r = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)[0]
        assert r.effective_at.year == 2026
        assert r.effective_at.month == 2

    def test_end_to_end_a_march_firmware_change_strands_a_february_signoff(self, ledger):
        record_manifest(ledger, manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        record_intervention(ledger, intervention())

        passport = build_passport(ledger, manifest(item(content_hash="d" * 64),
                                                   manifest_id="MAN-SEP"), actor=ENG)
        sf01 = next(f for f in passport.coverage.functions
                    if f.function_id == "SF-01")
        assert sf01.coverage is Coverage.STALE
        assert sf01.invalidated_by == "INT-0007"
        assert passport.verdict == "gaps"


class TestPassport:
    def test_it_is_sealed_and_lands_in_the_ledger(self, ledger):
        record_manifest(ledger, manifest())
        p = build_passport(ledger, manifest(), actor=ENG)
        assert p.evidence.verify()
        assert ledger.get(p.content_hash) is not None

    def test_no_seal_leaves_the_ledger_alone(self, ledger):
        before = len(ledger)
        p = build_passport(ledger, manifest(), actor=ENG, seal=False)
        assert len(ledger) == before
        assert ledger.get(p.content_hash) is None

    def test_it_says_when_no_verification_is_filed_under_the_machine(self, ledger):
        p = build_passport(ledger, manifest(), actor=ENG)
        assert any("seal it with subject=" in c for c in p.evidence.checks_skipped)

    def test_an_auditor_can_re_verify_it_against_the_ledger(self, ledger, tmp_path):
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        p = build_passport(ledger, manifest(), actor=ENG).write(tmp_path / "p.json")
        ok, problems = verify_passport(p, ledger=ledger)
        assert ok, problems

    def test_editing_the_verdict_after_sealing_is_caught(self, ledger, tmp_path):
        p = build_passport(ledger, manifest(), actor=ENG).write(tmp_path / "p.json")
        d = json.loads(p.read_text())
        d["evidence"]["body"]["verdict"] = "covered"
        p.write_text(json.dumps(d))
        ok, problems = verify_passport(p)
        assert not ok
        assert any("edited after sealing" in x for x in problems)
        assert any("its own function list implies" in x for x in problems)

    def test_a_passport_from_another_ledger_is_caught(self, ledger, tmp_path):
        p = build_passport(ledger, manifest(), actor=ENG,
                           seal=False).write(tmp_path / "p.json")
        ok, problems = verify_passport(p, ledger=ledger)
        assert not ok
        assert any("not in the ledger supplied" in x for x in problems)

    def test_checking_only_the_seal_is_reported_as_a_limitation(self, ledger, tmp_path):
        p = build_passport(ledger, manifest(), actor=ENG).write(tmp_path / "p.json")
        ok, problems = verify_passport(p)
        assert ok
        assert any("NOT CHECKED" in x for x in problems)

    def test_a_file_that_is_not_a_passport_is_rejected(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"schema": "nope/1"}))
        ok, problems = verify_passport(p)
        assert not ok


# =====================================================================
# HTTP
# =====================================================================

@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from assurance.api import deps

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "l.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "a.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    from assurance.api.service import create_app

    with TestClient(create_app()) as c:
        yield c
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture
def store(client):
    from assurance.api import deps
    return deps.get_accounts()


def keyed(store, tier):
    account = store.upsert_account(email=f"{tier}-mach@example.de", tier=tier)
    return {"X-API-Key": store.issue_key(account.id)}


class TestHttp:
    def test_diff_needs_no_account(self, client):
        r = client.post("/v1/machinery/diff", json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(item(content_hash="d" * 64),
                                 manifest_id="NOW").to_dict()})
        assert r.status_code == 200
        assert r.json()["verdict"] == "safety_relevant_drift"
        assert r.json()["affected_functions"] == ["SF-01", "SF-02"]

    def test_diff_is_metered_on_the_free_tier(self, client):
        r = client.post("/v1/machinery/diff", json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(manifest_id="NOW").to_dict()})
        assert r.headers["x-assurance-quota-limit"] == "10"

    def test_diff_refuses_two_different_machines(self, client):
        other = manifest(machine=MachineIdentity("Grimaldi", "AR-7", "9999"),
                         manifest_id="OTHER")
        r = client.post("/v1/machinery/diff", json={
            "baseline": manifest().to_dict(), "observed": other.to_dict()})
        assert r.status_code == 422

    def test_coverage_is_a_402_without_the_cell_plan(self, client, store):
        r = client.post("/v1/machinery/coverage",
                        json={"manifest": manifest().to_dict()},
                        headers=keyed(store, "register"))
        assert r.status_code == 402

    def test_coverage_is_a_401_with_no_key(self, client):
        r = client.post("/v1/machinery/coverage",
                        json={"manifest": manifest().to_dict()})
        assert r.status_code == 401

    def test_the_cell_plan_can_seal_and_then_see_the_gap(self, client, store):
        h = keyed(store, "cell")
        assert client.post("/v1/machinery/manifest",
                           json={"manifest": manifest().to_dict()},
                           headers=h).status_code == 200
        r = client.post("/v1/machinery/intervention",
                        json={"intervention": intervention().to_dict()}, headers=h)
        assert r.status_code == 200
        assert r.json()["revalidated"] is False
        assert r.json()["findings"]

        cov = client.post("/v1/machinery/coverage",
                          json={"manifest": manifest().to_dict()}, headers=h)
        assert cov.status_code == 200
        assert cov.json()["verdict"] == "gaps"

    def test_a_sealed_manifest_reports_what_it_could_not_see(self, client, store):
        m = manifest(item(), item("ITM-HMI", kind=ItemKind.LIBRARY, name="HMI",
                                  version="9", content_hash="",
                                  hash_source=HashSource.DECLARED, implements=()))
        r = client.post("/v1/machinery/manifest", json={"manifest": m.to_dict()},
                        headers=keyed(store, "cell"))
        assert r.json()["uncomparable_items"] == ["ITM-HMI"]
        assert r.json()["undemonstrable_functions"] == ["SF-03"]

    def test_a_passport_can_be_re_checked_by_anyone(self, client, store):
        built = client.post("/v1/machinery/passport",
                            json={"manifest": manifest().to_dict(),
                                  "actor": "a.integrator"},
                            headers=keyed(store, "cell"))
        assert built.status_code == 200, built.text
        r = client.post("/v1/machinery/passport/check",
                        json={"passport": built.json()})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["checked"]["against_ledger"] is False

    def test_the_free_checker_is_not_metered(self, client, store):
        built = client.post("/v1/machinery/passport",
                            json={"manifest": manifest().to_dict(),
                                  "actor": "a.integrator"},
                            headers=keyed(store, "cell")).json()
        for _ in range(15):
            assert client.post("/v1/machinery/passport/check",
                               json={"passport": built}).status_code == 200

    def test_only_the_cell_plan_advertises_machinery(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert any("Annex III 1.1.9" in i for i in plans["cell"]["includes"])
        assert plans["free"]["limits"]["diffs_per_day"] == 10
