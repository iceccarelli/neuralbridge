"""Which manifest is 'the machine', and what a customer-facing verdict may say.

The fleet answers every question from one manifest per machine. If the wrong one
is chosen, every later answer is about a machine that is not there; and the
customer-facing verdict is the sentence a plant manager reads, so it may not say
'verified' or 'no impact' about a machine it could not actually see.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from assurance.check.pipeline import (
    AssuranceVerdict,
    run_ad_hoc_check,
    run_enrolled_check,
)
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machine.bundle import build_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
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

ENG = Actor("a.integrator", "safety engineer")
AFFECTED = "1" * 64
FIXED = "3" * 64

FUNCS = (SafetyFunction("SF-01", "Protective stop", "PL d",
                        verified_by=("ssm_separation", "stop_characterisation")),)


def item(version="3.8.2", h=AFFECTED, **over):
    kw = {"item_id": "ITM-FW", "kind": ItemKind.FIRMWARE, "name": "Safety firmware",
          "version": version, "content_hash": h,
          "hash_source": HashSource.READ_FROM_MACHINE, "supplier": "ControlCo",
          "implements": ("SF-01",)}
    kw.update(over)
    return SafetyItem(**kw)


def manifest(h=AFFECTED, version="3.8.2", source=ManifestSource.AS_FOUND,
             taken=datetime(2026, 9, 1, tzinfo=UTC), mid="M", functions=FUNCS,
             items=None):
    return SafetyManifest(
        manifest_id=mid, machine=MachineIdentity("Grimaldi", "AR-7", "0412"),
        source=source, taken_at=taken, taken_by=ENG,
        items=items or (item(version, h, implements=("SF-01",) if functions else ()),),
        functions=functions, method="read")


def advisory():
    return ComponentAdvisory(
        advisory_id="A-1", issued_by="ControlCo",
        issued_at=datetime(2026, 9, 12, tzinfo=UTC), title="t", summary="s",
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact("ControlCo", "Safety firmware", ("3.8.2",),
                                   (AFFECTED,)),),
        reference="https://c.example/a", fixed_versions=("3.9.0",),
        fixed_hashes=(FIXED,))


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "l.db")


def current(ledger):
    return Fleet.from_ledger(ledger).records[0].manifest


class TestWhichManifestIsTheMachine:
    def test_a_later_filed_baseline_does_not_replace_what_was_found_on_the_machine(
            self, ledger):
        record_manifest(ledger, manifest(AFFECTED, mid="FOUND"))
        record_manifest(ledger, manifest(FIXED, "3.9.0", ManifestSource.AS_DECLARED,
                                         taken=datetime(2026, 9, 5, tzinfo=UTC),
                                         mid="BASELINE"))
        assert current(ledger).manifest_id == "FOUND"
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.machines_affected == ("Grimaldi/AR-7#0412",)

    def test_an_intended_manifest_is_a_plan_not_a_machine(self, ledger):
        record_manifest(ledger, manifest(AFFECTED, mid="FOUND"))
        record_manifest(ledger, manifest(FIXED, "3.9.0", ManifestSource.AS_INTENDED,
                                         mid="PLAN"))
        assert current(ledger).manifest_id == "FOUND"

    def test_a_machine_known_only_from_a_plan_is_not_in_the_fleet(self, ledger):
        record_manifest(ledger, manifest(FIXED, "3.9.0", ManifestSource.AS_INTENDED))
        assert len(Fleet.from_ledger(ledger)) == 0

    def test_a_declared_baseline_alone_is_used_and_flagged(self, ledger):
        record_manifest(ledger, manifest(AFFECTED, source=ManifestSource.AS_DECLARED))
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.machines_affected
        assert any("never observed" in c or "not observed" in c
                   for c in r.checks_skipped)

    def test_the_newer_observation_wins_whatever_order_they_were_filed_in(self, ledger):
        record_manifest(ledger, manifest(FIXED, "3.9.0", mid="NEWER",
                                         taken=datetime(2026, 9, 20, tzinfo=UTC)))
        record_manifest(ledger, manifest(AFFECTED, mid="OLDER",
                                         taken=datetime(2026, 9, 1, tzinfo=UTC)))
        assert current(ledger).manifest_id == "NEWER"

    def test_a_manifest_dated_in_the_future_cannot_pin_itself_as_current(self, ledger):
        record_manifest(ledger, manifest(FIXED, "3.9.0", mid="FUTURE",
                                         taken=datetime(2099, 1, 1, tzinfo=UTC)))
        record_manifest(ledger, manifest(AFFECTED, mid="REAL",
                                         taken=datetime.now(UTC)))
        assert current(ledger).manifest_id == "REAL"

    def test_equal_dates_fall_back_to_ledger_order(self, ledger):
        record_manifest(ledger, manifest(AFFECTED, mid="FIRST"))
        record_manifest(ledger, manifest(FIXED, "3.9.0", mid="SECOND"))
        assert current(ledger).manifest_id == "SECOND"


def broken(fleet):
    return dataclasses.replace(fleet, chain_verified=False,
                               chain_problems=("entry 2 does not chain",))


class TestCustomerVerdictsAreNotFlattering:
    def enrol_verified(self, ledger):
        m = manifest()
        record_manifest(ledger, m)
        env = SafetyEnvelope(
            envelope_id="E", product="AR-7", product_version="2.4.1",
            workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
            max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
            stop=StopPerformance(0.1, 0.25, 120.0, 500.0, FigureBasis("measured", "S-1")),
            uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "C-3")),
            intrusion_distance_mm=850.0)
        run = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="fw",
                    started_at=datetime(2026, 9, 2, tzinfo=UTC), sample_rate_hz=50.0,
                    samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0),
                                         tcp_speed=400.0, mode=OperatingMode.SSM,
                                         separation=2200.0) for i in range(10)))
        build_bundle(env, run, actor=ENG, ledger=ledger, subject=m.machine.key)
        return m.machine.key

    def test_the_baseline_good_case_is_verified(self, ledger):
        key = self.enrol_verified(ledger)
        assert run_enrolled_check(ledger, key).verdict is AssuranceVerdict.VERIFIED

    def test_a_machine_with_no_declared_safety_functions_is_not_verified(self, ledger):
        m = manifest(functions=())
        record_manifest(ledger, m)
        c = run_enrolled_check(ledger, m.machine.key)
        assert c.verdict is AssuranceVerdict.CANNOT_DETERMINE
        assert c.affected

    def test_a_ledger_chain_that_does_not_verify_is_not_verified(self, ledger, monkeypatch):
        key = self.enrol_verified(ledger)
        real = Fleet.from_ledger
        monkeypatch.setattr(Fleet, "from_ledger", classmethod(
            lambda cls, led: broken(real(led))))
        c = run_enrolled_check(ledger, key)
        assert c.verdict is AssuranceVerdict.CANNOT_DETERMINE
        assert any("DOES NOT VERIFY" in s for s in c.checks_skipped)

    def test_a_chain_that_does_not_verify_is_not_no_impact_either(self, ledger, monkeypatch):
        key = self.enrol_verified(ledger)
        clear = dataclasses.replace(advisory(), affected=(AffectedArtefact(
            "ControlCo", "Safety firmware", ("1.0",)),))
        real = Fleet.from_ledger
        monkeypatch.setattr(Fleet, "from_ledger", classmethod(
            lambda cls, led: broken(real(led))))
        c = run_enrolled_check(ledger, key, clear)
        assert c.verdict is AssuranceVerdict.CANNOT_DETERMINE

    def test_a_chain_that_does_not_verify_does_not_soften_a_real_match(
            self, ledger, monkeypatch):
        key = self.enrol_verified(ledger)
        real = Fleet.from_ledger
        monkeypatch.setattr(Fleet, "from_ledger", classmethod(
            lambda cls, led: broken(real(led))))
        c = run_enrolled_check(ledger, key, advisory())
        assert c.verdict in (AssuranceVerdict.REQUIRES_REVERIFICATION,
                             AssuranceVerdict.REQUIRES_HUMAN_REVIEW,
                             AssuranceVerdict.POTENTIALLY_AFFECTED)

    def test_an_item_with_no_supplier_that_shares_the_name_needs_a_human(self):
        it = item(supplier="")
        m = manifest(items=(it,))
        c = run_ad_hoc_check(m, advisory())
        assert c.verdict is AssuranceVerdict.REQUIRES_HUMAN_REVIEW
        assert c.human_review_required

    def test_an_unrelated_manifest_has_no_impact_found(self):
        m = manifest(items=(item(name="Something else", h="7" * 64),))
        assert run_ad_hoc_check(m, advisory()).verdict is AssuranceVerdict.NO_IMPACT_FOUND

    def test_the_ad_hoc_path_says_it_did_not_read_any_evidence(self):
        c = run_ad_hoc_check(manifest(), advisory())
        assert any("no ledger" in s for s in c.checks_skipped)
