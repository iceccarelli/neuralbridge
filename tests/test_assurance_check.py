"""Tests for the Machine Assurance Check: the composed customer transaction.

This module invents no new fixtures for matching or staleness — it reuses the
same shapes as ``test_assurance_fleet.py`` and ``test_assurance_machinery.py``
because the pipeline itself composes those modules' functions rather than
reimplementing them. What is new here is the verdict: given the same inputs
those tests already exercise, does the composed check land on the right
explicit state, and never silently collapse "nothing found" into "the system
could not tell"?
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.check import AssuranceVerdict, CheckError, run_ad_hoc_check, run_enrolled_check
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.machine.bundle import build_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import record_intervention, record_manifest

ENG = Actor("a.integrator", "safety engineer")
TECH = Actor("m.tech", "service technician")

GOOD_FW = "1" * 64
FIXED_FW = "3" * 64

FUNCS = (
    SafetyFunction("SF-01", "Protective stop on zone intrusion", "PL d",
                   verified_by=("ssm_separation", "stop_characterisation")),
    SafetyFunction("SF-02", "Speed limit in collaborative operation", "PL d",
                   verified_by=("speed_limit",)),
)


def fw(content_hash=GOOD_FW, version="3.8.2", **over):
    kw = {
        "item_id": "ITM-FW", "kind": ItemKind.FIRMWARE,
        "name": "Safety controller firmware", "version": version,
        "content_hash": content_hash, "hash_source": HashSource.READ_FROM_MACHINE,
        "supplier": "ControlCo", "implements": ("SF-01", "SF-02"),
    }
    kw.update(over)
    return SafetyItem(**kw)


def zones():
    return SafetyItem(
        "ITM-ZONES", ItemKind.SAFETY_CONFIGURATION, "Safety scanner zone set",
        "r4", "b" * 64, HashSource.READ_FROM_MACHINE, supplier="ScanCo",
        implements=("SF-01",), modifiable_in_field=True,
    )


def manifest(serial="0412", *items, site="Plant 2", functions=FUNCS, **over):
    machine = MachineIdentity("Grimaldi", "AR-7", serial, site=site)
    kw = {
        "manifest_id": f"MAN-{serial}", "machine": machine,
        "source": ManifestSource.AS_FOUND,
        "taken_at": datetime(2026, 9, 1, tzinfo=UTC), "taken_by": ENG,
        "items": items or (fw(), zones()), "functions": functions,
        "method": "read via controller service port",
    }
    kw.update(over)
    return SafetyManifest(**kw)


def advisory(**over):
    kw = {
        "advisory_id": "CTRL-2026-11", "issued_by": "ControlCo",
        "issued_at": datetime(2026, 9, 12, 8, tzinfo=UTC),
        "title": "Watchdog may not trip under sustained bus load",
        "summary": "The watchdog can fail to trigger the safety-rated stop.",
        "severity": AdvisorySeverity.SAFETY_RELEVANT,
        "affected": (AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.0", "3.8.1", "3.8.2"), content_hashes=(GOOD_FW,)),),
        "remedy": "Update to 3.9.0 and re-run the stop-performance test.",
        "reference": "https://controlco.example/advisories/CTRL-2026-11",
        "fixed_versions": ("3.9.0",), "fixed_hashes": (FIXED_FW,),
    }
    kw.update(over)
    return ComponentAdvisory(**kw)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "check.db")


def enrol(ledger, serial, *, verify=True, intervene=False, functions=FUNCS):
    man = manifest(serial, fw(), zones(), functions=functions)
    record_manifest(ledger, man)
    if verify:
        env = SafetyEnvelope(
            envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
            workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
            max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
            stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                                 FigureBasis("measured", "STOP-11", "2026-01-18")),
            uncertainty=SensingUncertainty(100.0, 50.0,
                                           FigureBasis("measured", "CAL-003")),
            intrusion_distance_mm=850.0)
        run = Trace(trace_id=f"RUN-{serial}", provenance=Provenance.FIELD,
                    source_system="AR-7 fw",
                    started_at=datetime(2026, 2, 9, tzinfo=UTC), sample_rate_hz=50.0,
                    samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0),
                                         tcp_speed=400.0, mode=OperatingMode.SSM,
                                         separation=2200.0) for i in range(10)))
        build_bundle(env, run, actor=ENG, ledger=ledger, subject=man.machine.key)
    if intervene:
        record_intervention(ledger, Intervention(
            intervention_id=f"INT-{serial}", machine_key=man.machine.key,
            item_id="ITM-ZONES", kind=InterventionKind.PARAMETER_CHANGE,
            occurred_at=datetime(2026, 8, 2, tzinfo=UTC), performed_by=TECH,
            reason="Zone reshaped after a layout change.",
            from_hash="b" * 64, to_hash="e" * 64, affects_functions=("SF-01",)))
    return man


# =====================================================================
# Case A — no matching advisory
# =====================================================================

class TestNoImpact:
    def test_an_advisory_nobody_matches_is_no_impact_found(self):
        result = run_ad_hoc_check(
            manifest("0620", fw(FIXED_FW, "3.9.0"), zones()), advisory())
        assert result.verdict is AssuranceVerdict.NO_IMPACT_FOUND
        assert result.matches == ()
        assert result.affected is False


# =====================================================================
# Case B — advisory matches, no ledger
# =====================================================================

class TestPotentiallyAffected:
    def test_a_matching_advisory_with_no_ledger_is_potentially_affected(self):
        result = run_ad_hoc_check(manifest(), advisory())
        assert result.verdict is AssuranceVerdict.POTENTIALLY_AFFECTED
        assert result.enrolled is False
        assert len(result.matches) == 1
        assert any("needs the machine enrolled" in c for c in result.checks_skipped)

    def test_a_contradictory_match_needs_a_human(self):
        result = run_ad_hoc_check(manifest("0418", fw("2" * 64), zones()), advisory())
        assert result.verdict is AssuranceVerdict.REQUIRES_HUMAN_REVIEW
        assert result.human_review_required is True


# =====================================================================
# Case C — matching advisory + stale evidence
# =====================================================================

class TestRequiresReverification:
    def test_matching_advisory_and_stale_evidence_requires_reverification(self, ledger):
        enrol(ledger, "0412", intervene=True)
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412", advisory())
        assert result.verdict is AssuranceVerdict.REQUIRES_REVERIFICATION
        assert "SF-01" in result.required_actions
        assert result.evidence_stale >= 1

    def test_a_current_machine_with_no_advisory_is_verified(self, ledger):
        enrol(ledger, "0412", intervene=False)
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412")
        assert result.verdict is AssuranceVerdict.VERIFIED
        assert result.advisory_evaluated is False


# =====================================================================
# Case D — intervention history appears in the result
# =====================================================================

class TestInterventionHistory:
    def test_the_intervention_is_named_in_the_result(self, ledger):
        enrol(ledger, "0412", intervene=True)
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412")
        assert result.latest_intervention is not None
        assert result.latest_intervention["intervention_id"] == "INT-0412"
        assert len(result.interventions) == 1


# =====================================================================
# Case E — insufficient machine information
# =====================================================================

class TestCannotDetermine:
    def test_a_function_with_no_declared_checks_cannot_be_determined(self, ledger):
        item = SafetyItem(
            "ITM-BRAKE", ItemKind.SAFETY_CONFIGURATION, "Brake hold parameter",
            "r1", "c" * 64, HashSource.READ_FROM_MACHINE, supplier="ScanCo",
            implements=("SF-09",))
        man = SafetyManifest(
            manifest_id="MAN-0900",
            machine=MachineIdentity("Grimaldi", "AR-7", "0900", site="Plant 2"),
            source=ManifestSource.AS_FOUND,
            taken_at=datetime(2026, 9, 1, tzinfo=UTC), taken_by=ENG,
            items=(item,),
            functions=(SafetyFunction("SF-09", "Undeclared function", "PL d"),),
        )
        record_manifest(ledger, man)
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0900")
        assert result.verdict is AssuranceVerdict.CANNOT_DETERMINE

    def test_an_ad_hoc_check_with_neither_advisory_nor_ledger_refuses(self):
        with pytest.raises(CheckError, match="nothing to"):
            run_ad_hoc_check(manifest(), advisory=None)

    def test_an_unenrolled_machine_is_refused_not_guessed(self, ledger):
        with pytest.raises(CheckError, match="not enrolled"):
            run_enrolled_check(ledger, "Grimaldi/AR-7#9999", advisory())


# =====================================================================
# Case F — fleet contains multiple matching and non-matching machines
# =====================================================================

class TestFleetFanOut:
    def test_the_affected_count_is_correct_across_the_fleet(self, ledger):
        enrol(ledger, "0412")  # matches: GOOD_FW
        enrol(ledger, "0620", verify=True)
        # Give 0620 the fixed firmware so it does not match the advisory.
        record_manifest(ledger, manifest("0620", fw(FIXED_FW, "3.9.0"), zones()))
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412", advisory())
        assert result.fleet_machines_analyzed == 2
        assert result.fleet_machines_affected == 1


# =====================================================================
# Configuration status: is the machine still the declared baseline?
# =====================================================================

class TestConfigurationStatus:
    def test_no_declared_baseline_is_unknown_not_a_guess(self, ledger):
        enrol(ledger, "0412")  # AS_FOUND only, never declared
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412")
        assert result.configuration_status == "unknown"
        assert any("no as-declared baseline" in c for c in result.checks_skipped)

    def test_an_unchanged_configuration_matches(self, ledger):
        baseline = manifest("0412", fw(), zones(), source=ManifestSource.AS_DECLARED,
                            manifest_id="MAN-0412-DECLARED")
        record_manifest(ledger, baseline)
        enrol(ledger, "0412")  # a later, identical AS_FOUND manifest
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412")
        assert result.configuration_status == "matched"
        assert result.configuration_changes == ()

    def test_a_changed_firmware_is_reported_as_changed(self, ledger):
        baseline = manifest("0412", fw(), zones(), source=ManifestSource.AS_DECLARED,
                            manifest_id="MAN-0412-DECLARED")
        record_manifest(ledger, baseline)
        record_manifest(ledger, manifest("0412", fw("9" * 64, "9.9.9"), zones()))
        result = run_enrolled_check(ledger, "Grimaldi/AR-7#0412")
        assert result.configuration_status == "changed"
        assert any(c["item_id"] == "ITM-FW" for c in result.configuration_changes)


# =====================================================================
# HTTP — free vs paid entitlement (Cases G, H, I)
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


@pytest.fixture
def api_ledger(client):
    from assurance.api import deps
    return deps.get_register().ledger


def keyed(store, tier):
    account = store.upsert_account(email=f"{tier}-check@example.de", tier=tier)
    return {"X-API-Key": store.issue_key(account.id)}


class TestHttp:
    def test_the_free_check_needs_no_account(self, client):
        r = client.post("/v1/check/machine", json={
            "manifest": manifest().to_dict(), "advisory": advisory().to_dict()})
        assert r.status_code == 200, r.text
        assert r.json()["verdict"] == "potentially_affected"
        assert r.json()["enrolled"] is False

    def test_the_free_check_reports_no_impact_explicitly(self, client):
        r = client.post("/v1/check/machine", json={
            "manifest": manifest("0620", fw(FIXED_FW, "3.9.0"), zones()).to_dict(),
            "advisory": advisory().to_dict()})
        assert r.json()["verdict"] == "no_impact_found"

    def test_the_enrolled_check_is_a_402_without_the_cell_plan(self, client, store):
        r = client.post("/v1/check/fleet-machine",
                        json={"machine_key": "Grimaldi/AR-7#0412"},
                        headers=keyed(store, "register"))
        assert r.status_code == 402

    def test_the_enrolled_check_needs_a_key(self, client):
        r = client.post("/v1/check/fleet-machine",
                        json={"machine_key": "Grimaldi/AR-7#0412"})
        assert r.status_code == 401

    def test_the_cell_plan_gets_the_enrolled_check(self, client, store, api_ledger):
        enrol(api_ledger, "0412", intervene=True)
        r = client.post("/v1/check/fleet-machine",
                        json={"machine_key": "Grimaldi/AR-7#0412",
                              "advisory": advisory().to_dict()},
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["verdict"] == "requires_reverification"
        assert d["enrolled"] is True
        assert d["latest_intervention"]["intervention_id"] == "INT-0412"

    def test_an_unenrolled_machine_is_a_404_not_a_guess(self, client, store):
        r = client.post("/v1/check/fleet-machine",
                        json={"machine_key": "Grimaldi/AR-7#0000"},
                        headers=keyed(store, "cell"))
        assert r.status_code == 404

    def test_the_402_is_structured_for_an_agent(self, client, store):
        r = client.post("/v1/check/fleet-machine",
                        json={"machine_key": "Grimaldi/AR-7#0412"},
                        headers=keyed(store, "register"))
        d = r.json()["detail"]
        assert d["status"] == "payment_required"
        assert d["required_plan"] == "cell"
        assert d["service"] == "fleet_machine_assurance"
        assert d["next_step"] == "checkout"

    def test_the_401_is_structured_for_an_agent(self, client):
        r = client.post("/v1/check/fleet-machine",
                        json={"machine_key": "Grimaldi/AR-7#0412"})
        d = r.json()["detail"]
        assert d["status"] == "authentication_required"
        assert d["service"] == "fleet_machine_assurance"

    def test_the_service_catalogue_is_free_and_real(self, client):
        r = client.get("/v1/check/services")
        assert r.status_code == 200
        ids = {s["service_id"] for s in r.json()["services"]}
        assert ids == {"machine_assurance_check", "fleet_machine_assurance"}
        cell_service = next(s for s in r.json()["services"]
                            if s["service_id"] == "fleet_machine_assurance")
        assert cell_service["required_plan"] == "cell"
        assert cell_service["free_or_paid"] == "paid"
        assert "manifest" in cell_service["input_schema"] or \
               "machine_key" in cell_service["input_schema"]["properties"]

    def test_the_free_check_names_the_real_next_action(self, client):
        r = client.post("/v1/check/machine", json={
            "manifest": manifest().to_dict(), "advisory": advisory().to_dict()})
        action = r.json()["commercial_next_action"]
        assert action["action"] == "enroll_machine"
        assert action["endpoint"] == "POST /v1/machinery/manifest"
