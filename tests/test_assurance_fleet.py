"""Tests for the fleet layer: advisories, impact, and the declaration binding.

The tests that carry the product are the matching ones. An advisory matched on a
version label when the artefact contradicts the supplier's own published hash
must land in neither the affected column nor the clear one, and a machine whose
evidence was already stale must not be counted as newly in question — otherwise
the report hides the machines that were fine until this morning.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.fleet.declaration import (
    DeclarationError,
    DeclarationOfConformity,
    DeclarationVerdict,
    check_declaration,
)
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
from assurance.machinery.staleness import Coverage

ENG = Actor("a.integrator", "safety engineer")
TECH = Actor("m.tech", "service technician")

GOOD_FW = "1" * 64      # what ControlCo published for 3.8.2
OTHER_FW = "2" * 64     # a different artefact wearing the same label
FIXED_FW = "3" * 64     # ControlCo's 3.9.0

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


def manifest(serial="0412", *items, site="Plant 2", **over):
    machine = MachineIdentity("Grimaldi", "AR-7", serial, site=site)
    kw = {
        "manifest_id": f"MAN-{serial}", "machine": machine,
        "source": ManifestSource.AS_FOUND,
        "taken_at": datetime(2026, 9, 1, tzinfo=UTC), "taken_by": ENG,
        "items": items or (fw(),), "functions": FUNCS,
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


# =====================================================================
# matching — the part that decides whether the report is worth anything
# =====================================================================

class TestMatching:
    def test_a_hash_match_is_confirmed(self):
        basis, detail = match_item(advisory(), fw())
        assert basis is MatchBasis.HASH
        assert basis.confidence == "confirmed"
        assert "byte-identical" in detail

    def test_a_label_that_the_artefact_contradicts_is_its_own_finding(self):
        """Neither affected nor clear. The star finding of this module."""
        basis, detail = match_item(advisory(), fw(content_hash=OTHER_FW))
        assert basis is MatchBasis.HASH_MISMATCH
        assert basis.confidence == "contradictory"
        assert basis.needs_a_human
        assert "not running what it says" in detail

    def test_a_machine_already_carrying_the_fix_but_a_stale_label_says_so(self):
        basis, detail = match_item(advisory(), fw(content_hash=FIXED_FW))
        assert basis is MatchBasis.HASH_MISMATCH
        assert "lists as FIXED" in detail

    def test_a_label_match_with_no_published_hash_rests_on_a_label(self):
        adv = advisory(affected=(AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.2",)),))
        basis, detail = match_item(adv, fw())
        assert basis is MatchBasis.VERSION
        assert basis.confidence == "probable"
        assert "a label is not an artefact" in detail

    def test_a_fixed_version_does_not_match(self):
        assert match_item(advisory(), fw(content_hash=FIXED_FW,
                                         version="3.9.0")) is None

    def test_an_unlisted_version_does_not_match(self):
        assert match_item(advisory(), fw(content_hash="9" * 64,
                                         version="4.0.0")) is None

    def test_a_component_with_no_version_recorded_needs_a_human(self):
        basis, detail = match_item(advisory(), fw(content_hash="", version="",
                                                  hash_source=HashSource.DECLARED))
        assert basis is MatchBasis.NAME_ONLY
        assert "Somebody has to look" in detail

    def test_a_different_supplier_does_not_match(self):
        assert match_item(advisory(), fw(supplier="OtherCo")) is None

    def test_supplier_matching_is_case_and_space_insensitive_but_not_fuzzy(self):
        assert match_item(advisory(), fw(supplier=" controlco ")) is not None
        assert match_item(advisory(), fw(supplier="Control Co GmbH")) is None

    def test_an_advisory_naming_neither_version_nor_hash_is_refused(self):
        with pytest.raises(AdvisoryError, match="every version"):
            AffectedArtefact(supplier="ControlCo", name="fw")

    def test_an_advisory_with_no_reference_is_refused(self):
        with pytest.raises(AdvisoryError, match="rumour"):
            advisory(reference="")

    def test_an_advisory_with_no_affected_artefact_is_refused(self):
        with pytest.raises(AdvisoryError, match="no affected artefact"):
            advisory(affected=())

    def test_it_survives_json(self, tmp_path):
        a = advisory()
        p = tmp_path / "a.json"
        p.write_text(json.dumps(a.to_dict()))
        assert ComponentAdvisory.from_json(p).content_hash() == a.content_hash()


# =====================================================================
# the fleet and the fan-out
# =====================================================================

@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "fleet.db")


def enrol(ledger, serial, *, fw_hash=GOOD_FW, fw_version="3.8.2",
          verify=True, intervene=False, site="Plant 2"):
    man = manifest(serial, fw(fw_hash, fw_version),
                   SafetyItem("ITM-ZONES", ItemKind.SAFETY_CONFIGURATION,
                              "Safety scanner zone set", "r4", "b" * 64,
                              HashSource.READ_FROM_MACHINE, supplier="ScanCo",
                              implements=("SF-01",), modifiable_in_field=True),
                   site=site)
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


class TestFleet:
    def test_an_empty_ledger_is_an_empty_fleet(self, ledger):
        assert len(Fleet.from_ledger(ledger)) == 0

    def test_each_machine_appears_once(self, ledger):
        enrol(ledger, "0412")
        enrol(ledger, "0418")
        assert len(Fleet.from_ledger(ledger)) == 2

    def test_the_latest_manifest_wins(self, ledger):
        enrol(ledger, "0412", fw_hash=GOOD_FW)
        record_manifest(ledger, manifest("0412", fw(OTHER_FW),
                                         manifest_id="MAN-LATER"))
        fleet = Fleet.from_ledger(ledger)
        assert len(fleet) == 1
        assert fleet.records[0].manifest.manifest_id == "MAN-LATER"

    def test_machines_with_gaps_are_separated(self, ledger):
        enrol(ledger, "0412")
        enrol(ledger, "0501", intervene=True)
        fleet = Fleet.from_ledger(ledger)
        assert [r.machine_key for r in fleet.with_gaps()] == ["Grimaldi/AR-7#0501"]

    def test_the_summary_counts_by_worst_state(self, ledger):
        enrol(ledger, "0412")
        enrol(ledger, "0733", verify=False)
        s = Fleet.from_ledger(ledger).summary()
        assert s.machines == 2
        assert s.by_worst["never_verified"] == 1
        assert s.chain_verified

    def test_the_table_puts_the_worst_first(self, ledger):
        enrol(ledger, "0412")
        enrol(ledger, "0501", intervene=True)
        table = Fleet.from_ledger(ledger).table()
        assert table.index("0501") < table.index("0412")

    def test_sites_are_counted(self, ledger):
        enrol(ledger, "0412", site="Plant 2")
        enrol(ledger, "0620", site="Plant 7")
        assert Fleet.from_ledger(ledger).summary().sites == {"Plant 2": 1,
                                                             "Plant 7": 1}


class TestImpact:
    def test_an_advisory_nobody_matches_is_clear(self, ledger):
        enrol(ledger, "0620", fw_hash=FIXED_FW, fw_version="3.9.0")
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.verdict == "clear"
        assert r.machines_affected == ()

    def test_it_reaches_serial_numbers(self, ledger):
        enrol(ledger, "0412")
        enrol(ledger, "0620", fw_hash=FIXED_FW, fw_version="3.9.0")
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.machines_affected == ("Grimaldi/AR-7#0412",)

    def test_it_reaches_the_safety_functions_that_were_covered(self, ledger):
        enrol(ledger, "0412")
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.verdict == "exposed"
        assert r.functions_newly_in_question == 2
        names = {f.function_id for e in r.exposures for f in e.newly_in_question}
        assert names == {"SF-01", "SF-02"}

    def test_a_function_already_stale_is_not_counted_as_newly_in_question(self, ledger):
        """An advisory does not make an already-lapsed function worse."""
        enrol(ledger, "0501", intervene=True)
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        e = r.exposures[0]
        by_id = {f.function_id: f for f in e.functions}
        assert by_id["SF-01"].coverage_before is Coverage.STALE
        assert by_id["SF-01"].newly_in_question is False
        assert by_id["SF-02"].newly_in_question is True

    def test_a_never_verified_function_is_not_newly_in_question_either(self, ledger):
        enrol(ledger, "0733", verify=False)
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.functions_newly_in_question == 0
        assert r.verdict == "needs_review"

    def test_a_contradictory_match_is_counted_in_neither_column(self, ledger):
        enrol(ledger, "0418", fw_hash=OTHER_FW)
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert len(r.contradictory) == 1
        assert r.functions_newly_in_question == 0
        assert r.confirmed == ()
        assert any("neither column" in c for c in r.checks_skipped)

    def test_an_informational_advisory_puts_nothing_in_question(self, ledger):
        enrol(ledger, "0412")
        r = assess_impact(advisory(severity=AdvisorySeverity.INFORMATIONAL),
                          Fleet.from_ledger(ledger))
        assert r.exposures
        assert r.functions_newly_in_question == 0
        assert r.verdict == "needs_review"

    def test_a_stop_use_advisory_is_ranked_above_safety_relevant(self):
        assert AdvisorySeverity.STOP_USE.rank > AdvisorySeverity.SAFETY_RELEVANT.rank
        assert AdvisorySeverity.STOP_USE.puts_functions_in_question

    def test_it_says_when_the_supplier_published_no_hashes(self, ledger):
        enrol(ledger, "0412")
        adv = advisory(affected=(AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.2",)),))
        r = assess_impact(adv, Fleet.from_ledger(ledger))
        assert any("rests on a version label" in c for c in r.checks_skipped)

    def test_absence_is_never_reported_as_safety(self, ledger):
        enrol(ledger, "0412")
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert any("absence here is not evidence of safety" in c
                   for c in r.checks_skipped)

    def test_the_full_mixed_fleet_lands_in_the_right_columns(self, ledger):
        enrol(ledger, "0412")                                    # confirmed, covered
        enrol(ledger, "0418", fw_hash=OTHER_FW)                  # contradictory
        enrol(ledger, "0501", intervene=True)                    # confirmed, part stale
        enrol(ledger, "0620", fw_hash=FIXED_FW, fw_version="3.9.0")  # clear
        enrol(ledger, "0733", verify=False)                      # confirmed, no evidence
        r = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert r.machines_in_fleet == 5
        assert len(r.machines_affected) == 4
        assert len(r.confirmed) == 3
        assert len(r.contradictory) == 1
        assert r.functions_newly_in_question == 3   # 0412 both, 0501 one


# =====================================================================
# declarations
# =====================================================================

class TestDeclaration:
    def _doc(self, man, **over):
        kw = {
            "doc_id": "DOC-0412", "issued_by": "Grimaldi Engineering",
            "issued_at": datetime(2026, 1, 20, tzinfo=UTC),
            "legislation": ("Regulation (EU) 2023/1230",),
            "standards": ("EN ISO 10218-2:2025",),
        }
        kw.update(over)
        return DeclarationOfConformity.bind(man, **kw)

    def test_a_declaration_with_no_configuration_hash_is_refused(self):
        with pytest.raises(DeclarationError, match="no configuration hash"):
            DeclarationOfConformity(
                doc_id="D", machine_key="k", issued_by="x",
                issued_at=datetime(2026, 1, 1, tzinfo=UTC),
                configuration_hash="", legislation=("x",))

    def test_a_declaration_of_conformity_to_nothing_is_refused(self):
        with pytest.raises(DeclarationError, match="names no legislation"):
            DeclarationOfConformity(
                doc_id="D", machine_key="k", issued_by="x",
                issued_at=datetime(2026, 1, 1, tzinfo=UTC),
                configuration_hash="a" * 64, legislation=())

    def test_an_unchanged_machine_is_still_described(self):
        man = manifest()
        status = check_declaration(self._doc(man), man)
        assert status.verdict is DeclarationVerdict.DESCRIBES_THE_MACHINE

    def test_a_changed_configuration_is_the_finding(self):
        man = manifest()
        later = manifest(items=(fw(content_hash=OTHER_FW),))
        status = check_declaration(self._doc(man), later)
        assert status.verdict is DeclarationVerdict.CONFIGURATION_CHANGED
        assert "does not describe this machine" in status.statement

    def test_a_declaration_about_another_machine_says_nothing(self):
        status = check_declaration(self._doc(manifest("0412")), manifest("9999"))
        assert status.verdict is DeclarationVerdict.WRONG_MACHINE

    def test_an_intact_configuration_with_lapsed_evidence_is_separate(self, ledger):
        man = enrol(ledger, "0501", intervene=True)
        from assurance.machinery.record import interventions_from_ledger
        from assurance.machinery.staleness import VerificationRecord, assess_coverage
        coverage = assess_coverage(
            man,
            VerificationRecord.from_ledger(ledger, subject=man.machine.key),
            interventions_from_ledger(ledger, man.machine.key))
        status = check_declaration(self._doc(man), man, coverage)
        assert status.verdict is \
            DeclarationVerdict.CONFIGURATION_INTACT_EVIDENCE_LAPSED
        assert "SF-01" in status.lapsed_functions

    def test_it_refuses_to_give_legal_advice_in_writing(self):
        man = manifest()
        status = check_declaration(self._doc(man), man)
        assert any("Nothing here is legal advice" in c for c in status.checks_skipped)

    def test_without_coverage_it_says_only_the_configuration_was_compared(self):
        man = manifest()
        status = check_declaration(self._doc(man), man)
        assert any("only the configuration was compared" in c
                   for c in status.checks_skipped)

    def test_unhashed_items_are_declared_as_outside_the_configuration_hash(self):
        man = manifest("0412", fw(),
                       SafetyItem("ITM-HMI", ItemKind.LIBRARY, "HMI", "9", "",
                                  HashSource.DECLARED, implements=()))
        status = check_declaration(self._doc(man), man)
        assert any("leaves the configuration hash unmoved" in c
                   for c in status.checks_skipped)

    def test_it_survives_json(self, tmp_path):
        d = self._doc(manifest())
        p = tmp_path / "d.json"
        p.write_text(json.dumps(d.to_dict()))
        assert DeclarationOfConformity.from_json(p).content_hash() == d.content_hash()


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


@pytest.fixture
def api_ledger(client):
    from assurance.api import deps
    return deps.get_register().ledger


def keyed(store, tier):
    account = store.upsert_account(email=f"{tier}-fleet@example.de", tier=tier)
    return {"X-API-Key": store.issue_key(account.id)}


class TestHttp:
    def test_the_single_machine_check_needs_no_account(self, client):
        r = client.post("/v1/fleet/advisory/check", json={
            "advisory": advisory().to_dict(), "manifest": manifest().to_dict()})
        assert r.status_code == 200
        assert r.json()["affected"] is True
        assert r.json()["matches"][0]["basis"] == "hash"

    def test_it_is_metered_on_the_free_tier(self, client):
        r = client.post("/v1/fleet/advisory/check", json={
            "advisory": advisory().to_dict(), "manifest": manifest().to_dict()})
        assert r.headers["x-assurance-quota-limit"] == "10"

    def test_a_clear_machine_is_reported_as_clear(self, client):
        r = client.post("/v1/fleet/advisory/check", json={
            "advisory": advisory().to_dict(),
            "manifest": manifest("0620", fw(FIXED_FW, "3.9.0")).to_dict()})
        assert r.json()["affected"] is False

    def test_a_contradiction_is_surfaced_over_http_too(self, client):
        r = client.post("/v1/fleet/advisory/check", json={
            "advisory": advisory().to_dict(),
            "manifest": manifest("0418", fw(OTHER_FW)).to_dict()})
        m = r.json()["matches"][0]
        assert m["basis"] == "hash_mismatch"
        assert m["needs_a_human"] is True

    def test_the_fan_out_is_a_402_without_the_cell_plan(self, client, store):
        r = client.post("/v1/fleet/advisory",
                        json={"advisory": advisory().to_dict()},
                        headers=keyed(store, "register"))
        assert r.status_code == 402

    def test_the_fan_out_needs_a_key(self, client):
        assert client.post("/v1/fleet/advisory",
                           json={"advisory": advisory().to_dict()}).status_code == 401

    def test_the_cell_plan_gets_the_fan_out(self, client, store, api_ledger):
        enrol(api_ledger, "0412")
        enrol(api_ledger, "0620", fw_hash=FIXED_FW, fw_version="3.9.0")
        r = client.post("/v1/fleet/advisory",
                        json={"advisory": advisory().to_dict()},
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["verdict"] == "exposed"
        assert d["machines_in_fleet"] == 2
        assert d["machines_affected"] == ["Grimaldi/AR-7#0412"]
        assert d["functions_newly_in_question"] == 2

    def test_the_machine_list_is_gated_and_ordered(self, client, store, api_ledger):
        enrol(api_ledger, "0412")
        enrol(api_ledger, "0501", intervene=True)
        r = client.get("/v1/fleet/machines", headers=keyed(store, "cell"))
        assert r.status_code == 200
        assert r.json()["summary"]["machines"] == 2
        assert r.json()["summary"]["with_gaps"] == 1

    def test_the_declaration_check_is_free(self, client):
        man = manifest()
        doc = DeclarationOfConformity.bind(
            man, doc_id="DOC-1", issued_by="Grimaldi",
            issued_at=datetime(2026, 1, 20, tzinfo=UTC),
            legislation=("Regulation (EU) 2023/1230",))
        r = client.post("/v1/fleet/declaration/check", json={
            "declaration": doc.to_dict(),
            "manifest": manifest("0412", fw(OTHER_FW)).to_dict()})
        assert r.status_code == 200
        assert r.json()["verdict"] == "configuration_changed"

    def test_coverage_on_the_declaration_check_needs_a_plan_and_says_so(self, client):
        man = manifest()
        doc = DeclarationOfConformity.bind(
            man, doc_id="DOC-1", issued_by="Grimaldi",
            issued_at=datetime(2026, 1, 20, tzinfo=UTC),
            legislation=("Regulation (EU) 2023/1230",))
        r = client.post("/v1/fleet/declaration/check", json={
            "declaration": doc.to_dict(), "manifest": man.to_dict(),
            "with_coverage": True})
        assert r.json()["coverage_assessed"] is False
        assert any("needs a plan" in c for c in r.json()["checks_skipped"])

    def test_declare_binds_to_the_configuration_in_front_of_you(self, client, store):
        man = manifest()
        r = client.post("/v1/fleet/declare", json={
            "manifest": man.to_dict(), "doc_id": "DOC-9",
            "issued_by": "Grimaldi Engineering",
            "legislation": ["Regulation (EU) 2023/1230"]},
            headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        assert r.json()["declaration"]["configuration_hash"] == \
            man.configuration_hash()

    def test_the_cell_plan_advertises_the_fleet(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert any("Fleet:" in i for i in plans["cell"]["includes"])
        assert any("Declaration of Conformity" in i
                   for i in plans["free"]["includes"])
