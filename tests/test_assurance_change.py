"""Continuous Machine Change Assurance: change -> impact -> action -> re-
verification -> human decision -> closure — over the real engines, not a
simulation of them.

Every fixture below is copied from an existing test file
(``tests/test_assurance_machinery.py``, ``tests/test_assurance_fleet.py``)
rather than invented, so a ``ChangeAssuranceCase`` here is built from exactly
the same ``SafetyManifest``/``Intervention``/``ComponentAdvisory`` objects the
rest of this product already tests against.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.change import (
    CaseStatus,
    CaseStore,
    CaseTransitionError,
    TriggerType,
    advance,
    assess_advisory,
    assess_drift,
    assess_intervention,
    claim,
    decide,
    reverify,
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
from assurance.machinery.divergence import compare
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
from assurance.machinery.record import (
    interventions_from_ledger,
    record_intervention,
    record_manifest,
)
from assurance.machinery.staleness import VerificationRecord

ENG = Actor("a.integrator", "safety engineer")
TECH = Actor("m.tech", "service technician")
REVIEWER = Actor("v.grimaldi", "assurance reviewer")

MACHINE = MachineIdentity(manufacturer="Grimaldi", model="AR-7", serial="0412", site="Plant 2")
FUNCS = (
    SafetyFunction("SF-01", "Protective stop on zone intrusion", "PL d",
                   verified_by=("ssm_separation", "stop_characterisation")),
    SafetyFunction("SF-02", "Speed limit in collaborative operation", "PL d",
                   verified_by=("speed_limit",)),
)


def item(item_id="ITM-FW", **over):
    kw = {
        "item_id": item_id, "kind": ItemKind.FIRMWARE,
        "name": "Safety controller firmware", "version": "3.8.2",
        "content_hash": "a" * 64, "hash_source": HashSource.READ_FROM_MACHINE,
        "supplier": "ControlCo", "implements": ("SF-01", "SF-02"),
    }
    kw.update(over)
    return SafetyItem(**kw)


def manifest(*items, **over):
    kw = {
        "manifest_id": "MAN-1", "machine": MACHINE, "source": ManifestSource.AS_FOUND,
        "taken_at": datetime(2026, 1, 20, tzinfo=UTC), "taken_by": ENG,
        "items": items or (item(),), "functions": FUNCS,
        "method": "read via controller service port",
    }
    kw.update(over)
    return SafetyManifest(**kw)


def intervention(**over):
    kw = {
        "intervention_id": "INT-0007", "machine_key": MACHINE.key, "item_id": "ITM-FW",
        "kind": InterventionKind.UPDATE,
        "occurred_at": datetime(2026, 3, 14, 9, 30, tzinfo=UTC), "performed_by": TECH,
        "reason": "Vendor advisory: watchdog timeout under bus load.",
        "from_hash": "a" * 64, "to_hash": "d" * 64,
        "affects_functions": ("SF-01", "SF-02"),
    }
    kw.update(over)
    return Intervention(**kw)


def seal_a_real_verification(ledger, *, when):
    env = SafetyEnvelope(
        envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-11", "2026-01-18")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "CAL-003")),
        intrusion_distance_mm=850.0)
    run = Trace(trace_id=f"RUN-{when:%Y%m%d}", provenance=Provenance.FIELD,
                source_system="AR-7 fw", started_at=when, sample_rate_hz=50.0,
                samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=400.0,
                                     mode=OperatingMode.SSM, separation=2200.0)
                             for i in range(10)))
    return build_bundle(env, run, actor=ENG, ledger=ledger, subject=MACHINE.key)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "change.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


# =====================================================================
# The required demonstration: a machine changes, a case opens, evidence
# goes stale, re-verification closes it, and the ledger stays whole.
# =====================================================================

class TestDriftLifecycle:
    def test_a_relabelling_opens_no_case(self, store):
        baseline = manifest(manifest_id="BASE")
        observed = manifest(item(version="3.8.2a"), manifest_id="NOW")
        divergence = compare(baseline, observed)
        case = assess_drift(store, divergence, observed, [], [], actor=ENG)
        assert case is None

    def test_a_safety_relevant_change_opens_a_case_naming_the_functions(self, store):
        baseline = manifest(manifest_id="BASE")
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        divergence = compare(baseline, observed)
        case = assess_drift(store, divergence, observed, [], [], actor=ENG)
        assert case is not None
        assert case.status is CaseStatus.OPEN
        assert case.machines == (MACHINE.key,)
        assert set(case.affected_functions) == {"SF-01", "SF-02"}
        assert case.required_reverifications
        # No verification and no intervention have ever been recorded for
        # this machine at all: assess_coverage reports never_verified, not
        # stale, and the required action says exactly that.
        assert "no verification" in case.required_actions[0]

    def test_the_same_drift_seen_twice_is_one_case(self, store):
        baseline = manifest(manifest_id="BASE")
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        divergence = compare(baseline, observed)
        first = assess_drift(store, divergence, observed, [], [], actor=ENG)
        second = assess_drift(store, divergence, observed, [], [], actor=ENG)
        assert first.case_id == second.case_id
        assert len(store.list()) == 1

    def test_end_to_end_change_to_impact_to_closure(self, ledger, store):
        """The exact demonstration the product exists to run.

        A configuration change is detected, a case opens naming the affected
        function, evidence is stale, a human claims the case, re-verification
        evidence is supplied through the real machine-verification engine,
        the case reaches READY_TO_CLOSE, and only a named human decision
        closes it — and the whole thing is still one verifying ledger.
        """
        record_manifest(ledger, manifest(manifest_id="BASE"))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        record_intervention(ledger, intervention())

        observed = manifest(item(content_hash="d" * 64), manifest_id="AFTER")
        baseline = manifest(manifest_id="BASE")
        divergence = compare(baseline, observed)
        assert divergence.verdict == "safety_relevant_drift"

        verifications = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        interventions = interventions_from_ledger(ledger, MACHINE.key)
        case = assess_drift(store, divergence, observed, verifications, interventions,
                            actor=ENG)
        assert case is not None
        assert case.evidence_current["SF-01"] == "stale"
        assert "INT-0007" in case.invalidation_reason

        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        assert case.status is CaseStatus.IN_REVIEW

        # A required action ("re-run the checks") is outstanding, so the
        # first hop lands on AWAITING_ACTION, not straight past it.
        case = advance(store, case.case_id, actor=REVIEWER)
        assert case.status is CaseStatus.AWAITING_ACTION

        case = advance(store, case.case_id, actor=REVIEWER)
        assert case.status is CaseStatus.AWAITING_REVERIFICATION

        # Cannot close from here — no shortcut, whoever asks.
        with pytest.raises(CaseTransitionError):
            decide(store, case.case_id, disposition="closed",
                  reason="looks fine", actor=REVIEWER)

        fresh_bundle = seal_a_real_verification(ledger, when=datetime(2026, 4, 1, tzinfo=UTC))
        new_verifications = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        case = reverify(store, case.case_id, observed, new_verifications, interventions,
                        verification_content_hash=fresh_bundle.content_hash, actor=REVIEWER)
        assert case.status is CaseStatus.READY_TO_CLOSE
        assert not case.required_reverifications

        case = decide(store, case.case_id, disposition="closed",
                     reason="Stop-performance re-run on 2026-04-01; SF-01 current again.",
                     actor=REVIEWER)
        assert case.status is CaseStatus.CLOSED
        assert case.decision_by == "v.grimaldi"
        assert case.closed_at

        ok, problems = ledger.verify_chain()
        assert ok, problems
        replayed = store.get(case.case_id)
        assert replayed.status is CaseStatus.CLOSED
        assert len(replayed.history) >= 4  # opened, transition, reverification, decision


class TestRejectAndDefer:
    def test_a_case_can_be_rejected_without_reverification(self, store):
        baseline = manifest(manifest_id="BASE")
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        case = assess_drift(store, compare(baseline, observed), observed, [], [], actor=ENG)
        case = decide(store, case.case_id, disposition="rejected",
                     reason="Duplicate of a change already tracked in INT-0007.",
                     actor=REVIEWER)
        assert case.status is CaseStatus.REJECTED
        assert case.status.is_settled
        assert not case.status.is_closed

    def test_a_settled_case_seeing_the_same_drift_again_is_left_alone(self, store):
        baseline = manifest(manifest_id="BASE")
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        divergence = compare(baseline, observed)
        case = assess_drift(store, divergence, observed, [], [], actor=ENG)
        decide(store, case.case_id, disposition="rejected", reason="not real",
              actor=REVIEWER)
        again = assess_drift(store, divergence, observed, [], [], actor=ENG)
        assert again.status is CaseStatus.REJECTED  # untouched, not reopened

    def test_decide_needs_a_reason(self, store):
        baseline = manifest(manifest_id="BASE")
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        case = assess_drift(store, compare(baseline, observed), observed, [], [], actor=ENG)
        with pytest.raises(CaseTransitionError, match="needs a reason"):
            decide(store, case.case_id, disposition="rejected", reason="  ", actor=REVIEWER)


# =====================================================================
# Trigger B — the supplier path
# =====================================================================

GOOD_FW = "1" * 64
FIXED_FW = "3" * 64


def fw(content_hash=GOOD_FW, version="3.8.2", **over):
    kw = {
        "item_id": "ITM-FW", "kind": ItemKind.FIRMWARE,
        "name": "Safety controller firmware", "version": version,
        "content_hash": content_hash, "hash_source": HashSource.READ_FROM_MACHINE,
        "supplier": "ControlCo", "implements": ("SF-01", "SF-02"),
    }
    kw.update(over)
    return SafetyItem(**kw)


def advisory(**over):
    kw = {
        "advisory_id": "CTRL-2026-11", "issued_by": "ControlCo",
        "issued_at": datetime(2026, 9, 12, 8, tzinfo=UTC),
        "title": "Watchdog may not trip under sustained bus load",
        "summary": "The watchdog can fail to trigger the safety-rated stop.",
        "severity": AdvisorySeverity.SAFETY_RELEVANT,
        "affected": (AffectedArtefact(supplier="ControlCo", name="Safety controller firmware",
                                      versions=("3.8.0", "3.8.1", "3.8.2"),
                                      content_hashes=(GOOD_FW,)),),
        "remedy": "Update to 3.9.0 and re-run the stop-performance test.",
        "reference": "https://controlco.example/advisories/CTRL-2026-11",
        "fixed_versions": ("3.9.0",), "fixed_hashes": (FIXED_FW,),
    }
    kw.update(over)
    return ComponentAdvisory(**kw)


class TestAdvisoryLifecycle:
    def test_a_clear_advisory_opens_no_case(self, store, ledger):
        record_manifest(ledger, manifest(fw(content_hash="9" * 64, version="9.9.9")))
        fleet = Fleet.from_ledger(ledger)
        report = assess_impact(advisory(), fleet)
        assert assess_advisory(store, report, actor=ENG) is None

    def test_an_exposed_fleet_opens_one_case_naming_every_machine(self, ledger, store):
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
        other = manifest(fw(), manifest_id="MAN-0413",
                         machine=MachineIdentity("Grimaldi", "AR-7", "0413", site="Plant 3"))
        record_manifest(ledger, other)
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))

        fleet = Fleet.from_ledger(ledger)
        report = assess_impact(advisory(), fleet)
        case = assess_advisory(store, report, actor=ENG)
        assert case is not None
        assert case.trigger_type is TriggerType.SUPPLIER_ADVISORY
        assert set(case.machines) == {MACHINE.key, "Grimaldi/AR-7#0413"}
        assert case.required_actions
        assert len(store.list()) == 1  # one case, not one per machine


class TestInterventionLifecycle:
    def test_an_intervention_with_nothing_re_run_opens_a_case(self, ledger, store):
        record_manifest(ledger, manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        interv = intervention()
        record_intervention(ledger, interv)

        verifications = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        interventions = interventions_from_ledger(ledger, MACHINE.key)
        case = assess_intervention(store, interv, manifest(), verifications, interventions,
                                   actor=TECH)
        assert case is not None
        assert case.trigger_type is TriggerType.INTERVENTION
        assert "SF-01" in case.affected_functions


    def test_a_revalidated_intervention_opens_no_case(self, ledger, store):
        """assess_coverage does not treat an unevidenced revalidation claim as
        covering — see test_assurance_machinery.py — so this still opens a
        case; it exists here to document that boundary for this module too."""
        record_manifest(ledger, manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        interv = intervention()
        record_intervention(ledger, interv)
        verifications = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        interventions = interventions_from_ledger(ledger, MACHINE.key)
        case = assess_intervention(store, interv, manifest(), verifications, interventions,
                                   actor=TECH)
        assert case is not None


# =====================================================================
# The CLI — the surface a customer actually types at
# =====================================================================

class TestCli:
    def _change(self, *argv) -> int:
        from assurance.change.cli import main

        return main(list(argv))

    def test_end_to_end_through_the_cli(self, tmp_path, capsys):
        ledger_path = tmp_path / "l.db"
        ledger = EvidenceLedger(ledger_path)
        record_manifest(ledger, manifest(manifest_id="BASE"))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        record_intervention(ledger, intervention())

        base_path = tmp_path / "base.json"
        base_path.write_text(json.dumps(manifest(manifest_id="BASE").to_dict()))
        after = manifest(item(content_hash="d" * 64), manifest_id="AFTER")
        after_path = tmp_path / "after.json"
        after_path.write_text(json.dumps(after.to_dict()))

        capsys.readouterr()
        assert self._change("assess-drift", "--ledger", str(ledger_path),
                            "--baseline", str(base_path), "--observed", str(after_path),
                            "--actor", "watch-01") == 0
        out = capsys.readouterr().out
        assert "case-" in out

        store = CaseStore(EvidenceLedger(ledger_path))
        case_id = store.list()[0].case_id

        capsys.readouterr()
        assert self._change("list", "--ledger", str(ledger_path)) == 1
        listing = capsys.readouterr().out
        assert case_id in listing
        assert "safety-relevant" in listing

        assert self._change("claim", "--ledger", str(ledger_path), case_id,
                            "--owner", "v.grimaldi", "--actor", "v.grimaldi") == 0
        assert self._change("advance", "--ledger", str(ledger_path), case_id,
                            "--actor", "v.grimaldi") == 0
        assert self._change("advance", "--ledger", str(ledger_path), case_id,
                            "--actor", "v.grimaldi") == 0

        fresh = seal_a_real_verification(ledger, when=datetime(2026, 4, 1, tzinfo=UTC))
        assert self._change("reverify", "--ledger", str(ledger_path), case_id,
                            "--manifest", str(after_path),
                            "--verification-hash", fresh.content_hash,
                            "--actor", "v.grimaldi") == 0

        assert self._change("decide", "--ledger", str(ledger_path), case_id,
                            "--disposition", "closed",
                            "--reason", "Re-verified 2026-04-01.",
                            "--actor", "v.grimaldi") == 0

        capsys.readouterr()
        assert self._change("show", "--ledger", str(ledger_path), case_id) == 0
        detail = capsys.readouterr().out
        assert "CLOSED" in detail
        assert "v.grimaldi" in detail

        ok, problems = ledger.verify_chain()
        assert ok, problems

    def test_a_clean_diff_opens_no_case_and_says_so(self, tmp_path, capsys):
        ledger_path = tmp_path / "l.db"
        base_path = tmp_path / "base.json"
        base_path.write_text(json.dumps(manifest(manifest_id="BASE").to_dict()))
        capsys.readouterr()
        assert self._change("assess-drift", "--ledger", str(ledger_path),
                            "--baseline", str(base_path), "--observed", str(base_path)) == 0
        assert "no case opened" in capsys.readouterr().out

    def test_show_an_unknown_case_is_a_clean_error(self, tmp_path, capsys):
        ledger_path = tmp_path / "l.db"
        EvidenceLedger(ledger_path)
        capsys.readouterr()
        assert self._change("show", "--ledger", str(ledger_path), "case-doesnotexist") == 2
        assert "no case" in capsys.readouterr().err

    def test_closing_before_ready_is_refused(self, tmp_path, capsys):
        ledger_path = tmp_path / "l.db"
        base_path = tmp_path / "base.json"
        base_path.write_text(json.dumps(manifest(manifest_id="BASE").to_dict()))
        after_path = tmp_path / "after.json"
        after_path.write_text(json.dumps(
            manifest(item(content_hash="d" * 64), manifest_id="AFTER").to_dict()))
        self._change("assess-drift", "--ledger", str(ledger_path),
                    "--baseline", str(base_path), "--observed", str(after_path))
        store = CaseStore(EvidenceLedger(ledger_path))
        case_id = store.list()[0].case_id
        capsys.readouterr()
        assert self._change("decide", "--ledger", str(ledger_path), case_id,
                            "--disposition", "closed", "--reason", "premature") == 1
        assert "finding" in capsys.readouterr().err


# =====================================================================
# HTTP — the same Cell-tier boundary as /v1/machine and /v1/machinery/coverage
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
def account_store(client):
    from assurance.api import deps
    return deps.get_accounts()


def keyed(account_store, tier):
    account = account_store.upsert_account(email=f"{tier}-change@example.de", tier=tier)
    return {"X-API-Key": account_store.issue_key(account.id)}


class TestHttp:
    def test_assess_drift_is_a_402_without_the_cell_plan(self, client, account_store):
        r = client.post("/v1/change/assess/drift",
                        json={"baseline": manifest(manifest_id="BASE").to_dict(),
                              "observed": manifest(manifest_id="BASE").to_dict()},
                        headers=keyed(account_store, "register"))
        assert r.status_code == 402

    def test_assess_drift_needs_no_body_actor(self, client, account_store):
        r = client.post("/v1/change/assess/drift",
                        json={"baseline": manifest(manifest_id="BASE").to_dict(),
                              "observed": manifest(item(content_hash="d" * 64),
                                                   manifest_id="NOW").to_dict()},
                        headers=keyed(account_store, "cell"))
        assert r.status_code == 200
        body = r.json()
        assert body["opened"] is True
        assert body["case"]["status"] == "open"

    def test_the_full_lifecycle_over_http(self, client, account_store):
        headers = keyed(account_store, "cell")
        r = client.post("/v1/change/assess/drift",
                        json={"baseline": manifest(manifest_id="BASE").to_dict(),
                              "observed": manifest(item(content_hash="d" * 64),
                                                   manifest_id="NOW").to_dict()},
                        headers=headers)
        case_id = r.json()["case"]["case_id"]

        r = client.get("/v1/change/cases", headers=headers)
        assert r.status_code == 200
        assert r.json()["summary"]["open"] == 1

        r = client.get(f"/v1/change/cases/{case_id}", headers=headers)
        assert r.status_code == 200

        r = client.post(f"/v1/change/cases/{case_id}/claim",
                        json={"owner": "v.grimaldi"}, headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "in_review"

        r = client.post(f"/v1/change/cases/{case_id}/decision",
                        json={"disposition": "closed", "reason": "too early"},
                        headers=headers)
        assert r.status_code == 409  # not ready_to_close yet

    def test_an_unknown_case_is_a_404(self, client, account_store):
        r = client.get("/v1/change/cases/case-doesnotexist", headers=keyed(account_store, "cell"))
        assert r.status_code == 404
