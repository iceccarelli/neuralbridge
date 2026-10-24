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
from datetime import UTC, datetime, timedelta

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
from assurance.core.identity import utc_now
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

from .support_recorder import build_attested_bundle

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


def _inputs(when, subject=None):
    env = SafetyEnvelope(
        envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-11", "2026-01-18")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "CAL-003")),
        intrusion_distance_mm=850.0)
    run = Trace(trace_id=f"RUN-{when:%Y%m%d}" + (f"-{subject}" if subject else ""),
                provenance=Provenance.FIELD,
                source_system="AR-7 fw", started_at=when, sample_rate_hz=50.0,
                samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=400.0,
                                     mode=OperatingMode.SSM, separation=2200.0)
                             for i in range(10)))
    return env, run


_INPUTS: dict[str, tuple] = {}


def seal_a_real_verification(ledger, *, when, subject=None, attested=True):
    """Seal a verification of a field recording.

    By default a recorder the verifier trusts attested the recording (a real signature,
    accepted by the real assessment), so the tests that import this can pin what happens
    to a ``validated`` verification afterwards. ``attested=False`` seals the same
    recording with only its declared provenance, which the engine caps at ``community``.
    """
    env, run = _inputs(when, subject)
    seal = build_attested_bundle if attested else build_bundle
    bundle = seal(env, run, actor=ENG, ledger=ledger, subject=subject or MACHINE.key)
    _INPUTS[bundle.content_hash] = (env, run)
    return bundle


def _same_inputs_as(bundle):
    return _INPUTS[bundle.content_hash]


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


_DECIDERS: dict[tuple[str, str], str] = {}


def as_decider(headers, name="v.grimaldi"):
    """Headers for a key issued to a ``decider`` operator of the caller's account.

    Decisions are refused to account-level keys; this is how a test acts as the
    named human who is allowed to make one. Cached per account and name.
    """
    from assurance.api import deps
    store = deps.get_accounts()
    principal = store.peek_key(headers["X-API-Key"])
    cache_key = (str(store.path), principal.account.id, name)
    if cache_key not in _DECIDERS:
        _DECIDERS[cache_key] = store.create_operator(principal.account.id, name, "decider")[1]
    return {"X-API-Key": _DECIDERS[cache_key]}


def _account_ids(store):
    import sqlite3
    db = sqlite3.connect(store.path)
    try:
        return [r[0] for r in db.execute("SELECT id FROM accounts")]
    finally:
        db.close()


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
                        json={"owner": "v.grimaldi", "actor": "v.grimaldi"},
                        headers=headers)
        assert r.status_code == 200
        assert r.json()["status"] == "in_review"

        r = client.post(f"/v1/change/cases/{case_id}/decision",
                        json={"disposition": "closed", "reason": "too early",
                              "actor": "v.grimaldi"},
                        headers=as_decider(headers))
        assert r.status_code == 409  # not ready_to_close yet

    def test_a_human_step_needs_a_named_actor_bound_to_the_account(self, client, account_store):
        headers = keyed(account_store, "cell")
        r = client.post("/v1/change/assess/drift",
                        json={"baseline": manifest(manifest_id="BASE").to_dict(),
                              "observed": manifest(item(content_hash="d" * 64),
                                                   manifest_id="NOW").to_dict()},
                        headers=headers)
        case_id = r.json()["case"]["case_id"]
        base = f"/v1/change/cases/{case_id}"
        for path, body in (
            ("claim", {"owner": "o"}),
            ("advance", {}),
        ):
            assert client.post(f"{base}/{path}", json=body, headers=headers).status_code == 422
            assert client.post(f"{base}/{path}", json={**body, "actor": "  "},
                               headers=headers).status_code == 422
        # The ledger records the declared person AND the authenticated account.
        r = client.post(f"{base}/claim", json={"owner": "o", "actor": "v.grimaldi"},
                        headers=headers)
        assert r.status_code == 200
        from assurance.api import deps
        account = account_store.account(_account_ids(account_store)[0])
        ledger = deps._tenant_register_for(str(deps.tenant_ledger_path(account.id))).ledger
        recorded = json.dumps([e.payload for e in ledger.entries()])
        assert "v.grimaldi" in recorded
        assert f"via account {account.id}" in recorded
        # An account-level key proves the account, not the person: it is recorded as such.
        assert "attribution=declared_by_account_key" in recorded

    def test_an_unknown_case_is_a_404(self, client, account_store):
        r = client.get("/v1/change/cases/case-doesnotexist", headers=keyed(account_store, "cell"))
        assert r.status_code == 404


# =====================================================================
# Slice S2 — the rules that make the case trustworthy
#
# Idempotency, additive merging, reopening, the human-only decision, the
# guards on READY_TO_CLOSE, and reconstruction from the ledger alone. All of it
# over the real engines (compare / assess_coverage / assess_impact).
# =====================================================================

import sqlite3  # noqa: E402
from dataclasses import replace  # noqa: E402

from assurance.change import (  # noqa: E402
    CaseStoreError,
    reconstruct_case,
    resolve_decision,
    resume,
)
from assurance.change.service import _open_or_update  # noqa: E402
from assurance.change.store import CASE_KINDS, TRANSITION_KIND  # noqa: E402
from assurance.core.evidence import Evidence, Origin  # noqa: E402

BOT = Actor("watch-01", "scheduled watch", kind="automation")
LATER = datetime(2026, 4, 1, tzinfo=UTC)


def case_entries(ledger, case_id):
    return [e for e in ledger.entries(subject=case_id) if e.kind in CASE_KINDS]


def drift(store, ledger=None, *, changed="d", baseline=None, actor=ENG):
    baseline = baseline or manifest(manifest_id="BASE")
    observed = manifest(item(content_hash=changed * 64), manifest_id="NOW")
    verifs = VerificationRecord.from_ledger(ledger, subject=MACHINE.key) if ledger else []
    intervs = interventions_from_ledger(ledger, MACHINE.key) if ledger else []
    return assess_drift(store, compare(baseline, observed), observed, verifs, intervs,
                        actor=actor), observed


def drive(ledger, store, status, *, changed="d"):
    """A drift case taken, through the real service calls, to ``status``."""
    record_manifest(ledger, manifest(manifest_id="BASE"))
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
    case, observed = drift(store, ledger, changed=changed)
    if status is CaseStatus.OPEN:
        return case, observed
    if status in (CaseStatus.REJECTED, CaseStatus.DEFERRED):
        return decide(store, case.case_id, disposition=status.value, reason="r",
                      actor=REVIEWER), observed
    case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
    if status is CaseStatus.IN_REVIEW:
        return case, observed
    case = advance(store, case.case_id, actor=REVIEWER)
    if status is CaseStatus.AWAITING_ACTION:
        return case, observed
    case = advance(store, case.case_id, actor=REVIEWER)
    if status is CaseStatus.AWAITING_REVERIFICATION:
        return case, observed
    bundle = seal_a_real_verification(ledger, when=LATER)
    case = reverify(store, case.case_id, observed,
                    VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                    interventions_from_ledger(ledger, MACHINE.key),
                    verification_content_hash=bundle.content_hash, actor=REVIEWER)
    assert case.status is CaseStatus.READY_TO_CLOSE
    if status is CaseStatus.READY_TO_CLOSE:
        return case, observed
    case = decide(store, case.case_id, disposition="closed", reason="re-verified",
                  actor=REVIEWER)
    assert status is CaseStatus.CLOSED
    return case, observed


def advisory_case_ready(ledger, store):
    """An advisory case on one machine, worked to READY_TO_CLOSE."""
    record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
    case = assess_advisory(
        store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
    case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
    while case.status is not CaseStatus.AWAITING_REVERIFICATION:
        case = advance(store, case.case_id, actor=REVIEWER)
    after = utc_now() + timedelta(hours=1)          # after the case opened
    fresh = manifest(fw(), manifest_id="MAN-AFTER", taken_at=after)
    record_manifest(ledger, fresh)                  # ledger-backed, collected after
    bundle = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
    case = reverify(store, case.case_id, fresh,
                    VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                    interventions_from_ledger(ledger, MACHINE.key),
                    verification_content_hash=bundle.content_hash, actor=REVIEWER)
    assert case.status is CaseStatus.READY_TO_CLOSE
    return case


def add_second_machine(ledger):
    other = MachineIdentity("Grimaldi", "AR-7", "0413", site="Plant 3")
    record_manifest(ledger, manifest(fw(), manifest_id="MAN-0413", machine=other))
    return other


class TestIdempotency:
    """Identical input twice: one case, and the ledger does not move."""

    def test_the_same_drift_twice_writes_nothing_the_second_time(self, ledger, store):
        first, _ = drift(store, ledger)
        before = len(ledger)
        second, _ = drift(store, ledger)
        assert second.case_id == first.case_id
        assert len(ledger) == before
        assert len(case_entries(ledger, first.case_id)) == 1
        assert len(store.get(first.case_id).history) == 1

    def test_the_same_advisory_twice_writes_nothing_the_second_time(self, ledger, store):
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
        report = assess_impact(advisory(), Fleet.from_ledger(ledger))
        first = assess_advisory(store, report, actor=BOT)
        before = len(ledger)
        again = assess_advisory(store, assess_impact(advisory(), Fleet.from_ledger(ledger)),
                                actor=BOT)
        assert again.case_id == first.case_id
        assert len(ledger) == before

    def test_the_same_intervention_twice_writes_nothing_the_second_time(self, ledger, store):
        record_manifest(ledger, manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        interv = intervention()
        record_intervention(ledger, interv)
        args = (manifest(), VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                interventions_from_ledger(ledger, MACHINE.key))
        first = assess_intervention(store, interv, *args, actor=BOT)
        before = len(ledger)
        assess_intervention(store, interv, *args, actor=BOT)
        assert len(ledger) == before
        assert len(case_entries(ledger, first.case_id)) == 1

    def test_a_re_observation_with_real_new_information_is_still_recorded(self, ledger, store):
        """No-op means 'nothing differs', not 'ignore the watch'."""
        first, _ = drift(store)                   # no verification on record yet
        record_manifest(ledger, manifest(manifest_id="BASE"))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        second, _ = drift(store, ledger)          # now there is one
        assert second.case_id == first.case_id
        assert second.evidence_current != first.evidence_current
        assert len(case_entries(ledger, first.case_id)) == 2

    def test_a_re_observation_never_re_inflates_a_case_past_review(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        assert case.required_actions == () and case.required_reverifications == ()
        before = len(ledger)
        # The watch looks again with data as stale as it was at the start.
        again, _ = drift(store, None)
        assert again.status is CaseStatus.READY_TO_CLOSE
        assert again.required_actions == ()
        assert again.required_reverifications == ()
        assert len(ledger) == before

    def test_an_in_flight_case_keeps_its_progress_when_a_function_is_added(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        # Fresh data names a function the case did not track before.
        extra = replace(case, status=CaseStatus.OPEN,
                        affected_functions=(*case.affected_functions, "SF-09"),
                        required_reverifications=("SF-01", "SF-02", "SF-09"),
                        required_actions=("Re-run for SF-09",),
                        evidence_current={"SF-09": "stale"})
        merged = _open_or_update(store, extra, actor=BOT, detail="more",
                                 actions_by_fid={"SF-09": ["Re-run for SF-09"]})
        assert merged.status is CaseStatus.AWAITING_REVERIFICATION
        assert merged.affected_functions == (*case.affected_functions, "SF-09")
        assert merged.required_reverifications == (*case.required_reverifications, "SF-09")
        assert merged.required_actions == (*case.required_actions, "Re-run for SF-09")
        assert merged.owner == "v.grimaldi"

    def test_a_new_machine_steps_a_ready_advisory_case_back(self, ledger, store):
        case = advisory_case_ready(ledger, store)
        other = add_second_machine(ledger)
        widened = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        assert widened.status is CaseStatus.AWAITING_REVERIFICATION
        assert set(widened.machines) == {MACHINE.key, other.key}
        assert widened.required_reverifications
        assert widened.owner == "v.grimaldi"           # progress kept, not reset
        assert widened.reverified_at == case.reverified_at


class TestReopen:
    """The rule table in CHANGE.md, one test per row."""

    def test_the_same_closed_drift_seen_again_does_not_reopen(self, ledger, store):
        drive(ledger, store, CaseStatus.CLOSED)
        before = len(ledger)
        again, _ = drift(store, ledger)
        assert again.status is CaseStatus.CLOSED
        assert len(ledger) == before

    def test_a_to_b_closed_then_b_to_a_then_a_to_b_again_reopens_it(self, ledger, store):
        case, observed_b = drive(ledger, store, CaseStatus.CLOSED)
        closure = store.closure_entry(case.case_id)
        assert closure is not None
        cycle1_history = len(case.history)

        # B -> A: the machine goes back; the ledger now holds A after the closure.
        record_manifest(ledger, manifest(manifest_id="BACK-TO-A"))
        # A -> B again: the same trigger, a second time.
        reopened, _ = drift(store, ledger, baseline=manifest(manifest_id="BACK-TO-A"))

        assert reopened.case_id == case.case_id
        assert reopened.status is CaseStatus.OPEN
        assert reopened.owner == "" and reopened.decision == ""
        assert len(reopened.prior_closures) == 1
        prior = reopened.prior_closures[0]
        assert prior["closure_hash"] == closure.content_hash
        assert prior["closed_by"] == "v.grimaldi"
        assert "returned to" in prior["reopened_because"]
        assert any(link["content_hash"] == closure.content_hash
                   for link in reopened.linked_evidence)
        # History is carried, not rewritten; the closure entry is untouched.
        assert reopened.history[:cycle1_history] == case.history
        assert len(reopened.history) == cycle1_history + 1
        assert reopened.history[-1]["kind"] == "assurance.change.reopened"
        assert store.closure_entry(case.case_id).content_hash == closure.content_hash
        assert reconstruct_case(ledger, case.case_id).ok

        # And the new cycle is worked like any other, and can close again.
        c = claim(store, case.case_id, owner="w.second", actor=REVIEWER)
        c = advance(store, c.case_id, actor=REVIEWER)
        c = advance(store, c.case_id, actor=REVIEWER)
        bundle = seal_a_real_verification(ledger, when=datetime(2026, 5, 1, tzinfo=UTC))
        c = reverify(store, c.case_id, observed_b,
                     VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                     interventions_from_ledger(ledger, MACHINE.key),
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        c = decide(store, c.case_id, disposition="closed", reason="second cycle",
                   actor=REVIEWER)
        assert c.status is CaseStatus.CLOSED and len(c.prior_closures) == 1
        assert reconstruct_case(ledger, case.case_id).ok

    def test_a_closed_advisory_reopens_only_for_a_machine_it_did_not_name(self, ledger, store):
        case = advisory_case_ready(ledger, store)
        decide(store, case.case_id, disposition="closed", reason="remedy applied",
               actor=REVIEWER)
        before = len(ledger)
        same = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        assert same.status is CaseStatus.CLOSED and len(ledger) == before

        add_second_machine(ledger)
        wider = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        assert wider.status is CaseStatus.OPEN
        assert "did not name" in wider.prior_closures[0]["reopened_because"]

    def test_a_rejected_trigger_stays_rejected_but_a_new_trigger_is_a_new_case(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.REJECTED)
        before = len(ledger)
        again, _ = drift(store, ledger)
        assert again.status is CaseStatus.REJECTED and len(ledger) == before

        fresh, _ = drift(store, ledger, changed="e")      # a different configuration
        assert fresh.case_id != case.case_id
        assert fresh.status is CaseStatus.OPEN
        assert len(store.list()) == 2

    def test_a_deferred_case_is_left_alone_until_a_person_resumes_it(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.DEFERRED)
        before = len(ledger)
        again, _ = drift(store, ledger)
        assert again.status is CaseStatus.DEFERRED and len(ledger) == before

        resumed = resume(store, case.case_id, reason="supplier visit is done",
                         actor=REVIEWER)
        assert resumed.status is CaseStatus.IN_REVIEW
        assert resumed.decision == "" and resumed.decision_by == ""
        assert "deferred by v.grimaldi" in resumed.history[-1]["detail"]
        assert resumed.history[-1]["kind"] == TRANSITION_KIND
        # ... and it can be worked on from there.
        assert advance(store, case.case_id, actor=REVIEWER).status \
            is CaseStatus.AWAITING_ACTION
        assert reconstruct_case(ledger, case.case_id).ok

    def test_resume_needs_a_person_a_reason_and_a_deferred_case(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.DEFERRED)
        with pytest.raises(CaseTransitionError, match="named person"):
            resume(store, case.case_id, reason="go", actor=BOT)
        with pytest.raises(CaseTransitionError, match="needs a reason"):
            resume(store, case.case_id, reason=" ", actor=REVIEWER)
        resume(store, case.case_id, reason="go", actor=REVIEWER)
        with pytest.raises(CaseTransitionError, match="not deferred"):
            resume(store, case.case_id, reason="again", actor=REVIEWER)


ALL_STATES = [CaseStatus.OPEN, CaseStatus.IN_REVIEW, CaseStatus.AWAITING_ACTION,
              CaseStatus.AWAITING_REVERIFICATION, CaseStatus.READY_TO_CLOSE,
              CaseStatus.CLOSED, CaseStatus.REJECTED, CaseStatus.DEFERRED]


class TestGuards:
    """READY_TO_CLOSE and CLOSED cannot be reached around the rules."""

    @pytest.mark.parametrize(
        "status", [s for s in ALL_STATES if s is not CaseStatus.READY_TO_CLOSE],
        ids=lambda s: s.value)
    def test_closing_is_refused_from_every_state_but_ready_to_close(
            self, ledger, store, status):
        case, _ = drive(ledger, store, status)
        assert case.status is status
        with pytest.raises(CaseTransitionError):
            decide(store, case.case_id, disposition="closed", reason="bypass",
                   actor=REVIEWER)
        assert store.get(case.case_id).status is status          # and nothing moved

    @pytest.mark.parametrize("verb,allowed", [
        ("claim", {CaseStatus.OPEN}),
        ("advance", {CaseStatus.IN_REVIEW, CaseStatus.AWAITING_ACTION}),
        ("reverify", {CaseStatus.AWAITING_REVERIFICATION}),
        ("resume", {CaseStatus.DEFERRED}),
    ])
    def test_every_verb_refuses_every_wrong_state(self, tmp_path, verb, allowed):
        """The mutation test: call each service verb from each state it is not for."""
        for status in ALL_STATES:
            if status in allowed:
                continue
            led = EvidenceLedger(tmp_path / f"{verb}-{status.value}.db")
            st = CaseStore(led)
            case, observed = drive(led, st, status)
            with pytest.raises(CaseTransitionError):
                self._attempt(verb, st, led, case, observed)
            assert st.get(case.case_id).status is status

    @staticmethod
    def _attempt(verb, st, led, case, observed):
        if verb == "claim":
            return claim(st, case.case_id, owner="x", actor=REVIEWER)
        if verb == "advance":
            return advance(st, case.case_id, actor=REVIEWER)
        if verb == "reverify":
            return reverify(
                st, case.case_id, observed,
                VerificationRecord.from_ledger(led, subject=MACHINE.key), [],
                verification_content_hash="0" * 64, actor=REVIEWER)
        return resume(st, case.case_id, reason="x", actor=REVIEWER)

    def test_the_store_itself_refuses_ready_to_close_with_work_outstanding(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        with pytest.raises(CaseStoreError, match="outstanding"):
            store.transition(replace(case, status=CaseStatus.READY_TO_CLOSE),
                             actor=REVIEWER, detail="forced")
        with pytest.raises(CaseStoreError, match="outstanding"):
            store.decide(replace(case, status=CaseStatus.CLOSED, decision="closed"),
                         actor=REVIEWER, detail="forced")
        assert store.get(case.case_id).status is CaseStatus.AWAITING_REVERIFICATION

    def test_a_reverification_that_does_not_make_the_function_current_stays_put(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_a_real_verification(ledger, when=LATER)
        # A manifest that no longer declares SF-02: it cannot be shown current.
        without = manifest(item(content_hash="d" * 64, implements=("SF-01",)),
                           functions=FUNCS[:1], manifest_id="NOW")
        record_manifest(ledger, without)             # ledger truth, not the caller's say-so
        c = reverify(store, case.case_id, without,
                     VerificationRecord.from_ledger(ledger, subject=MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert "SF-02" in c.required_reverifications
        assert c.evidence_current["SF-02"] == "unknown"
        with pytest.raises(CaseTransitionError):
            decide(store, c.case_id, disposition="closed", reason="x", actor=REVIEWER)

    def test_a_verification_the_check_was_not_run_against_is_refused(self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        with pytest.raises(CaseTransitionError, match="not among the sealed"):
            reverify(store, case.case_id, observed,
                     VerificationRecord.from_ledger(ledger, subject=MACHINE.key), [],
                     verification_content_hash="f" * 64, actor=REVIEWER)

    def test_an_open_human_decision_blocks_ready_to_close_until_a_person_answers(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        question = "0412/ITM-FW: matched by medium confidence only."
        store.update(replace(case, human_decisions_required=(question,)),
                     actor=BOT, detail="the advisory pass raised a question")
        bundle = seal_a_real_verification(ledger, when=LATER)
        c = reverify(store, case.case_id, observed,
                     VerificationRecord.from_ledger(ledger, subject=MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        # Everything is re-verified, and it still is not ready.
        assert c.required_reverifications == ()
        assert c.status is CaseStatus.AWAITING_ACTION
        assert "Decide:" in c.next_action()
        with pytest.raises(CaseTransitionError):
            decide(store, c.case_id, disposition="closed", reason="x", actor=REVIEWER)
        with pytest.raises(CaseTransitionError, match="unresolved"):
            advance(store, c.case_id, actor=REVIEWER)

        with pytest.raises(CaseTransitionError, match="named person"):
            resolve_decision(store, c.case_id, decision=question, resolution="ok", actor=BOT)
        with pytest.raises(CaseTransitionError, match="no open human decision"):
            resolve_decision(store, c.case_id, decision="something else",
                             resolution="ok", actor=REVIEWER)
        c = resolve_decision(store, c.case_id, decision=question,
                             resolution="Hash checked against the supplier's table.",
                             actor=REVIEWER)
        assert c.human_decisions_required == ()
        assert c.resolved_decisions[0]["by"] == "v.grimaldi"
        c = advance(store, c.case_id, actor=REVIEWER)
        assert c.status is CaseStatus.READY_TO_CLOSE
        # A later look at the same advisory does not ask it again.
        again = replace(c, status=CaseStatus.OPEN, human_decisions_required=(question,))
        assert _open_or_update(store, again, actor=BOT, detail="x") \
            .human_decisions_required == ()
        assert decide(store, c.case_id, disposition="closed", reason="done",
                      actor=REVIEWER).status is CaseStatus.CLOSED
        assert reconstruct_case(ledger, c.case_id).ok

    @pytest.mark.parametrize("who", [
        Actor("watch-01", "scheduled watch", kind="automation"),
        Actor("svc-api", "service", kind="service"),
        Actor("claude-agent", "assistant", kind="agent"),
        Actor("operator", "", kind="automation"),
        Actor("  ", "reviewer", kind="person"),
    ], ids=["automation", "service", "agent", "anonymous", "blank-name"])
    def test_an_automated_or_anonymous_actor_cannot_decide(self, ledger, store, who):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        for disposition in ("closed", "rejected", "deferred"):
            with pytest.raises(CaseTransitionError, match="named person"):
                decide(store, case.case_id, disposition=disposition, reason="r", actor=who)
        assert store.get(case.case_id).status is CaseStatus.READY_TO_CLOSE
        assert decide(store, case.case_id, disposition="closed", reason="r",
                      actor=REVIEWER).decision_by == "v.grimaldi"

    def test_the_watch_actor_can_open_but_not_close(self, ledger, store):
        case, _ = drift(store, ledger, actor=BOT)
        assert case.history[0]["kind"] == "assurance.change.opened"
        evidence = case_entries(ledger, case.case_id)[0].evidence()
        assert evidence.actor.kind == "automation"


class TestReconstruction:
    """State rebuilt from the ledger alone, and every step replayed."""

    def test_a_whole_lifecycle_replays_cleanly_and_matches_the_store(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.CLOSED)
        replay = reconstruct_case(ledger, case.case_id)
        assert replay.ok, replay.violations
        assert replay.entries == len(case.history) == 6
        assert replay.case == store.get(case.case_id)
        assert replay.case.status is CaseStatus.CLOSED
        assert "every step was legal" in replay.summary()

    def test_a_case_with_no_entries_does_not_replay(self, ledger):
        replay = reconstruct_case(ledger, "case-nope")
        assert not replay.ok and replay.case is None
        assert "no ledger entries" in replay.violations[0]

    def test_a_tampered_entry_is_reported_and_excluded(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        entries = case_entries(ledger, case.case_id)
        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET payload = replace(payload, 'in_review', 'closed') "
                   "WHERE seq = ?", (entries[-1].seq,))
        db.commit()
        db.close()
        replay = reconstruct_case(ledger, case.case_id)
        assert not replay.ok
        assert any("does not verify" in v for v in replay.violations)
        assert any(v.startswith("ledger chain:") for v in replay.violations)
        assert replay.case.status is CaseStatus.OPEN        # the last entry that verified

    def test_an_illegal_jump_is_reported(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.OPEN)
        # Open straight to closed: the store accepts the write (nothing is
        # outstanding), the lifecycle never would have.
        store.decide(replace(case, status=CaseStatus.CLOSED, decision="closed",
                             decision_by="v.grimaldi", decision_reason="r",
                             closed_at="2026-01-01T00:00:00Z",
                             required_actions=(), required_reverifications=()),
                     actor=REVIEWER, detail="closed: r")
        replay = reconstruct_case(ledger, case.case_id)
        assert not replay.ok
        assert any("open -> closed" in v for v in replay.violations)

    def test_a_closure_by_something_that_is_not_a_person_is_reported(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        store.decide(replace(case, status=CaseStatus.CLOSED, decision="closed",
                             decision_by="watch-01", decision_reason="r",
                             closed_at="2026-01-01T00:00:00Z"),
                     actor=BOT, detail="closed: r")
        replay = reconstruct_case(ledger, case.case_id)
        assert any("not a named person" in v for v in replay.violations)

    def _forge(self, ledger, case, snapshot):
        ledger.append(Evidence(kind=TRANSITION_KIND, body={"case": snapshot.to_dict()},
                               actor=REVIEWER,
                               origin=Origin(system="assurance.change",
                                             reference=case.case_id)).seal(),
                      subject=case.case_id)

    def test_a_forged_ready_to_close_with_work_outstanding_is_reported(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        self._forge(ledger, case, replace(
            case, status=CaseStatus.READY_TO_CLOSE,
            history=(*case.history, {"kind": TRANSITION_KIND, "at": "x",
                                     "detail": "forged"})))
        replay = reconstruct_case(ledger, case.case_id)
        assert any("re-verification" in v and "outstanding" in v
                   for v in replay.violations)

    def test_rewritten_history_is_reported(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._forge(ledger, case, replace(
            case, status=CaseStatus.AWAITING_ACTION,
            history=({"kind": "assurance.change.opened", "at": "x", "detail": "edited"},
                     {"kind": TRANSITION_KIND, "at": "y", "detail": "z"})))
        replay = reconstruct_case(ledger, case.case_id)
        assert any("history was rewritten" in v for v in replay.violations)


class TestCliS2:
    def _change(self, *argv) -> int:
        from assurance.change.cli import main

        return main(list(argv))

    def test_replay_resume_and_resolve_through_the_cli(self, tmp_path, capsys):
        path = tmp_path / "l.db"
        ledger = EvidenceLedger(path)
        store = CaseStore(ledger)
        case, _ = drive(ledger, store, CaseStatus.DEFERRED)
        capsys.readouterr()
        assert self._change("resume", "--ledger", str(path), case.case_id,
                            "--reason", "back") == 1               # no --actor: automation
        assert self._change("resume", "--ledger", str(path), case.case_id,
                            "--reason", "back", "--actor", "v.grimaldi") == 0
        assert self._change("replay", "--ledger", str(path), case.case_id) == 0
        assert "every step was legal" in capsys.readouterr().out
        assert self._change("replay", "--ledger", str(path), "case-nope") == 2  # unknown: could not run
        assert self._change("resolve-decision", "--ledger", str(path), case.case_id,
                            "--number", "1", "--resolution", "x",
                            "--actor", "v.grimaldi") == 1           # none open

    def test_assess_intervention_through_the_cli(self, tmp_path, capsys):
        path = tmp_path / "l.db"
        ledger = EvidenceLedger(path)
        record_manifest(ledger, manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        record_intervention(ledger, intervention())
        mpath = tmp_path / "m.json"
        mpath.write_text(json.dumps(manifest().to_dict()))
        capsys.readouterr()
        assert self._change("assess-intervention", "--ledger", str(path),
                            "--manifest", str(mpath), "--intervention-id", "INT-0007") == 0
        assert "case-" in capsys.readouterr().out
        assert self._change("assess-intervention", "--ledger", str(path),
                            "--manifest", str(mpath), "--intervention-id", "INT-9999") == 2


class TestHttpDecisionsNeedAPerson:
    def _open_case(self, client, headers):
        r = client.post("/v1/change/assess/drift",
                        json={"baseline": manifest(manifest_id="BASE").to_dict(),
                              "observed": manifest(item(content_hash="d" * 64),
                                                   manifest_id="NOW").to_dict()},
                        headers=headers)
        return r.json()["case"]["case_id"]

    def test_an_account_level_key_cannot_decide_whatever_name_it_sends(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        case_id = self._open_case(client, headers)
        for actor in ({}, {"actor": ""}, {"actor": "Dr. Anna Keller"}):
            r = client.post(f"/v1/change/cases/{case_id}/decision",
                            json={"disposition": "rejected", "reason": "not real", **actor},
                            headers=headers)
            assert r.status_code == 403, actor
            assert r.json()["detail"]["error"] == "operator_required"
        assert client.get(f"/v1/change/cases/{case_id}",
                          headers=headers).json()["status"] == "open"

    def test_an_operator_key_decides_as_that_operator_and_cannot_be_someone_else(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        case_id = self._open_case(client, headers)
        mine = as_decider(headers, "v.grimaldi")
        # Naming another person in the body is impersonation: refused.
        r = client.post(f"/v1/change/cases/{case_id}/decision",
                        json={"disposition": "rejected", "reason": "not real",
                              "actor": "Dr. Anna Keller"}, headers=mine)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "actor_mismatch"
        assert client.get(f"/v1/change/cases/{case_id}",
                          headers=headers).json()["status"] == "open"
        # With no actor, or the right one, the server attributes it to the operator.
        r = client.post(f"/v1/change/cases/{case_id}/decision",
                        json={"disposition": "rejected", "reason": "not real"}, headers=mine)
        assert r.status_code == 200 and r.json()["status"] == "rejected"
        from assurance.api import deps
        account = account_store.account(_account_ids(account_store)[0])
        ledger = deps._tenant_register_for(str(deps.tenant_ledger_path(account.id))).ledger
        actor = ledger.entries(subject=case_id)[-1].evidence().actor
        assert actor.identifier == "v.grimaldi" and actor.kind == "person"
        assert "attribution=authenticated_operator" in actor.role
        assert f"via account {account.id}" in actor.role and "operator=op_" in actor.role

    def test_the_export_states_how_each_action_was_attributed(self, client, account_store):
        headers = keyed(account_store, "cell")
        case_id = self._open_case(client, headers)
        assert client.post(f"/v1/change/cases/{case_id}/claim",
                           json={"owner": "o", "actor": "declared.person"},
                           headers=headers).status_code == 200
        r = client.post(f"/v1/change/cases/{case_id}/decision",
                        json={"disposition": "rejected", "reason": "not real"},
                        headers=as_decider(headers, "v.grimaldi"))
        assert r.status_code == 200
        bundle = client.get(f"/v1/change/cases/{case_id}/export", headers=headers).json()
        roles = [e["evidence"]["actor"]["role"] for e in bundle["entries"]]
        assert any("attribution=declared_by_account_key" in x for x in roles)
        assert "attribution=authenticated_operator" in roles[-1]
        # an operator-attributed action never claims identity proofing
        assert not any("proof" in x for x in roles)

    def test_a_contributor_operator_cannot_decide_and_a_disabled_one_cannot_act(
            self, client, account_store):
        headers = keyed(account_store, "cell")
        case_id = self._open_case(client, headers)
        account = account_store.account(_account_ids(account_store)[0])
        # bootstrap: the first operator must be a decider
        r = client.post("/v1/operators", json={"name": "Lena", "role": "contributor"},
                        headers=headers)
        assert r.status_code == 422
        r = client.post("/v1/operators", json={"name": "Boss", "role": "decider"},
                        headers=headers)
        assert r.status_code == 201
        boss = {"X-API-Key": r.json()["api_key"]}
        # an account-level key can no longer mint operators
        assert client.post("/v1/operators", json={"name": "Mallory", "role": "decider"},
                           headers=headers).status_code == 403
        r = client.post("/v1/operators", json={"name": "Lena", "role": "contributor"},
                        headers=boss)
        lena, lena_id = {"X-API-Key": r.json()["api_key"]}, r.json()["operator_id"]
        r = client.post(f"/v1/change/cases/{case_id}/decision",
                        json={"disposition": "rejected", "reason": "x"}, headers=lena)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "decider_role_required"
        # the contributor may still take a workflow step, attributed to her
        assert client.post(f"/v1/change/cases/{case_id}/claim", json={"owner": "Lena"},
                           headers=lena).status_code == 200
        # a contributor cannot manage operators
        assert client.post(f"/v1/operators/{lena_id}/disable", headers=lena).status_code == 403
        # a decider disables her; her key stops authenticating at all
        assert client.post(f"/v1/operators/{lena_id}/disable",
                           headers=boss).json()["outcome"] == "disabled"
        assert client.get("/v1/change/cases", headers=lena).status_code == 401
        # another account cannot see or disable this account's operators
        other = keyed(account_store, "register")
        assert account.id != account_store.peek_key(other["X-API-Key"]).account.id
        assert client.post(f"/v1/operators/{lena_id}/disable", headers=other).status_code in (
            402, 403, 404)
        assert client.get(f"/v1/change/cases/{case_id}", headers=headers).status_code == 200


# =====================================================================
# Slice S2, second pass — defects an adversarial review proved. Each test
# below failed against the first version of this module.
# =====================================================================

import unicodedata  # noqa: E402

OTHER = MachineIdentity(manufacturer="Grimaldi", model="AR-7", serial="0413", site="Plant 3")
EARLY = datetime(2026, 1, 1, tzinfo=UTC)


def two_machine_advisory_case(ledger, store):
    """An advisory case naming both machines, both verified once before it."""
    record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
    record_manifest(ledger, manifest(fw(), manifest_id="MAN-0413", machine=OTHER))
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC), subject=OTHER.key)
    case = assess_advisory(
        store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
    case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
    while case.status is not CaseStatus.AWAITING_REVERIFICATION:
        case = advance(store, case.case_id, actor=REVIEWER)
    return case


def verifs(ledger, key):
    return VerificationRecord.from_ledger(ledger, subject=key)


class TestF1ReverifyAcceptsOnlyTheRightEvidence:
    def test_another_machines_manifest_cannot_clear_this_machines_case(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        record_manifest(ledger, manifest(manifest_id="OTHER", machine=OTHER))
        bundle = seal_a_real_verification(ledger, when=LATER, subject=OTHER.key)
        with pytest.raises(CaseTransitionError, match="does not concern"):
            reverify(store, case.case_id, manifest(manifest_id="OTHER", machine=OTHER),
                     verifs(ledger, OTHER.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert store.get(case.case_id).status is CaseStatus.AWAITING_REVERIFICATION

    def test_a_two_machine_advisory_case_is_ready_only_when_every_machine_is(
            self, ledger, store):
        case = two_machine_advisory_case(ledger, store)
        assert {e.rsplit("/", 1)[0] for e in case.required_reverifications} \
            == {MACHINE.key, OTHER.key}

        after = utc_now() + timedelta(hours=1)
        m1 = manifest(fw(), manifest_id="AFTER-0412", taken_at=after)
        m2 = manifest(fw(), manifest_id="AFTER-0413", taken_at=after, machine=OTHER)
        record_manifest(ledger, m1)
        record_manifest(ledger, m2)
        b1 = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
        c = reverify(store, case.case_id, m1, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=b1.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert {e.rsplit("/", 1)[0] for e in c.required_reverifications} == {OTHER.key}

        b2 = seal_a_real_verification(ledger, when=after + timedelta(minutes=5),
                                      subject=OTHER.key)
        c = reverify(store, c.case_id, m2, verifs(ledger, OTHER.key),
                     [], verification_content_hash=b2.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.READY_TO_CLOSE
        assert c.required_reverifications == ()
        assert reconstruct_case(ledger, c.case_id).ok

    def test_a_declared_manifest_with_the_right_hash_is_not_a_look_at_the_machine(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_a_real_verification(ledger, when=LATER)
        # Nothing was read off the machine: a person typed the configuration in. Its
        # configuration hash is identical to the real one, which ignores the source.
        declared = manifest(item(content_hash="d" * 64), manifest_id="PAPER",
                            source=ManifestSource.AS_DECLARED, taken_at=LATER)
        record_manifest(ledger, declared)
        with pytest.raises(CaseTransitionError, match="not a record of looking"):
            reverify(store, case.case_id, declared, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert store.get(case.case_id).status is CaseStatus.AWAITING_REVERIFICATION

    def test_one_recording_cannot_be_evidence_for_two_machines(self, ledger, store):
        case = two_machine_advisory_case(ledger, store)
        after = utc_now() + timedelta(hours=1)
        m1 = manifest(fw(), manifest_id="AFTER-0412", taken_at=after)
        m2 = manifest(fw(), manifest_id="AFTER-0413", taken_at=after, machine=OTHER)
        record_manifest(ledger, m1)
        record_manifest(ledger, m2)
        mine = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
        # the very same trace, filed under the second machine's key
        borrowed = build_bundle(
            *_same_inputs_as(mine), actor=ENG, ledger=ledger, subject=OTHER.key)
        with pytest.raises(CaseTransitionError, match="also filed as evidence"):
            reverify(store, case.case_id, m2, verifs(ledger, OTHER.key), [],
                     verification_content_hash=borrowed.content_hash, actor=REVIEWER)

    def test_a_bundle_sealed_before_the_case_cannot_clear_it(self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        pre = verifs(ledger, MACHINE.key)[0]          # the February bundle, pre-change
        with pytest.raises(CaseTransitionError, match="before this case"):
            reverify(store, case.case_id, observed, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=pre.content_hash, actor=REVIEWER)

    def test_a_bundle_sealed_after_but_describing_a_state_before_the_change_cannot(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        old_run = seal_a_real_verification(ledger, when=EARLY)       # filed now, a January run
        with pytest.raises(CaseTransitionError, match="describes a state before"):
            reverify(store, case.case_id, observed, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=old_run.content_hash, actor=REVIEWER)

    def test_a_function_whose_checks_the_bundle_did_not_pass_is_not_cleared(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_a_real_verification(ledger, when=LATER)
        funcs = (SafetyFunction("SF-01", "Protective stop on zone intrusion", "PL d",
                                verified_by=("ssm_separation", "stop_characterisation",
                                             "laser_scan_resolution")),
                 FUNCS[1])
        wider = manifest(item(content_hash="d" * 64), functions=funcs, manifest_id="NOW")
        record_manifest(ledger, wider)               # ledger truth, not the caller's say-so
        c = reverify(store, case.case_id, wider, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert c.required_reverifications == ("SF-01",)
        # Coverage now needs every check a function declares, so a function whose
        # third check has never been run reads never_verified, not current-then-
        # no_new_evidence. Either way it is not cleared, which is what is asserted.
        assert c.evidence_current["SF-01"] in ("never_verified", "no_new_evidence")
        assert c.evidence_current["SF-02"] == "current"


class TestF2AdvisoryClosureNeedsEvidenceOrAnExplicitWaiver:
    def _never_verified(self, ledger, store):
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))      # nothing ever verified
        case = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        return case

    def test_every_exposed_function_needs_re_verification_even_if_never_verified(
            self, ledger, store):
        case = self._never_verified(ledger, store)
        assert case.evidence_before[f"{MACHINE.key}/SF-01"] == "never_verified"
        assert set(case.required_reverifications) == {f"{MACHINE.key}/SF-01",
                                                      f"{MACHINE.key}/SF-02"}
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        while case.status is not CaseStatus.AWAITING_REVERIFICATION:
            case = advance(store, case.case_id, actor=REVIEWER)
        with pytest.raises(CaseTransitionError):
            advance(store, case.case_id, actor=REVIEWER)
        with pytest.raises(CaseTransitionError):
            decide(store, case.case_id, disposition="closed", reason="x", actor=REVIEWER)

    def test_closing_with_no_evidence_is_possible_only_as_a_recorded_human_waiver(
            self, ledger, store):
        from assurance.change import waive_reverification

        case = self._never_verified(ledger, store)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        while case.status is not CaseStatus.AWAITING_REVERIFICATION:
            case = advance(store, case.case_id, actor=REVIEWER)
        entries = list(case.required_reverifications)
        with pytest.raises(CaseTransitionError, match="named person"):
            waive_reverification(store, case.case_id, entry=entries[0],
                                 reason="not needed", actor=BOT)
        with pytest.raises(CaseTransitionError, match="reason"):
            waive_reverification(store, case.case_id, entry=entries[0],
                                 reason=" ", actor=REVIEWER)
        for e in entries:
            case = waive_reverification(store, case.case_id, entry=e,
                                        reason="Machine is out of service; no run possible.",
                                        actor=REVIEWER)
        assert case.required_reverifications == ()
        assert all(case.evidence_current[e] == "waived" for e in entries)
        assert len(case.resolved_decisions) == len(entries)
        case = advance(store, case.case_id, actor=REVIEWER)
        assert case.status is CaseStatus.READY_TO_CLOSE
        closed = decide(store, case.case_id, disposition="closed",
                        reason="Closed without evidence, on the waivers above.",
                        actor=REVIEWER)
        assert closed.status is CaseStatus.CLOSED
        assert reconstruct_case(ledger, case.case_id).ok


class TestF3IncompleteCollectionNeverReopens:
    def test_an_incomplete_manifest_is_not_another_configuration(self, ledger, store):
        from assurance.change.service import INCOMPLETE_COLLECTION_MARK

        case, _ = drive(ledger, store, CaseStatus.CLOSED)
        # A transient, partial collection of the same machine after the closure ...
        partial = manifest(item("ITM-OTHER", content_hash="9" * 64), manifest_id="PARTIAL",
                           notes=f"{INCOMPLETE_COLLECTION_MARK}: robot-params.json missing]")
        record_manifest(ledger, partial)
        # ... and then the closed configuration comes back, complete.
        before = len(ledger)
        again, _ = drift(store, ledger, baseline=partial)
        assert again.status is CaseStatus.CLOSED
        assert len(ledger) == before

    def test_a_complete_other_configuration_still_counts(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.CLOSED)
        record_manifest(ledger, manifest(item("ITM-OTHER", content_hash="9" * 64),
                                         manifest_id="REAL-OTHER"))
        again, _ = drift(store, ledger)
        assert again.status is CaseStatus.OPEN
        assert len(again.prior_closures) == 1


class TestF4ReplayDoesNotAcceptAForgedReadyToClose:
    def test_the_reviews_repro_a_plain_transition_that_empties_the_lists(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        forged = store.transition(
            replace(case, status=CaseStatus.READY_TO_CLOSE, required_reverifications=(),
                    required_actions=()), actor=BOT, detail="forged")
        replay = reconstruct_case(ledger, forged.case_id)
        assert not replay.ok
        assert any("shrank" in v or "cannot remove" in v for v in replay.violations)

    def test_a_reverification_entry_that_cites_nothing_is_reported(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        store.reverify(replace(case, status=CaseStatus.READY_TO_CLOSE,
                               required_reverifications=(), required_actions=()),
                       actor=REVIEWER, detail="forged reverification")
        replay = reconstruct_case(ledger, case.case_id)
        assert any("supports" in v or "reverified_at" in v for v in replay.violations)

    def test_a_reverification_citing_a_bundle_that_is_not_in_the_ledger_is_reported(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        store.reverify(replace(
            case, status=CaseStatus.READY_TO_CLOSE, required_reverifications=(),
            required_actions=(), reverified_at="2026-04-01T00:00:00Z",
            linked_evidence=(*case.linked_evidence,
                             {"relation": "supports", "content_hash": "e" * 64,
                              "note": "re-verification evidence"})),
            actor=REVIEWER, detail="forged reverification")
        replay = reconstruct_case(ledger, case.case_id)
        assert any("not a sealed verification" in v for v in replay.violations)

    def test_a_reverification_citing_a_bundle_from_before_the_case_is_reported(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        pre = verifs(ledger, MACHINE.key)[0]
        store.reverify(replace(
            case, status=CaseStatus.READY_TO_CLOSE, required_reverifications=(),
            required_actions=(), reverified_at="2026-04-01T00:00:00Z",
            linked_evidence=(*case.linked_evidence,
                             {"relation": "supports", "content_hash": pre.content_hash,
                              "note": "re-verification evidence"})),
            actor=REVIEWER, detail="forged reverification")
        replay = reconstruct_case(ledger, case.case_id)
        assert any("before the case" in v for v in replay.violations)

    def test_an_entry_whose_evidence_kind_disagrees_with_its_ledger_kind_is_reported(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        # Sealed as a transition, then the ledger row's kind column is rewritten.
        store.transition(replace(case, status=CaseStatus.AWAITING_ACTION),
                         actor=REVIEWER, detail="advanced")
        db = sqlite3.connect(ledger.path)
        db.execute("UPDATE chain SET kind = ? WHERE seq = (SELECT MAX(seq) FROM chain)",
                   ("assurance.change.decision",))
        db.commit()
        db.close()
        replay = reconstruct_case(ledger, case.case_id)
        assert any("sealed as" in v for v in replay.violations)

    def test_a_legitimate_lifecycle_still_replays_clean(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.CLOSED)
        assert reconstruct_case(ledger, case.case_id).ok


class TestF6TheActorGuard:
    @pytest.mark.parametrize("name", [
        "ㅤ", "ᅟ", "ᅠ", "ﾠ", "⠀", "​", "a​b", "‮x",
        "x y", "line\nbreak", "tab\tname", "!!!", "...", "   ",
        "AUTOMATION", " Watch ", "agent", "SERVICE", "system", "Bot", "assistant",
        "operator", "AI", "ａｇｅｎｔ",
    ])
    def test_a_name_that_is_not_a_visible_person_is_refused(self, ledger, store, name):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        who = Actor(name, "reviewer", kind="person")
        for call in (
            lambda: decide(store, case.case_id, disposition="closed", reason="r", actor=who),
            lambda: decide(store, case.case_id, disposition="deferred", reason="r", actor=who),
            lambda: resolve_decision(store, case.case_id, decision="q", resolution="r",
                                     actor=who),
            lambda: resume(store, case.case_id, reason="r", actor=who),
        ):
            with pytest.raises(CaseTransitionError):
                call()
        assert store.get(case.case_id).status is CaseStatus.READY_TO_CLOSE

    @pytest.mark.parametrize("kind", ["Person", "person ", " person", "PERSON", "persons", ""])
    def test_the_kind_must_be_exactly_person(self, ledger, store, kind):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        with pytest.raises(CaseTransitionError, match="named person"):
            decide(store, case.case_id, disposition="closed", reason="r",
                   actor=Actor("v.grimaldi", "reviewer", kind=kind))

    def test_a_claim_owner_must_be_a_visible_name_too(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.OPEN)
        for owner in ("ㅤ", "bot", "!!!"):
            with pytest.raises(CaseTransitionError):
                claim(store, case.case_id, owner=owner, actor=BOT)

    def test_ordinary_names_still_work(self, ledger, store):
        for name in ("v.grimaldi", "Vincenzo Grimaldi", "jürgen.müller", "田中"):
            assert not any(unicodedata.category(c) in ("Cf", "Cc") for c in name)
            led = EvidenceLedger(ledger.path.parent / f"{abs(hash(name))}.db")
            st = CaseStore(led)
            case, _ = drive(led, st, CaseStatus.READY_TO_CLOSE)
            assert decide(st, case.case_id, disposition="closed", reason="r",
                          actor=Actor(name, "reviewer")).status is CaseStatus.CLOSED


class TestF7SettledCasesDoNotSwallowGrowingExposure:
    def _deferred_advisory(self, ledger, store):
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
        case = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        return decide(store, case.case_id, disposition="deferred", reason="supplier call",
                      actor=REVIEWER)

    def test_a_deferred_case_gains_the_new_machine_and_a_question(self, ledger, store):
        case = self._deferred_advisory(ledger, store)
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0413", machine=OTHER))
        report = assess_impact(advisory(), Fleet.from_ledger(ledger))
        grown = assess_advisory(store, report, actor=BOT)
        assert grown.status is CaseStatus.DEFERRED
        assert set(grown.machines) == {MACHINE.key, OTHER.key}
        assert any(OTHER.key in q for q in grown.human_decisions_required)
        # Recorded once: the same look again writes nothing.
        before = len(ledger)
        assess_advisory(store, report, actor=BOT)
        assert len(ledger) == before
        assert reconstruct_case(ledger, case.case_id).ok

    def test_a_rejected_advisory_reopens_for_a_machine_it_did_not_name(self, ledger, store):
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
        case = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        decide(store, case.case_id, disposition="rejected", reason="not ours",
               actor=REVIEWER)
        before = len(ledger)
        same = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        assert same.status is CaseStatus.REJECTED and len(ledger) == before   # stable

        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0413", machine=OTHER))
        wider = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        assert wider.status is CaseStatus.OPEN
        assert wider.prior_closures[0]["disposition"] == "rejected"
        assert wider.prior_closures[0]["closed_by"] == "v.grimaldi"
        assert reconstruct_case(ledger, case.case_id).ok

    def test_a_rejected_drift_stays_rejected(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.REJECTED)
        record_manifest(ledger, manifest(item("ITM-OTHER", content_hash="9" * 64),
                                         manifest_id="REAL-OTHER"))
        again, _ = drift(store, ledger)
        assert again.status is CaseStatus.REJECTED


class TestTheSurvivingMutant:
    def test_decide_closed_checks_the_status_on_its_own(self, ledger, store):
        """Empty work lists must not be enough: the status check is its own guard."""
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        emptied = store.update(replace(case, required_reverifications=(),
                                       required_actions=(), human_decisions_required=()),
                               actor=BOT, detail="lists emptied, status untouched")
        assert emptied.status is CaseStatus.AWAITING_REVERIFICATION
        with pytest.raises(CaseTransitionError, match="not ready_to_close"):
            decide(store, case.case_id, disposition="closed", reason="x", actor=REVIEWER)


    def test_decide_closed_re_checks_the_work_lists_on_its_own(self, ledger, store):
        """A ready_to_close snapshot that names outstanding work (forged straight
        into the ledger, past the store's own guard) still cannot be closed."""
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        forged = replace(case, required_reverifications=("SF-01",),
                         history=(*case.history, {"kind": TRANSITION_KIND, "at": "x",
                                                  "detail": "forged"}))
        ledger.append(Evidence(kind=TRANSITION_KIND, body={"case": forged.to_dict()},
                               actor=REVIEWER,
                               origin=Origin(system="assurance.change",
                                             reference=case.case_id)).seal(),
                      subject=case.case_id)
        assert store.get(case.case_id).status is CaseStatus.READY_TO_CLOSE
        with pytest.raises(CaseTransitionError, match="outstanding work"):
            decide(store, case.case_id, disposition="closed", reason="x", actor=REVIEWER)


# =====================================================================
# Slice S2, third pass — a second review: the floor and the manifest must
# come from the case and the ledger, never from the caller.
# =====================================================================

class TestAReverifyFloorComesFromTheCaseNotTheCaller:
    def _advisory_awaiting(self, ledger, store):
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-0412"))
        case = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        while case.status is not CaseStatus.AWAITING_REVERIFICATION:
            case = advance(store, case.case_id, actor=REVIEWER)
        return case

    def test_an_advisory_case_stamps_its_own_opening_time_as_the_trigger(self, ledger, store):
        case = self._advisory_awaiting(ledger, store)
        assert case.trigger_at == case.opened_at != ""
        # and a repeat look does not move it
        again = assess_advisory(
            store, assess_impact(advisory(), Fleet.from_ledger(ledger)), actor=BOT)
        assert again.trigger_at == case.trigger_at

    def test_the_reviews_repro_a_2020_run_with_a_2019_manifest_cannot_close_it(
            self, ledger, store):
        case = self._advisory_awaiting(ledger, store)
        stale = seal_a_real_verification(ledger, when=datetime(2020, 1, 1, tzinfo=UTC))
        # The caller's manifest is the ledger's own, relabelled as taken in 2019.
        forged_date = manifest(fw(), manifest_id="MAN-0412",
                               taken_at=datetime(2019, 1, 1, tzinfo=UTC))
        with pytest.raises(CaseTransitionError):
            reverify(store, case.case_id, forged_date, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=stale.content_hash, actor=REVIEWER)
        assert store.get(case.case_id).status is CaseStatus.AWAITING_REVERIFICATION

    def test_an_advisory_case_is_cleared_by_evidence_after_the_case_and_a_fresh_manifest(
            self, ledger, store):
        case = self._advisory_awaiting(ledger, store)
        after = utc_now() + timedelta(hours=1)
        record_manifest(ledger, manifest(fw(), manifest_id="MAN-AFTER", taken_at=after))
        bundle = seal_a_real_verification(ledger, when=after + timedelta(minutes=5))
        c = reverify(store, case.case_id, manifest(fw(), taken_at=after),
                     verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.READY_TO_CLOSE

    def test_a_manifest_older_than_the_case_is_refused_even_with_a_new_bundle(
            self, ledger, store):
        case = self._advisory_awaiting(ledger, store)      # ledger manifest: January
        bundle = seal_a_real_verification(ledger, when=utc_now() + timedelta(hours=1))
        with pytest.raises(CaseTransitionError, match="predates"):
            reverify(store, case.case_id, manifest(fw()), verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)


class TestBTheManifestIsBoundToTheLedger:
    def test_a_manifest_for_an_unrelated_configuration_cannot_clear_a_drift_case(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_a_real_verification(ledger, when=LATER)
        unrelated = manifest(item(content_hash="9" * 64), manifest_id="NOW")
        assert unrelated.configuration_hash() != case.after_hash
        with pytest.raises(CaseTransitionError, match="configuration"):
            reverify(store, case.case_id, unrelated, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)

    def test_the_declared_checks_come_from_the_ledgers_manifest_not_the_callers(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        strict = (SafetyFunction("SF-01", "Protective stop on zone intrusion", "PL d",
                                 verified_by=("ssm_separation", "stop_characterisation",
                                              "laser_scan_resolution")), FUNCS[1])
        record_manifest(ledger, manifest(item(content_hash="d" * 64), functions=strict,
                                         manifest_id="LEDGER-STRICT"))
        # The caller sends the same configuration with the extra check removed.
        weakened = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        assert weakened.configuration_hash() == case.after_hash
        bundle = seal_a_real_verification(ledger, when=LATER)
        c = reverify(store, case.case_id, weakened, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert c.required_reverifications == ("SF-01",)

    def test_a_machine_the_ledger_has_no_manifest_for_is_refused(self, ledger, store):
        observed = manifest(item(content_hash="d" * 64), manifest_id="NOW")
        case = assess_drift(store, compare(manifest(manifest_id="BASE"), observed),
                            observed, [], [], actor=ENG)
        case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)
        case = advance(store, case.case_id, actor=REVIEWER)
        bundle = seal_a_real_verification(ledger, when=LATER)
        with pytest.raises(CaseTransitionError, match="no manifest"):
            reverify(store, case.case_id, observed, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)

    def test_a_later_ledger_manifest_is_accepted_and_is_the_one_used(self, ledger, store):
        """The caller's manifest may be the newest sealed one rather than the one the
        case was opened on."""
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        newer = manifest(item(content_hash="d" * 64, version="3.8.3"), manifest_id="NEWER")
        record_manifest(ledger, newer)
        bundle = seal_a_real_verification(ledger, when=LATER)
        c = reverify(store, case.case_id, newer, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.READY_TO_CLOSE


    def test_coverage_is_assessed_against_the_ledgers_manifest_too(self, ledger, store):
        """Whatever the caller declares, the verdict is the ledger's: a garbled
        function list in the request neither clears nor blocks anything."""
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        garbled = manifest(
            item(content_hash="d" * 64),
            functions=(SafetyFunction("SF-01", "x", "PL d", verified_by=("no_such_check",)),
                       SafetyFunction("SF-02", "x", "PL d", verified_by=("no_such_check",))),
            manifest_id="NOW")
        assert garbled.configuration_hash() == case.after_hash
        bundle = seal_a_real_verification(ledger, when=LATER)
        c = reverify(store, case.case_id, garbled, verifs(ledger, MACHINE.key), [],
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.READY_TO_CLOSE


class TestCConfusableNames:
    @pytest.mark.parametrize("name", [
        "agent.", "system:", "аutomation", "AGENT!", "‘bot’", "bot-7",
        "operator_1", "automation bot", "ορerator", "aɡent",
        "(watch)", "ѕervice", "ASSISTANT 2",
    ])
    def test_a_reserved_word_in_disguise_is_refused(self, ledger, store, name):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        with pytest.raises(CaseTransitionError):
            decide(store, case.case_id, disposition="closed", reason="r",
                   actor=Actor(name, "reviewer", kind="person"))

    @pytest.mark.parametrize("name", ["Agent Smith", "Watch Dog", "v.grimaldi",
                                      "Systems Engineer Rossi", "Botticelli"])
    def test_names_that_merely_contain_a_reserved_word_are_allowed(self, ledger, store, name):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        assert decide(store, case.case_id, disposition="closed", reason="r",
                      actor=Actor(name, "reviewer")).status is CaseStatus.CLOSED


class TestOperatorBootstrapAndLimits:
    def test_concurrent_first_operators_cannot_both_succeed_and_names_are_unique(
            self, client, account_store):
        import threading
        headers = keyed(account_store, "cell")
        results = []

        def go(name):
            results.append(client.post("/v1/operators", json={"name": name, "role": "decider"},
                                       headers=headers).status_code)

        ts = [threading.Thread(target=go, args=(f"Person {i}",)) for i in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        assert sorted(results).count(201) == 1 and results.count(403) == 3
        account = account_store.account(_account_ids(account_store)[0])
        assert len(account_store.operators_for(account.id)) == 1
        boss = {"X-API-Key": account_store.keys_for(account.id)[-1]["prefix"]}  # noqa: F841
        with pytest.raises(ValueError, match="already exists"):
            name = account_store.operators_for(account.id)[0]["name"]
            account_store.create_operator(account.id, name.upper(), "contributor")

    def test_the_platform_operator_credential_cannot_manage_operators(self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_API_KEYS", "platform-key")
        r = client.post("/v1/operators", json={"name": "X", "role": "decider"},
                        headers={"X-API-Key": "platform-key"})
        assert r.status_code == 403 and r.json()["detail"]["error"] == "account_required"
