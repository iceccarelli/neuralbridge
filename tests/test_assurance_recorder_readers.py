"""MEDIUM-3 of the recorder-attestation review: readers fail closed.

A reader of the evidence ledger that is handed no recorder trust list believes the sealing
verifier's own word about a ``validated`` tier. That is right for an offline CLI reading its
owner's own ledger and wrong for a hosted route: a deleted, mistyped or corrupted trust file
used to make every route read *more* generously than a valid one that revokes a key.

Now the hosted service distinguishes "``ASSURANCE_RECORDER_TRUST`` is unset" from "set but
unreadable" (both trust nobody, the second is surfaced once, never with the path) and every
API reader is handed the server's list, empty if need be, never ``None``.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

import pytest

from assurance.machine.recorder_attestation import RecorderTrust

from .support_recorder import RECORDER, Recorder, server_trust, with_attestation
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_recorder_attestation import envelope, make_trace
from .test_assurance_recorder_review_fixes import UNKNOWN_ALGORITHM_TRUST

client = _client
store = _store


class TestTheServersTrustState:
    @pytest.fixture(autouse=True)
    def _fresh(self):
        from assurance.api import recorder_trust as rt

        rt._REPORTED.clear()
        yield
        rt._REPORTED.clear()

    def test_unset_is_not_the_same_as_broken(self, monkeypatch):
        from assurance.api.recorder_trust import server_recorder_trust, server_recorder_trust_state

        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)
        assert server_recorder_trust() is None
        assert server_recorder_trust_state().status == "unset"

    @pytest.mark.parametrize("how", ["missing", "corrupt", "unknown-algorithm", "wrong-format"])
    def test_set_but_unusable_is_an_empty_trust_and_says_unreadable(
            self, monkeypatch, tmp_path, how, caplog):
        from assurance.api.recorder_trust import server_recorder_trust, server_recorder_trust_state

        p = tmp_path / "private-dir-name" / "trust.json"
        p.parent.mkdir()
        if how == "corrupt":
            p.write_text("{garbage")
        elif how == "unknown-algorithm":
            p.write_text(json.dumps(UNKNOWN_ALGORITHM_TRUST))
        elif how == "wrong-format":
            p.write_text(json.dumps({"format": "nope", "recorders": []}))
        monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(p))
        with caplog.at_level(logging.WARNING):
            trust = server_recorder_trust()
            state = server_recorder_trust_state()
        assert isinstance(trust, RecorderTrust) and len(trust) == 0
        assert state.status == "unreadable" and state.trust is not None
        # surfaced once, and never with the path
        assert len([r for r in caplog.records
                    if "ASSURANCE_RECORDER_TRUST" in r.getMessage()]) == 1
        assert "private-dir-name" not in caplog.text and str(tmp_path) not in caplog.text
        assert "private-dir-name" not in state.note and str(tmp_path) not in state.note

    def test_a_good_file_is_configured(self, monkeypatch, tmp_path):
        from assurance.api.recorder_trust import server_recorder_trust_state

        server_trust(monkeypatch, tmp_path)
        s = server_recorder_trust_state()
        assert s.status == "configured" and s.trust is not None and len(s.trust) == 1

    def test_the_reader_trust_is_never_none(self, monkeypatch, tmp_path):
        from assurance.api.recorder_trust import reader_recorder_trust

        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)
        t = reader_recorder_trust()
        assert isinstance(t, RecorderTrust) and len(t) == 0
        server_trust(monkeypatch, tmp_path)
        assert len(reader_recorder_trust()) == 1

    def test_a_broken_file_is_surfaced_in_the_verify_response_without_the_path(
            self, client, store, monkeypatch, tmp_path):
        p = tmp_path / "secretdir" / "t.json"
        p.parent.mkdir()
        p.write_text("{nope")
        monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(p))
        env, tr = envelope(), make_trace()
        body = with_attestation({"envelope": env.to_dict(), "trace": tr.hashable_payload(),
                                 "actor": "v.g"}, env, tr)
        r = client.post("/v1/machine/verify", json=body, headers=keyed(store, "cell"))
        d = r.json()
        assert r.status_code == 200 and d["tier"] == "community"
        assert d["recorder_trust"]["status"] == "unreadable"
        assert "secretdir" not in r.text and str(tmp_path) not in r.text

    def test_the_verify_response_says_unset_and_configured_too(
            self, client, store, monkeypatch, tmp_path):
        env, tr = envelope(), make_trace()
        body = {"envelope": env.to_dict(), "trace": tr.hashable_payload(), "actor": "v.g"}
        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)
        h = keyed(store, "cell")
        assert client.post("/v1/machine/verify", json=body, headers=h).json()[
            "recorder_trust"]["status"] == "unset"
        server_trust(monkeypatch, tmp_path)
        assert client.post("/v1/machine/verify", json=body, headers=h).json()[
            "recorder_trust"]["status"] == "configured"


def _ar7():
    """The AR-7 envelope and a field run, as ``seal_a_real_verification`` builds them."""
    from assurance.machine.envelope import (
        FigureBasis,
        SafetyEnvelope,
        SensingUncertainty,
        StopPerformance,
        Workspace,
    )
    from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace

    env = SafetyEnvelope(
        envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-11", "2026-01-18")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "CAL-003")),
        intrusion_distance_mm=850.0)
    run = Trace(trace_id="RUN-0209", provenance=Provenance.FIELD, source_system="AR-7 fw",
                started_at=datetime(2026, 2, 9, tzinfo=UTC), sample_rate_hz=50.0,
                samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=400.0,
                                     mode=OperatingMode.SSM, separation=2200.0)
                              for i in range(10)))
    return env, run


@pytest.fixture
def seeded(client, store, monkeypatch, tmp_path):
    """A cell account whose ledger holds a manifest and an ATTESTED verification of unit 0412,
    sealed through the API under the server's trust; returns (headers, trust file path)."""
    from .test_assurance_machinery import MACHINE
    from .test_assurance_machinery_tiers import covered_manifest

    path = server_trust(monkeypatch, tmp_path)
    h = keyed(store, "cell")
    assert client.post("/v1/machinery/manifest", json={"manifest": covered_manifest().to_dict()},
                       headers=h).status_code == 200
    env, run = _ar7()
    body = with_attestation(
        {"envelope": env.to_dict(), "trace": run.hashable_payload(), "actor": "a.integrator",
         "subject": MACHINE.key}, env, run, machine_serial="0412")
    r = client.post("/v1/machine/verify", json=body, headers=h)
    assert r.status_code == 200 and r.json()["tier"] == "validated", r.text
    return h, path


def _floor(client, h):
    from .test_assurance_machinery_tiers import covered_manifest

    r = client.post("/v1/machinery/coverage", json={"manifest": covered_manifest().to_dict()},
                    headers=h)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["verdict"] == "covered", d
    return d["evidence_tier_floor"]


def _passport_floor(client, h):
    from .test_assurance_machinery_tiers import covered_manifest

    r = client.post("/v1/machinery/passport", json={"manifest": covered_manifest().to_dict(),
                                                    "actor": "a.integrator", "seal": False},
                    headers=h)
    assert r.status_code == 200, r.text
    return r.json()["evidence"]["body"]["evidence_tier_floor"]


class TestTheApiReadersApplyTheServersTrust:
    def test_the_baseline_is_validated_under_the_servers_trust(self, client, seeded):
        h, _ = seeded
        assert _floor(client, h) == "validated"
        assert _passport_floor(client, h) == "validated"

    def test_revoking_the_key_downgrades_the_coverage_route(self, client, seeded):
        h, path = seeded
        RECORDER.write_trust(path, revoked=True)
        assert _floor(client, h) == "community"

    def test_revoking_the_key_downgrades_the_passport(self, client, seeded):
        h, path = seeded
        RECORDER.write_trust(path, revoked_on="2026-03-01")
        assert _passport_floor(client, h) == "community"

    @pytest.mark.parametrize("how", ["unset", "removed", "corrupt"])
    def test_no_usable_trust_file_means_community_not_the_sealing_verdict(
            self, client, seeded, monkeypatch, how):
        h, path = seeded
        if how == "unset":
            monkeypatch.delenv("ASSURANCE_RECORDER_TRUST")
        elif how == "removed":
            path.unlink()
        else:
            path.write_text("{garbage")
        assert _floor(client, h) == "community"
        assert _passport_floor(client, h) == "community"

    def test_a_file_that_trusts_somebody_else_is_community(self, client, seeded):
        h, path = seeded
        Recorder().write_trust(path)
        assert _floor(client, h) == "community"

    def test_the_offline_reader_with_no_list_still_believes_its_own_ledger(self, tmp_path):
        from assurance.evidence.ledger import EvidenceLedger
        from assurance.machinery.staleness import VerificationRecord

        from .test_assurance_machinery import seal_a_real_verification

        led = EvidenceLedger(tmp_path / "own.db")
        seal_a_real_verification(led, when=datetime(2026, 2, 9, tzinfo=UTC), attested=True)
        assert [v.tier for v in VerificationRecord.from_ledger(led)] == ["validated"]
        assert [v.tier for v in VerificationRecord.from_ledger(
            led, recorder_trust=RecorderTrust())] == ["community"]


@pytest.fixture
def spy(monkeypatch):
    """Every ``recorder_trust`` a ledger reader is handed (``"MISSING"`` if none)."""
    from assurance.machinery.staleness import VerificationRecord

    seen: list = []
    original = VerificationRecord.from_ledger.__func__

    def wrapper(cls, ledger, **kw):
        seen.append(kw.get("recorder_trust", "MISSING"))
        return original(cls, ledger, **kw)

    monkeypatch.setattr(VerificationRecord, "from_ledger", classmethod(wrapper))
    return seen


def _all_trust_lists(seen):
    assert seen, "the route never read verifications from the ledger"
    assert all(isinstance(t, RecorderTrust) for t in seen), seen


class TestEveryApiReaderIsHandedTheTrust:
    """The reviewer's mutants (a route passing ``None``) survived because nothing watched
    what a route hands the reader. These do, with no server trust file configured: the
    reader must still be given a (here empty) list, never ``None``."""

    @pytest.fixture(autouse=True)
    def _no_server_file(self, monkeypatch):
        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)

    def test_the_machinery_coverage_route(self, client, store, spy):
        from .test_assurance_machinery_tiers import covered_manifest

        client.post("/v1/machinery/coverage", json={"manifest": covered_manifest().to_dict()},
                    headers=keyed(store, "cell"))
        _all_trust_lists(spy)

    def test_the_machinery_passport_route(self, client, store, spy):
        from .test_assurance_machinery_tiers import covered_manifest

        client.post("/v1/machinery/passport",
                    json={"manifest": covered_manifest().to_dict(), "actor": "a.i",
                          "seal": False}, headers=keyed(store, "cell"))
        _all_trust_lists(spy)

    def test_the_fleet_declaration_check(self, client, store, spy):
        from assurance.fleet.declaration import DeclarationOfConformity

        from .test_assurance_fleet import manifest as fleet_manifest

        man = fleet_manifest()
        doc = DeclarationOfConformity.bind(
            man, doc_id="DOC-1", issued_by="Grimaldi",
            issued_at=datetime(2026, 1, 20, tzinfo=UTC),
            legislation=("Regulation (EU) 2023/1230",))
        r = client.post("/v1/fleet/declaration/check", json={
            "declaration": doc.to_dict(), "manifest": man.to_dict(), "with_coverage": True},
            headers=keyed(store, "cell"))
        assert r.json()["coverage_assessed"] is True
        _all_trust_lists(spy)

    def test_the_fleet_listing(self, client, store, spy):
        from .test_assurance_fleet import manifest as fleet_manifest

        h = keyed(store, "cell")
        assert client.post("/v1/machinery/manifest", json={"manifest": fleet_manifest().to_dict()},
                           headers=h).status_code == 200
        spy.clear()
        assert client.get("/v1/fleet/machines", headers=h).status_code == 200
        _all_trust_lists(spy)

    def test_the_change_drift_route(self, client, store, spy):
        from .test_assurance_fleet import OTHER_FW, fw
        from .test_assurance_fleet import manifest as fleet_manifest

        base = fleet_manifest()
        seen = fleet_manifest("0412", fw(OTHER_FW), manifest_id="MAN-NOW")
        r = client.post("/v1/change/assess/drift", json={
            "baseline": base.to_dict(), "observed": seen.to_dict(), "actor": "watch"},
            headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        _all_trust_lists(spy)

    def test_the_change_intervention_route(self, client, store, spy):
        from .test_assurance_machinery import intervention, manifest

        h = keyed(store, "cell")
        assert client.post("/v1/machinery/manifest", json={"manifest": manifest().to_dict()},
                           headers=h).status_code == 200
        assert client.post("/v1/machinery/intervention",
                           json={"intervention": intervention().to_dict()},
                           headers=h).status_code == 200
        spy.clear()
        r = client.post("/v1/change/assess/intervention", json={
            "manifest": manifest().to_dict(), "intervention_id": "INT-0007", "actor": "watch"},
            headers=h)
        assert r.status_code == 200, r.text
        _all_trust_lists(spy)

    def _enrol(self, client, store):
        from .test_assurance_fleet import manifest as fleet_manifest

        h = keyed(store, "cell")
        man = fleet_manifest()
        assert client.post("/v1/machinery/manifest", json={"manifest": man.to_dict()},
                           headers=h).status_code == 200
        return h, man

    def test_the_value_route(self, client, store, spy):
        h, _ = self._enrol(client, store)
        spy.clear()
        assert client.get("/v1/value", headers=h).status_code == 200
        _all_trust_lists(spy)

    def test_the_enrolled_check_route(self, client, store, spy):
        h, man = self._enrol(client, store)
        spy.clear()
        r = client.post("/v1/check/fleet-machine", json={"machine_key": man.machine.key},
                        headers=h)
        assert r.status_code == 200, r.text
        _all_trust_lists(spy)

    def test_the_fleet_report_route(self, client, store, spy):
        h, _ = self._enrol(client, store)
        spy.clear()
        assert client.get("/v1/fleet/report", headers=h).status_code == 200
        _all_trust_lists(spy)

    def test_the_watch_route_hands_ingest_the_trust(self, client, store, monkeypatch):
        from assurance.api import watch_routes

        from .test_assurance_watch_report import failed, now, report

        seen: dict = {}
        original = watch_routes.ingest_report

        def wrapper(ledger, rep, **kw):
            seen.update(kw)
            return original(ledger, rep, **kw)

        monkeypatch.setattr(watch_routes, "ingest_report", wrapper)
        r = client.post("/v1/watch/report", json=report(failed("0412", at=now())),
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        assert isinstance(seen.get("recorder_trust"), RecorderTrust)

    def test_ingest_hands_the_drift_assessment_the_trust(self, tmp_path, spy):
        from assurance.evidence.ledger import EvidenceLedger
        from assurance.watch.ingest import ingest_report

        from .test_assurance_watch_report import SCANNER, good, make_manifest, now, report

        led = EvidenceLedger(tmp_path / "w.db")
        t0 = now()
        first = make_manifest(tmp_path, "0412", fw=b"firmware 3.8.2")
        second = make_manifest(tmp_path, "0412", fw=b"firmware 3.9.0")
        ingest_report(led, report(good(first, at=t0 - timedelta(hours=2))), actor=SCANNER,
                      recorder_trust=RecorderTrust())
        spy.clear()
        out = ingest_report(led, report(good(second, at=t0, status="changed")),
                            actor=SCANNER, recorder_trust=RecorderTrust())
        assert out.results[0].recorded_status == "changed"
        _all_trust_lists(spy)

    def test_no_api_module_reads_the_ledger_without_a_trust_list(self):
        """A reader added to a route later cannot quietly forget the list."""
        import re
        from pathlib import Path

        api = Path(__file__).resolve().parents[1] / "src" / "assurance" / "api"
        pattern = re.compile(r"(VerificationRecord\.from_ledger|Fleet\.from_ledger|"
                             r"build_passport|assess_recorded_intervention|ingest_report)\(")
        offenders = []
        for path in sorted(api.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for m in pattern.finditer(text):
                depth, end = 0, len(text) - 1
                for i in range(m.end() - 1, len(text)):
                    depth += text[i] == "("
                    depth -= text[i] == ")"
                    if depth == 0:
                        end = i
                        break
                call = text[m.start(): end + 1]
                if "recorder_trust=" not in call:
                    offenders.append(f"{path.name}: {call.splitlines()[0]}")
        assert not offenders, offenders
