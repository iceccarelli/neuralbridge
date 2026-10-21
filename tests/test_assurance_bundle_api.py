"""The bundle checkers over HTTP: honest flags, limits, no event-loop stalls, bounded cost.

``POST /v1/machine/bundle/check`` (anonymous, unmetered) and the machine-bundle
branch of ``POST /v1/evidence/verify`` must apply the library's rules and must not
claim a check that did not run.
"""

from __future__ import annotations

import copy
import json
import time

import pytest

from assurance.api import evidence_routes, machine_routes
from assurance.api.evidence_routes import MAX_CONTAINERS, analyse

from .test_assurance_bundle_check import LIMITS, envelope, make, reseal, trace
from .test_assurance_evidence_api import build_real_ledger
from .test_assurance_evidence_api import check as evidence_check
from .test_assurance_evidence_api import post as evidence_post

URL = "/v1/machine/bundle/check"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    from assurance.api import deps

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "service" / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "service" / "accounts.db"))
    for name in ("ASSURANCE_API_KEYS", "ASSURANCE_ALLOW_UNAUTHENTICATED",
                 "ASSURANCE_MAX_EVIDENCE_BODY_BYTES", "ASSURANCE_MAX_BODY_BYTES"):
        monkeypatch.delenv(name, raising=False)
    caches = (deps._register_for, deps._tenant_register_for, deps._accounts_for)
    for cache in caches:
        cache.cache_clear()
    with TestClient(importlib.import_module("assurance.api.service").create_app()) as c:
        yield c
    for cache in caches:
        cache.cache_clear()


@pytest.fixture()
def machine_bundle(tmp_path):
    from datetime import UTC, datetime

    from assurance.evidence.ledger import EvidenceLedger

    from .test_assurance_change import seal_a_real_verification

    ledger = EvidenceLedger(tmp_path / "m" / "m.db")
    return seal_a_real_verification(
        ledger, when=datetime(2026, 2, 9, tzinfo=UTC)).to_dict()


def call(client, bundle, *, env=None, tr=None, limits=None):
    body = {"bundle": bundle}
    if env is not None:
        body["envelope"] = env.to_dict()
    if tr is not None:
        body["trace"] = tr.hashable_payload()
    if limits is not None:
        body["limits"] = limits.to_dict()
    return client.post(URL, json=body)


@pytest.fixture()
def made(tmp_path):
    _, raw, e, t = make(tmp_path)
    return raw, e, t


@pytest.fixture()
def pfl(tmp_path):
    e, t = envelope(pfl=True), trace(pfl=True)
    _, raw, _, _ = make(tmp_path, env=e, tr=t, limits=LIMITS)
    return raw, e, t


class TestFlagsReflectWhatRan:
    def test_alone_it_is_integrity_only_and_nothing_original_was_checked(
            self, client, made):
        raw, _, _ = made
        d = call(client, raw).json()
        assert d["ok"] is True and d["level"] == "integrity_only"
        assert d["reproduced"] is False
        assert d["checked"] == {
            "seal": True, "internal_consistency": True,
            "against_original_envelope": False, "against_original_trace": False,
            "against_limits": False, "reproduced": False}

    def test_a_reseal_that_is_incoherent_passes_the_seal_but_not_the_consistency(
            self, client, made):
        raw, _, _ = made
        raw["evidence"]["body"]["verdict"] = "fail"
        d = call(client, reseal(raw)).json()
        assert d["ok"] is False and d["level"] == "rejected"
        assert d["checked"]["seal"] is True
        assert d["checked"]["internal_consistency"] is False

    def test_an_edited_body_fails_the_seal(self, client, made):
        raw, _, _ = made
        raw["evidence"]["body"]["verdict"] = "fail"
        d = call(client, raw).json()
        assert d["checked"]["seal"] is False and d["level"] == "rejected"

    def test_an_unreadable_evidence_object_checked_nothing(self, client, made):
        raw, _, _ = made
        raw["evidence"] = {"kind": "x"}
        d = call(client, raw).json()
        assert d["ok"] is False
        assert d["checked"]["seal"] is False
        assert d["checked"]["internal_consistency"] is False

    def test_the_originals_reproduce_it(self, client, made):
        raw, e, t = made
        d = call(client, raw, env=e, tr=t).json()
        assert d["ok"] is True and d["level"] == "reproduced"
        assert d["checked"]["against_original_envelope"] is True
        assert d["checked"]["against_original_trace"] is True
        assert d["checked"]["reproduced"] is True

    def test_a_different_trace_is_not_marked_as_checked_against_the_original(
            self, client, made):
        raw, e, _ = made
        other = trace(separation=2999.0)
        d = call(client, raw, env=e, tr=other).json()
        assert d["ok"] is False
        assert d["checked"]["against_original_trace"] is False
        assert d["checked"]["reproduced"] is False

    def test_the_envelope_alone_is_not_a_reproduction(self, client, made):
        raw, e, _ = made
        d = call(client, raw, env=e).json()
        assert d["ok"] is True and d["level"] == "integrity_only"
        assert d["checked"]["against_original_envelope"] is False


class TestLimitsOverHttp:
    def test_a_pfl_bundle_without_its_table_is_never_a_full_replay(self, client, pfl):
        raw, e, t = pfl
        d = call(client, raw, env=e, tr=t).json()
        assert d["ok"] is True
        assert d["level"] == "integrity_only"
        assert d["checked"]["against_original_trace"] is False
        assert d["checked"]["reproduced"] is False
        assert any("NOT CHECKED" in n and "limits" in n for n in d["limitations"])

    def test_with_the_table_it_replays_fully(self, client, pfl):
        raw, e, t = pfl
        d = call(client, raw, env=e, tr=t, limits=LIMITS).json()
        assert d["ok"] is True and d["level"] == "reproduced"
        assert d["checked"]["against_original_trace"] is True
        assert d["checked"]["against_limits"] is True

    def test_another_table_is_refused(self, client, pfl):
        from assurance.machine.limits import BodyRegionLimit, LimitsTable
        raw, e, t = pfl
        other = LimitsTable(
            edition="Example 2016", transcribed_by="a", verified_by="b",
            verified_on="2026-04-01", transient_multiplier=2.0,
            regions={"hand": BodyRegionLimit("hand", "Hand", 260.0, 999.0)})
        d = call(client, raw, env=e, tr=t, limits=other).json()
        assert d["ok"] is False and d["checked"]["reproduced"] is False

    def test_an_unreadable_table_is_a_422(self, client, pfl):
        raw, e, t = pfl
        r = client.post(URL, json={"bundle": raw, "limits": {"nonsense": 1}})
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "invalid_limits"

    def test_an_oversized_trace_is_refused_as_on_the_paid_route(
            self, client, made, monkeypatch):
        raw, e, t = made
        monkeypatch.setattr(machine_routes, "MAX_SAMPLES", 3)
        r = call(client, raw, env=e, tr=t)
        assert r.status_code == 413
        assert r.json()["detail"]["error"] == "trace_too_large"


class TestSameRulesAsTheLibrary:
    def test_a_datasheet_envelope_bundle_resealed_as_validated_is_inconsistent(
            self, client, tmp_path):
        d = envelope().to_dict()
        d["stop"]["basis"] = {"kind": "datasheet", "reference": "rev D", "date": ""}
        from assurance.machine.envelope import SafetyEnvelope
        _, raw, _, _ = make(tmp_path, env=SafetyEnvelope.from_dict(d))
        raw["evidence"]["body"]["tier"] = "validated"
        raw["result"]["tier"] = "validated"
        raw["result"]["may_claim_physical_behaviour"] = True
        out = call(client, reseal(raw)).json()
        assert out["ok"] is False
        assert any("ceiling" in p for p in out["problems"])

    def test_the_cpu_part_runs_off_the_event_loop(self, client, made, monkeypatch):
        import asyncio

        raw, _, _ = made
        seen = {}
        real = machine_routes.check_bundle_data

        def probe(*a, **k):
            try:
                asyncio.get_running_loop()
                seen["on_loop"] = True
            except RuntimeError:
                seen["on_loop"] = False
            return real(*a, **k)

        monkeypatch.setattr(machine_routes, "check_bundle_data", probe)
        assert call(client, raw).status_code == 200
        assert seen == {"on_loop": False}

    def test_nothing_is_written_to_disk(self, client, made, monkeypatch):
        import tempfile

        raw, _, _ = made

        def boom(*a, **k):
            raise AssertionError("the checker must not touch the disk")

        monkeypatch.setattr(tempfile, "TemporaryDirectory", boom)
        assert call(client, raw).status_code == 200


class TestEvidenceVerifyMachineBundle:
    def test_it_lists_only_claims_that_were_checked(self, client, machine_bundle):
        del machine_bundle["envelope"]
        d = evidence_check(client, machine_bundle)
        assert d["ok"] is True
        joined = " ".join(d["verified"])
        assert "envelope" not in joined
        assert any("hashes to the hash it carries" in v for v in d["verified"])

    def test_with_the_envelope_copy_it_says_what_it_compared(self, client, machine_bundle):
        d = evidence_check(client, machine_bundle)
        joined = " ".join(d["verified"])
        assert "envelope copy" in joined and "ceiling" in joined

    def test_without_the_result_block_it_does_not_say_the_block_agrees(
            self, client, machine_bundle):
        del machine_bundle["result"]
        d = evidence_check(client, machine_bundle)
        assert d["ok"] is True
        assert not any("result block" in v for v in d["verified"])

    def test_it_says_the_bundle_was_not_reproduced(self, client, machine_bundle):
        d = evidence_check(client, machine_bundle)
        assert d["level"] == "integrity_only"
        assert "not reproduced" in d["summary"].lower()

    def test_a_fabricated_one_check_bundle_is_inconsistent(self, client, machine_bundle):
        forged = copy.deepcopy(machine_bundle)
        forged["evidence"]["body"]["checks"] = [
            {"name": "all_good", "outcome": "verified", "violation_count": 0,
             "violations": []}]
        del forged["result"]
        d = evidence_check(client, reseal(forged))
        assert d["ok"] is False and d["outcome"] == "inconsistent"
        assert d["verified"] == [] and d["level"] == "rejected"


def _empty_objects(n):
    return b'{"entries":[' + b"{}," * n + b"{}]}"


def _nested_lists(n):
    deep = b"[" * 40 + b"]" * 40
    return b'{"entries":[' + (deep + b",") * n + b"[]]}"


class TestStructureIsBoundedBeforeAnalysis:
    @pytest.mark.parametrize("body", [
        pytest.param(_empty_objects(1_400_000), id="millions-of-empty-objects"),
        pytest.param(_nested_lists(50_000), id="many-nested-lists"),
    ])
    def test_a_pathological_file_is_refused_cheaply(self, body):
        assert len(body) <= 4 * 1024 * 1024 + 200_000
        started = time.monotonic()
        result = analyse(body)
        assert time.monotonic() - started < 0.5
        assert result["outcome"] == "unreadable"
        assert f"{MAX_CONTAINERS:,}" in " ".join(result["problems"])

    def test_the_same_file_over_http_is_a_200_finding(self, client):
        started = time.monotonic()
        response = evidence_post(client, _empty_objects(1_300_000))
        assert response.status_code == 200
        assert time.monotonic() - started < 1.5
        assert response.json()["outcome"] == "unreadable"

    def test_a_legitimate_large_ledger_is_still_analysed(self, tmp_path):
        ledger, _ = build_real_ledger(tmp_path / "big" / "ledger.db")
        doc = ledger.export()
        average = sum(len(json.dumps(e)) for e in doc["entries"]) // len(doc["entries"])
        doc["entries"] = [copy.deepcopy(doc["entries"][i % len(doc["entries"])])
                          for i in range(3_700_000 // average)]
        raw = json.dumps(doc).encode()
        assert 3_000_000 < len(raw) <= 4 * 1024 * 1024
        containers = raw.count(b"{") + raw.count(b"[")
        assert containers < MAX_CONTAINERS // 2, "the cap must leave real ledgers headroom"
        result = analyse(raw)
        assert result["kind"] == "ledger_export"
        assert result["outcome"] != "unreadable"

    def test_the_cap_is_a_named_constant_and_the_entries_cap_is_unchanged(self):
        assert evidence_routes.MAX_CONTAINERS == MAX_CONTAINERS > 0
        assert evidence_routes.MAX_ENTRIES == 50_000
