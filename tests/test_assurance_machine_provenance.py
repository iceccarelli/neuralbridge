"""A provenance the filer declares cannot lift a machine verification's tier.

The defect: ``provenance`` (simulation / bench / field) is a field in the trace the
caller files. Nothing signs a recording, so a Cell account could POST a trace from
"a python range() generator on my laptop", declare ``field``, and get a ``validated``
tier with ``may_claim_physical_behaviour`` true; the anonymous bundle checker then
said ``ok``. The fix caps a declared provenance at ``community`` and records
``provenance_basis: declared_by_filer`` (``machine/provenance_trust.py``); the one
extension point for a future signed recorder attestation mirrors the limits review.

This module deliberately does NOT assume a recorder attestation (the other machine
test modules do, so that they can pin the other inputs of the tier floor), except in
the tests that name it.

It also pins the second half of the same trust boundary: the sealed actor follows the
authenticated credential (``POST /v1/machine/verify``), as on ``/v1/change``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor, Evidence
from assurance.core.tiers import AssuranceTier
from assurance.machine import provenance_trust
from assurance.machine.bundle import (
    LEVEL_INTEGRITY_ONLY,
    LEVEL_REJECTED,
    LEVEL_REPRODUCED,
    build_bundle,
    check_bundle_data,
)
from assurance.machine.cli import main as machine_cli
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import ENGINE_VERSION, verify

from .support_recorder_attestation import simulate_verified_recorder_attestation
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store

# the HTTP fixtures of the machine tests (this module does not assume an attestation)
client = _client
store = _store

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")
LAPTOP = "python range() generator on my laptop"
CHECK_URL = "/v1/machine/bundle/check"


def envelope() -> SafetyEnvelope:
    """Every figure measured: the envelope itself would allow ``validated``."""
    return SafetyEnvelope(
        envelope_id="ENV-1", product="Cell", product_version="1.0.0",
        workspace=Workspace(minimum=(-1000.0, -1000.0, 0.0),
                            maximum=(1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0},
        stop=StopPerformance(reaction_time_s=0.1, stop_time_s=0.25,
                             stop_distance_mm=120.0, measured_at_speed_mm_s=500.0,
                             basis=MEASURED),
        uncertainty=SensingUncertainty(human_position_mm=100.0, robot_position_mm=50.0,
                                       basis=MEASURED),
        intrusion_distance_mm=850.0,
    )


def laptop_trace(provenance: Provenance = Provenance.FIELD,
                 source_system: str = LAPTOP) -> Trace:
    """Twenty perfect samples that a ``range()`` loop could have produced."""
    return Trace(
        trace_id="RUN-LAPTOP", provenance=provenance, source_system=source_system,
        started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
        samples=tuple(
            Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                   mode=OperatingMode.SSM, separation=3000.0)
            for i in range(20)))


def reseal(raw: dict) -> dict:
    """What an editor holding this package can do: edit the body, recompute the hash."""
    raw["evidence"]["content_hash"] = Evidence.from_dict(raw["evidence"]).compute_hash()
    return raw


def forge_validated(raw: dict, *, result_block: bool = True) -> dict:
    """Claim ``validated`` / physical behaviour / HIGH confidence, and reseal."""
    raw["evidence"]["body"]["tier"] = "validated"
    raw["evidence"]["confidence"] = "high"
    if result_block:
        raw["result"]["tier"] = "validated"
        raw["result"]["may_claim_physical_behaviour"] = True
    else:
        del raw["result"]
    return reseal(raw)


def honest_raw(env=None, tr=None) -> tuple[dict, SafetyEnvelope, Trace]:
    env, tr = env or envelope(), tr or laptop_trace()
    return json.loads(json.dumps(build_bundle(env, tr, actor=ACTOR).to_dict())), env, tr


# -- (a) the exact repro --------------------------------------------------

class TestTheReproducedDefect:
    def _payload(self, **over):
        t = laptop_trace()
        return {"envelope": envelope().to_dict(), "trace": t.hashable_payload(),
                "actor": "v.grimaldi", **over}

    def test_a_laptop_generator_filed_as_field_is_not_validated(self, client, store):
        r = client.post("/v1/machine/verify", json=self._payload(),
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["verdict"] == "pass"
        assert d["tier"] in ("community", "profile")
        assert AssuranceTier(d["tier"]).rank <= AssuranceTier.COMMUNITY.rank
        assert d["may_claim_physical_behaviour"] is False
        assert d["result"]["may_claim_physical_behaviour"] is False
        # ... and the result says why, in the API result, the sealed body and the
        # stated limitations
        assert d["provenance_basis"] == "declared_by_filer"
        assert "declared" in d["provenance_note"] or "whoever filed" in d["provenance_note"]
        assert d["evidence"]["body"]["provenance_basis"] == "declared_by_filer"
        assert d["result"]["provenance_basis"] == "declared_by_filer"
        assert d["result"]["provenance_assessment"]["lifts_tier"] is False
        assert any("provenance_basis declared_by_filer" in c
                   for c in d["evidence"]["checks_skipped"])
        assert d["evidence"]["confidence"] != "high"

    def test_the_anonymous_checker_sees_the_cap_and_the_basis(self, client, store):
        sealed = client.post("/v1/machine/verify", json=self._payload(),
                             headers=keyed(store, "cell")).json()
        out = client.post(CHECK_URL, json={"bundle": sealed}).json()
        assert out["ok"] is True
        assert out["recorded_tier"] == "community"
        assert out["recorded_provenance_basis"] == "declared_by_filer"

    @pytest.mark.parametrize("prov", list(Provenance))
    def test_no_declared_provenance_reaches_validated_with_every_figure_measured(
            self, prov):
        r = verify(envelope(), laptop_trace(prov))
        assert r.tier.rank <= AssuranceTier.COMMUNITY.rank
        assert not r.may_claim_physical_behaviour
        assert r.provenance_basis == "declared_by_filer"

    def test_the_cli_reports_the_basis_in_json_and_in_words(self, tmp_path, capsys):
        (tmp_path / "e.json").write_text(json.dumps(envelope().to_dict()))
        (tmp_path / "t.json").write_text(json.dumps(laptop_trace().hashable_payload()))
        args = ["verify", "--envelope", str(tmp_path / "e.json"), "--trace",
                str(tmp_path / "t.json"), "--actor", "v.grimaldi"]
        assert machine_cli([*args, "--json"]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["tier"] == "community"
        assert out["result"]["provenance_basis"] == "declared_by_filer"
        assert machine_cli(args) == 0
        text = capsys.readouterr().out
        assert "at tier community" in text and "declared_by_filer" in text
        assert "filer's own declaration" in text

    def test_the_engine_was_bumped_so_old_bundles_are_never_reinterpreted(self):
        assert ENGINE_VERSION == "5"
        assert verify(envelope(), laptop_trace()).engine_version == "5"

    def test_an_honest_declared_bundle_still_checks_and_replays(self):
        raw, env, tr = honest_raw()
        assert raw["evidence"]["body"]["tier"] == "community"
        assert check_bundle_data(raw).level == LEVEL_INTEGRITY_ONLY
        assert check_bundle_data(raw, envelope=env, trace=tr).level == LEVEL_REPRODUCED


# -- (b) a resealed or edited bundle ---------------------------------------

class TestAResealedValidatedClaimIsRejected:
    def test_the_public_checker_rejects_validated_from_a_declared_provenance(
            self, client):
        raw, _, _ = honest_raw()
        out = client.post(CHECK_URL, json={"bundle": forge_validated(raw)}).json()
        assert out["ok"] is False and out["level"] == LEVEL_REJECTED
        assert any("declared" in p and "validated" in p for p in out["problems"]), \
            out["problems"]

    def test_even_with_no_result_block_beside_the_seal(self):
        raw, _, _ = honest_raw()
        res = check_bundle_data(forge_validated(raw, result_block=False))
        assert not res.ok
        assert any("provenance" in p and "declared" in p for p in res.problems)

    def test_and_with_the_original_inputs_replay_reports_it_too(self):
        raw, env, tr = honest_raw()
        res = check_bundle_data(forge_validated(raw), envelope=env, trace=tr)
        assert not res.ok
        assert any("declared" in p for p in res.problems)
        assert any("re-running the engine" in p and "tier" in p for p in res.problems)

    def test_an_old_engine_bundle_that_carries_validated_from_field_is_rejected(self):
        """What engine 4 sealed: no provenance_basis at all, tier validated."""
        raw, _, _ = honest_raw()
        body = raw["evidence"]["body"]
        body.pop("provenance_basis")
        body.pop("provenance_assessment")
        body["engine_version"] = "4"
        raw["result"].pop("provenance_basis")
        raw["result"].pop("provenance_assessment")
        raw["result"]["engine_version"] = "4"
        res = check_bundle_data(forge_validated(raw))
        assert not res.ok
        assert any("engine 4 or earlier" in p for p in res.problems), res.problems

    def test_a_forged_attested_basis_is_not_believed(self):
        """No attestation can be verified yet, so the word 'attested' lifts nothing."""
        raw, _, _ = honest_raw()
        raw["evidence"]["body"]["provenance_basis"] = "recorder_attested"
        raw["result"]["provenance_basis"] = "recorder_attested"
        res = check_bundle_data(forge_validated(raw))
        assert not res.ok
        assert any("recorder_attested" in p for p in res.problems), res.problems

    def test_a_bundle_sealed_under_an_assumed_attestation_is_rejected_by_a_real_checker(
            self, monkeypatch):
        with monkeypatch.context() as m:
            simulate_verified_recorder_attestation(m)
            raw, env, tr = honest_raw()
            assert raw["evidence"]["body"]["tier"] == "validated"
            assert check_bundle_data(raw, envelope=env, trace=tr).ok  # the double's world
        res = check_bundle_data(raw, envelope=env, trace=tr)           # the real one
        assert not res.ok and res.level == LEVEL_REJECTED

    def test_a_simulation_is_still_capped_on_its_own_rule(self):
        raw, _, _ = honest_raw(tr=laptop_trace(Provenance.SIMULATION))
        res = check_bundle_data(forge_validated(raw))
        assert any("simulation" in p for p in res.problems)

    def test_a_result_handed_to_build_bundle_cannot_claim_the_lifted_tier(self):
        from dataclasses import replace

        from assurance.machine.bundle import BundleError

        env, tr = envelope(), laptop_trace()
        forged = replace(verify(env, tr), tier=AssuranceTier.VALIDATED)
        with pytest.raises(BundleError, match="validated"):
            build_bundle(env, tr, actor=ACTOR, result=forged)


class TestTheExtensionPoint:
    def test_a_verified_attestation_lifts_the_cap_through_one_function(
            self, monkeypatch):
        simulate_verified_recorder_attestation(monkeypatch)
        r = verify(envelope(), laptop_trace())
        assert r.tier is AssuranceTier.VALIDATED and r.may_claim_physical_behaviour
        assert r.provenance_basis == "recorder_attested"

    def test_nothing_lifts_today(self):
        assert provenance_trust.LIFTING_BASES == frozenset()
        assert provenance_trust.assess_provenance(laptop_trace()).lifts_tier is False


# -- (c) the actor follows the credential -----------------------------------

class TestTheSealedActorFollowsTheCredential:
    def _body(self, actor="v.grimaldi", **over):
        t = laptop_trace()
        return {"envelope": envelope().to_dict(), "trace": t.hashable_payload(),
                "actor": actor, **over}

    def _operator(self, store, headers, name, role="decider"):
        """Headers for a key issued to an individual operator of the caller's account."""
        account = store.peek_key(headers["X-API-Key"]).account
        return {"X-API-Key": store.create_operator(account.id, name, role)[1]}

    def test_an_operator_key_records_that_operator_as_the_sealed_actor(
            self, client, store):
        headers = keyed(store, "cell")
        mine = self._operator(store, headers, "v.grimaldi")
        r = client.post("/v1/machine/verify", json=self._body("v.grimaldi"), headers=mine)
        assert r.status_code == 200, r.text
        actor = r.json()["evidence"]["actor"]
        assert actor["identifier"] == "v.grimaldi"
        assert "attribution=authenticated_operator" in actor["role"]
        assert "operator=op_" in actor["role"]

    def test_naming_somebody_else_with_an_operator_key_is_refused_and_seals_nothing(
            self, client, store):
        from assurance.api import deps

        headers = keyed(store, "cell")
        mine = self._operator(store, headers, "v.grimaldi")
        r = client.post("/v1/machine/verify", json=self._body("Dr. Anna Keller"),
                        headers=mine)
        assert r.status_code == 403
        assert r.json()["detail"]["error"] == "actor_mismatch"
        account = store.peek_key(headers["X-API-Key"]).account
        ledger = deps._tenant_register_for(str(deps.tenant_ledger_path(account.id))).ledger
        assert len(ledger) == 0

    def test_an_account_level_key_is_recorded_as_declared_not_authenticated(
            self, client, store):
        r = client.post("/v1/machine/verify", json=self._body("anyone.at.all"),
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        actor = r.json()["evidence"]["actor"]
        assert actor["identifier"] == "anyone.at.all"
        assert "attribution=declared_by_account_key" in actor["role"]
        assert "authenticated_operator" not in actor["role"]

    def test_the_role_the_caller_names_is_kept_beside_the_attribution(
            self, client, store):
        r = client.post("/v1/machine/verify",
                        json=self._body("a.b", role="commissioning engineer"),
                        headers=keyed(store, "cell"))
        assert r.json()["evidence"]["actor"]["role"].startswith("commissioning engineer")

    def test_open_mode_keeps_the_declared_label_and_says_so(
            self, tmp_path, monkeypatch):
        import importlib

        from fastapi.testclient import TestClient

        from assurance.api import deps

        monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "open.db"))
        monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
        monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
        monkeypatch.setenv("ASSURANCE_ALLOW_UNAUTHENTICATED", "1")
        for cache in (deps._register_for, deps._tenant_register_for, deps._accounts_for):
            cache.cache_clear()
        try:
            with TestClient(importlib.import_module("assurance.api.service")
                            .create_app()) as c:
                r = c.post("/v1/machine/verify", json=self._body("local.engineer"))
            assert r.status_code == 200, r.text
            actor = r.json()["evidence"]["actor"]
            assert actor["identifier"] == "local.engineer"
            assert "attribution=declared_open_mode" in actor["role"]
        finally:
            for cache in (deps._register_for, deps._tenant_register_for,
                          deps._accounts_for):
                cache.cache_clear()

    def test_the_cli_keeps_the_label_it_is_given(self, tmp_path, capsys):
        (tmp_path / "e.json").write_text(json.dumps(envelope().to_dict()))
        (tmp_path / "t.json").write_text(json.dumps(laptop_trace().hashable_payload()))
        assert machine_cli(["verify", "--envelope", str(tmp_path / "e.json"), "--trace",
                            str(tmp_path / "t.json"), "--actor", "bench.engineer",
                            "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["evidence"]["actor"][
            "identifier"] == "bench.engineer"

