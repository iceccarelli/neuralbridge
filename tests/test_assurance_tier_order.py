"""The assurance tiers are an ordered ladder, and every comparison operator agrees.

``AssuranceTier`` is a ``StrEnum``. A ``str`` defines all six comparison operators, and the
class once defined only ``<`` and ``<=`` by rank, so ``>`` and ``>=`` silently fell back to the
STRING order of the names: ``profile > community`` was True, ``certified > community`` was
False. Two guards in ``machine/bundle.py`` are written with ``>`` and both were wrong:

* ``_refuse_foreign_result`` (``result.tier > ceiling``) is what stops a caller sealing a
  result that claims more than its inputs can support;
* ``check_bundle_data`` (``recorded_tier > COMMUNITY and not fully_reproduced``) is what caps
  the tier the FREE, anonymous checkers believe.

These tests pin the operators themselves and then both guards, through the library and through
the live HTTP routes.
"""

from __future__ import annotations

import copy
import dataclasses
import itertools
import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor
from assurance.core.tiers import AssuranceTier
from assurance.machine.bundle import BundleError, build_bundle, check_bundle_data
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import verify

from .support_recorder import attested
from .test_assurance_bundle_check import reseal
from .test_assurance_evidence_api import check as evidence_check

LADDER = [AssuranceTier.PROFILE, AssuranceTier.COMMUNITY, AssuranceTier.VALIDATED,
          AssuranceTier.CERTIFIED]
ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")
URL = "/v1/machine/bundle/check"
MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
DATASHEET = FigureBasis(kind="datasheet", reference="scanner rev D")


# -- the operators ---------------------------------------------------------

class TestEveryOperatorFollowsTheLadder:
    def test_the_ladder_is_the_documented_order(self):
        assert [t.rank for t in LADDER] == [0, 1, 2, 3]
        assert [t.value for t in LADDER] == ["profile", "community", "validated", "certified"]

    @pytest.mark.parametrize(("a", "b"), list(itertools.product(LADDER, LADDER)),
                             ids=lambda t: t.value)
    def test_all_six_operators_agree_with_rank(self, a, b):
        assert (a < b) is (a.rank < b.rank)
        assert (a <= b) is (a.rank <= b.rank)
        assert (a > b) is (a.rank > b.rank)
        assert (a >= b) is (a.rank >= b.rank)
        assert (a == b) is (a.rank == b.rank)
        assert (a != b) is (a.rank != b.rank)

    def test_the_cases_string_order_got_wrong(self):
        """The four pairs the audit named, spelled out so a regression reads plainly."""
        assert AssuranceTier.PROFILE < AssuranceTier.COMMUNITY
        assert not AssuranceTier.PROFILE > AssuranceTier.COMMUNITY
        assert AssuranceTier.CERTIFIED > AssuranceTier.COMMUNITY
        assert AssuranceTier.CERTIFIED > AssuranceTier.VALIDATED
        assert AssuranceTier.CERTIFIED >= AssuranceTier.PROFILE
        assert not AssuranceTier.COMMUNITY >= AssuranceTier.VALIDATED

    def test_sorted_max_min_follow_the_ladder_whatever_the_input_order(self):
        for perm in itertools.permutations(LADDER):
            assert sorted(perm) == LADDER
            assert sorted(perm, reverse=True) == LADDER[::-1]
            assert max(perm) is AssuranceTier.CERTIFIED
            assert min(perm) is AssuranceTier.PROFILE

    def test_a_tier_does_not_compare_with_a_bare_string_by_rank(self):
        """Only another tier has a rank. Anything else is left to ``str`` / refused."""
        with pytest.raises(TypeError):
            AssuranceTier.PROFILE < 3  # noqa: B015
        with pytest.raises(TypeError):
            AssuranceTier.PROFILE > 3  # noqa: B015


# -- the guard that refuses to seal a result above what its inputs support --

def _envelope(basis: FigureBasis, uncertainty_basis: FigureBasis | None = None):
    return SafetyEnvelope(
        envelope_id="ENV-1", product="Cell", product_version="1.0.0",
        workspace=Workspace(minimum=(-1000.0, -1000.0, 0.0), maximum=(1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0},
        stop=StopPerformance(reaction_time_s=0.1, stop_time_s=0.25, stop_distance_mm=120.0,
                             measured_at_speed_mm_s=500.0, basis=basis),
        uncertainty=SensingUncertainty(human_position_mm=100.0, robot_position_mm=50.0,
                                       basis=uncertainty_basis or basis),
        intrusion_distance_mm=850.0)


def _trace():
    return Trace(
        trace_id="RUN-1", provenance=Provenance.FIELD, source_system="fw",
        started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
        samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                             mode=OperatingMode.SSM, separation=3000.0)
                      for i in range(20)))


class TestASealedResultMayNotClaimMoreThanItsInputsSupport:
    def _honest(self, env, **attest):
        tr = _trace()
        kw = attested(env, tr) if attest else {}
        return env, tr, kw, verify(env, tr, **kw)

    def test_the_honest_result_is_sealed_at_each_ceiling(self):
        for env, want, attest in (
                (_envelope(DATASHEET), AssuranceTier.PROFILE, {}),
                (_envelope(MEASURED), AssuranceTier.COMMUNITY, {}),
                (_envelope(MEASURED), AssuranceTier.VALIDATED, {"a": 1})):
            env, tr, kw, res = self._honest(env, **attest)
            assert res.tier is want
            assert build_bundle(env, tr, actor=ACTOR, result=res, **kw).tier is want

    @pytest.mark.parametrize(("basis", "attest", "claimed", "honest"), [
        (DATASHEET, False, AssuranceTier.COMMUNITY, AssuranceTier.PROFILE),
        (DATASHEET, False, AssuranceTier.VALIDATED, AssuranceTier.PROFILE),
        (MEASURED, False, AssuranceTier.VALIDATED, AssuranceTier.COMMUNITY),
        (DATASHEET, False, AssuranceTier.CERTIFIED, AssuranceTier.PROFILE),
        (MEASURED, False, AssuranceTier.CERTIFIED, AssuranceTier.COMMUNITY),
        (MEASURED, True, AssuranceTier.CERTIFIED, AssuranceTier.VALIDATED),
    ], ids=["community-over-profile", "validated-over-profile", "validated-over-community",
            "certified-over-profile", "certified-over-community", "certified-over-validated"])
    def test_a_result_above_its_ceiling_is_refused(self, basis, attest, claimed, honest):
        env, tr, kw, res = self._honest(_envelope(basis), **({"a": 1} if attest else {}))
        assert res.tier is honest
        forged = dataclasses.replace(res, tier=claimed)
        with pytest.raises(BundleError, match="claims tier"):
            build_bundle(env, tr, actor=ACTOR, result=forged, **kw)


# -- the tier the free checkers believe -----------------------------------

def _bundle(env, tr=None):
    tr = tr or _trace()
    return json.loads(json.dumps(build_bundle(env, tr, actor=ACTOR).to_dict()))


def _forge(raw, tier):
    raw = copy.deepcopy(raw)
    raw["evidence"]["body"]["tier"] = tier
    raw["result"]["tier"] = tier
    raw["result"]["may_claim_physical_behaviour"] = tier in ("validated", "certified")
    return reseal(raw)


class TestTheBelievedTierOfACheckedBundle:
    def test_a_resealed_certified_bundle_is_rejected_and_believed_as_community(self):
        raw = _forge(_bundle(_envelope(MEASURED)), "certified")
        check = check_bundle_data(raw)
        assert check.ok is False and check.level == "rejected"
        assert any("certified" in p for p in check.problems)
        assert check.believed_tier == "community"

    def test_a_resealed_validated_bundle_over_declared_provenance_is_believed_as_community(
            self):
        raw = _forge(_bundle(_envelope(MEASURED)), "validated")
        check = check_bundle_data(raw)
        assert check.ok is False
        assert check.believed_tier == "community"

    def test_a_profile_bundle_is_believed_as_profile_not_raised_to_community(self):
        """A lower recorded tier stays: the checker may cap a tier, never lift one."""
        raw = _bundle(_envelope(DATASHEET))
        assert raw["evidence"]["body"]["tier"] == "profile"
        check = check_bundle_data(raw)
        assert check.ok is True
        assert check.believed_tier == "profile"

    def test_a_reproduced_profile_bundle_is_still_believed_as_profile(self):
        env, tr = _envelope(DATASHEET), _trace()
        check = check_bundle_data(_bundle(env, tr), envelope=env, trace=tr)
        assert check.level == "reproduced"
        assert check.believed_tier == "profile"

    def test_a_community_bundle_is_believed_as_community(self):
        check = check_bundle_data(_bundle(_envelope(MEASURED)))
        assert check.ok is True and check.believed_tier == "community"


# -- the same, through the live FastAPI app -------------------------------

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


class TestOverTheFreeAnonymousRoutes:
    def test_machine_bundle_check_does_not_believe_a_forged_certified_bundle(self, client):
        raw = _forge(_bundle(_envelope(MEASURED)), "certified")
        r = client.post(URL, json={"bundle": raw})
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is False and d["level"] == "rejected"
        assert d["believed_tier"] == "community"

    def test_evidence_verify_does_not_believe_a_forged_certified_bundle(self, client):
        raw = _forge(_bundle(_envelope(MEASURED)), "certified")
        d = evidence_check(client, raw)
        assert d["ok"] is False
        assert d["tier"]["recorded_tier"] == "certified"
        assert d["tier"]["believed_tier"] == "community"

    def test_machine_bundle_check_keeps_a_profile_bundle_at_profile(self, client):
        r = client.post(URL, json={"bundle": _bundle(_envelope(DATASHEET))})
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True and d["believed_tier"] == "profile"

    def test_evidence_verify_keeps_a_profile_bundle_at_profile(self, client):
        d = evidence_check(client, _bundle(_envelope(DATASHEET)))
        assert d["ok"] is True and d["tier"]["believed_tier"] == "profile"
