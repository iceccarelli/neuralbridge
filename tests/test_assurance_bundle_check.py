"""Re-verifying a bundle you did not produce.

``verify_bundle`` is the free checker an auditor runs, so every way a bundle can
lie has to end in a ``False`` — or in an ``ok`` that says, in words, what it did
not check. The cases here are the ways a determined editor gets past a seal that
only covers *part* of the file: the sealed evidence is hashed, but the envelope
and the result printed beside it are not, and a seal anyone can recompute proves
nothing about whether the sealed claim is coherent.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor, Evidence
from assurance.machine.bundle import build_bundle, verify_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")

LIMITS = LimitsTable(
    edition="Example 2016", transcribed_by="a", verified_by="b",
    verified_on="2026-04-01", transient_multiplier=2.0,
    regions={"hand": BodyRegionLimit("hand", "Hand", 260.0, 140.0)})


def envelope(pfl=False):
    return SafetyEnvelope(
        envelope_id="ENV-1", product="Cell", product_version="1.0.0",
        workspace=Workspace(minimum=(-1000.0, -1000.0, 0.0),
                            maximum=(1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0, OperatingMode.PFL: 250.0},
        stop=StopPerformance(reaction_time_s=0.1, stop_time_s=0.25,
                             stop_distance_mm=120.0, measured_at_speed_mm_s=500.0,
                             basis=MEASURED),
        uncertainty=SensingUncertainty(human_position_mm=100.0, robot_position_mm=50.0,
                                       basis=MEASURED),
        intrusion_distance_mm=850.0,
        pfl_limits_hash=LIMITS.content_hash() if pfl else "",
    )


def trace(provenance=Provenance.FIELD, separation=3000.0, pfl=False):
    samples = []
    for i in range(20):
        samples.append(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                              mode=OperatingMode.SSM, separation=separation))
    if pfl:
        for i in range(20, 40):
            samples.append(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=100.0,
                                  mode=OperatingMode.PFL, contact_force=50.0,
                                  contact_area=2.0, body_region="hand"))
    return Trace(trace_id="RUN-1", provenance=provenance, source_system="fw",
                 started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC),
                 sample_rate_hz=50.0, samples=tuple(samples))


def write(tmp_path, raw, name="bundle.json"):
    p = tmp_path / name
    p.write_text(json.dumps(raw), encoding="utf-8")
    return p


def make(tmp_path, env=None, tr=None, limits=None):
    env = env or envelope()
    tr = tr or trace()
    b = build_bundle(env, tr, actor=ACTOR, limits=limits)
    return b, json.loads(json.dumps(b.to_dict())), env, tr


def reseal(raw):
    """What an editor with the package can do: change the body, recompute the hash."""
    ev = Evidence.from_dict(raw["evidence"])
    raw["evidence"]["content_hash"] = ev.compute_hash()
    return raw


# -- the three things that already worked ----------------------------------

class TestAlreadyCaught:
    def test_a_clean_bundle_replays(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert ok and problems == []

    def test_an_edited_sealed_body_is_caught(self, tmp_path):
        _, raw, env, tr = make(tmp_path, tr=trace(separation=10.0))
        raw["evidence"]["body"]["verdict"] = "pass"
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok
        assert any("edited after sealing" in p for p in problems)

    def test_a_different_trace_is_caught(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        other = trace(separation=2999.0)
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=other)
        assert not ok

    def test_a_different_envelope_is_caught(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        d = env.to_dict()
        d["intrusion_distance_mm"] = 100.0
        ok, problems = verify_bundle(write(tmp_path, raw),
                                     envelope=SafetyEnvelope.from_dict(d), trace=tr)
        assert not ok


# -- the part of the file the seal does not cover --------------------------

class TestUnsealedHalfOfTheFile:
    def test_an_edited_envelope_beside_the_seal_is_caught_without_the_originals(
            self, tmp_path):
        """``bundle['envelope']`` is printed for the reader and was never checked."""
        _, raw, _, _ = make(tmp_path)
        raw["envelope"]["intrusion_distance_mm"] = 1.0
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok
        assert any("envelope" in p for p in problems)

    def test_an_edited_result_verdict_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(separation=10.0))
        assert raw["result"]["verdict"] == "fail"
        raw["result"]["verdict"] = "pass"
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok
        assert any("result" in p for p in problems)

    def test_an_edited_result_tier_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(Provenance.SIMULATION))
        raw["result"]["tier"] = "validated"
        raw["result"]["may_claim_physical_behaviour"] = True
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok

    def test_an_edited_result_check_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(separation=10.0))
        for c in raw["result"]["checks"]:
            if c["outcome"] == "violated":
                c["outcome"] = "verified"
                c["violation_count"] = 0
                c["violations"] = []
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok

    def test_a_result_naming_other_inputs_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["result"]["trace_hash"] = "0" * 64
        ok, _ = verify_bundle(write(tmp_path, raw))
        assert not ok

    def test_a_bundle_with_no_envelope_or_result_block_is_a_limitation_not_a_pass(
            self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        del raw["envelope"]
        del raw["result"]
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert ok
        assert any("NOT CHECKED" in p for p in problems)


# -- a seal anyone can recompute -------------------------------------------

class TestResealedLies:
    """The hash is a content hash, not a signature: an editor who recomputes it
    gets past the first check, so the claim itself has to hang together."""

    def test_a_simulated_trace_claiming_a_validated_tier_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(Provenance.SIMULATION))
        assert raw["evidence"]["body"]["tier"] == "community"
        raw["evidence"]["body"]["tier"] = "validated"
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("simulation" in p and "tier" in p for p in problems)

    def test_a_claim_of_physical_behaviour_without_field_provenance_is_caught(
            self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(Provenance.SIMULATION))
        raw["result"]["may_claim_physical_behaviour"] = True
        raw["evidence"]["body"]["tier"] = "validated"
        raw["result"]["tier"] = "validated"
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("physical" in p or "simulation" in p for p in problems)

    def test_a_certified_tier_is_caught_because_no_file_can_reach_it(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["tier"] = "certified"
        del raw["result"]          # isolate: the printed result would also disagree
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("certified" in p and "not reachable" in p for p in problems)

    def test_an_unknown_tier_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["tier"] = "platinum"
        ok, _ = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok

    def test_a_pass_hand_written_over_a_violation_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(separation=10.0))
        raw["evidence"]["body"]["verdict"] = "pass"
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("imply" in p for p in problems)

    def test_a_violated_check_with_no_violations_listed_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(separation=10.0))
        for c in raw["evidence"]["body"]["checks"]:
            if c["outcome"] == "violated":
                c["violation_count"] = 0
                c["violations"] = []
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok

    def test_a_verified_check_that_lists_violations_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(separation=10.0))
        for c in raw["evidence"]["body"]["checks"]:
            if c["name"] == "speed_limit":
                c["violation_count"] = 1
                c["violations"] = [{"check": "speed_limit"}]
        ok, _ = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok

    def test_a_validation_state_that_disagrees_with_the_verdict_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(separation=10.0))
        raw["evidence"]["validation_state"] = "verified"
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("validation" in p for p in problems)

    def test_high_confidence_on_a_non_physical_pass_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path, tr=trace(Provenance.SIMULATION))
        raw["evidence"]["confidence"] = "high"
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("confidence" in p for p in problems)

    def test_evidence_of_another_kind_dressed_as_a_bundle_is_caught(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["kind"] = "machinery.safety_manifest"
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok
        assert any("kind" in p for p in problems)

    def test_a_resealed_edit_to_a_margin_is_caught_by_the_replay(self, tmp_path):
        """Verdict and tier unchanged, so only a full comparison of the checks sees it."""
        _, raw, env, tr = make(tmp_path)
        for c in raw["evidence"]["body"]["checks"]:
            if c["name"] == "ssm_separation":
                c["worst_margin"] = 99999.0
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)),
                                     envelope=env, trace=tr)
        assert not ok
        assert any("ssm_separation" in p for p in problems)

    def test_resealed_stated_limitations_that_were_dropped_are_caught_by_the_replay(
            self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        raw["evidence"]["checks_skipped"] = []
        del raw["result"]          # isolate the replay from the printed-result check
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)), envelope=env, trace=tr)
        assert not ok
        assert any("limitations differ" in p for p in problems)

    def test_a_replay_under_another_engine_version_is_not_called_a_match(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        raw["evidence"]["body"]["engine_version"] = "1"
        del raw["result"]          # isolate: the printed result also names the engine
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)), envelope=env, trace=tr)
        assert not ok
        assert any("engine" in p and "not a reproduction" in p for p in problems)


# -- limits ----------------------------------------------------------------

class TestLimitsAreReplayedToo:
    def test_a_bundle_made_with_a_limits_table_replays_when_the_table_is_supplied(
            self, tmp_path):
        env, tr = envelope(pfl=True), trace(pfl=True)
        _, raw, _, _ = make(tmp_path, env=env, tr=tr, limits=LIMITS)
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr,
                                     limits=LIMITS)
        assert ok and problems == []

    def test_without_the_table_the_replay_says_it_could_not_check(self, tmp_path):
        """It used to replay without limits and call the resulting difference an edit."""
        env, tr = envelope(pfl=True), trace(pfl=True)
        _, raw, _, _ = make(tmp_path, env=env, tr=tr, limits=LIMITS)
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert any("NOT CHECKED" in p and "limits" in p for p in problems)

    def test_a_different_table_is_caught(self, tmp_path):
        env, tr = envelope(pfl=True), trace(pfl=True)
        _, raw, _, _ = make(tmp_path, env=env, tr=tr, limits=LIMITS)
        other = LimitsTable(
            edition="Example 2016", transcribed_by="a", verified_by="b",
            verified_on="2026-04-01", transient_multiplier=2.0,
            regions={"hand": BodyRegionLimit("hand", "Hand", 260.0, 999.0)})
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr,
                                     limits=other)
        assert not ok
        assert any("limits" in p for p in problems)

    def test_a_table_supplied_for_a_bundle_that_used_none_is_caught(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        ok, problems = verify_bundle(write(tmp_path, raw), envelope=env, trace=tr,
                                     limits=LIMITS)
        assert not ok


# -- a verifier reports; it does not raise ----------------------------------

class TestMalformedFiles:
    def test_a_file_that_is_not_json_is_rejected_not_raised(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text("{nope", encoding="utf-8")
        ok, problems = verify_bundle(p)
        assert not ok and problems

    def test_binary_garbage_is_rejected_not_raised(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_bytes(b"\xff\xfe\x00\x01")
        ok, problems = verify_bundle(p)
        assert not ok and problems

    def test_a_json_list_is_rejected_not_raised(self, tmp_path):
        ok, problems = verify_bundle(write(tmp_path, [1, 2, 3]))
        assert not ok and problems

    def test_a_bundle_without_evidence_is_rejected(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        del raw["evidence"]
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok and problems

    def test_a_body_without_checks_is_not_a_pass(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"]["checks"] = []
        ok, problems = verify_bundle(write(tmp_path, reseal(raw)))
        assert not ok

    def test_a_body_that_is_not_an_object_is_rejected(self, tmp_path):
        _, raw, _, _ = make(tmp_path)
        raw["evidence"]["body"] = [1, 2]
        ok, problems = verify_bundle(write(tmp_path, raw))
        assert not ok and problems

    def test_deeply_nested_json_is_rejected_not_raised(self, tmp_path):
        p = tmp_path / "b.json"
        p.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        ok, problems = verify_bundle(p)
        assert not ok and problems

    def test_the_input_is_never_mutated_by_checking(self, tmp_path):
        _, raw, env, tr = make(tmp_path)
        before = copy.deepcopy(raw)
        verify_bundle(write(tmp_path, raw), envelope=env, trace=tr)
        assert raw == before


class TestCliCheckTakesLimits:
    def test_check_accepts_a_limits_file(self, tmp_path, capsys):
        from assurance.machine.cli import main
        env, tr = envelope(pfl=True), trace(pfl=True)
        _, raw, _, _ = make(tmp_path, env=env, tr=tr, limits=LIMITS)
        bundle = write(tmp_path, raw)
        e = tmp_path / "e.json"
        e.write_text(json.dumps(env.to_dict()), encoding="utf-8")
        t = tmp_path / "t.json"
        t.write_text(json.dumps(tr.hashable_payload()), encoding="utf-8")
        lim = tmp_path / "l.json"
        lim.write_text(json.dumps(LIMITS.to_dict()), encoding="utf-8")
        code = main(["check", str(bundle), "--envelope", str(e), "--trace", str(t),
                     "--limits", str(lim)])
        assert code == 0, capsys.readouterr().out


@pytest.mark.parametrize("field", ["verdict", "tier", "provenance", "envelope_hash",
                                   "trace_hash"])
def test_every_scalar_the_result_block_repeats_must_match_the_sealed_body(
        tmp_path, field):
    _, raw, _, _ = make(tmp_path)
    raw["result"][field] = "tampered"
    ok, _ = verify_bundle(write(tmp_path, raw))
    assert not ok
