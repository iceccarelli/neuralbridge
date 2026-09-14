"""Core assurance primitives: identity, evidence objects, tiers.

These tests exist because each of them corresponds to a way the primitives have
been seen to fail in a real codebase: a hash that depends on key order, an
audit record that could be edited after the fact, and a tier vocabulary that
lets a simulation be described as a validated system.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.core import (
    Actor,
    AssuranceTier,
    Confidence,
    Evidence,
    EvidenceIncompleteError,
    EvidenceObject,
    Origin,
    SealedObjectError,
    ValidationState,
    canonical_json,
    content_hash_of,
    format_utc,
    parse_utc,
)


class TestIdentity:
    def test_hash_is_independent_of_key_order(self):
        assert content_hash_of({"a": 1, "b": 2}) == content_hash_of({"b": 2, "a": 1})

    def test_hash_is_independent_of_float_noise_below_precision(self):
        assert content_hash_of({"x": 2.0}) == content_hash_of({"x": 2.0000000001})

    def test_hash_distinguishes_values_above_precision(self):
        assert content_hash_of({"x": 2.0}) != content_hash_of({"x": 2.00001})

    def test_negative_zero_normalises(self):
        assert content_hash_of({"x": -0.0}) == content_hash_of({"x": 0.0})

    def test_canonical_json_has_no_whitespace_and_sorted_keys(self):
        assert canonical_json({"b": "x", "a": "y"}) == '{"a":"y","b":"x"}'

    def test_integers_and_floats_of_equal_value_share_an_identity(self):
        # A count of 1 and a count of 1.0 are the same fact. This mirrors the
        # planning engine's canonicalisation so hashes computed on either side
        # are comparable without a translation layer.
        assert content_hash_of({"n": 1}) == content_hash_of({"n": 1.0})
        assert canonical_json({"n": 1}) == '{"n":1.0}'

    def test_parse_utc_refuses_naive_timestamps(self):
        # A naive timestamp in an awareness record silently moves a legal deadline.
        with pytest.raises(ValueError, match="no timezone"):
            parse_utc("2026-09-19T06:30:00")

    def test_parse_utc_normalises_offsets(self):
        berlin = parse_utc("2026-09-19T08:30:00+02:00")
        assert format_utc(berlin) == "2026-09-19T06:30:00Z"

    def test_format_utc_drops_subsecond_precision(self):
        moment = datetime(2026, 9, 19, 6, 30, 0, 123456, tzinfo=UTC)
        assert format_utc(moment) == "2026-09-19T06:30:00Z"


def _evidence(**overrides) -> Evidence:
    defaults = {
        "kind": "test.record",
        "body": {"value": 1},
        "actor": Actor("m.braun", "engineer"),
        "origin": Origin("unit-test", reference="TEST-1", method="constructed"),
    }
    defaults.update(overrides)
    return Evidence(**defaults)


class TestEvidence:
    def test_satisfies_the_protocol_structurally(self):
        assert isinstance(_evidence().seal(), EvidenceObject)

    def test_sealing_fixes_the_hash_and_verifies(self):
        sealed = _evidence().seal()
        assert sealed.is_sealed
        assert sealed.verify()

    def test_identity_excludes_recording_time(self):
        # Two identical facts recorded a second apart are the same fact.
        first = _evidence().seal()
        second = _evidence().seal()
        assert first.content_hash == second.content_hash

    def test_identity_includes_declared_gaps(self):
        without = _evidence().seal()
        with_gap = _evidence(checks_skipped=("did not check X",)).seal()
        assert without.content_hash != with_gap.content_hash

    def test_double_sealing_is_refused(self):
        sealed = _evidence().seal()
        with pytest.raises(SealedObjectError, match="already sealed"):
            sealed.seal()

    def test_unattributed_evidence_is_refused(self):
        with pytest.raises(EvidenceIncompleteError, match="no actor"):
            _evidence(actor=Actor("")).seal()

    def test_evidence_without_origin_is_refused(self):
        with pytest.raises(EvidenceIncompleteError, match="no origin"):
            _evidence(origin=Origin("")).seal()

    def test_supersede_points_back_and_leaves_the_original_intact(self):
        original = _evidence().seal()
        successor = original.supersede(body={"value": 2})
        assert successor.relations[-1].relation == "supersedes"
        assert successor.relations[-1].content_hash == original.content_hash
        assert original.body == {"value": 1}
        assert original.verify()

    def test_superseding_an_unsealed_object_is_refused(self):
        with pytest.raises(SealedObjectError):
            _evidence().supersede(body={})

    def test_round_trip_through_json_preserves_the_hash(self):
        sealed = _evidence(
            validation_state=ValidationState.VERIFIED,
            confidence=Confidence.HIGH,
            checks_skipped=("one gap",),
        ).seal()
        restored = Evidence.from_dict(json.loads(json.dumps(sealed.to_dict())))
        assert restored.content_hash == sealed.content_hash
        assert restored.verify()

    def test_mutation_after_sealing_is_detectable(self):
        sealed = _evidence().seal()
        forged = Evidence.from_dict({**sealed.to_dict(), "body": {"value": 999}})
        assert not forged.verify()


class TestValidationState:
    def test_only_verified_is_dependable(self):
        dependable = [s for s in ValidationState if s.is_dependable]
        assert dependable == [ValidationState.VERIFIED]


class TestAssuranceTier:
    def test_tiers_are_ordered(self):
        assert (
            AssuranceTier.PROFILE
            < AssuranceTier.COMMUNITY
            < AssuranceTier.VALIDATED
            < AssuranceTier.CERTIFIED
        )

    def test_simulation_does_not_entitle_a_claim_about_hardware(self):
        # The distinction this vocabulary exists to keep: passing a contract
        # suite against a simulator says nothing about a real gripper.
        assert not AssuranceTier.COMMUNITY.may_claim_physical_behaviour
        assert AssuranceTier.VALIDATED.may_claim_physical_behaviour

    def test_only_certified_may_assert_conformity(self):
        entitled = [t for t in AssuranceTier if t.may_claim_conformity]
        assert entitled == [AssuranceTier.CERTIFIED]

    def test_every_tier_states_its_evidence(self):
        for tier in AssuranceTier:
            assert tier.evidence_required.strip()
