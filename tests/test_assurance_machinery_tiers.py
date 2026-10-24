"""A passport cannot read VERIFIED / HIGH on evidence below ``validated``.

Declared trace provenance is capped at ``community``. ``build_passport`` used to
seal ``verdict: covered`` as ``VERIFIED`` with ``HIGH`` confidence for such a
verification and leave the tier to a caveat. The state and confidence now follow
the tier floor of the evidence the cover rests on, in the builder and in the
checker anyone can run.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Confidence, ValidationState
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import build_passport, record_manifest, verify_passport
from assurance.machinery.staleness import VerificationRecord, assess_coverage

from .support_recorder_attestation import simulate_verified_recorder_attestation
from .test_assurance_machinery import (
    ENG,
    FUNCS,
    manifest,
    seal_a_real_verification,
    verification,
)

#: Only functions that declare checks, so a verification can cover every one of them.
DEMONSTRABLE = tuple(f for f in FUNCS if f.verified_by)


def covered_manifest():
    return manifest(functions=DEMONSTRABLE)


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "tiers.db")


def _tier(v, tier):
    return dataclasses.replace(v, tier=tier)


class TestTheFloorIsReported:
    def test_a_community_cover_has_a_community_floor(self):
        report = assess_coverage(covered_manifest(), [_tier(verification(), "community")], [])
        assert report.verdict == "covered"
        assert report.evidence_tier_floor == "community"
        assert report.to_dict()["evidence_tier_floor"] == "community"

    def test_the_floor_is_the_weakest_tier_a_current_function_rests_on(self):
        strong = verification(seq=1, verified=("ssm_separation", "stop_characterisation"))
        weak = _tier(verification(seq=2, verified=("speed_limit",)), "community")
        report = assess_coverage(covered_manifest(), [strong, weak], [])
        assert report.verdict == "covered"
        assert report.evidence_tier_floor == "community"

    def test_a_validated_cover_has_a_validated_floor_and_no_tier_caveat(self):
        report = assess_coverage(covered_manifest(), [verification()], [])
        assert report.evidence_tier_floor == "validated"
        assert not any("below 'validated'" in c for c in report.checks_skipped)

    def test_nothing_current_has_no_floor(self):
        assert assess_coverage(covered_manifest(), [], []).evidence_tier_floor == ""


class TestThePassportIsCappedAtTheFloor:
    def test_a_community_cover_is_not_verified_and_not_high(self, ledger):
        p = build_passport(ledger, covered_manifest(), actor=ENG,
                           verifications=[_tier(verification(), "community")],
                           interventions=[])
        assert p.verdict == "covered"
        assert p.evidence.body["evidence_tier_floor"] == "community"
        assert p.evidence.validation_state is ValidationState.INDETERMINATE
        assert p.evidence.confidence is Confidence.LOW
        assert any("below 'validated'" in c and "attestation" in c
                   for c in p.evidence.checks_skipped)

    def test_a_real_bundle_the_engine_sealed_is_capped_too(self, ledger):
        record_manifest(ledger, covered_manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        p = build_passport(ledger, covered_manifest(), actor=ENG, interventions=[])
        assert p.verdict == "covered"
        assert p.evidence.validation_state is not ValidationState.VERIFIED
        assert p.evidence.confidence not in (Confidence.HIGH, Confidence.ESTABLISHED)

    def test_a_validated_cover_is_still_verified_and_high(self, ledger):
        p = build_passport(ledger, covered_manifest(), actor=ENG,
                           verifications=[verification()], interventions=[])
        assert p.evidence.validation_state is ValidationState.VERIFIED
        assert p.evidence.confidence is Confidence.HIGH

    def test_an_attested_bundle_reaches_verified(self, ledger, monkeypatch):
        simulate_verified_recorder_attestation(monkeypatch)
        record_manifest(ledger, covered_manifest())
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        p = build_passport(ledger, covered_manifest(), actor=ENG, interventions=[])
        assert p.evidence.validation_state is ValidationState.VERIFIED
        assert p.evidence.confidence is Confidence.HIGH

    def test_the_cap_survives_a_round_trip_through_the_checker(self, ledger, tmp_path):
        p = build_passport(ledger, covered_manifest(), actor=ENG,
                           verifications=[_tier(verification(), "community")],
                           interventions=[]).write(tmp_path / "p.json")
        ok, problems = verify_passport(p)
        assert ok, problems


class TestTheCheckerRefusesAPassportThatIgnoresTheFloor:
    def _forged(self, ledger, tmp_path, *, state, confidence):
        """A community-floor passport resealed so it claims more than its floor allows."""
        p = build_passport(ledger, covered_manifest(), actor=ENG,
                           verifications=[_tier(verification(), "community")],
                           interventions=[]).write(tmp_path / "p.json")
        d = json.loads(p.read_text())
        ev = d["evidence"]
        ev["validation_state"] = state
        ev["confidence"] = confidence
        # Reseal so the hash is not what gives it away: only the claim's coherence is.
        from assurance.core.evidence import Evidence
        sealed = dataclasses.replace(Evidence.from_dict(ev), content_hash="").seal()
        d["evidence"] = sealed.to_dict()
        p.write_text(json.dumps(d))
        return p

    def test_a_resealed_verified_claim_on_a_community_floor_is_a_problem(
            self, ledger, tmp_path):
        p = self._forged(ledger, tmp_path, state="verified", confidence="low")
        ok, problems = verify_passport(p)
        assert not ok
        assert any("validation state" in x and "verified" in x for x in problems)

    def test_a_resealed_high_confidence_on_a_community_floor_is_a_problem(
            self, ledger, tmp_path):
        p = self._forged(ledger, tmp_path, state="indeterminate", confidence="high")
        ok, problems = verify_passport(p)
        assert not ok
        assert any("confidence" in x and "'validated'" in x for x in problems)

    def test_an_old_passport_without_a_floor_is_accepted_with_a_stated_limit(
            self, ledger, tmp_path):
        p = build_passport(ledger, covered_manifest(), actor=ENG,
                           verifications=[verification()], interventions=[]
                           ).write(tmp_path / "old.json")
        d = json.loads(p.read_text())
        from assurance.core.evidence import Evidence
        body = {k: v for k, v in d["evidence"]["body"].items() if k != "evidence_tier_floor"}
        d["evidence"]["body"] = body
        d["evidence"] = dataclasses.replace(
            Evidence.from_dict(d["evidence"]), content_hash="").seal().to_dict()
        p.write_text(json.dumps(d))
        ok, problems = verify_passport(p)
        assert ok, problems
        assert any("NOT CHECKED" in x and "tier floor" in x for x in problems)


class TestAHandBuiltRecordKeepsItsTier:
    def test_only_the_ledger_reader_caps_so_tests_can_still_build_validated_records(self):
        v = verification()
        assert isinstance(v, VerificationRecord) and v.tier == "validated"
