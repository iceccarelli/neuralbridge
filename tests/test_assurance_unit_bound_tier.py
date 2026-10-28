"""A unit's ``validated`` tier must rest on that unit's recorder.

Regression: ``VerificationRecord.from_ledger`` re-assessed a recorded attestation without the
unit serial, so a bundle sealed for a product line (no serial) accepted an attestation made
on unit A and was believed ``validated`` for unit B when filed under B's key. The honest
paths derive the serial from the subject; this closes the hand-appended case.
"""

from __future__ import annotations

from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle
from assurance.machinery.staleness import VerificationRecord
from tests.support_recorder import Recorder
from tests.test_assurance_machine_provenance import ACTOR, envelope, laptop_trace


def _tiers(tmp_path, bundle, subject, trust):
    ledger = EvidenceLedger(tmp_path / "ledger.db")
    ledger.append(bundle.evidence, subject=subject)
    return [r.tier for r in VerificationRecord.from_ledger(
        ledger, subject=subject, recorder_trust=trust)]


def _bundle(serial_sealed, attested_for):
    env, tr = envelope(), laptop_trace()
    rec = Recorder()
    att = rec.attest_for(env, tr, machine_serial=attested_for).to_dict()
    bundle = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[att],
                          recorder_trust=rec.trust(), machine_serial=serial_sealed)
    return bundle, rec.trust()


def test_a_bundle_sealed_for_the_unit_it_is_filed_under_stays_validated(tmp_path):
    bundle, trust = _bundle("UNIT-A", "UNIT-A")
    assert bundle.tier.value == "validated"
    assert _tiers(tmp_path, bundle, "mk/md#UNIT-A", trust) == ["validated"]


def test_the_same_bundle_filed_under_another_unit_is_not_validated(tmp_path):
    bundle, trust = _bundle("UNIT-A", "UNIT-A")
    assert _tiers(tmp_path, bundle, "mk/md#UNIT-B", trust) == ["community"]


def test_a_serial_less_bundle_carrying_unit_a_attestation_is_not_validated_for_b(tmp_path):
    """The reproduced case: sealed with no serial, attestation made on UNIT-A."""
    bundle, trust = _bundle("", "UNIT-A")
    assert bundle.tier.value == "validated"  # at seal time a product line needs no serial
    assert _tiers(tmp_path, bundle, "mk/md#UNIT-B", trust) == ["community"]


def test_a_product_line_subject_is_unchanged(tmp_path):
    bundle, trust = _bundle("", "UNIT-A")
    assert _tiers(tmp_path, bundle, "Cell@1.0.0", trust) == ["validated"]


def test_a_malformed_unit_key_cannot_be_tied_to_any_unit(tmp_path):
    bundle, trust = _bundle("UNIT-A", "UNIT-A")
    assert _tiers(tmp_path, bundle, "mk/md#", trust) == ["community"]
    assert _tiers(tmp_path, bundle, "mk/md#UNIT-A#X", trust) == ["community"]


def test_without_a_trust_list_the_unit_binding_still_applies(tmp_path):
    bundle, _ = _bundle("UNIT-A", "UNIT-A")
    ledger = EvidenceLedger(tmp_path / "l.db")
    ledger.append(bundle.evidence, subject="mk/md#UNIT-B")
    assert [r.tier for r in VerificationRecord.from_ledger(
        ledger, subject="mk/md#UNIT-B")] == ["community"]
