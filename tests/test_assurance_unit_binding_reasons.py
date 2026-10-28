"""The reason the unit binding held a verification at community reaches the person who must act.

Regression (round-2 review, F3): a legacy or second-claimant bundle that IS attested is held at
``community`` by the unit binding (it was sealed without, or for another, unit key), but the
re-verification case said "a trace's declared provenance is capped ... a recorder attestation is
needed" and the fleet panel hard-coded "a provenance the filer declared": the operator was sent
to re-attest instead of re-sealing under the exact unit key.

- ``blocked_reason`` has its own code, ``below_validated_unit_binding``, and names the remedy;
  ``below_validated_tier`` stays for declared provenance.
- the case's ``checks_skipped`` carries the record's own reason;
- every fleet row carries ``tier_notes`` (the reasons, JSON + TS + panel text).
"""

from __future__ import annotations

from assurance.change import advance, claim, reverify
from assurance.change.model import CaseStatus
from assurance.change.service import blocked_reason
from assurance.fleet.registry import Fleet
from assurance.machinery.record import interventions_from_ledger, record_manifest
from assurance.machinery.staleness import VerificationRecord

from .support_recorder import build_attested_bundle
from .support_trust_hardening import KEY, attested_bundle
from .support_trust_hardening import ledger as make_ledger
from .support_trust_hardening import manifest as fleet_manifest
from .test_assurance_change import (
    ENG,
    LATER,
    MACHINE,
    REVIEWER,
    UTC,
    _inputs,
    datetime,
    drift,
    manifest,
    seal_a_real_verification,
)
from .test_assurance_change import _pinned_clock as _clock
from .test_assurance_change import ledger as _ledger
from .test_assurance_change import store as _store

# the fixtures of the change tests (this module relies on their pinned clock too)
ledger, store, _pinned_clock = _ledger, _store, _clock


def _awaiting(ledger, store):
    record_manifest(ledger, manifest(manifest_id="BASE"))
    seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
    case, observed = drift(store, ledger)
    case = claim(store, case.case_id, owner="v.grimaldi", actor=REVIEWER)
    case = advance(store, case.case_id, actor=REVIEWER)
    case = advance(store, case.case_id, actor=REVIEWER)
    assert case.status is CaseStatus.AWAITING_REVERIFICATION
    return case, observed


def _reverify_with(ledger, store, case, observed, bundle):
    ledger.append(bundle.evidence, subject=MACHINE.key)
    return reverify(
        store, case.case_id, observed,
        VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
        interventions_from_ledger(ledger, MACHINE.key),
        verification_content_hash=bundle.content_hash, actor=REVIEWER)


def test_an_attested_legacy_bundle_is_blocked_by_its_unit_binding_not_a_missing_attestation(
        ledger, store):
    case, observed = _awaiting(ledger, store)
    env, run = _inputs(LATER, "legacy")
    legacy = build_attested_bundle(env, run, actor=ENG, machine_serial=MACHINE.serial)
    assert legacy.tier.value == "validated" and "unit_key" not in legacy.evidence.body
    case = _reverify_with(ledger, store, case, observed, legacy)
    reason = blocked_reason(case)
    assert reason["code"] == "below_validated_unit_binding"
    assert set(reason["entries"].values()) == {"below_validated_unit_binding:community"}
    assert reason["tiers"] == ["community"]
    message = reason["message"]
    assert "unit key" in message and MACHINE.key in message or "--subject" in message
    assert "recorder attestation is needed" not in message.lower()
    # the record's own reason is on the case
    assert any("sealed without a unit key" in c for c in case.checks_skipped)


def test_a_declared_provenance_bundle_keeps_the_old_code(ledger, store):
    case, observed = _awaiting(ledger, store)
    env, run = _inputs(LATER, "declared")
    from assurance.machine.bundle import build_bundle
    declared = build_bundle(env, run, actor=ENG, subject=MACHINE.key)
    assert declared.tier.value == "community"
    case = _reverify_with(ledger, store, case, observed, declared)
    reason = blocked_reason(case)
    assert reason["code"] == "below_validated_tier"
    assert set(reason["entries"].values()) == {"below_validated:community"}


class TestTheFleetRow:
    def test_a_unit_binding_reason_is_on_the_row(self, tmp_path):
        from .support_trust_hardening import legacy_bundle
        led = make_ledger(tmp_path)
        record_manifest(led, fleet_manifest())
        bundle, rec = legacy_bundle("0001")
        led.append(bundle.evidence, subject=KEY)
        row = Fleet.from_ledger(led, recorder_trust=rec.trust()).to_dict()["machines"][0]
        assert row["verdict"] == "covered_at_community"
        assert len(row["tier_notes"]) == 1
        assert row["tier_notes"][0].startswith("it was sealed without a unit key")

    def test_a_validated_row_has_no_notes(self, tmp_path):
        led = make_ledger(tmp_path)
        record_manifest(led, fleet_manifest())
        _, rec = attested_bundle(KEY, file_under=led)
        row = Fleet.from_ledger(led, recorder_trust=rec.trust()).to_dict()["machines"][0]
        assert row["evidence_tier_floor"] == "validated"
        assert row["tier_notes"] == []

    def test_a_declared_provenance_row_has_no_notes_either(self, tmp_path):
        from .support_trust_hardening import community_bundle
        led = make_ledger(tmp_path)
        record_manifest(led, fleet_manifest())
        community_bundle(KEY, file_under=led)
        row = Fleet.from_ledger(led).to_dict()["machines"][0]
        assert row["verdict"] == "covered_at_community" and row["tier_notes"] == []
