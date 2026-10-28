"""A unit's ``validated`` tier must rest on a bundle sealed for THAT unit's full key.

Regression (independent review of a135c0e, findings R1/R1b/M01/R10): PR #54 bound a unit's
``validated`` tier to the SERIAL only. A bundle validated for ``Acme/AR-7#0001`` and refiled
under ``Beta/XY-9#0001`` stayed ``validated``; through ``POST /v1/machine/verify`` one
attestation made both subjects read ``validated``; one recording could be the validated
evidence of two units in coverage, the passport and the fleet (only ``reverify`` refused it).

What the fix binds, and what it does not:

* the recorder key signs ``(product, product_version, machine_serial)`` and the recording
  window. Its ``machine_ref`` cannot carry a maker or model without changing the attestation
  format, and this change does not change that format;
* the SERVICE binds the verification to the unit key it was sealed for: ``unit_key`` is a field
  of the sealed bundle body (covered by the content hash) and the readers compare the WHOLE
  key, case- and whitespace-sensitively, with the ledger subject the bundle is filed under;
* a bundle sealed before that field existed (it names a serial and no maker/model) is
  capped at ``community`` under a unit-key subject: no silent grandfathering;
* the same recording may be the validated evidence of one unit key only; a second claimant is
  ``community`` with a named reason (``VerificationRecord.tier_note``).

An attestation proves what a key signed, not that the machine is safe.
"""

from __future__ import annotations

import sqlite3

import pytest

from assurance.fleet.registry import Fleet
from assurance.machine.bundle import BUNDLE_KIND, build_bundle, check_bundle_data
from assurance.machine.recorder_attestation import RecorderTrust
from assurance.machinery.record import build_passport, record_manifest
from assurance.machinery.staleness import (
    VerificationRecord,
    _believed_tier,
    _unit_binding,
    assess_coverage,
)

from .support_recorder import Recorder, server_trust, with_attestation
from .support_trust_hardening import (
    KEY,
    attested_bundle,
    community_bundle,
    ledger,
    legacy_bundle,
    manifest,
    reseal_body,
)
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_machine_provenance import ACTOR, envelope, laptop_trace
from .test_assurance_recorder_attestation import envelope as att_envelope
from .test_assurance_recorder_attestation import make_trace

client, store = _client, _store


def _read(led, subject, trust):
    return VerificationRecord.from_ledger(led, subject=subject, recorder_trust=trust)


def _tiers(tmp_path, evidence, subject, trust):
    led = ledger(tmp_path)
    led.append(evidence, subject=subject)
    return [r.tier for r in _read(led, subject, trust)]


class TestTheWholeUnitKeyIsCompared:
    def test_control_the_unit_it_was_sealed_for_is_validated(self, tmp_path):
        bundle, rec = attested_bundle(KEY)
        assert bundle.tier.value == "validated"
        assert _tiers(tmp_path, bundle.evidence, KEY, rec.trust()) == ["validated"]

    @pytest.mark.parametrize("other", [
        "Beta/XY-9#0001",        # the reviewer's case: other maker AND model, same serial
        "Beta/AR-7#0001",        # other maker
        "Acme/XY-9#0001",        # other model
        "acme/AR-7#0001",        # case variants are distinct units: fail closed
        "Acme/ar-7#0001",
        " Acme/AR-7#0001",       # leading whitespace
        "Acme /AR-7#0001",
        "Acme/AR-7 #0001",
        "Аcme/AR-7#0001",   # Cyrillic capital A
        "Acme/AR-7#0001​",  # zero-width space
    ])
    def test_a_bundle_sealed_for_one_unit_is_community_under_any_other_key(
            self, tmp_path, other):
        bundle, rec = attested_bundle(KEY)
        assert _tiers(tmp_path, bundle.evidence, other, rec.trust()) == ["community"]

    def test_the_same_holds_with_no_trust_list_at_all(self, tmp_path):
        bundle, _ = attested_bundle(KEY)
        assert _tiers(tmp_path, bundle.evidence, "Beta/XY-9#0001", None) == ["community"]

    def test_and_the_exact_key_is_validated_with_no_trust_list(self, tmp_path):
        bundle, _ = attested_bundle(KEY)
        assert _tiers(tmp_path, bundle.evidence, KEY, None) == ["validated"]

    def test_the_unit_key_is_part_of_the_sealed_body(self):
        bundle, _ = attested_bundle(KEY)
        assert bundle.evidence.body["unit_key"] == KEY
        assert bundle.evidence.body["machine_serial"] == "0001"
        # editing it breaks the seal: it is hashed content, not a label beside it
        forged = {**bundle.evidence.to_dict(),
                  "body": {**bundle.evidence.body, "unit_key": "Beta/XY-9#0001"}}
        from assurance.core.evidence import Evidence
        assert Evidence.from_dict(forged).verify() is False

    def test_a_product_line_bundle_records_no_unit_key(self):
        b = build_bundle(envelope(), laptop_trace(), actor=ACTOR)
        assert "unit_key" not in b.evidence.body

    def test_a_product_line_subject_is_unchanged(self, tmp_path):
        bundle, rec = attested_bundle(KEY)
        assert _tiers(tmp_path, bundle.evidence, "Cell@1.0.0", rec.trust()) == ["validated"]


class TestOldBundlesAreNotGrandfathered:
    def test_a_serial_only_bundle_is_community_under_a_unit_key(self, tmp_path):
        bundle, rec = legacy_bundle("0001")
        assert bundle.tier.value == "validated"          # at seal time: a product line
        assert "unit_key" not in bundle.evidence.body
        assert _tiers(tmp_path, bundle.evidence, KEY, rec.trust()) == ["community"]

    def test_a_serial_only_bundle_is_community_without_a_trust_list_too(self, tmp_path):
        bundle, _ = legacy_bundle("0001")
        assert _tiers(tmp_path, bundle.evidence, KEY, None) == ["community"]

    def test_the_reader_names_why_a_serial_only_bundle_is_not_validated(self, tmp_path):
        bundle, rec = legacy_bundle("0001")
        led = ledger(tmp_path)
        led.append(bundle.evidence, subject=KEY)
        (record,) = _read(led, KEY, rec.trust())
        assert record.tier == "community"
        assert record.tier_note.startswith("it was sealed without a unit key")
        assert record.to_dict()["tier_note"] == record.tier_note

    def test_a_serial_less_bundle_is_community_under_a_unit_key(self, tmp_path):
        bundle, rec = legacy_bundle("")
        assert _tiers(tmp_path, bundle.evidence, KEY, rec.trust()) == ["community"]

    def test_the_passport_and_fleet_do_not_cover_on_a_serial_only_bundle(self, tmp_path):
        led = ledger(tmp_path)
        man = manifest()
        record_manifest(led, man)
        bundle, rec = legacy_bundle("0001")
        led.append(bundle.evidence, subject=KEY)
        passport = build_passport(led, man, actor=ACTOR, seal=False, recorder_trust=rec.trust())
        assert passport.coverage.evidence_tier_floor == "community"
        row = Fleet.from_ledger(led, recorder_trust=rec.trust()).to_dict()["machines"][0]
        assert row["evidence_tier_floor"] == "community"


class TestMalformedUnitKeys:
    """Survivor M01: a serial-less bundle under ``mk/md#`` must not read validated."""

    def test_a_serial_less_bundle_under_a_malformed_key_is_community(self, tmp_path):
        bundle, rec = legacy_bundle("")
        assert _tiers(tmp_path, bundle.evidence, "mk/md#", rec.trust()) == ["community"]

    def test_a_serial_less_bundle_under_a_key_with_two_hashes_is_community(self, tmp_path):
        bundle, rec = legacy_bundle("")
        assert _tiers(tmp_path, bundle.evidence, "mk/md#A#B", rec.trust()) == ["community"]

    def test_the_serial_in_the_key_must_be_the_serial_sealed_even_with_no_trust_list(
            self, tmp_path):
        """No list to re-assess the attestation under: the body's own serial is the guard."""
        bundle, _ = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, unit_key="Acme/AR-7#0002")
        assert _tiers(tmp_path, forged, "Acme/AR-7#0002", None) == ["community"]
        ledger_note = ledger(tmp_path, "n.db")
        ledger_note.append(forged, subject="Acme/AR-7#0002")
        (record,) = _read(ledger_note, "Acme/AR-7#0002", None)
        assert "matched against serial '0001', not '0002'" in record.tier_note

    def test_a_forged_body_naming_a_malformed_key_is_community(self, tmp_path):
        """Reseal a body that records the malformed key itself: only the well-formedness
        test stops this (the key and the empty serial otherwise 'match')."""
        bundle, rec = legacy_bundle("")
        forged = reseal_body(bundle.evidence, unit_key="mk/md#", machine_serial="")
        assert _tiers(tmp_path, forged, "mk/md#", rec.trust()) == ["community"]
        assert _unit_binding("mk/md#").well_formed is False
        assert _believed_tier(forged.body, rec.trust(), _unit_binding("mk/md#")) == "community"

    def test_the_serial_in_the_key_must_be_the_serial_sealed(self, tmp_path):
        """A body whose unit key says #0002 but whose attestation is for 0001."""
        bundle, rec = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, unit_key="Acme/AR-7#0002")
        assert _tiers(tmp_path, forged, "Acme/AR-7#0002", rec.trust()) == ["community"]


class TestTheCoherenceOfTheField:
    def test_a_sealed_unit_key_bundle_replays_and_is_reproduced(self):
        env, tr = envelope(), laptop_trace()
        bundle, rec = attested_bundle(KEY, trace=tr)
        check = check_bundle_data(bundle.to_dict(), envelope=env, trace=tr,
                                  recorder_trust=rec.trust())
        assert check.ok, check.problems
        assert check.level == "reproduced"
        assert check.believed_tier == "validated"

    def test_a_unit_key_whose_serial_is_not_the_sealed_serial_is_rejected(self):
        bundle, rec = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, unit_key="Acme/AR-7#0002")
        raw = {**bundle.to_dict(), "evidence": forged.to_dict()}
        check = check_bundle_data(raw, recorder_trust=rec.trust())
        assert check.ok is False
        assert check.believed_tier == "community"

    def test_a_malformed_unit_key_in_a_bundle_is_rejected(self):
        bundle, rec = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, unit_key="mk/md#")
        raw = {**bundle.to_dict(), "evidence": forged.to_dict()}
        assert check_bundle_data(raw, recorder_trust=rec.trust()).ok is False

    def test_a_unit_key_that_is_not_text_is_rejected(self):
        bundle, rec = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, unit_key=["Acme/AR-7#0001"])
        raw = {**bundle.to_dict(), "evidence": forged.to_dict()}
        assert check_bundle_data(raw, recorder_trust=rec.trust()).ok is False

    def test_an_old_bundle_without_the_field_still_checks_and_replays(self):
        env, tr = envelope(), laptop_trace()
        bundle, rec = legacy_bundle("0001", trace=tr)
        check = check_bundle_data(bundle.to_dict(), envelope=env, trace=tr,
                                  recorder_trust=rec.trust())
        assert check.ok, check.problems
        assert check.level == "reproduced"


class TestOneRecordingIsOneUnit:
    """The same recording may be the validated evidence of one unit key only."""

    def _two_units(self, tmp_path, *, first, second):
        """The same trace, each unit attested by the same trusted recorder for its own serial."""
        led = ledger(tmp_path)
        rec, tr = Recorder(), laptop_trace()
        for key in (first, second):
            record_manifest(led, manifest(*_maker_model_serial(key)))
        b1, _ = attested_bundle(first, rec=rec, trace=tr)
        b2, _ = attested_bundle(second, rec=rec, trace=tr)
        led.append(b1.evidence, subject=first)
        led.append(b2.evidence, subject=second)
        return led, rec

    def test_the_second_claimant_is_community_with_a_named_reason(self, tmp_path):
        first, second = KEY, "Beta/XY-9#0002"
        led, rec = self._two_units(tmp_path, first=first, second=second)
        (a,) = _read(led, first, rec.trust())
        (b,) = _read(led, second, rec.trust())
        assert a.tier == "validated"
        assert b.tier == "community"
        assert first in b.tier_note and "recording" in b.tier_note
        assert a.tier_note == ""

    def test_the_order_of_filing_decides_not_the_alphabet(self, tmp_path):
        first, second = "Beta/XY-9#0002", KEY
        led, rec = self._two_units(tmp_path, first=first, second=second)
        assert [r.tier for r in _read(led, first, rec.trust())] == ["validated"]
        assert [r.tier for r in _read(led, second, rec.trust())] == ["community"]

    def test_the_same_serial_in_two_makers_also_conflicts(self, tmp_path):
        first, second = KEY, "Beta/XY-9#0001"
        led, rec = self._two_units(tmp_path, first=first, second=second)
        assert [r.tier for r in _read(led, first, rec.trust())] == ["validated"]
        assert [r.tier for r in _read(led, second, rec.trust())] == ["community"]

    def test_coverage_the_passport_and_the_fleet_all_cap_the_second(self, tmp_path):
        first, second = KEY, "Beta/XY-9#0002"
        led, rec = self._two_units(tmp_path, first=first, second=second)
        man2 = manifest("Beta", "XY-9", "0002")
        report = assess_coverage(man2, _read(led, second, rec.trust()), [])
        assert report.verdict == "covered_at_community"
        assert report.evidence_tier_floor == "community"
        assert any("recording" in c and first in c for c in report.checks_skipped)
        passport = build_passport(led, man2, actor=ACTOR, seal=False,
                                  recorder_trust=rec.trust())
        assert passport.coverage.evidence_tier_floor == "community"
        rows = {r["machine"]: r for r in
                Fleet.from_ledger(led, recorder_trust=rec.trust()).to_dict()["machines"]}
        assert rows[first]["evidence_tier_floor"] == "validated"
        assert rows[second]["evidence_tier_floor"] == "community"

    def test_the_same_recording_refiled_under_the_same_unit_is_not_a_conflict(
            self, tmp_path):
        led = ledger(tmp_path)
        bundle, rec = attested_bundle(KEY)
        led.append(bundle.evidence, subject=KEY)
        led.append(bundle.evidence, subject=KEY)
        assert [r.tier for r in _read(led, KEY, rec.trust())] == ["validated", "validated"]

    def test_a_community_copy_filed_first_does_not_take_the_validated_place(
            self, tmp_path):
        """Only a claim that would itself be validated is a claimant."""
        led = ledger(tmp_path)
        rec, tr = Recorder(), laptop_trace()
        led.append(community_bundle("Beta/XY-9#0002", trace=tr).evidence,
                   subject="Beta/XY-9#0002")
        good, _ = attested_bundle(KEY, rec=rec, trace=tr)
        led.append(good.evidence, subject=KEY)
        assert [r.tier for r in _read(led, KEY, rec.trust())] == ["validated"]

    def test_a_filing_the_unit_binding_already_caps_claims_nothing(self, tmp_path):
        """Stored 'validated' but filed under a key it was not sealed for: it reads community
        and so is no claim on the recording either."""
        led = ledger(tmp_path)
        rec, tr = Recorder(), laptop_trace()
        stray, _ = legacy_bundle("0002", rec=rec, trace=tr)     # sealed with a serial only
        assert stray.tier.value == "validated"
        led.append(stray.evidence, subject="Beta/XY-9#0002")
        good, _ = attested_bundle(KEY, rec=rec, trace=tr)
        led.append(good.evidence, subject=KEY)
        assert [r.tier for r in _read(led, "Beta/XY-9#0002", rec.trust())] == ["community"]
        assert [r.tier for r in _read(led, KEY, rec.trust())] == ["validated"]

    def test_an_entry_that_fails_its_own_seal_claims_nothing(self, tmp_path):
        """A tampered earlier filing is skipped everywhere; it does not take the recording."""
        import json
        first, second = "Beta/XY-9#0002", KEY
        led, rec = self._two_units(tmp_path, first=first, second=second)
        db = sqlite3.connect(led.path)
        seq, payload = db.execute(
            "select seq,payload from chain where subject=? and kind=?",
            (first, BUNDLE_KIND)).fetchone()
        p = json.loads(payload)
        p["body"]["verdict"] = "pass-edited"
        db.execute("update chain set payload=? where seq=?",
                   (json.dumps(p, sort_keys=True, separators=(",", ":")), seq))
        db.commit()
        db.close()
        assert _read(led, first, rec.trust()) == []
        (mine,) = _read(led, second, rec.trust())
        assert mine.tier == "validated" and mine.tier_note == ""

    def test_it_holds_without_a_trust_list_too(self, tmp_path):
        first, second = KEY, "Beta/XY-9#0002"
        led, _ = self._two_units(tmp_path, first=first, second=second)
        assert [r.tier for r in _read(led, first, None)] == ["validated"]
        assert [r.tier for r in _read(led, second, None)] == ["community"]


def _maker_model_serial(key: str) -> tuple[str, str, str]:
    head, _, serial = key.partition("#")
    maker, _, model = head.partition("/")
    return maker, model, serial


class TestTheHostedRoute:
    """``POST /v1/machine/verify``: one attestation must not make two units validated."""

    @staticmethod
    def _verify(client, headers, subject, serial="0001"):
        env, tr = att_envelope(), make_trace()
        body = with_attestation({
            "envelope": env.to_dict(), "trace": tr.hashable_payload(),
            "actor": "a.integrator", "subject": subject}, env, tr, machine_serial=serial)
        return client.post("/v1/machine/verify", json=body, headers=headers)

    @staticmethod
    def _enrol(client, headers, *units):
        """Only a claim under an ENROLLED unit key holds a recording (a manifest was sealed)."""
        for maker, model, serial in units:
            r = client.post("/v1/machinery/manifest",
                            json={"manifest": manifest(maker, model, serial).to_dict()},
                            headers=headers)
            assert r.status_code == 200, r.text

    def test_the_same_attestation_for_another_makers_unit_is_refused(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        self._enrol(client, h, ("Acme", "AR-7", "0001"), ("Beta", "XY-9", "0001"))
        a = self._verify(client, h, "Acme/AR-7#0001")
        assert a.status_code == 200 and a.json()["tier"] == "validated"
        b = self._verify(client, h, "Beta/XY-9#0001")
        assert b.status_code == 422
        assert b.json()["detail"]["error"] == "invalid_subject"
        assert "Acme/AR-7#0001" in b.json()["detail"]["detail"]

    def test_one_recording_cannot_be_validated_for_two_serials(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        self._enrol(client, h, ("Acme", "AR-7", "0001"), ("Acme", "AR-7", "0002"))
        assert self._verify(client, h, "Acme/AR-7#0001", "0001").json()["tier"] == "validated"
        b = self._verify(client, h, "Acme/AR-7#0002", "0002")
        assert b.status_code == 422

    def test_a_refused_second_claim_seals_nothing(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        self._enrol(client, h, ("Acme", "AR-7", "0001"), ("Beta", "XY-9", "0001"))
        self._verify(client, h, "Acme/AR-7#0001")
        before = client.get("/v1/ledger/verify", headers=h)
        assert before.status_code == 200 and before.json()["verified"] is True
        refused = self._verify(client, h, "Beta/XY-9#0001")
        assert refused.status_code == 422
        after = client.get("/v1/ledger/verify", headers=h)
        stable = ("length", "head_seq", "head_link_hash")      # not `attested_at`, a clock
        assert {k: after.json()["attestation"][k] for k in stable} == \
            {k: before.json()["attestation"][k] for k in stable}
        assert before.json()["attestation"]["length"] >= 1

    def test_the_same_recording_for_the_same_unit_again_is_fine(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        self._enrol(client, h, ("Acme", "AR-7", "0001"))    # a holder exists: it is this unit
        for _ in range(2):
            r = self._verify(client, h, "Acme/AR-7#0001")
            assert r.status_code == 200 and r.json()["tier"] == "validated"

    def test_without_seal_nothing_is_compared_or_written(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        env, tr = att_envelope(), make_trace()
        for subject in ("Acme/AR-7#0001", "Beta/XY-9#0001"):
            body = with_attestation({
                "envelope": env.to_dict(), "trace": tr.hashable_payload(),
                "actor": "a.integrator", "subject": subject, "seal": False},
                env, tr, machine_serial="0001")
            assert client.post("/v1/machine/verify", json=body, headers=h).status_code == 200


class TestCertifiedIsNeverRead:
    """L1: nothing in this product certifies; a resealed 'certified' body reads 'validated' at most."""

    def test_a_resealed_certified_body_is_not_read_as_certified(self, tmp_path):
        bundle, rec = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, tier="certified")
        tiers = _tiers(tmp_path, forged, KEY, rec.trust())
        assert tiers != ["certified"]
        assert tiers == ["validated"]

    def test_the_cap_applies_without_a_trust_list(self, tmp_path):
        bundle, _ = attested_bundle(KEY)
        forged = reseal_body(bundle.evidence, tier="certified")
        assert _tiers(tmp_path, forged, KEY, None) == ["validated"]

    def test_a_certified_body_with_no_attestation_is_still_only_community(self, tmp_path):
        bundle = community_bundle(KEY)
        forged = reseal_body(bundle.evidence, tier="certified")
        assert _tiers(tmp_path, forged, KEY, Recorder().trust()) == ["community"]


class TestSurvivorKillers:
    """Tests the shipped suite lacked: each fails under the mutant named in its docstring."""

    def test_m30_the_attestation_the_body_cites_must_be_the_one_that_is_accepted(
            self, tmp_path):
        """Dropping the attestation-hash equality in ``_reproduces``: a body that cites a
        forged attestation Y (untrusted key) while also carrying a genuine one X reads
        validated on X's acceptance."""
        env, tr = envelope(), laptop_trace()
        trusted, stranger = Recorder("trusted"), Recorder("stranger")
        real = trusted.attest_for(env, tr, machine_serial="0001").to_dict()
        fake = stranger.attest_for(env, tr, machine_serial="0001").to_dict()
        both_trust = RecorderTrust([*trusted.trust().recorders,
                                    *stranger.trust().recorders])
        bundle = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[fake],
                              recorder_trust=both_trust, subject=KEY)
        assert bundle.tier.value == "validated"
        rec_block = bundle.evidence.body["recorder_attestation"]
        forged = reseal_body(bundle.evidence, recorder_attestation={
            **rec_block, "attestations": [*rec_block["attestations"], real]})
        # the reader trusts only the genuine recorder
        assert _tiers(tmp_path, forged, KEY, trusted.trust()) == ["community"]

    def test_m14_the_tier_floor_is_the_weakest_run_the_cover_rests_on(self):
        from datetime import UTC, datetime, timedelta

        def rec(seq, days, tier, verified):
            return VerificationRecord(
                content_hash=f"{seq:064x}", effective_at=datetime(2026, 1, 1, tzinfo=UTC)
                + timedelta(days=days), ledger_seq=seq, product="p", product_version="1",
                verdict="pass", tier=tier, checks_verified=tuple(verified),
                checks_not_verified=())
        report = assess_coverage(
            manifest(), [rec(1, 1, "validated", ("workspace_containment",)),
                         rec(2, 2, "community", ("speed_limit",))], [])
        assert report.functions[0].coverage.value == "current"
        assert report.evidence_tier_floor == "community"
        assert report.verdict == "covered_at_community"

    def test_m31_a_verification_that_fails_its_seal_is_not_read(self, tmp_path):
        import json
        bundle, rec = attested_bundle(KEY)
        led = ledger(tmp_path)
        led.append(bundle.evidence, subject=KEY)
        db = sqlite3.connect(led.path)
        seq, payload = db.execute("select seq,payload from chain").fetchone()
        p = json.loads(payload)
        p["body"]["verdict"] = "pass-edited"
        db.execute("update chain set payload=? where seq=?",
                   (json.dumps(p, sort_keys=True, separators=(",", ":")), seq))
        db.commit()
        db.close()
        assert _read(led, KEY, rec.trust()) == []
