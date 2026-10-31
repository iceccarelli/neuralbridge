"""Recorder attestation: the only route above the declared-provenance cap.

A trace's ``provenance`` is a word its filer writes. A signed recorder attestation,
assessed against a trust list the VERIFIER holds, is the one thing that can let it reach
its own ceiling -- and it proves only that a trusted key signed these exact trace bytes.

The tests that matter are the refusals: no trust configured, an unknown / revoked /
wrong-class key, a bad signature, every signed field tampered with, a trace edited after
signing, an attestation for another trace or machine, replays, stale / expired dates,
malformed / smuggled / mistyped JSON, cross-protocol signatures, a private key supplied,
a trust list smuggled inside a bundle, and a resealed bundle that merely claims the basis.
Each guard here was removed once to see a test fail (see the mutation table in the PR).
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.attest.attestation import AttestationLog, attest
from assurance.attest.keys import SigningKey
from assurance.core.evidence import Actor, Evidence
from assurance.core.tiers import AssuranceTier
from assurance.evidence.ledger import EvidenceLedger
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
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.limits_review import LimitsReview
from assurance.machine.recorder_attestation import (
    ATTESTATION_FORMAT,
    MAX_ATTESTATIONS,
    MAX_LAG_DAYS,
    SIGNING_PREFIX,
    TRUST_FORMAT,
    AttestationStatus,
    MachineRef,
    RecorderAttestation,
    RecorderAttestationError,
    RecorderTrust,
    TrustedRecorder,
    assess_recorder_attestation,
    load_attestation_file,
    loads_strict,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import ENGINE_VERSION, verify

from .support_recorder import (
    RECORDER,
    Recorder,
    attested,
    build_attested_bundle,
    server_trust,
    with_attestation,
)
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store

client = _client
store = _store

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
START = datetime(2026, 9, 12, 4, 31, tzinfo=UTC)
# Bundles are sealed against the real clock, so an expiry must be relative to it: a fixed date
# stops sealing the day after it passes (this failed on 2026-10-31 with "2026-10-30").
_TODAY = datetime.now(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
_EXPIRES = (_TODAY + timedelta(days=30)).date().isoformat()
MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
DATASHEET = FigureBasis(kind="datasheet", reference="scanner rev D")
ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")
REF = MachineRef("Cell", "1.0.0")
CHECK_URL = "/v1/machine/bundle/check"


def envelope(**over) -> SafetyEnvelope:
    kw = {
        "envelope_id": "ENV-1", "product": "Cell", "product_version": "1.0.0",
        "workspace": Workspace(minimum=(-1000.0, -1000.0, 0.0),
                               maximum=(1000.0, 1000.0, 2000.0)),
        "max_tcp_speed_mm_s": {OperatingMode.SSM: 500.0},
        "stop": StopPerformance(reaction_time_s=0.1, stop_time_s=0.25,
                                stop_distance_mm=120.0, measured_at_speed_mm_s=500.0,
                                basis=MEASURED),
        "uncertainty": SensingUncertainty(human_position_mm=100.0,
                                          robot_position_mm=50.0, basis=MEASURED),
        "intrusion_distance_mm": 850.0,
    }
    kw.update(over)
    return SafetyEnvelope(**kw)


def make_trace(provenance=Provenance.FIELD, *, trace_id="RUN-1", sep=3000.0, n=20,
               started_at=START, source_system="controller fw 1.0", conditions=None) -> Trace:
    return Trace(
        trace_id=trace_id, provenance=provenance, source_system=source_system,
        started_at=started_at, sample_rate_hz=50.0, conditions=conditions or {},
        samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                             mode=OperatingMode.SSM, separation=sep) for i in range(n)))


def resign(att: RecorderAttestation, key: SigningKey, **changes) -> RecorderAttestation:
    """Re-sign a hand-modified attestation: the key holder lying, not an outsider forging."""
    unsigned = replace(att, signature="", **changes)
    sig = base64.b64encode(key.sign(unsigned.signed_payload())).decode("ascii")
    return replace(unsigned, signature=sig)


def assess(trace, atts, trust, *, ref=REF, now=NOW):
    return assess_recorder_attestation(trace, atts, trust, machine_ref=ref, now=now)


def run(trace, atts, trust, env_=None, **kw):
    return verify(env_ or envelope(), trace, recorder_attestations=atts,
                  recorder_trust=trust, now=NOW, **kw)


def statuses(a):
    return [f.status for f in a.findings]


def private_pem() -> str:
    from cryptography.hazmat.primitives import serialization

    return RECORDER.key.private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()


def reseal(raw: dict) -> dict:
    raw["evidence"]["content_hash"] = Evidence.from_dict(raw["evidence"]).compute_hash()
    return raw


def sealed(trace=None, *, recorder=None, **kw) -> tuple[dict, SafetyEnvelope, Trace]:
    env, tr = envelope(), trace or make_trace()
    raw = build_attested_bundle(env, tr, actor=ACTOR, recorder=recorder or RECORDER, **kw)
    return json.loads(json.dumps(raw.to_dict())), env, tr


# ---------------------------------------------------------------------------
# what is signed
# ---------------------------------------------------------------------------
class TestTheSignedPayload:
    def test_the_signed_bytes_are_a_domain_prefix_then_canonical_json_of_the_body(self):
        from assurance.core.identity import canonical_json

        rec, tr = Recorder(), make_trace()
        att = rec.attest(tr)
        assert SIGNING_PREFIX == b"assurance.machine.recorder-attestation.v1\n"
        assert att.signed_payload() == SIGNING_PREFIX + canonical_json(
            {k: v for k, v in att.to_dict().items() if k != "signature"}).encode()
        assert rec.key.verifying.verify(att.signed_payload(), att.signature_bytes())

    def test_every_field_is_inside_the_signed_body(self):
        att = Recorder().attest(make_trace(), machine_serial="SN-1", expires_on="2027-01-01")
        d = att.to_dict()
        assert set(d) == {"format", "attestation_id", "trace_hash", "exact_samples_digest",
                          "trace_id", "provenance", "window", "recorder_id", "machine_ref",
                          "attested_on", "expires_on", "key_fingerprint", "signature"}
        assert d["format"] == ATTESTATION_FORMAT == "assurance.machine.recorder-attestation.v1"
        assert set(d["window"]) == {"started_at", "sample_count", "sample_rate_hz", "duration_s"}
        assert set(d["machine_ref"]) == {"product", "product_version", "machine_serial"}
        body = json.loads(att.signed_payload()[len(SIGNING_PREFIX):])
        assert set(body) == set(d) - {"signature"}

    def test_the_window_is_carried_as_strings_so_float_formatting_cannot_be_reinterpreted(self):
        tr = make_trace()
        w = Recorder().attest(tr).to_dict()["window"]
        assert all(type(v) is str for v in w.values())
        assert w == {"started_at": "2026-09-12T04:31:00Z", "sample_count": "20",
                     "sample_rate_hz": "50.000000", "duration_s": "0.380000"}

    def test_it_binds_the_content_hash_of_the_exact_trace(self):
        tr = make_trace()
        assert Recorder().attest(tr).trace_hash == tr.content_hash()

    def test_a_private_key_is_never_part_of_an_attestation(self):
        rec = Recorder()
        text = json.dumps(rec.attest(make_trace()).to_dict())
        assert "PRIVATE" not in text.upper()


# ---------------------------------------------------------------------------
# accepted, and only then lifted
# ---------------------------------------------------------------------------
class TestAnAcceptedAttestation:
    @pytest.mark.parametrize("prov", [Provenance.BENCH, Provenance.FIELD])
    def test_it_lets_bench_and_field_reach_their_own_ceiling(self, prov):
        rec, tr = Recorder(), make_trace(prov)
        r = run(tr, [rec.attest_for(envelope(), tr)], rec.trust())
        assert r.provenance_basis == "recorder_attested"
        assert r.tier is AssuranceTier.VALIDATED and r.may_claim_physical_behaviour
        assert r.provenance_assessment["lifts_tier"] is True
        assert r.provenance_assessment["key_fingerprint"] == rec.fingerprint
        assert r.recorder_attestation["status"] == "accepted"

    def test_it_says_what_it_proves_and_what_it_does_not(self):
        rec, tr = Recorder(), make_trace()
        text = run(tr, [rec.attest_for(envelope(), tr)], rec.trust()).provenance_assessment[
            "explanation"]
        assert "does not establish" in text and "physical" in text
        assert "integrity is not recorder authenticity" in text
        assert "recorder authenticity is not physical safety" in text
        assert "not verified" in text            # the recorder's own label

    def test_a_trusted_key_attesting_a_simulation_stays_community(self):
        rec, tr = Recorder(), make_trace(Provenance.SIMULATION)
        r = run(tr, [rec.attest_for(envelope(), tr)], rec.trust())
        assert r.tier is AssuranceTier.COMMUNITY and r.provenance_basis == "declared_by_filer"
        a = assess(tr, [rec.attest_for(envelope(), tr)], rec.trust())
        assert a.status is AttestationStatus.PROVENANCE_NOT_PERMITTED

    def test_the_tier_is_the_min_of_every_ceiling_not_just_the_provenance(self):
        rec, tr = Recorder(), make_trace()
        weak = envelope(stop=StopPerformance(0.1, 0.25, 120.0, 500.0, DATASHEET))
        r = run(tr, [rec.attest_for(weak, tr)], rec.trust(), weak)
        assert r.provenance_basis == "recorder_attested"
        assert r.tier is AssuranceTier.PROFILE      # the datasheet figure caps it

    def test_an_unreviewed_limits_table_still_caps_an_attested_trace(self):
        lt = LimitsTable(edition="Example 2016", transcribed_by="a", verified_by="b",
                         verified_on="2026-04-01", transient_multiplier=2.0,
                         regions={"hand": BodyRegionLimit("hand", "Hand", 140.0, 140.0)})
        env = envelope(pfl_limits_hash=lt.content_hash(),
                       max_tcp_speed_mm_s={OperatingMode.SSM: 500.0, OperatingMode.PFL: 250.0})
        tr = Trace(trace_id="RUN-P", provenance=Provenance.FIELD, source_system="fw",
                   started_at=START, sample_rate_hz=50.0,
                   samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=100.0,
                                        mode=OperatingMode.PFL, contact_force=10.0,
                                        contact_area=20.0, body_region="hand")
                                 for i in range(40)))
        rec = Recorder()
        r = verify(env, tr, limits=lt, recorder_attestations=[rec.attest_for(env, tr)],
                   recorder_trust=rec.trust(), now=NOW)
        assert r.provenance_basis == "recorder_attested"
        assert r.tier is AssuranceTier.COMMUNITY     # no reviewed limits table

    def test_a_caller_written_basis_or_provenance_never_lifts_anything(self):
        d = make_trace().hashable_payload()
        d["provenance_basis"] = "recorder_attested"
        d["recorder_trust"] = RECORDER.trust_dict()
        d["source_system"] = "NOTARISED RECORDER"
        r = verify(envelope(), Trace.from_dict(d), now=NOW)
        assert r.provenance_basis == "declared_by_filer"
        assert r.tier.rank <= AssuranceTier.COMMUNITY.rank

    def test_without_a_trust_list_nothing_can_be_accepted(self):
        rec, tr = Recorder(), make_trace()
        for trust in (None, RecorderTrust()):
            r = run(tr, [rec.attest_for(envelope(), tr)], trust)
            assert r.provenance_basis == "declared_by_filer"
            assert r.tier.rank <= AssuranceTier.COMMUNITY.rank
            assert r.recorder_attestation["status"] == "untrusted_key"
            assert r.recorder_attestation["trust_configured"] is False

    def test_the_extension_point_is_the_real_assessment_and_not_a_set_to_add_to(self):
        rec, tr = Recorder(), make_trace()
        assert provenance_trust.LIFTING_BASES == frozenset({"recorder_attested"})
        p = provenance_trust.assess_provenance(
            tr, [rec.attest_for(envelope(), tr)], rec.trust(), machine_ref=REF, now=NOW)
        assert p.lifts_tier and p.basis is provenance_trust.ProvenanceBasis.RECORDER_ATTESTED
        assert not provenance_trust.assess_provenance(tr).lifts_tier


# ---------------------------------------------------------------------------
# every refusal
# ---------------------------------------------------------------------------
class TestTrustIsAVerifierInput:
    def test_an_unknown_key_is_untrusted(self):
        tr = make_trace()
        a = assess(tr, [Recorder().attest(tr)], Recorder().trust())
        assert a.status is AttestationStatus.UNTRUSTED_KEY and a.trust_configured

    def test_a_revoked_key_rejects_all_of_its_attestations_whatever_date_they_state(self):
        rec, tr = Recorder(), make_trace()
        early = rec.attest(tr, attested_on="2026-09-12")
        for trust in (rec.trust(revoked=True), rec.trust(revoked_on="2026-12-31")):
            a = assess(tr, [early], trust)
            assert a.status is AttestationStatus.REVOKED_KEY
            assert "every attestation it signed is rejected" in a.findings[0].detail

    def test_a_key_trusted_for_bench_cannot_lift_a_field_trace(self):
        rec, tr = Recorder(), make_trace(Provenance.FIELD)
        a = assess(tr, [rec.attest(tr)], rec.trust(provenance=("bench",)))
        assert a.status is AttestationStatus.PROVENANCE_NOT_PERMITTED
        r = run(tr, [rec.attest_for(envelope(), tr)], rec.trust(provenance=("bench",)))
        assert r.tier.rank <= AssuranceTier.COMMUNITY.rank

    def test_a_bench_key_does_lift_a_bench_trace(self):
        rec, tr = Recorder(), make_trace(Provenance.BENCH)
        assert assess(tr, [rec.attest(tr)], rec.trust(provenance=("bench",))).attested

    def test_the_fingerprint_is_computed_and_a_mismatching_one_refuses_to_load(self):
        d = RECORDER.trust_dict()
        d["recorders"][0]["fingerprint"] = "0" * 16
        with pytest.raises(RecorderAttestationError, match="does not match"):
            RecorderTrust.from_dict(d)

    def test_simulation_can_never_be_trusted_for(self):
        d = RECORDER.trust_dict()
        d["recorders"][0]["provenance"] = ["simulation"]
        with pytest.raises(RecorderAttestationError, match="simulation"):
            RecorderTrust.from_dict(d)

    @pytest.mark.parametrize("mutate", [
        lambda d: d.update(extra=1),
        lambda d: d["recorders"][0].update(extra=1),
        lambda d: d["recorders"][0].pop("provenance"),
        lambda d: d["recorders"][0].update(provenance=[]),
        lambda d: d["recorders"][0].update(revoked="no"),
        lambda d: d["recorders"][0].update(public_key_pem=5),
        lambda d: d.update(format="assurance.machine.recorder-trust.v2"),
        lambda d: d.update(recorders={}),
        lambda d: d["recorders"].append(d["recorders"][0]),
    ])
    def test_a_malformed_trust_file_refuses_to_load(self, mutate):
        d = RECORDER.trust_dict()
        mutate(d)
        with pytest.raises(RecorderAttestationError):
            RecorderTrust.from_dict(d)

    def test_a_revocation_date_alone_revokes_a_key_loaded_from_a_file(self, tmp_path):
        d = RECORDER.trust_dict()
        d["recorders"][0]["revoked"] = False
        d["recorders"][0]["revoked_on"] = "2026-09-01"
        p = tmp_path / "t.json"
        p.write_text(json.dumps(d))
        loaded = RecorderTrust.from_json(p)
        assert loaded.get(RECORDER.fingerprint).revoked is True
        tr = make_trace()
        assert assess(tr, [RECORDER.attest(tr)], loaded).status is AttestationStatus.REVOKED_KEY

    def test_the_trust_file_round_trips_and_has_the_documented_shape(self, tmp_path):
        p = RECORDER.write_trust(tmp_path / "t.json")
        d = json.loads(p.read_text())
        assert d["format"] == TRUST_FORMAT == "assurance.machine.recorder-trust.v1"
        assert set(d["recorders"][0]) == {"label", "public_key_pem", "fingerprint",
                                          "provenance", "revoked", "revoked_on"}
        assert RecorderTrust.from_json(p).get(RECORDER.fingerprint).provenance == {
            "bench", "field"}

    def test_a_trust_file_with_a_repeated_key_is_refused(self, tmp_path):
        p = tmp_path / "t.json"
        p.write_text('{"format": "assurance.machine.recorder-trust.v1", "recorders": [], '
                     '"recorders": []}')
        with pytest.raises(RecorderAttestationError, match="repeats the key"):
            RecorderTrust.from_json(p)

    def test_a_private_key_in_a_trust_file_is_refused_unread(self, tmp_path):
        d = RECORDER.trust_dict()
        d["recorders"][0]["public_key_pem"] = private_pem()
        p = tmp_path / "t.json"
        p.write_text(json.dumps(d))
        with pytest.raises(RecorderAttestationError, match="private key") as exc:
            RecorderTrust.from_json(p)
        assert "BEGIN" not in str(exc.value)


class TestSignatures:
    def test_a_bad_signature_is_refused(self):
        rec, tr = Recorder(), make_trace()
        good = rec.attest(tr)
        raw = bytearray(good.signature_bytes())
        raw[0] ^= 1
        bad = replace(good, signature=base64.b64encode(bytes(raw)).decode())
        assert assess(tr, [bad], rec.trust()).status is AttestationStatus.BAD_SIGNATURE

    def test_a_signature_by_another_key_over_the_same_body_is_refused(self):
        rec, other, tr = Recorder(), Recorder(), make_trace()
        forged = resign(rec.attest(tr), other.key)          # the trusted fingerprint, a stranger's signature
        assert assess(tr, [forged], rec.trust()).status is AttestationStatus.BAD_SIGNATURE

    @pytest.mark.parametrize(("path", "value", "status"), [
        (("attestation_id",), "tampered-id-0001", AttestationStatus.BAD_SIGNATURE),
        (("trace_hash",), "0" * 64, AttestationStatus.BAD_SIGNATURE),
        (("trace_id",), "RUN-OTHER", AttestationStatus.BAD_SIGNATURE),
        (("provenance",), "bench", AttestationStatus.BAD_SIGNATURE),
        (("window", "started_at"), "2026-09-12T04:32:00Z", AttestationStatus.BAD_SIGNATURE),
        (("window", "sample_count"), "21", AttestationStatus.BAD_SIGNATURE),
        (("window", "sample_rate_hz"), "60.000000", AttestationStatus.BAD_SIGNATURE),
        (("window", "duration_s"), "9.000000", AttestationStatus.BAD_SIGNATURE),
        (("recorder_id",), "SOMEBODY-ELSE", AttestationStatus.BAD_SIGNATURE),
        (("machine_ref", "product"), "Other", AttestationStatus.BAD_SIGNATURE),
        (("machine_ref", "product_version"), "9.9.9", AttestationStatus.BAD_SIGNATURE),
        (("machine_ref", "machine_serial"), "SN-2", AttestationStatus.BAD_SIGNATURE),
        (("attested_on",), "2026-09-13", AttestationStatus.BAD_SIGNATURE),
        (("expires_on",), "2099-01-01", AttestationStatus.BAD_SIGNATURE),
        (("key_fingerprint",), "f" * 16, AttestationStatus.UNTRUSTED_KEY),
        (("format",), "assurance.machine.recorder-attestation.v2",
         AttestationStatus.UNSUPPORTED_VERSION),
    ])
    def test_altering_any_signed_field_after_signing_is_caught(self, path, value, status):
        rec, tr = Recorder(), make_trace()
        d = rec.attest(tr, machine_serial="SN-1", expires_on="2026-12-31").to_dict()
        target = d
        for p in path[:-1]:
            target = target[p]
        assert target[path[-1]] != value
        target[path[-1]] = value
        a = assess(tr, [d], rec.trust(), ref=MachineRef("Cell", "1.0.0", "SN-1"))
        assert a.status is status and not a.attested

    def test_a_limits_review_signature_is_not_a_recorder_attestation(self):
        rec, tr = Recorder(), make_trace()
        lt = LimitsTable(edition="E", transcribed_by="a", verified_by="b", verified_on="2026-04-01",
                         transient_multiplier=2.0,
                         regions={"hand": BodyRegionLimit("hand", "Hand", 140.0, 140.0)})
        review = LimitsReview.sign(lt, rec.key, reviewer="r", basis="b", reviewed_on="2026-09-01")
        d = rec.attest(tr).to_dict()
        d["signature"] = review.signature
        assert assess(tr, [d], rec.trust()).status is AttestationStatus.BAD_SIGNATURE

    def test_a_ledger_head_attestation_signature_is_not_a_recorder_attestation(self, tmp_path):
        rec, tr = Recorder(), make_trace()
        ledger = EvidenceLedger(tmp_path / "l.db")
        log = AttestationLog(tmp_path / "log.jsonl")
        head = attest(ledger, rec.key, log)
        d = rec.attest(tr).to_dict()
        d["signature"] = head.signature
        assert assess(tr, [d], rec.trust()).status is AttestationStatus.BAD_SIGNATURE

    def test_a_recorder_signature_does_not_verify_as_a_limits_review_or_a_head(self, tmp_path):
        rec, tr = Recorder(), make_trace()
        att = rec.attest(tr)
        # the same key signing the bare canonical body (what the other protocols sign)
        from assurance.core.identity import canonical_json

        bare = base64.b64encode(rec.key.sign(canonical_json(
            {k: v for k, v in att.to_dict().items() if k != "signature"}).encode())).decode()
        assert assess(tr, [replace(att, signature=bare)], rec.trust()).status \
            is AttestationStatus.BAD_SIGNATURE
        # and the recorder's signature is not valid over a limits review / head body
        assert not rec.key.verifying.verify(
            canonical_json({"format": "assurance.machine.limits-review.v1"}).encode(),
            att.signature_bytes())

    def test_the_domain_prefix_is_what_separates_the_protocols(self):
        rec, tr = Recorder(), make_trace()
        att = rec.attest(tr)
        unprefixed = att.signed_payload()[len(SIGNING_PREFIX):]
        assert not rec.key.verifying.verify(unprefixed, att.signature_bytes())


class TestTheAttestationIsAboutThisRecordingAndThisMachine:
    def test_an_attestation_for_another_trace_is_refused(self):
        rec = Recorder()
        a, b = make_trace(trace_id="RUN-A"), make_trace(trace_id="RUN-B", sep=2500.0)
        out = assess(b, [rec.attest(a)], rec.trust())
        assert out.status is AttestationStatus.TRACE_MISMATCH
        assert "was changed after it was attested" in out.findings[0].detail

    @pytest.mark.parametrize("edit", [
        pytest.param(lambda t: replace(t, samples=(replace(t.samples[0], tcp_speed=301.0),
                                                   *t.samples[1:])), id="one-sample"),
        pytest.param(lambda t: replace(t, provenance=Provenance.BENCH), id="provenance"),
        pytest.param(lambda t: replace(t, conditions={"payload_kg": 99}), id="conditions"),
        pytest.param(lambda t: replace(t, source_system="a different controller"),
                     id="source-system"),
        pytest.param(lambda t: replace(t, started_at=t.started_at + timedelta(seconds=1)),
                     id="started-at"),
        pytest.param(lambda t: replace(t, sample_rate_hz=51.0), id="sample-rate"),
    ])
    def test_a_trace_edited_after_signing_loses_the_attestation(self, edit):
        rec, tr = Recorder(), make_trace()
        att = rec.attest_for(envelope(), tr)
        edited = edit(tr)
        r = run(edited, [att], rec.trust())
        assert r.tier.rank <= AssuranceTier.COMMUNITY.rank
        assert r.recorder_attestation["status"] == "trace_mismatch"

    def test_a_trace_edited_and_the_bundle_resealed_is_rejected_on_replay(self):
        raw, env, tr = sealed()
        edited = replace(tr, samples=(replace(tr.samples[0], tcp_speed=301.0), *tr.samples[1:]))
        res = check_bundle_data(raw, envelope=env, trace=edited, recorder_trust=RECORDER.trust())
        assert not res.ok and any("not the one this bundle was produced" in p
                                  for p in res.problems)

    def test_the_window_is_compared_even_when_the_hash_is_genuinely_signed(self):
        rec, tr = Recorder(), make_trace()
        good = rec.attest_for(envelope(), tr)
        for change in ({"sample_count": "5"}, {"sample_rate_hz": "25.000000"},
                       {"duration_s": "1.000000"}, {"started_at": "2026-09-12T04:32:00Z"},
                       {"trace_id": "RUN-X"}, {"provenance": "bench"}):
            lying = resign(good, rec.key, **change)
            assert assess(tr, [lying], rec.trust()).status is AttestationStatus.TRACE_MISMATCH, change

    @pytest.mark.parametrize(("attested_ref", "wanted", "needle"), [
        (("Other", "1.0.0", ""), MachineRef("Cell", "1.0.0"), "product"),
        (("Cell", "2.0.0", ""), MachineRef("Cell", "1.0.0"), "version"),
        (("Cell", "1.0.0", "SN-1"), MachineRef("Cell", "1.0.0", "SN-2"), "serial"),
        (("Cell", "1.0.0", ""), MachineRef("Cell", "1.0.0", "SN-2"), "no serial"),
    ])
    def test_another_machine_is_refused(self, attested_ref, wanted, needle):
        rec, tr = Recorder(), make_trace()
        p, v, s = attested_ref
        att = rec.attest(tr, product=p, product_version=v, machine_serial=s)
        a = assess(tr, [att], rec.trust(), ref=wanted)
        assert a.status is AttestationStatus.MACHINE_MISMATCH and needle in a.findings[0].detail

    def test_a_serial_the_recorder_names_is_not_required_of_a_product_line_verification(self):
        rec, tr = Recorder(), make_trace()
        assert assess(tr, [rec.attest(tr, machine_serial="SN-1")], rec.trust()).attested

    def test_a_unit_subject_carries_its_serial_into_the_match(self):
        rec, tr = Recorder(), make_trace()
        env = envelope()
        att = rec.attest_for(env, tr, machine_serial="SN-1")
        ok = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[att],
                          recorder_trust=rec.trust(), subject="ACME/Cell#SN-1")
        wrong = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[att],
                             recorder_trust=rec.trust(), subject="ACME/Cell#SN-2")
        assert ok.result.provenance_basis == "recorder_attested"
        assert ok.evidence.body["machine_serial"] == "SN-1"
        assert wrong.result.provenance_basis == "declared_by_filer"
        assert wrong.result.recorder_attestation["status"] == "machine_mismatch"


class TestDatesAndReplays:
    def test_an_attestation_dated_before_the_recording_began_is_stale(self):
        rec, tr = Recorder(), make_trace()
        a = assess(tr, [rec.attest(tr, attested_on="2026-09-11")], rec.trust())
        assert a.status is AttestationStatus.STALE and "before the recording began" in a.findings[0].detail

    def test_one_dated_implausibly_long_after_is_stale(self):
        rec, tr = Recorder(), make_trace()
        late = (START + timedelta(days=MAX_LAG_DAYS + 1)).date().isoformat()
        edge = (START + timedelta(days=MAX_LAG_DAYS)).date().isoformat()
        later = datetime(2027, 6, 1, tzinfo=UTC)
        assert assess(tr, [rec.attest(tr, attested_on=late)], rec.trust(), now=later).status \
            is AttestationStatus.STALE
        assert assess(tr, [rec.attest(tr, attested_on=edge)], rec.trust(), now=later).attested

    def test_a_future_dated_attestation_is_not_yet_valid(self):
        rec, tr = Recorder(), make_trace()
        a = assess(tr, [rec.attest(tr, attested_on="2026-09-21")], rec.trust())
        assert a.status is AttestationStatus.NOT_YET_VALID

    def test_an_expired_attestation_is_refused(self):
        rec, tr = Recorder(), make_trace()
        a = assess(tr, [rec.attest(tr, expires_on="2026-09-19")], rec.trust())
        assert a.status is AttestationStatus.EXPIRED
        assert assess(tr, [rec.attest(tr, expires_on="2026-09-20")], rec.trust()).attested

    def test_the_same_attestation_twice_is_a_duplicate_and_counts_once(self):
        rec, tr = Recorder(), make_trace()
        att = rec.attest(tr)
        a = assess(tr, [att, att.to_dict()], rec.trust())
        assert a.attested and statuses(a) == [AttestationStatus.DUPLICATE]

    def test_a_second_statement_reusing_an_attestation_id_is_a_duplicate(self):
        rec, tr = Recorder(), make_trace()
        first = rec.attest(tr, attestation_id="nonce-0001-abcd")
        second = rec.attest(tr, attestation_id="nonce-0001-abcd", recorder_id="REC-OTHER")
        assert statuses(assess(tr, [first, second], rec.trust())) == [AttestationStatus.DUPLICATE]

    def test_an_attestation_replayed_onto_a_different_trace_is_refused(self):
        rec = Recorder()
        a, b = make_trace(trace_id="RUN-A"), make_trace(trace_id="RUN-B")
        att = rec.attest(a)
        assert assess(a, [att], rec.trust()).attested
        assert assess(b, [att], rec.trust()).status is AttestationStatus.TRACE_MISMATCH

    def test_a_later_good_attestation_is_still_found_after_defective_ones(self):
        rec, tr = Recorder(), make_trace()
        a = assess(tr, [rec.attest(tr, attested_on="2026-09-01"), rec.attest(tr)], rec.trust())
        assert a.attested and statuses(a) == [AttestationStatus.STALE]


class TestMalformedInput:
    @pytest.mark.parametrize("junk", [
        None, 5, "text", [], [1, 2], {}, {"format": 5}, {"format": ATTESTATION_FORMAT},
        {"format": "something-else"}, True,
    ])
    def test_junk_is_reported_not_raised(self, junk):
        a = assess(make_trace(), [junk], RECORDER.trust())
        assert a.status in (AttestationStatus.MALFORMED, AttestationStatus.UNSUPPORTED_VERSION)
        assert not a.attested

    @pytest.mark.parametrize("mutate", [
        lambda d: d.update(smuggled="unsigned"),
        lambda d: d["window"].update(smuggled="x"),
        lambda d: d["machine_ref"].update(smuggled="x"),
        lambda d: d.pop("expires_on"),
        lambda d: d["window"].update(sample_count=20),
        lambda d: d["window"].update(sample_count=True),
        lambda d: d["window"].update(sample_rate_hz=50.0),
        lambda d: d["window"].update(duration_s="0.38"),
        lambda d: d["window"].update(sample_count="020"),
        lambda d: d.update(window="x"),
        lambda d: d.update(machine_ref=["Cell"]),
        lambda d: d["machine_ref"].update(product=None),
        lambda d: d["machine_ref"].update(product=""),
        lambda d: d.update(attested_on="2026-9-12"),
        lambda d: d.update(attested_on="20260912"),
        lambda d: d.update(attested_on="2026-02-30"),
        lambda d: d.update(expires_on="never"),
        lambda d: d.update(attested_on=20260912),
        lambda d: d.update(trace_hash="ABC"),
        lambda d: d.update(key_fingerprint="xyz"),
        lambda d: d.update(attestation_id="short"),
        lambda d: d.update(signature="not base64!!"),
        lambda d: d.update(signature=base64.b64encode(b"short").decode()),
        lambda d: d.update(recorder_id="bad\nlabel"),
        lambda d: d.update(recorder_id="x" * 300),
        lambda d: d.update(provenance="lab"),
    ])
    def test_a_malformed_attestation_is_refused(self, mutate):
        tr = make_trace()
        d = RECORDER.attest(tr).to_dict()
        mutate(d)
        a = assess(tr, [d], RECORDER.trust())
        assert a.status is AttestationStatus.MALFORMED, a.findings

    def test_an_unsupported_version_is_named_as_such(self):
        d = RECORDER.attest(make_trace()).to_dict()
        d["format"] = "assurance.machine.recorder-attestation.v2"
        d["brand_new_field"] = "v2 fields"
        a = assess(make_trace(), [d], RECORDER.trust())
        assert a.status is AttestationStatus.UNSUPPORTED_VERSION

    def test_the_number_examined_is_capped_and_the_cap_is_said(self):
        rec, tr = Recorder(), make_trace()
        good = rec.attest(tr)
        junk = [{"x": i} for i in range(MAX_ATTESTATIONS)]
        a = assess(tr, [*junk, good], rec.trust())      # the good one is past the cap
        assert not a.attested
        assert any(f"more than {MAX_ATTESTATIONS}" in f.detail for f in a.findings)
        assert len(a.submitted) == MAX_ATTESTATIONS

    def test_a_file_with_a_repeated_key_is_refused(self, tmp_path):
        p = tmp_path / "a.json"
        d = json.dumps(RECORDER.attest(make_trace()).to_dict())
        p.write_text(d[:-1] + ', "recorder_id": "SECOND"}')
        with pytest.raises(RecorderAttestationError, match="repeats the key"):
            load_attestation_file(p)

    def test_nan_and_garbage_are_refused(self):
        for text in ('{"a": NaN}', "{", "[1, 2"):
            with pytest.raises(RecorderAttestationError):
                loads_strict(text, "x")

    def test_an_oversized_attestation_is_refused(self):
        d = RECORDER.attest(make_trace()).to_dict()
        d["recorder_id"] = "x" * 250
        d["machine_ref"]["product"] = "y" * 250
        d["trace_id"] = "z" * 250
        d["window"]["started_at"] = "2026-09-12T04:31:00Z"
        d["attestation_id"] = "a" * 120
        # within the field caps this is fine; a pile of extra bytes is not
        d["window"]["extra"] = "e" * 9000
        assert assess(make_trace(), [d], RECORDER.trust()).status is AttestationStatus.MALFORMED


class TestPrivateKeys:
    def test_an_attestation_carrying_a_private_key_is_refused_and_not_sealed(self):
        rec, tr = Recorder(), make_trace()
        d = rec.attest(tr).to_dict()
        d["recorder_id"] = private_pem()
        a = assess(tr, [d], rec.trust())
        assert a.status is AttestationStatus.MALFORMED
        assert "BEGIN" not in json.dumps(a.to_dict())

    def test_a_one_line_private_key_in_an_otherwise_valid_field_is_still_refused(self):
        rec, tr = Recorder(), make_trace()
        one_line = " ".join(private_pem().split())            # no newline to trip other checks
        d = rec.attest(tr).to_dict()
        d["recorder_id"] = one_line
        with pytest.raises(RecorderAttestationError, match="private key"):
            RecorderAttestation.from_dict(d)
        a = assess(tr, [d], rec.trust())
        assert a.status is AttestationStatus.MALFORMED
        key_material = "".join(private_pem().splitlines()[1:-1])
        assert key_material not in json.dumps(a.to_dict()) and "BEGIN" not in json.dumps(a.to_dict())

    def test_a_file_that_is_a_private_key_is_refused_unread(self, tmp_path):
        p = tmp_path / "k.json"
        p.write_text(private_pem())
        with pytest.raises(RecorderAttestationError, match="private key"):
            load_attestation_file(p)

    def test_a_bundle_never_contains_a_private_key_or_a_trust_list(self):
        raw, _, _ = sealed()
        text = json.dumps(raw)
        assert "PRIVATE" not in text.upper()
        assert "public_key_pem" not in text and "recorders" not in text

    def test_the_api_refuses_a_private_key_in_the_attestations(self, client, store, monkeypatch,
                                                                tmp_path):
        server_trust(monkeypatch, tmp_path)
        env, tr = envelope(), make_trace()
        body = {"envelope": env.to_dict(), "trace": tr.hashable_payload(), "actor": "a.b",
                "recorder_attestations": [{**RECORDER.attest_for(env, tr).to_dict(),
                                           "recorder_id": private_pem()}]}
        r = client.post("/v1/machine/verify", json=body, headers=keyed(store, "cell"))
        assert r.status_code == 422
        assert r.json()["detail"]["error"] == "private_key_refused"
        assert "BEGIN" not in r.text


# ---------------------------------------------------------------------------
# sealing and re-evaluation on replay
# ---------------------------------------------------------------------------
class TestSealedAndReassessed:
    def test_the_bundle_records_the_assessment_and_the_attestations_as_supplied(self):
        raw, env, tr = sealed()
        body = raw["evidence"]["body"]
        rec = body["recorder_attestation"]
        assert body["engine_version"] == ENGINE_VERSION == "6"
        assert body["provenance_basis"] == "recorder_attested" and body["tier"] == "validated"
        assert rec["status"] == "accepted" and rec["attested"] is True
        assert rec["key_fingerprint"] == RECORDER.fingerprint
        assert rec["attestation_hash"] == body["provenance_assessment"]["attestation_hash"]
        assert len(rec["attestations"]) == 1
        assert rec["attestations"][0] == rec["accepted_attestation"]
        assert RecorderAttestation.from_dict(rec["attestations"][0]).trace_hash == tr.content_hash()
        assert rec["assessed_on"]

    def test_a_checker_with_the_right_trust_and_the_originals_reproduces_it(self):
        raw, env, tr = sealed()
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust())
        assert res.ok and res.level == LEVEL_REPRODUCED
        assert res.provenance_basis == "recorder_attested"
        assert res.provenance_reassessed == "reproduced" and res.believed_tier == "validated"

    def test_without_the_originals_the_checker_still_reassesses_under_its_own_trust(self):
        raw, _, _ = sealed()
        res = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert res.ok and res.level == LEVEL_INTEGRITY_ONLY
        # The attestation holds under the checker's list, but nothing re-ran the checks, so
        # no tier is believed (see test_assurance_recorder_review_fixes.TestTheBelievedTier).
        assert res.provenance_reassessed == "reproduced" and res.believed_tier == "community"
        assert res.reassessment_note == "attestation re-assessed; checks not re-run"
        assert any("recording window was not compared" in v for v in res.verified)

    def test_a_checker_with_no_trust_does_not_believe_it_and_says_so(self):
        raw, env, tr = sealed()
        for kw in ({}, {"envelope": env, "trace": tr}):
            res = check_bundle_data(raw, **kw)
            assert res.ok and res.level == LEVEL_INTEGRITY_ONLY and not res.reproduced
            assert res.provenance_reassessed == "unverifiable"
            assert res.believed_tier == "community"          # capped, not believed
            assert any("NOT believed" in n and "recorder trust" in n for n in res.limitations)

    def test_a_checker_whose_trust_lacks_the_key_rejects_it(self):
        raw, env, tr = sealed()
        stranger = Recorder().trust()
        for kw in ({}, {"envelope": env, "trace": tr}):
            res = check_bundle_data(raw, recorder_trust=stranger, **kw)
            assert not res.ok and res.level == LEVEL_REJECTED
            assert res.provenance_reassessed == "not_reproduced" and res.believed_tier == "community"

    def test_a_checker_that_has_since_revoked_the_key_rejects_it(self):
        raw, env, tr = sealed()
        res = check_bundle_data(raw, envelope=env, trace=tr,
                                recorder_trust=RECORDER.trust(revoked_on="2026-09-30"),
                                as_of=NOW)
        assert not res.ok and res.provenance_reassessed == "not_reproduced"

    def test_a_checker_that_trusts_the_key_for_another_class_rejects_it(self):
        raw, _, _ = sealed()
        res = check_bundle_data(raw, recorder_trust=RECORDER.trust(provenance=("bench",)))
        assert not res.ok

    def test_expiry_is_judged_on_the_checkers_day_not_the_sealed_one(self):
        env, tr = envelope(), make_trace()
        raw = json.loads(json.dumps(build_bundle(
            env, tr, actor=ACTOR, recorder_attestations=[
                RECORDER.attest_for(env, tr, expires_on=_EXPIRES)],
            recorder_trust=RECORDER.trust()).to_dict()))
        soon = _TODAY
        later = _TODAY + timedelta(days=60)
        assert check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust(),
                                 as_of=soon).ok
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust(),
                                as_of=later)
        assert not res.ok and res.provenance_reassessed == "not_reproduced"

    def test_a_trust_list_embedded_in_the_bundle_is_ignored(self):
        raw, env, tr = sealed(recorder=Recorder())      # sealed by a recorder nobody here trusts
        raw["recorder_trust"] = RECORDER.trust_dict()
        body = raw["evidence"]["body"]
        body["recorder_trust"] = RECORDER.trust_dict()
        body["recorder_attestation"]["recorder_trust"] = RECORDER.trust_dict()
        raw["result"]["recorder_trust"] = RECORDER.trust_dict()
        reseal(raw)
        res = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert res.provenance_reassessed == "not_reproduced" and not res.ok
        assert check_bundle_data(raw).provenance_reassessed == "unverifiable"
        assert check_bundle_data(raw).believed_tier == "community"

    def test_the_attestation_the_bundle_cites_is_the_one_the_checker_must_accept(self):
        """A checker that trusts a DIFFERENT recorder than the one the seal cites does not
        reproduce the seal, even though one of the recorded attestations is acceptable to it."""
        env, tr = envelope(), make_trace()
        cited, other = Recorder("cited"), Recorder("other")
        raw = json.loads(json.dumps(build_bundle(
            env, tr, actor=ACTOR,
            recorder_attestations=[cited.attest_for(env, tr), other.attest_for(env, tr)],
            recorder_trust=cited.trust()).to_dict()))
        assert raw["evidence"]["body"]["recorder_attestation"]["key_fingerprint"] \
            == cited.fingerprint
        assert check_bundle_data(raw, recorder_trust=cited.trust()).ok
        res = check_bundle_data(raw, recorder_trust=other.trust())   # accepts the 2nd, not the 1st
        assert not res.ok and res.provenance_reassessed == "not_reproduced"
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=other.trust())
        assert not res.ok

    def test_the_checkers_own_serial_is_what_the_replay_uses(self):
        env, tr = envelope(), make_trace()
        raw = json.loads(json.dumps(build_bundle(
            env, tr, actor=ACTOR, machine_serial="SN-1",
            recorder_attestations=[RECORDER.attest_for(env, tr, machine_serial="SN-1")],
            recorder_trust=RECORDER.trust()).to_dict()))
        assert check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust(),
                                 machine_serial="SN-1").reproduced
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust(),
                                machine_serial="SN-2")
        assert not res.ok and res.provenance_reassessed == "not_reproduced"

    def test_the_file_checker_judges_expiry_on_the_day_the_checker_names(self, tmp_path):
        from assurance.machine.bundle import check_bundle

        env, tr = envelope(), make_trace()
        b = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[
            RECORDER.attest_for(env, tr, expires_on=_EXPIRES)],
            recorder_trust=RECORDER.trust())
        path = b.write(tmp_path / "b.json")
        assert check_bundle(path, envelope=env, trace=tr, recorder_trust=RECORDER.trust(),
                            as_of=_TODAY).ok
        assert not check_bundle(path, envelope=env, trace=tr, recorder_trust=RECORDER.trust(),
                                as_of=_TODAY + timedelta(days=60)).ok

    def test_the_machine_serial_can_be_pinned_by_the_checker(self):
        env, tr = envelope(), make_trace()
        raw = json.loads(json.dumps(build_bundle(
            env, tr, actor=ACTOR, machine_serial="SN-1",
            recorder_attestations=[RECORDER.attest_for(env, tr, machine_serial="SN-1")],
            recorder_trust=RECORDER.trust()).to_dict()))
        assert check_bundle_data(raw, recorder_trust=RECORDER.trust(), machine_serial="SN-1").ok
        assert not check_bundle_data(raw, recorder_trust=RECORDER.trust(),
                                     machine_serial="SN-2").ok


class TestAResealedBundleThatMerelyClaimsIt:
    def _declared(self):
        env, tr = envelope(), make_trace()
        raw = json.loads(json.dumps(build_bundle(env, tr, actor=ACTOR).to_dict()))
        return raw, env, tr

    def _claim(self, raw, basis="recorder_attested"):
        raw["evidence"]["body"]["provenance_basis"] = basis
        raw["result"]["provenance_basis"] = basis
        raw["evidence"]["body"]["tier"] = "validated"
        raw["result"]["tier"] = "validated"
        raw["result"]["may_claim_physical_behaviour"] = True
        raw["evidence"]["confidence"] = "high"
        return reseal(raw)

    def test_claiming_the_basis_with_no_attestation_behind_it_is_rejected_by_everyone(self):
        raw, env, tr = self._declared()
        self._claim(raw)
        for trust in (None, RECORDER.trust()):
            res = check_bundle_data(raw, recorder_trust=trust)
            assert not res.ok and res.believed_tier == "community"
            assert any("recorder_attested" in p for p in res.problems)
        assert not check_bundle_data(raw, envelope=env, trace=tr).ok

    def test_a_self_attested_bundle_is_community_to_a_verifier_that_does_not_trust_the_key(self):
        attacker = Recorder("attacker")
        raw, env, tr = sealed(recorder=attacker)
        assert raw["evidence"]["body"]["tier"] == "validated"   # true under ITS trust list
        no_trust = check_bundle_data(raw, envelope=env, trace=tr)
        assert no_trust.provenance_reassessed == "unverifiable"
        assert no_trust.believed_tier == "community" and not no_trust.reproduced
        mine = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust())
        assert not mine.ok and mine.believed_tier == "community"

    def test_a_hand_edited_assessment_that_names_a_different_attestation_is_rejected(self):
        raw, _, _ = sealed()
        other = Recorder().attest(make_trace(trace_id="RUN-Z")).to_dict()
        raw["evidence"]["body"]["recorder_attestation"]["accepted_attestation"] = other
        reseal(raw)
        res = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert not res.ok and res.provenance_reassessed == "not_reproduced"

    def test_a_forged_accepted_status_over_garbage_is_not_believed_under_a_real_trust_list(self):
        raw, env, tr = self._declared()
        att = Recorder("forger").attest_for(env, tr)
        body = raw["evidence"]["body"]
        body["engine_version"] = raw["result"]["engine_version"] = "6"
        body["recorder_attestation"] = {
            "trace_hash": body["trace_hash"], "status": "accepted", "attested": True,
            "attestation_hash": att.content_hash(), "key_fingerprint": att.key_fingerprint,
            "accepted_attestation": att.to_dict(), "attestations": [att.to_dict()],
            "findings": [], "assessed_on": "2026-09-20", "trust_configured": True,
            "window_checked": True, "explanation": "trust me"}
        body["provenance_assessment"] = {
            "declared": "field", "basis": "recorder_attested", "ceiling": "validated",
            "lifts_tier": True, "attestation_hash": att.content_hash(),
            "key_fingerprint": att.key_fingerprint, "explanation": "trust me"}
        raw["result"]["provenance_assessment"] = body["provenance_assessment"]
        raw["result"]["recorder_attestation"] = body["recorder_attestation"]
        self._claim(raw)
        assert check_bundle_data(raw).believed_tier == "community"
        mine = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert not mine.ok and mine.believed_tier == "community"

    def test_a_trace_hash_swapped_after_the_fact_is_a_trace_mismatch(self):
        raw, _, _ = sealed()
        body = raw["evidence"]["body"]
        body["trace_hash"] = "1" * 64
        raw["result"]["trace_hash"] = "1" * 64
        for rel in raw["evidence"]["relations"]:
            if rel["relation"] == "derived_from":
                rel["content_hash"] = "1" * 64
        reseal(raw)
        res = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert not res.ok


class TestVersioning:
    def _bundle_as_engine(self, version: str):
        raw, env, tr = sealed()
        raw["evidence"]["body"]["engine_version"] = version
        raw["result"]["engine_version"] = version
        return reseal(raw), env, tr

    @pytest.mark.parametrize("old", ["5", "4", "3", "1", ""])
    def test_an_older_engine_can_never_carry_recorder_attested(self, old):
        raw, env, tr = self._bundle_as_engine(old)
        for trust in (None, RECORDER.trust()):
            res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=trust)
            assert not res.ok and res.believed_tier == "community"
            assert any("engines before 6" in p for p in res.problems), res.problems

    def test_an_engine_5_bundle_replayed_under_engine_6_is_still_a_different_engine(self):
        env, tr = envelope(), make_trace()
        raw = json.loads(json.dumps(build_bundle(env, tr, actor=ACTOR).to_dict()))
        for k in ("recorder_attestation", "machine_serial"):
            raw["evidence"]["body"].pop(k)
            raw["result"].pop(k)
        raw["evidence"]["body"]["engine_version"] = raw["result"]["engine_version"] = "5"
        reseal(raw)
        res = check_bundle_data(raw, envelope=env, trace=tr)
        assert not res.ok and any("engine '5'" in p and "engine '6'" in p for p in res.problems)

    def test_an_upgraded_engine_field_on_a_declared_bundle_is_caught_on_replay(self):
        env, tr = envelope(), make_trace()
        raw = json.loads(json.dumps(build_bundle(env, tr, actor=ACTOR).to_dict()))
        raw["evidence"]["body"]["engine_version"] = raw["result"]["engine_version"] = "7"
        reseal(raw)
        res = check_bundle_data(raw, envelope=env, trace=tr)
        assert not res.ok and any("engine '7'" in p for p in res.problems)

    def test_the_ledger_consumers_do_not_believe_an_older_engines_validated_tier(self):
        from assurance.machinery.staleness import _believed_tier

        raw, _, _ = sealed()
        body = dict(raw["evidence"]["body"])
        assert _believed_tier(body) == "validated"
        assert _believed_tier({**body, "engine_version": "5"}) == "community"
        assert _believed_tier({**body, "provenance_basis": "declared_by_filer"}) == "community"
        assert _believed_tier({**body, "recorder_attestation": None}) == "community"
        stripped = {k: v for k, v in body.items() if k != "recorder_attestation"}
        assert _believed_tier(stripped) == "community"

    def test_a_ledger_consumer_with_a_trust_list_applies_revocation(self):
        from assurance.machinery.staleness import _believed_tier

        raw, _, _ = sealed()
        body = raw["evidence"]["body"]
        assert _believed_tier(body, RECORDER.trust()) == "validated"
        assert _believed_tier(body, RECORDER.trust(revoked=True)) == "community"
        assert _believed_tier(body, Recorder().trust()) == "community"


# ---------------------------------------------------------------------------
# surfaces
# ---------------------------------------------------------------------------
@pytest.fixture
def plant(tmp_path):
    env, tr = envelope(), make_trace()
    (tmp_path / "e.json").write_text(json.dumps(env.to_dict()))
    (tmp_path / "t.json").write_text(json.dumps(tr.hashable_payload()))
    return tmp_path, env, tr


class TestCli:
    def test_the_signing_tool_runs_offline_on_the_recorders_side(self, plant, capsys):
        d, env, tr = plant
        key = RECORDER.key.save(d / "rec.pem")
        assert machine_cli([
            "recorder-sign", "--key", str(key), "--trace", str(d / "t.json"),
            "--product", "Cell", "--product-version", "1.0.0", "--machine-serial", "SN-1",
            "--recorder-id", "REC-9", "--attested-on", "2026-09-12",
            "--out", str(d / "att.json")]) == 0
        out = capsys.readouterr().out
        assert "BEGIN" not in out and RECORDER.fingerprint in out
        assert "does NOT prove" in out
        att = RecorderAttestation.from_dict(json.loads((d / "att.json").read_text()))
        assert att.machine_serial == "SN-1" and att.trace_hash == tr.content_hash()
        assert RECORDER.key.verifying.verify(att.signed_payload(), att.signature_bytes())
        assert "PRIVATE" not in (d / "att.json").read_text().upper()

    def test_the_signing_tool_refuses_to_overwrite_and_to_sign_with_a_public_key(self, plant):
        d, _, _ = plant
        key = RECORDER.key.save(d / "rec.pem")
        args = ["recorder-sign", "--key", str(key), "--trace", str(d / "t.json"),
                "--product", "Cell", "--product-version", "1.0.0", "--recorder-id", "R",
                "--attested-on", "2026-09-12", "--out", str(d / "att.json")]
        assert machine_cli(args) == 0
        assert machine_cli(args) == 2                      # exists
        pub = d / "pub.pem"
        pub.write_text(RECORDER.key.verifying.pem())
        args[2] = str(pub)
        args[-1] = str(d / "att2.json")
        assert machine_cli(args) == 2

    def test_verify_with_an_attestation_and_the_checkers_own_trust_file(self, plant, capsys):
        d, env, tr = plant
        att = RECORDER.write_attestation(d / "att.json", env, tr)
        trust = RECORDER.write_trust(d / "trust.json")
        args = ["verify", "--envelope", str(d / "e.json"), "--trace", str(d / "t.json"),
                "--actor", "v.g", "--recorder-attestation", str(att), "--json"]
        assert machine_cli([*args, "--recorder-trust", str(trust)]) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["tier"] == "validated"
        assert out["result"]["provenance_basis"] == "recorder_attested"
        # no trust file: nothing is accepted
        assert machine_cli(args) == 0
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["tier"] == "community"
        assert out["result"]["recorder_attestation"]["status"] == "untrusted_key"

    def test_a_cli_never_reads_the_servers_trust_variable(self, plant, capsys, monkeypatch):
        d, env, tr = plant
        att = RECORDER.write_attestation(d / "att.json", env, tr)
        monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(RECORDER.write_trust(d / "srv.json")))
        assert machine_cli(["verify", "--envelope", str(d / "e.json"), "--trace",
                            str(d / "t.json"), "--actor", "v.g", "--recorder-attestation",
                            str(att), "--json"]) == 0
        assert json.loads(capsys.readouterr().out)["result"]["tier"] == "community"

    def test_check_replays_under_the_checkers_trust_file(self, plant, capsys):
        d, env, tr = plant
        att = RECORDER.write_attestation(d / "att.json", env, tr)
        trust = RECORDER.write_trust(d / "trust.json")
        assert machine_cli(["verify", "--envelope", str(d / "e.json"), "--trace",
                            str(d / "t.json"), "--actor", "v.g", "--recorder-attestation",
                            str(att), "--recorder-trust", str(trust), "--out",
                            str(d / "b.json")]) == 0
        capsys.readouterr()
        base = ["check", str(d / "b.json"), "--envelope", str(d / "e.json"), "--trace",
                str(d / "t.json")]
        assert machine_cli([*base, "--recorder-trust", str(trust)]) == 0
        assert "REPRODUCED" in capsys.readouterr().out
        assert machine_cli(base) == 0
        out = capsys.readouterr().out
        assert "NOT REPRODUCED" in out and "NOT believed" in out
        other = Recorder().write_trust(d / "other.json")
        assert machine_cli([*base, "--recorder-trust", str(other)]) == 1

    def test_a_private_key_given_as_an_attestation_or_trust_file_is_refused(self, plant, capsys):
        d, _, _ = plant
        key = RECORDER.key.save(d / "rec.pem")
        for flag in ("--recorder-attestation", "--recorder-trust"):
            assert machine_cli(["verify", "--envelope", str(d / "e.json"), "--trace",
                                str(d / "t.json"), "--actor", "v.g", flag, str(key)]) == 2
            assert "private key" in capsys.readouterr().err

    def test_a_trust_file_can_be_built_from_a_public_key(self, plant, capsys):
        d, _, _ = plant
        pub = d / "pub.pem"
        pub.write_text(RECORDER.key.verifying.pem())
        assert machine_cli(["recorder-trust", "--trust", str(d / "trust.json"),
                            "--public-key", str(pub), "--label", "Cell 4 recorder",
                            "--provenance", "bench,field"]) == 0
        t = RecorderTrust.from_json(d / "trust.json")
        assert t.get(RECORDER.fingerprint).label == "Cell 4 recorder"
        # a private key is refused
        key = RECORDER.key.save(d / "k.pem")
        capsys.readouterr()
        assert machine_cli(["recorder-trust", "--trust", str(d / "t2.json"),
                            "--public-key", str(key), "--label", "x",
                            "--provenance", "field"]) == 2
        err = capsys.readouterr().err
        assert "private key" in err and "BEGIN" not in err
        assert not (d / "t2.json").exists()


class TestApi:
    def _payload(self):
        env, tr = envelope(), make_trace()
        return {"envelope": env.to_dict(), "trace": tr.hashable_payload(),
                "actor": "v.grimaldi"}, env, tr

    def test_with_the_servers_trust_the_attested_trace_is_validated(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        body, env, tr = self._payload()
        r = client.post("/v1/machine/verify", json=with_attestation(body, env, tr),
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["tier"] == "validated" and d["provenance_basis"] == "recorder_attested"
        assert d["recorder_attestation"]["status"] == "accepted"
        assert d["recorder_attestation"]["key_fingerprint"] == RECORDER.fingerprint
        assert "does not establish" in d["provenance_note"]
        assert d["evidence"]["body"]["recorder_attestation"]["attestations"]

    def test_with_no_server_trust_it_is_community_and_says_why(self, client, store, monkeypatch):
        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)
        body, env, tr = self._payload()
        d = client.post("/v1/machine/verify", json=with_attestation(body, env, tr),
                        headers=keyed(store, "cell")).json()
        assert d["tier"] == "community" and d["provenance_basis"] == "declared_by_filer"
        assert d["recorder_attestation"]["status"] == "untrusted_key"
        assert d["recorder_attestation"]["trust_configured"] is False

    def test_a_broken_server_trust_file_trusts_nobody(self, client, store, monkeypatch, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json")
        monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(p))
        body, env, tr = self._payload()
        d = client.post("/v1/machine/verify", json=with_attestation(body, env, tr),
                        headers=keyed(store, "cell")).json()
        assert d["tier"] == "community"

    def test_a_caller_cannot_supply_trust_or_a_basis_to_the_sealing_path(
            self, client, store, monkeypatch):
        monkeypatch.delenv("ASSURANCE_RECORDER_TRUST", raising=False)
        body, env, tr = self._payload()
        for extra in ({"recorder_trust": RECORDER.trust_dict()},
                      {"provenance_basis": "recorder_attested"}):
            r = client.post("/v1/machine/verify",
                            json={**with_attestation(body, env, tr), **extra},
                            headers=keyed(store, "cell"))
            assert r.status_code == 422, extra

    def test_the_attestation_list_is_capped(self, client, store):
        body, env, tr = self._payload()
        body["recorder_attestations"] = [{"x": i} for i in range(MAX_ATTESTATIONS + 1)]
        r = client.post("/v1/machine/verify", json=body, headers=keyed(store, "cell"))
        assert r.status_code == 422

    def test_entitlements_are_unchanged(self, client, store):
        body, env, tr = self._payload()
        assert client.post("/v1/machine/verify", json=with_attestation(body, env, tr)
                           ).status_code == 401
        assert client.post("/v1/machine/verify", json=with_attestation(body, env, tr),
                           headers=keyed(store, "register")).status_code == 402

    def test_check_as_me_uses_the_callers_trust_and_never_the_servers(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path, recorder=Recorder("server only"))
        raw, env, tr = sealed()
        base = {"bundle": raw}
        none = client.post(CHECK_URL, json=base).json()
        assert none["ok"] is True and none["provenance_reassessed"] == "unverifiable"
        assert none["believed_tier"] == "community" and none["recorded_tier"] == "validated"
        assert none["provenance_basis_recorded"] == "recorder_attested"
        assert none["checked"]["recorder_attestation"] is False
        mine = client.post(CHECK_URL, json={**base, "recorder_trust": RECORDER.trust_dict()}).json()
        assert mine["ok"] is True and mine["provenance_reassessed"] == "reproduced"
        assert mine["believed_tier"] == "community"      # attestation only: checks not re-run
        assert mine["reassessment_note"] == "attestation re-assessed; checks not re-run"
        assert mine["checked"]["recorder_attestation"]
        full = client.post(CHECK_URL, json={**base, "recorder_trust": RECORDER.trust_dict(),
                                            "envelope": envelope().to_dict(),
                                            "trace": make_trace().hashable_payload()}).json()
        assert full["ok"] is True and full["level"] == "reproduced"
        assert full["believed_tier"] == "validated" and full["reassessment_note"] == ""
        wrong = client.post(CHECK_URL, json={**base, "recorder_trust": Recorder().trust_dict()}
                            ).json()
        assert wrong["ok"] is False and wrong["believed_tier"] == "community"

    def test_check_refuses_a_malformed_or_private_trust(self, client):
        raw, _, _ = sealed()
        r = client.post(CHECK_URL, json={"bundle": raw, "recorder_trust": {"format": "x"}})
        assert r.status_code == 422
        pem = private_pem()
        r = client.post(CHECK_URL, json={"bundle": raw, "recorder_trust": {
            "format": TRUST_FORMAT, "recorders": [{"public_key_pem": pem, "provenance": ["field"]}]}})
        assert r.status_code == 422 and "BEGIN" not in r.text

    def test_the_public_validator_reports_the_recorded_basis_and_the_reassessed_one(self, client):
        raw, _, _ = sealed()
        r = client.post("/v1/evidence/verify", content=json.dumps(raw),
                        headers={"Content-Type": "application/json"}).json()
        t = r["tier"]
        assert t["provenance_basis"] == "recorder_attested"
        assert t["provenance_reassessed"] == "unverifiable" and t["believed_tier"] == "community"
        assert r["ok"] is True       # ... which is "no inconsistency", not recorder authenticity
        assert any("recorder authenticity" in x for x in r["not_checked"] + r["assumptions"])
        h = {"Content-Type": "application/json",
             "X-Recorder-Trust": json.dumps(RECORDER.trust_dict())}
        r2 = client.post("/v1/evidence/verify", content=json.dumps(raw), headers=h).json()
        assert r2["tier"]["provenance_reassessed"] == "reproduced"
        assert r2["tier"]["believed_tier"] == "community"      # the trace is never supplied here
        h["X-Recorder-Trust"] = json.dumps(Recorder().trust_dict())
        r3 = client.post("/v1/evidence/verify", content=json.dumps(raw), headers=h).json()
        assert r3["ok"] is False and r3["tier"]["believed_tier"] == "community"

    def test_the_public_validator_refuses_a_private_key_in_the_trust_header(self, client):
        raw, _, _ = sealed()
        h = {"Content-Type": "application/json",
             "X-Recorder-Trust": "-----BEGIN PRIVATE KEY----- abc -----END PRIVATE KEY-----"}
        r = client.post("/v1/evidence/verify", content=json.dumps(raw), headers=h)
        assert r.status_code == 422 and r.json()["detail"]["error"] == "private_key_refused"

    def test_there_is_no_signing_route(self, client):
        paths = client.get("/openapi.json").json()["paths"]
        assert not [p for p in paths if "sign" in p and "machine" in p]


class TestMcp:
    @pytest.mark.asyncio
    async def test_the_verify_tool_passes_attestations_and_can_carry_no_trust_or_key(
            self, monkeypatch):
        import inspect

        from assurance.mcp import server

        seen: dict = {}

        async def record(method, path, *, json_body=None, params=None):
            seen.update(method=method, path=path, body=json_body)
            return {"status": 200, "body": {}}

        monkeypatch.setattr(server, "_call", record)
        await server.machine_verify({}, {}, "a.b", recorder_attestations=[{"x": 1}],
                                    machine_serial="SN-1")
        assert (seen["method"], seen["path"]) == ("POST", "/v1/machine/verify")
        assert set(seen["body"]) == {"envelope", "trace", "actor", "recorder_attestations",
                                     "machine_serial"}
        await server.machine_verify({}, {}, "a.b")
        assert set(seen["body"]) == {"envelope", "trace", "actor"}
        params = set(inspect.signature(server.machine_verify).parameters)
        assert not [p for p in params if "trust" in p or "key" in p or "basis" in p]

    async def test_the_verify_tool_can_file_a_verification_under_a_unit_like_the_cli_and_api(
            self, monkeypatch):
        """CLI ``--subject`` and API ``subject`` file a bundle under maker/model#serial; the
        MCP tool had no such parameter, so what it sealed never counted for a unit."""
        from assurance.mcp import server

        seen: dict = {}

        async def record(method, path, *, json_body=None, params=None):
            seen["body"] = json_body
            return {"status": 200, "body": {}}

        monkeypatch.setattr(server, "_call", record)
        await server.machine_verify({}, {}, "a.b", subject="Acme/AR-7#0412")
        assert seen["body"]["subject"] == "Acme/AR-7#0412"


# ---------------------------------------------------------------------------
# no test double reaches production
# ---------------------------------------------------------------------------
SRC = Path(__file__).resolve().parents[1] / "src"
TESTS = Path(__file__).resolve().parent


class TestNoTestDoubleInProduction:
    def test_no_module_under_src_imports_from_tests_or_names_a_test_support_file(self):
        offenders = []
        for path in SRC.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if re.search(r"^\s*(from|import)\s+tests?\b", text, re.M) \
                    or re.search(r"support_recorder|_recorder_attestation_shim|sitecustomize",
                                 text):
                offenders.append(str(path.relative_to(SRC)))
        assert not offenders, offenders

    def test_the_old_double_and_its_shim_are_gone(self):
        assert not (TESTS / "support_recorder_attestation.py").exists()
        assert not (TESTS / "_recorder_attestation_shim").exists()
        for path in TESTS.glob("*.py"):
            if path.name == Path(__file__).name:
                continue
            text = path.read_text(encoding="utf-8")
            assert "simulate_verified_recorder_attestation" not in text, path.name
            assert "_recorder_attestation_shim" not in text, path.name

    def test_production_reads_the_trust_environment_variable_in_one_place_only(self):
        users = {str(p.relative_to(SRC)) for p in SRC.rglob("*.py")
                 if re.search(r"(environ|getenv)[^\n]*ASSURANCE_RECORDER_TRUST",
                              p.read_text(encoding="utf-8"))}
        assert users == {"assurance/api/recorder_trust.py"}

    def test_python_path_and_environment_tricks_enable_nothing(self, plant, tmp_path):
        import subprocess
        import sys

        d, env, tr = plant
        trap = tmp_path / "trap"
        trap.mkdir()
        (trap / "sitecustomize.py").write_text(
            "import os\nos.environ['ASSURANCE_RECORDER_TRUST']='/dev/null'\n")
        (trap / "tests").mkdir()
        r = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "assurance", "machine", "verify", "--envelope",
             str(d / "e.json"), "--trace", str(d / "t.json"), "--actor", "v.g", "--json"],
            capture_output=True, text=True, check=False, timeout=120,
            env={**__import__("os").environ, "PYTHONPATH": f"{SRC}:{trap}:{TESTS}"})
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)["result"]
        assert out["provenance_basis"] == "declared_by_filer" and out["tier"] == "community"


class TestHelperAndFixtureSanity:
    def test_attested_helper_signs_the_actual_trace(self):
        env, tr = envelope(), make_trace()
        kw = attested(env, tr)
        assert kw["recorder_attestations"][0]["trace_hash"] == tr.content_hash()
        assert verify(env, tr, now=NOW, **kw).provenance_basis \
            == "recorder_attested"
        assert verify(env, replace(tr, trace_id="OTHER"), now=NOW, **kw).provenance_basis \
            == "declared_by_filer"

    def test_a_trusted_recorder_is_only_a_key_and_a_class_list(self):
        t = RecorderTrust([TrustedRecorder("x", SigningKey.generate().verifying,
                                           frozenset({"field"}))])
        assert len(t) == 1
