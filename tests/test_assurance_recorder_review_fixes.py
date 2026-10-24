"""Findings of the independent cryptographic review of recorder attestation.

Each class is one proved finding, written red first:

* HIGH-1   an attestation for another unit must not be accepted for this one: one strict
           subject grammar (``maker/model#serial``), one serial per verification;
* MEDIUM-2 ``believed_tier`` is ``validated`` only when the whole result was reproduced;
           unknown engine strings do not skip the check-set completeness test;
* MEDIUM-3 readers fail closed: no trust file, a broken one, or one that revokes the key
           means nothing re-assessed is ``validated``; every API reader gets the trust;
* LOW-4    the attestation binds the exact samples, not only the 6-decimal content hash;
* LOW-5    one unreadable attestation next to a real one no longer rejects an honest
           bundle on replay;
* LOW-6    a trust list with a public key of an unknown algorithm is a 422, not a 500;
* LOW-7    no expiry is documented behaviour, and a non-canonical signature is refused.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from assurance.attest.keys import SigningKeyError, VerifyingKey
from assurance.core.tiers import AssuranceTier
from assurance.machine.bundle import (
    LEVEL_INTEGRITY_ONLY,
    LEVEL_REJECTED,
    LEVEL_REPRODUCED,
    MachineSubjectError,
    build_bundle,
    check_bundle_data,
    resolve_machine_serial,
)
from assurance.machine.cli import main as machine_cli
from assurance.machine.recorder_attestation import (
    TRUST_FORMAT,
    AttestationStatus,
    RecorderAttestation,
    RecorderAttestationError,
    RecorderTrust,
)
from assurance.machine.ssm import separation_required
from assurance.machine.verify import verify

from .support_recorder import (
    RECORDER,
    Recorder,
    build_attested_bundle,
    server_trust,
    with_attestation,
)
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_recorder_attestation import (
    ACTOR,
    CHECK_URL,
    NOW,
    assess,
    envelope,
    make_trace,
    reseal,
    resign,
    sealed,
)
from .test_assurance_recorder_attestation import plant as _plant

client = _client
store = _store
plant = _plant


def _raw(bundle) -> dict:
    return json.loads(json.dumps(bundle.to_dict()))


# ---------------------------------------------------------------------------
# HIGH-1: an attestation for another unit is not evidence for this one
# ---------------------------------------------------------------------------
class TestOneSubjectGrammar:
    def _seal(self, att_serial: str, **kw):
        rec, tr, env = Recorder(), make_trace(), envelope()
        att = rec.attest_for(env, tr, machine_serial=att_serial)
        return build_bundle(env, tr, actor=ACTOR, recorder_attestations=[att],
                            recorder_trust=rec.trust(), **kw)

    def test_the_serial_in_a_machine_key_is_everything_after_the_first_hash(self):
        assert resolve_machine_serial("Mk/Md#UNIT-A", "") == "UNIT-A"
        assert resolve_machine_serial("Mk/Md#UNIT-A", "UNIT-A") == "UNIT-A"

    def test_a_subject_with_no_serial_is_a_product_line_and_keeps_the_explicit_one(self):
        assert resolve_machine_serial("", "") == ""
        assert resolve_machine_serial("Cell@1.0.0", "") == ""
        assert resolve_machine_serial("Cell@1.0.0", "SN-1") == "SN-1"
        assert resolve_machine_serial("", "SN-1") == "SN-1"

    @pytest.mark.parametrize("subject", [
        "Mk/Md#UNIT-B#", "Mk/Md#", "Mk/Md#X#UNIT-A", "Mk/Md##UNIT-A", "#UNIT-A",
        "Mk/Md# UNIT-A", "Mk/Md#UNIT-A ", "Mk/Md#UNIT\nA",
    ])
    def test_a_malformed_unit_key_is_refused_whatever_else_is_given(self, subject):
        for explicit in ("", "UNIT-A"):
            with pytest.raises(MachineSubjectError):
                resolve_machine_serial(subject, explicit)

    def test_an_explicit_serial_that_differs_from_the_keys_is_refused_with_a_remedy(self):
        with pytest.raises(MachineSubjectError) as exc:
            resolve_machine_serial("Mk/Md#UNIT-B", "UNIT-A")
        text = str(exc.value)
        assert "UNIT-A" in text and "UNIT-B" in text and "omit machine_serial" in text

    def test_the_exploit_an_attestation_for_unit_a_filed_under_unit_b_is_refused(self):
        with pytest.raises(MachineSubjectError):
            self._seal("UNIT-A", subject="Mk/Md#UNIT-B", machine_serial="UNIT-A")

    @pytest.mark.parametrize("subject", ["Mk/Md#UNIT-B#", "Mk/Md#X#UNIT-A"])
    def test_the_exploit_by_a_trailing_or_embedded_hash_is_refused(self, subject):
        with pytest.raises(MachineSubjectError):
            self._seal("UNIT-A", subject=subject)

    def test_unit_a_attestation_under_unit_bs_key_does_not_lift_and_says_why(self):
        b = self._seal("UNIT-A", subject="Mk/Md#UNIT-B")
        assert b.result.provenance_basis == "declared_by_filer"
        assert b.tier.rank <= AssuranceTier.COMMUNITY.rank
        assert b.result.recorder_attestation["status"] == "machine_mismatch"
        assert b.evidence.body["machine_serial"] == "UNIT-B"

    @pytest.mark.parametrize("kw", [{}, {"machine_serial": "UNIT-A"}])
    def test_the_matching_unit_still_lifts(self, kw):
        b = self._seal("UNIT-A", subject="Mk/Md#UNIT-A", **kw)
        assert b.result.provenance_basis == "recorder_attested"
        assert b.tier is AssuranceTier.VALIDATED
        assert b.evidence.body["machine_serial"] == "UNIT-A"

    def test_a_product_line_subject_does_not_require_the_serial_the_recorder_names(self):
        b = self._seal("UNIT-A", subject="Cell@1.0.0")
        assert b.result.provenance_basis == "recorder_attested"
        assert b.evidence.body["machine_serial"] == ""

    def test_the_cli_refuses_a_conflicting_serial(self, plant, capsys):
        d, _, _ = plant
        code = machine_cli([
            "verify", "--envelope", str(d / "e.json"), "--trace", str(d / "t.json"),
            "--actor", "v.g", "--subject", "Mk/Md#UNIT-B", "--machine-serial", "UNIT-A"])
        assert code != 0
        assert "UNIT-A" in capsys.readouterr().err

    def _payload(self, **extra):
        env, tr = envelope(), make_trace()
        return {"envelope": env.to_dict(), "trace": tr.hashable_payload(),
                "actor": "v.grimaldi", **extra}, env, tr

    @pytest.mark.parametrize("extra", [
        {"subject": "Mk/Md#UNIT-B", "machine_serial": "UNIT-A"},
        {"subject": "Mk/Md#UNIT-B#"},
        {"subject": "Mk/Md#X#UNIT-A"},
        {"subject": "Mk/Md#"},
    ])
    def test_the_api_refuses_it_with_a_422_and_a_remedy(self, client, store, monkeypatch,
                                                         tmp_path, extra):
        server_trust(monkeypatch, tmp_path)
        body, env, tr = self._payload(**extra)
        body = with_attestation(body, env, tr, machine_serial="UNIT-A")
        r = client.post("/v1/machine/verify", json=body, headers=keyed(store, "cell"))
        assert r.status_code == 422, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_subject"
        assert "machine_serial" in detail["detail"] or "serial" in detail["detail"]

    def test_the_api_matching_unit_lifts_and_a_mismatched_key_does_not(
            self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        body, env, tr = self._payload(subject="Mk/Md#UNIT-A")
        ok = client.post("/v1/machine/verify",
                         json=with_attestation(body, env, tr, machine_serial="UNIT-A"),
                         headers=h)
        assert ok.status_code == 200 and ok.json()["tier"] == "validated"
        body, env, tr = self._payload(subject="Mk/Md#UNIT-B")
        other = client.post("/v1/machine/verify",
                            json=with_attestation(body, env, tr, machine_serial="UNIT-A"),
                            headers=h)
        assert other.status_code == 200
        assert other.json()["tier"] == "community"
        assert other.json()["recorder_attestation"]["status"] == "machine_mismatch"


# ---------------------------------------------------------------------------
# MEDIUM-2: the believed tier
# ---------------------------------------------------------------------------
class TestTheBelievedTier:
    def _forged_failing_run(self):
        """A trusted recorder honestly attests a FAILING run; the bundle is then rewritten
        to a pass and resealed (the seal is a hash, not a signature)."""
        env, tf, rec = envelope(), make_trace(sep=100.0), Recorder()
        raw = _raw(build_attested_bundle(env, tf, actor=ACTOR, recorder=rec))
        body = raw["evidence"]["body"]
        assert body["verdict"] == "fail"
        for blk in (body["checks"], raw["result"]["checks"]):
            for c in blk:
                if c["outcome"] == "violated":
                    c["outcome"], c["violations"], c["violation_count"] = "verified", [], 0
        body["verdict"] = raw["result"]["verdict"] = "pass"
        raw["evidence"]["validation_state"] = "verified"
        raw["evidence"]["confidence"] = "high"
        raw["result"]["may_claim_physical_behaviour"] = True
        return reseal(raw), env, tf, rec

    def test_a_flipped_verdict_is_not_the_believed_tier_without_the_trace(self):
        raw, env, _, rec = self._forged_failing_run()
        for kw in ({}, {"envelope": env}):
            res = check_bundle_data(raw, recorder_trust=rec.trust(), **kw)
            assert res.ok and res.level == LEVEL_INTEGRITY_ONLY      # undetectable here
            assert res.believed_tier == "community"                  # ... so not believed
            assert res.provenance_reassessed == "reproduced"
            assert res.reassessment_note == "attestation re-assessed; checks not re-run"

    def test_with_the_trace_the_flip_is_rejected_and_nothing_is_believed(self):
        raw, env, tf, rec = self._forged_failing_run()
        res = check_bundle_data(raw, envelope=env, trace=tf, recorder_trust=rec.trust())
        assert not res.ok and res.level == LEVEL_REJECTED
        assert res.believed_tier == "community"

    def test_a_rejected_bundle_never_reports_validated(self):
        raw, env, tr = sealed()
        other = make_trace(trace_id="RUN-OTHER", sep=2500.0)
        res = check_bundle_data(raw, envelope=env, trace=other,
                                recorder_trust=RECORDER.trust())
        assert not res.ok and res.believed_tier == "community"

    def test_a_replay_that_differs_is_not_believed_even_if_the_attestation_reassesses(self):
        raw, env, tr = sealed()
        raw["evidence"]["body"]["provenance_assessment"]["explanation"] = "edited after sealing"
        reseal(raw)
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust())
        assert not res.ok and res.level == LEVEL_REJECTED
        assert res.provenance_reassessed == "reproduced"       # the attestation itself holds
        assert res.believed_tier == "community"                # the bundle does not

    def test_only_a_full_reproduction_believes_validated(self):
        raw, env, tr = sealed()
        full = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=RECORDER.trust())
        assert full.ok and full.level == LEVEL_REPRODUCED
        assert full.believed_tier == "validated" and full.reassessment_note == ""
        part = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert part.ok and part.level == LEVEL_INTEGRITY_ONLY
        assert part.believed_tier == "community"
        assert part.reassessment_note == "attestation re-assessed; checks not re-run"
        assert check_bundle_data(raw, envelope=env, trace=tr).believed_tier == "community"

    def test_a_lower_recorded_tier_is_never_raised(self):
        env, tr = envelope(), make_trace()
        raw = _raw(build_bundle(env, tr, actor=ACTOR))
        res = check_bundle_data(raw, envelope=env, trace=tr)
        assert res.ok and res.believed_tier == raw["evidence"]["body"]["tier"] == "community"

    def test_the_api_labels_it_and_does_not_call_it_the_believed_tier(self, client):
        raw, _, _ = sealed()
        d = client.post(CHECK_URL, json={"bundle": raw,
                                         "recorder_trust": RECORDER.trust_dict()}).json()
        assert d["ok"] is True and d["level"] == "integrity_only"
        assert d["provenance_reassessed"] == "reproduced"
        assert d["believed_tier"] == "community"
        assert d["reassessment_note"] == "attestation re-assessed; checks not re-run"

    def test_the_cli_says_it_in_the_same_words(self, tmp_path, capsys):
        raw, _, _ = sealed()
        (tmp_path / "b.json").write_text(json.dumps(raw))
        trust = RECORDER.write_trust(tmp_path / "trust.json")
        code = machine_cli(["check", str(tmp_path / "b.json"), "--recorder-trust", str(trust)])
        out = capsys.readouterr().out
        assert code == 0
        assert "attestation re-assessed; checks not re-run" in out
        assert "tier believed by this check" not in out

    def test_the_public_validator_says_the_same(self, client):
        raw, _, _ = sealed()
        h = {"Content-Type": "application/json",
             "X-Recorder-Trust": json.dumps(RECORDER.trust_dict())}
        t = client.post("/v1/evidence/verify", content=json.dumps(raw), headers=h).json()["tier"]
        assert t["provenance_reassessed"] == "reproduced"
        assert t["believed_tier"] == "community"
        assert t["reassessment_note"] == "attestation re-assessed; checks not re-run"


class TestUnknownEngineVersions:
    def _declared(self):
        env, tr = envelope(), make_trace()
        return _raw(build_bundle(env, tr, actor=ACTOR)), env, tr

    def _with_engine(self, raw, version, *, drop_checks=3):
        raw["evidence"]["body"]["engine_version"] = version
        raw["evidence"]["body"]["checks"] = raw["evidence"]["body"]["checks"][:drop_checks]
        del raw["result"]                     # isolate coherence from the printed result
        return reseal(raw)

    @pytest.mark.parametrize("version", ["7", "٦", "06", " 6", "6 ", "0", "0-old", "", "6.0",
                                         "٥", "1e1"])
    def test_an_unknown_engine_does_not_skip_the_completeness_test(self, version):
        raw, _, _ = self._declared()
        res = check_bundle_data(self._with_engine(raw, version))
        assert not res.ok, version
        assert any("unknown engine" in p for p in res.problems), res.problems

    @pytest.mark.parametrize("version", ["٦", "7", "06"])
    def test_an_attested_bundle_naming_an_unknown_engine_is_rejected(self, version):
        raw, _, _ = sealed()
        raw["evidence"]["body"]["engine_version"] = version
        raw["evidence"]["body"]["checks"] = raw["evidence"]["body"]["checks"][:3]
        del raw["result"]
        reseal(raw)
        res = check_bundle_data(raw, recorder_trust=RECORDER.trust())
        assert not res.ok and res.believed_tier == "community"
        assert any("unknown engine" in p for p in res.problems), res.problems

    def test_an_older_engine_that_really_existed_is_still_only_a_limitation(self):
        raw, _, _ = self._declared()
        res = check_bundle_data(self._with_engine(raw, "5"))
        assert not any("unknown engine" in p for p in res.problems)
        assert any("NOT CHECKED" in n and "'5'" in n for n in res.limitations)

    def test_the_ledger_readers_parse_the_engine_as_strictly(self):
        from assurance.machinery.staleness import _believed_tier

        raw, _, _ = sealed()
        body = raw["evidence"]["body"]
        assert _believed_tier(body) == "validated"
        for bad in ("٦", " 6", "6 ", "06", "6.0", "+6"):
            assert _believed_tier({**body, "engine_version": bad}) == "community", bad


# ---------------------------------------------------------------------------
# LOW-4: the attestation binds the exact samples
# ---------------------------------------------------------------------------
class TestExactSamples:
    def _pair(self):
        env = envelope()
        required = separation_required(env, robot_speed_mm_s=300.0,
                                       human_speed_mm_s=None).total_mm
        failing = make_trace(sep=required - 4e-7)
        passing = make_trace(sep=required + 4e-7)
        return env, failing, passing

    def test_the_premise_both_traces_share_a_content_hash_and_differ_in_verdict(self):
        env, failing, passing = self._pair()
        assert failing.content_hash() == passing.content_hash()
        assert verify(env, failing).verdict.value == "fail"
        assert verify(env, passing).verdict.value == "pass"
        assert failing.exact_digest() != passing.exact_digest()

    def test_the_swap_is_a_trace_mismatch_and_the_tier_is_not_lifted(self):
        env, failing, passing = self._pair()
        rec = Recorder()
        att = rec.attest_for(env, failing).to_dict()
        honest = verify(env, failing, recorder_attestations=[att],
                        recorder_trust=rec.trust(), now=NOW)
        assert honest.provenance_basis == "recorder_attested"
        assert honest.verdict.value == "fail"
        swapped = verify(env, passing, recorder_attestations=[att],
                         recorder_trust=rec.trust(), now=NOW)
        assert swapped.provenance_basis == "declared_by_filer"
        assert swapped.tier.rank <= AssuranceTier.COMMUNITY.rank
        assert swapped.recorder_attestation["status"] == "trace_mismatch"
        assert "exact" in swapped.recorder_attestation["findings"][0]["detail"]

    def test_a_validated_bundle_does_not_replay_against_a_trace_that_differs_below_the_hash(self):
        env, rec = envelope(), Recorder()
        tr = make_trace()
        near = replace(tr, samples=(replace(tr.samples[0], tcp_speed=300.0 + 4e-7),
                                    *tr.samples[1:]))
        assert near.content_hash() == tr.content_hash() and near.exact_digest() != tr.exact_digest()
        raw = _raw(build_attested_bundle(env, tr, actor=ACTOR, recorder=rec))
        assert check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=rec.trust()).reproduced
        res = check_bundle_data(raw, envelope=env, trace=near, recorder_trust=rec.trust())
        assert not res.ok and res.believed_tier == "community"

    def test_the_attestation_carries_the_digest_inside_the_signed_body(self):
        tr = make_trace()
        att = Recorder().attest(tr)
        assert att.exact_samples_digest == tr.exact_digest()
        assert att.to_dict()["exact_samples_digest"] == tr.exact_digest()
        assert b"exact_samples_digest" in att.signed_payload()

    def test_a_v1_attestation_without_the_digest_is_malformed(self):
        rec, tr = Recorder(), make_trace()
        d = rec.attest_for(envelope(), tr).to_dict()
        del d["exact_samples_digest"]
        out = assess(tr, [d], rec.trust())
        assert out.status is AttestationStatus.MALFORMED
        assert "exact_samples_digest" in out.findings[0].detail

    def test_a_forged_digest_with_a_bad_signature_or_wrong_form_is_refused(self):
        rec, tr = Recorder(), make_trace()
        good = rec.attest_for(envelope(), tr)
        d = good.to_dict()
        d["exact_samples_digest"] = "0" * 64
        assert assess(tr, [d], rec.trust()).status is AttestationStatus.BAD_SIGNATURE
        d["exact_samples_digest"] = "xyz"
        assert assess(tr, [d], rec.trust()).status is AttestationStatus.MALFORMED

    def test_a_signed_wrong_digest_is_a_trace_mismatch(self):
        rec, tr = Recorder(), make_trace()
        good = rec.attest_for(envelope(), tr)
        lying = resign(good, rec.key, exact_samples_digest="1" * 64)
        assert assess(tr, [lying], rec.trust()).status is AttestationStatus.TRACE_MISMATCH

    @pytest.mark.parametrize("edit", [
        pytest.param(lambda t: replace(t, samples=(t.samples[0],
                                                   replace(t.samples[1], t=t.samples[1].t + 1e-9),
                                                   *t.samples[2:])), id="t"),
        pytest.param(lambda t: replace(t, samples=(replace(t.samples[0], tcp_speed=300.0 + 1e-9),
                                                   *t.samples[1:])), id="speed"),
        pytest.param(lambda t: replace(t, samples=(replace(t.samples[0],
                                                           tcp=(1e-9, 0.0, 1000.0)),
                                                   *t.samples[1:])), id="tcp"),
        pytest.param(lambda t: replace(t, samples=(replace(t.samples[0], human_speed=1e-9),
                                                   *t.samples[1:])), id="human-speed"),
        pytest.param(lambda t: replace(t, sample_rate_hz=50.0 + 1e-9), id="rate"),
        pytest.param(lambda t: replace(t, conditions={"x": 1e-9}), id="conditions"),
        pytest.param(lambda t: replace(t, started_at=t.started_at + timedelta(seconds=1)),
                     id="started-at"),
    ])
    def test_every_field_is_inside_the_exact_digest(self, edit):
        tr = make_trace(conditions={"x": 0.0})
        edited = edit(tr)
        assert edited.exact_digest() != tr.exact_digest()

    def test_the_digest_is_stable_and_is_not_the_content_hash(self):
        tr = make_trace()
        assert tr.exact_digest() == make_trace().exact_digest()
        assert tr.exact_digest() != tr.content_hash() and len(tr.exact_digest()) == 64

    def test_an_honest_trace_is_still_accepted(self):
        rec, tr = Recorder(), make_trace()
        assert assess(tr, [rec.attest_for(envelope(), tr)], rec.trust()).attested


# ---------------------------------------------------------------------------
# LOW-5: an unreadable attestation next to a real one
# ---------------------------------------------------------------------------
class TestReplayIgnoresWhatCouldNotBeRead:
    def _cases(self, env, tr, rec):
        real = rec.attest_for(env, tr).to_dict()
        stranger = Recorder().attest_for(env, tr).to_dict()
        return {
            "junk+real": [{"x": 1}, real],
            "real+junk": [real, {"x": 1}],
            "unsupported-version+real": [
                {"format": "assurance.machine.recorder-attestation.v9"}, real],
            "real+dupe": [real, real],
            "other-untrusted-key+real": [stranger, real],
            "junk only": [{"x": 1}],
            "unsupported only": [{"format": "assurance.machine.recorder-attestation.v9"}],
            "junk+untrusted": [{"x": 1}, stranger],
            "not-a-dict+real": ["nope", real],
        }

    @pytest.mark.parametrize("case", [
        "junk+real", "real+junk", "unsupported-version+real", "real+dupe",
        "other-untrusted-key+real", "junk only", "unsupported only", "junk+untrusted",
        "not-a-dict+real"])
    def test_an_honest_bundle_reproduces(self, case):
        env, tr, rec = envelope(), make_trace(), Recorder()
        atts = self._cases(env, tr, rec)[case]
        b = build_bundle(env, tr, actor=ACTOR, recorder_attestations=atts,
                         recorder_trust=rec.trust())
        raw = _raw(b)
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=rec.trust())
        assert res.ok and res.level == LEVEL_REPRODUCED, res.problems
        # the placeholder of what could not be read is still sealed, for the record
        assert len(raw["evidence"]["body"]["recorder_attestation"]["attestations"]) == len(atts) \
            or case == "real+dupe"

    def test_replay_does_not_feed_a_placeholder_back_to_the_assessor(self, monkeypatch):
        from assurance.machine import bundle as bundle_module

        env, tr, rec = envelope(), make_trace(), Recorder()
        raw = _raw(build_bundle(env, tr, actor=ACTOR, recorder_trust=rec.trust(),
                                recorder_attestations=[{"x": 1},
                                                       rec.attest_for(env, tr).to_dict()]))
        assert any("unreadable" in a for a in
                   raw["evidence"]["body"]["recorder_attestation"]["attestations"])
        seen: list = []
        original = bundle_module.verify

        def spy(*a, **kw):
            seen.append(list(kw["recorder_attestations"]))
            return original(*a, **kw)

        monkeypatch.setattr(bundle_module, "verify", spy)
        assert check_bundle_data(raw, envelope=env, trace=tr,
                                 recorder_trust=rec.trust()).reproduced
        assert len(seen) == 1 and len(seen[0]) == 1 and "unreadable" not in seen[0][0]

    def test_the_headline_of_a_refusal_is_about_what_could_be_read(self):
        env, tr, rec = envelope(), make_trace(), Recorder()
        stranger = Recorder().attest_for(env, tr).to_dict()
        out = assess(tr, [{"x": 1}, stranger], rec.trust())
        assert out.status is AttestationStatus.UNTRUSTED_KEY
        assert [f.status for f in out.findings][0] is AttestationStatus.MALFORMED
        assert "malformed" not in out.explanation       # unreadable ones do not shape it
        only_junk = assess(tr, [{"x": 1}], rec.trust())
        assert only_junk.status is AttestationStatus.MALFORMED
        assert "no readable recorder attestation" in only_junk.explanation

    def test_the_accepted_attestation_and_tier_are_what_replay_compares(self):
        env, tr, rec = envelope(), make_trace(), Recorder()
        real = rec.attest_for(env, tr).to_dict()
        raw = _raw(build_bundle(env, tr, actor=ACTOR,
                                recorder_attestations=[{"x": 1}, real],
                                recorder_trust=rec.trust()))
        assert raw["evidence"]["body"]["tier"] == "validated"
        # a checker that does not trust the key still rejects the lifted tier
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=Recorder().trust())
        assert not res.ok and res.believed_tier == "community"

    def test_a_replay_still_catches_a_swapped_accepted_attestation(self):
        env, tr, rec = envelope(), make_trace(), Recorder()
        raw = _raw(build_bundle(env, tr, actor=ACTOR,
                                recorder_attestations=[{"x": 1},
                                                       rec.attest_for(env, tr).to_dict()],
                                recorder_trust=rec.trust()))
        other = Recorder().attest_for(env, tr).to_dict()
        raw["evidence"]["body"]["recorder_attestation"]["accepted_attestation"] = other
        reseal(raw)
        res = check_bundle_data(raw, envelope=env, trace=tr, recorder_trust=rec.trust())
        assert not res.ok

    def test_a_forged_tier_on_a_junk_only_bundle_is_still_rejected_on_replay(self):
        env, tr, rec = envelope(), make_trace(), Recorder()
        raw = _raw(build_bundle(env, tr, actor=ACTOR, recorder_attestations=[{"x": 1}],
                                recorder_trust=rec.trust()))
        for blk in (raw["evidence"]["body"], raw["result"]):
            blk["tier"] = "validated"
            blk["provenance_basis"] = "recorder_attested"
        reseal(raw)
        assert not check_bundle_data(raw, envelope=env, trace=tr,
                                     recorder_trust=rec.trust()).ok


# ---------------------------------------------------------------------------
# LOW-6: a public key of an algorithm this service does not know
# ---------------------------------------------------------------------------
def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    return bytes([tag]) + (bytes([n]) if n < 128 else bytes([0x81, n])) + body


_SPKI = _der(0x30, _der(0x30, _der(0x06, bytes([0x2A, 0x03, 0x04]))) + _der(0x03, b"\x00" + b"A" * 32))
UNKNOWN_ALGORITHM_PEM = ("-----BEGIN PUBLIC KEY-----\n"
                         + base64.encodebytes(_SPKI).decode()
                         + "-----END PUBLIC KEY-----\n")
UNKNOWN_ALGORITHM_TRUST = {"format": TRUST_FORMAT, "recorders": [
    {"public_key_pem": UNKNOWN_ALGORITHM_PEM, "provenance": ["field"]}]}


class TestAKeyOfAnUnknownAlgorithm:
    def test_the_key_loader_reports_it_as_a_key_error(self):
        with pytest.raises(SigningKeyError):
            VerifyingKey.from_pem(UNKNOWN_ALGORITHM_PEM)

    def test_the_trust_list_reports_it_as_an_attestation_error(self):
        with pytest.raises(RecorderAttestationError):
            RecorderTrust.from_dict(UNKNOWN_ALGORITHM_TRUST)

    def test_bundle_check_answers_422_not_500(self, client):
        raw, _, _ = sealed()
        r = client.post(CHECK_URL, json={"bundle": raw,
                                         "recorder_trust": UNKNOWN_ALGORITHM_TRUST})
        assert r.status_code == 422, r.text
        assert r.json()["detail"]["error"] == "invalid_recorder_trust"

    def test_the_public_validator_answers_422_not_500(self, client):
        raw, _, _ = sealed()
        h = {"Content-Type": "application/json",
             "X-Recorder-Trust": json.dumps(UNKNOWN_ALGORITHM_TRUST)}
        r = client.post("/v1/evidence/verify", content=json.dumps(raw), headers=h)
        assert r.status_code == 422, r.text
        assert r.json()["detail"]["error"] == "invalid_recorder_trust"

    def test_a_server_trust_file_with_one_fails_closed_and_breaks_no_route(
            self, client, store, monkeypatch, tmp_path):
        p = tmp_path / "trust.json"
        p.write_text(json.dumps(UNKNOWN_ALGORITHM_TRUST))
        monkeypatch.setenv("ASSURANCE_RECORDER_TRUST", str(p))
        env, tr = envelope(), make_trace()
        body = with_attestation({"envelope": env.to_dict(), "trace": tr.hashable_payload(),
                                 "actor": "v.g"}, env, tr)
        r = client.post("/v1/machine/verify", json=body, headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        assert r.json()["tier"] == "community"


# ---------------------------------------------------------------------------
# LOW-7: expiry and the signature's spelling
# ---------------------------------------------------------------------------
class TestExpiryAndSignatureSpelling:
    def test_an_attestation_with_no_expiry_never_expires_and_says_so(self):
        rec, tr = Recorder(), make_trace()
        att = rec.attest_for(envelope(), tr)
        later = datetime(2036, 1, 1, tzinfo=UTC)
        out = assess(tr, [att], rec.trust(), now=later)
        assert out.attested
        assert "no expiry date" in out.explanation
        assert "revoked" in out.explanation

    def test_an_expiry_date_is_still_honoured(self):
        rec, tr = Recorder(), make_trace()
        att = rec.attest_for(envelope(), tr, expires_on="2026-10-01")
        assert assess(tr, [att], rec.trust(), now=NOW).attested
        late = datetime(2026, 10, 2, tzinfo=UTC)
        assert assess(tr, [att], rec.trust(), now=late).status is AttestationStatus.EXPIRED

    @staticmethod
    def _non_canonical(signature: str) -> str:
        """Another spelling of the same 64 bytes: the unused bits of the last character."""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        assert signature.endswith("==")
        last = signature[-3]
        idx = alphabet.index(last)
        other = alphabet[(idx & ~0xF) | ((idx + 1) & 0xF)]
        assert other != last
        variant = signature[:-3] + other + "=="
        assert base64.b64decode(variant, validate=True) == base64.b64decode(signature)
        return variant

    def test_the_same_signature_in_another_spelling_is_refused(self):
        rec, tr = Recorder(), make_trace()
        d = rec.attest_for(envelope(), tr).to_dict()
        assert assess(tr, [d], rec.trust()).attested
        d["signature"] = self._non_canonical(d["signature"])
        out = assess(tr, [d], rec.trust())
        assert out.status is AttestationStatus.MALFORMED
        assert "canonical" in out.findings[0].detail

    def test_the_strict_parser_refuses_it_too(self):
        d = Recorder().attest_for(envelope(), make_trace()).to_dict()
        d["signature"] = self._non_canonical(d["signature"])
        with pytest.raises(RecorderAttestationError, match="canonical"):
            RecorderAttestation.from_dict(d)


# ---------------------------------------------------------------------------
# the offline sign + verify path still opens no sockets
# ---------------------------------------------------------------------------
class TestOfflineStaysOffline:
    def test_signing_and_verifying_a_recording_open_no_socket(self, monkeypatch):
        import socket

        def refuse(*a, **k):
            raise AssertionError("the offline recorder path opened a socket")

        monkeypatch.setattr(socket.socket, "connect", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        env, tr, rec = envelope(), make_trace(), Recorder()
        att = rec.attest_for(env, tr)
        res = verify(env, tr, recorder_attestations=[att.to_dict()],
                     recorder_trust=rec.trust(), now=NOW)
        assert res.provenance_basis == "recorder_attested"
        raw = _raw(build_bundle(env, tr, actor=ACTOR, recorder_attestations=[att],
                                recorder_trust=rec.trust()))
        assert check_bundle_data(raw, envelope=env, trace=tr,
                                 recorder_trust=rec.trust()).reproduced

