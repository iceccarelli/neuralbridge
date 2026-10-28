"""A mistyped or hostile first claim cannot burn a recording for the real unit.

Regression (round-2 review, F2): the one-recording-one-unit rule counted EVERY first validated
filing, so anyone holding the recording and its attestation could seal it first under
``Acme/AR7#0001`` (a typo) or ``Evil/Co#0001`` and the legitimate ``Acme/AR-7#0001`` seal then
returned 422 -- or, filed anyway, read ``community`` for ever in an append-only ledger.

The rule now: only a claim under a unit key that is ENROLLED in the same ledger (a manifest for it
was sealed there) holds a recording. A claim under a key nobody enrolled holds nothing; once an
enrolled unit claims the same recording, the unenrolled claim reads ``community`` with the reason.

Residual, stated: a tenant member who can enrol a manifest for a hostile key can still squat; the
ledger is append-only and has no withdrawal, so the remedy is a new recording attested for the
unit. That is in the refusal message.
"""

from __future__ import annotations

import pytest

from assurance.machine.bundle import MachineSubjectError, build_bundle
from assurance.machinery.record import record_manifest
from assurance.machinery.staleness import VerificationRecord

from .support_recorder import Recorder, server_trust, with_attestation
from .support_trust_hardening import KEY, attested_bundle, ledger, manifest
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_machine_provenance import ACTOR, envelope, laptop_trace
from .test_assurance_recorder_attestation import envelope as att_envelope
from .test_assurance_recorder_attestation import make_trace

client, store = _client, _store

TYPO, EVIL = "Acme/AR7#0001", "Evil/Co#0001"


def _read(led, key, rec):
    return VerificationRecord.from_ledger(led, subject=key, recorder_trust=rec.trust())


@pytest.mark.parametrize("squatter", [TYPO, EVIL, "Аcme/AR-7#0001"])
def test_an_unenrolled_first_claim_does_not_block_sealing_the_real_unit(tmp_path, squatter):
    led = ledger(tmp_path)
    rec, tr = Recorder(), laptop_trace()
    attested_bundle(squatter, rec=rec, trace=tr, file_under=led)       # the typo / hostile claim
    record_manifest(led, manifest())                                   # the real unit is enrolled
    real, _ = attested_bundle(KEY, rec=rec, trace=tr, file_under=led)  # must NOT be refused
    assert real.tier.value == "validated"
    (mine,) = _read(led, KEY, rec)
    assert mine.tier == "validated" and mine.tier_note == ""


@pytest.mark.parametrize("squatter", [TYPO, EVIL])
def test_the_squatters_claim_then_reads_community_with_the_reason(tmp_path, squatter):
    led = ledger(tmp_path)
    rec, tr = Recorder(), laptop_trace()
    attested_bundle(squatter, rec=rec, trace=tr, file_under=led)
    assert [r.tier for r in _read(led, squatter, rec)] == ["validated"]   # alone, unchallenged
    record_manifest(led, manifest())
    attested_bundle(KEY, rec=rec, trace=tr, file_under=led)
    (theirs,) = _read(led, squatter, rec)
    assert theirs.tier == "community"
    assert KEY in theirs.tier_note


def test_an_enrolled_first_claim_still_holds_the_recording(tmp_path):
    """The residual: enrolling a manifest is what makes a claim count."""
    led = ledger(tmp_path)
    rec, tr = Recorder(), laptop_trace()
    record_manifest(led, manifest("Evil", "Co", "0001"))
    attested_bundle(EVIL, rec=rec, trace=tr, file_under=led)
    record_manifest(led, manifest())
    with pytest.raises(MachineSubjectError) as refused:
        attested_bundle(KEY, rec=rec, trace=tr, file_under=led)
    message = str(refused.value)
    assert EVIL in message
    # the refusal names the real remedy (a new recording), not "file it without an attestation"
    assert "new recording" in message
    assert "without an attestation" not in message


def test_a_manifest_that_fails_its_own_seal_enrols_nothing(tmp_path):
    import json
    import sqlite3

    from assurance.machinery.record import MANIFEST_KIND
    led = ledger(tmp_path)
    rec, tr = Recorder(), laptop_trace()
    record_manifest(led, manifest("Evil", "Co", "0001"))
    db = sqlite3.connect(led.path)
    seq, payload = db.execute("select seq,payload from chain where kind=?",
                              (MANIFEST_KIND,)).fetchone()
    p = json.loads(payload)
    p["body"]["manifest"]["machine"]["site"] = "edited after sealing"
    db.execute("update chain set payload=? where seq=?",
               (json.dumps(p, sort_keys=True, separators=(",", ":")), seq))
    db.commit()
    db.close()
    attested_bundle(EVIL, rec=rec, trace=tr, file_under=led)       # claims, but is not enrolled
    record_manifest(led, manifest())
    real, _ = attested_bundle(KEY, rec=rec, trace=tr, file_under=led)
    assert real.tier.value == "validated"


def test_two_enrolled_units_still_cannot_share_a_recording(tmp_path):
    led = ledger(tmp_path)
    rec, tr = Recorder(), laptop_trace()
    for k in (KEY, "Beta/XY-9#0002"):
        maker, _, rest = k.partition("/")
        model, _, serial = rest.partition("#")
        record_manifest(led, manifest(maker, model, serial))
    attested_bundle(KEY, rec=rec, trace=tr, file_under=led)
    with pytest.raises(MachineSubjectError):
        attested_bundle("Beta/XY-9#0002", rec=rec, trace=tr, file_under=led)


def test_a_claim_whose_recorder_key_was_revoked_blocks_nothing(tmp_path):
    """Build time uses the same trust-aware claim map as the reader (round-2 LOW 7)."""
    led = ledger(tmp_path)
    old, new, tr = Recorder("old"), Recorder("new"), laptop_trace()
    env = envelope()
    record_manifest(led, manifest())
    record_manifest(led, manifest("Beta", "XY-9", "0002"))
    first = old.attest_for(env, tr, machine_serial="0001").to_dict()
    build_bundle(env, tr, actor=ACTOR, recorder_attestations=[first],
                 recorder_trust=old.trust(), subject=KEY, ledger=led)
    second = new.attest_for(env, tr, machine_serial="0002").to_dict()
    from assurance.machine.recorder_attestation import RecorderTrust
    trust = RecorderTrust([*old.trust(revoked=True).recorders, *new.trust().recorders])
    sealed = build_bundle(env, tr, actor=ACTOR, recorder_attestations=[second],
                          recorder_trust=trust, subject="Beta/XY-9#0002", ledger=led)
    assert sealed.tier.value == "validated"


class TestTheHostedRoute:
    @staticmethod
    def _verify(client, headers, subject, serial):
        env, tr = att_envelope(), make_trace()
        body = with_attestation({
            "envelope": env.to_dict(), "trace": tr.hashable_payload(),
            "actor": "a.integrator", "subject": subject}, env, tr, machine_serial=serial)
        return client.post("/v1/machine/verify", json=body, headers=headers)

    def test_a_typo_cannot_burn_the_recording(self, client, store, monkeypatch, tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        typo = self._verify(client, h, TYPO, "0001")
        assert typo.status_code == 200
        legit = self._verify(client, h, KEY, "0001")
        assert legit.status_code == 200 and legit.json()["tier"] == "validated"

    def test_an_enrolled_claim_is_refused_with_the_remedy(self, client, store, monkeypatch,
                                                          tmp_path):
        server_trust(monkeypatch, tmp_path)
        h = keyed(store, "cell")
        for m in (manifest("Evil", "Co", "0001"), manifest()):
            assert client.post("/v1/machinery/manifest", json={"manifest": m.to_dict()},
                               headers=h).status_code == 200
        assert self._verify(client, h, EVIL, "0001").status_code == 200
        refused = self._verify(client, h, KEY, "0001")
        assert refused.status_code == 422
        assert refused.json()["detail"]["error"] == "invalid_subject"
        assert "new recording" in refused.json()["detail"]["detail"]
