"""The key ceremony tooling: keygen guards, the recorder trust-list workflow, preflight,
rotation and revocation, driven through the real verifiers.

What is under test is not that a signature verifies. It is that the operator cannot be led
into the mistakes that make a key worthless: a private key readable by the host, a key
overwritten, a trust list that names a key nobody checked, a revoked key still believed, a
key taken from the artefact it is meant to check. And that no command, on any path, prints
the private key.

Every key here is a throwaway generated in a temp directory. Nothing is configured anywhere.
"""

# The tests make files deliberately too open, to show they are refused.
# ruff: noqa: S103
from __future__ import annotations

import base64
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from assurance.api.recorder_trust import server_recorder_trust_state
from assurance.attest import SigningKey, VerifyingKey
from assurance.attest.attestation import AttestationLog, attest
from assurance.attest.cli import main
from assurance.attest.custody import (
    key_file_problems,
    require_private_key_file,
    verify_log_across_rotation,
)
from assurance.attest.keys import SigningKeyError
from assurance.attest.preflight import KEY_PEM_ENV, TRUST_ENV, run_preflight
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.recorder_attestation import (
    AttestationStatus,
    MachineRef,
    RecorderAttestation,
    RecorderTrust,
    assess_recorder_attestation,
)

from .interfaces_support import trace

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX")

_ENV_VARS = (KEY_PEM_ENV, "ASSURANCE_ATTEST_KEY", "ASSURANCE_ATTEST_PASSPHRASE",
             "ASSURANCE_ATTEST_LOGS", TRUST_ENV, "ASSURANCE_LEDGER",
             "ASSURANCE_TENANT_LEDGERS")
MARKER = "SECRETMARKERSECRETMARKER"
MACHINE = MachineRef("AR-7", "2.4.1", "")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for name in _ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def run(capsys, *argv) -> tuple[int, str, str]:
    code = main([str(a) for a in argv])
    out = capsys.readouterr()
    return code, out.out, out.err


def private_body(path: Path) -> list[str]:
    """The base64 lines of a PEM: what must never be printed."""
    return [ln for ln in path.read_text().splitlines()
            if ln and not ln.startswith("-----")]


def assert_no_key_material(path: Path, *texts: str) -> None:
    body = private_body(path)
    assert body, "test bug: nothing to look for"
    for text in texts:
        assert "PRIVATE KEY" not in text
        for line in body:
            assert line not in text
        # the raw 32-byte seed, as hex, is the other way it could be shown
        raw = SigningKey.load(path).private.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        assert raw.hex() not in text


def keygen(capsys, tmp_path, name, *extra) -> tuple[Path, Path, str]:
    priv = tmp_path / "keys" / f"{name}.pem"
    pub = tmp_path / "keys" / f"{name}.pub"
    code, out, _ = run(capsys, "keygen", "--out", priv, "--public-out", pub, "--json", *extra)
    assert code == 0
    return priv, pub, json.loads(out)["fingerprint"]


def make_ledger(path: Path, count: int = 3) -> EvidenceLedger:
    led = EvidenceLedger(path)
    for n in range(count):
        led.append(Evidence(kind="test.record", body={"n": n}, actor=Actor(identifier="t"),
                            origin=Origin(system="pytest")).seal(), subject=f"m-{n}")
    return led


# ---------------------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------------------
class TestKeygen:
    def test_private_key_is_0600_and_only_the_fingerprint_is_printed(self, capsys, tmp_path):
        priv = tmp_path / "k" / "svc.pem"
        code, out, err = run(capsys, "keygen", "--out", priv)
        assert code == 0
        assert stat.S_IMODE(priv.stat().st_mode) == 0o600
        fp = SigningKey.load(priv).fingerprint
        assert fp in out
        assert_no_key_material(priv, out, err)

    def test_json_output_has_the_fingerprint_and_paths_and_no_key(self, capsys, tmp_path):
        priv, pub, fp = keygen(capsys, tmp_path, "svc")
        # the keygen helper already parsed the JSON; re-run output equivalence on a new key
        priv2 = tmp_path / "k2.pem"
        code, out, err = run(capsys, "keygen", "--out", priv2, "--json")
        data = json.loads(out)
        assert code == 0 and set(data) == {
            "fingerprint", "private_key_file", "public_key_file", "private_key_encrypted"}
        assert_no_key_material(priv2, out, err)
        assert VerifyingKey.from_file(pub).fingerprint == fp

    def test_an_existing_private_key_is_never_overwritten(self, capsys, tmp_path):
        priv, pub, _ = keygen(capsys, tmp_path, "svc")
        before = priv.read_bytes()
        code, out, err = run(capsys, "keygen", "--out", priv, "--public-out",
                             tmp_path / "other.pub")
        assert code == 2 and "already exists" in err
        assert priv.read_bytes() == before
        assert not (tmp_path / "other.pub").exists()
        assert_no_key_material(priv, out, err)

    def test_an_existing_public_key_is_never_overwritten_and_no_private_key_is_made(
            self, capsys, tmp_path):
        _, pub, _ = keygen(capsys, tmp_path, "svc")
        before = pub.read_bytes()
        new = tmp_path / "keys" / "new.pem"
        code, _, err = run(capsys, "keygen", "--out", new, "--public-out", pub)
        assert code == 2 and "already exists" in err
        assert pub.read_bytes() == before
        assert not new.exists(), "a private key was made for a public key that was refused"

    def test_public_out_cannot_be_the_private_path(self, capsys, tmp_path):
        p = tmp_path / "same.pem"
        code, _, err = run(capsys, "keygen", "--out", p, "--public-out", p)
        assert code == 2 and not p.exists()
        assert "must not be" in err or "already exists" in err

    def test_a_key_is_refused_beside_the_ledger_it_would_sign(self, capsys, tmp_path):
        ledger = make_ledger(tmp_path / "register.db").path
        code, _, err = run(capsys, "keygen", "--out", tmp_path / "k.pem", "--ledger", ledger)
        assert code == 2 and "refusing to write the signing key" in err
        assert not (tmp_path / "k.pem").exists()

    def test_a_passphrase_is_read_from_the_environment_and_never_echoed(
            self, capsys, tmp_path, monkeypatch):
        monkeypatch.setenv("CEREMONY_PW", "hunter2-hunter2")
        priv = tmp_path / "enc.pem"
        code, out, err = run(capsys, "keygen", "--out", priv, "--passphrase-env", "CEREMONY_PW")
        assert code == 0 and "ENCRYPTED PRIVATE KEY" in priv.read_text()
        assert "hunter2" not in out + err
        with pytest.raises(SigningKeyError):
            SigningKey.load(priv)                 # not usable without the passphrase

    def test_a_missing_passphrase_variable_is_an_error_not_an_unencrypted_key(
            self, capsys, tmp_path):
        code, _, err = run(capsys, "keygen", "--out", tmp_path / "k.pem",
                           "--passphrase-env", "NOT_SET_ANYWHERE_XYZ")
        assert code == 1 and "is not set" in err
        assert not (tmp_path / "k.pem").exists()


# ---------------------------------------------------------------------------------------
# key file permissions
# ---------------------------------------------------------------------------------------
class TestKeyFilePermissions:
    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o660, 0o666, 0o604, 0o707])
    def test_a_key_others_can_read_is_refused_by_sign(self, capsys, tmp_path, mode):
        priv, _, _ = keygen(capsys, tmp_path, "svc")
        ledger = make_ledger(tmp_path / "data" / "r.db").path
        os.chmod(priv, mode)
        code, out, err = run(capsys, "sign", "--ledger", ledger, "--key", priv,
                             "--log", tmp_path / "log.jsonl")
        assert code == 2 and "chmod 600" in err
        assert not (tmp_path / "log.jsonl").exists(), "it signed with a world-readable key"
        assert_no_key_material(priv, out, err)

    def test_an_owner_only_key_signs(self, capsys, tmp_path):
        priv, _, _ = keygen(capsys, tmp_path, "svc")
        ledger = make_ledger(tmp_path / "data" / "r.db").path
        for mode in (0o600, 0o400):
            os.chmod(priv, mode)
            code, _, _ = run(capsys, "sign", "--ledger", ledger, "--key", priv,
                             "--log", tmp_path / f"log{mode}.jsonl")
            assert code == 0

    def test_a_symlinked_key_is_refused(self, capsys, tmp_path):
        priv, _, _ = keygen(capsys, tmp_path, "svc")
        link = tmp_path / "link.pem"
        link.symlink_to(priv)
        assert "symbolic link" in " ".join(key_file_problems(link))
        with pytest.raises(SigningKeyError):
            require_private_key_file(link)

    def test_a_missing_or_non_regular_file_is_a_problem(self, tmp_path):
        assert key_file_problems(tmp_path / "nope.pem")
        assert "not a regular file" in " ".join(key_file_problems(tmp_path))

    def test_a_garbage_key_file_error_does_not_echo_its_contents(self, capsys, tmp_path):
        bad = tmp_path / "bad.pem"
        bad.write_text(f"-----BEGIN PRIVATE KEY-----\n{MARKER}\n-----END PRIVATE KEY-----\n")
        os.chmod(bad, 0o600)
        ledger = make_ledger(tmp_path / "data" / "r.db").path
        code, out, err = run(capsys, "sign", "--ledger", ledger, "--key", bad,
                             "--log", tmp_path / "log.jsonl")
        assert code == 2
        assert MARKER not in out + err


# ---------------------------------------------------------------------------------------
# the trust-list workflow
# ---------------------------------------------------------------------------------------
class Ceremony:
    def __init__(self, capsys, tmp_path) -> None:
        self.capsys, self.tmp = capsys, tmp_path
        self.trust = tmp_path / "trust" / "recorder-trust.json"

    def run(self, *argv):
        return run(self.capsys, *argv)

    def recorder(self, name="rec"):
        return keygen(self.capsys, self.tmp, name)

    def create(self):
        return self.run("trust-list", "create", "--trust", self.trust)

    def add(self, pub, fp, *, label="Plant 2 line 4", provenance="bench,field"):
        return self.run("trust-list", "add", "--trust", self.trust, "--public-key", pub,
                        "--label", label, "--provenance", provenance, "--fingerprint", fp)

    def revoke(self, fp, effective="2026-06-01"):
        return self.run("trust-list", "revoke", "--trust", self.trust, "--fingerprint", fp,
                        "--effective", effective)


@pytest.fixture
def cer(capsys, tmp_path):
    return Ceremony(capsys, tmp_path)


def _attested(priv: Path, *, started: datetime, **kw) -> tuple[object, dict]:
    run_trace = trace(started)
    att = RecorderAttestation.sign(
        run_trace, SigningKey.load(priv), recorder_id="REC-TEST-1", product="AR-7",
        product_version="2.4.1", **kw)
    return run_trace, att.to_dict()


def _assess(trace_, atts, trust_path, *, now=None):
    return assess_recorder_attestation(
        trace_, atts, RecorderTrust.from_json(trust_path), machine_ref=MACHINE, now=now)


class TestTrustList:
    def test_create_add_list_verify_roundtrip_and_the_server_loads_it(
            self, cer, monkeypatch):
        assert cer.create()[0] == 0
        _, pub, fp = cer.recorder()
        code, out, _ = cer.add(pub, fp)
        assert code == 0 and fp in out
        code, out, _ = cer.run("trust-list", "list", "--trust", cer.trust)
        assert code == 0 and fp in out and "Plant 2 line 4" in out and "bench,field" in out
        code, out, _ = cer.run("trust-list", "list", "--trust", cer.trust, "--json")
        assert json.loads(out) == [{"label": "Plant 2 line 4", "fingerprint": fp,
                                    "provenance": ["bench", "field"], "revoked": False,
                                    "revoked_on": ""}]
        assert cer.run("trust-list", "verify-file", "--trust", cer.trust)[0] == 0
        monkeypatch.setenv(TRUST_ENV, str(cer.trust))
        state = server_recorder_trust_state()
        assert state.status == "configured" and state.trust.get(fp) is not None
        assert stat.S_IMODE(cer.trust.stat().st_mode) == 0o644

    def test_create_refuses_to_replace_a_list(self, cer):
        cer.create()
        before = cer.trust.read_bytes()
        code, _, err = cer.create()
        assert code == 2 and "already exists" in err
        assert cer.trust.read_bytes() == before

    def test_add_requires_the_out_of_band_fingerprint_and_refuses_a_different_key(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        _, _, other_fp = cer.recorder("attacker")
        before = cer.trust.read_bytes()
        code, _, err = cer.add(pub, other_fp)
        assert code == 2 and "Do not trust it" in err
        assert cer.trust.read_bytes() == before
        with pytest.raises(SystemExit):                       # --fingerprint is mandatory
            main(["trust-list", "add", "--trust", str(cer.trust), "--public-key", str(pub),
                  "--label", "x", "--provenance", "bench"])

    def test_add_refuses_a_private_key_without_reading_or_echoing_it(self, cer):
        cer.create()
        priv, _, fp = cer.recorder()
        before = cer.trust.read_bytes()
        code, out, err = cer.add(priv, fp)
        assert code == 2 and "PRIVATE key" in err and "burned" in err
        assert cer.trust.read_bytes() == before
        assert_no_key_material(priv, out, err)

    @pytest.mark.parametrize("classes", ["simulation", "bench,simulation", "", "lab", ","])
    def test_add_refuses_provenance_that_can_never_be_lifted(self, cer, classes):
        cer.create()
        _, pub, fp = cer.recorder()
        code, _, err = cer.add(pub, fp, provenance=classes)
        assert code == 2 and "provenance" in err
        assert RecorderTrust.from_json(cer.trust).recorders == ()

    def test_add_refuses_a_duplicate_key_and_an_empty_label(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        assert cer.add(pub, fp)[0] == 0
        assert cer.add(pub, fp)[0] == 2
        assert len(RecorderTrust.from_json(cer.trust)) == 1
        _, pub2, fp2 = cer.recorder("rec2")
        assert cer.add(pub2, fp2, label="  ")[0] == 2

    def test_add_to_a_list_that_does_not_exist_is_an_error_not_a_silent_create(self, cer):
        _, pub, fp = cer.recorder()
        code, _, _ = cer.add(pub, fp)
        assert code == 2 and not cer.trust.exists()

    def test_revoke_needs_an_explicit_date(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        with pytest.raises(SystemExit):
            main(["trust-list", "revoke", "--trust", str(cer.trust), "--fingerprint", fp])

    @pytest.mark.parametrize("bad", ["", "yesterday", "2026-13-01", "2026-6-1", "20260601",
                                     "2026-06-01T00:00:00"])
    def test_revoke_refuses_a_date_that_is_not_an_explicit_calendar_date(self, cer, bad):
        cer.create()
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        code, _, err = cer.revoke(fp, bad)
        assert code == 2 and "YYYY-MM-DD" in err
        assert not RecorderTrust.from_json(cer.trust).get(fp).revoked

    def test_revoke_records_the_date_is_total_and_is_not_rewritten(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        code, out, _ = cer.revoke(fp, "2026-06-01")
        assert code == 0 and "total and immediate" in out
        entry = RecorderTrust.from_json(cer.trust).get(fp)
        assert entry.revoked and entry.revoked_on == "2026-06-01"
        code, _, err = cer.revoke(fp, "2026-07-01")
        assert code == 2 and "already revoked" in err
        assert RecorderTrust.from_json(cer.trust).get(fp).revoked_on == "2026-06-01"

    def test_revoke_of_an_unknown_key_is_an_error(self, cer):
        cer.create()
        assert cer.revoke("0" * 16)[0] == 2
        assert cer.revoke("nothex")[0] == 2

    def test_verify_file_fails_for_a_file_the_server_could_not_load(self, cer):
        cer.create()
        cer.trust.write_text('{"format": "something-else", "recorders": []}')
        code, _, err = cer.run("trust-list", "verify-file", "--trust", cer.trust)
        assert code == 2 and "format" in err

    def test_verify_file_flags_a_list_that_others_can_write(self, cer):
        cer.create()
        os.chmod(cer.trust, 0o666)
        code, out, _ = cer.run("trust-list", "verify-file", "--trust", cer.trust, "--json")
        assert code == 1 and json.loads(out)["ok"] is False
        assert "writable by group or other" in json.loads(out)["problems"][0]

    def test_a_private_key_pasted_into_the_list_is_refused_by_the_loader(self, cer):
        cer.create()
        priv, _, _ = cer.recorder()
        doc = json.loads(cer.trust.read_text())
        doc["recorders"] = [{"label": "x", "public_key_pem": priv.read_text(),
                             "provenance": ["bench"]}]
        cer.trust.write_text(json.dumps(doc))
        code, out, err = cer.run("trust-list", "verify-file", "--trust", cer.trust)
        assert code == 2
        assert_no_key_material(priv, out, err)


# ---------------------------------------------------------------------------------------
# what the recorder verifier does with a list the CLI wrote
# ---------------------------------------------------------------------------------------
class TestRecorderVerifierSemantics:
    NOW = datetime(2026, 7, 1, 12, tzinfo=UTC)
    STARTED = datetime(2026, 6, 20, 8, tzinfo=UTC)

    def _trusted(self, cer, **kw):
        cer.create()
        priv, pub, fp = cer.recorder()
        cer.add(pub, fp, **kw)
        return priv, fp

    def test_a_key_added_by_the_cli_lifts_the_trace(self, cer):
        priv, _ = self._trusted(cer)
        t, att = _attested(priv, started=self.STARTED, attested_on="2026-06-21")
        a = _assess(t, [att], cer.trust, now=self.NOW)
        assert a.status is AttestationStatus.ACCEPTED

    def test_a_key_nobody_added_is_not_believed(self, cer):
        self._trusted(cer)
        stranger, _, _ = cer.recorder("stranger")
        t, att = _attested(stranger, started=self.STARTED, attested_on="2026-06-21")
        assert _assess(t, [att], cer.trust, now=self.NOW).status \
            is AttestationStatus.UNTRUSTED_KEY

    def test_the_attestation_cannot_supply_the_key_that_checks_it(self, cer):
        priv, fp = self._trusted(cer)
        stranger, spub, _ = cer.recorder("stranger")
        t, att = _attested(stranger, started=self.STARTED, attested_on="2026-06-21")
        # 1. an attestation carrying its own public key is malformed, not self-trusting
        att_with_key = {**att, "public_key_pem": VerifyingKey.from_file(spub).pem()}
        a = _assess(t, [att_with_key], cer.trust, now=self.NOW)
        assert a.status is not AttestationStatus.ACCEPTED
        # 2. one that claims the trusted fingerprint is a bad signature, not a pass
        forged = RecorderAttestation.from_dict(att).to_dict()
        forged["key_fingerprint"] = fp
        a = _assess(t, [forged], cer.trust, now=self.NOW)
        assert a.status is AttestationStatus.BAD_SIGNATURE

    def test_an_expired_attestation_does_not_reach_validated(self, cer):
        priv, _ = self._trusted(cer)
        t, att = _attested(priv, started=self.STARTED, attested_on="2026-06-21",
                           expires_on="2026-06-30")
        assert _assess(t, [att], cer.trust, now=self.NOW).status is AttestationStatus.EXPIRED
        assert _assess(t, [att], cer.trust,
                       now=datetime(2026, 6, 29, tzinfo=UTC)).status \
            is AttestationStatus.ACCEPTED

    def test_an_attestation_dated_long_after_the_recording_is_stale(self, cer):
        priv, _ = self._trusted(cer)
        late = (self.STARTED + timedelta(days=200)).date().isoformat()
        t, att = _attested(priv, started=self.STARTED, attested_on=late)
        a = _assess(t, [att], cer.trust, now=self.STARTED + timedelta(days=210))
        assert a.status is AttestationStatus.STALE

    def test_a_key_trusted_for_bench_cannot_lift_a_field_trace(self, cer):
        priv, _ = self._trusted(cer, provenance="bench")
        t, att = _attested(priv, started=self.STARTED, attested_on="2026-06-21")
        assert _assess(t, [att], cer.trust, now=self.NOW).status \
            is AttestationStatus.PROVENANCE_NOT_PERMITTED

    @pytest.mark.parametrize("stated", ["2026-06-21", "2026-06-30", "2026-07-01"])
    def test_a_revoked_recorder_reaches_validated_for_no_date_it_states(self, cer, stated):
        """Revocation is total: before, on and after the effective date alike."""
        priv, fp = self._trusted(cer)
        t, att = _attested(priv, started=self.STARTED, attested_on=stated)
        assert _assess(t, [att], cer.trust, now=self.NOW).status is AttestationStatus.ACCEPTED
        assert cer.revoke(fp, "2026-06-25")[0] == 0
        a = _assess(t, [att], cer.trust, now=self.NOW)
        assert a.status is AttestationStatus.REVOKED_KEY
        assert not a.attested

    def test_revoking_one_recorder_leaves_another_trusted(self, cer):
        priv_a, fp_a = self._trusted(cer)
        priv_b, pub_b, fp_b = cer.recorder("b")
        cer.add(pub_b, fp_b, label="B")
        cer.revoke(fp_a)
        t, att_b = _attested(priv_b, started=self.STARTED, attested_on="2026-06-21")
        assert _assess(t, [att_b], cer.trust, now=self.NOW).status \
            is AttestationStatus.ACCEPTED

    def test_removing_the_recorder_from_the_file_is_the_same_as_revoking(self, cer):
        priv, _ = self._trusted(cer)
        t, att = _attested(priv, started=self.STARTED, attested_on="2026-06-21")
        cer.trust.write_text(json.dumps(RecorderTrust().to_dict()))
        assert _assess(t, [att], cer.trust, now=self.NOW).status \
            is AttestationStatus.UNTRUSTED_KEY


# ---------------------------------------------------------------------------------------
# rotating the service key, against the existing verifiers
# ---------------------------------------------------------------------------------------
class TestServiceKeyRotation:
    def _rotated_log(self, capsys, tmp_path):
        old_priv, old_pub, old_fp = keygen(capsys, tmp_path, "old")
        new_priv, new_pub, new_fp = keygen(capsys, tmp_path, "new")
        ledger = make_ledger(tmp_path / "data" / "r.db")
        log = tmp_path / "vault" / "attest.jsonl"
        assert run(capsys, "sign", "--ledger", ledger.path, "--key", old_priv,
                   "--log", log)[0] == 0
        assert run(capsys, "sign", "--ledger", ledger.path, "--key", old_priv,
                   "--log", log)[0] == 0
        return ledger, log, (old_priv, old_pub, old_fp), (new_priv, new_pub, new_fp)

    def test_a_different_key_needs_rotating_to_be_said_out_loud(self, capsys, tmp_path):
        ledger, log, _, (new_priv, _, _) = self._rotated_log(capsys, tmp_path)
        code, _, err = run(capsys, "sign", "--ledger", ledger.path, "--key", new_priv,
                           "--log", log)
        assert code == 1 and "rotation" in err
        assert len(AttestationLog(log).scan()[0]) == 2
        assert run(capsys, "sign", "--ledger", ledger.path, "--key", new_priv,
                   "--log", log, "--rotating")[0] == 0

    def test_attestations_signed_before_rotation_verify_under_the_retained_old_key(
            self, capsys, tmp_path):
        ledger, log, (old_priv, old_pub, old_fp), (new_priv, new_pub, new_fp) = \
            self._rotated_log(capsys, tmp_path)
        run(capsys, "sign", "--ledger", ledger.path, "--key", new_priv, "--log", log,
            "--rotating")
        records, _ = AttestationLog(log).scan()
        old_key, new_key = VerifyingKey.from_file(old_pub), VerifyingKey.from_file(new_pub)
        assert [r.verified_by(old_key) for r in records] == [True, True, False]
        assert [r.verified_by(new_key) for r in records] == [False, False, True]
        # the whole log: neither single key vouches for it ...
        for pub in (old_pub, new_pub):
            code, out, _ = run(capsys, "verify", "--log", log, "--public-key", pub, "--json")
            assert code == 1 and json.loads(out)["ok"] is False
        # ... and both pinned keys do, each over its own span
        code, out, _ = run(capsys, "verify", "--log", log, "--public-key", old_pub,
                           "--public-key", new_pub, "--ledger", ledger.path, "--json")
        data = json.loads(out)
        assert code == 0 and data["ok"] is True and data["checked"] == 3
        assert old_fp in data["key_fingerprint"] and new_fp in data["key_fingerprint"]

    def test_the_pre_rotation_prefix_alone_still_verifies_with_the_old_key(
            self, capsys, tmp_path):
        ledger, log, (_, old_pub, _), (new_priv, _, _) = self._rotated_log(capsys, tmp_path)
        prefix = tmp_path / "prefix.jsonl"
        prefix.write_bytes(log.read_bytes())          # copy taken before rotating
        run(capsys, "sign", "--ledger", ledger.path, "--key", new_priv, "--log", log,
            "--rotating")
        assert run(capsys, "verify", "--log", prefix, "--public-key", old_pub)[0] == 0

    def test_dropping_the_old_key_from_the_verifier_is_a_finding_not_a_pass(
            self, capsys, tmp_path):
        ledger, log, _, (new_priv, new_pub, _) = self._rotated_log(capsys, tmp_path)
        run(capsys, "sign", "--ledger", ledger.path, "--key", new_priv, "--log", log,
            "--rotating")
        _, stranger_pub, _ = keygen(capsys, tmp_path, "stranger")
        code, out, _ = run(capsys, "verify", "--log", log, "--public-key", new_pub,
                           "--public-key", stranger_pub, "--json")
        problems = json.loads(out)["problems"]
        assert code == 1 and any("not one of the keys you pinned" in p for p in problems)

    def test_a_key_supplied_by_the_log_itself_checks_nothing(self, capsys, tmp_path):
        """A forger signs with their own key and ships the public half in the record."""
        ledger, log, (_, old_pub, _), _ = self._rotated_log(capsys, tmp_path)
        forger_priv, forger_pub, forger_fp = keygen(capsys, tmp_path, "forger")
        forged_log = tmp_path / "forged.jsonl"
        assert run(capsys, "sign", "--ledger", ledger.path, "--key", forger_priv,
                   "--log", forged_log)[0] == 0
        lines = [json.loads(ln) for ln in forged_log.read_text().splitlines()]
        lines[0]["public_key_pem"] = VerifyingKey.from_file(forger_pub).pem()
        forged_log.write_text("".join(json.dumps(r) + "\n" for r in lines))
        code, out, _ = run(capsys, "verify", "--log", forged_log, "--public-key", old_pub,
                           "--json")
        assert code == 1 and json.loads(out)["ok"] is False
        # the rotation-aware path also refuses it: the forger's key is not pinned
        records, _ = AttestationLog(forged_log).scan()
        verdict = verify_log_across_rotation(records, [VerifyingKey.from_file(old_pub)])
        assert not verdict.ok

    def test_a_record_relabelled_with_another_pinned_keys_fingerprint_is_caught(
            self, capsys, tmp_path):
        ledger, log, (old_priv, old_pub, old_fp), (new_priv, new_pub, new_fp) = \
            self._rotated_log(capsys, tmp_path)
        records, _ = AttestationLog(log).scan()
        # valid under old, but claims to be the new key's: the claim must not select the key
        liar = records[0].__class__(**{**records[0].__dict__, "key_fingerprint": new_fp})
        verdict = verify_log_across_rotation(
            [liar], [VerifyingKey.from_file(old_pub), VerifyingKey.from_file(new_pub)])
        assert not verdict.ok

    def test_a_record_signed_by_one_pinned_key_under_the_other_ones_name_is_caught(
            self, capsys, tmp_path):
        """The signer itself signs a label that is not its own: the label must not pick."""
        ledger, log, (old_priv, old_pub, _), (_, new_pub, new_fp) = \
            self._rotated_log(capsys, tmp_path)
        first = AttestationLog(log).scan()[0][0]
        mislabelled = first.__class__(**{**first.__dict__, "key_fingerprint": new_fp,
                                         "signature": ""})
        signed = first.__class__(**{**mislabelled.__dict__, "signature": base64.b64encode(
            SigningKey.load(old_priv).sign(mislabelled.signed_payload())).decode("ascii")})
        assert signed.verified_by(VerifyingKey.from_file(old_pub))      # a genuine signature
        verdict = verify_log_across_rotation(
            [signed], [VerifyingKey.from_file(old_pub), VerifyingKey.from_file(new_pub)])
        assert not verdict.ok
        assert any("does not verify under pinned key" in p for p in verdict.problems)

    def test_a_tampered_record_under_a_pinned_key_fails(self, capsys, tmp_path):
        ledger, log, (_, old_pub, _), (new_priv, new_pub, _) = self._rotated_log(
            capsys, tmp_path)
        lines = [json.loads(ln) for ln in log.read_text().splitlines()]
        lines[1]["ledger_length"] = 1
        log.write_text("".join(json.dumps(r) + "\n" for r in lines))
        code, out, _ = run(capsys, "verify", "--log", log, "--public-key", old_pub,
                           "--public-key", new_pub, "--json")
        assert code == 1 and json.loads(out)["ok"] is False

    def test_the_wrong_key_is_a_finding(self, capsys, tmp_path):
        _, log, _, _ = self._rotated_log(capsys, tmp_path)
        _, wrong, _ = keygen(capsys, tmp_path, "wrong")
        assert run(capsys, "verify", "--log", log, "--public-key", wrong)[0] == 1

    def test_a_rewound_ledger_is_still_caught_across_a_rotation(self, capsys, tmp_path):
        import sqlite3

        ledger, log, (_, old_pub, _), (new_priv, new_pub, _) = self._rotated_log(
            capsys, tmp_path)
        run(capsys, "sign", "--ledger", ledger.path, "--key", new_priv, "--log", log,
            "--rotating")
        db = sqlite3.connect(ledger.path)
        db.execute("DELETE FROM chain WHERE seq > 1")
        db.commit()
        db.close()
        code, out, _ = run(capsys, "verify", "--log", log, "--public-key", old_pub,
                           "--public-key", new_pub, "--ledger", ledger.path, "--json")
        assert code == 1 and json.loads(out)["ok"] is False

    def test_the_library_attest_function_agrees(self, capsys, tmp_path):
        a = SigningKey.generate()
        b = SigningKey.generate()
        led = make_ledger(tmp_path / "r.db")
        log = AttestationLog(tmp_path / "l.jsonl")
        attest(led, a, log)
        attest(led, b, log, rotating=True)
        verdict = verify_log_across_rotation(log.scan()[0], [a.verifying, b.verifying])
        assert verdict.ok and verdict.checked == 2


# ---------------------------------------------------------------------------------------
# preflight
# ---------------------------------------------------------------------------------------
def _status(report, name):
    return [c.status for c in report.checks if c.name == name]


class TestPreflight:
    def test_an_empty_environment_has_neither_capability_and_says_why(self, capsys):
        code, out, _ = run(capsys, "preflight", "--json")
        data = json.loads(out)
        assert code == 1 and data["ok"] is False
        assert data["counter_signing"]["available"] is False
        assert "503" in data["counter_signing"]["without_it"]
        assert data["validated_verification"]["available"] is False
        assert data["validated_verification"]["trust_status"] == "unset"
        assert "community" in data["validated_verification"]["without_it"]
        assert any("Backup of the private key" in n for n in data["not_checked"])
        assert any("customers were told" in n for n in data["not_checked"])
        assert any("Key custody" in n for n in data["not_checked"])

    def test_require_none_reports_without_failing_an_unconfigured_environment(self, capsys):
        assert run(capsys, "preflight", "--require", "none")[0] == 0

    def test_a_configured_environment_passes_by_path_and_prints_no_key(
            self, capsys, tmp_path, cer):
        priv, _, fp = keygen(capsys, tmp_path, "svc")
        cer.create()
        _, pub, rfp = cer.recorder()
        cer.add(pub, rfp)
        code, out, err = run(capsys, "preflight", "--key", priv, "--trust", cer.trust,
                             "--expect-fingerprint", fp, "--json")
        data = json.loads(out)
        assert code == 0, out
        assert data["counter_signing"]["service_fingerprint"] == fp
        assert data["validated_verification"]["available"] is True
        assert data["validated_verification"]["recorders"][0]["fingerprint"] == rfp
        assert_no_key_material(priv, out, err)
        text_code, text_out, text_err = run(capsys, "preflight", "--key", priv,
                                            "--trust", cer.trust)
        assert text_code == 0 and fp in text_out and "NOT checked" in text_out
        assert_no_key_material(priv, text_out, text_err)

    def test_the_pem_in_the_environment_is_what_the_service_reads(
            self, capsys, tmp_path, monkeypatch):
        priv, _, fp = keygen(capsys, tmp_path, "svc")
        monkeypatch.setenv(KEY_PEM_ENV, priv.read_text())
        code, out, err = run(capsys, "preflight", "--require", "counter-signing", "--json")
        data = json.loads(out)
        assert code == 0 and data["counter_signing"]["service_fingerprint"] == fp
        assert "ASSURANCE_ATTEST_KEY_PEM" in data["counter_signing"]["key_source"]
        assert_no_key_material(priv, out, err)

    def test_garbage_in_the_pem_variable_is_not_echoed(self, capsys, monkeypatch):
        monkeypatch.setenv(
            KEY_PEM_ENV, f"-----BEGIN PRIVATE KEY-----\n{MARKER}\n-----END PRIVATE KEY-----")
        code, out, err = run(capsys, "preflight", "--json")
        assert code == 1 and MARKER not in out + err
        assert json.loads(out)["counter_signing"]["available"] is False

    @pytest.mark.parametrize("raised", [SigningKeyError(f"odd failure {MARKER}"),
                                        RuntimeError(f"surprise {MARKER}")])
    def test_no_exception_text_is_shown_whatever_the_loader_raises(
            self, capsys, monkeypatch, raised):
        def boom(*_a, **_k):
            raise raised
        monkeypatch.setattr(SigningKey, "from_pem", staticmethod(boom))
        monkeypatch.setenv(KEY_PEM_ENV, "anything")
        code, out, err = run(capsys, "preflight", "--json")
        assert code == 1 and MARKER not in out + err
        assert "key.load" in out

    def test_an_encrypted_key_without_its_passphrase_is_not_available(
            self, capsys, tmp_path, monkeypatch):
        monkeypatch.setenv("CEREMONY_PW", "correct horse battery")
        priv = tmp_path / "enc.pem"
        run(capsys, "keygen", "--out", priv, "--passphrase-env", "CEREMONY_PW")
        report = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv)})
        assert not report.counter_signing and "passphrase" in " ".join(
            c.detail for c in report.failures)
        ok = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv),
                            "ASSURANCE_ATTEST_PASSPHRASE": "correct horse battery"})
        assert ok.counter_signing
        wrong = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv),
                               "ASSURANCE_ATTEST_PASSPHRASE": "nope"})
        assert not wrong.counter_signing

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o660])
    def test_a_key_file_others_can_read_is_not_available(self, capsys, tmp_path, mode):
        priv, _, _ = keygen(capsys, tmp_path, "svc")
        os.chmod(priv, mode)
        code, out, err = run(capsys, "preflight", "--key", priv, "--require", "counter-signing",
                             "--json")
        data = json.loads(out)
        assert code == 1 and data["counter_signing"]["available"] is False
        assert any(c["name"] == "key.permissions" and c["status"] == "fail"
                   for c in data["checks"])
        assert_no_key_material(priv, out, err)

    def test_a_key_stored_with_the_ledger_it_vouches_for_is_not_available(
            self, capsys, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        priv = data_dir / "svc.pem"
        run(capsys, "keygen", "--out", priv)
        r = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv),
                           "ASSURANCE_LEDGER": str(data_dir / "ledger.db")})
        assert not r.counter_signing and _status(r, "key.apart_from_data") == ["fail"]
        r = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv),
                           "ASSURANCE_ATTEST_LOGS": str(data_dir)})
        assert not r.counter_signing
        r = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv),
                           "ASSURANCE_TENANT_LEDGERS": str(tmp_path)})
        assert not r.counter_signing                       # a parent of the data is data too

    def test_a_fingerprint_that_is_not_the_one_you_wrote_down_fails(self, capsys, tmp_path):
        priv, _, fp = keygen(capsys, tmp_path, "svc")
        r = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv)}, expect_fingerprint="0" * 16)
        assert _status(r, "key.expected_fingerprint") == ["fail"]
        assert r.exit_code("counter-signing") == 1
        good = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv)}, expect_fingerprint=fp.upper())
        assert good.exit_code("counter-signing") == 0

    def test_an_unwritable_log_directory_is_not_available(self, capsys, tmp_path, monkeypatch):
        # Root can write anywhere, so a directory that is really unwritable cannot be built
        # in every environment; the one answer the check asks of the OS is supplied instead.
        priv, _, _ = keygen(capsys, tmp_path, "svc")
        logs = tmp_path / "logs"
        logs.mkdir()
        env = {"ASSURANCE_ATTEST_KEY": str(priv), "ASSURANCE_ATTEST_LOGS": str(logs)}
        assert run_preflight(env).counter_signing
        monkeypatch.setattr(os, "access", lambda *_a, **_k: False)
        assert not run_preflight(env).counter_signing

    def test_an_unreadable_trust_file_fails_closed_like_the_server(self, capsys, tmp_path):
        bad = tmp_path / "trust.json"
        bad.write_text("{not json")
        r = run_preflight({TRUST_ENV: str(bad)})
        assert r.trust_status == "unreadable" and not r.validated_verification
        assert r.exit_code("validated") == 1
        missing = run_preflight({TRUST_ENV: str(tmp_path / "gone.json")})
        assert missing.trust_status == "unreadable"

    def test_an_empty_or_all_revoked_list_cannot_reach_validated(self, cer):
        cer.create()
        assert not run_preflight({TRUST_ENV: str(cer.trust)}).validated_verification
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        assert run_preflight({TRUST_ENV: str(cer.trust)}).validated_verification
        cer.revoke(fp)
        r = run_preflight({TRUST_ENV: str(cer.trust)})
        assert not r.validated_verification and _status(r, "trust.live_keys") == ["warn"]

    def test_a_revocation_dated_in_the_future_is_already_in_force(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        cer.revoke(fp, "2099-01-01")
        r = run_preflight({TRUST_ENV: str(cer.trust)}, today=datetime(2026, 7, 1).date())
        assert _status(r, "trust.revoked_future") == ["warn"] and not r.validated_verification

    def test_a_key_that_must_be_revoked_but_is_still_trusted_fails(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        r = run_preflight({TRUST_ENV: str(cer.trust)}, must_be_revoked=(fp,))
        assert _status(r, "trust.revoked_but_trusted") == ["fail"]
        assert not r.validated_verification and r.exit_code("none") == 1
        cer.revoke(fp)
        r = run_preflight({TRUST_ENV: str(cer.trust)}, must_be_revoked=(fp,))
        assert _status(r, "trust.revoked_but_trusted") == ["ok"]

    def test_the_service_key_must_not_also_be_a_trusted_recorder(self, capsys, tmp_path, cer):
        priv, pub, fp = keygen(capsys, tmp_path, "svc")
        cer.create()
        cer.add(pub, fp)
        r = run_preflight({"ASSURANCE_ATTEST_KEY": str(priv), TRUST_ENV: str(cer.trust)})
        assert _status(r, "trust.service_key_is_recorder") == ["fail"]
        assert not r.validated_verification and r.exit_code("none") == 1

    def test_a_trust_file_others_can_write_is_not_available(self, cer):
        cer.create()
        _, pub, fp = cer.recorder()
        cer.add(pub, fp)
        os.chmod(cer.trust, 0o666)
        r = run_preflight({TRUST_ENV: str(cer.trust)})
        assert not r.validated_verification and _status(r, "trust.permissions") == ["fail"]

    def test_the_private_key_never_appears_whichever_failure_is_reported(
            self, capsys, tmp_path, cer):
        priv, _, _ = keygen(capsys, tmp_path, "svc")
        os.chmod(priv, 0o666)
        cer.create()
        os.chmod(cer.trust, 0o666)
        code, out, err = run(capsys, "preflight", "--key", priv, "--trust", cer.trust,
                             "--expect-fingerprint", "0" * 16, "--must-be-revoked", "1" * 16)
        assert code == 1
        assert_no_key_material(priv, out, err)
