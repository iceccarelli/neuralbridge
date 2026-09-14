"""What a signature over a ledger head must refuse to say.

The interesting tests here are not the ones where a signature verifies. They
are the ones where a perfectly valid chain has been rewound and the chain check
is happy about it — because that is the case the whole module exists for, and
it is the case every hash-chain audit log ships without.
"""

from __future__ import annotations

import importlib
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from assurance.attest import (
    ATTESTATION_FORMAT,
    AttestationBasis,
    AttestationError,
    AttestationLog,
    HeadAttestation,
    LedgerHead,
    SigningKey,
    SigningKeyError,
    VerifyingKey,
    attest,
    head_of,
    verify_log,
)
from assurance.core.evidence import Actor, Evidence, Origin
from assurance.evidence.ledger import GENESIS, EvidenceLedger

OPERATOR_KEY = "operator-key-test"
PASSPHRASE = "correct horse battery staple"  # noqa: S105


def _ledger(path, count: int = 4) -> EvidenceLedger:
    led = EvidenceLedger(path)
    for n in range(count):
        led.append(
            Evidence(
                kind="test.record",
                body={"n": n},
                actor=Actor(identifier="tester"),
                origin=Origin(system="pytest"),
            ).seal(),
            subject=f"machine-{n}",
        )
    return led


def _truncate(path, keep: int) -> None:
    """Rewind a ledger the way an administrator with write access would."""
    db = sqlite3.connect(path)
    db.execute("DELETE FROM chain WHERE seq > ?", (keep,))
    db.commit()
    db.close()


# --------------------------------------------------------------------------
class TestKeys:
    def test_a_key_will_not_be_written_beside_the_ledger_it_signs(self, tmp_path):
        ledger = tmp_path / "data" / "register.db"
        ledger.parent.mkdir()
        with pytest.raises(SigningKeyError) as exc:
            SigningKey.generate().save(
                tmp_path / "data" / "key.pem", ledger=ledger)
        assert "refusing to write the signing key" in str(exc.value)

    def test_a_key_is_not_silently_overwritten(self, tmp_path):
        first = SigningKey.generate()
        first.save(tmp_path / "k.pem")
        with pytest.raises(SigningKeyError) as exc:
            SigningKey.generate().save(tmp_path / "k.pem")
        assert "already exists" in str(exc.value)
        # And the original still loads, which is the point of the refusal.
        assert SigningKey.load(tmp_path / "k.pem").fingerprint == first.fingerprint

    def test_a_passphrase_is_honoured_in_both_directions(self, tmp_path):
        key = SigningKey.generate()
        key.save(tmp_path / "k.pem", passphrase=PASSPHRASE)
        with pytest.raises(SigningKeyError):
            SigningKey.load(tmp_path / "k.pem")
        assert SigningKey.load(
            tmp_path / "k.pem", passphrase=PASSPHRASE).fingerprint == key.fingerprint

    def test_the_private_key_file_is_not_world_readable(self, tmp_path):
        path = SigningKey.generate().save(tmp_path / "k.pem")
        assert oct(path.stat().st_mode)[-3:] == "600"

    def test_a_public_key_round_trips_through_pem(self, tmp_path):
        key = SigningKey.generate()
        (tmp_path / "k.pub").write_text(key.verifying.pem())
        loaded = VerifyingKey.from_file(tmp_path / "k.pub")
        assert loaded.fingerprint == key.fingerprint
        assert loaded.verify(b"hello", key.sign(b"hello"))

    def test_a_signature_over_other_bytes_does_not_verify(self):
        key = SigningKey.generate()
        assert not key.verifying.verify(b"goodbye", key.sign(b"hello"))

    def test_an_rsa_key_is_refused_by_name(self, tmp_path):
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with pytest.raises(SigningKeyError) as exc:
            VerifyingKey.from_pem(pem)
        assert "Ed25519" in str(exc.value)


# --------------------------------------------------------------------------
class TestAttesting:
    def test_the_head_of_an_empty_ledger_is_still_worth_signing(self, tmp_path):
        led = EvidenceLedger(tmp_path / "l.db")
        head = head_of(led)
        assert head.length == 0
        assert head.head_seq == 0
        assert head.head_link_hash == GENESIS

    def test_a_signed_head_verifies_against_the_public_key(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "att.jsonl")
        record = attest(led, key, log, note="weekly")

        assert record.sequence == 1
        assert record.ledger_length == 4
        assert record.head_seq == 4
        assert record.basis is AttestationBasis.READ_FROM_LEDGER
        assert record.format == ATTESTATION_FORMAT
        assert record.verified_by(key.verifying)

    def test_the_basis_says_whether_the_signer_saw_the_ledger(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        declared = LedgerHead(
            length=4, head_seq=4, head_link_hash=led.entries()[-1].link_hash)
        record = attest(declared, key, AttestationLog(tmp_path / "a.jsonl"))
        assert record.basis is AttestationBasis.DECLARED_BY_HOLDER
        # And it is inside the signed bytes, so it cannot be upgraded later.
        assert b"declared_by_holder" in record.signed_payload()

    def test_a_ledger_that_does_not_verify_is_never_attested(self, tmp_path):
        path = tmp_path / "l.db"
        _ledger(path)
        db = sqlite3.connect(path)
        db.execute("UPDATE chain SET payload = ? WHERE seq = 2", ('{"kind":"x"}',))
        db.commit()
        db.close()
        with pytest.raises(AttestationError) as exc:
            attest(EvidenceLedger(path), SigningKey.generate(),
                   AttestationLog(tmp_path / "a.jsonl"))
        assert "refusing to attest a ledger that does not verify" in str(exc.value)

    def test_a_rewound_ledger_is_refused_and_the_message_is_the_finding(self, tmp_path):
        path = tmp_path / "l.db"
        led = _ledger(path)
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)

        _truncate(path, keep=2)
        rewound = EvidenceLedger(path)
        # The chain is perfectly happy. This is the whole problem.
        assert rewound.verify_chain()[0] is True

        with pytest.raises(AttestationError) as exc:
            attest(rewound, key, log)
        message = str(exc.value)
        assert "holds 2 record(s)" in message
        assert "signed for 4" in message
        assert "does not get shorter" in message

    def test_a_fork_at_an_attested_position_is_refused(self, tmp_path):
        path = tmp_path / "l.db"
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(_ledger(path), key, log)

        # Same length, different history: rebuild seq 4 with other content.
        db = sqlite3.connect(path)
        db.execute("UPDATE chain SET link_hash = ? WHERE seq = 4", ("f" * 64,))
        db.commit()
        db.close()
        # Rebuild the ledger so it self-verifies at the new content by rewinding
        # and re-appending — the realistic attack, not a hand-edited hash.
        _truncate(path, keep=3)
        rebuilt = EvidenceLedger(path)
        rebuilt.append(
            Evidence(kind="test.record", body={"n": "different"},
                     actor=Actor(identifier="tester"),
                     origin=Origin(system="pytest")).seal(),
            subject="machine-3")
        assert rebuilt.verify_chain()[0] is True
        assert len(rebuilt) == 4

        with pytest.raises(AttestationError) as exc:
            attest(rebuilt, key, log)
        assert "fork, not a gap" in str(exc.value)

    def test_a_different_key_needs_to_be_declared_a_rotation(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, SigningKey.generate(), log)
        second = SigningKey.generate()
        with pytest.raises(AttestationError) as exc:
            attest(led, second, log)
        assert "rotation" in str(exc.value)
        assert attest(led, second, log, rotating=True).sequence == 2

    def test_each_attestation_names_its_predecessor(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        first = attest(led, key, log)
        led.append(
            Evidence(kind="test.record", body={"n": 99},
                     actor=Actor(identifier="tester"),
                     origin=Origin(system="pytest")).seal())
        second = attest(led, key, log)
        assert first.previous == ""
        assert second.previous == first.content_hash()
        assert second.ledger_length == 5

    def test_a_head_hash_that_cannot_have_come_from_a_ledger_is_refused(self):
        with pytest.raises(AttestationError) as exc:
            LedgerHead(length=1, head_seq=1, head_link_hash="not-a-hash")
        assert "SHA-256" in str(exc.value)

    def test_an_empty_ledger_cannot_claim_a_head(self):
        with pytest.raises(AttestationError):
            LedgerHead(length=0, head_seq=3, head_link_hash="a" * 64)


# --------------------------------------------------------------------------
class TestVerifying:
    def test_a_clean_log_verifies_and_still_names_what_it_did_not_check(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)

        verdict = verify_log(log.read(), key.verifying, ledger=led)
        assert verdict.ok
        assert verdict.problems == []
        assert any("belongs to whom you think" in c for c in verdict.checks_skipped)

    def test_without_a_ledger_the_omission_is_stated_not_implied(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, key, log)

        verdict = verify_log(log.read(), key.verifying)
        assert verdict.ok
        assert any("ledger itself was not examined" in c for c in verdict.checks_skipped)

    def test_a_rewind_is_found_by_verification_as_well_as_by_signing(self, tmp_path):
        path = tmp_path / "l.db"
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(_ledger(path), key, log)
        _truncate(path, keep=2)

        verdict = verify_log(log.read(), VerifyingKey.from_pem(key.verifying.pem()),
                             ledger=EvidenceLedger(path))
        assert not verdict.ok
        assert any("2 record(s) were removed after being attested" in p
                   for p in verdict.problems)

    def test_the_wrong_public_key_fails_every_signature(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(led, SigningKey.generate(), log)
        verdict = verify_log(log.read(), SigningKey.generate().verifying, ledger=led)
        assert not verdict.ok
        assert any("signature does not verify" in p for p in verdict.problems)

    def test_an_edited_attestation_stops_verifying(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        record = attest(led, key, log)

        forged = HeadAttestation(
            **{**record.to_dict(),
               "basis": record.basis,
               "ledger_length": 99})
        assert not forged.verified_by(key.verifying)

    def test_an_attestation_removed_from_the_middle_is_detected(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        for n in range(3):
            attest(led, key, log)
            led.append(
                Evidence(kind="test.record", body={"n": 100 + n},
                         actor=Actor(identifier="tester"),
                         origin=Origin(system="pytest")).seal())
        records = log.read()
        assert len(records) == 3

        verdict = verify_log([records[0], records[2]], key.verifying)
        assert not verdict.ok
        assert any("out of order" in p for p in verdict.problems)
        assert any("spliced" in p for p in verdict.problems)

    def test_a_counter_signature_is_labelled_as_one_in_what_was_not_checked(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        attest(LedgerHead(length=4, head_seq=4,
                          head_link_hash=led.entries()[-1].link_hash),
               key, log)
        verdict = verify_log(log.read(), key.verifying)
        assert verdict.ok
        assert any("never saw the ledger" in c for c in verdict.checks_skipped)

    def test_a_damaged_log_is_a_finding_not_a_crash(self, tmp_path):
        path = tmp_path / "a.jsonl"
        path.write_text('{"not": "an attestation"}\n')
        with pytest.raises(AttestationError) as exc:
            AttestationLog(path).read()
        assert "missing" in str(exc.value)

    def test_a_signature_that_is_not_base64_is_a_finding(self, tmp_path):
        led = _ledger(tmp_path / "l.db")
        key = SigningKey.generate()
        log = AttestationLog(tmp_path / "a.jsonl")
        record = attest(led, key, log)
        broken = HeadAttestation(
            **{**record.to_dict(), "basis": record.basis, "signature": "!!!!"})
        with pytest.raises(AttestationError):
            broken.signature_bytes()


# --------------------------------------------------------------------------
class TestCli:
    def _run(self, *argv) -> int:
        from assurance.attest.cli import main

        return main(list(argv))

    def test_keygen_writes_both_halves(self, tmp_path, capsys):
        assert self._run("keygen", "--out", str(tmp_path / "k.pem")) == 0
        assert (tmp_path / "k.pem").exists()
        assert (tmp_path / "k.pem.pub").exists()
        assert "not encrypted" in capsys.readouterr().out

    def test_sign_then_verify_exits_zero(self, tmp_path, capsys):
        _ledger(tmp_path / "l.db")
        self._run("keygen", "--out", str(tmp_path / "k.pem"))
        capsys.readouterr()
        assert self._run(
            "sign", "--ledger", str(tmp_path / "l.db"),
            "--key", str(tmp_path / "k.pem"),
            "--log", str(tmp_path / "a.jsonl")) == 0
        assert self._run(
            "verify", "--log", str(tmp_path / "a.jsonl"),
            "--public-key", str(tmp_path / "k.pem.pub"),
            "--ledger", str(tmp_path / "l.db")) == 0

    def test_a_finding_exits_one_and_a_missing_file_exits_two(self, tmp_path):
        path = tmp_path / "l.db"
        _ledger(path)
        self._run("keygen", "--out", str(tmp_path / "k.pem"))
        self._run("sign", "--ledger", str(path), "--key", str(tmp_path / "k.pem"),
                  "--log", str(tmp_path / "a.jsonl"))
        _truncate(path, keep=1)

        assert self._run(
            "verify", "--log", str(tmp_path / "a.jsonl"),
            "--public-key", str(tmp_path / "k.pem.pub"),
            "--ledger", str(path)) == 1
        assert self._run(
            "sign", "--ledger", str(path), "--key", str(tmp_path / "k.pem"),
            "--log", str(tmp_path / "a.jsonl")) == 1
        assert self._run(
            "verify", "--log", str(tmp_path / "a.jsonl"),
            "--public-key", str(tmp_path / "nope.pub")) == 2

    def test_the_log_verb_says_it_verified_nothing(self, tmp_path, capsys):
        _ledger(tmp_path / "l.db")
        self._run("keygen", "--out", str(tmp_path / "k.pem"))
        self._run("sign", "--ledger", str(tmp_path / "l.db"),
                  "--key", str(tmp_path / "k.pem"), "--log", str(tmp_path / "a.jsonl"))
        capsys.readouterr()
        assert self._run("log", "--log", str(tmp_path / "a.jsonl")) == 0
        assert "Nothing here was verified" in capsys.readouterr().out

    def test_the_passphrase_comes_from_the_environment_not_the_argv(
            self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_ATTEST_PASS", PASSPHRASE)
        assert self._run("keygen", "--out", str(tmp_path / "k.pem"),
                         "--passphrase-env", "TEST_ATTEST_PASS") == 0
        with pytest.raises(SigningKeyError):
            SigningKey.load(tmp_path / "k.pem")
        assert SigningKey.load(tmp_path / "k.pem", passphrase=PASSPHRASE)

    def test_a_missing_passphrase_variable_is_named(self, tmp_path, monkeypatch, capsys):
        monkeypatch.delenv("TEST_ATTEST_PASS", raising=False)
        assert self._run("keygen", "--out", str(tmp_path / "k.pem"),
                         "--passphrase-env", "TEST_ATTEST_PASS") == 1
        assert "$TEST_ATTEST_PASS is not set" in capsys.readouterr().err


# --------------------------------------------------------------------------
@pytest.fixture()
def attest_env(tmp_path, monkeypatch):
    key_path = tmp_path / "secrets" / "service.pem"
    SigningKey.generate().save(key_path)
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(key_path))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    return tmp_path


@pytest.fixture()
def client(attest_env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


class TestApi:
    def _head(self, tmp_path, count=4):
        led = _ledger(tmp_path / "customer.db", count)
        entries = led.entries()
        return {
            "ledger_length": len(entries),
            "head_seq": entries[-1].seq,
            "head_link_hash": entries[-1].link_hash,
        }

    def test_the_public_key_is_free_and_says_what_it_does_not_prove(self, client):
        response = client.get("/v1/ledger/attest/key")
        assert response.status_code == 200
        body = response.json()
        assert body["algorithm"] == "Ed25519"
        assert "BEGIN PUBLIC KEY" in body["public_key_pem"]
        assert any("second route" in c for c in body["checks_skipped"])

    def test_counter_signing_needs_the_cell_plan(self, client, attest_env, tmp_path):
        from assurance.billing.accounts import AccountStore

        store = AccountStore(str(attest_env / "accounts.db"))
        account = store.upsert_account(email="a@b.de", tier="register")
        key = store.issue_key(account.id)
        response = client.post("/v1/ledger/attest",
                               json=self._head(attest_env),
                               headers={"X-API-Key": key})
        assert response.status_code == 402
        assert response.json()["detail"]["error"] == (
            "plan_does_not_include_signed_attestation")

    def test_a_counter_signature_never_receives_the_ledger(self, client, attest_env):
        head = self._head(attest_env)
        response = client.post("/v1/ledger/attest", json=head,
                               headers={"X-API-Key": OPERATOR_KEY})
        assert response.status_code == 200
        body = response.json()
        record = body["attestation"]
        assert record["basis"] == "declared_by_holder"
        assert record["head_link_hash"] == head["head_link_hash"]
        assert any("did not verify your chain" in c for c in body["checks_skipped"])

    def test_the_service_refuses_to_sign_a_shorter_ledger(self, client, attest_env):
        head = self._head(attest_env)
        assert client.post("/v1/ledger/attest", json=head,
                           headers={"X-API-Key": OPERATOR_KEY}).status_code == 200
        shorter = dict(head, ledger_length=2, head_seq=2)
        response = client.post("/v1/ledger/attest", json=shorter,
                               headers={"X-API-Key": OPERATOR_KEY})
        assert response.status_code == 409
        assert "does not get shorter" in response.json()["detail"]["finding"]

    def test_verification_is_free_and_needs_no_key(self, client, attest_env):
        signed = client.post("/v1/ledger/attest", json=self._head(attest_env),
                             headers={"X-API-Key": OPERATOR_KEY}).json()["attestation"]
        response = client.post("/v1/ledger/attest/verify",
                               json={"attestations": [signed]})
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert any("checking its own work" in c for c in body["checks_skipped"])

    def test_a_tampered_attestation_fails_free_verification(self, client, attest_env):
        signed = client.post("/v1/ledger/attest", json=self._head(attest_env),
                             headers={"X-API-Key": OPERATOR_KEY}).json()["attestation"]
        signed["ledger_length"] = 40
        response = client.post("/v1/ledger/attest/verify",
                               json={"attestations": [signed]})
        assert response.json()["ok"] is False

    def test_a_head_hash_that_is_not_a_hash_is_refused(self, client, attest_env):
        response = client.post(
            "/v1/ledger/attest",
            json={"ledger_length": 1, "head_seq": 1, "head_link_hash": "z" * 64},
            headers={"X-API-Key": OPERATOR_KEY})
        assert response.status_code == 422

    def test_without_a_key_the_service_says_so_rather_than_inventing_one(
            self, client, monkeypatch):
        monkeypatch.delenv("ASSURANCE_ATTEST_KEY")
        response = client.get("/v1/ledger/attest/key")
        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "no_attestation_key_configured"

    def test_the_key_can_come_from_the_environment_as_a_secret_manager_gives_it(
            self, client, monkeypatch):
        """fly secrets, and every other secrets manager, hand over a value, not a path."""
        monkeypatch.delenv("ASSURANCE_ATTEST_KEY")
        key = SigningKey.generate()
        pem = key.private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY_PEM", pem)
        body = client.get("/v1/ledger/attest/key").json()
        assert body["fingerprint"] == key.fingerprint

    def test_an_unreadable_key_in_the_environment_is_503_not_500(
            self, client, monkeypatch):
        monkeypatch.setenv("ASSURANCE_ATTEST_KEY_PEM", "-----BEGIN PRIVATE KEY-----\nnope")
        response = client.get("/v1/ledger/attest/key")
        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "attestation_key_unusable"

    def test_the_cell_plan_page_matches_what_the_code_gates(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert plans["cell"]["limits"]["signed_attestation"] is True
        assert plans["register"]["limits"]["signed_attestation"] is False
        assert any("attest" in line for line in plans["cell"]["includes"])
