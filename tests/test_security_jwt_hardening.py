"""JWT hardening for the platform auth module (algorithm confusion, alg=none, key hygiene)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import timedelta

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from neuralbridge.config import Settings, check_hmac_secret
from neuralbridge.security import auth

# >= 64 bytes: the HS512 control in test_header_alg_mismatch_... verifies with this very key, and
# PyJWT warns (InsecureKeyLengthWarning) when an HMAC key is shorter than its digest.
SECRET = "a-long-random-test-secret-0123456789-0123456789-0123456789-0123456789"


@pytest.fixture
def handler(monkeypatch):
    monkeypatch.setattr(auth, "JWT_SECRET_KEY", SECRET)
    monkeypatch.setattr(auth, "JWT_ALGORITHM", "HS256")
    return auth.AuthHandler()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge(header: dict, payload: dict, key: bytes, digest=hashlib.sha256) -> str:
    """Hand-built HS token: bypasses any library guard so the verifier is what is tested."""
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(payload).encode())}"
    sig = hmac.new(key, signing_input.encode(), digest).digest()
    return f"{signing_input}.{_b64(sig)}"


def _public_pem_and_der():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    pem = pub.public_bytes(serialization.Encoding.PEM,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    der = pub.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem, der


CLAIMS = {"sub": "alice", "exp": 4102444800}  # 2100-01-01: never expires during a test run


class TestNormalOperation:
    def test_round_trip(self, handler):
        token = handler.create_access_token({"sub": "alice", "roles": ["Admin"]})
        payload = handler.decode_token(token)
        assert payload is not None and payload.sub == "alice"
        assert [str(r) for r in payload.roles] == ["Admin"]

    def test_hand_forged_token_with_the_right_secret_is_accepted(self, handler):
        # Control for the rejection tests below: the _forge helper itself produces a token
        # the verifier accepts, so those rejections are about the guards, not the helper.
        token = _forge({"alg": "HS256", "typ": "JWT"}, CLAIMS, SECRET.encode())
        payload = handler.decode_token(token)
        assert payload is not None and payload.sub == "alice"

    def test_expired_token_rejected(self, handler):
        token = handler.create_access_token({"sub": "alice"}, expires_delta=timedelta(seconds=-5))
        assert handler.decode_token(token) is None

    def test_token_without_exp_rejected(self, handler):
        token = pyjwt.encode({"sub": "alice"}, SECRET, algorithm="HS256")
        assert handler.decode_token(token) is None

    def test_wrong_secret_rejected(self, handler):
        token = pyjwt.encode(CLAIMS, "some-other-secret-value-0123456789", algorithm="HS256")
        assert handler.decode_token(token) is None

    def test_garbage_rejected(self, handler):
        assert handler.decode_token("not.a.token") is None
        assert handler.decode_token("") is None


class TestAlgorithmConfusion:
    def test_hs256_signed_with_public_pem_as_secret_is_rejected(self, handler, monkeypatch):
        pem, _ = _public_pem_and_der()
        # The classic attack: the verifier is (mis)configured with the public key and an
        # attacker signs HS256 using that same public key as the HMAC secret.
        forged = _forge({"alg": "HS256", "typ": "JWT"}, CLAIMS, pem)
        monkeypatch.setattr(auth, "JWT_SECRET_KEY", pem.decode())
        with pytest.raises(ValueError, match="asymmetric"):
            handler.decode_token(forged)

    def test_hs256_signed_with_public_der_as_secret_is_rejected(self, handler, monkeypatch):
        _, der = _public_pem_and_der()
        forged = _forge({"alg": "HS256", "typ": "JWT"}, CLAIMS, der)
        monkeypatch.setattr(auth, "JWT_SECRET_KEY", base64.b64encode(der).decode())
        with pytest.raises(ValueError, match="DER"):
            handler.decode_token(forged)

    def test_asymmetric_header_with_hmac_config_rejected(self, handler):
        pem, _ = _public_pem_and_der()
        forged = _forge({"alg": "RS256", "typ": "JWT"}, CLAIMS, pem)
        assert handler.decode_token(forged) is None

    def test_es256_header_rejected(self, handler):
        key = ec.generate_private_key(ec.SECP256R1())
        token = pyjwt.encode(CLAIMS, key, algorithm="ES256")
        assert handler.decode_token(token) is None

    def test_alg_none_rejected(self, handler):
        header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        assert handler.decode_token(f"{header}.{_b64(json.dumps(CLAIMS).encode())}.") is None

    @pytest.mark.parametrize("alg", ["None", "NONE", "nOnE"])
    def test_alg_none_case_variants_rejected(self, handler, alg):
        header = _b64(json.dumps({"alg": alg}).encode())
        assert handler.decode_token(f"{header}.{_b64(json.dumps(CLAIMS).encode())}.") is None

    def test_header_alg_mismatch_rejected_even_with_valid_signature(self, handler):
        # Correct secret, valid HMAC, but HS512 while the service is configured for HS256.
        token = _forge({"alg": "HS512", "typ": "JWT"}, CLAIMS, SECRET.encode(), hashlib.sha512)
        assert pyjwt.decode(token, SECRET, algorithms=["HS512"])["sub"] == "alice"  # control
        assert handler.decode_token(token) is None

    def test_creation_never_signs_with_asymmetric_or_none(self, handler, monkeypatch):
        for alg in ("ES256", "RS256", "none", "EdDSA"):
            monkeypatch.setattr(auth, "JWT_ALGORITHM", alg)
            with pytest.raises(ValueError, match="HMAC only"):
                handler.create_access_token({"sub": "alice"})


class TestConfigurationRefusal:
    @pytest.mark.parametrize("secret", [
        "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----\n",
        "  -----BEGIN RSA PRIVATE KEY-----\nabc",
        "ssh-rsa AAAAB3NzaC1yc2E user@host",
        "ecdsa-sha2-nistp256 AAAAE2VjZHNh user@host",
        "ssh-ed25519 AAAAC3Nza user@host",
    ])
    def test_pem_and_ssh_looking_secrets_refused(self, secret):
        with pytest.raises(ValueError, match="asymmetric"):
            Settings(jwt_secret_key=secret, jwt_algorithm="HS256")

    def test_real_pem_and_base64_der_refused_at_settings_load(self):
        pem, der = _public_pem_and_der()
        with pytest.raises(ValueError):
            Settings(jwt_secret_key=pem.decode(), jwt_algorithm="HS256")
        with pytest.raises(ValueError, match="DER"):
            Settings(jwt_secret_key=base64.b64encode(der).decode(), jwt_algorithm="HS256")

    def test_der_bytes_decoded_as_text_refused(self):
        _, der = _public_pem_and_der()
        with pytest.raises(ValueError, match="DER"):
            check_hmac_secret(der.decode("latin-1"), "HS256")

    @pytest.mark.parametrize("alg", ["none", "RS256", "ES256", "ES384", "EdDSA", ""])
    def test_non_hmac_algorithms_refused(self, alg):
        with pytest.raises(ValueError, match="HMAC only"):
            Settings(jwt_secret_key=SECRET, jwt_algorithm=alg)

    def test_error_message_does_not_contain_the_secret(self):
        secret = "ssh-rsa AAAAB3NzaC1yc2E-super-sensitive-tail"
        with pytest.raises(ValueError) as exc:
            check_hmac_secret(secret, "HS256")
        assert "super-sensitive-tail" not in str(exc.value)

    @pytest.mark.parametrize("alg", ["HS256", "HS384", "HS512"])
    def test_ordinary_secret_accepted(self, alg):
        assert Settings(jwt_secret_key=SECRET, jwt_algorithm=alg).jwt_algorithm == alg

    def test_default_settings_still_load(self):
        Settings()


def test_no_asymmetric_signing_path_in_source():
    from pathlib import Path
    text = Path(auth.__file__).read_text(encoding="utf-8")
    assert "jose" not in text
    for needle in ("ES256", "ES384", "ES512", "RS256", "ecdsa"):
        assert needle not in text


def test_failed_decode_does_not_log_the_token(handler, capsys, caplog):
    secret_token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sentinel-token-body"
    assert handler.decode_token(secret_token) is None
    out = capsys.readouterr()
    assert "sentinel-token-body" not in out.out + out.err + caplog.text
