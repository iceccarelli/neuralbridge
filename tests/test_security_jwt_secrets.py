"""JWT secret hygiene: key-shaped secrets in disguise, shipped defaults, strength floors."""

from __future__ import annotations

import base64
import json
import logging
import secrets
import string

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from neuralbridge.config import DEFAULT_JWT_SECRET, DEFAULT_SECRET_KEY, Settings, check_hmac_secret
from neuralbridge.security import auth

GOOD = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(48))

_RSA = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_EC = ec.generate_private_key(ec.SECP256R1())
_SPKI = serialization.PublicFormat.SubjectPublicKeyInfo
_DER, _PEM = serialization.Encoding.DER, serialization.Encoding.PEM
SPKI_DER = _RSA.public_key().public_bytes(_DER, _SPKI)
SPKI_PEM = _RSA.public_key().public_bytes(_PEM, _SPKI)
PKCS1_PUB = _RSA.public_key().public_bytes(_DER, serialization.PublicFormat.PKCS1)
PKCS8_PRIV = _RSA.private_bytes(_DER, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
PKCS1_PRIV = _RSA.private_bytes(_DER, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
EC_SPKI = _EC.public_key().public_bytes(_DER, _SPKI)
EC_POINT = _EC.public_key().public_bytes(serialization.Encoding.X962,
                                         serialization.PublicFormat.UncompressedPoint)
EC_POINT_C = _EC.public_key().public_bytes(serialization.Encoding.X962,
                                           serialization.PublicFormat.CompressedPoint)


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def ub64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode()


def wrapped(s: str, n: int = 64) -> str:
    return "\n".join(s[i:i + n] for i in range(0, len(s), n))


JWK = json.dumps({"kty": "RSA", "n": "x" * 40, "e": "AQAB"})

VARIANTS = {
    "wrapped_b64_der": wrapped(b64(SPKI_DER)),
    "pem_body_no_header": "".join(SPKI_PEM.decode().splitlines()[1:-1]),
    "pem_body_wrapped_no_header": "\n".join(SPKI_PEM.decode().splitlines()[1:-1]),
    "b64_of_pem": b64(SPKI_PEM),
    "hex_der": SPKI_DER.hex(),
    "urlsafe_b64_der": ub64(SPKI_DER),
    "urlsafe_b64_der_unpadded": ub64(SPKI_DER).rstrip("="),
    "std_b64_der_unpadded": b64(SPKI_DER).rstrip("="),
    "jwk": JWK,
    "jwk_spaced": json.dumps({"kty": "oct", "k": "abc"}, indent=2),
    "b64_of_jwk": b64(JWK.encode()),
    "pkcs1_public_b64": b64(PKCS1_PUB),
    "pkcs8_private_b64": b64(PKCS8_PRIV),
    "pkcs1_private_hex": PKCS1_PRIV.hex(),
    "ec_spki_b64": b64(EC_SPKI),
    "ec_point_hex": EC_POINT.hex(),
    "ec_point_compressed_b64": b64(EC_POINT_C),
    "hex_of_pem": SPKI_PEM.hex(),
    "double_b64_pem": b64(b64(SPKI_PEM).encode()),
}


class TestKeyShapedSecretsRefused:
    @pytest.mark.parametrize("name", sorted(VARIANTS))
    @pytest.mark.parametrize("env", ["production", "development"])
    def test_refused_in_every_environment(self, name, env):
        with pytest.raises(ValueError, match="key material") as exc:
            Settings(jwt_secret_key=VARIANTS[name], jwt_algorithm="HS256", env=env)
        assert VARIANTS[name][:40] not in str(exc.value)

    def test_normal_random_secrets_not_mistaken_for_keys(self):
        for _ in range(200):
            check_hmac_secret(secrets.token_urlsafe(36), "HS256", "production")
            check_hmac_secret(secrets.token_hex(32), "HS256", "production")
            check_hmac_secret(b64(secrets.token_bytes(40)), "HS256", "production")


class TestDefaultsAndFloors:
    @pytest.mark.parametrize("value", [
        DEFAULT_JWT_SECRET, DEFAULT_SECRET_KEY, "secret", "changeme",
        "Change-Me-please-" + "x" * 30, "password", "jwt-secret", "  " + DEFAULT_JWT_SECRET,
    ])
    @pytest.mark.parametrize("env", ["production", "staging"])
    def test_denylisted_values_refused(self, value, env):
        with pytest.raises(ValueError, match="refusing outside development"):
            Settings(jwt_secret_key=value, env=env)

    def test_shipped_defaults_refused_in_production(self):
        with pytest.raises(ValueError):
            Settings(env="production")
        with pytest.raises(ValueError, match="secret_key"):
            Settings(env="production", jwt_secret_key=GOOD)

    def test_short_secret_refused(self):
        with pytest.raises(ValueError, match="shorter than 32"):
            Settings(env="production", jwt_secret_key=GOOD[:31], secret_key=GOOD)

    def test_low_variety_secret_refused(self):
        with pytest.raises(ValueError, match="distinct"):
            Settings(env="production", jwt_secret_key="ab" * 30, secret_key=GOOD)

    def test_check_without_env_is_production_like(self):
        with pytest.raises(ValueError):
            check_hmac_secret(DEFAULT_JWT_SECRET, "HS256")
        with pytest.raises(ValueError):
            check_hmac_secret(GOOD[:10], "HS256", "")
        with pytest.raises(ValueError):
            check_hmac_secret(GOOD[:10], "HS256", "prod")

    def test_good_secret_accepted_in_production(self):
        s = Settings(env="production", jwt_secret_key=GOOD, secret_key=GOOD[::-1])
        assert s.jwt_secret_key == GOOD

    def test_development_accepts_default_with_one_warning_and_no_value(self, caplog):
        with caplog.at_level(logging.WARNING, logger="neuralbridge.config"):
            Settings(env="development", jwt_secret_key=DEFAULT_JWT_SECRET, secret_key=GOOD)
        warns = [r for r in caplog.records if r.name == "neuralbridge.config"]
        assert len(warns) == 1
        assert DEFAULT_JWT_SECRET not in caplog.text and "change-me" not in caplog.text
        assert "development only" in caplog.text

    def test_no_warning_for_good_secret(self, caplog):
        with caplog.at_level(logging.WARNING, logger="neuralbridge.config"):
            Settings(env="development", jwt_secret_key=GOOD, secret_key=GOOD)
        assert not caplog.records


class TestNoEcho:
    @pytest.mark.parametrize("value", [
        "ababab-UNIQUE-TAIL-xyz", "changeme-UNIQUE-TAIL-xyz", "ssh-rsa UNIQUE-TAIL-xyz",
        VARIANTS["hex_der"],
    ])
    def test_exception_text_never_contains_secret(self, value, caplog):
        with caplog.at_level(logging.DEBUG):
            with pytest.raises(ValueError) as exc:
                check_hmac_secret(value, "HS256", "production")
        assert value not in str(exc.value) and "UNIQUE-TAIL" not in str(exc.value)
        assert "UNIQUE-TAIL" not in caplog.text

    def test_settings_validation_error_does_not_echo(self):
        with pytest.raises(ValueError) as exc:
            Settings(env="production", jwt_secret_key="short-UNIQUE-TAIL-xyz")  # noqa: S106
        assert "UNIQUE-TAIL" not in str(exc.value)


class TestTokensStillVerify:
    def test_round_trip_with_strong_secret_in_production(self, monkeypatch):
        monkeypatch.setattr(auth, "JWT_SECRET_KEY", GOOD)
        monkeypatch.setattr(auth, "JWT_ALGORITHM", "HS256")
        monkeypatch.setattr(auth.settings, "env", "production")
        h = auth.AuthHandler()
        tok = h.create_access_token({"sub": "alice"})
        assert h.decode_token(tok).sub == "alice"

    def test_default_secret_cannot_sign_or_verify_in_production(self, monkeypatch):
        monkeypatch.setattr(auth, "JWT_SECRET_KEY", DEFAULT_JWT_SECRET)
        monkeypatch.setattr(auth, "JWT_ALGORITHM", "HS256")
        monkeypatch.setattr(auth.settings, "env", "production")
        h = auth.AuthHandler()
        with pytest.raises(ValueError):
            h.create_access_token({"sub": "alice"})
        with pytest.raises(ValueError):
            h.decode_token("a.b.c")
