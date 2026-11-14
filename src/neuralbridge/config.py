"""
NeuralBridge — Centralized Configuration via Pydantic Settings.

All application configuration is validated at startup through Pydantic v2
models.  Environment variables, ``.env`` files, and YAML adapter manifests
are merged into a single, type-safe ``Settings`` instance that every module
can import.

CRA-relevant fields (organisation name, contact e-mail, reporting toggle)
are first-class citizens so that compliance is never an afterthought.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

#: The only JWT algorithms this platform will sign or verify with. HMAC only: there is no
#: asymmetric (RS*/ES*/PS*) signing path, and "none" is never accepted.
ALLOWED_JWT_ALGORITHMS: frozenset[str] = frozenset({"HS256", "HS384", "HS512"})

_ASYMMETRIC_KEY_MARKERS = ("-----begin", "ssh-rsa", "ssh-ed25519", "ecdsa-sha2")

#: Shipped defaults and well-known placeholder values. Matched case-insensitively, either
#: exactly or as a substring for the ``change-me`` family.
DEFAULT_JWT_SECRET = "change-me-jwt-secret"
DEFAULT_SECRET_KEY = "change-me-to-a-random-64-char-string"
_DENY_EXACT = frozenset({
    "secret", "changeme", "password", "jwt-secret", "jwtsecret", "jwt_secret", "default",
    "admin", "test", "testing", "neuralbridge", "supersecret", "secretkey", "secret-key",
    "secret_key", "your-secret-key", "your-secret", "replace-me", "replaceme", "12345678",
    DEFAULT_JWT_SECRET, DEFAULT_SECRET_KEY,
})
_DENY_SUBSTRINGS = ("change-me", "changeme", "change_me")

#: Floors for HMAC secrets outside development. Length and distinct-character count are
#: sanity floors only; they do not measure the strength of a secret.
MIN_SECRET_LENGTH = 32
MIN_DISTINCT_CHARS = 12

_B64_RE = re.compile(rb"[A-Za-z0-9+/_-]+={0,2}")

_log = logging.getLogger("neuralbridge.config")


def _der_is_well_formed_sequence(raw: bytes) -> bool:
    """True when ``raw`` is exactly one DER SEQUENCE (0x30 + length) of useful size."""
    if len(raw) < 16 or raw[0] != 0x30:
        return False
    first = raw[1]
    if first < 0x80:
        head = 2
        total = 2 + first
    else:
        n = first & 0x7F
        if n == 0 or n > 4 or len(raw) < 2 + n:
            return False
        head = 2 + n
        total = head + int.from_bytes(raw[2:head], "big")
    # The first inner element must be an INTEGER or SEQUENCE (every RSA/EC/PKCS8/SPKI shape).
    return len(raw) == total and raw[head] in (0x02, 0x30)


def _key_material_reason(raw: bytes) -> str | None:
    """Return a short reason when ``raw`` is asymmetric key material, else ``None``."""
    low = raw.lower()
    if any(m.encode() in low for m in _ASYMMETRIC_KEY_MARKERS):
        return "PEM/SSH"
    stripped = raw.strip()
    if stripped[:1] in (b"{", b"["):
        try:
            obj = json.loads(stripped)
        except (ValueError, RecursionError):
            obj = None
        if isinstance(obj, dict) and ("kty" in obj or "keys" in obj):
            return "JWK"
        if isinstance(obj, list) and any(isinstance(o, dict) and "kty" in o for o in obj):
            return "JWK"
    if _der_is_well_formed_sequence(raw):
        return "DER"
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import (
        load_der_private_key,
        load_der_public_key,
    )

    for loader in (load_der_public_key, lambda d: load_der_private_key(d, None)):
        try:
            loader(raw)
        except Exception:  # noqa: BLE001, S112 - any parse failure means "not a key"
            continue
        return "DER"
    if raw[:1] in (b"\x02", b"\x03", b"\x04") and len(raw) in (33, 49, 67, 65, 97, 133):
        for curve in (ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1(), ec.SECP256K1()):
            try:
                ec.EllipticCurvePublicKey.from_encoded_point(curve, raw)
            except Exception:  # noqa: BLE001, S112
                continue
            return "EC point"
    return None


def _decodings(text: str, depth: int = 3) -> list[bytes]:
    """The secret as raw text plus every base64 (std/urlsafe, padded or not) and hex
    decoding, recursively to ``depth`` layers."""
    out: list[bytes] = []
    queue: list[tuple[bytes, int]] = [(text.encode("utf-8", "surrogatepass"), depth)]
    try:  # raw DER bytes that were decoded as latin-1 text
        out.append(text.encode("latin-1"))
    except UnicodeEncodeError:
        pass
    seen: set[bytes] = set()
    while queue:
        data, d = queue.pop()
        if data in seen:
            continue
        seen.add(data)
        out.append(data)
        if d == 0:
            continue
        compact = b"".join(data.split())
        if not compact:
            continue
        if _B64_RE.fullmatch(compact):
            std = compact.replace(b"-", b"+").replace(b"_", b"/")
            std = std.rstrip(b"=")
            std += b"=" * (-len(std) % 4)
            try:  # strict: stray bytes must not be silently discarded
                dec = base64.b64decode(std, validate=True)
            except (binascii.Error, ValueError):
                dec = b""
            if dec:
                queue.append((dec, d - 1))
        try:
            dec = bytes.fromhex(compact.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            dec = b""
        if dec:
            queue.append((dec, d - 1))
    return out


def _weak_secret_reasons(secret: str) -> list[str]:
    reasons = []
    low = secret.strip().lower()
    if low in _DENY_EXACT or any(m in low for m in _DENY_SUBSTRINGS):
        reasons.append("is a shipped default or well-known placeholder value")
    if len(secret) < MIN_SECRET_LENGTH:
        reasons.append(f"is shorter than {MIN_SECRET_LENGTH} characters")
    if len(set(secret)) < MIN_DISTINCT_CHARS:
        reasons.append(f"has fewer than {MIN_DISTINCT_CHARS} distinct characters")
    return reasons


def check_secret_strength(name: str, secret: str, env: str | None) -> None:
    """Refuse default/short/low-variety secrets unless ``env`` is explicitly development.

    ``env`` of ``None``, empty or anything other than ``"development"`` is treated as
    production-like (fail closed). In development a weak secret only logs one warning.
    Neither the exception text nor the log ever includes the secret.
    """
    reasons = _weak_secret_reasons(secret)
    if not reasons:
        return
    detail = "; ".join(reasons)
    if str(getattr(env, "value", env) or "").strip().lower() == "development":
        _log.warning("%s %s (tolerated in development only)", name, detail)
        return
    raise ValueError(
        f"{name} {detail}; set a random value of at least {MIN_SECRET_LENGTH} characters "
        "(refusing outside development)"
    )


def check_hmac_secret(secret: str, algorithm: str, env: str | None = None) -> None:
    """Raise ``ValueError`` unless ``algorithm`` is an allowed HMAC algorithm, ``secret``
    does not look like asymmetric key material, and (outside development) the secret is
    not a default and meets the length / distinct-character floors.

    An HMAC secret that is really a PEM/DER/SSH/JWK public key is the algorithm-confusion
    shape: anyone who knows the (public) key can forge tokens. The secret is tested raw
    and after whitespace removal and base64 (standard and url-safe) / hex decoding.
    The message never includes the secret. ``env=None`` means production-like.
    """
    if algorithm not in ALLOWED_JWT_ALGORITHMS:
        raise ValueError(
            f"jwt_algorithm must be one of {sorted(ALLOWED_JWT_ALGORITHMS)} (HMAC only); "
            f"got {algorithm!r}"
        )
    compact = "".join(secret.split())
    for raw in _decodings(compact) + _decodings(secret):
        reason = _key_material_reason(raw)
        if reason:
            raise ValueError(
                f"jwt_secret_key looks like or decodes to {reason} asymmetric key material; "
                "refusing to use it as an HMAC secret"
            )
    check_secret_strength("jwt_secret_key", secret, env)


class Environment(StrEnum):
    """Deployment environment selector."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """
    Root configuration for NeuralBridge.

    Values are loaded in order of precedence:
    1. Explicit environment variables
    2. ``.env`` file in the project root
    3. Defaults declared below

    Every adapter, security module, and compliance reporter reads from this
    single source of truth.
    """

    model_config = SettingsConfigDict(
        env_prefix="NEURALBRIDGE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        # A rejected secret must never be echoed back inside pydantic's error text.
        hide_input_in_errors=True,
    )

    # ── Core ─────────────────────────────────────────────────
    env: Environment = Environment.DEVELOPMENT
    debug: bool = True
    # Exact browser origins allowed to call this API in production. Keep this a comma-separated
    # origin list (scheme + host + optional port), never a URL with a path and never "*".
    # Development keeps the permissive local behaviour when debug=True.
    cors_allowed_origins: str = "https://neuralbridge.io,https://www.neuralbridge.io"
    host: str = "127.0.0.1"  # Use 0.0.0.0 in Docker via env var
    port: int = 8000
    secret_key: str = Field(
        default="change-me-to-a-random-64-char-string",
        description="Master secret used for signing tokens and encrypting credentials.",
    )
    encryption_key: str = Field(
        default="",
        description="Fernet key for credential encryption. Auto-generated on first run if empty.",
    )
    base_dir: Path = Field(
        default_factory=lambda: Path(__file__).resolve().parent.parent.parent,
        description="Project root directory.",
    )

    # ── Database ─────────────────────────────────────────────
    database_url: str = (
        "postgresql+asyncpg://neuralbridge:neuralbridge@localhost:5432/neuralbridge"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # ── Redis ────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 3600  # seconds

    # ── JWT / Auth ───────────────────────────────────────────
    jwt_secret_key: str = "change-me-jwt-secret"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30

    # ── OpenTelemetry ────────────────────────────────────────
    otel_exporter_endpoint: str = "http://localhost:4317"
    otel_service_name: str = "neuralbridge"

    # ── CRA Compliance ───────────────────────────────────────
    cra_organization_name: str = "Your Organization"
    cra_contact_email: str = "compliance@example.com"
    cra_reporting_enabled: bool = True

    # ── Rate Limiting ────────────────────────────────────────
    rate_limit_default: str = "100/minute"
    rate_limit_burst: int = 20

    # ── Logging ──────────────────────────────────────────────
    log_level: str = "INFO"
    log_format: str = "json"  # json | console

    # ── Adapter config directory ─────────────────────────────
    adapters_config_dir: Path = Field(
        default_factory=lambda: Path(os.getcwd()) / "adapters",
        description="Directory containing YAML adapter manifests.",
    )

    # ── Validators ───────────────────────────────────────────
    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper

    @model_validator(mode="after")
    def _validate_jwt_hmac_config(self) -> Settings:
        check_hmac_secret(self.jwt_secret_key, self.jwt_algorithm, self.env)
        check_secret_strength("secret_key", self.secret_key, self.env)
        return self


def get_settings(**overrides: Any) -> Settings:
    """
    Factory that returns a ``Settings`` instance.

    Keyword arguments override environment / file values, which is useful
    for testing.
    """
    return Settings(**overrides)
