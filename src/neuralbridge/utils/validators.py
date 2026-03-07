"""
NeuralBridge Input Validators.

Centralised validation functions used across adapters, API routes, and
the configuration loader.  Every external input passes through these
guards before reaching business logic — a key zero-trust principle.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator

# ── Reusable Regex Patterns ──────────────────────────────────

_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_\-]{0,127}$")
_RATE_LIMIT_PATTERN = re.compile(r"^\d+/(second|minute|hour|day)$")


def validate_identifier(value: str, field_name: str = "identifier") -> str:
    """
    Ensure *value* is a safe alphanumeric identifier (max 128 chars).

    Raises
    ------
    ValueError
        If the value contains disallowed characters.
    """
    if not _SAFE_IDENTIFIER.match(value):
        raise ValueError(
            f"{field_name} must match ^[a-zA-Z_][a-zA-Z0-9_-]{{0,127}}$, got: {value!r}"
        )
    return value


def validate_url(value: str, schemes: set[str] | None = None) -> str:
    """
    Validate that *value* is a well-formed URL with an allowed scheme.

    Parameters
    ----------
    schemes : set[str] | None
        Allowed URL schemes.  Defaults to ``{"http", "https"}``.
    """
    allowed = schemes or {"http", "https"}
    parsed = urlparse(value)
    if parsed.scheme not in allowed:
        raise ValueError(f"URL scheme must be one of {allowed}, got: {parsed.scheme!r}")
    if not parsed.netloc:
        raise ValueError(f"URL must include a host, got: {value!r}")
    return value


def validate_rate_limit(value: str) -> str:
    """
    Validate rate-limit strings like ``"100/minute"`` or ``"5000/hour"``.
    """
    if not _RATE_LIMIT_PATTERN.match(value):
        raise ValueError(
            f"Rate limit must match '<int>/<second|minute|hour|day>', got: {value!r}"
        )
    return value


def sanitize_sql_identifier(value: str) -> str:
    """
    Prevent SQL injection in dynamic identifiers (table / column names).

    Only allows alphanumeric characters, underscores, and dots.
    """
    cleaned = re.sub(r"[^a-zA-Z0-9_.]", "", value)
    if cleaned != value:
        raise ValueError(f"Potentially unsafe SQL identifier: {value!r}")
    return cleaned


# ── Pydantic Models for Common Payloads ──────────────────────

class AdapterConfigPayload(BaseModel):
    """Validates the JSON body when creating / updating an adapter via the API."""

    name: str
    adapter_type: str
    auth_type: str = "api_key"
    config: dict[str, Any] = {}
    permissions: list[str] = []
    rate_limit: str = "100/minute"

    @field_validator("name")
    @classmethod
    def _check_name(cls, v: str) -> str:
        return validate_identifier(v, "name")

    @field_validator("rate_limit")
    @classmethod
    def _check_rate_limit(cls, v: str) -> str:
        return validate_rate_limit(v)
