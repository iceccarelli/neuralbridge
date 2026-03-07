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

import os
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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
    )

    # ── Core ─────────────────────────────────────────────────
    env: Environment = Environment.DEVELOPMENT
    debug: bool = True
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


def get_settings(**overrides: Any) -> Settings:
    """
    Factory that returns a ``Settings`` instance.

    Keyword arguments override environment / file values, which is useful
    for testing.
    """
    return Settings(**overrides)
