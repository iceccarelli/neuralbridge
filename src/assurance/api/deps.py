"""Dependencies: the ledger, and authentication.

Authentication is not optional and not mocked. An Article 14 register holds the
record that decides whether a manufacturer filed on time; an unauthenticated
one is worse than no register, because it produces confident artifacts that
anyone could have written.

Configuration, all by environment variable:

``ASSURANCE_LEDGER``
    Path to the SQLite ledger. Default ``art14-register.db``.

``ASSURANCE_API_KEYS``
    Comma-separated API keys. Presented as ``X-API-Key``.

``ASSURANCE_ALLOW_UNAUTHENTICATED``
    Set to ``1`` to run with no keys configured. Intended for a local
    evaluation only; the service says so on every response and in ``/healthz``.
    Without it, and with no keys configured, every route that touches the
    register returns 503 rather than serving unauthenticated writes.
"""

from __future__ import annotations

import hmac
import os
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, status

from ..evidence.ledger import EvidenceLedger
from ..security.art14.engine import Art14Register

__all__ = ["get_register", "require_api_key", "auth_mode", "ledger_path"]

_LEDGER_ENV = "ASSURANCE_LEDGER"
_KEYS_ENV = "ASSURANCE_API_KEYS"
_OPEN_ENV = "ASSURANCE_ALLOW_UNAUTHENTICATED"


def ledger_path() -> str:
    return os.environ.get(_LEDGER_ENV, "art14-register.db")


def _configured_keys() -> tuple[str, ...]:
    raw = os.environ.get(_KEYS_ENV, "")
    return tuple(k.strip() for k in raw.split(",") if k.strip())


def auth_mode() -> str:
    """``api_key``, ``open`` or ``unconfigured``."""
    if _configured_keys():
        return "api_key"
    if os.environ.get(_OPEN_ENV) == "1":
        return "open"
    return "unconfigured"


@lru_cache(maxsize=8)
def _register_for(path: str) -> Art14Register:
    return Art14Register(EvidenceLedger(path))


def get_register() -> Art14Register:
    """The register, opened once per ledger path."""
    return _register_for(ledger_path())


async def require_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Reject anything that is not presenting a configured key.

    Comparison is constant-time. The failure message never says whether the
    key was absent, malformed or simply wrong.
    """
    mode = auth_mode()
    if mode == "unconfigured":
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"No API keys are configured. Set {_KEYS_ENV} to a comma-separated list, or "
                f"set {_OPEN_ENV}=1 to run without authentication for local evaluation. "
                "This service refuses to accept unauthenticated writes to a regulatory "
                "register by default."
            ),
        )
    if mode == "open":
        return "unauthenticated"
    presented = x_api_key or ""
    for key in _configured_keys():
        if hmac.compare_digest(presented, key):
            return key[:8]
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing X-API-Key.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


Authenticated = Depends(require_api_key)
