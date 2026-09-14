"""Dependencies: the register, the account store, and who is calling.

Three things are settled here.

**Authentication is not optional.** An Article 14 register holds the record
that decides whether a manufacturer filed on time. An unauthenticated one is
worse than none, because it produces confident artifacts anyone could have
written.

**Entitlement is read on every request.** A tier that is stored and never
consulted is a pricing page that lies. :func:`require_register` is the only
door into the register, and it asks the plan every time.

**Quota is spent in the same transaction that authorises the call.** Counting
elsewhere and reconciling later is how a metered product leaks.

Configuration, all by environment variable:

``ASSURANCE_LEDGER``    evidence ledger path (default ``art14-register.db``)
``ASSURANCE_ACCOUNTS``  account and key store path (default ``accounts.db``)
``ASSURANCE_API_KEYS``  comma-separated operator keys; full access, no quota
``ASSURANCE_ALLOW_UNAUTHENTICATED``  ``1`` to run open for local evaluation
``ASSURANCE_PUBLIC_URL`` base URL used in checkout redirects
``STRIPE_SECRET_KEY`` / ``STRIPE_WEBHOOK_SECRET`` / ``ASSURANCE_PRICE_*``
"""

from __future__ import annotations

import hmac
import os
from functools import lru_cache

from fastapi import Depends, Header, HTTPException, Request, status

from ..billing.accounts import Account, AccountStore, Principal, QuotaExceededError
from ..evidence.ledger import EvidenceLedger
from ..security.art14.engine import Art14Register

__all__ = [
    "get_register",
    "get_accounts",
    "current_principal",
    "require_machine",
    "require_register",
    "spend",
    "auth_mode",
    "ledger_path",
    "accounts_path",
    "public_url",
]

_LEDGER_ENV = "ASSURANCE_LEDGER"
_ACCOUNTS_ENV = "ASSURANCE_ACCOUNTS"
_KEYS_ENV = "ASSURANCE_API_KEYS"
_OPEN_ENV = "ASSURANCE_ALLOW_UNAUTHENTICATED"


def ledger_path() -> str:
    return os.environ.get(_LEDGER_ENV, "art14-register.db")


def accounts_path() -> str:
    return os.environ.get(_ACCOUNTS_ENV, "accounts.db")


def public_url() -> str:
    return os.environ.get("ASSURANCE_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")


def _operator_keys() -> tuple[str, ...]:
    raw = os.environ.get(_KEYS_ENV, "")
    return tuple(k.strip() for k in raw.split(",") if k.strip())


def auth_mode() -> str:
    """``api_key``, ``open`` or ``unconfigured``."""
    if _operator_keys():
        return "api_key"
    if os.environ.get(_OPEN_ENV) == "1":
        return "open"
    return "unconfigured"


@lru_cache(maxsize=8)
def _register_for(path: str) -> Art14Register:
    return Art14Register(EvidenceLedger(path))


@lru_cache(maxsize=8)
def _accounts_for(path: str) -> AccountStore:
    return AccountStore(path)


def get_register() -> Art14Register:
    return _register_for(ledger_path())


def get_accounts() -> AccountStore:
    return _accounts_for(accounts_path())


_OPERATOR = Account(
    id="operator",
    email="",
    company="operator",
    tier="cell",
    status="active",
)


async def current_principal(
    request: Request,
    x_api_key: str | None = Header(default=None),
    accounts: AccountStore = Depends(get_accounts),
) -> Principal:
    """Resolve the caller. Never raises for an absent key.

    No key means the free, address-limited path — which is the point: the
    validator has to be usable by a prospect who has not signed up for
    anything. A key that is presented and wrong is a 401, because that is a
    mistake the caller needs told about.
    """
    presented = (x_api_key or "").strip()
    if not presented:
        client = request.client.host if request.client else "unknown"
        return Principal(account=None, key_prefix="", anonymous_subject=f"ip:{client}")

    for key in _operator_keys():
        if hmac.compare_digest(presented, key):
            return Principal(account=_OPERATOR, key_prefix="operator")

    principal = accounts.resolve_key(presented)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return principal


def spend(principal: Principal, scope: str, limit: int | None, accounts: AccountStore) -> None:
    """Consume one unit of allowance, or refuse with a 429 that says what to do."""
    try:
        accounts.consume(principal.subject, scope, limit, principal.tier)
    except QuotaExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "quota_exceeded",
                "scope": exc.scope,
                "limit": exc.limit,
                "used": exc.used,
                "tier": exc.tier,
                "remedy": (
                    "The free validator allows "
                    f"{exc.limit} calls per day. A paid plan removes the cap: see "
                    "GET /v1/plans, then POST /v1/checkout."
                ),
            },
        ) from exc


async def require_register(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The only door into the register.

    Returns 402 rather than 403 when the caller is authenticated but not
    entitled: the obstacle is payment, and the status code should say so.
    """
    mode = auth_mode()
    if mode == "unconfigured" and principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"No operator keys configured and no account presented. Set {_KEYS_ENV}, "
                f"or sell a plan, or set {_OPEN_ENV}=1 for local evaluation. This service "
                "refuses unauthenticated writes to a regulatory register by default."
            ),
        )
    if mode == "open" and principal.account is None:
        return Principal(account=_OPERATOR, key_prefix="open-mode")

    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not principal.plan.register:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "plan_does_not_include_register",
                "tier": principal.tier,
                "account_status": principal.account.status,
                "remedy": (
                    "The register is included from the Register plan upward. "
                    "GET /v1/plans, then POST /v1/checkout."
                ),
            },
        )
    return principal


async def require_machine(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The door into machine safety verification.

    Same 402-not-403 rule as the register: an authenticated caller without the
    entitlement is looking at a price, not a prohibition.
    """
    if auth_mode() == "open" and principal.account is None:
        return Principal(account=_OPERATOR, key_prefix="open-mode")
    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not principal.plan.machine_verification:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "plan_does_not_include_machine_verification",
                "tier": principal.tier,
                "account_status": principal.account.status,
                "remedy": (
                    "Machine safety verification is included from the Cell plan "
                    "upward. The separation calculator "
                    "(POST /v1/machine/separation) and the bundle re-checker "
                    "(POST /v1/machine/bundle/check) stay free. "
                    "GET /v1/plans, then POST /v1/checkout."
                ),
            },
        )
    return principal


Registered = Depends(require_register)
Machine = Depends(require_machine)
Anyone = Depends(current_principal)
