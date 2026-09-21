"""The paid gate for /ai and the raw adapters/MCP paths it shares a policy
with — reusing the assurance product's own account store and API-key
mechanism rather than inventing a second one.

Why reuse `assurance` directly instead of an HTTP call to it: both
`neuralbridge` and `assurance` are packages inside this one installed
distribution (one `pyproject.toml`, one Python environment — see
`pyproject.toml`'s single `[project]` block). Whether they are ultimately
served as one ASGI process or two, the *entitlement data* — who has a
Register/Cell key, what a plan permits — lives in one place:
`ASSURANCE_ACCOUNTS` (the same SQLite file `assurance.api.service` reads).
Importing `assurance.api.deps.current_principal` here means a customer's
existing Register/Cell API key works against `/ai` with zero extra setup,
and there is exactly one entitlement engine in the codebase, not two that
can drift. If a future deployment genuinely splits these into separate
network services, this module is the one place that would change to an
HTTP call — nothing above it (`api/routes/ai.py`, `api/routes/adapters.py`,
`core/gateway.py`) needs to know the difference.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, status

from assurance.api.deps import _operator_keys, auth_mode, current_principal, get_accounts, spend
from assurance.billing.accounts import Account, AccountStore, Principal

__all__ = [
    "Principal",
    "current_principal",
    "get_accounts",
    "require_ai_control_plane",
    "resolve_principal",
    "spend_ai_read",
]

_OPERATOR = Account(id="operator", email="", company="operator", tier="cell", status="active")


async def require_ai_control_plane(principal: Principal) -> Principal:
    """The door into WRITE (plan/approve), additional connections, and the
    full audit trail — everywhere this is imported, not just `/ai`'s own
    routes, so a free caller cannot buy the same capability more cheaply by
    going around `/ai` through the raw adapters REST route or the MCP
    gateway (see `reports/NEURALBRIDGE-AI-PHASE2.md`, "closing the bypass").

    Deliberately **402 for every under-entitled caller, key or no key** —
    unlike `assurance.api.deps.require_register` (401 for no key at all,
    402 only once a key proves insufficient), because the free tier here
    is Validator, a real tier that needs no key at all elsewhere in this
    product (`spec_validate`, `plans`, ...). An anonymous READ-only caller
    hitting a WRITE-shaped request should see "upgrade," not "log in" —
    they were never going to get further by presenting *a* key, only *a
    paid* key. A key that is presented and simply wrong still raises 401
    inside `current_principal` before this function ever runs.
    """
    if auth_mode() == "open" and principal.account is None:
        return Principal(account=_OPERATOR, key_prefix="open-mode")

    if not principal.plan.ai_control_plane:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "plan_does_not_include_ai_control_plane",
                "tier": principal.tier,
                "remedy": (
                    "The /ai control plane's write path (propose-and-approve, "
                    "additional connections, full audit trail) is included from "
                    "the Register plan upward. Reads stay free, rate-limited. "
                    "GET /v1/plans, then POST /v1/checkout."
                ),
            },
        )
    return principal


def resolve_principal(api_key: str | None, accounts: AccountStore, *, anonymous_subject: str = "mcp:anonymous") -> Principal:
    """Resolve a :class:`Principal` outside an HTTP request — for the MCP
    gateway (stdio, no ``Request``/``Header`` to inject). Same key
    resolution as ``assurance.api.deps.current_principal``, reusing its
    private ``_operator_keys()`` rather than re-parsing
    ``ASSURANCE_API_KEYS`` a second way.

    Raises :class:`ValueError` for a presented-but-invalid key — the
    caller decides how to surface that (the gateway turns it into a JSON-RPC
    error, matching ``current_principal``'s 401 in the HTTP path).
    """
    presented = (api_key or "").strip()
    if not presented:
        return Principal(account=None, key_prefix="", anonymous_subject=anonymous_subject)
    for key in _operator_keys():
        if hmac.compare_digest(presented, key):
            return Principal(account=_OPERATOR, key_prefix="operator")
    principal = accounts.resolve_key(presented)
    if principal is None:
        raise ValueError("Invalid or revoked API key.")
    return principal


def spend_ai_read(principal: Principal, accounts: AccountStore) -> None:
    """Meter a READ against the free daily allowance. No-ops for a paid plan
    (``ai_reads_per_day`` is ``None`` for Register/Cell — see
    ``AccountStore.consume``, which treats ``limit=None`` as unlimited)."""
    spend(principal, "ai_reads", principal.plan.ai_reads_per_day, accounts)
