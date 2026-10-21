"""Tenant isolation for the /ai control plane — who may see and use what.

Every connection, plan and audit entry the control plane stores carries an
``owner``: the id of the account that created it. The owner is derived
**only** from the validated :class:`~neuralbridge.ai.entitlements.Principal`
(see :func:`neuralbridge.ai.entitlements.scope_for`) — never from a header,
query string or body field the caller controls. ``X-NB-Actor`` is
client-supplied and is deliberately *not* a tenancy input; it only labels
who-did-what inside one tenant's trail.

Visibility rules (the single place they are written down):

* **Customer account** (``acc_...``): sees/uses only records whose owner is
  its own account id, plus the env-seeded demo connection for READ
  discovery (the documented free surface).
* **Anonymous / free**: owns nothing (it cannot bind or plan). It may read
  the seeded demo connection and nothing else.
* **Operator** (an ``ASSURANCE_API_KEYS`` key, or open mode): full access to
  every record, as before this change.
* **Legacy rows** (owner ``''`` — written before owners existed): visible to
  the operator only, *except* the seeded demo connection, which is
  identified by ``source == "seeded_from_env"`` and so stays a shared demo.
* The seeded demo connection is **not deletable** by a non-operator. A paid
  account may still propose/approve WRITEs against it (the documented
  Register/Cell write path — see ``DEMO_WRITABLE_BY_PAID``); anonymous/free
  callers cannot, as before (402 at the paid gate).

A record the caller may not see is indistinguishable from one that does not
exist: callers get the same 404 body for both. There is no existence oracle.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

#: ``source`` of the env-seeded demo connection — shared, READ-discoverable.
DEMO_SOURCE = "seeded_from_env"

#: Whether a *paid* (non-operator) account may propose/approve WRITEs on the
#: shared seeded demo connection. True preserves the documented Register/Cell
#: write loop on the demo database (see tests/test_ai_buyer_journey.py);
#: flip to False to make the demo strictly read-only for every non-operator.
DEMO_WRITABLE_BY_PAID = True

OPERATOR_OWNER = "operator"


@dataclass(frozen=True)
class Scope:
    """Who is asking, in tenancy terms. ``owner`` is never empty."""

    owner: str
    is_operator: bool = False

    def __post_init__(self) -> None:
        if not self.owner:
            raise ValueError("a tenancy Scope must have a non-empty owner")


class _HasOwner(Protocol):
    owner: str


class _Connection(_HasOwner, Protocol):
    source: str


def is_demo(connection: _Connection) -> bool:
    return connection.source == DEMO_SOURCE


def can_read_connection(scope: Scope, connection: _Connection) -> bool:
    """May ``scope`` list/describe/read this connection?"""
    if scope.is_operator:
        return True
    if is_demo(connection):
        return True
    return bool(connection.owner) and connection.owner == scope.owner


def can_plan_on_connection(scope: Scope, connection: _Connection) -> bool:
    """May ``scope`` propose a WRITE on this connection? (The paid gate is
    enforced separately at the route layer.)"""
    if scope.is_operator:
        return True
    if is_demo(connection):
        return DEMO_WRITABLE_BY_PAID
    return bool(connection.owner) and connection.owner == scope.owner


def can_delete_connection(scope: Scope, connection: _Connection) -> bool:
    """May ``scope`` unbind this connection? The demo is operator-only."""
    if scope.is_operator:
        return True
    if is_demo(connection):
        return False
    return bool(connection.owner) and connection.owner == scope.owner


def can_access_plan(scope: Scope, plan: _HasOwner) -> bool:
    """May ``scope`` inspect/approve/deny this plan? Only the account that
    proposed it (or the operator)."""
    if scope.is_operator:
        return True
    return bool(plan.owner) and plan.owner == scope.owner


def can_see_audit_entry(scope: Scope, entry_owner: str | None) -> bool:
    if scope.is_operator:
        return True
    return bool(entry_owner) and entry_owner == scope.owner
