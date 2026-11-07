"""Security-relevant audit events for the control plane, in one place.

Every event carries the **actor** (``kind:id`` from ``X-NB-Actor``, label only) and
the **tenant** (``details["owner"]``, derived from the validated principal, never
from client input) so a customer's ``/ai/audit`` and ``/logs`` show exactly their
own trail and the operator's shows all of it.

Event types written here (the router additionally writes ``adapter_call`` /
``adapter_error`` for every adapter execution, and the MCP gateway writes
``mcp_request`` / ``mcp_error``):

=====================  ===========================================================
``connection_create``  a connection was bound
``connection_rotate``  its credentials were replaced (or re-supplied after a restart)
``connection_revoke``  it was revoked (permanent; takes effect on the next call)
``connection_delete``  it was unbound
``plan_propose``       a WRITE/DESTRUCTIVE operation was proposed
``plan_approve``       a plan was approved (result ``success``) or the approval was refused
``plan_deny``          a plan was denied
``plan_execute``       the approved plan ran (``success``) or failed / outcome unknown (``failure``)
``entitlement_denied`` a 402 at a paid gate (``/ai`` write path, raw adapters route, MCP)
``policy_denied``      a 403 from the SQL policy / payload guard
=====================  ===========================================================

No secret is passed in: callers hand over identifiers, statuses and a SHA-256 of
plan parameters (so the exact SQL approved is attributable without copying it into
the trail), and ``AuditLogger.log_event`` redacts credential-shaped keys and values
regardless.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from fastapi import HTTPException

from neuralbridge.ai.entitlements import Principal, scope_for
from neuralbridge.ai.guard import enforce_write_gate
from neuralbridge.security.audit import AuditLogger, AuditUnavailableError


def params_digest(params: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON of plan parameters."""
    blob = json.dumps(params, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(blob.encode()).hexdigest()


async def record(
    audit: AuditLogger,
    *,
    event_type: str,
    actor: str,
    owner: str | None,
    resource: str,
    action: str,
    result: str,
    details: dict[str, Any] | None = None,
    quiet: bool = False,
) -> None:
    """Write one event. ``quiet=True`` is for *refusals* (nothing happened, so a
    broken sink must not change the answer the caller gets); every other event
    propagates :class:`AuditUnavailableError` so the request fails loudly (503)."""
    body: dict[str, Any] = dict(details or {})
    if owner:
        body["owner"] = owner
    try:
        await audit.log_event(
            event_type=event_type, actor=actor, resource=resource, action=action,
            result=result, details=body,
        )
    except AuditUnavailableError:
        if not quiet:
            raise


async def gate_with_audit(
    audit: AuditLogger,
    *,
    surface: str,
    actor: str,
    adapter_type: str,
    operation: str,
    params: dict[str, Any],
    principal: Principal,
) -> None:
    """``enforce_write_gate`` that records a refusal (402 -> ``entitlement_denied``,
    403 -> ``policy_denied``) with actor and tenant before re-raising it unchanged."""
    try:
        await enforce_write_gate(adapter_type, operation, params, principal)
    except HTTPException as exc:
        if exc.status_code in (402, 403):
            await record(
                audit,
                event_type="entitlement_denied" if exc.status_code == 402 else "policy_denied",
                actor=actor,
                owner=scope_for(principal).owner,
                resource=adapter_type,
                action=operation,
                result="denied",
                details={"surface": surface, "status_code": exc.status_code, "tier": principal.tier},
                quiet=True,
            )
        raise
