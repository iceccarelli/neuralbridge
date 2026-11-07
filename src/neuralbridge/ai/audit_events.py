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
import time
from typing import Any

from fastapi import HTTPException

from neuralbridge.ai.entitlements import Principal, scope_for
from neuralbridge.ai.guard import enforce_write_gate
from neuralbridge.security.audit import (
    MAX_FIELD_CHARS,
    AuditLogger,
    AuditUnavailableError,
    bound_text,
)

#: A refusal writes an append-only row for something that did not happen, and the 402/403 gates are
#: reachable without a key, so refusals are rate limited per tenant (``anonymous`` is one shared
#: tenant) *before* the write. Authorized events (``quiet=False``) never go through this limiter.
#: What is dropped is counted, and the count rides on the next refusal that is written, so the
#: suppression is itself visible in the trail.
REFUSAL_BURST = 30
REFUSAL_REFILL_PER_S = 0.2  # 12 per minute per tenant once the burst is spent
GLOBAL_REFUSAL_BURST = 100
GLOBAL_REFUSAL_REFILL_PER_S = 0.5  # 30 per minute across all callers
_GLOBAL = "\x00global"
_MAX_BUCKETS = 4096
_DETAIL_STR_CHARS = 512
_buckets: dict[str, list[float]] = {}  # tenant -> [tokens, last_refill_monotonic, suppressed_since_last_write]
_suppressed_total = 0


def refusals_suppressed_total() -> int:
    """How many refusal events this process has declined to write (for /health/ready)."""
    return _suppressed_total


def reset_refusal_limiter() -> None:
    """Forget all buckets and counters (tests)."""
    global _suppressed_total
    _buckets.clear()
    _suppressed_total = 0


def _take(key: str, burst: int, refill_per_s: float, now: float, *, consume: bool) -> bool:
    bucket = _buckets.get(key)
    if bucket is None:
        if len(_buckets) >= _MAX_BUCKETS:
            _buckets.pop(next(k for k in _buckets if k != _GLOBAL))
        bucket = _buckets[key] = [float(burst), now, 0.0]
    bucket[0] = min(float(burst), bucket[0] + (now - bucket[1]) * refill_per_s)
    bucket[1] = now
    if bucket[0] < 1.0:
        return False
    if consume:
        bucket[0] -= 1.0
    return True


def _admit_refusal(tenant: str) -> int | None:
    """``None``: drop this refusal. Otherwise the number of refusals dropped since the last written one.

    Two buckets must both have a token: the tenant's, and one shared by every caller (an anonymous
    caller's tenant key can be chosen by the caller, e.g. the MCP gateway's ``actor`` argument, so
    the per-tenant bucket alone would not bound an attacker)."""
    global _suppressed_total
    now = time.monotonic()
    ok = (_take(tenant, REFUSAL_BURST, REFUSAL_REFILL_PER_S, now, consume=False)
          and _take(_GLOBAL, GLOBAL_REFUSAL_BURST, GLOBAL_REFUSAL_REFILL_PER_S, now, consume=False))
    mine = _buckets[tenant]
    if not ok:
        mine[2] += 1
        _suppressed_total += 1
        return None
    mine[0] -= 1.0
    _buckets[_GLOBAL][0] -= 1.0
    dropped, mine[2] = int(mine[2]), 0.0
    return dropped


def _bound_details(value: Any) -> Any:
    if isinstance(value, str):
        return bound_text(value, _DETAIL_STR_CHARS)
    if isinstance(value, dict):
        return {str(k): _bound_details(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_bound_details(v) for v in value[:64]]
    return value


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
    body: dict[str, Any] = _bound_details(dict(details or {}))
    if owner:
        body["owner"] = bound_text(owner, 128)
    if quiet:
        dropped = _admit_refusal(bound_text(owner, 128) if owner else "anonymous")
        if dropped is None:
            return
        if dropped:
            body["suppressed_since_last"] = dropped
    actor, resource, action = (bound_text(x, MAX_FIELD_CHARS) for x in (actor, resource, action))
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


async def gate_validate_with_audit(
    audit: AuditLogger, *, surface: str, actor: str, adapter_type: str, principal: Principal,
) -> None:
    """``enforce_validate_gate`` that records a 402 as ``entitlement_denied`` (rate limited like every refusal)."""
    from neuralbridge.ai.guard import enforce_validate_gate

    try:
        await enforce_validate_gate(adapter_type, principal)
    except HTTPException as exc:
        if exc.status_code == 402:
            await record(
                audit, event_type="entitlement_denied", actor=actor, owner=scope_for(principal).owner,
                resource=adapter_type, action="validate", result="denied",
                details={"surface": surface, "status_code": 402, "tier": principal.tier}, quiet=True,
            )
        raise
