"""NeuralBridge AI — REST surface for /ai.

Implements the plan → approve → execute → verify loop from
``neuralbridge.ai.orchestrator`` over HTTP. Every route requires a real
actor (see ``neuralbridge.ai.identity``) for the audit trail. Discovery and
READ are free (READ rate-limited on the free tier); WRITE (plan/approve),
binding an additional connection, and the account's audit log require the
Register/Cell entitlement (``neuralbridge.ai.entitlements`` — reusing the
assurance product's own API-key/account mechanism) and return **402**, not
403, when the caller is authenticated but under-tiered — same shape as
every other paid gate in this codebase (``assurance.api.deps``).

**Tenant isolation.** Every connection, plan and audit entry is owned by the
account that created it; the owner comes only from the validated API key
(``neuralbridge.ai.entitlements.scope_for``), never from a header or body
field. A caller sees and uses its own records plus the shared seeded demo
connection (READ); another account's id is a plain 404, identical to a
missing id. The operator key keeps full access. Rules and rationale live in
``neuralbridge.ai.tenancy``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, SecretStr

from neuralbridge.ai import orchestrator
from neuralbridge.ai.audit_events import params_digest, record
from neuralbridge.ai.connections import (
    ConnectionLifecycleError,
    create_connection,
    delete_connection,
    list_connections,
    revoke_connection,
    rotate_connection,
)
from neuralbridge.ai.entitlements import (
    Principal,
    current_principal,
    get_accounts,
    require_ai_control_plane,
    scope_for,
    spend_ai_read,
)
from neuralbridge.ai.identity import Actor, get_current_actor
from neuralbridge.ai.orchestrator import OrchestratorError
from neuralbridge.ai.schemas import (
    ApprovalCard,
    Capability,
    ConnectionSummary,
    ExecutionReceipt,
    Plan,
    PlanRequest,
    QueryResultCard,
    ReadRequest,
)
from neuralbridge.ai.store import AiStore
from neuralbridge.ai.tenancy import Scope, can_see_audit_entry
from neuralbridge.api.dependencies import (
    get_adapter_registry,
    get_ai_store,
    get_audit_logger,
    get_request_router,
)
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger

router = APIRouter(prefix="/ai", tags=["AI"])


def _raise(exc: OrchestratorError) -> None:
    headers = {"Retry-After": str(exc.retry_after)} if exc.retry_after else None
    raise HTTPException(status_code=exc.status_code, detail=exc.detail, headers=headers) from exc


def _raise_lifecycle(exc: ConnectionLifecycleError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


async def _paid_principal(
    request: Request,
    principal: Principal = Depends(current_principal),
    actor: Actor = Depends(get_current_actor),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> Principal:
    """FastAPI dependency wrapping ``require_ai_control_plane`` — the one
    door every WRITE-shaped /ai route (and the raw adapters/MCP paths that
    share this policy) goes through. A refusal (402) is audited with the
    actor and tenant before it is re-raised."""
    try:
        return await require_ai_control_plane(principal)
    except HTTPException as exc:
        if exc.status_code == 402:
            await record(
                audit_logger, event_type="entitlement_denied", actor=actor.as_audit_string(),
                owner=scope_for(principal).owner, resource=request.url.path, action=request.method,
                result="denied", details={"surface": "ai_route", "tier": principal.tier}, quiet=True,
            )
        raise


async def _scope(principal: Principal = Depends(current_principal)) -> Scope:
    """Tenancy scope of the validated caller — the only source of ``owner``."""
    return scope_for(principal)


async def _paid_scope(principal: Principal = Depends(_paid_principal)) -> Scope:
    return scope_for(principal)


class BindConnectionRequest(BaseModel):
    name: str = Field(..., description="Human-readable connection name.")
    host: str
    port: int = 5432
    user: str
    #: Write-only. A ``SecretStr`` so it can never reach a log line, a repr or a
    #: validation-error echo; it is stored nowhere and returned nowhere.
    password: SecretStr
    database: str
    ssl_mode: str = "prefer"


class RotateConnectionRequest(BaseModel):
    """New credentials for an existing connection (same host/port/database)."""

    user: str
    password: SecretStr


@router.get("/session", summary="Resolve the current actor identity and entitlement")
async def session(
    actor: Actor = Depends(get_current_actor),
    principal: Principal = Depends(current_principal),
) -> dict[str, Any]:
    """Every subsequent call from this browser tab should reuse this session id
    (send it back as ``X-NB-Session``) so plans/approvals/audit stay attributable
    to one continuous actor rather than a fresh anonymous id per request."""
    return {
        "actor_id": actor.id,
        "session_id": actor.session_id,
        "kind": actor.kind,
        "tier": principal.tier,
        "ai_control_plane": principal.plan.ai_control_plane,
        "ai_reads_per_day": principal.plan.ai_reads_per_day,
    }


@router.get("/connections", summary="Real connections — never invented")
async def connections_route(
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_scope),
) -> list[ConnectionSummary]:
    """The caller's own connections plus the shared seeded demo (operator: all)."""
    return list_connections(registry, store, scope)


@router.post("/connections", summary="Bind an additional connection — Register/Cell")
async def bind_connection(
    request: BindConnectionRequest,
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_paid_scope),
    actor: Actor = Depends(get_current_actor),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> ConnectionSummary:
    await audit_logger.ensure_writable()  # no credential is accepted if the act cannot be recorded
    created = create_connection(
        registry, store, owner=scope.owner, name=request.name, host=request.host, port=request.port,
        user=request.user, password=request.password.get_secret_value(), database=request.database,
        ssl_mode=request.ssl_mode,
    )
    await record(
        audit_logger, event_type="connection_create", actor=actor.as_audit_string(), owner=scope.owner,
        resource=f"connection:{created.id}", action="create", result="success",
        details={"connection_id": created.id, "adapter_type": created.adapter_type, "name": created.name,
                 "host": request.host, "port": request.port, "database": request.database,
                 "ssl_mode": request.ssl_mode},
    )
    return ConnectionSummary(
        id=created.id, name=created.name, adapter_type=created.adapter_type,
        status=created.status, source=created.source,
    )


@router.post("/connections/{connection_id}/rotate", summary="Replace a connection's credentials")
async def rotate(
    connection_id: str,
    request: RotateConnectionRequest,
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_scope),
    actor: Actor = Depends(get_current_actor),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> ConnectionSummary:
    """Owner-only and, like unbind, **not** behind the paid gate (a lapsed account can still
    take a credential out of service). The new credentials are verified against the target
    before the live adapter is swapped; on failure the old ones keep working. Write-only: the
    password is in no response, log line or audit record. 404 for a missing or foreign id,
    409 if revoked, 422 if the target rejects the credentials."""
    await audit_logger.ensure_writable()
    result, summary = "success", None
    try:
        rotated = await rotate_connection(
            registry, store, scope, connection_id, user=request.user,
            password=request.password.get_secret_value(),
        )
        summary = ConnectionSummary(
            id=rotated.id, name=rotated.name, adapter_type=rotated.adapter_type,
            status=rotated.status, source=rotated.source,
        )
    except ConnectionLifecycleError as exc:
        result = f"refused:{exc.status_code}"
        await record(
            audit_logger, event_type="connection_rotate", actor=actor.as_audit_string(), owner=scope.owner,
            resource=f"connection:{connection_id}", action="rotate", result=result,
            details={"connection_id": connection_id},
        )
        _raise_lifecycle(exc)
    await record(
        audit_logger, event_type="connection_rotate", actor=actor.as_audit_string(), owner=scope.owner,
        resource=f"connection:{connection_id}", action="rotate", result=result,
        details={"connection_id": connection_id},
    )
    assert summary is not None
    return summary


@router.post("/connections/{connection_id}/revoke", summary="Revoke a connection (permanent)")
async def revoke(
    connection_id: str,
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_scope),
    actor: Actor = Depends(get_current_actor),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> dict[str, Any]:
    """Owner-only, not paid-gated. Takes effect on the very next call from any worker:
    reads, plans and approvals against the connection answer 409, and plans still pending on
    it are denied. Idempotent. 404 for a missing or foreign id."""
    await audit_logger.ensure_writable()
    try:
        changed = await revoke_connection(
            registry, store, scope, connection_id, by=actor.as_audit_string())
    except ConnectionLifecycleError as exc:
        await record(
            audit_logger, event_type="connection_revoke", actor=actor.as_audit_string(), owner=scope.owner,
            resource=f"connection:{connection_id}", action="revoke", result=f"refused:{exc.status_code}",
            details={"connection_id": connection_id},
        )
        _raise_lifecycle(exc)
    await record(
        audit_logger, event_type="connection_revoke", actor=actor.as_audit_string(), owner=scope.owner,
        resource=f"connection:{connection_id}", action="revoke",
        result="success" if changed else "already_revoked", details={"connection_id": connection_id},
    )
    return {"revoked": connection_id, "already_revoked": not changed}


@router.delete("/connections/{connection_id}", summary="Unbind one of your connections")
async def unbind_connection(
    connection_id: str,
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_scope),
    actor: Actor = Depends(get_current_actor),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> dict[str, str]:
    """Owner-only, and deliberately **not** behind the paid gate: removing a
    connection shrinks exposure, so an account whose plan lapsed can still
    unbind what it bound. Someone else's id, a missing id, the shared seeded
    demo (for non-operators) and any anonymous caller all answer the same 404."""
    await audit_logger.ensure_writable()
    deleted = await delete_connection(registry, store, scope, connection_id)
    await record(
        audit_logger, event_type="connection_delete", actor=actor.as_audit_string(), owner=scope.owner,
        resource=f"connection:{connection_id}", action="delete", result="success" if deleted else "refused:404",
        details={"connection_id": connection_id},
    )
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Connection '{connection_id}' not found.")
    return {"deleted": connection_id}


@router.get("/capabilities", summary="What this agent can do against one connection")
async def capabilities(
    connection_id: str,
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_scope),
) -> list[Capability]:
    try:
        return orchestrator.list_capabilities(store, scope, connection_id)
    except OrchestratorError as exc:
        _raise(exc)
        raise  # unreachable, satisfies type checkers


@router.post("/read", summary="Execute a READ operation immediately (free, rate-limited)")
async def read(
    request: ReadRequest,
    actor: Actor = Depends(get_current_actor),
    principal: Principal = Depends(current_principal),
    request_router: RequestRouter = Depends(get_request_router),
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
) -> QueryResultCard:
    spend_ai_read(principal, get_accounts())
    try:
        return await orchestrator.read(
            request_router, registry, scope_for(principal), actor, store,
            request.connection_id, request.operation, request.params,
        )
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan", summary="Propose a WRITE/DESTRUCTIVE operation — Register/Cell, never executes it")
async def plan(
    request: PlanRequest,
    actor: Actor = Depends(get_current_actor),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_paid_scope),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> ApprovalCard:
    await audit_logger.ensure_writable()
    base = {"connection_id": request.connection_id, "operation": request.operation,
            "params_sha256": params_digest(request.params)}
    try:
        card = orchestrator.create_plan(store, scope, actor, request.connection_id, request.operation, request.params)
    except OrchestratorError as exc:
        await record(
            audit_logger, event_type="plan_propose", actor=actor.as_audit_string(), owner=scope.owner,
            resource=f"connection:{request.connection_id}", action="propose",
            result=f"refused:{exc.status_code}", details=base, quiet=True,
        )
        _raise(exc)
        raise
    await record(
        audit_logger, event_type="plan_propose", actor=actor.as_audit_string(), owner=scope.owner,
        resource=f"plan:{card.plan.id}", action="propose", result="success",
        details={**base, "plan_id": card.plan.id, "operation_class": card.plan.operation_class.value},
    )
    return card


@router.get("/plan/{plan_id}", summary="Inspect a plan's current status")
async def get_plan(
    plan_id: str, store: AiStore = Depends(get_ai_store), scope: Scope = Depends(_scope)
) -> Plan:
    try:
        return orchestrator.get_plan(store, scope, plan_id)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan/{plan_id}/approve", summary="Approve a pending plan and execute it — Register/Cell")
async def approve(
    plan_id: str,
    actor: Actor = Depends(get_current_actor),
    request_router: RequestRouter = Depends(get_request_router),
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_paid_scope),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> ExecutionReceipt:
    await audit_logger.ensure_writable()
    who, ref = actor.as_audit_string(), f"plan:{plan_id}"
    try:
        receipt = await orchestrator.approve_and_execute(request_router, registry, store, scope, actor, plan_id)
    except OrchestratorError as exc:
        # Distinguish "refused before anything ran" (plan still pending, or never ours) from
        # "approved, then the execution failed" (plan is `failed`; outcome unknown).
        after = store.get_plan(plan_id)
        failed = after is not None and after.status == "failed"
        await record(
            audit_logger, event_type="plan_execute" if failed else "plan_approve", actor=who, owner=scope.owner,
            resource=ref, action="execute" if failed else "approve",
            result=f"failure:{exc.status_code}" if failed else f"refused:{exc.status_code}",
            details={"plan_id": plan_id}, quiet=not failed,
        )
        _raise(exc)
        raise
    await record(
        audit_logger, event_type="plan_approve", actor=who, owner=scope.owner, resource=ref, action="approve",
        result="success", details={"plan_id": plan_id, "connection_id": receipt.provenance.connection_id},
    )
    await record(
        audit_logger, event_type="plan_execute", actor=who, owner=scope.owner, resource=ref, action="execute",
        result="success" if receipt.success else "failure",
        details={"plan_id": plan_id, "connection_id": receipt.provenance.connection_id,
                 "request_id": receipt.provenance.request_id},
    )
    return receipt


@router.post("/plan/{plan_id}/deny", summary="Deny a pending plan — Register/Cell, nothing executes")
async def deny(
    plan_id: str,
    reason: str = "denied by operator",
    actor: Actor = Depends(get_current_actor),
    store: AiStore = Depends(get_ai_store),
    scope: Scope = Depends(_paid_scope),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> Plan:
    await audit_logger.ensure_writable()
    try:
        denied = orchestrator.deny_plan(store, scope, actor, plan_id, reason)
    except OrchestratorError as exc:
        await record(
            audit_logger, event_type="plan_deny", actor=actor.as_audit_string(), owner=scope.owner,
            resource=f"plan:{plan_id}", action="deny", result=f"refused:{exc.status_code}",
            details={"plan_id": plan_id}, quiet=True,
        )
        _raise(exc)
        raise
    await record(
        audit_logger, event_type="plan_deny", actor=actor.as_audit_string(), owner=scope.owner,
        resource=f"plan:{plan_id}", action="deny", result="success",
        details={"plan_id": plan_id, "reason": reason},
    )
    return denied


#: Free callers can still see *their own* recent activity — just not the
#: full trail. Matches the commercial map's "limited or 402 (pick one,
#: document)" instruction for the free tier: picked "limited."
_FREE_AUDIT_LIMIT = 3


@router.get("/audit", summary="Recent audit events for your account (limited on the free tier)")
async def audit(
    limit: int = Query(25, ge=1, le=500, description="Max entries (1-500)."),
    principal: Principal = Depends(current_principal),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> list[dict[str, Any]]:
    """Only entries stamped with the caller's own account (``details.owner``,
    set server-side from the validated principal). Entries with no owner
    (written before tenancy, or by non-/ai callers) are operator-only; the
    operator sees everything. The trail is durable (SQLite by default,
    ``api/dependencies.get_audit_logger``) and shared by every worker process;
    newest first."""
    scope = scope_for(principal)
    effective_limit = limit if principal.plan.ai_control_plane else min(limit, _FREE_AUDIT_LIMIT)
    events = []
    async for entry in audit_logger.query_events(
        owner=None if scope.is_operator else scope.owner, limit=effective_limit, newest_first=True,
    ):
        if not can_see_audit_entry(scope, entry.details.get("owner")):
            continue
        events.append(entry.model_dump(mode="json"))
    return events[:effective_limit]
