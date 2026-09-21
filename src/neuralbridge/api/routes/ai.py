"""NeuralBridge AI — REST surface for /ai.

Implements the plan → approve → execute → verify loop from
``neuralbridge.ai.orchestrator`` over HTTP. Every route requires a real
actor (see ``neuralbridge.ai.identity``) for the audit trail. Discovery and
READ are free (READ rate-limited on the free tier); WRITE (plan/approve),
binding an additional connection, and the full audit trail require the
Register/Cell entitlement (``neuralbridge.ai.entitlements`` — reusing the
assurance product's own API-key/account mechanism) and return **402**, not
403, when the caller is authenticated but under-tiered — same shape as
every other paid gate in this codebase (``assurance.api.deps``).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from neuralbridge.ai import orchestrator
from neuralbridge.ai.connections import create_connection, list_connections
from neuralbridge.ai.entitlements import (
    Principal,
    current_principal,
    get_accounts,
    require_ai_control_plane,
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
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


async def _paid_principal(principal: Principal = Depends(current_principal)) -> Principal:
    """FastAPI dependency wrapping ``require_ai_control_plane`` — the one
    door every WRITE-shaped /ai route (and the raw adapters/MCP paths that
    share this policy) goes through."""
    return await require_ai_control_plane(principal)


class BindConnectionRequest(BaseModel):
    name: str = Field(..., description="Human-readable connection name.")
    host: str
    port: int = 5432
    user: str
    password: str
    database: str
    ssl_mode: str = "prefer"


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
) -> list[ConnectionSummary]:
    return list_connections(registry, store)


@router.post("/connections", summary="Bind an additional connection — Register/Cell")
async def bind_connection(
    request: BindConnectionRequest,
    registry: AdapterRegistry = Depends(get_adapter_registry),
    store: AiStore = Depends(get_ai_store),
    _paid: Principal = Depends(_paid_principal),
) -> ConnectionSummary:
    record = create_connection(
        registry, store, name=request.name, host=request.host, port=request.port,
        user=request.user, password=request.password, database=request.database,
        ssl_mode=request.ssl_mode,
    )
    return ConnectionSummary(
        id=record.id, name=record.name, adapter_type=record.adapter_type,
        status=record.status, source=record.source,
    )


@router.get("/capabilities", summary="What this agent can do against one connection")
async def capabilities(
    connection_id: str,
    store: AiStore = Depends(get_ai_store),
) -> list[Capability]:
    try:
        return orchestrator.list_capabilities(store, connection_id)
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
            request_router, registry, actor, store, request.connection_id, request.operation, request.params
        )
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan", summary="Propose a WRITE/DESTRUCTIVE operation — Register/Cell, never executes it")
async def plan(
    request: PlanRequest,
    actor: Actor = Depends(get_current_actor),
    store: AiStore = Depends(get_ai_store),
    _paid: Principal = Depends(_paid_principal),
) -> ApprovalCard:
    try:
        return orchestrator.create_plan(store, actor, request.connection_id, request.operation, request.params)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.get("/plan/{plan_id}", summary="Inspect a plan's current status")
async def get_plan(plan_id: str, store: AiStore = Depends(get_ai_store)) -> Plan:
    try:
        return orchestrator.get_plan(store, plan_id)
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
    _paid: Principal = Depends(_paid_principal),
) -> ExecutionReceipt:
    try:
        return await orchestrator.approve_and_execute(request_router, registry, store, actor, plan_id)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan/{plan_id}/deny", summary="Deny a pending plan — Register/Cell, nothing executes")
async def deny(
    plan_id: str,
    reason: str = "denied by operator",
    actor: Actor = Depends(get_current_actor),
    store: AiStore = Depends(get_ai_store),
    _paid: Principal = Depends(_paid_principal),
) -> Plan:
    try:
        return orchestrator.deny_plan(store, actor, plan_id, reason)
    except OrchestratorError as exc:
        _raise(exc)
        raise


#: Free callers can still see *their own* recent activity — just not the
#: full trail. Matches the commercial map's "limited or 402 (pick one,
#: document)" instruction for the free tier: picked "limited."
_FREE_AUDIT_LIMIT = 3


@router.get("/audit", summary="Recent audit events for this actor (limited on the free tier)")
async def audit(
    limit: int = 25,
    actor: Actor = Depends(get_current_actor),
    principal: Principal = Depends(current_principal),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> list[dict[str, Any]]:
    effective_limit = limit if principal.plan.ai_control_plane else min(limit, _FREE_AUDIT_LIMIT)
    events = []
    async for entry in audit_logger.query_events(actor=actor.as_audit_string()):
        events.append(entry.model_dump(mode="json"))
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:effective_limit]
