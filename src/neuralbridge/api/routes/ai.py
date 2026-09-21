"""NeuralBridge AI — REST surface for /ai.

Implements the plan → approve → execute → verify loop from
``neuralbridge.ai.orchestrator`` over HTTP. Every route requires a real
actor (see ``neuralbridge.ai.identity``) and every write goes through an
explicit approval step — there is no endpoint that both proposes and
executes a WRITE in one call.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from neuralbridge.ai import orchestrator
from neuralbridge.ai.connections import list_connections
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
from neuralbridge.api.dependencies import get_adapter_registry, get_audit_logger, get_request_router
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger

router = APIRouter(prefix="/ai", tags=["AI"])


def _raise(exc: OrchestratorError) -> None:
    raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc


@router.get("/session", summary="Resolve the current actor identity")
async def session(actor: Actor = Depends(get_current_actor)) -> dict[str, str]:
    """Every subsequent call from this browser tab should reuse this session id
    (send it back as ``X-NB-Session``) so plans/approvals/audit stay attributable
    to one continuous actor rather than a fresh anonymous id per request."""
    return {"actor_id": actor.id, "session_id": actor.session_id, "kind": actor.kind}


@router.get("/connections", summary="Real connections — never invented")
async def connections_route(
    registry: AdapterRegistry = Depends(get_adapter_registry),
) -> list[ConnectionSummary]:
    return list_connections(registry)


@router.get("/capabilities", summary="What this agent can do against one connection")
async def capabilities(connection_id: str) -> list[Capability]:
    try:
        return orchestrator.list_capabilities(connection_id)
    except OrchestratorError as exc:
        _raise(exc)
        raise  # unreachable, satisfies type checkers


@router.post("/read", summary="Execute a READ operation immediately")
async def read(
    request: ReadRequest,
    actor: Actor = Depends(get_current_actor),
    request_router: RequestRouter = Depends(get_request_router),
) -> QueryResultCard:
    try:
        return await orchestrator.read(
            request_router, actor, request.connection_id, request.operation, request.params
        )
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan", summary="Propose a WRITE/DESTRUCTIVE operation — never executes it")
async def plan(
    request: PlanRequest,
    actor: Actor = Depends(get_current_actor),
) -> ApprovalCard:
    try:
        return orchestrator.create_plan(actor, request.connection_id, request.operation, request.params)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.get("/plan/{plan_id}", summary="Inspect a plan's current status")
async def get_plan(plan_id: str) -> Plan:
    try:
        return orchestrator.get_plan(plan_id)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan/{plan_id}/approve", summary="Approve a pending plan and execute it")
async def approve(
    plan_id: str,
    actor: Actor = Depends(get_current_actor),
    request_router: RequestRouter = Depends(get_request_router),
) -> ExecutionReceipt:
    try:
        return await orchestrator.approve_and_execute(request_router, actor, plan_id)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.post("/plan/{plan_id}/deny", summary="Deny a pending plan — nothing executes")
async def deny(
    plan_id: str,
    reason: str = "denied by operator",
    actor: Actor = Depends(get_current_actor),
) -> Plan:
    try:
        return orchestrator.deny_plan(actor, plan_id, reason)
    except OrchestratorError as exc:
        _raise(exc)
        raise


@router.get("/audit", summary="Recent audit events for this actor")
async def audit(
    limit: int = 25,
    actor: Actor = Depends(get_current_actor),
    audit_logger: AuditLogger = Depends(get_audit_logger),
) -> list[dict[str, Any]]:
    """Scoped to the calling actor by default — this is provenance for
    *this* operator's own session, not a general audit browser."""
    events = []
    async for entry in audit_logger.query_events(actor=actor.as_audit_string()):
        events.append(entry.model_dump(mode="json"))
    events.sort(key=lambda e: e["timestamp"], reverse=True)
    return events[:limit]
