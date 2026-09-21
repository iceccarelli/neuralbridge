"""The plan → approve → execute → verify loop for /ai.

State (plans) lives in an in-process dict, same honesty tradeoff as the
existing ``connections`` store this slice reuses — not durable across a
restart, documented rather than disguised. A production follow-up should
back this with the same kind of persistent store the assurance product
uses for its evidence ledger; that is explicitly out of scope here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from neuralbridge.adapters.base import AdapterResponse
from neuralbridge.ai.identity import Actor
from neuralbridge.ai.policy import PolicyError, evaluate
from neuralbridge.ai.schemas import (
    ApprovalCard,
    Capability,
    ExecutionReceipt,
    OperationClass,
    Plan,
    PlanStatus,
    Provenance,
    QueryResultCard,
)
from neuralbridge.core.router import RequestRouter

from . import connections as ai_connections

#: Plan store — in-memory, single-process, documented (see module docstring).
_plans: dict[str, Plan] = {}

_POSTGRES_CAPABILITIES: list[tuple[str, OperationClass, str]] = [
    ("health_check", OperationClass.READ, "Check the connection is reachable and report the server version."),
    ("list_tables", OperationClass.READ, "List tables in the connected database."),
    ("describe_table", OperationClass.READ, "Show columns and types for one table."),
    ("query", OperationClass.READ, "Run a SELECT statement and return rows."),
    ("execute_sql", OperationClass.WRITE, "Run an INSERT/UPDATE/DELETE/DDL statement — requires approval."),
]


class OrchestratorError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def list_capabilities(connection_id: str) -> list[Capability]:
    conn = ai_connections.get_connection(connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{connection_id}' not found.")
    if conn["adapter_type"] != "postgres":
        return []
    return [
        Capability(
            connection_id=connection_id,
            adapter_type="postgres",
            operation=op,
            operation_class=op_class,
            description=desc,
        )
        for op, op_class, desc in _POSTGRES_CAPABILITIES
    ]


def _build_provenance(conn: dict[str, Any], operation: str, response: AdapterResponse) -> Provenance:
    return Provenance(
        connection_id=conn["id"],
        connection_name=conn["name"],
        adapter_type=conn["adapter_type"],
        tool=operation,
        request_id=response.request_id,
        timestamp=response.timestamp,
        mocked=bool(response.metadata.get("mock")),
    )


async def _run(router: RequestRouter, actor: Actor, conn: dict[str, Any], operation: str, params: dict[str, Any]) -> tuple[AdapterResponse, Provenance]:
    result = await router.route(
        adapter_type=conn["adapter_type"],
        operation=operation,
        params=params,
        request_id=str(uuid.uuid4()),
        actor=actor.as_audit_string(),
    )
    response: AdapterResponse = result["data"]
    provenance = _build_provenance(conn, operation, response)
    return response, provenance


async def read(router: RequestRouter, actor: Actor, connection_id: str, operation: str, params: dict[str, Any]) -> QueryResultCard:
    """Execute a READ immediately. Refuses anything that isn't a READ."""
    conn = ai_connections.get_connection(connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{connection_id}' not found.")

    try:
        decision = evaluate(conn["adapter_type"], operation, params)
    except PolicyError as exc:
        raise OrchestratorError(403, exc.reason) from exc

    if decision.requires_approval:
        raise OrchestratorError(
            400,
            f"'{operation}' is a {decision.operation_class.value} operation and requires approval — "
            "use POST /ai/plan, not /ai/read.",
        )

    response, provenance = await _run(router, actor, conn, operation, params)
    return QueryResultCard(success=response.success, data=response.data, error=response.error, provenance=provenance)


def create_plan(actor: Actor, connection_id: str, operation: str, params: dict[str, Any]) -> ApprovalCard:
    """Propose a WRITE/DESTRUCTIVE operation. Never executes it."""
    conn = ai_connections.get_connection(connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{connection_id}' not found.")

    try:
        decision = evaluate(conn["adapter_type"], operation, params)
    except PolicyError as exc:
        raise OrchestratorError(403, exc.reason) from exc

    if not decision.requires_approval:
        raise OrchestratorError(
            400,
            f"'{operation}' is read-only — call POST /ai/read directly instead of planning it.",
        )

    plan = Plan(
        connection_id=connection_id,
        adapter_type=conn["adapter_type"],
        operation=operation,
        operation_class=decision.operation_class,
        params=params,
        proposed_by=actor.as_audit_string(),
    )
    _plans[plan.id] = plan
    return ApprovalCard(plan=plan, risk_note=decision.risk_note)


def get_plan(plan_id: str) -> Plan:
    plan = _plans.get(plan_id)
    if plan is None:
        raise OrchestratorError(404, f"Plan '{plan_id}' not found.")
    return plan


def deny_plan(actor: Actor, plan_id: str, reason: str) -> Plan:
    plan = get_plan(plan_id)
    if plan.status != PlanStatus.PENDING_APPROVAL:
        raise OrchestratorError(409, f"Plan '{plan_id}' is '{plan.status.value}', not pending approval.")
    plan.status = PlanStatus.DENIED
    plan.decided_by = actor.as_audit_string()
    plan.decided_at = datetime.now(UTC)
    plan.deny_reason = reason
    return plan


async def approve_and_execute(router: RequestRouter, actor: Actor, plan_id: str) -> ExecutionReceipt:
    """Approve a pending plan and execute it in the same call — the only path to a WRITE running."""
    plan = get_plan(plan_id)
    if plan.status != PlanStatus.PENDING_APPROVAL:
        raise OrchestratorError(409, f"Plan '{plan_id}' is '{plan.status.value}', not pending approval.")

    conn = ai_connections.get_connection(plan.connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{plan.connection_id}' backing this plan no longer exists.")

    plan.status = PlanStatus.APPROVED
    plan.decided_by = actor.as_audit_string()
    plan.decided_at = datetime.now(UTC)

    try:
        response, provenance = await _run(router, actor, conn, plan.operation, plan.params)
    except Exception as exc:
        plan.status = PlanStatus.FAILED
        raise OrchestratorError(502, f"Execution failed: {exc}") from exc

    plan.status = PlanStatus.EXECUTED
    return ExecutionReceipt(
        plan_id=plan.id,
        success=response.success,
        data=response.data,
        error=response.error,
        provenance=provenance,
        approved_by=plan.decided_by,
        executed_at=datetime.now(UTC),
    )
