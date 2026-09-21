"""The plan → approve → execute → verify loop for /ai.

Plans and connections are durable (``neuralbridge.ai.store.AiStore``,
SQLite) — a restart keeps pending/approved/denied plans and every
connection record. This module is deliberately principal/billing-agnostic:
entitlement (who is allowed to call which of these functions) is decided
one layer up, in ``api/routes/ai.py`` and the shared raw-path guards in
``api/routes/adapters.py`` / ``core/gateway.py`` — see
``neuralbridge.ai.entitlements``. That keeps exactly one place that knows
about plans/pricing (``assurance.billing.plans``) and one place that knows
about the operation loop (here), rather than tangling the two.
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
from neuralbridge.ai.store import AiStore, ConnectionRecord, PlanRecord, new_id
from neuralbridge.core.router import AdapterRegistry, RequestRouter

_POSTGRES_CAPABILITIES: list[tuple[str, OperationClass, str]] = [
    ("health_check", OperationClass.READ, "Check the connection is reachable and report the server version."),
    ("list_tables", OperationClass.READ, "List tables in the connected database."),
    ("describe_table", OperationClass.READ, "Show columns and types for one table."),
    ("query", OperationClass.READ, "Run a SELECT statement and return rows."),
    ("execute_sql", OperationClass.WRITE, "Run an INSERT/UPDATE/DELETE/DDL statement — requires approval and Register/Cell."),
]


class OrchestratorError(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


def _plan_to_schema(record: PlanRecord) -> Plan:
    return Plan(
        id=record.id,
        connection_id=record.connection_id,
        adapter_type=record.adapter_type,
        operation=record.operation,
        operation_class=OperationClass(record.operation_class),
        params=record.params,
        proposed_by=record.proposed_by,
        status=PlanStatus(record.status),
        created_at=datetime.fromisoformat(record.created_at),
        decided_by=record.decided_by,
        decided_at=datetime.fromisoformat(record.decided_at) if record.decided_at else None,
        deny_reason=record.deny_reason,
    )


def _require_live_adapter(registry: AdapterRegistry, conn: ConnectionRecord) -> None:
    """A connection record can outlive its adapter instance across a
    restart when its credentials are not persisted (see
    ``connections.create_connection`` — additional, operator-bound
    connections never have their password stored). The seeded demo
    connection re-registers itself from env on first use after a restart
    (``connections.ensure_seeded_connection``); any other connection in
    that state needs the operator to bind it again with fresh credentials
    — an honest 409, not a confusing adapter-not-found 500."""
    if conn.registry_key not in registry:
        raise OrchestratorError(
            409,
            f"Connection '{conn.id}' has no live adapter (likely after a restart — "
            "credentials are never persisted). Re-bind it with POST /ai/connections.",
        )


def list_capabilities(store: AiStore, connection_id: str) -> list[Capability]:
    conn = store.get_connection(connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{connection_id}' not found.")
    if conn.adapter_type != "postgres":
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


def _build_provenance(conn: ConnectionRecord, operation: str, response: AdapterResponse) -> Provenance:
    return Provenance(
        connection_id=conn.id,
        connection_name=conn.name,
        adapter_type=conn.adapter_type,
        tool=operation,
        request_id=response.request_id,
        timestamp=response.timestamp,
        mocked=bool(response.metadata.get("mock")),
    )


async def _run(
    router: RequestRouter, actor: Actor, conn: ConnectionRecord, operation: str, params: dict[str, Any]
) -> tuple[AdapterResponse, Provenance]:
    result = await router.route(
        adapter_type=conn.registry_key,
        operation=operation,
        params=params,
        request_id=str(uuid.uuid4()),
        actor=actor.as_audit_string(),
    )
    response: AdapterResponse = result["data"]
    provenance = _build_provenance(conn, operation, response)
    return response, provenance


async def read(
    router: RequestRouter, registry: AdapterRegistry, actor: Actor, store: AiStore,
    connection_id: str, operation: str, params: dict[str, Any],
) -> QueryResultCard:
    """Execute a READ immediately. Refuses anything that isn't a READ."""
    conn = store.get_connection(connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{connection_id}' not found.")

    try:
        decision = evaluate(conn.adapter_type, operation, params)
    except PolicyError as exc:
        raise OrchestratorError(403, exc.reason) from exc

    if decision.requires_approval:
        raise OrchestratorError(
            400,
            f"'{operation}' is a {decision.operation_class.value} operation and requires approval — "
            "use POST /ai/plan, not /ai/read.",
        )

    _require_live_adapter(registry, conn)
    response, provenance = await _run(router, actor, conn, operation, params)
    return QueryResultCard(success=response.success, data=response.data, error=response.error, provenance=provenance)


def create_plan(store: AiStore, actor: Actor, connection_id: str, operation: str, params: dict[str, Any]) -> ApprovalCard:
    """Propose a WRITE/DESTRUCTIVE operation. Never executes it. Paid-gated
    by the caller (``api/routes/ai.py``) before this is reached."""
    conn = store.get_connection(connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{connection_id}' not found.")

    try:
        decision = evaluate(conn.adapter_type, operation, params)
    except PolicyError as exc:
        raise OrchestratorError(403, exc.reason) from exc

    if not decision.requires_approval:
        raise OrchestratorError(
            400,
            f"'{operation}' is read-only — call POST /ai/read directly instead of planning it.",
        )

    record = PlanRecord(
        id=new_id(),
        connection_id=connection_id,
        adapter_type=conn.adapter_type,
        operation=operation,
        operation_class=decision.operation_class.value,
        params=params,
        proposed_by=actor.as_audit_string(),
    )
    store.create_plan(record)
    return ApprovalCard(plan=_plan_to_schema(record), risk_note=decision.risk_note)


def get_plan(store: AiStore, plan_id: str) -> Plan:
    record = store.get_plan(plan_id)
    if record is None:
        raise OrchestratorError(404, f"Plan '{plan_id}' not found.")
    return _plan_to_schema(record)


def deny_plan(store: AiStore, actor: Actor, plan_id: str, reason: str) -> Plan:
    record = store.get_plan(plan_id)
    if record is None:
        raise OrchestratorError(404, f"Plan '{plan_id}' not found.")
    if record.status != PlanStatus.PENDING_APPROVAL.value:
        raise OrchestratorError(409, f"Plan '{plan_id}' is '{record.status}', not pending approval.")
    updated = store.update_plan_status(
        plan_id, status=PlanStatus.DENIED.value, decided_by=actor.as_audit_string(),
        decided_at=datetime.now(UTC).isoformat(), deny_reason=reason,
    )
    return _plan_to_schema(updated)


async def approve_and_execute(
    router: RequestRouter, registry: AdapterRegistry, store: AiStore, actor: Actor, plan_id: str
) -> ExecutionReceipt:
    """Approve a pending plan and execute it in the same call — the only
    path to a WRITE running. Paid-gated by the caller before this is
    reached."""
    record = store.get_plan(plan_id)
    if record is None:
        raise OrchestratorError(404, f"Plan '{plan_id}' not found.")
    if record.status != PlanStatus.PENDING_APPROVAL.value:
        raise OrchestratorError(409, f"Plan '{plan_id}' is '{record.status}', not pending approval.")

    conn = store.get_connection(record.connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{record.connection_id}' backing this plan no longer exists.")
    _require_live_adapter(registry, conn)

    store.update_plan_status(
        plan_id, status=PlanStatus.APPROVED.value, decided_by=actor.as_audit_string(),
        decided_at=datetime.now(UTC).isoformat(),
    )

    try:
        response, provenance = await _run(router, actor, conn, record.operation, record.params)
    except Exception as exc:
        store.update_plan_status(plan_id, status=PlanStatus.FAILED.value)
        raise OrchestratorError(502, f"Execution failed: {exc}") from exc

    updated = store.update_plan_status(plan_id, status=PlanStatus.EXECUTED.value)
    return ExecutionReceipt(
        plan_id=updated.id,
        success=response.success,
        data=response.data,
        error=response.error,
        provenance=provenance,
        approved_by=updated.decided_by or actor.as_audit_string(),
        executed_at=datetime.now(UTC),
    )


def list_plans(store: AiStore, *, limit: int = 50) -> list[Plan]:
    return [_plan_to_schema(r) for r in store.list_plans(limit=limit)]
