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

import structlog

from neuralbridge.adapters.base import AdapterResponse
from neuralbridge.ai.approval import (
    CallerRef,
    effective_policy,
    expiry_for,
    independence_problem,
    is_expired,
    named_operator_problem,
)
from neuralbridge.ai.connections import SEEDED_REGISTRY_KEY, register_seeded_adapter
from neuralbridge.ai.credentials import CustodyError, vault_for
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
from neuralbridge.ai.store import REVOKED, AiStore, ConnectionRecord, PlanRecord, new_id
from neuralbridge.ai.tenancy import (
    Scope,
    can_access_plan,
    can_plan_on_connection,
    can_read_connection,
    is_demo,
)
from neuralbridge.core.router import (
    AdapterRegistry,
    AdapterTimeoutError,
    AuditPreflightError,
    RequestRouter,
)
from neuralbridge.security.audit import AuditUnavailableError
from neuralbridge.security.limits import ResourceLimitError

logger = structlog.get_logger(__name__)

_POSTGRES_CAPABILITIES: list[tuple[str, OperationClass, str]] = [
    ("health_check", OperationClass.READ, "Check the connection is reachable and report the server version."),
    ("list_tables", OperationClass.READ, "List tables in the connected database."),
    ("describe_table", OperationClass.READ, "Show columns and types for one table."),
    ("query", OperationClass.READ, "Run a SELECT statement and return rows."),
    ("execute_sql", OperationClass.WRITE, "Run an INSERT/UPDATE/DELETE/DDL statement — requires approval and Register/Cell."),
]


class OrchestratorError(Exception):
    def __init__(
        self, status_code: int, detail: str, *, retry_after: int | None = None, not_dispatched: bool = False,
    ) -> None:
        self.status_code = status_code
        self.detail = detail
        #: Seconds for a ``Retry-After`` header (rate limit / busy).
        self.retry_after = retry_after
        #: True when the adapter was never invoked, so nothing ran on the target.
        self.not_dispatched = not_dispatched
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
        four_eyes=record.four_eyes,
        expires_at=datetime.fromisoformat(record.expires_at) if record.expires_at else None,
    )


async def _require_live_adapter(registry: AdapterRegistry, store: AiStore, conn: ConnectionRecord) -> None:
    """Make sure THIS process can use the connection, from its CURRENT shared record.

    The seeded demo connection re-registers itself from ``NEURALBRIDGE_AI_PG_*`` in the process
    that is about to use it. A bound connection under vault custody is (re)built from the sealed
    credential in the shared store whenever this worker has no adapter for it or built it from an
    older credential version; a revoked one is dropped and refused (``neuralbridge.ai.credentials``).
    A connection bound under single-worker process-local custody is live only in the process that
    bound it and answers an honest 409 elsewhere; so does one whose custody is not configured (503)."""
    if conn.source == "seeded_from_env" and conn.registry_key == SEEDED_REGISTRY_KEY:
        register_seeded_adapter(registry)
        if conn.registry_key not in registry:
            raise OrchestratorError(409, f"Connection '{conn.id}' has no live adapter (no demo DSN configured).")
        return
    try:
        await vault_for(store).ensure_live(registry, conn)
    except CustodyError as exc:
        raise OrchestratorError(exc.status_code, exc.detail) from exc


def _not_found_connection(connection_id: str) -> OrchestratorError:
    """The one 404 for a connection that is missing *or* not the caller's —
    identical status and text, so there is no existence oracle."""
    return OrchestratorError(404, f"Connection '{connection_id}' not found.")


_UPSTREAM_FAILED = "The connection could not complete the operation."

_DEMO_READ_ONLY = (
    "The shared demo connection is read-only. Bind your own connection "
    "(POST /ai/connections) to propose writes."
)


def _connection_revoked(connection_id: str) -> OrchestratorError:
    return OrchestratorError(
        409,
        f"Connection '{connection_id}' has been revoked and cannot be used. "
        "Revocation is permanent: bind a new connection with POST /ai/connections.",
    )


async def _drop_stale_adapter(registry: AdapterRegistry, store: AiStore, conn: ConnectionRecord) -> None:
    """A revoked connection's adapter must not linger in this worker's registry (it holds the
    decrypted credential and an open pool): drop and close it as soon as the revocation is seen."""
    stale = registry.get(conn.registry_key)
    if stale is None or conn.source == "seeded_from_env":
        return
    revoked = conn.status == REVOKED
    if not revoked:
        try:
            vault_for(store).authorize(conn)
        except CustodyError as exc:
            revoked = exc.code == "revoked"
    if revoked:
        registry.unregister(conn.registry_key)
        try:
            await stale.disconnect()
        except Exception:  # noqa: BLE001 - best effort: the credential has left the registry either way
            logger.warning("ai_connection_disconnect_failed", connection_id=conn.id)


def _require_active(store: AiStore, conn: ConnectionRecord) -> None:
    """A revoked connection refuses every operation on its next call. The record is read from the
    shared store on each request, and the anti-rollback journal is consulted for vault connections,
    so this holds across worker processes and across a restore of an older backup."""
    if conn.status == REVOKED:
        raise _connection_revoked(conn.id)
    try:
        vault_for(store).authorize(conn)
    except CustodyError as exc:
        if exc.code == "revoked":
            raise _connection_revoked(conn.id) from exc
        raise OrchestratorError(exc.status_code, exc.detail) from exc


def _not_found_plan(plan_id: str) -> OrchestratorError:
    return OrchestratorError(404, f"Plan '{plan_id}' not found.")


def _visible_connection(store: AiStore, scope: Scope, connection_id: str) -> ConnectionRecord:
    conn = store.get_connection(connection_id)
    if conn is None or not can_read_connection(scope, conn):
        raise _not_found_connection(connection_id)
    return conn


def _visible_plan(store: AiStore, scope: Scope, plan_id: str) -> PlanRecord:
    record = store.get_plan(plan_id)
    if record is None or not can_access_plan(scope, record):
        raise _not_found_plan(plan_id)
    return record


def list_capabilities(store: AiStore, scope: Scope, connection_id: str) -> list[Capability]:
    conn = _visible_connection(store, scope, connection_id)
    if conn.adapter_type != "postgres" or conn.status == REVOKED:
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
    router: RequestRouter, scope: Scope, actor: Actor, conn: ConnectionRecord, operation: str, params: dict[str, Any]
) -> tuple[AdapterResponse, Provenance]:
    try:
        result = await router.route(
            adapter_type=conn.registry_key,
            operation=operation,
            params=params,
            request_id=str(uuid.uuid4()),
            actor=actor.as_audit_string(),
            owner=scope.owner,
        )
    except ResourceLimitError as exc:
        raise OrchestratorError(
            exc.status_code, f"{exc.code}: {exc}", retry_after=exc.retry_after, not_dispatched=True,
        ) from exc
    except AuditPreflightError:
        raise  # not dispatched; the app answers 503 audit_unavailable
    except AuditUnavailableError:
        raise  # dispatched, but the trail could not record it: callers treat the outcome as unknown
    except AdapterTimeoutError as exc:
        raise OrchestratorError(504, "The connection did not answer within the time limit.") from exc
    except Exception as exc:
        # The router has already logged the real error server-side and in the
        # owner's audit entry. The client gets a generic body: driver/OS text
        # carries the target's host and port.
        raise OrchestratorError(502, _UPSTREAM_FAILED) from exc
    response: AdapterResponse = result["data"]
    provenance = _build_provenance(conn, operation, response)
    return response, provenance


async def read(
    router: RequestRouter, registry: AdapterRegistry, scope: Scope, actor: Actor, store: AiStore,
    connection_id: str, operation: str, params: dict[str, Any],
) -> QueryResultCard:
    """Execute a READ immediately. Refuses anything that isn't a READ.
    Only on a connection ``scope`` may read (its own, or the seeded demo)."""
    conn = _visible_connection(store, scope, connection_id)
    await _drop_stale_adapter(registry, store, conn)
    _require_active(store, conn)

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

    await _require_live_adapter(registry, store, conn)
    response, provenance = await _run(router, scope, actor, conn, operation, params)
    return QueryResultCard(success=response.success, data=response.data, error=response.error, provenance=provenance)


def create_plan(
    store: AiStore, scope: Scope, actor: Actor, connection_id: str, operation: str, params: dict[str, Any],
    caller: CallerRef | None = None,
) -> ApprovalCard:
    """Propose a WRITE/DESTRUCTIVE operation. Never executes it. Paid-gated
    by the caller (``api/routes/ai.py``) before this is reached. The plan is
    owned by ``scope.owner`` — only that account may approve or deny it. ``caller`` is the proposer's
    server-derived key fingerprint (``neuralbridge.ai.approval``); with four-eyes in force it is what
    the approver is compared against."""
    caller = caller or CallerRef()
    conn = store.get_connection(connection_id)
    if conn is None or not can_read_connection(scope, conn):
        raise _not_found_connection(connection_id)
    if not can_plan_on_connection(scope, conn):
        # Only the shared demo reaches here (anything else unplannable is
        # unreadable, so already a 404): it is visible, so a 403 is no oracle.
        raise OrchestratorError(403, _DEMO_READ_ONLY)
    _require_active(store, conn)

    try:
        decision = evaluate(conn.adapter_type, operation, params)
    except PolicyError as exc:
        raise OrchestratorError(403, exc.reason) from exc

    policy = effective_policy(store, scope.owner)
    if policy.four_eyes and not caller.key_ref:
        raise OrchestratorError(
            403, "four_eyes_required: this account requires an independently authenticated approver, so a "
                 "plan can only be proposed by a caller identified by an API key.")
    if policy.four_eyes:
        problem = named_operator_problem(caller, role="proposer")
        if problem is not None:
            raise OrchestratorError(403, f"four_eyes_required: {problem}.")

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
        owner=scope.owner,
        four_eyes=policy.four_eyes,
        expires_at=expiry_for(policy),
        proposed_key_ref=caller.key_ref,
        proposed_operator=caller.operator,
    )
    store.create_plan(record)
    return ApprovalCard(plan=_plan_to_schema(record), risk_note=decision.risk_note)


def _expire_if_due(store: AiStore, record: PlanRecord) -> PlanRecord:
    """A pending four-eyes plan past its deadline becomes ``expired`` (terminal, compare-and-set), so
    it is reported as such and can never be approved. Other plans are returned unchanged."""
    if record.status != PlanStatus.PENDING_APPROVAL.value or not record.four_eyes \
            or not is_expired(record.expires_at):
        return record
    moved = store.transition_plan(
        record.id, expected=PlanStatus.PENDING_APPROVAL.value, status=PlanStatus.EXPIRED.value,
        decided_by="system:expired", decided_at=datetime.now(UTC).isoformat(),
        deny_reason="the approval window elapsed before an independent approver decided")
    return moved or store.get_plan(record.id) or record


def get_plan(store: AiStore, scope: Scope, plan_id: str) -> Plan:
    record = _expire_if_due(store, _visible_plan(store, scope, plan_id))
    return _plan_to_schema(record)


def _lost_race(plan_id: str, store: AiStore) -> OrchestratorError:
    current = store.get_plan(plan_id)
    state = current.status if current is not None else "gone"
    return OrchestratorError(409, f"Plan '{plan_id}' is '{state}', not pending approval.")


def deny_plan(store: AiStore, scope: Scope, actor: Actor, plan_id: str, reason: str) -> Plan:
    record = _expire_if_due(store, _visible_plan(store, scope, plan_id))
    if record.status != PlanStatus.PENDING_APPROVAL.value:
        raise OrchestratorError(409, f"Plan '{plan_id}' is '{record.status}', not pending approval.")
    # Compare-and-set: a concurrent approve/deny that won between the read above
    # and here makes this a 409, and can never overwrite `executed`/`failed`.
    updated = store.transition_plan(
        plan_id, expected=PlanStatus.PENDING_APPROVAL.value, status=PlanStatus.DENIED.value,
        decided_by=actor.as_audit_string(), decided_at=datetime.now(UTC).isoformat(), deny_reason=reason,
    )
    if updated is None:
        raise _lost_race(plan_id, store)
    return _plan_to_schema(updated)


async def approve_and_execute(
    router: RequestRouter, registry: AdapterRegistry, store: AiStore, scope: Scope, actor: Actor, plan_id: str,
    caller: CallerRef | None = None,
) -> ExecutionReceipt:
    """Approve a pending plan and execute it in the same call — the only
    path to a WRITE running. Paid-gated by the caller before this is
    reached. Only the account that proposed the plan (or the operator) may
    approve it; anyone else gets the same 404 as for a missing plan.

    Exactly-once: the plan is *claimed* (``pending_approval`` -> ``approved``,
    a compare-and-set in the store) before anything is routed, so of any number
    of concurrent approvals — threads or worker processes — only the claimant
    executes; the rest get 409.  ``approved`` therefore means "claimed, in
    flight". If execution then fails (upstream error, or the request is
    cancelled mid-flight) the write may or may not have landed, so the plan
    goes to ``failed`` — terminal, never pending, never silently re-run; the
    operator reviews the target and proposes a new plan. Checks that fail
    *before* the claim (missing connection, tenancy, adapter not live) change
    nothing and leave the plan pending."""
    caller = caller or CallerRef()
    record = _expire_if_due(store, _visible_plan(store, scope, plan_id))
    if record.status != PlanStatus.PENDING_APPROVAL.value:
        raise OrchestratorError(409, f"Plan '{plan_id}' is '{record.status}', not pending approval.")

    # Four-eyes: in force if it was when the plan was proposed OR is now (it can be tightened, never
    # loosened, for a plan already waiting). Checked before anything is claimed or routed.
    if record.four_eyes or effective_policy(store, record.owner).four_eyes:
        problem = independence_problem(record.proposed_key_ref, record.proposed_operator, caller)
        if problem is not None:
            raise OrchestratorError(
                403, f"four_eyes_required: a different, independently authenticated principal must approve "
                     f"this plan ({problem}).")

    conn = store.get_connection(record.connection_id)
    if conn is None:
        raise OrchestratorError(404, f"Connection '{record.connection_id}' backing this plan no longer exists.")
    if not can_plan_on_connection(scope, conn):
        raise OrchestratorError(403, _DEMO_READ_ONLY if is_demo(conn) else f"Plan '{plan_id}' not found.")
    await _drop_stale_adapter(registry, store, conn)
    _require_active(store, conn)
    await _require_live_adapter(registry, store, conn)

    claimed = store.transition_plan(
        plan_id, expected=PlanStatus.PENDING_APPROVAL.value, status=PlanStatus.APPROVED.value,
        decided_by=actor.as_audit_string(), decided_at=datetime.now(UTC).isoformat(),
        decided_key_ref=caller.key_ref or None, decided_operator=caller.operator or None,
    )
    if claimed is None:
        raise _lost_race(plan_id, store)

    try:
        response, provenance = await _run(router, scope, actor, conn, record.operation, record.params)
    except (OrchestratorError, AuditPreflightError) as exc:
        if isinstance(exc, AuditPreflightError) or exc.not_dispatched:
            # Refused before the adapter ran (rate limit, busy, audit sink down): nothing
            # happened on the target, so the claim is released and the plan is pending again.
            store.transition_plan(
                plan_id, expected=PlanStatus.APPROVED.value, status=PlanStatus.PENDING_APPROVAL.value,
                reset_decision=True)
        else:
            # Upstream failed or timed out: outcome unknown.
            store.transition_plan(
                plan_id, expected=PlanStatus.APPROVED.value, status=PlanStatus.FAILED.value)
        raise
    except BaseException:
        # Cancellation, or the trail failing after dispatch: outcome unknown.
        store.transition_plan(
            plan_id, expected=PlanStatus.APPROVED.value, status=PlanStatus.FAILED.value)
        raise

    updated = store.transition_plan(
        plan_id, expected=PlanStatus.APPROVED.value, status=PlanStatus.EXECUTED.value) or claimed
    return ExecutionReceipt(
        plan_id=updated.id,
        success=response.success,
        data=response.data,
        error=response.error,
        provenance=provenance,
        approved_by=updated.decided_by or actor.as_audit_string(),
        executed_at=datetime.now(UTC),
    )


def list_plans(store: AiStore, scope: Scope, *, limit: int = 50) -> list[Plan]:
    owner = None if scope.is_operator else scope.owner
    return [_plan_to_schema(_expire_if_due(store, r)) for r in store.list_plans(limit=limit, owner=owner)]
