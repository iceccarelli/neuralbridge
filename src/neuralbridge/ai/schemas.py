"""Pydantic models for the /ai control-plane loop.

Every response shape the frontend renders as a card
(QueryResultCard / ApprovalCard / ExecutionReceipt) is defined here, once,
so the API and the UI cannot drift from each other.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class OperationClass(StrEnum):
    """How an operation is classified for policy purposes."""

    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class PlanStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTED = "executed"
    FAILED = "failed"


class Provenance(BaseModel):
    """Where a fact came from — attached to every result the UI shows.

    Required by the task brief: "every system fact cites connection,
    tool, timestamp, result id." ``mocked`` is surfaced explicitly because
    ``PostgresAdapter._do_execute`` silently falls back to canned mock
    data when it cannot reach a real database
    (``adapters/databases/postgres.py::_get_mock_response``) — the AI
    layer must never present that as a real system fact.
    """

    connection_id: str
    connection_name: str
    adapter_type: str
    tool: str
    request_id: str
    timestamp: datetime
    mocked: bool = False


class ConnectionSummary(BaseModel):
    """A connection as the /ai surface shows it — never invented."""

    id: str
    name: str
    adapter_type: str
    status: str
    source: str  # "connections_api" | "seeded_from_env"


class Capability(BaseModel):
    """One operation an actor could ask the agent to run."""

    connection_id: str
    adapter_type: str
    operation: str
    operation_class: OperationClass
    description: str


class ReadRequest(BaseModel):
    connection_id: str
    operation: str
    params: dict[str, Any] = Field(default_factory=dict)


class QueryResultCard(BaseModel):
    """What the UI renders for a completed READ."""

    success: bool
    data: Any = None
    error: str | None = None
    provenance: Provenance


class PlanRequest(BaseModel):
    connection_id: str
    operation: str
    params: dict[str, Any] = Field(default_factory=dict)


class Plan(BaseModel):
    """A proposed operation awaiting approval — never auto-executed."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    connection_id: str
    adapter_type: str
    operation: str
    operation_class: OperationClass
    params: dict[str, Any]
    proposed_by: str
    status: PlanStatus = PlanStatus.PENDING_APPROVAL
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    decided_by: str | None = None
    decided_at: datetime | None = None
    deny_reason: str | None = None


class ApprovalCard(BaseModel):
    """What the UI renders for a plan awaiting a decision."""

    plan: Plan
    risk_note: str


class ExecutionReceipt(BaseModel):
    """What the UI renders once an approved plan has run."""

    plan_id: str
    success: bool
    data: Any = None
    error: str | None = None
    provenance: Provenance
    approved_by: str
    executed_at: datetime


class PolicyDenial(BaseModel):
    reason: str
    operation_class: OperationClass
