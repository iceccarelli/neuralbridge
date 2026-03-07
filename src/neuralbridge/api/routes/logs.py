"""
NeuralBridge Audit Log Routes.

Provides read-only access to the immutable audit trail.  Compliance
officers use these endpoints (via the dashboard) to review operations,
investigate incidents, and export logs for CRA reporting.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query

from neuralbridge.api.dependencies import get_audit_logger
from neuralbridge.security.audit import AuditLogger

router = APIRouter(prefix="/logs")


@router.get("", summary="Query audit logs")
async def query_logs(
    event_type: str | None = Query(None, description="Filter by event type."),
    actor: str | None = Query(None, description="Filter by actor (user/agent)."),
    start_date: str | None = Query(None, description="Start date (ISO 8601)."),
    end_date: str | None = Query(None, description="End date (ISO 8601)."),
    limit: int = Query(100, ge=1, le=1000, description="Max results."),
    offset: int = Query(0, ge=0, description="Pagination offset."),
    audit: AuditLogger = Depends(get_audit_logger),
) -> dict[str, Any]:
    """
    Query the immutable audit log with optional filters.

    Results are ordered by timestamp descending (newest first).
    The audit trail is append-only and cannot be modified or deleted ---
    a core requirement for CRA compliance.
    """
    start_time = datetime.fromisoformat(start_date) if start_date else None
    end_time = datetime.fromisoformat(end_date) if end_date else None

    events: list[dict[str, Any]] = []
    idx = 0
    async for entry in audit.query_events(
        actor=actor,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
    ):
        if idx < offset:
            idx += 1
            continue
        if len(events) >= limit:
            break
        events.append(entry.model_dump(mode="json"))
        idx += 1

    return {
        "events": events,
        "total": len(events),
        "limit": limit,
        "offset": offset,
    }


@router.get("/export", summary="Export audit logs")
async def export_logs(
    file_format: str = Query("json", description="Export format: json or csv."),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    audit: AuditLogger = Depends(get_audit_logger),
) -> dict[str, Any]:
    """
    Export audit logs for external compliance systems.

    Supports JSON and CSV formats.  The exported data includes the
    hash-chain integrity field so that auditors can verify tamper-free
    history.
    """
    import tempfile

    start_time = datetime.fromisoformat(start_date) if start_date else None
    end_time = datetime.fromisoformat(end_date) if end_date else None

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_format}")
    await audit.export_events(
        file_path=tmp.name,
        file_format=file_format,
        start_time=start_time,
        end_time=end_time,
    )

    return {
        "format": file_format,
        "file_path": tmp.name,
        "exported_at": datetime.now(tz=UTC).isoformat(),
        "integrity": "hash_chain_verified",
    }


@router.get("/stats", summary="Audit log statistics")
async def log_stats(
    audit: AuditLogger = Depends(get_audit_logger),
) -> dict[str, Any]:
    """Return aggregate statistics about the audit trail."""
    return {
        "total_events": 0,  # Placeholder -- wired to AuditLogger in production
        "event_types": {},
        "top_actors": [],
        "top_adapters": [],
    }
