"""
NeuralBridge Audit Log Routes.

Provides read-only access to the audit trail.  Compliance officers use these
endpoints (via the dashboard) to review operations, investigate incidents,
and export logs for CRA reporting.

Tenancy: every entry is stamped with the owning account (``details.owner``,
set server-side from the validated API key — see ``neuralbridge.ai.tenancy``).
These routes require a key (anonymous is 401); a customer account sees only
the entries it owns, and the operator sees everything. Entries with no owner
(written before tenancy) are operator-only. Export is operator-only: it
dumps the whole trail.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from neuralbridge.ai.entitlements import (
    Principal,
    current_principal,
    require_operator,
    require_scope,
)
from neuralbridge.ai.tenancy import Scope, can_see_audit_entry
from neuralbridge.api.dependencies import get_audit_logger
from neuralbridge.security.audit import AuditEntry, AuditLogger

router = APIRouter(prefix="/logs")

_EXPORT_FORMATS = ("json", "csv")


async def _scope(principal: Principal = Depends(current_principal)) -> Scope:
    return require_scope(principal)


async def _operator(principal: Principal = Depends(current_principal)) -> Scope:
    return require_operator(principal)


def _parse_time(value: str | None, name: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"{name} must be an ISO 8601 timestamp.",
        ) from exc


@router.get("", summary="Query audit logs")
async def query_logs(
    event_type: str | None = Query(None, description="Filter by event type."),
    actor: str | None = Query(None, description="Filter by actor (user/agent)."),
    start_date: str | None = Query(None, description="Start date (ISO 8601)."),
    end_date: str | None = Query(None, description="End date (ISO 8601)."),
    limit: int = Query(100, ge=1, le=1000, description="Max results."),
    offset: int = Query(0, ge=0, description="Pagination offset."),
    audit: AuditLogger = Depends(get_audit_logger),
    scope: Scope = Depends(_scope),
) -> dict[str, Any]:
    """
    Query the audit log with optional filters, restricted to the entries the
    caller owns (the operator: all). Pagination is applied *after* the owner
    filter, so offsets and totals never reflect other tenants' entries.
    """
    start_time = _parse_time(start_date, "start_date")
    end_time = _parse_time(end_date, "end_date")

    events: list[dict[str, Any]] = []
    idx = 0
    async for entry in audit.query_events(
        actor=actor,
        event_type=event_type,
        start_time=start_time,
        end_time=end_time,
    ):
        if not can_see_audit_entry(scope, entry.details.get("owner")):
            continue
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


def _render(events: list[AuditEntry], file_format: str) -> tuple[bytes, str]:
    rows = [e.model_dump(mode="json") for e in events]
    if file_format == "json":
        return json.dumps(rows, indent=2).encode("utf-8"), "application/json"
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(AuditEntry.model_fields.keys()))
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue().encode("utf-8"), "text/csv"


@router.get("/export", summary="Export audit logs (operator only)")
async def export_logs(
    file_format: str = Query("json", description="Export format: json or csv."),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    audit: AuditLogger = Depends(get_audit_logger),
    _operator_scope: Scope = Depends(_operator),
) -> Response:
    """
    Export the whole audit trail for external compliance systems — the
    operator only. The body is the export itself (nothing is written to
    server disk); the hash-chain integrity result rides in response headers
    so auditors can see it was actually recomputed, not asserted.
    """
    if file_format not in _EXPORT_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"file_format must be one of {', '.join(_EXPORT_FORMATS)}.",
        )
    start_time = _parse_time(start_date, "start_date")
    end_time = _parse_time(end_date, "end_date")

    events = [
        e async for e in audit.query_events(start_time=start_time, end_time=end_time)
    ]
    body, media_type = _render(events, file_format)

    # Actually verify, rather than asserting that we did.
    chain_ok = await audit.verify_integrity()

    return Response(
        content=body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="audit-export.{file_format}"',
            "X-Hash-Chain-Verified": "true" if chain_ok else "false",
            "X-Exported-At": datetime.now(tz=UTC).isoformat(),
            "X-Integrity-Method": "recomputed over the full chain at export time",
        },
    )


@router.get("/stats", summary="Audit log statistics")
async def log_stats(
    audit: AuditLogger = Depends(get_audit_logger),
    scope: Scope = Depends(_scope),
) -> dict[str, Any]:
    """Aggregate statistics over the entries the caller owns."""
    event_types: dict[str, int] = {}
    actors: dict[str, int] = {}
    adapters: dict[str, int] = {}
    total = 0
    async for entry in audit.query_events():
        if not can_see_audit_entry(scope, entry.details.get("owner")):
            continue
        total += 1
        event_types[entry.event_type] = event_types.get(entry.event_type, 0) + 1
        actors[entry.actor] = actors.get(entry.actor, 0) + 1
        adapters[entry.resource] = adapters.get(entry.resource, 0) + 1

    def top(counts: dict[str, int]) -> list[dict[str, Any]]:
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return [{"name": name, "count": count} for name, count in ranked]

    return {
        "total_events": total,
        "event_types": event_types,
        "top_actors": top(actors),
        "top_adapters": top(adapters),
    }
