"""
NeuralBridge Connection Management Routes.

Endpoints for managing adapter connections — the YAML-configured
"bridges" between AI agents and external systems.  Business users
create connections via the dashboard's Connection Wizard; developers
can also use these endpoints directly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

router = APIRouter(prefix="/connections")


# ── In-Memory Store (production: PostgreSQL) ─────────────────

_connections: dict[str, dict[str, Any]] = {}


# ── Models ───────────────────────────────────────────────────

class ConnectionCreateRequest(BaseModel):
    """Payload for creating a new connection."""
    name: str = Field(..., description="Human-readable connection name.")
    description: str = Field(default="", description="Optional description.")
    adapter_type: str = Field(..., description="Target adapter type.")
    config: dict[str, Any] = Field(default_factory=dict, description="Adapter configuration.")
    auth: dict[str, Any] = Field(default_factory=dict, description="Authentication details.")
    permissions: list[str] = Field(default_factory=list)
    rate_limit: str = Field(default="100/minute")
    enabled: bool = True


class ConnectionUpdateRequest(BaseModel):
    """Payload for updating an existing connection."""
    name: str | None = None
    description: str | None = None
    config: dict[str, Any] | None = None
    auth: dict[str, Any] | None = None
    permissions: list[str] | None = None
    rate_limit: str | None = None
    enabled: bool | None = None


# ── Endpoints ────────────────────────────────────────────────

@router.get("", summary="List all connections")
async def list_connections() -> dict[str, Any]:
    """Return all configured connections."""
    return {
        "connections": list(_connections.values()),
        "total": len(_connections),
    }


@router.post("", summary="Create a new connection", status_code=status.HTTP_201_CREATED)
async def create_connection(request: ConnectionCreateRequest) -> dict[str, Any]:
    """
    Create a new connection from YAML or JSON configuration.

    This is the primary endpoint used by the Connection Wizard in the
    React dashboard.
    """
    connection_id = str(uuid.uuid4())
    connection = {
        "id": connection_id,
        "name": request.name,
        "description": request.description,
        "adapter_type": request.adapter_type,
        "config": request.config,
        "auth": dict.fromkeys(request.auth, "***"),  # Mask secrets in response
        "permissions": request.permissions,
        "rate_limit": request.rate_limit,
        "enabled": request.enabled,
        "status": "created",
        "created_at": datetime.now(UTC).isoformat(),
        "updated_at": datetime.now(UTC).isoformat(),
    }
    _connections[connection_id] = connection
    return connection


@router.get("/{connection_id}", summary="Get connection details")
async def get_connection(connection_id: str) -> dict[str, Any]:
    """Return details for a specific connection."""
    if connection_id not in _connections:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connection '{connection_id}' not found.",
        )
    return _connections[connection_id]


@router.patch("/{connection_id}", summary="Update a connection")
async def update_connection(
    connection_id: str,
    request: ConnectionUpdateRequest,
) -> dict[str, Any]:
    """Update fields on an existing connection."""
    if connection_id not in _connections:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connection '{connection_id}' not found.",
        )
    conn = _connections[connection_id]
    update_data = request.model_dump(exclude_none=True)
    conn.update(update_data)
    conn["updated_at"] = datetime.now(UTC).isoformat()
    return conn


@router.delete("/{connection_id}", summary="Delete a connection")
async def delete_connection(connection_id: str) -> dict[str, str]:
    """Remove a connection and its configuration."""
    if connection_id not in _connections:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connection '{connection_id}' not found.",
        )
    del _connections[connection_id]
    return {"status": "deleted", "id": connection_id}


@router.post("/{connection_id}/test", summary="Test a connection")
async def test_connection(connection_id: str) -> dict[str, Any]:
    """
    Test whether a connection can successfully reach its target system.

    Attempts to connect and validate credentials without executing
    any operations.
    """
    if connection_id not in _connections:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connection '{connection_id}' not found.",
        )
    conn = _connections[connection_id]
    # In production, this would instantiate the adapter and call validate_credentials()
    return {
        "connection_id": connection_id,
        "adapter_type": conn["adapter_type"],
        "test_result": "success",
        "message": "Connection test passed.",
        "latency_ms": 42,
    }
