"""
NeuralBridge Adapter Management Routes.

CRUD endpoints for registering, configuring, and invoking adapters.
Business users interact with these endpoints through the React dashboard;
agents interact via the MCP gateway (which delegates here internally).
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from neuralbridge.api.dependencies import (
    get_adapter_registry,
    get_audit_logger,
    get_request_router,
)
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger

router = APIRouter(prefix="/adapters")


# ── Request / Response Models ────────────────────────────────

class AdapterCreateRequest(BaseModel):
    """Payload for registering a new adapter."""
    adapter_type: str = Field(..., description="Adapter type identifier (e.g. 'salesforce').")
    config: dict[str, Any] = Field(default_factory=dict, description="Adapter-specific configuration.")
    enabled: bool = True


class AdapterExecuteRequest(BaseModel):
    """Payload for executing an operation on a registered adapter."""
    operation: str = Field(..., description="Operation name (e.g. 'query', 'send_message').")
    params: dict[str, Any] = Field(default_factory=dict, description="Operation parameters.")


class AdapterResponse(BaseModel):
    """Standard adapter response envelope."""
    status: str
    adapter: str
    data: Any = None
    error: str | None = None


# ── Endpoints ────────────────────────────────────────────────

@router.get("", summary="List registered adapters")
async def list_adapters(
    registry: AdapterRegistry = Depends(get_adapter_registry),
) -> dict[str, Any]:
    """Return all registered adapter types and their metadata."""
    adapter_types = registry.list_all()
    adapters_info = []
    for at in adapter_types:
        adapter = registry.get(at)
        if adapter:
            adapters_info.append({
                "type": at,
                "status": adapter.status.value,
                "category": adapter.category,
                "description": adapter.description,
                "supported_operations": adapter.supported_operations,
                "stats": adapter.get_stats(),
            })
    return {"adapters": adapters_info, "total": len(adapters_info)}


@router.get("/{adapter_type}", summary="Get adapter details")
async def get_adapter(
    adapter_type: str,
    registry: AdapterRegistry = Depends(get_adapter_registry),
) -> dict[str, Any]:
    """Return detailed information about a specific adapter."""
    adapter = registry.get(adapter_type)
    if not adapter:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Adapter '{adapter_type}' not found.",
        )
    meta = adapter.get_metadata()
    return {
        "type": meta.adapter_type,
        "name": meta.name,
        "description": meta.description,
        "version": meta.version,
        "category": meta.category,
        "supported_operations": meta.supported_operations,
        "config_schema": meta.config_schema,
        "status": adapter.status.value,
        "stats": adapter.get_stats(),
    }


@router.post("/{adapter_type}/execute", summary="Execute adapter operation")
async def execute_adapter(
    adapter_type: str,
    request: AdapterExecuteRequest,
    router_dep: RequestRouter = Depends(get_request_router),
    audit: AuditLogger = Depends(get_audit_logger),
) -> dict[str, Any]:
    """
    Execute an operation on the specified adapter.

    The request is routed through the RequestRouter, which handles
    validation, rate limiting, and audit logging.
    """
    try:
        result = await router_dep.route(
            adapter_type=adapter_type,
            operation=request.operation,
            params=request.params,
        )
        return result
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc


@router.post("/{adapter_type}/validate", summary="Validate adapter credentials")
async def validate_credentials(
    adapter_type: str,
    registry: AdapterRegistry = Depends(get_adapter_registry),
) -> dict[str, Any]:
    """Test whether the configured credentials for an adapter are valid."""
    adapter = registry.get(adapter_type)
    if not adapter:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Adapter '{adapter_type}' not found.",
        )
    result = await adapter.validate_credentials()
    return result.to_dict()


@router.get("/{adapter_type}/schema", summary="Get adapter config schema")
async def get_config_schema(
    adapter_type: str,
    registry: AdapterRegistry = Depends(get_adapter_registry),
) -> dict[str, Any]:
    """Return the JSON Schema for the adapter's YAML configuration."""
    adapter = registry.get(adapter_type)
    if not adapter:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Adapter '{adapter_type}' not found.",
        )
    return adapter._get_config_schema()
