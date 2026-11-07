"""
NeuralBridge MCP Gateway — Model Context Protocol Server.

Implements a fully MCP-compatible gateway that AI agents (OpenClaw, Claude
Desktop, Cursor, AutoGPT, LangChain) connect to via **STDIO** or
**StreamableHTTP** transports.

Key responsibilities:
* Accept incoming MCP ``tools/list`` and ``tools/call`` requests.
* Translate tool calls into adapter operations via the Router.
* Return normalised JSON responses with full OpenTelemetry tracing.
* Enforce zero-trust security on every request.

References
----------
* Model Context Protocol specification — https://modelcontextprotocol.io
* OpenClaw gateway integration — compatible with OpenClaw skill YAML
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import structlog

from neuralbridge.ai.audit_events import gate_with_audit
from neuralbridge.ai.entitlements import get_accounts, resolve_principal, scope_for
from neuralbridge.core.router import RequestRouter
from neuralbridge.security.audit import AuditLogger, AuditUnavailableError, redact_text
from neuralbridge.security.limits import Limits, ResourceLimitError

logger = structlog.get_logger(__name__)


# ── MCP Protocol Types ──────────────────────────────────────

class MCPTransport(StrEnum):
    """Supported MCP transport mechanisms."""
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"


@dataclass
class MCPToolDefinition:
    """
    Describes a single tool exposed to agents.

    Each NeuralBridge adapter is automatically registered as an MCP tool
    so that any MCP-compatible agent can discover and invoke it.
    """
    name: str
    description: str
    input_schema: dict[str, Any]
    adapter_type: str
    permissions: list[str] = field(default_factory=list)


@dataclass
class MCPRequest:
    """Inbound request from an MCP client."""
    id: str
    method: str  # e.g. "tools/list", "tools/call"
    params: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass
class MCPResponse:
    """Outbound response to an MCP client."""
    id: str
    result: Any = None
    error: dict[str, Any] | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self.id,
        }
        if self.error:
            payload["error"] = self.error
        else:
            payload["result"] = self.result
        return payload


class MCPGateway:
    """
    Central MCP gateway that bridges AI agents to NeuralBridge adapters.

    The gateway maintains a registry of available tools (one per adapter),
    handles discovery (``tools/list``), execution (``tools/call``), and
    streams results back to the calling agent.

    Parameters
    ----------
    router : RequestRouter
        Routes tool calls to the correct adapter instance.
    audit_logger : AuditLogger
        Records every operation for CRA-compliant immutable audit trails.
    transport : MCPTransport
        Communication channel — STDIO for local agents, StreamableHTTP
        for remote / cloud-hosted agents.
    """

    def __init__(
        self,
        router: RequestRouter,
        audit_logger: AuditLogger,
        transport: MCPTransport = MCPTransport.STREAMABLE_HTTP,
        default_actor: str | None = None,
        default_api_key: str | None = None,
    ) -> None:
        self._router = router
        self._audit = audit_logger
        self._transport = transport
        self._tools: dict[str, MCPToolDefinition] = {}
        self._running = False
        # Never the bare literal "mcp_client" — that was the Phase 0/1 gap
        # (see reports/NEURALBRIDGE-AI-DATA-MAP.md). A real identity for
        # the whole session, overridable per tool call via an "actor"
        # argument (same pattern assurance-mcp's own machine_verify tool
        # already uses). NEURALBRIDGE_MCP_ACTOR lets an operator configure
        # this once in their MCP client config instead of every call.
        self._default_actor = default_actor or os.environ.get("NEURALBRIDGE_MCP_ACTOR") or f"mcp-session:{id(self):x}"
        # Entitlement key for paid tool calls (execute_sql writes) — same
        # env-var-per-session pattern as assurance-mcp's ASSURANCE_API_KEY,
        # overridable per call via an "api_key" argument.
        self._default_api_key = default_api_key or os.environ.get("NEURALBRIDGE_MCP_API_KEY")

    # ── Tool Registry ────────────────────────────────────────

    def register_tool(self, tool: MCPToolDefinition) -> None:
        """Add an adapter-backed tool to the gateway's catalogue."""
        self._tools[tool.name] = tool
        logger.info("mcp_tool_registered", tool=tool.name, adapter=tool.adapter_type)

    def unregister_tool(self, name: str) -> None:
        """Remove a tool (e.g. when an adapter is disabled at runtime)."""
        self._tools.pop(name, None)
        logger.info("mcp_tool_unregistered", tool=name)

    def list_tools(self) -> list[dict[str, Any]]:
        """Return the full tool catalogue in MCP ``tools/list`` format."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for t in self._tools.values()
        ]

    # ── Request Handling ─────────────────────────────────────

    async def handle_request(self, raw: str | dict[str, Any]) -> MCPResponse:
        """
        Process a single MCP JSON-RPC request.

        Parameters
        ----------
        raw : str | dict
            JSON-RPC 2.0 request (string or already-parsed dict).

        Returns
        -------
        MCPResponse
            JSON-RPC 2.0 response with ``result`` or ``error``.
        """
        # Parse. The same body cap as the HTTP API (NEURALBRIDGE_MAX_BODY_BYTES) applies to the
        # raw JSON-RPC message, so the gateway is not a way round it.
        cap = Limits.from_env().max_body_bytes
        size = len(raw.encode("utf-8", "ignore")) if isinstance(raw, str) else len(json.dumps(raw, default=str))
        if size > cap:
            return MCPResponse(
                id="unknown",
                error={"code": -32600, "message": f"request_too_large: message exceeds {cap} bytes"},
            )
        if isinstance(raw, str):
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                return MCPResponse(id="unknown", error={"code": -32700, "message": str(exc)})
        else:
            data = raw

        request = MCPRequest(
            id=data.get("id", str(uuid.uuid4())),
            method=data.get("method", ""),
            params=data.get("params", {}),
        )

        logger.info("mcp_request_received", method=request.method, request_id=request.id)

        # Dispatch
        owner: str | None = None
        try:
            result: Any = None
            if request.method == "tools/list":
                result = self.list_tools()
            elif request.method == "tools/call":
                result, owner = await self._execute_tool(request)
            elif request.method == "initialize":
                result = self._handle_initialize(request)
            elif request.method == "ping":
                result = {"status": "pong"}
            else:
                return MCPResponse(
                    id=request.id,
                    error={"code": -32601, "message": f"Unknown method: {request.method}"},
                )
        except Exception as exc:
            logger.exception("mcp_request_failed", request_id=request.id)
            try:
                await self._audit.log_event(
                    event_type="mcp_error",
                    actor=f"mcp:{self._default_actor}",
                    resource=request.method,
                    action="call",
                    result="error",
                    details={"request_id": request.id, "error": str(exc),
                             **({"owner": owner} if owner else {})},
                )
            except AuditUnavailableError:
                logger.critical("mcp_error_not_audited", request_id=request.id)
            if isinstance(exc, ResourceLimitError):
                return MCPResponse(
                    id=request.id,
                    error={"code": -32000, "message": f"{exc.code}: {exc}",
                           "data": {"status": exc.status_code, "retry_after": exc.retry_after}},
                )
            if isinstance(exc, AuditUnavailableError):
                return MCPResponse(
                    id=request.id,
                    error={"code": -32000, "message": "audit_unavailable: the audit trail cannot record; "
                                                      "the operation was refused",
                           "data": {"status": 503}},
                )
            return MCPResponse(
                id=request.id,
                error={"code": -32603, "message": redact_text(str(exc))},
            )

        # Audit success
        try:
            await self._audit.log_event(
                event_type="mcp_request",
                actor=f"mcp:{self._default_actor}",
                resource=request.method,
                action="call",
                result="success",
                details={"request_id": request.id, "method": request.method,
                         **({"owner": owner} if owner else {})},
            )
        except AuditUnavailableError:
            return MCPResponse(
                id=request.id,
                error={"code": -32000, "message": "audit_unavailable: the call ran but could not be recorded",
                       "data": {"status": 503}},
            )
        return MCPResponse(id=request.id, result=result)

    # ── Private Helpers ──────────────────────────────────────

    def _handle_initialize(self, request: MCPRequest) -> dict[str, Any]:
        """Respond to the MCP ``initialize`` handshake."""
        return {
            "protocolVersion": "2025-03-26",
            "serverInfo": {
                "name": "NeuralBridge",
                "version": "0.1.0",
            },
            "capabilities": {
                "tools": {"listChanged": True},
                "logging": {},
            },
        }

    async def _execute_tool(self, request: MCPRequest) -> tuple[Any, str]:
        """
        Delegate a ``tools/call`` to the appropriate adapter via the Router.
        """
        tool_name = request.params.get("name", "")
        arguments = request.params.get("arguments", {})

        if tool_name not in self._tools:
            raise ValueError(f"Unknown tool: {tool_name}")

        tool = self._tools[tool_name]
        operation = arguments.get("operation", "execute")
        # "actor"/"api_key" are gateway-level control arguments, not
        # forwarded to the adapter as operation params — same treatment
        # assurance-mcp gives "actor" on its machine_verify tool.
        params = {k: v for k, v in arguments.items() if k not in ("actor", "api_key")}
        actor = str(arguments.get("actor") or self._default_actor)
        api_key = arguments.get("api_key") or self._default_api_key

        try:
            principal = resolve_principal(api_key, get_accounts(), anonymous_subject=f"mcp:{actor}")
        except ValueError as exc:
            raise ValueError(f"invalid_api_key: {exc}") from exc
        owner = scope_for(principal).owner
        await gate_with_audit(
            self._audit, surface="mcp_gateway", actor=f"mcp:{actor}", adapter_type=tool.adapter_type,
            operation=operation, params=params, principal=principal,
        )

        result = await self._router.route(
            adapter_type=tool.adapter_type,
            operation=operation,
            params=params,
            request_id=request.id,
            actor=f"mcp:{actor}",
            owner=owner,
        )
        return {"content": [{"type": "text", "text": json.dumps(result, default=str)}]}, owner

    # ── Transport Loops ──────────────────────────────────────

    async def serve_stdio(self) -> None:
        """
        Run the gateway over STDIO (for local agents like OpenClaw / Claude Desktop).

        Reads newline-delimited JSON from stdin, writes responses to stdout.
        """
        self._running = True
        logger.info("mcp_gateway_started", transport="stdio")

        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, __import__("sys").stdin)

        while self._running:
            line = await reader.readline()
            if not line:
                break
            response = await self.handle_request(line.decode().strip())
            __import__("sys").stdout.write(json.dumps(response.to_dict()) + "\n")
            __import__("sys").stdout.flush()

    async def shutdown(self) -> None:
        """Gracefully stop the gateway."""
        self._running = False
        logger.info("mcp_gateway_shutdown")
