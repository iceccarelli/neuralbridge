"""An MCP server for the /ai control plane — wraps the real `/ai` HTTP API.

Same shape as ``assurance.mcp.server``, deliberately: every tool here makes
a real HTTP call to a running ``neuralbridge.main:app`` deployment over
``httpx``. No local simulation, no canned response, no success faked when
the API is unreachable or unconfigured — with no ``NEURALBRIDGE_API_URL``
set, every tool returns the same honest "not configured" error instead of
pretending to have called anything.

This is the **one** platform MCP package story alongside the low-level
``neuralbridge.core.gateway`` (generic adapter dispatch, unchanged by
Phase 2 beyond the actor/entitlement fixes — see
``reports/NEURALBRIDGE-AI-PHASE2.md``): that module is the transport the
`/ai` HTTP API itself dispatches through, while this one exposes `/ai`'s
own plan → approve → execute → verify loop as MCP tools, matching how
``assurance.mcp.server`` wraps the assurance HTTP API rather than
reimplementing its engines. An agent that wants raw adapter access uses
the gateway; an agent that wants the paid, approval-gated control plane
uses this server.

Free tools (``ai_list_connections``, ``ai_capabilities``, ``ai_read``)
need no configuration beyond ``NEURALBRIDGE_API_URL`` — ``ai_read`` is
rate-limited server-side on the free tier, same as `/ai/read` itself.
Paid tools (``ai_plan_write``, ``ai_approve``, ``ai_deny``, ``ai_audit``)
also want ``NEURALBRIDGE_AI_API_KEY``; without one, or with a Validator-only
key, they return the API's real 402 — a structured, parseable answer
naming the required plan, not an error from this server.

Run with ``neuralbridge-ai-mcp`` (installed via
``pip install -e '.[neuralbridge-ai-mcp]'``) or
``python -m neuralbridge.mcp.server``. Transport is stdio by default,
matching Cursor's ``mcp.json`` and most MCP clients.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

mcp: MCPServer = MCPServer(
    name="neuralbridge-ai",
    version="0.1.0",
    instructions=(
        "Tools for the NeuralBridge AI control plane (/ai): discover connections, "
        "read data immediately, propose a write, and approve/deny it. Free tools "
        "(ai_list_connections, ai_capabilities, ai_read) need no configuration "
        "beyond NEURALBRIDGE_API_URL. Paid tools (ai_plan_write, ai_approve, "
        "ai_deny, ai_audit) also want NEURALBRIDGE_AI_API_KEY; without one they "
        "return the API's real 402, which is the correct, informative answer — "
        "not an error in this server. Set NEURALBRIDGE_AI_ACTOR to a real "
        "identity for the audit trail; it is never allowed to default to "
        "'system' or 'mcp_client'."
    ),
)


def _api_url() -> str | None:
    url = os.environ.get("NEURALBRIDGE_API_URL", "").strip()
    return url.rstrip("/") or None


def _headers() -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "X-NB-Actor": os.environ.get("NEURALBRIDGE_AI_ACTOR", "").strip() or f"mcp-session:{os.getpid()}",
    }
    key = os.environ.get("NEURALBRIDGE_AI_API_KEY", "").strip()
    if key:
        headers["X-API-Key"] = key
    return headers


_NOT_CONFIGURED = {
    "error": "neuralbridge_api_url_not_configured",
    "remedy": (
        "Set NEURALBRIDGE_API_URL to a running deployment of neuralbridge.main:app, "
        "e.g. http://127.0.0.1:8000/api/v1 for a local run "
        "(uvicorn neuralbridge.main:app). This server never fakes a response — "
        "see docs/ai-local-setup.md."
    ),
}


async def _call(method: str, path: str, *, json_body: dict[str, Any] | None = None) -> dict[str, Any]:
    base = _api_url()
    if base is None:
        return dict(_NOT_CONFIGURED)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.request(method, f"{base}{path}", headers=_headers(), json=json_body)
    except httpx.RequestError as exc:
        return {
            "error": "could_not_reach_api",
            "detail": str(exc),
            "remedy": f"Confirm {base} is reachable and running neuralbridge.main:app.",
        }

    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text}

    return {"status": response.status_code, "body": body}


@mcp.tool()
async def ai_list_connections() -> dict[str, Any]:
    """GET /ai/connections — real connections, never invented. Free, rate-limit exempt."""
    return await _call("GET", "/ai/connections")


@mcp.tool()
async def ai_capabilities(connection_id: str) -> dict[str, Any]:
    """GET /ai/capabilities — what this agent can do against one connection. Free.

    Args:
        connection_id: id from ai_list_connections.
    """
    return await _call("GET", f"/ai/capabilities?connection_id={connection_id}")


@mcp.tool()
async def ai_read(connection_id: str, operation: str, params: dict[str, Any]) -> dict[str, Any]:
    """POST /ai/read — run a READ (list_tables/describe_table/query/health_check) now.

    Free, rate-limited (see the plan's ai_reads_per_day — GET /v1/plans on the
    assurance API). Returns the API's real 429 with a quota_exceeded body once
    the daily allowance is spent, not a fake success.
    """
    return await _call(
        "POST", "/ai/read", json_body={"connection_id": connection_id, "operation": operation, "params": params}
    )


@mcp.tool()
async def ai_plan_write(connection_id: str, operation: str, params: dict[str, Any]) -> dict[str, Any]:
    """POST /ai/plan — propose a WRITE/DESTRUCTIVE operation. Never executes it.

    Register/Cell only. With no NEURALBRIDGE_AI_API_KEY, or a Validator-only
    key, this returns the API's real 402 naming the required plan.
    """
    return await _call(
        "POST", "/ai/plan", json_body={"connection_id": connection_id, "operation": operation, "params": params}
    )


@mcp.tool()
async def ai_approve(plan_id: str) -> dict[str, Any]:
    """POST /ai/plan/{plan_id}/approve — approve a pending plan and execute it.

    Register/Cell only, same 402 shape as ai_plan_write when under-entitled.
    """
    return await _call("POST", f"/ai/plan/{plan_id}/approve")


@mcp.tool()
async def ai_deny(plan_id: str, reason: str = "denied by agent") -> dict[str, Any]:
    """POST /ai/plan/{plan_id}/deny — deny a pending plan. Nothing executes."""
    return await _call("POST", f"/ai/plan/{plan_id}/deny?reason={reason}")


@mcp.tool()
async def ai_audit(limit: int = 25) -> dict[str, Any]:
    """GET /ai/audit — recent audit events for the configured actor.

    Limited to the last 3 on the free tier (matching /ai/audit's own
    documented free-vs-paid behaviour); the full trail up to `limit` on
    Register/Cell.
    """
    return await _call("GET", f"/ai/audit?limit={limit}")


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
