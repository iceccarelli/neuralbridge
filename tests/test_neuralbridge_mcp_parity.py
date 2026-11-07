# ruff: noqa: F811, F401  (fixtures are imported by name)
"""MCP and HTTP are two doors into the same domain functions: same gates, same answers.

* ``neuralbridge.mcp.server`` (the /ai tools) is compared with direct HTTP calls to the same
  running API, with the same headers: status, body shape, provenance fields, receipts.
* ``neuralbridge.core.gateway.MCPGateway`` (generic adapter dispatch) is compared with
  ``POST /adapters/{type}/execute`` across anonymous / invalid / free / paid callers: the
  outcome class must match for every case, and a refused call must never reach the adapter.

Real uvicorn server, real PostgreSQL, real accounts and audit sink. LOCAL evidence.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import os
import socket
import threading
import time
from collections.abc import Iterator

import httpx
import pytest
import uvicorn

pytest.importorskip("mcp", reason="neuralbridge.mcp.server needs the optional 'neuralbridge-ai-mcp' extra")

from .platform_support import (  # noqa: E402
    PG_DATABASE,
    PG_HOST,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    pg_run,
    requires_postgres,
)

pytestmark = requires_postgres

OPERATOR = "nb-parity-operator-key-0123456789abcdef0123456789"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Stack:
    def __init__(self, base: str, paid: str, other_paid: str, free: str, owner_ids: dict[str, str]) -> None:
        self.base, self.paid, self.other_paid, self.free, self.owner_ids = base, paid, other_paid, free, owner_ids


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    pg_run("DROP TABLE IF EXISTS parity_t", "CREATE TABLE parity_t (id int)")
    root = tmp_path_factory.mktemp("parity")
    saved = {k: os.environ.get(k) for k in (
        "NEURALBRIDGE_AI_PG_HOST", "NEURALBRIDGE_AI_PG_PORT", "NEURALBRIDGE_AI_PG_USER", "NEURALBRIDGE_AI_PG_PASSWORD",
        "NEURALBRIDGE_AI_PG_DATABASE", "ASSURANCE_API_KEYS", "ASSURANCE_ACCOUNTS", "NEURALBRIDGE_AI_STORE",
        "NEURALBRIDGE_AUDIT_DB", "NEURALBRIDGE_RATE_LIMIT_PER_MINUTE")}
    os.environ.update({
        "NEURALBRIDGE_AI_PG_HOST": PG_HOST, "NEURALBRIDGE_AI_PG_PORT": str(PG_PORT), "NEURALBRIDGE_AI_PG_USER": PG_USER,
        "NEURALBRIDGE_AI_PG_PASSWORD": PG_PASSWORD, "NEURALBRIDGE_AI_PG_DATABASE": PG_DATABASE,
        "ASSURANCE_API_KEYS": OPERATOR, "ASSURANCE_ACCOUNTS": str(root / "accounts.db"),
        "NEURALBRIDGE_AI_STORE": str(root / "ai.db"), "NEURALBRIDGE_AUDIT_DB": str(root / "audit.db"),
        "NEURALBRIDGE_RATE_LIMIT_PER_MINUTE": "0",
    })
    os.environ.pop("ASSURANCE_ALLOW_UNAUTHENTICATED", None)
    from assurance.api import deps as adeps
    from assurance.billing.accounts import AccountStore

    adeps._register_for.cache_clear()
    adeps._accounts_for.cache_clear()
    store = AccountStore(os.environ["ASSURANCE_ACCOUNTS"])
    a = store.upsert_account(email="pa@example.com", tier="register", company="Parity A")
    b = store.upsert_account(email="pb@example.com", tier="register", company="Parity B")
    f = store.upsert_account(email="pf@example.com", tier="free", company="Parity F")
    keys = [store.issue_key(x.id, label="parity") for x in (a, b, f)]

    import neuralbridge.api.dependencies as deps

    deps._adapter_registry = deps._request_router = deps._audit_logger = deps._ai_store = None
    app = importlib.import_module("neuralbridge.main").create_app()
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}/api/v1"
    for _ in range(80):
        try:
            httpx.get(f"{base}/health/live", timeout=0.5)
            break
        except httpx.TransportError:
            time.sleep(0.1)
    else:
        raise RuntimeError("API did not come up")
    yield Stack(base, keys[0], keys[1], keys[2], {"paid": a.id, "other": b.id, "free": f.id})
    server.should_exit = True
    thread.join(timeout=5)
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    pg_run("DROP TABLE IF EXISTS parity_t")


def mcp_env(monkeypatch: pytest.MonkeyPatch, st: Stack, key: str | None, actor: str = "parity-actor") -> None:
    monkeypatch.setenv("NEURALBRIDGE_API_URL", st.base)
    monkeypatch.setenv("NEURALBRIDGE_AI_ACTOR", actor)
    if key:
        monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", key)
    else:
        monkeypatch.delenv("NEURALBRIDGE_AI_API_KEY", raising=False)


def http(st: Stack, method: str, path: str, key: str | None, actor: str = "parity-actor", **kw) -> httpx.Response:
    """The request the MCP server would send: same URL, same headers."""
    headers = {"content-type": "application/json", "X-NB-Actor": actor}
    if key:
        headers["X-API-Key"] = key
    return httpx.request(method, f"{st.base}{path}", headers=headers, timeout=30, **kw)


def tool(name: str):
    return getattr(importlib.import_module("neuralbridge.mcp.server"), name)


def shape(value):
    """The structure of a JSON value (key sets and types), ignoring ids/timestamps/values."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [shape(value[0])] if value else []
    return type(value).__name__


def bind(st: Stack, key: str, name: str) -> dict:
    r = http(st, "POST", "/ai/connections", key, json={
        "name": name, "host": PG_HOST, "port": PG_PORT, "user": PG_USER, "password": PG_PASSWORD,
        "database": PG_DATABASE})
    assert r.status_code == 200, r.text
    return r.json()


# ───────────────────────────── /ai tools == /ai routes ─────────────────────────────


class TestAiToolsMatchTheRoutes:
    def test_every_tool_is_one_documented_route_and_every_ai_route_has_a_tool(self) -> None:
        import inspect
        import re

        server = importlib.import_module("neuralbridge.mcp.server")
        names = {n for n, f in inspect.getmembers(server, inspect.iscoroutinefunction) if n.startswith("ai_")}
        assert names == {"ai_list_connections", "ai_capabilities", "ai_read", "ai_plan_write", "ai_approve",
                         "ai_deny", "ai_audit"}
        claimed = set()
        for n in names:
            doc = inspect.getdoc(getattr(server, n)) or ""
            m = re.match(r"(GET|POST) (/ai/[^\s]+)", doc)
            assert m, f"{n} must say which route it wraps"
            claimed.add((m.group(1), re.sub(r"\{[^}]+\}", "{plan_id}", m.group(2))))
        from neuralbridge.main import create_app

        paths = create_app().openapi()["paths"]
        routes = {
            (method.upper(), re.sub(r"\{[^}]+\}", "{plan_id}", path.removeprefix("/api/v1")))
            for path, ops in paths.items() if path.startswith("/api/v1/ai/") for method in ops
        }
        assert claimed <= routes, claimed - routes
        # Deliberately not exposed to agents: credential handling (bind / rotate / revoke / unbind),
        # plan inspection and the session probe. A change here is a decision, not an accident.
        assert routes - claimed == {
            ("GET", "/ai/session"), ("POST", "/ai/connections"), ("DELETE", "/ai/connections/{plan_id}"),
            ("POST", "/ai/connections/{plan_id}/rotate"), ("POST", "/ai/connections/{plan_id}/revoke"),
            ("GET", "/ai/plan/{plan_id}"),
        }

    def test_discovery_and_reads_return_what_the_route_returns(self, stack: Stack, monkeypatch) -> None:
        conn = bind(stack, stack.paid, "parity-read")
        mcp_env(monkeypatch, stack, stack.paid)
        listed = asyncio.run(tool("ai_list_connections")())
        assert listed["status"] == 200 and listed["body"] == http(stack, "GET", "/ai/connections", stack.paid).json()
        caps = asyncio.run(tool("ai_capabilities")(conn["id"]))
        assert caps["body"] == http(stack, "GET", "/ai/capabilities", stack.paid, params={"connection_id": conn["id"]}).json()

        via_mcp = asyncio.run(tool("ai_read")(conn["id"], "query", {"sql": "SELECT 1 AS one"}))
        via_http = http(stack, "POST", "/ai/read", stack.paid, json={
            "connection_id": conn["id"], "operation": "query", "params": {"sql": "SELECT 1 AS one"}})
        assert via_mcp["status"] == via_http.status_code == 200
        assert shape(via_mcp["body"]) == shape(via_http.json())
        assert via_mcp["body"]["data"] == via_http.json()["data"] == [{"one": 1}]
        assert via_mcp["body"]["provenance"]["mocked"] is False and via_mcp["body"]["provenance"]["connection_id"] == conn["id"]

    def test_the_approval_receipt_has_the_same_fields_through_either_door(self, stack: Stack, monkeypatch) -> None:
        conn = bind(stack, stack.paid, "parity-write")
        mcp_env(monkeypatch, stack, stack.paid, actor="parity-agent")
        req = {"connection_id": conn["id"], "operation": "execute_sql", "params": {"sql": "INSERT INTO parity_t VALUES (1)"}}

        plan_mcp = asyncio.run(tool("ai_plan_write")(**req))
        plan_http = http(stack, "POST", "/ai/plan", stack.paid, actor="parity-agent", json=req)
        assert plan_mcp["status"] == plan_http.status_code == 200
        assert shape(plan_mcp["body"]) == shape(plan_http.json())
        assert plan_mcp["body"]["plan"]["status"] == "pending_approval" == plan_http.json()["plan"]["status"]
        assert plan_mcp["body"]["plan"]["proposed_by"] == plan_http.json()["plan"]["proposed_by"] == "human_session:parity-agent"

        receipt_mcp = asyncio.run(tool("ai_approve")(plan_mcp["body"]["plan"]["id"]))
        receipt_http = http(stack, "POST", f"/ai/plan/{plan_http.json()['plan']['id']}/approve", stack.paid, actor="parity-agent")
        assert receipt_mcp["status"] == receipt_http.status_code == 200
        a, b = receipt_mcp["body"], receipt_http.json()
        assert shape(a) == shape(b)
        assert set(a["provenance"]) == set(b["provenance"]) == {
            "connection_id", "connection_name", "adapter_type", "tool", "request_id", "timestamp", "mocked"}
        assert a["approved_by"] == b["approved_by"] == "human_session:parity-agent"
        assert a["success"] is b["success"] is True
        assert a["provenance"]["mocked"] is False and a["provenance"]["tool"] == "execute_sql"

        # re-approving is the same refusal through both doors
        again_mcp = asyncio.run(tool("ai_approve")(plan_mcp["body"]["plan"]["id"]))
        again_http = http(stack, "POST", f"/ai/plan/{plan_mcp['body']['plan']['id']}/approve", stack.paid, actor="parity-agent")
        assert again_mcp["status"] == again_http.status_code == 409 and again_mcp["body"] == again_http.json()

    def test_denial_and_audit_match(self, stack: Stack, monkeypatch) -> None:
        conn = bind(stack, stack.paid, "parity-deny")
        mcp_env(monkeypatch, stack, stack.paid)
        pid = asyncio.run(tool("ai_plan_write")(conn["id"], "execute_sql", {"sql": "DELETE FROM parity_t"}))["body"]["plan"]["id"]
        denied = asyncio.run(tool("ai_deny")(pid, "not now"))
        assert denied["status"] == 200 and denied["body"]["status"] == "denied" and denied["body"]["deny_reason"] == "not now"
        again = http(stack, "POST", f"/ai/plan/{pid}/deny", stack.paid, params={"reason": "x"})
        assert again.status_code == 409
        via_mcp = asyncio.run(tool("ai_audit")(500))["body"]
        via_http = http(stack, "GET", "/ai/audit", stack.paid, params={"limit": 500}).json()
        assert [e["event_id"] for e in via_mcp] == [e["event_id"] for e in via_http]
        assert {"plan_propose", "plan_deny"} <= {e["event_type"] for e in via_http}

    def test_refusals_are_identical_through_both_doors(self, stack: Stack, monkeypatch) -> None:
        mine = bind(stack, stack.paid, "parity-mine")
        # 402: a free account cannot propose a write
        mcp_env(monkeypatch, stack, stack.free)
        body = {"connection_id": mine["id"], "operation": "execute_sql", "params": {"sql": "INSERT INTO parity_t VALUES (2)"}}
        m = asyncio.run(tool("ai_plan_write")(**body))
        r = http(stack, "POST", "/ai/plan", stack.free, json=body)
        assert m["status"] == r.status_code == 402 and m["body"] == r.json()
        # 404: another tenant's connection reads exactly like a missing one
        mcp_env(monkeypatch, stack, stack.other_paid)
        m = asyncio.run(tool("ai_read")(mine["id"], "query", {"sql": "SELECT 1"}))
        r = http(stack, "POST", "/ai/read", stack.other_paid, json={
            "connection_id": mine["id"], "operation": "query", "params": {"sql": "SELECT 1"}})
        assert m["status"] == r.status_code == 404 and m["body"] == r.json()
        # 409: revoked
        mcp_env(monkeypatch, stack, stack.paid)
        assert http(stack, "POST", f"/ai/connections/{mine['id']}/revoke", stack.paid).status_code == 200
        m = asyncio.run(tool("ai_read")(mine["id"], "query", {"sql": "SELECT 1"}))
        r = http(stack, "POST", "/ai/read", stack.paid, json={
            "connection_id": mine["id"], "operation": "query", "params": {"sql": "SELECT 1"}})
        assert m["status"] == r.status_code == 409 and m["body"] == r.json()
        # 403: policy refusal (a URL smuggled into a parameter)
        other = bind(stack, stack.paid, "parity-policy")
        bad = {"connection_id": other["id"], "operation": "query", "params": {"sql": "SELECT 'http://evil.example'"}}
        m = asyncio.run(tool("ai_read")(**bad))
        r = http(stack, "POST", "/ai/read", stack.paid, json=bad)
        assert m["status"] == r.status_code == 403 and m["body"] == r.json()

    def test_the_audit_trail_names_the_same_actor_whichever_door_was_used(self, stack: Stack, monkeypatch) -> None:
        conn = bind(stack, stack.paid, "parity-actor")
        mcp_env(monkeypatch, stack, stack.paid, actor="agent-via-mcp")
        asyncio.run(tool("ai_read")(conn["id"], "health_check", {}))
        http(stack, "POST", "/ai/read", stack.paid, actor="agent-via-http", json={
            "connection_id": conn["id"], "operation": "health_check", "params": {}})
        events = [e for e in http(stack, "GET", "/ai/audit", stack.paid, params={"limit": 500}).json()
                  if e["event_type"] == "adapter_call" and e["resource"] == f"postgres:{conn['id']}"]
        assert {e["actor"] for e in events} == {"human_session:agent-via-mcp", "human_session:agent-via-http"}
        assert {e["details"]["owner"] for e in events} == {stack.owner_ids["paid"]}


# ───────────────────────────── generic gateway == raw adapters route ─────────────────────────────


class Probe:
    def __init__(self, adapter_type: str) -> None:
        self.adapter_type = adapter_type
        self.calls = 0

    async def execute(self, operation, params):
        self.calls += 1
        return {"ok": True}


CASES = [
    ("slack", "list_channels"),      # free discovery operation
    ("slack", "send_message"),       # write-shaped: paid
    ("rest", "get"),                 # a credentialed outbound call: paid even for GET
    ("salesforce", "query"),         # free discovery operation
    ("salesforce", "delete_record"),  # paid
    ("salesforce", "not_an_operation"),  # unrecognised -> treated as paid
]
CALLERS = ["anonymous", "invalid", "free", "paid"]


def outcome_http(status: int) -> str:
    return {200: "allowed", 401: "unauthorized", 402: "payment_required", 403: "forbidden"}.get(status, f"http_{status}")


class TestGatewayMatchesTheRawAdaptersRoute:
    def test_the_same_gate_decides_for_every_caller_and_operation(self, stack: Stack) -> None:
        import neuralbridge.api.dependencies as deps
        from neuralbridge.core.gateway import MCPGateway, MCPToolDefinition
        from neuralbridge.core.router import RequestRouter
        from neuralbridge.security.audit import AuditLogger, SQLiteAuditStorage

        probes = {t: Probe(t) for t in ("slack", "rest", "salesforce")}
        for p in probes.values():
            deps.get_adapter_registry().register(p, key=p.adapter_type)  # type: ignore[arg-type]
        audit = AuditLogger(SQLiteAuditStorage(os.environ["NEURALBRIDGE_AUDIT_DB"]))
        gateway = MCPGateway(RequestRouter(deps.get_adapter_registry(), audit), audit)
        for t in probes:
            gateway.register_tool(MCPToolDefinition(name=f"{t}_tool", description=t, input_schema={}, adapter_type=t))
        keys = {"anonymous": None, "invalid": "nb-not-a-real-key", "free": stack.free, "paid": stack.paid}

        mismatches = []
        for adapter_type, operation in CASES:
            for caller, key in keys.items():
                before = probes[adapter_type].calls
                r = http(stack, "POST", f"/adapters/{adapter_type}/execute", key, json={"operation": operation, "params": {}})
                ran_http = probes[adapter_type].calls - before
                via_http = outcome_http(r.status_code)

                before = probes[adapter_type].calls
                args = {"operation": operation, **({"api_key": key} if key else {})}
                resp = asyncio.run(gateway.handle_request(
                    {"jsonrpc": "2.0", "id": "1", "method": "tools/call",
                     "params": {"name": f"{adapter_type}_tool", "arguments": args}}))
                ran_mcp = probes[adapter_type].calls - before
                if resp.error is None:
                    via_mcp = "allowed"
                elif "invalid_api_key" in resp.error["message"]:
                    via_mcp = "unauthorized"
                else:
                    via_mcp = outcome_http(resp.error["data"]["status"])
                if (via_http, ran_http) != (via_mcp, ran_mcp):
                    mismatches.append((adapter_type, operation, caller, (via_http, ran_http), (via_mcp, ran_mcp)))
                if adapter_type == "rest":
                    # not just "both doors agree": REST makes a credentialed outbound call, so it is
                    # never free for a caller without the entitlement, whichever door they use
                    assert (via_http == "allowed") == (caller == "paid"), (caller, via_http)
                    assert (via_mcp == "allowed") == (caller == "paid"), (caller, via_mcp)
                # a refused call never reached the adapter, through either door
                assert (ran_http == 1) == (via_http == "allowed")
                assert (ran_mcp == 1) == (via_mcp == "allowed")
        assert mismatches == []

    def test_refusals_and_executions_are_audited_with_actor_and_tenant_through_the_gateway(self, stack: Stack) -> None:
        import neuralbridge.api.dependencies as deps
        from neuralbridge.core.gateway import MCPGateway, MCPToolDefinition
        from neuralbridge.core.router import RequestRouter
        from neuralbridge.security.audit import AuditLogger, SQLiteAuditStorage

        probe = Probe("slack")
        deps.get_adapter_registry().register(probe, key="slack")  # type: ignore[arg-type]
        audit = AuditLogger(SQLiteAuditStorage(os.environ["NEURALBRIDGE_AUDIT_DB"]))
        gateway = MCPGateway(RequestRouter(deps.get_adapter_registry(), audit), audit, default_actor="gw-agent")
        gateway.register_tool(MCPToolDefinition(name="slack_tool", description="", input_schema={}, adapter_type="slack"))

        def call(key, op):
            return asyncio.run(gateway.handle_request({"jsonrpc": "2.0", "id": op, "method": "tools/call", "params": {
                "name": "slack_tool", "arguments": {"operation": op, "api_key": key}}}))

        assert call(stack.free, "send_message").error["data"]["status"] == 402
        assert call(stack.paid, "send_message").error is None
        mine = http(stack, "GET", "/ai/audit", stack.paid, params={"limit": 500}).json()
        gw = [e for e in mine if e["actor"] == "mcp:gw-agent"]
        assert any(e["event_type"] == "adapter_call" and e["resource"] == "slack" for e in gw)
        assert all(e["details"]["owner"] == stack.owner_ids["paid"] for e in gw)
        free_trail = http(stack, "GET", "/ai/audit", stack.free, params={"limit": 50}).json()
        denied = [e for e in free_trail if e["event_type"] == "entitlement_denied" and e["details"]["surface"] == "mcp_gateway"]
        assert denied and denied[0]["actor"] == "mcp:gw-agent" and denied[0]["details"]["owner"] == stack.owner_ids["free"]

    def test_discovery_and_protocol_basics(self, stack: Stack) -> None:
        from neuralbridge.core.gateway import MCPGateway, MCPToolDefinition
        from neuralbridge.core.router import AdapterRegistry, RequestRouter
        from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

        audit = AuditLogger(InMemoryAuditStorage())
        gw = MCPGateway(RequestRouter(AdapterRegistry(), audit), audit)
        gw.register_tool(MCPToolDefinition(name="t1", description="d", input_schema={"type": "object"}, adapter_type="slack"))

        def rpc(method, params=None):
            return asyncio.run(gw.handle_request({"jsonrpc": "2.0", "id": "x", "method": method, "params": params or {}}))

        assert rpc("initialize").result["serverInfo"]["name"] == "NeuralBridge"
        assert rpc("tools/list").result == [{"name": "t1", "description": "d", "inputSchema": {"type": "object"}}]
        assert rpc("ping").result == {"status": "pong"}
        assert rpc("nope").error["code"] == -32601
        assert "Unknown tool" in rpc("tools/call", {"name": "missing"}).error["message"]
        assert asyncio.run(gw.handle_request("{not json")).error["code"] == -32700
