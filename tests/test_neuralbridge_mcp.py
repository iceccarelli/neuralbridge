"""The NeuralBridge AI MCP server, driven against a real local uvicorn
instance backed by a real PostgreSQL — no mocked HTTP, no mocked database.
Mirrors ``tests/test_assurance_mcp.py``'s own pattern: every tool is a
thin, honest wrapper around one HTTP call to a real deployment.
"""

from __future__ import annotations

import importlib
import os
import socket
import threading
import time
from collections.abc import Iterator

import asyncpg
import httpx
import pytest
import uvicorn

pytest.importorskip(
    "mcp",
    reason="neuralbridge.mcp.server wraps the mcp SDK directly — install the "
           "optional 'neuralbridge-ai-mcp' extra to run this module. The "
           "entitlement gating it wraps (the /ai control plane's real 402) is "
           "also covered without this SDK in tests/test_ai.py.",
)

PG_HOST = os.environ.get("NEURALBRIDGE_AI_PG_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("NEURALBRIDGE_AI_PG_PORT", "5432"))
PG_USER = os.environ.get("NEURALBRIDGE_AI_PG_USER", "neuralbridge")
PG_PASSWORD = os.environ.get("NEURALBRIDGE_AI_PG_PASSWORD", "neuralbridge_dev")
PG_DATABASE = os.environ.get("NEURALBRIDGE_AI_PG_TEST_DATABASE", "neuralbridge_ai_test")

KEY = "nb-mcp-test-key-do-not-ship"


def _postgres_reachable() -> bool:
    import asyncio

    async def _check() -> bool:
        try:
            conn = await asyncpg.connect(
                host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE, timeout=3,
            )
            await conn.close()
            return True
        except Exception:
            return False

    return asyncio.run(_check())


pytestmark = pytest.mark.skipif(
    not _postgres_reachable(),
    reason=f"No reachable PostgreSQL at {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DATABASE} — see docs/ai-local-setup.md.",
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def running_api(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """A real neuralbridge.main:app, with a real seeded postgres connection
    and a real (operator-key) entitlement store, on a local port."""
    import asyncio

    async def _seed_table() -> None:
        conn = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
        await conn.execute("DROP TABLE IF EXISTS mcp_test_customers")
        await conn.execute("CREATE TABLE mcp_test_customers (id serial primary key, name text)")
        await conn.execute("INSERT INTO mcp_test_customers (name) VALUES ('Acme Robotics')")
        await conn.close()

    asyncio.run(_seed_table())

    os.environ["NEURALBRIDGE_AI_PG_HOST"] = PG_HOST
    os.environ["NEURALBRIDGE_AI_PG_PORT"] = str(PG_PORT)
    os.environ["NEURALBRIDGE_AI_PG_USER"] = PG_USER
    os.environ["NEURALBRIDGE_AI_PG_PASSWORD"] = PG_PASSWORD
    os.environ["NEURALBRIDGE_AI_PG_DATABASE"] = PG_DATABASE
    os.environ["ASSURANCE_API_KEYS"] = KEY
    os.environ["ASSURANCE_ACCOUNTS"] = str(tmp_path_factory.mktemp("mcp-accounts") / "accounts.db")
    os.environ["NEURALBRIDGE_AI_STORE"] = str(tmp_path_factory.mktemp("mcp-ai-store") / "ai.db")

    import neuralbridge.api.dependencies as deps

    deps._adapter_registry = None
    deps._request_router = None
    deps._audit_logger = None
    deps._ai_store = None

    app_module = importlib.import_module("neuralbridge.main")
    app = app_module.create_app()

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}/api/v1"
    for _ in range(50):
        try:
            httpx.get(f"{base_url}/ai/connections", timeout=0.5)
            break
        except httpx.TransportError:
            time.sleep(0.1)
    else:
        raise RuntimeError("neuralbridge API did not come up in time")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)
    for var in ("NEURALBRIDGE_AI_PG_HOST", "NEURALBRIDGE_AI_PG_PORT", "NEURALBRIDGE_AI_PG_USER",
                "NEURALBRIDGE_AI_PG_PASSWORD", "NEURALBRIDGE_AI_PG_DATABASE",
                "ASSURANCE_API_KEYS", "ASSURANCE_ACCOUNTS", "NEURALBRIDGE_AI_STORE"):
        os.environ.pop(var, None)


@pytest.fixture()
def free_env(running_api: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NEURALBRIDGE_API_URL", running_api)
    monkeypatch.delenv("NEURALBRIDGE_AI_API_KEY", raising=False)
    monkeypatch.setenv("NEURALBRIDGE_AI_ACTOR", "mcp-free-tester")
    yield running_api


@pytest.fixture()
def paid_env(running_api: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("NEURALBRIDGE_API_URL", running_api)
    monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", KEY)
    monkeypatch.setenv("NEURALBRIDGE_AI_ACTOR", "mcp-paid-tester")
    yield running_api


@pytest.mark.asyncio
async def test_tool_list_matches_the_wrapped_routes() -> None:
    from neuralbridge.mcp import server as mcp_server

    tools = await mcp_server.mcp.list_tools()
    names = {t.name for t in tools}
    assert names == {
        "ai_list_connections", "ai_capabilities", "ai_read",
        "ai_plan_write", "ai_approve", "ai_deny", "ai_audit",
    }


@pytest.mark.asyncio
async def test_no_api_url_fails_closed_honestly() -> None:
    os.environ.pop("NEURALBRIDGE_API_URL", None)
    from neuralbridge.mcp.server import ai_list_connections

    result = await ai_list_connections()
    assert result["error"] == "neuralbridge_api_url_not_configured"
    assert "remedy" in result


@pytest.mark.asyncio
async def test_free_tools_call_the_real_api(free_env: str) -> None:
    from neuralbridge.mcp.server import ai_list_connections, ai_read

    result = await ai_list_connections()
    assert result["status"] == 200
    connections = result["body"]
    assert connections and connections[0]["source"] == "seeded_from_env"
    cid = connections[0]["id"]

    result = await ai_read(connection_id=cid, operation="list_tables", params={})
    assert result["status"] == 200
    assert "mcp_test_customers" in result["body"]["data"]


@pytest.mark.asyncio
async def test_plan_write_surfaces_a_real_402_not_a_fake_success(free_env: str) -> None:
    from neuralbridge.mcp.server import ai_list_connections, ai_plan_write

    connections = (await ai_list_connections())["body"]
    cid = connections[0]["id"]

    result = await ai_plan_write(
        connection_id=cid, operation="execute_sql", params={"sql": "UPDATE mcp_test_customers SET name='x'"}
    )
    assert result["status"] == 402
    assert result["body"]["detail"]["error"] == "plan_does_not_include_ai_control_plane"


@pytest.mark.asyncio
async def test_paid_plan_approve_loop_with_real_actor(paid_env: str) -> None:
    from neuralbridge.mcp.server import ai_approve, ai_list_connections, ai_plan_write

    connections = (await ai_list_connections())["body"]
    cid = connections[0]["id"]

    plan_result = await ai_plan_write(
        connection_id=cid, operation="execute_sql",
        params={"sql": "UPDATE mcp_test_customers SET name='Updated By Agent' WHERE id=1"},
    )
    assert plan_result["status"] == 200
    plan_id = plan_result["body"]["plan"]["id"]

    approve_result = await ai_approve(plan_id=plan_id)
    assert approve_result["status"] == 200
    assert approve_result["body"]["success"] is True
    assert approve_result["body"]["approved_by"] == "human_session:mcp-paid-tester"


# ── tenant isolation: the MCP tools inherit the API's boundary, no bypass ──


def _mint_two_account_keys() -> tuple[str, str]:
    from assurance.billing.accounts import AccountStore

    store = AccountStore(os.environ["ASSURANCE_ACCOUNTS"])
    a = store.upsert_account(email="mcp-a@example.com", tier="register", company="MCP Account A")
    b = store.upsert_account(email="mcp-b@example.com", tier="register", company="MCP Account B")
    return store.issue_key(a.id, label="mcp-a"), store.issue_key(b.id, label="mcp-b")


def _bind_over_http(base_url: str, key: str, name: str) -> str:
    r = httpx.post(
        f"{base_url}/ai/connections",
        headers={"X-API-Key": key, "X-NB-Actor": "mcp-tenancy-binder"},
        json={"name": name, "host": PG_HOST, "port": PG_PORT, "user": PG_USER,
              "password": PG_PASSWORD, "database": PG_DATABASE},
        timeout=10.0,
    )
    assert r.status_code == 200, r.text
    return r.json()["id"]


@pytest.mark.asyncio
async def test_mcp_tools_cannot_cross_the_tenant_boundary(running_api: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from neuralbridge.mcp.server import (
        ai_approve,
        ai_audit,
        ai_capabilities,
        ai_deny,
        ai_list_connections,
        ai_plan_write,
        ai_read,
    )

    key_a, key_b = _mint_two_account_keys()
    a_name = "MCP-A-PRIVATE-DB"
    a_id = _bind_over_http(running_api, key_a, a_name)
    monkeypatch.setenv("NEURALBRIDGE_API_URL", running_api)

    # Account A, through MCP, uses its own connection and proposes a write.
    monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", key_a)
    monkeypatch.setenv("NEURALBRIDGE_AI_ACTOR", "mcp-tenant-a")
    assert a_id in {c["id"] for c in (await ai_list_connections())["body"]}
    assert (await ai_read(connection_id=a_id, operation="query", params={"sql": "SELECT 1 AS one"}))["status"] == 200
    planned = await ai_plan_write(
        connection_id=a_id, operation="execute_sql", params={"sql": "UPDATE mcp_test_customers SET name=name"}
    )
    assert planned["status"] == 200
    plan_id = planned["body"]["plan"]["id"]

    # Account B and an anonymous MCP client: A's connection and plan do not exist for them.
    for key in (key_b, None):
        if key:
            monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", key)
        else:
            monkeypatch.delenv("NEURALBRIDGE_AI_API_KEY", raising=False)
        monkeypatch.setenv("NEURALBRIDGE_AI_ACTOR", "mcp-tenant-a")  # same actor label: grants nothing

        listing = await ai_list_connections()
        assert a_name not in str(listing) and a_id not in str(listing)
        read_attempt = await ai_read(connection_id=a_id, operation="query", params={"sql": "SELECT current_user"})
        assert read_attempt["status"] == 404
        assert (await ai_capabilities(connection_id=a_id))["status"] == 404
        assert a_id not in str(await ai_audit())
        if key:
            blocked = await ai_plan_write(
                connection_id=a_id, operation="execute_sql", params={"sql": "DELETE FROM mcp_test_customers"}
            )
            assert blocked["status"] == 404
            assert (await ai_approve(plan_id=plan_id))["status"] == 404
            assert (await ai_deny(plan_id=plan_id))["status"] == 404
        else:
            assert (await ai_approve(plan_id=plan_id))["status"] == 402

    # A tool argument cannot smuggle extra query parameters or rewrite the path.
    monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", key_b)
    odd = await ai_capabilities(connection_id=f"{a_id}&connection_id=x")
    assert odd["status"] == 404 and "&connection_id=x" in odd["body"]["detail"]

    # The owner's plan is still pending and still approvable by its owner.
    monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", key_a)
    approved = await ai_approve(plan_id=plan_id)
    assert approved["status"] == 200 and approved["body"]["success"] is True


@pytest.mark.asyncio
async def test_mcp_plan_id_cannot_rewrite_the_request_path(running_api: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Without percent-encoding, ``plan_id = "<id>/deny?"`` turns an ``ai_approve``
    call into ``POST /ai/plan/<id>/deny`` — an action the caller did not ask for."""
    from neuralbridge.mcp.server import ai_approve, ai_plan_write

    key_a, _ = _mint_two_account_keys()
    a_id = _bind_over_http(running_api, key_a, "MCP-QUOTE-DB")
    monkeypatch.setenv("NEURALBRIDGE_API_URL", running_api)
    monkeypatch.setenv("NEURALBRIDGE_AI_API_KEY", key_a)
    monkeypatch.setenv("NEURALBRIDGE_AI_ACTOR", "mcp-quote")
    planned = await ai_plan_write(
        connection_id=a_id, operation="execute_sql", params={"sql": "UPDATE mcp_test_customers SET name=name"}
    )
    plan_id = planned["body"]["plan"]["id"]

    result = await ai_approve(plan_id=f"{plan_id}/deny?")
    assert result["status"] == 404

    status = httpx.get(f"{running_api}/ai/plan/{plan_id}", headers={"X-API-Key": key_a}, timeout=10.0).json()
    assert status["status"] == "pending_approval"
