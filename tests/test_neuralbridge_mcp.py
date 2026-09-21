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
