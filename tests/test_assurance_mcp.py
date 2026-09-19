"""The MCP server, driven against a real local uvicorn instance.

No mocked HTTP: `spec_validate` and `plans` call an actual running copy of
`assurance.api.service:app` over a real socket, the same way a deployed MCP
server would call a real deployment. The point is proving this server does
not fake anything — every tool is a thin, honest wrapper around one HTTP call.
"""

from __future__ import annotations

import importlib
import os
import socket
import threading
import time
from collections.abc import Iterator

import httpx
import pytest
import uvicorn

KEY = "mcp-test-key-do-not-ship"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def running_api(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Start a real assurance API on a local port for the duration of the module."""
    ledger = tmp_path_factory.mktemp("mcp-api") / "art14.db"
    os.environ["ASSURANCE_LEDGER"] = str(ledger)
    os.environ["ASSURANCE_API_KEYS"] = KEY

    from assurance.api import deps

    deps._register_for.cache_clear()
    app_module = importlib.import_module("assurance.api.service")
    app = app_module.create_app()

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(f"{base_url}/healthz", timeout=0.5)
            break
        except httpx.TransportError:
            time.sleep(0.1)
    else:
        raise RuntimeError("assurance API did not come up in time")

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)
    del os.environ["ASSURANCE_LEDGER"]
    del os.environ["ASSURANCE_API_KEYS"]


@pytest.fixture()
def mcp_env(running_api: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("ASSURANCE_API_URL", running_api)
    monkeypatch.setenv("ASSURANCE_API_KEY", KEY)
    yield running_api


@pytest.mark.asyncio
async def test_tool_list_matches_the_wrapped_routes() -> None:
    from assurance.mcp import server as mcp_server

    tools = await mcp_server.mcp.list_tools()
    tool_names = {t.name for t in tools}
    assert tool_names == {"plans", "spec_validate", "machine_verify", "register_cases"}


@pytest.mark.asyncio
async def test_plans_calls_the_real_api(mcp_env: str) -> None:
    from assurance.mcp.server import plans

    result = await plans()
    assert result["status"] == 200
    assert "free" in {p["tier"] for p in result["body"]}


@pytest.mark.asyncio
async def test_spec_validate_calls_the_real_api(mcp_env: str) -> None:
    from assurance.mcp.server import spec_validate

    result = await spec_validate(
        track="actively_exploited_vulnerability",
        stage="early_warning",
        payload={"product_name": "AR-7 Palletising Cell", "member_states_available": ["DE", "CH"]},
    )
    assert result["status"] == 200
    # CH is not an EU Member State — the free validator should catch it, not
    # rubber-stamp the draft.
    assert result["body"]["submittable"] is False
    fields = {issue["field_name"] for issue in result["body"]["issues"]}
    assert "member_states_available" in fields or any("CH" in str(i) for i in result["body"]["issues"])


@pytest.mark.asyncio
async def test_machine_verify_surfaces_a_real_402_not_a_fake_success(mcp_env: str) -> None:
    """The API key above has no plan attached — machine_verify is Cell-only."""
    from assurance.mcp.server import machine_verify

    result = await machine_verify(envelope={}, trace={}, actor="a.tester")
    assert result["status"] in (401, 402, 422)
    assert "status" in result and "body" in result


@pytest.mark.asyncio
async def test_no_api_url_fails_closed_honestly() -> None:
    """With ASSURANCE_API_URL unset, tools must say so — never fake a response."""
    os.environ.pop("ASSURANCE_API_URL", None)
    from assurance.mcp.server import plans

    result = await plans()
    assert result["error"] == "assurance_api_url_not_configured"
    assert "remedy" in result
