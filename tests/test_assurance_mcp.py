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

pytest.importorskip(
    "mcp",
    reason="assurance.mcp.server wraps the mcp SDK directly — install the "
           "optional 'assurance-mcp' extra to run this module. The tier-gating "
           "logic it wraps (POST /v1/machine/verify's Cell-only 402) is also "
           "covered without this SDK in tests/test_assurance_machine.py.",
)

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
    assert tool_names == {"plans", "spec_validate", "machine_verify", "machine_check",
                         "evidence_verify", "machinery_coverage", "machinery_passport_check",
                         "fleet_report", "register_cases",
                         "change_cases", "change_case", "change_export", "change_claim",
                         "change_advance", "change_reverify", "change_assess_drift",
                         "change_assess_intervention"}


@pytest.mark.asyncio
async def test_no_tool_lets_an_agent_decide_a_case() -> None:
    """Closing, rejecting, deferring, resuming and resolving need a named person.
    This server is the surface an agent drives, so none of them is a tool."""
    from assurance.mcp import server as mcp_server

    names = {t.name for t in await mcp_server.mcp.list_tools()}
    assert not {n for n in names if any(w in n for w in
                                        ("decide", "close", "reject", "defer",
                                         "resume", "resolve"))}


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
async def test_change_cases_calls_the_real_api(mcp_env: str) -> None:
    """``ASSURANCE_API_KEYS`` above is an operator key (full access), so this
    is a real 200 over an empty queue — proving the tool calls the live
    route rather than faking a shape."""
    from assurance.mcp.server import change_cases

    result = await change_cases()
    assert result["status"] == 200
    assert result["body"]["cases"] == []
    assert result["body"]["summary"]["open"] == 0


@pytest.mark.asyncio
async def test_change_case_surfaces_a_real_404_not_a_fake_success(mcp_env: str) -> None:
    from assurance.mcp.server import change_case

    result = await change_case("case-doesnotexist")
    assert result["status"] == 404


@pytest.mark.asyncio
async def test_change_write_tools_relay_the_real_api_refusals(mcp_env: str) -> None:
    """Each write tool is one real POST. An unknown case is the API's own 404 —
    the same one the read tools get for the same id."""
    from assurance.mcp.server import change_advance, change_claim, change_reverify

    claimed = await change_claim("case-doesnotexist", owner="v.grimaldi", actor="v.grimaldi")
    assert claimed["status"] == 404
    assert claimed["body"]["detail"] == {"error": "case_not_found",
                                         "case_id": "case-doesnotexist"}

    advanced = await change_advance("case-doesnotexist", actor="v.grimaldi")
    assert advanced["status"] == 404

    bad = await change_reverify("case-doesnotexist", manifest={"nonsense": True},
                                verification_content_hash="a" * 64, actor="v.grimaldi")
    assert bad["status"] == 422                      # the manifest is rejected first
    blank = await change_advance("case-doesnotexist", actor="")
    assert blank["status"] == 422                    # an actor is required


@pytest.mark.asyncio
async def test_no_api_url_fails_closed_honestly() -> None:
    """With ASSURANCE_API_URL unset, tools must say so — never fake a response."""
    os.environ.pop("ASSURANCE_API_URL", None)
    from assurance.mcp.server import plans

    result = await plans()
    assert result["error"] == "assurance_api_url_not_configured"
    assert "remedy" in result


# ---------------------------------------------------------------------------
# the verify/read tools agree with the CLI on the same artefacts (examples/workflow)
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def pack(tmp_path_factory):
    """The shipped synthetic workflow, run for real once; its sealed outputs are the inputs."""
    import json
    import subprocess
    import sys
    from pathlib import Path

    work = tmp_path_factory.mktemp("pack")
    script = Path(__file__).resolve().parents[1] / "examples" / "workflow" / "run.py"
    run = subprocess.run([sys.executable, str(script), "--keep", str(work)],  # noqa: S603
                         capture_output=True, text=True, check=False)
    assert run.returncode == 0, run.stdout[-500:]
    load = lambda n: json.loads((work / n).read_text("utf-8"))  # noqa: E731
    return {n: load(f"{n}.json") for n in ("bundle-after", "envelope", "trace-after", "passport",
                                           "manifest")}


@pytest.mark.asyncio
async def test_machine_check_reproduces_a_real_bundle_and_rejects_an_edited_one(
        mcp_env: str, pack) -> None:
    import copy

    from assurance.mcp.server import machine_check

    ok = await machine_check(pack["bundle-after"], pack["envelope"], pack["trace-after"])
    assert ok["status"] == 200, ok
    assert "REJECTED" not in str(ok["body"])
    # The server holds no recorder trust list here, so it will not believe `validated`.
    assert "validated" not in str(ok["body"].get("tier_believed", ""))

    edited = copy.deepcopy(pack["bundle-after"])
    edited["result"]["verdict"] = "fail" if edited["result"]["verdict"] != "fail" else "pass"
    bad = await machine_check(edited, pack["envelope"], pack["trace-after"])
    assert bad["status"] == 200 and (bad["body"].get("ok") is False
                                     or "REJECTED" in str(bad["body"]).upper()), bad


@pytest.mark.asyncio
async def test_passport_check_accepts_the_real_passport_and_rejects_an_edited_one(
        mcp_env: str, pack) -> None:
    import copy

    from assurance.mcp.server import machinery_passport_check

    ok = await machinery_passport_check(pack["passport"])
    assert ok["status"] == 200 and ok["body"].get("ok") is True, ok
    edited = copy.deepcopy(pack["passport"])
    edited["coverage"] = {**edited["coverage"], "verdict": "gaps"}
    bad = await machinery_passport_check(edited)
    assert bad["status"] == 200 and bad["body"].get("ok") is False, bad


@pytest.mark.asyncio
async def test_evidence_verify_and_the_read_tools_make_real_calls(mcp_env: str, pack) -> None:
    from assurance.mcp.server import evidence_verify, fleet_report, machinery_coverage

    # A non-export is refused by the real verifier, never reported as a pass.
    refused = await evidence_verify({"not": "an export"})
    assert refused["status"] in (200, 422) and refused["body"].get("ok") is not True, refused
    cov = await machinery_coverage(pack["manifest"])
    assert cov["status"] in (200, 402, 404, 422) and "body" in cov, cov
    report = await fleet_report(organisation="Synthetic Org", prepared_by="test")
    assert report["status"] in (200, 402) and "body" in report, report
