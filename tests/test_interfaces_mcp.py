"""No MCP tool can decide, waive, resume or resolve — proven from the outside.

The MCP server is the surface an agent drives. ``decide`` (close / reject /
defer), ``resume``, ``resolve-decision`` and ``waive-reverification`` are the
human decisions, so no tool reaches them. Three independent checks:

* the tool list is exactly the one ``deploy/assurance/CHANGE.md`` documents;
* every tool, called with hostile arguments, makes only calls on an allow-list
  of (method, route) pairs, and none of them is a decision route;
* against a real API, the tools can take a case to the stop where a person is
  needed and no further.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from . import interfaces_fixtures as fx  # noqa: E402
from .test_assurance_change import item, manifest  # noqa: E402

live_api = fx.live_api

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "deploy" / "assurance" / "CHANGE.md"

#: The routes a tool is allowed to call, as (method, regex over the path).
_ID = r"[^/]+"
ALLOWED = [
    ("GET", r"/v1/plans"),
    ("GET", r"/v1/capabilities"),
    ("POST", r"/v1/spec/validate"),
    ("POST", r"/v1/machine/verify"),
    ("GET", r"/v1/check/services"),
    ("POST", r"/v1/check/machine"),
    ("POST", r"/v1/check/fleet-machine"),
    ("POST", r"/v1/machine/bundle/check"),
    ("POST", r"/v1/evidence/verify"),
    ("POST", r"/v1/machinery/coverage"),
    ("POST", r"/v1/machinery/passport/check"),
    ("GET", r"/v1/fleet/report"),
    ("GET", r"/v1/cases"),
    ("GET", r"/v1/change/cases"),
    ("GET", rf"/v1/change/cases/{_ID}"),
    ("GET", rf"/v1/change/cases/{_ID}/export"),
    ("POST", rf"/v1/change/cases/{_ID}/claim"),
    ("POST", rf"/v1/change/cases/{_ID}/advance"),
    ("POST", rf"/v1/change/cases/{_ID}/reverification"),
    ("POST", r"/v1/change/assess/drift"),
    ("POST", r"/v1/change/assess/intervention"),
]
#: The read-only tools (a GET, or a POST that answers a question and records nothing). Kept apart
#: from ALLOWED so a test can say "these, and only these, never write": nothing here may ever
#: be moved to a route that seals, signs, pins, closes or decides.
READ_ONLY_ALLOWED = [
    ("GET", r"/v1/spec/fields"),
    ("GET", rf"/v1/cases/{_ID}"),
    ("GET", rf"/v1/cases/{_ID}/export"),
    ("GET", r"/v1/register"),
    ("GET", r"/v1/register/breaches"),
    ("GET", r"/v1/ledger/verify"),
    ("GET", r"/v1/ledger/attest/log"),
    ("GET", r"/v1/ledger/attest/key"),
    ("POST", r"/v1/ledger/attest/verify"),
    ("POST", r"/v1/machine/separation"),
    ("POST", r"/v1/machinery/diff"),
    ("GET", r"/v1/fleet/machines"),
    ("GET", r"/v1/fleet/observations"),
    ("POST", r"/v1/fleet/declaration/check"),
    ("GET", r"/v1/value"),
    ("GET", rf"/v1/change/cases/{_ID}/replay"),
    ("GET", r"/v1/supplier/trust"),
    ("POST", r"/v1/supplier/trust/evaluate"),
]
ALLOWED += READ_ONLY_ALLOWED
#: The tools added for read-only parity, each with the one call it documents.
READ_ONLY_TOOLS = {
    "spec_fields": ("GET", "/v1/spec/fields"),
    "art14_case": ("GET", "/v1/cases/case-0123456789abcdef"),
    "art14_register": ("GET", "/v1/register"),
    "art14_breaches": ("GET", "/v1/register/breaches"),
    "art14_export": ("GET", "/v1/cases/case-0123456789abcdef/export"),
    "ledger_verify": ("GET", "/v1/ledger/verify"),
    "attest_log": ("GET", "/v1/ledger/attest/log"),
    "attest_verify": ("POST", "/v1/ledger/attest/verify"),
    "attest_service_key": ("GET", "/v1/ledger/attest/key"),
    "machine_separation": ("POST", "/v1/machine/separation"),
    "machinery_diff": ("POST", "/v1/machinery/diff"),
    "fleet_machines": ("GET", "/v1/fleet/machines"),
    "fleet_observations": ("GET", "/v1/fleet/observations"),
    "fleet_declaration_check": ("POST", "/v1/fleet/declaration/check"),
    "value_position": ("GET", "/v1/value"),
    "change_replay": ("GET", "/v1/change/cases/case-0123456789abcdef/replay"),
    "supplier_trust_list": ("GET", "/v1/supplier/trust"),
    "supplier_trust_check": ("POST", "/v1/supplier/trust/evaluate"),
}
#: Path segments that mean a human decision. None may appear in any call.
FORBIDDEN = ("decision", "resume", "resolve", "waive", "reject", "defer", "close")
HOSTILE = ["case-x/decision", "case-x/../resume", "x/waive-reverification?", "x#/decision",
           "..%2fdecision", "x/resolve-decision", "a b", "case-ok"]


def documented_tools() -> set[str]:
    m = re.search(r"MCP tools \(exactly these\): (.+)", DOC.read_text(encoding="utf-8"))
    assert m, "CHANGE.md must carry the line 'MCP tools (exactly these): a, b, ...'"
    return {t.strip() for t in m.group(1).split(",") if t.strip()}


@pytest.mark.asyncio
async def test_the_tool_list_is_exactly_what_is_documented() -> None:
    from assurance.mcp import server

    assert {t.name for t in await server.mcp.list_tools()} == documented_tools()


@pytest.mark.asyncio
async def test_no_tool_assesses_an_advisory() -> None:
    """An advisory is third-party content; a case opened from an unsigned one is the
    attack the signed feed exists to stop. Only a person opens that case."""
    from assurance.mcp import server

    for tool in await server.mcp.list_tools():
        assert "advisory" not in tool.name, tool.name
        assert "/assess/advisory" not in (tool.description or ""), tool.name


@pytest.mark.asyncio
async def test_no_tool_name_or_description_offers_a_decision() -> None:
    from assurance.mcp import server

    for tool in await server.mcp.list_tools():
        assert not any(w in tool.name for w in FORBIDDEN), tool.name
        text = (tool.description or "").lower()
        # A tool may say it cannot decide; it may not say it can.
        assert "close a case" not in text.replace("deliberately no tool here to close", "")


@pytest.mark.asyncio
async def test_every_tool_makes_only_allowed_calls_whatever_it_is_passed(monkeypatch) -> None:
    from assurance.mcp import server

    seen: list[tuple[str, str]] = []

    async def record(method: str, path: str, *, json_body: Any = None, params: Any = None):
        seen.append((method, path))
        return {"status": 200, "body": {}}

    monkeypatch.setattr(server, "_call", record)

    for tool in await server.mcp.list_tools():
        fn = getattr(server, tool.name)
        params = inspect.signature(fn).parameters
        for hostile in HOSTILE:
            kwargs: dict[str, Any] = {}
            for name, p in params.items():
                ann = str(p.annotation)
                if "dict" in ann:
                    kwargs[name] = {}
                elif p.default is not inspect.Parameter.empty:
                    kwargs[name] = hostile if "str" in ann else p.default
                else:
                    kwargs[name] = hostile
            await fn(**kwargs)

    assert seen, "the recorder saw nothing; the test would pass vacuously"
    for method, path in seen:
        assert any(method == m and re.fullmatch(rx, path) for m, rx in ALLOWED), (method, path)
        # A hostile id is one percent-encoded segment; it is never a route word.
        assert not {"decision", "resume", "resolve-decision",
                    "waive-reverification"} & set(path.split("/")), path
    # Every call that carried a hostile id kept it inside one segment.


@pytest.mark.asyncio
async def test_a_hostile_id_never_leaves_the_process_and_a_real_unknown_one_is_a_404(
        live_api, monkeypatch) -> None:
    """The API server decodes %2F before routing, so an id like 'case-x/decision' cannot
    be made safe by encoding it. The tools refuse it instead, before any call."""
    from assurance.mcp import server

    _, headers = live_api.account("mcp-hostile@example.de")
    monkeypatch.setenv("ASSURANCE_API_URL", live_api.url)
    monkeypatch.setenv("ASSURANCE_API_KEY", headers["X-API-Key"])
    def calls(case_id):
        return (server.change_case(case_id), server.change_export(case_id),
                server.change_claim(case_id, owner="v.grimaldi", actor="v.grimaldi"),
                server.change_advance(case_id, actor="v.grimaldi"),
                server.change_reverify(case_id, manifest={}, actor="v.grimaldi",
                                       verification_content_hash="a" * 64))

    for hostile in [h for h in HOSTILE if h != "case-ok"]:
        for call in calls(hostile):
            result = await call
            assert result["error"] == "invalid_case_id" and "status" not in result, hostile
    for call in calls("case-0123456789abcdef"):
        result = await call
        assert result["status"] in (404, 422), result      # 422: reverify's empty manifest
    assert (await server.change_case("case-0123456789abcdef"))["status"] == 404


@pytest.mark.asyncio
async def test_an_agent_can_take_a_case_to_the_human_stop_and_no_further(
        live_api, monkeypatch) -> None:
    from assurance.mcp import server

    _, headers = live_api.account("mcp-agent@example.de")
    monkeypatch.setenv("ASSURANCE_API_URL", live_api.url)
    monkeypatch.setenv("ASSURANCE_API_KEY", headers["X-API-Key"])
    with live_api.client() as http:
        r = http.post("/v1/change/assess/drift", headers=headers, json={
            "baseline": manifest(manifest_id="BASE").to_dict(),
            "observed": manifest(item(content_hash="d" * 64), manifest_id="NOW").to_dict()})
        cid = r.json()["case"]["case_id"]

        assert (await server.change_cases())["body"]["summary"]["open"] == 1
        claimed = await server.change_claim(cid, owner="v.grimaldi", actor="v.grimaldi")
        assert claimed["status"] == 200 and claimed["body"]["status"] == "in_review"
        for _ in range(2):
            moved = await server.change_advance(cid, actor="v.grimaldi")
        assert moved["body"]["status"] == "awaiting_reverification"
        # Advance will not leave awaiting_reverification with work outstanding...
        stuck = await server.change_advance(cid, actor="v.grimaldi")
        assert stuck["status"] == 409
        # ... a re-verification with no evidence behind it clears nothing ...
        bad = await server.change_reverify(
            cid, manifest=manifest(item(content_hash="d" * 64)).to_dict(),
            verification_content_hash="a" * 64, actor="v.grimaldi")
        assert bad["status"] == 409
        # ... and nothing an agent can call gets the case any further.
        final = (await server.change_case(cid))["body"]
        assert final["status"] == "awaiting_reverification"
        assert final["decision"] == "" and final["resolved_decisions"] == []


def _benign_kwargs(fn) -> dict[str, Any]:
    kwargs: dict[str, Any] = {}
    for name, p in inspect.signature(fn).parameters.items():
        ann = str(p.annotation)
        if p.default is not inspect.Parameter.empty:
            continue
        kwargs[name] = ({} if "dict" in ann else [] if "list" in ann else 1.0 if "float" in ann
                        else "case-0123456789abcdef")
    return kwargs


@pytest.mark.asyncio
async def test_the_read_only_tools_are_in_the_allow_list_and_reach_no_write_route(
        monkeypatch) -> None:
    """Each read-only tool makes exactly the one call it documents; that call is on the
    read-only allow-list; and no route that records, seals, signs, pins or decides can be
    named by any argument. The write routes are taken from the live API, not from a list here."""
    from assurance.api.service import create_app
    from assurance.mcp import server

    def matches(allowed: list[tuple[str, str]], method: str, path: str) -> bool:
        return any(method == m and re.fullmatch(rx, path) for m, rx in allowed)

    paths = create_app().openapi()["paths"]
    write_routes: list[tuple[str, re.Pattern[str]]] = []
    for route, item_ in paths.items():
        sample = re.sub(r"\{[^}]+\}", "x", route)
        for method in item_:
            if method in ("post", "put", "patch", "delete") and not matches(
                    READ_ONLY_ALLOWED, method.upper(), sample):
                write_routes.append((method.upper(),
                                     re.compile(re.sub(r"\\\{[^}]+\\\}", "[^/]+",
                                                       re.escape(route)))))
    assert len(write_routes) > 40, "the live API listed no write routes; the test is vacuous"
    # sanity: the decision routes are among the routes the read-only tools must never reach
    assert any(m == "POST" and w.fullmatch("/v1/change/cases/x/decision")
               for m, w in write_routes)
    assert any(m == "POST" and w.fullmatch("/v1/ledger/attest") for m, w in write_routes)
    assert any(m == "POST" and w.fullmatch("/v1/supplier/trust/pin") for m, w in write_routes)

    seen: list[tuple[str, str]] = []

    async def record(method: str, path: str, *, json_body: Any = None, params: Any = None):
        seen.append((method, path))
        return {"status": 200, "body": {}}

    monkeypatch.setattr(server, "_call", record)
    registered = {t.name for t in await server.mcp.list_tools()}
    assert set(READ_ONLY_TOOLS) <= registered

    def reaches_write(method: str, path: str) -> bool:
        return any(method == m and w.fullmatch(path) for m, w in write_routes)

    for name, (method, path) in READ_ONLY_TOOLS.items():
        fn = getattr(server, name)
        seen.clear()
        await fn(**_benign_kwargs(fn))
        assert seen == [(method, path)], name
        assert matches(READ_ONLY_ALLOWED, method, path), name
        assert not reaches_write(method, path), (name, path)
        for hostile in HOSTILE:
            seen.clear()
            kwargs = {k: (hostile if isinstance(v, str) else v)
                      for k, v in _benign_kwargs(fn).items()}
            await fn(**kwargs)
            for m, p in seen:
                assert matches(READ_ONLY_ALLOWED, m, p), (name, hostile, p)
                assert not reaches_write(m, p), (name, hostile, p)
                assert not {"decision", "resume", "resolve-decision", "waive-reverification",
                            "pin", "rotate", "revoke", "override", "feed-baseline", "declare",
                            "manifest", "intervention", "passport", "report"
                            } & set(p.split("/")), (name, p)


@pytest.mark.asyncio
async def test_no_read_only_tool_takes_a_key_a_trust_list_or_a_signature() -> None:
    """What makes a verifier tool safe to offer: what it is asked to check is judged under the
    server's own configuration, never under anything the caller supplies."""
    from assurance.mcp import server

    forbidden = {"public_key_pem", "candidate_public_key_pem", "recorder_trust", "trust",
                 "private_key", "key", "signing_key", "actor", "reason", "pin", "override"}
    for name in READ_ONLY_TOOLS:
        params = set(inspect.signature(getattr(server, name)).parameters)
        assert not params & forbidden, (name, params & forbidden)
