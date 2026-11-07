"""The same capability gives the same 401 / 402 / 403 over the API, the CLI's one HTTP caller and MCP.

The surfaces drifted before (a verifier on the API and not on MCP). Gating is enforced in the API,
the MCP server is a thin client of it and the CLI works on local files with no principal, so what
can differ is (a) a route whose runtime answer is not the gate it declares, (b) an MCP tool whose
answer differs from the route it wraps, (c) the one CLI path that calls the API
(``watch push``) hiding or changing a status, and (d) a human-decision route that an account-level
key can reach. This table-driven test pins all four against the LIVE app and a live server:

principals   no key | account key (active Cell) | operator key with role ``decider`` (same account)
             | lapsed account (cancelled, tier free)

* every state-changing ``/v1`` route answers each principal as its declared plan gate says
  (``capabilities._gates``, read from the live dependency graph, against the Cell plan);
* the routes that are a human decision answer an account-level key 403 and a decider operator
  something else, and no MCP tool exists for any of them;
* each MCP tool that wraps a state-changing route answers every principal in the same class as the
  route itself, for the same request;
* the CLI's HTTP caller (``watch push``) passes the API's status through unchanged.

"class" is 401 / 402 / 403 / "reached" (the request passed authentication and entitlement and
was judged on its merits: 2xx, 404, 409, 422 ...).
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from assurance import capabilities  # noqa: E402
from assurance.api.service import app  # noqa: E402
from assurance.billing.plans import PLANS  # noqa: E402

from . import interfaces_fixtures as fx  # noqa: E402

live_api = fx.live_api

PRINCIPALS = ("none", "account", "decider", "lapsed")
CASE = "case-0123456789abcdef"

#: Account plane and operator-only routes: authenticated for the account itself, deliberately
#: not plan-gated, and exercised by their own tests (keys and operators change principals).
_ACCOUNT_PLANE = {"POST /v1/keys", "POST /v1/keys/revoke", "POST /v1/operators",
                  "POST /v1/operators/{operator_id}/disable", "POST /v1/usage/limits",
                  "POST /v1/billing/portal", "POST /v1/checkout", "POST /v1/checkout/complete",
                  "POST /v1/billing/webhook"}


def klass(status: int) -> str:
    return str(status) if status in (401, 402, 403) else "reached"


def _write_routes() -> list[tuple[str, str]]:
    """``[(method, path template)]`` of every state-changing /v1 operation of the live app."""
    out = []
    for path, item in app.openapi()["paths"].items():
        if path.startswith("/v1"):
            for method in item:
                if method in ("post", "put", "patch", "delete"):
                    out.append((method.upper(), path))
    return sorted(out)


def _expected(principal: str, flags: list[str]) -> str:
    """What the declared gate says this principal gets, for the active Cell plan."""
    if not flags:
        return "reached"                    # an open route answers everyone on its merits
    if principal == "none":
        return "401"
    if principal == "lapsed":
        return "402"
    cell = PLANS["cell"]
    return "402" if any(not getattr(cell, flag) for flag in flags) else "reached"


@pytest.fixture
def world(live_api, monkeypatch):
    """Four principals against one live server: header sets keyed by principal.

    The deployment has an operator key configured (``ASSURANCE_API_KEYS``), as every real one
    does: with none, a keyless caller of the register gets 503 ``unconfigured`` instead of 401.
    """
    monkeypatch.setenv("ASSURANCE_API_KEYS", "operator-key-do-not-ship-0123456789abcdef0123456789")
    acct_id, account = live_api.account("parity-cell@example.de")
    decider = live_api.operator_headers(acct_id, "Maria Rossi")
    lapsed_id, lapsed = live_api.account("parity-lapsed@example.de")
    live_api.accounts.upsert_account(
        email="parity-lapsed@example.de", tier="free", status="cancelled",
        account_id=lapsed_id, event_created=9_000_000)
    return live_api, {"none": {}, "account": account, "decider": decider, "lapsed": lapsed}


def _send(http: httpx.Client, method: str, route: str, headers: dict[str, str],
          body: dict[str, Any]) -> int:
    url = re.sub(r"\{[^}]+\}", CASE, route)
    return http.request(method, url, headers=headers, json=body).status_code


# =============================================================================================
def test_every_state_changing_route_answers_each_principal_as_its_gate_declares(world) -> None:
    api, headers = world
    gates = capabilities._gates(app)
    routes = [(m, p) for m, p in _write_routes() if f"{m} {p}" not in _ACCOUNT_PLANE]
    assert len(routes) > 45, "the live app listed too few write routes; the test would be vacuous"
    # the table must actually contain both gated and open routes, or it proves nothing
    flagged = [r for r in routes if gates[f"{r[0]} {r[1]}"]]
    assert len(flagged) > 35 and len(routes) - len(flagged) >= 8
    wrong: list[str] = []
    with api.client() as http:
        for method, path in routes:
            flags = gates[f"{method} {path}"]
            for principal in PRINCIPALS:
                got = klass(_send(http, method, path, headers[principal], {}))
                want = _expected(principal, flags)
                if got != want:
                    wrong.append(f"{method} {path} as {principal}: got {got}, gate "
                                 f"{flags or 'none'} says {want}")
    assert not wrong, "\n".join(wrong)


# =============================================================================================
def _minimal(schema_name: str) -> dict[str, Any]:
    schema = app.openapi()["components"]["schemas"][schema_name]
    out: dict[str, Any] = {}
    for key in schema.get("required", []):
        prop = schema["properties"][key]
        out[key] = ("x" if prop.get("type", "string") == "string"
                    else {} if prop.get("type") == "object" else [])
    return out


def _body_of(path: str) -> dict[str, Any]:
    ref = app.openapi()["paths"][path]["post"]["requestBody"]["content"]["application/json"][
        "schema"]["$ref"].rsplit("/", 1)[-1]
    return _minimal(ref)


#: Routes that are a human decision. An account-level key may not make them (403); an operator
#: with the decider role is judged on the merits of the request. No agent surface offers any.
DECISIONS = [
    ("POST", "/v1/change/cases/{case_id}/decision", {"disposition": "closed", "reason": "r"}),
    ("POST", "/v1/change/cases/{case_id}/resume", {"reason": "r"}),
    ("POST", "/v1/change/cases/{case_id}/resolve-decision",
     {"decision": "d", "resolution": "r"}),
    ("POST", "/v1/change/cases/{case_id}/waive-reverification", {"entry": "e", "reason": "r"}),
    ("POST", "/v1/supplier/trust/pin", None),
    ("POST", "/v1/supplier/trust/rotate", None),
    ("POST", "/v1/supplier/trust/revoke", None),
    ("POST", "/v1/supplier/trust/override", None),
    ("POST", "/v1/supplier/trust/feed-baseline", None),
]


def test_human_decisions_refuse_an_account_key_and_have_no_agent_tool(world) -> None:
    api, headers = world
    wrong: list[str] = []
    with api.client() as http:
        for method, path, body in DECISIONS:
            payload = body if body is not None else _body_of(path)
            seen = {p: _send(http, method, path, headers[p], payload) for p in PRINCIPALS}
            if seen["none"] != 401:
                wrong.append(f"{path}: no key gave {seen['none']}, not 401")
            if seen["lapsed"] != 402:
                wrong.append(f"{path}: a lapsed account gave {seen['lapsed']}, not 402")
            if seen["account"] != 403:
                wrong.append(f"{path}: an account-level key gave {seen['account']}, not 403")
            if seen["decider"] in (401, 402, 403):
                wrong.append(f"{path}: a decider operator was refused with {seen['decider']}")
    assert not wrong, "\n".join(wrong)

    # and the MCP server offers none of them: no tool wraps a decision route
    catalogue = {c.id: c for c in capabilities.CAPABILITIES}
    decision_routes = {f"{m} {p}" for m, p, _ in DECISIONS}
    for cap in catalogue.values():
        if decision_routes & set(cap.api):
            assert not cap.mcp, f"{cap.id}: a human decision must have no MCP tool"
            assert "mcp" in cap.gaps and cap.gaps["mcp"][0] == capabilities.BY_DESIGN, cap.id


# =============================================================================================
def _mcp_tools_over_state_changing_routes() -> list[tuple[str, str, str]]:
    """``[(tool, method, route template)]`` for each MCP tool whose capability claims a
    state-changing API route (a POST: the verifiers that only answer a question are POSTs too, and
    belong in the same table because their gate must also agree)."""
    out = []
    for cap in capabilities.CAPABILITIES:
        for tool in cap.mcp:
            for route in cap.api:
                method, _, path = route.partition(" ")
                if method in ("POST", "PUT", "PATCH", "DELETE"):
                    out.append((tool, method, path))
    return sorted(set(out))


def _kwargs(fn: Any) -> dict[str, Any]:
    import inspect

    kwargs: dict[str, Any] = {}
    for name, p in inspect.signature(fn).parameters.items():
        if p.default is not inspect.Parameter.empty:
            continue
        ann = str(p.annotation)
        kwargs[name] = ({} if "dict" in ann else [] if "list" in ann else 1.0 if "float" in ann
                        else CASE if "case" in name
                        else "Maria Rossi" if name in ("actor", "owner") else "x")
    return kwargs


@pytest.mark.asyncio
async def test_each_mcp_tool_answers_every_principal_in_the_class_of_the_route_it_wraps(
        world, monkeypatch) -> None:
    from assurance.mcp import server

    api, headers = world
    tools = _mcp_tools_over_state_changing_routes()
    assert len(tools) >= 12, tools
    assert {"machine_verify", "change_claim", "change_advance", "change_reverify",
            "change_assess_drift", "change_assess_intervention"} <= {t[0] for t in tools}
    monkeypatch.setenv("ASSURANCE_API_URL", api.url)
    wrong: list[str] = []
    for tool, method, path in tools:
        fn = getattr(server, tool)
        for principal in PRINCIPALS:
            key = headers[principal].get("X-API-Key", "")
            if key:
                monkeypatch.setenv("ASSURANCE_API_KEY", key)
            else:
                monkeypatch.delenv("ASSURANCE_API_KEY", raising=False)
            with api.client() as http:
                via_api = klass(_send(http, method, path, headers[principal], {}))
            result = await fn(**_kwargs(fn))
            via_mcp = klass(result["status"]) if "status" in result else f"no status: {result}"
            if via_api != via_mcp:
                wrong.append(f"{tool} as {principal}: MCP {via_mcp}, {method} {path} {via_api}")
    assert not wrong, "\n".join(wrong)


# =============================================================================================
def test_the_cli_http_caller_passes_the_status_through_unchanged(world) -> None:
    """``assurance watch push`` is the one CLI command that calls the API with a key. It must
    report the API's 401 / 402 as such (the CLI has no principal of its own: every other command
    works on local files, and the capability catalogue says so as ``offline_only``)."""
    from assurance.watch.push import _post

    api, headers = world
    got: dict[str, str] = {}
    with api.client() as http:
        for principal in PRINCIPALS:
            status, _ = _post(http, f"{api.url}/v1/watch/report",
                              headers[principal].get("X-API-Key", ""), {},
                              retries=0, wait=0.0, sleep=lambda _s: None)
            got[principal] = klass(status)
    assert got == {"none": "401", "account": "reached", "decider": "reached", "lapsed": "402"}
    # the CLI offers nothing else that holds a key: every other CLI command of a capability that
    # also has an API route works on local files; "hosting" says where each runs
    modes = {c.id: c.hosting for c in capabilities.CAPABILITIES}
    assert modes["watch.push"] == "hosted_and_offline"
    assert modes["watch.run"] == "offline_only"
