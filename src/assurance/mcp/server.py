"""An MCP server that wraps the real Assurance API — nothing more.

Every tool here makes a real HTTP call to a deployment of
``assurance.api.service:app`` over ``httpx``. There is no local
simulation, no canned response, and no success faked when the API is
unreachable or unconfigured: with no ``ASSURANCE_API_URL`` set, every tool
returns the same honest "not configured" error instead of pretending to
have called anything, matching the fail-closed pattern the rest of this
site uses (see ``/console`` and ``/developers``).

Tool set is deliberately small: the always-free routes (``plans``,
``spec_validate``, ``services``, ``machine_assurance_check``) plus paid
routes (``machine_verify``, ``register_cases``, ``fleet_machine_assurance``)
chosen specifically because calling them on the wrong plan or with no key
surfaces the API's real, structured 401/402 shape — the thing an agent
actually needs to see to route a human to checkout, not a summary of it.

Run with ``assurance-mcp`` (installed via ``pip install -e '.[assurance-mcp]'``)
or ``python -m assurance.mcp.server``. Transport is stdio by default, which
is what Cursor's ``mcp.json`` and most MCP clients expect.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

mcp: MCPServer = MCPServer(
    name="assurance",
    version="0.1.0",
    instructions=(
        "Tools for the Industrial Autonomous Assurance API "
        "(CRA Article 14 / Machinery Regulation Annex III evidence). "
        "Free tools (plans, spec_validate) need no configuration beyond "
        "ASSURANCE_API_URL. Paid tools (machine_verify, register_cases) "
        "also want ASSURANCE_API_KEY; without one they return the API's "
        "real 401, which is the correct, informative answer — not an error "
        "in this server."
    ),
)


def _api_url() -> str | None:
    url = os.environ.get("ASSURANCE_API_URL", "").strip()
    return url.rstrip("/") or None


def _headers() -> dict[str, str]:
    key = os.environ.get("ASSURANCE_API_KEY", "").strip()
    headers = {"content-type": "application/json"}
    if key:
        headers["X-API-Key"] = key
    return headers


_NOT_CONFIGURED = {
    "error": "assurance_api_url_not_configured",
    "remedy": (
        "Set ASSURANCE_API_URL to a running deployment of "
        "assurance.api.service:app, e.g. http://127.0.0.1:8000 for a local "
        "run (uvicorn assurance.api.service:app) or the Fly hostname of a "
        "real deployment. This server never fakes a response — see "
        "https://neuralbridge.io/status for what a live deployment needs."
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
            "remedy": f"Confirm {base} is reachable and running assurance.api.service:app.",
        }

    try:
        body = response.json()
    except ValueError:
        body = {"raw": response.text}

    return {"status": response.status_code, "body": body}


@mcp.tool()
async def plans() -> dict[str, Any]:
    """GET /v1/plans — the pricing table, generated live from enforced entitlements. Free, no key."""
    return await _call("GET", "/v1/plans")


@mcp.tool()
async def spec_validate(track: str, stage: str, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/spec/validate — validate an Article 14 draft submission without recording it. Free, no key.

    Args:
        track: e.g. "actively_exploited_vulnerability".
        stage: e.g. "early_warning".
        payload: the draft submission fields to check, e.g.
            {"product_name": "...", "member_states_available": ["DE", "CH"]}.
    """
    return await _call("POST", "/v1/spec/validate", json_body={"track": track, "stage": stage, "payload": payload})


@mcp.tool()
async def machine_verify(envelope: dict[str, Any], trace: dict[str, Any], actor: str) -> dict[str, Any]:
    """POST /v1/machine/verify — verify a recorded machine run against its declared envelope.

    Cell-tier only. With no ASSURANCE_API_KEY, or a key on Validator/Register,
    this returns the API's real 401/402 — a structured, parseable answer
    naming the required plan, not an error from this server.
    """
    return await _call(
        "POST",
        "/v1/machine/verify",
        json_body={"envelope": envelope, "trace": trace, "actor": actor},
    )


@mcp.tool()
async def register_cases() -> dict[str, Any]:
    """GET /v1/cases — list Article 14 cases for the authenticated account.

    Register-tier only. With no ASSURANCE_API_KEY, or a Validator-only key,
    this returns the API's real 401/402, the same as machine_verify.
    """
    return await _call("GET", "/v1/cases")


@mcp.tool()
async def services() -> dict[str, Any]:
    """GET /v1/check/services — the Machine Assurance Check service catalogue.

    Free, no key. Call this first: it returns each service's real input
    schema, whether it is free or paid, the plan it needs, and what the API
    actually does if you are not entitled — so a purchase decision can be
    made before ``machine_assurance_check`` or ``fleet_machine_assurance``
    is ever called.
    """
    return await _call("GET", "/v1/check/services")


@mcp.tool()
async def machine_assurance_check(manifest: dict[str, Any], advisory: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/check/machine — does this change match this machine? Free, no key.

    Args:
        manifest: the machine's current safety manifest (SafetyManifest.to_dict() shape).
        advisory: the supplier advisory or change being checked (ComponentAdvisory.to_dict() shape).

    Cannot assess whether standing safety evidence is still valid — that
    needs the machine enrolled in the ledger. The result's
    ``checks_skipped`` says so, and ``commercial_next_action`` names the
    real next call, exactly as a human reading the page would see.
    """
    return await _call(
        "POST", "/v1/check/machine", json_body={"manifest": manifest, "advisory": advisory},
    )


@mcp.tool()
async def fleet_machine_assurance(machine_key: str, advisory: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST /v1/check/fleet-machine — an enrolled machine's own evidence, plus the fleet fan-out.

    Cell-tier only. With no ASSURANCE_API_KEY, or a key below Cell, this
    returns the API's real, structured 401/402 — a ``status`` of
    ``authentication_required`` or ``payment_required``, the ``required_plan``,
    and the concrete next step (``GET /v1/plans`` or ``POST /v1/checkout``) —
    never a fake success and never a bare 500.

    Args:
        machine_key: the ledger subject, e.g. "Grimaldi/AR-7#0412" — the
            machine must already be enrolled via POST /v1/machinery/manifest.
        advisory: optional; when given, also fans this advisory out across
            every other enrolled machine.
    """
    body: dict[str, Any] = {"machine_key": machine_key}
    if advisory is not None:
        body["advisory"] = advisory
    return await _call("POST", "/v1/check/fleet-machine", json_body=body)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
