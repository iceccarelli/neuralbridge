"""An MCP server that wraps the real Assurance API — nothing more.

Every tool here makes a real HTTP call to a deployment of
``assurance.api.service:app`` over ``httpx``. There is no local
simulation, no canned response, and no success faked when the API is
unreachable or unconfigured: with no ``ASSURANCE_API_URL`` set, every tool
returns the same honest "not configured" error instead of pretending to
have called anything, matching the fail-closed pattern the rest of this
site uses (see ``/console`` and ``/developers``).

Tool set is deliberately small, and pinned to the list in
``deploy/assurance/CHANGE.md`` by ``tests/test_interfaces_mcp.py``: the two
always-free routes (``plans``, ``spec_validate``), two paid routes
(``machine_verify``, Cell tier; ``register_cases``, Register tier) chosen because
calling them on the wrong plan or with no key surfaces the API's real, structured
401/402 shape, and the change queue: three reads (``change_cases``,
``change_case``, ``change_export``) and three writes an agent may make
(``change_claim``, ``change_advance``, ``change_reverify``). There is no tool that
closes, rejects, defers or resumes a case, answers its open questions or waives a
re-verification: those are a named person's, on the CLI or the HTTP API.

Run with ``assurance-mcp`` (installed via ``pip install -e '.[assurance-mcp]'``)
or ``python -m assurance.mcp.server``. Transport is stdio by default, which
is what Cursor's ``mcp.json`` and most MCP clients expect.
"""

from __future__ import annotations

import os
import re
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
        "ASSURANCE_API_URL. Paid tools (machine_verify, register_cases, the "
        "change_* tools) also want ASSURANCE_API_KEY; without one they return "
        "the API's real 401, which is the correct, informative answer — not an "
        "error in this server. You can read and work the change queue; you "
        "cannot decide a case, resume it, answer its open questions or waive a "
        "re-verification — those need a named person."
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


#: What a case id looks like (``case-`` and sixteen hex digits today). Anything
#: with a slash, a dot-segment, a query or a space is not one.
_CASE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _invalid_case_id(case_id: str) -> dict[str, Any]:
    return {
        "error": "invalid_case_id",
        "detail": f"{case_id[:80]!r} is not a case id. Ids look like 'case-0123456789abcdef'; "
                  "nothing was sent.",
    }


def _case_path(case_id: str, suffix: str = "") -> str | None:
    """``/v1/change/cases/{case_id}{suffix}``, or ``None`` if the id is not one.

    An agent chooses ``case_id``, and the API server decodes ``%2F`` before it
    routes, so percent-encoding cannot keep ``x/decision`` inside one segment.
    The id is checked instead, and a value that is not an id never leaves this
    process: it cannot steer a call onto another route.
    """
    if not _CASE_ID.fullmatch(case_id):
        return None
    return f"/v1/change/cases/{case_id}{suffix}"


async def _call(method: str, path: str, *, json_body: dict[str, Any] | None = None,
                params: dict[str, str] | None = None) -> dict[str, Any]:
    base = _api_url()
    if base is None:
        return dict(_NOT_CONFIGURED)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.request(method, f"{base}{path}", headers=_headers(),
                                            json=json_body, params=params)
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
async def machine_verify(
    envelope: dict[str, Any], trace: dict[str, Any], actor: str,
    recorder_attestations: list[dict[str, Any]] | None = None, machine_serial: str = "",
) -> dict[str, Any]:
    """POST /v1/machine/verify — verify a recorded machine run against its declared envelope.

    Cell-tier only. With no ASSURANCE_API_KEY, or a key on Validator/Register,
    this returns the API's real 401/402 — a structured, parseable answer
    naming the required plan, not an error from this server.

    ``recorder_attestations`` are signed attestations of the trace, produced offline by
    the recorder operator (``assurance machine recorder-sign``). They are assessed
    against the recorder trust list the SERVER is configured with; this tool cannot
    supply a trust list, a private key or a provenance basis. Without an accepted
    attestation a declared provenance is capped at ``community``; an accepted one proves
    a trusted key signed these exact trace bytes, not that the recording is physically
    true. ``machine_serial`` names the unit the verification is about.
    """
    body: dict[str, Any] = {"envelope": envelope, "trace": trace, "actor": actor}
    if recorder_attestations:
        body["recorder_attestations"] = recorder_attestations
    if machine_serial:
        body["machine_serial"] = machine_serial
    return await _call("POST", "/v1/machine/verify", json_body=body)


@mcp.tool()
async def register_cases() -> dict[str, Any]:
    """GET /v1/cases — list Article 14 cases for the authenticated account.

    Register-tier only. With no ASSURANCE_API_KEY, or a Validator-only key,
    this returns the API's real 401/402, the same as machine_verify.
    """
    return await _call("GET", "/v1/cases")


@mcp.tool()
async def change_cases(status: str = "") -> dict[str, Any]:
    """GET /v1/change/cases — the Active Assurance Cases queue: which machine
    changes are open, what evidence they invalidated, and what each one still
    needs before a human can close it.

    Cell-tier only. Answers "which machine changes require review" and
    "which cases are still open" directly from the response's ``cases`` rows
    and ``summary`` counts — this tool never summarises on its own.

    Args:
        status: optional filter — one of open, in_review, awaiting_action,
            awaiting_reverification, ready_to_close, closed, rejected, deferred.
    """
    return await _call("GET", "/v1/change/cases", params={"status": status} if status else None)


@mcp.tool()
async def change_case(case_id: str) -> dict[str, Any]:
    """GET /v1/change/cases/{case_id} — one case in full: what changed, which
    safety functions it affects, why evidence went stale, what is required
    before it is ready to close, and its full decision timeline.

    Cell-tier only.
    """
    path = _case_path(case_id)
    return await _call("GET", path) if path else _invalid_case_id(case_id)


@mcp.tool()
async def change_export(case_id: str, skeleton: bool = False) -> dict[str, Any]:
    """GET /v1/change/cases/{case_id}/export — the case's verifiable evidence bundle:
    every ledger entry of the case, hash-chained. Read-only. Cell-tier only.

    The ``body`` is what ``assurance evidence verify`` checks offline. It proves the
    bundle is internally consistent; it does not prove it is the operator's ledger.
    ``skeleton=True`` also lists the id, kind and time of every OTHER entry in the
    account's ledger so completeness can be checked; leave it off unless the person
    who will receive the file may see those (it is off by default for that reason).

    The bundle carries an ``anchor`` only when the operator has signed this account's
    ledger (``assurance attest sign``): the same record the HTTP API embeds, chosen by
    the same rule, never one the customer declared. Without one, completeness is not
    checked. A 409 ``anchor_contradicts_ledger`` is a finding about the ledger, not a
    fault: report it, do not retry around it. A 500 ``attestation_log_damaged`` means
    the anchor could not be chosen; no unanchored bundle is substituted.
    """
    path = _case_path(case_id, "/export")
    if not path:
        return _invalid_case_id(case_id)
    return await _call("GET", path, params={"skeleton": "true"} if skeleton else None)


# Write parity for the change queue — claim, advance, reverify. Deliberately NOT
# `decide`, `resume`, `resolve-decision` or `waive-reverification`: closing,
# rejecting, deferring, resuming a case, answering its open human question and
# waiving a re-verification are decisions only a named person may make, and this
# server is the surface an agent drives. An agent can read the queue, take a case
# up, move it to the next stop its own required work names and submit a
# re-verification for the engine to judge; it cannot decide. Those stay on the
# CLI and the HTTP API. tests/test_interfaces_mcp.py proves it from the outside.

@mcp.tool()
async def change_claim(case_id: str, owner: str, actor: str) -> dict[str, Any]:
    """POST /v1/change/cases/{case_id}/claim — OPEN -> IN_REVIEW; a named owner takes the case.

    Cell-tier only. ``actor`` is the named person this step is taken for; the API
    refuses a blank one (422). A case in any other state is a real 409, and an
    unknown case id is a 404, the same as the read tools return for it.
    """
    path = _case_path(case_id, "/claim")
    if path is None:
        return _invalid_case_id(case_id)
    return await _call("POST", path, json_body={"owner": owner, "actor": actor})


@mcp.tool()
async def change_advance(case_id: str, actor: str) -> dict[str, Any]:
    """POST /v1/change/cases/{case_id}/advance — move to the next stop the case's own
    required work names. It never reaches ready_to_close while a re-verification or a
    human decision is outstanding, and it never marks anything done by itself.

    Cell-tier only. ``actor`` is the named person this step is taken for.
    """
    path = _case_path(case_id, "/advance")
    if path is None:
        return _invalid_case_id(case_id)
    return await _call("POST", path, json_body={"actor": actor})


@mcp.tool()
async def change_reverify(
    case_id: str, manifest: dict[str, Any], verification_content_hash: str, actor: str,
) -> dict[str, Any]:
    """POST /v1/change/cases/{case_id}/reverification — submit the machine's current
    manifest and the content hash of a sealed verification bundle; the coverage engine,
    not the caller, decides which functions are current again.

    A 200 means the submission was recorded, not that it cleared anything: while the
    case still awaits re-verification the body carries ``blocked_reason`` (a ``code``
    such as ``below_validated_tier``, the ``entries`` and a sentence). Today no
    verification this package produces reaches ``validated``, so a person has to waive
    the entry. Read ``blocked_reason`` before reporting the case as progressing.

    Cell-tier only. There is deliberately no tool here to close, reject, defer or
    resume a case, to answer its open questions or to waive a re-verification: those
    need a named person, on the CLI or the HTTP API.
    """
    path = _case_path(case_id, "/reverification")
    if path is None:
        return _invalid_case_id(case_id)
    return await _call("POST", path,
                       json_body={"manifest": manifest, "actor": actor,
                                  "verification_content_hash": verification_content_hash})


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
