"""An MCP server that wraps the real Assurance API — nothing more.

Every tool here makes a real HTTP call to a deployment of
``assurance.api.service:app`` over ``httpx``. There is no local
simulation, no canned response, and no success faked when the API is
unreachable or unconfigured: with no ``ASSURANCE_API_URL`` set, every tool
returns the same honest "not configured" error instead of pretending to
have called anything, matching the fail-closed pattern the rest of this
site uses (see ``/console`` and ``/developers``).

Tool set is deliberately small, and pinned to the list in
``deploy/assurance/CHANGE.md`` by ``tests/test_interfaces_mcp.py``: the always-free routes
(``plans``, ``spec_validate``, ``services``,
``machine_assurance_check``, ``machine_check``, ``evidence_verify``, ``machinery_passport_check``),
the paid routes (``machine_verify``, ``machinery_coverage``, ``fleet_report``,
``fleet_machine_assurance``, Cell tier; ``register_cases``, Register tier) chosen because calling
them on the wrong plan or with no key surfaces the API's real, structured 401/402 shape (the thing
an agent needs to see to route a human to checkout, not a summary of it), and the change queue:
three reads (``change_cases``, ``change_case``, ``change_export``), three writes an agent may make
(``change_claim``, ``change_advance``, ``change_reverify``) and two that open a case from a
machine's own manifests (``change_assess_drift``, ``change_assess_intervention``). Eighteen further
read-only tools (``spec_fields``, ``art14_case``, ``art14_register``, ``art14_breaches``,
``art14_export``, ``ledger_verify``, ``attest_log``, ``attest_verify``, ``attest_service_key``,
``machine_separation``, ``machinery_diff``, ``fleet_machines``, ``fleet_observations``,
``fleet_declaration_check``, ``value_position``, ``change_replay``, ``supplier_trust_list``,
``supplier_trust_check``) wrap a GET or a POST that answers a question and records nothing.
Everything beyond the case work reads or verifies and never decides or records, and none of it can supply a
trust list or a public key, so what an agent asks the server to check is judged under the server's
own configuration. There is no tool that assesses an advisory, and no tool that closes, rejects,
defers or resumes a case, answers its open questions or waives a re-verification: those are a
named person's, on the CLI or the HTTP API.

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

from assurance.core.api_url import api_url_problem

mcp: MCPServer = MCPServer(
    name="assurance",
    version="0.1.0",
    instructions=(
        "Tools for the Industrial Autonomous Assurance API "
        "(CRA Article 14 / Machinery Regulation Annex III evidence). "
        "Free tools (plans, spec_validate, evidence_verify, machine_check, "
        "machinery_passport_check) need no configuration beyond "
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
    # The same rule `assurance watch push` applies: https, except plain http to loopback;
    # no credentials in the URL. The key is never sent anywhere else.
    problem = api_url_problem(base)
    if problem:
        return {
            "error": "assurance_api_url_not_allowed",
            "detail": problem.replace("--api-url", "ASSURANCE_API_URL"),
            "remedy": "Set ASSURANCE_API_URL to an https URL (plain http is accepted only "
                      "for localhost, 127.0.0.1 and ::1). Nothing was sent.",
        }

    try:
        # trust_env=False: the key goes to the host named in ASSURANCE_API_URL and to no proxy
        # an environment variable names (`assurance watch push` does the same).
        async with httpx.AsyncClient(timeout=15.0, trust_env=False) as client:
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
async def capabilities() -> dict[str, Any]:
    """GET /v1/capabilities — every capability of this service and which surface offers it.

    Free, no key. Lists what the command line, the HTTP API and this MCP server each offer, the plan
    flag that gates each API route, and every surface that is missing together with whether that is
    by design (a human decision, an offline step, key custody) or a known gap. Use it to find out
    what you can do before you try. ``present`` means it exists, not that the surfaces behave alike.
    """
    return await _call("GET", "/v1/capabilities")


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
    subject: str = "",
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
    true. ``machine_serial`` names the unit the verification is about. ``subject`` files
    the sealed bundle under that ledger subject, as ``--subject`` does on the CLI; give a
    unit key (``maker/model#serial``) for it to count as evidence of that unit. Without
    one the bundle is filed under ``product@version`` and counts for no unit.
    """
    body: dict[str, Any] = {"envelope": envelope, "trace": trace, "actor": actor}
    if recorder_attestations:
        body["recorder_attestations"] = recorder_attestations
    if machine_serial:
        body["machine_serial"] = machine_serial
    if subject:
        body["subject"] = subject
    return await _call("POST", "/v1/machine/verify", json_body=body)


@mcp.tool()
async def machine_check(
    bundle: dict[str, Any], envelope: dict[str, Any] | None = None,
    trace: dict[str, Any] | None = None, machine_serial: str = "",
) -> dict[str, Any]:
    """POST /v1/machine/bundle/check — re-verify a machine verification bundle somebody else sealed.

    Free, no key. With the ``envelope`` and ``trace`` it was made from, the engine is re-run and
    the result compared with what the bundle records; without them only the seal is checked and
    the answer says so. This tool cannot supply a recorder trust list: the server judges the
    bundle's recorder attestation under the list it is configured with, and with none, a
    recorded ``validated`` is believed only as ``community``. A seal is not a signature, and a
    pass does not show the recording came from a real machine.
    """
    body: dict[str, Any] = {"bundle": bundle}
    if envelope is not None:
        body["envelope"] = envelope
    if trace is not None:
        body["trace"] = trace
    if machine_serial:
        body["machine_serial"] = machine_serial
    return await _call("POST", "/v1/machine/bundle/check", json_body=body)


@mcp.tool()
async def evidence_verify(bundle: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/evidence/verify — check an evidence export you were handed. Free, anonymous.

    Checks hashes, links and chain structure of a ledger export (and detects other sealed
    artefacts). Without a signed anchor under a key you obtained elsewhere, completeness is
    NOT established and the answer says so; the tool cannot supply that key. Nothing is stored.
    """
    return await _call("POST", "/v1/evidence/verify", json_body=bundle)


@mcp.tool()
async def machinery_coverage(manifest: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/machinery/coverage — which of a machine's declared safety functions a recorded
    verification still stands for, at what evidence tier, and why any does not.

    Reads the account's own ledger; records nothing. Entitlement and key rules are the API's
    (a real 401/402 comes back as is). ``covered_at_community`` is not ``covered``: the
    evidence stands, but nobody demonstrated it on the machine.
    """
    return await _call("POST", "/v1/machinery/coverage", json_body={"manifest": manifest})


@mcp.tool()
async def machinery_passport_check(passport: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/machinery/passport/check — re-verify a machine passport you did not produce.

    Free, no key. Confirms the passport's seal and that its printed blocks repeat what the seal
    covers; it cannot confirm the records the passport names exist without the ledger.
    """
    return await _call("POST", "/v1/machinery/passport/check", json_body={"passport": passport})


@mcp.tool()
async def fleet_report(organisation: str = "", prepared_by: str = "") -> dict[str, Any]:
    """GET /v1/fleet/report — the whole fleet on one page: which machines are covered, stale,
    failing or unchecked, from the account's own ledger. Read-only.
    """
    params = {k: v for k, v in (("organisation", organisation), ("prepared_by", prepared_by)) if v}
    return await _call("GET", "/v1/fleet/report", params=params or None)


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
    such as ``below_validated_tier`` or ``below_validated_unit_binding``, the ``entries``
    and a sentence). A verification clears an entry only at ``validated``, which needs a
    recorder attestation accepted under the server's trust list AND a seal for the exact
    unit key; otherwise a person has to waive the entry. Read ``blocked_reason`` before
    reporting the case as progressing.

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


@mcp.tool()
async def change_assess_drift(
    baseline: dict[str, Any], observed: dict[str, Any], actor: str,
) -> dict[str, Any]:
    """POST /v1/change/assess/drift — compare a machine's baseline manifest with the one
    observed now; if the divergence puts a safety function in question, a change case
    is opened (otherwise the body says why not).

    Cell-tier only. Both manifests are the caller's claim about the machine, and the
    engine judges them as such; this opens a case for a person to work, it does not
    clear or close anything. ``actor`` is the named person this step is taken for.

    Read ``baseline_source`` in the answer before reporting a verdict: ``ledger`` means
    the account's own sealed baseline was used (and ``request_baseline_ignored`` says if
    yours differed); ``request`` means the account has none, so "unchanged" only says the
    two manifests you sent match each other, not that the machine matches anything sealed.
    """
    return await _call("POST", "/v1/change/assess/drift",
                       json_body={"baseline": baseline, "observed": observed, "actor": actor})


@mcp.tool()
async def change_assess_intervention(
    manifest: dict[str, Any], intervention_id: str, actor: str,
) -> dict[str, Any]:
    """POST /v1/change/assess/intervention — did an intervention already sealed in the
    account's ledger invalidate standing evidence on this machine? Opens a change case
    when it did.

    Cell-tier only. ``intervention_id`` must name an intervention already sealed
    (``POST /v1/machinery/intervention``); an unknown one is the API's own 4xx. There
    is deliberately no tool to assess an advisory: an advisory is third-party content,
    and a case opened from an unsigned one is the attack the signed feed exists to
    stop, so that stays with a named person on the CLI or the HTTP API.
    """
    return await _call("POST", "/v1/change/assess/intervention",
                       json_body={"manifest": manifest, "intervention_id": intervention_id,
                                  "actor": actor})


# Read-only parity — reads of the account's own ledger and pure computations. Every tool
# below wraps a GET, or a POST that answers a question and records nothing. None supplies a
# trust list, a public key or a signing key (``attest_verify`` is judged under the server's
# own key; ``supplier_trust_check`` under the account's own pins), none seals, closes or
# decides, and none can name a route other than its own: a caller's id is checked before it
# is put in a path. tests/test_interfaces_mcp.py proves it from the outside.

def _id_path(template: str, ident: str) -> str | None:
    """``template`` with ``ident`` filled in, or ``None`` if it is not one segment of an id."""
    return template.format(ident) if _CASE_ID.fullmatch(ident) else None


@mcp.tool()
async def spec_fields(track: str, stage: str) -> dict[str, Any]:
    """GET /v1/spec/fields — the platform field specification for an Article 14 track and stage.

    Free, no key. ``track`` is actively_exploited_vulnerability or severe_incident; ``stage`` is
    early_warning, notification, final or intermediate. Anything else is the API's own 422.
    """
    return await _call("GET", "/v1/spec/fields", params={"track": track, "stage": stage})


@mcp.tool()
async def art14_case(case_id: str) -> dict[str, Any]:
    """GET /v1/cases/{case_id} — one Article 14 case with its deadlines. Read-only.

    Register-tier only; a real 401/402 comes back as is. Awareness and every filing are human
    decisions already on the record; this tool only reads them.
    """
    path = _id_path("/v1/cases/{}", case_id)
    return await _call("GET", path) if path else _invalid_case_id(case_id)


@mcp.tool()
async def art14_register() -> dict[str, Any]:
    """GET /v1/register — readiness across every Article 14 case, worst first. Read-only.

    Register-tier only.
    """
    return await _call("GET", "/v1/register")


@mcp.tool()
async def art14_breaches() -> dict[str, Any]:
    """GET /v1/register/breaches — Article 14 deadlines missed or overdue. Read-only.

    Register-tier only. An empty list means none were found in the records, not that none exist.
    """
    return await _call("GET", "/v1/register/breaches")


@mcp.tool()
async def art14_export(case_id: str, skeleton: bool = False, anchor: bool = True) -> dict[str, Any]:
    """GET /v1/cases/{case_id}/export — one Article 14 case's verifiable evidence bundle,
    hash-chained. Read-only.

    Register-tier or above; a lapsed subscription still reads its own evidence. The same rules
    as ``change_export`` apply: ``skeleton=True`` also lists the id, kind and time of every other
    entry in the account's ledger, so leave it off unless the person who receives the file may
    see those. ``anchor=False`` exports without the operator's signed anchor and says so in the
    bundle; a 409 ``anchor_contradicts_ledger`` is a finding, not a fault.
    """
    path = _id_path("/v1/cases/{}/export", case_id)
    if not path:
        return _invalid_case_id(case_id)
    params = {k: v for k, v in (("skeleton", "true" if skeleton else ""),
                                ("anchor", "" if anchor else "false")) if v}
    return await _call("GET", path, params=params or None)


@mcp.tool()
async def ledger_verify() -> dict[str, Any]:
    """GET /v1/ledger/verify — verify the account's evidence chain. Read-only.

    ``verified`` is the chain's self-consistency only; completeness (nothing removed from the
    end) is NOT established without a signed anchor and ``not_checked`` says so.
    """
    return await _call("GET", "/v1/ledger/verify")


@mcp.tool()
async def attest_log() -> dict[str, Any]:
    """GET /v1/ledger/attest/log — every attestation the service has made for the account,
    checking nothing. Read-only. Use ``attest_verify`` to check them.
    """
    return await _call("GET", "/v1/ledger/attest/log")


@mcp.tool()
async def attest_verify(attestations: list[dict[str, Any]]) -> dict[str, Any]:
    """POST /v1/ledger/attest/verify — check an attestation log's signatures and consistency.
    Free, no key. Stores nothing.

    This tool cannot supply a public key: the log is checked against the service's own key. A
    key that arrived over the same connection as the signatures proves only that one party was
    consistent, and this check cannot see the ledger, so it does not show the ledger still holds
    what was signed for.
    """
    return await _call("POST", "/v1/ledger/attest/verify", json_body={"attestations": attestations})


@mcp.tool()
async def attest_service_key() -> dict[str, Any]:
    """GET /v1/ledger/attest/key — the public key the hosted service counter-signs with. No account.

    Read the fingerprint against one published somewhere this service does not control; a key
    fetched over the connection that carries the signature is weak evidence of who holds it.
    """
    return await _call("GET", "/v1/ledger/attest/key")


@mcp.tool()
async def machine_separation(
    robot_speed_mm_s: float, reaction_time_s: float, stop_time_s: float, stop_distance_mm: float,
    measured_at_speed_mm_s: float, intrusion_distance_mm: float,
    human_position_uncertainty_mm: float = 0.0, robot_position_uncertainty_mm: float = 0.0,
    human_speed_mm_s: float | None = None,
) -> dict[str, Any]:
    """POST /v1/machine/separation — the protective separation distance, term by term. Records nothing.

    A calculation over figures the caller supplies and labels as estimated; it is not a measurement
    of any machine, and the result says where a figure is outside what it was measured at.
    """
    body: dict[str, Any] = {
        "robot_speed_mm_s": robot_speed_mm_s, "reaction_time_s": reaction_time_s,
        "stop_time_s": stop_time_s, "stop_distance_mm": stop_distance_mm,
        "measured_at_speed_mm_s": measured_at_speed_mm_s,
        "intrusion_distance_mm": intrusion_distance_mm,
        "human_position_uncertainty_mm": human_position_uncertainty_mm,
        "robot_position_uncertainty_mm": robot_position_uncertainty_mm,
    }
    if human_speed_mm_s is not None:
        body["human_speed_mm_s"] = human_speed_mm_s
    return await _call("POST", "/v1/machine/separation", json_body=body)


@mcp.tool()
async def machinery_diff(baseline: dict[str, Any], observed: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/machinery/diff — is the machine still the configuration that was signed off?

    Compares two manifests the caller supplies; records nothing and opens no case (use
    ``change_assess_drift`` for that). An item with no hash is reported uncomparable, never
    unchanged. Both manifests are the caller's claim about the machine.
    """
    return await _call("POST", "/v1/machinery/diff",
                       json_body={"baseline": baseline, "observed": observed})


@mcp.tool()
async def fleet_machines() -> dict[str, Any]:
    """GET /v1/fleet/machines — every enrolled machine, worst coverage first, from the account's
    own ledger. Read-only. Cell-tier only.
    """
    return await _call("GET", "/v1/fleet/machines")


@mcp.tool()
async def fleet_observations() -> dict[str, Any]:
    """GET /v1/fleet/observations — when each machine was last looked at, and did the last attempt
    work. Read-only. Cell-tier only.

    Reads only what the account holder reported (``watch push``); a failed attempt is never a
    positive one, and a machine nobody reported on is unchecked, not fine.
    """
    return await _call("GET", "/v1/fleet/observations")


@mcp.tool()
async def fleet_declaration_check(
    declaration: dict[str, Any], manifest: dict[str, Any], with_coverage: bool = False,
) -> dict[str, Any]:
    """POST /v1/fleet/declaration/check — does this Declaration of Conformity still describe the
    machine? Free; records nothing.

    ``with_coverage=True`` also assesses the evidence in the account's own ledger (needs a plan
    that reads it). Without it the answer is ``configuration_matches_coverage_not_assessed``,
    which is not a pass. Whether a change is a substantial modification is for the manufacturer
    and their notified body.
    """
    return await _call("POST", "/v1/fleet/declaration/check",
                       json_body={"declaration": declaration, "manifest": manifest,
                                  "with_coverage": with_coverage})


@mcp.tool()
async def value_position() -> dict[str, Any]:
    """GET /v1/value — the account's assurance position, derived from its own ledger. Read-only.

    Cell-tier only. Derived, not asserted: nothing here is a market or customer claim.
    """
    return await _call("GET", "/v1/value")


@mcp.tool()
async def change_replay(case_id: str) -> dict[str, Any]:
    """GET /v1/change/cases/{case_id}/replay — rebuild a case from the ledger alone and check
    every step. Read-only. Cell-tier only.

    ``ok`` false lists ``violations``: report them, do not repair around them.
    """
    path = _case_path(case_id, "/replay")
    return await _call("GET", path) if path else _invalid_case_id(case_id)


@mcp.tool()
async def supplier_trust_list() -> dict[str, Any]:
    """GET /v1/supplier/trust — the supplier keys this account has pinned and every trust
    decision on record. Read-only. Cell-tier only.

    Pinning, rotating, revoking and overriding are a named person's decisions and have no tool.
    """
    return await _call("GET", "/v1/supplier/trust")


@mcp.tool()
async def supplier_trust_check(
    feed: str = "", hosted_feed_id: str = "", expect_supplier: str = "",
) -> dict[str, Any]:
    """POST /v1/supplier/trust/evaluate — what is this signed supplier feed, state by state,
    under the account's own pinned keys? Records nothing. Cell-tier only.

    Give the feed text (one JSON record per line) or the id of a feed hosted here. An untrusted
    feed is a result, not an error. This tool cannot supply a key to trust (not even as a
    candidate), and it does not open a case from an advisory: that is a named person's act.
    """
    body: dict[str, Any] = {}
    if feed:
        body["feed"] = feed
    if hosted_feed_id:
        if not _CASE_ID.fullmatch(hosted_feed_id):
            return {"error": "invalid_feed_id",
                    "detail": f"{hosted_feed_id[:80]!r} is not a feed id; nothing was sent."}
        body["hosted_feed_id"] = hosted_feed_id
    if expect_supplier:
        body["expect_supplier"] = expect_supplier
    return await _call("POST", "/v1/supplier/trust/evaluate", json_body=body)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
