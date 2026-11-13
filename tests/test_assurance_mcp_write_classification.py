"""An MCP tool writes the account's ledger if, and only if, the site classifies it as a write.

The product says an agent does not write evidence: software drafts, a named person decides. The
MCP connector page (``app/connectors/mcp/page.tsx``) carries that as ``agentWrite`` on every tool,
and ``tests/test_site_mcp_parity.py`` pins the writer set. Nothing checked the claim against what a
tool DOES to the ledger, and ``machine_verify`` did not match it: it never sent ``seal``, the API
defaults ``seal`` to true, so an agent's "verify" call appended a sealed bundle to the account's
hash-chained ledger and the reply said ``sealed: true``.

This file closes that from the outside, through the real FastAPI app on a real socket and the
tools' own request path (no mocked HTTP):

* the regression: ``machine_verify`` leaves the ledger exactly as it found it, still answers with a
  complete verdict, and says that nothing was recorded;
* the guard: EVERY registered tool is driven with minimal valid synthetic arguments against a
  throwaway Cell account, and the account's ledger (and the operator's shared one) grows if and
  only if the committed classification calls the tool a write.

A read tool is driven to the route's SUCCESS path, not to a 4xx that would write nothing whatever
the route did: the status each tool must reach is stated below, with the reason where it is not
200. A tool that cannot be driven generically is listed in ``NOT_DRIVEN`` with the reason; there is
no ``pytest.skip`` here.
"""

from __future__ import annotations

import copy
import inspect
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from . import interfaces_fixtures as fx  # noqa: E402
from .ingest_support import csaf_doc, raw, sbom_doc  # noqa: E402
from .interfaces_scenario import KEY, OTHER, PERSON, CliDriver, Plant, advisory  # noqa: E402
from .interfaces_support import envelope_dict, trace_dict  # noqa: E402
from .test_assurance_intel_api import CVE_LISTED, STORE_ENV, build_store  # noqa: E402
from .test_site_mcp_parity import _page_tools  # noqa: E402
from .test_surface_parity import _host  # noqa: E402

live_api = fx.live_api

ART14_CASE = "case-art14-classification"
ACTOR = {"identifier": "m.braun", "role": "Entwicklungsleitung"}


def _fingerprint(ledger: Any) -> tuple[int, str]:
    """How long a ledger is and the link hash of its last entry: any append changes both."""
    entries = ledger.entries()
    return len(entries), entries[-1].link_hash if entries else ""


def _operator_ledger() -> Any:
    from assurance.api import deps

    return deps.shared_register().ledger


# ------------------------------------------------------------------------- the regression
@pytest.mark.asyncio
async def test_machine_verify_through_mcp_computes_and_records_nothing(
        live_api, monkeypatch) -> None:
    """The auditor's finding, replayed: a Cell account asks the tool to verify a passing run.

    Before the fix the API's ``seal`` default (true) applied, the reply said ``sealed: true`` and
    the account's ledger (and ``GET /v1/cases``) held a new entry. Now the ledger is untouched,
    the verdict is still complete, and the reply says in terms that it was not recorded.
    """
    from assurance.mcp import server

    account_id, headers = live_api.account("mcp-noseal@example.de")
    monkeypatch.setenv("ASSURANCE_API_URL", live_api.url)
    monkeypatch.setenv("ASSURANCE_API_KEY", headers["X-API-Key"])
    ledger = live_api.tenant_ledger(account_id)
    operator = _operator_ledger()
    run = trace_dict(datetime.now(UTC), trace_id="RUN-MCP-NOSEAL")
    with live_api.client() as http:
        def seen() -> tuple[Any, ...]:
            return (_fingerprint(ledger), _fingerprint(operator),
                    http.get("/v1/cases", headers=headers).json(),
                    http.get("/v1/ledger/verify", headers=headers).json()["attestation"]["length"])

        before = seen()
        assert before[0][0] == 0

        out = await server.machine_verify(
            envelope=envelope_dict(), trace=run, actor="v.grimaldi", subject=KEY)

        assert out["status"] == 200, out
        body = out["body"]
        # The auditor's evidence: the ledger length, the case listing and the chain are as before.
        assert seen() == before, "the tool recorded something in the account's ledger"
        assert len(ledger) == 0 and len(operator) == 0
        # The verification itself is complete and honest ...
        assert body["verdict"] == "pass" and body["tier"] == "community"
        assert body["may_claim_physical_behaviour"] is False
        assert body["provenance_basis"] == "declared_by_filer" and body["content_hash"]
        assert body["evidence"]["body"]["unit_key"] == KEY
        # ... and it was not recorded, which the API says (`sealed`) and the tool says too.
        assert body["sealed"] is False
        assert out["recorded"] is False
        assert "NOT recorded" in out["recording_note"]
        assert "account holder" in out["recording_note"]

        # Recording stays possible, by the account holder, through the API (whose default is
        # unchanged): that call, and only that call, appends the bundle.
        direct = http.post("/v1/machine/verify", headers=headers, json={
            "envelope": envelope_dict(), "trace": run, "actor": "v.grimaldi", "subject": KEY})
        assert direct.status_code == 200 and direct.json()["sealed"] is True
        assert len(ledger) == 1
        for field_ in ("verdict", "tier", "provenance_basis", "content_hash"):
            assert direct.json()[field_] == body[field_], field_


@pytest.mark.asyncio
async def test_machine_verify_always_sends_seal_false_and_offers_no_way_to_change_it(
        monkeypatch) -> None:
    """The request, whatever the arguments: ``seal`` is false. There is no parameter for it."""
    from assurance.mcp import server

    sent: list[dict[str, Any]] = []

    async def record(method: str, path: str, *, json_body: Any = None, params: Any = None):
        assert (method, path) == ("POST", "/v1/machine/verify")
        sent.append(json_body)
        return {"status": 200, "body": {"sealed": json_body.get("seal", True)}}

    monkeypatch.setattr(server, "_call", record)
    param_sets: list[dict[str, Any]] = [
        {},
        {"subject": KEY},
        {"subject": "AR-7@2.4.1", "machine_serial": "0501", "configuration_hash": "a" * 64},
        {"recorder_attestations": [{"x": 1}]},
        {"subject": KEY, "machine_serial": "0501", "configuration_hash": "b" * 64,
         "recorder_attestations": [{"x": 1}]},
    ]
    for extra in param_sets:
        await server.machine_verify({}, {}, "a.b", **extra)
    assert len(sent) == len(param_sets)
    assert all(body["seal"] is False for body in sent), sent
    # the signature is exactly these seven: no `seal` (or any other way to opt in to recording)
    params = set(inspect.signature(server.machine_verify).parameters)
    assert params == {"envelope", "trace", "actor", "recorder_attestations", "machine_serial",
                      "subject", "configuration_hash"}, params
    # ... and an extra argument cannot smuggle one in
    with pytest.raises(TypeError):
        await server.machine_verify({}, {}, "a.b", seal=True)  # type: ignore[call-arg]
    assert len(sent) == len(param_sets)


@pytest.mark.asyncio
async def test_the_tool_never_says_not_recorded_unless_the_api_says_not_sealed(
        monkeypatch) -> None:
    """The note is the API's `sealed: false` relayed, not an assumption: a reply that does not
    say so (an error, an older service) gets no claim from this tool either way."""
    from assurance.mcp import server

    replies: list[dict[str, Any]] = [
        {"status": 401, "body": {"detail": "x"}},
        {"status": 200, "body": {"sealed": True}},
        {"status": 200, "body": {}},
        {"error": "could_not_reach_api"},
    ]

    async def reply(method: str, path: str, *, json_body: Any = None, params: Any = None):
        return copy.deepcopy(replies.pop(0))

    monkeypatch.setattr(server, "_call", reply)
    for _ in range(4):
        out = await server.machine_verify({}, {}, "a.b")
        assert "recorded" not in out and "recording_note" not in out, out


def test_the_tool_description_the_agent_sees_says_it_computes_and_does_not_record() -> None:
    from assurance.mcp import server

    doc = " ".join((server.machine_verify.__doc__ or "").split())
    assert doc.startswith("POST /v1/machine/verify")
    assert "NOT recorded" in doc and "does not append" in doc
    assert "account holder" in doc and "API or the CLI" in doc
    assert "files the sealed bundle" not in doc          # the old, false sentence
    assert "sealed" not in doc.lower().replace("not sealed", "")


# --------------------------------------------------------------------------- the guard
@dataclass
class Acct:
    """One throwaway Cell account holding a copy of the plant ledger, as its owner would."""

    tool: str
    account_id: str
    http: Any
    headers: dict[str, str]
    plant: Plant
    verification: str
    scratch: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest(self) -> dict[str, Any]:
        return self.plant.manifest_dict(KEY)

    @property
    def other_manifest(self) -> dict[str, Any]:
        return self.plant.manifest_dict(OTHER)

    @property
    def case_id(self) -> str:
        return self.plant.expected_drift_case_id()

    def api(self, method: str, path: str, expect: tuple[int, ...] = (200,), **kw: Any) -> Any:
        r = self.http.request(method, path, headers=self.headers, **kw)
        assert r.status_code in expect, (method, path, r.status_code, r.text[:300])
        return r.json()


@dataclass(frozen=True)
class Drive:
    """How to drive one tool to the route's real answer, and what that answer must be."""

    args: Callable[[Acct], dict[str, Any]]
    prepare: Callable[[Acct], None] | None = None


def _none(_: Acct) -> dict[str, Any]:
    return {}


def _claimed(a: Acct) -> None:
    a.api("POST", f"/v1/change/cases/{a.case_id}/claim", json={"owner": PERSON, "actor": PERSON})


def _awaiting_reverification(a: Acct) -> None:
    _claimed(a)
    for _ in range(2):
        a.api("POST", f"/v1/change/cases/{a.case_id}/advance", json={"actor": PERSON})


def _art14_case(a: Acct) -> None:
    a.api("POST", f"/v1/cases/{ART14_CASE}/signal", expect=(200, 201), json={
        "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
        "description": "Integrator observed exploitation on a live line",
        "reference": "TICKET-8812", "actor": ACTOR})


def _sbom_text() -> str:
    return raw(sbom_doc()).decode()


def _csaf_text() -> str:
    return raw(csaf_doc()).decode()


def _imported_sbom(a: Acct) -> None:
    a.scratch["draft_id"] = a.api("POST", "/v1/ingest/sbom",
                                  json={"document": _sbom_text()})["draft_id"]


def _imported_csaf(a: Acct) -> None:
    out = a.api("POST", "/v1/ingest/csaf", json={"document": _csaf_text()})
    a.scratch["advisory_ref"] = out["advisory_ref"]


def _drifted(a: Acct) -> dict[str, Any]:
    """The other machine's manifest with one safety item's content changed: a new case."""
    observed = copy.deepcopy(a.other_manifest)
    observed["manifest_id"] = "NOW"
    observed["items"][0]["content_hash"] = "d" * 64
    return observed


def _sealed_intervention(a: Acct) -> None:
    now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    a.api("POST", "/v1/machinery/intervention", json={"intervention": {
        "intervention_id": "INT-CLASSIFY-1", "machine_key": KEY, "item_id": "ITM-FW",
        "kind": "update", "occurred_at": now,
        "performed_by": {"identifier": "m.tech", "role": "service technician", "kind": "person"},
        "reason": "Vendor advisory: watchdog timeout under bus load.",
        "from_hash": "a" * 64, "to_hash": "d" * 64,
        "affects_functions": ["SF-01", "SF-02"]}})


def _declared(a: Acct) -> None:
    out = a.api("POST", "/v1/fleet/declare", json={
        "manifest": a.manifest, "doc_id": "DOC-CLASSIFY-1", "issued_by": "Grimaldi Robotics",
        "legislation": ["Regulation (EU) 2023/1230"]})
    a.scratch["declaration"] = out["declaration"]


def _unsealed_bundle(a: Acct) -> None:
    a.scratch["bundle"] = a.api("POST", "/v1/machine/verify", json={
        "envelope": envelope_dict(), "trace": trace_dict(datetime.now(UTC), trace_id="RUN-BUNDLE"),
        "actor": PERSON, "seal": False})


def _attested(a: Acct) -> None:
    """The account's ledger head counter-signed by the service key, and the log that holds it."""
    head = a.api("GET", "/v1/ledger/verify")["attestation"]
    a.api("POST", "/v1/ledger/attest", json={
        "ledger_length": head["length"], "head_seq": head["head_seq"],
        "head_link_hash": head["head_link_hash"]})
    a.scratch["attestations"] = a.api("GET", "/v1/ledger/attest/log")["attestations"]


def _passport(a: Acct) -> None:
    """A real passport for the machine, sealed into the account's ledger as its holder would."""
    a.scratch["passport"] = a.api("POST", "/v1/machinery/passport", json={
        "manifest": a.manifest, "actor": PERSON})


def _case_export(a: Acct) -> None:
    a.scratch["export"] = a.api("GET", f"/v1/change/cases/{a.case_id}/export")


SPEC_FIELDS = {"track": "actively_exploited_vulnerability", "stage": "early_warning"}

#: Every registered MCP tool, with the arguments that drive it to its route's real answer.
DRIVES: dict[str, Drive] = {
    # ---- free and anonymous
    "plans": Drive(_none),
    "capabilities": Drive(_none),
    "services": Drive(_none),
    "spec_fields": Drive(lambda a: dict(SPEC_FIELDS)),
    "spec_validate": Drive(lambda a: {**SPEC_FIELDS, "payload": {"product_name": "AR-7"}}),
    "machine_separation": Drive(lambda a: {
        "robot_speed_mm_s": 500.0, "reaction_time_s": 0.1, "stop_time_s": 0.3,
        "stop_distance_mm": 80.0, "measured_at_speed_mm_s": 500.0, "intrusion_distance_mm": 120.0}),
    "machine_assurance_check": Drive(lambda a: {
        "manifest": a.manifest, "advisory": advisory().to_dict()}),
    "machinery_diff": Drive(lambda a: {"baseline": a.manifest, "observed": a.manifest}),
    "machine_check": Drive(lambda a: {"bundle": a.scratch["bundle"]}, prepare=_unsealed_bundle),
    "evidence_verify": Drive(lambda a: {"bundle": a.scratch["export"]}, prepare=_case_export),
    "machinery_passport_check": Drive(lambda a: {"passport": a.scratch["passport"]},
                                      prepare=_passport),
    "attest_verify": Drive(lambda a: {"attestations": a.scratch["attestations"]},
                           prepare=_attested),
    "attest_service_key": Drive(_none),
    "fleet_declaration_check": Drive(
        lambda a: {"declaration": a.scratch["declaration"], "manifest": a.manifest,
                   "with_coverage": True}, prepare=_declared),
    # ---- Cell: reads of the account's own ledger
    "machine_verify": Drive(lambda a: {
        "envelope": envelope_dict(), "trace": trace_dict(datetime.now(UTC), trace_id="RUN-GUARD"),
        "actor": PERSON, "subject": KEY}),
    "machinery_coverage": Drive(lambda a: {"manifest": a.manifest}),
    "machinery_export": Drive(lambda a: {"machine": KEY, "skeleton": True}),
    "machinery_passport_check_ledger": Drive(lambda a: {"passport": a.scratch["passport"]},
                                             prepare=_passport),
    "fleet_report": Drive(_none),
    "fleet_machines": Drive(_none),
    "fleet_observations": Drive(_none),
    "fleet_machine_assurance": Drive(lambda a: {
        "machine_key": KEY, "advisory": advisory().to_dict()}),
    "value_position": Drive(_none),
    "ledger_verify": Drive(_none),
    "attest_log": Drive(_none),
    "supplier_trust_list": Drive(_none),
    "supplier_trust_check": Drive(lambda a: {"feed": "{}\n"}),
    "change_cases": Drive(_none),
    "change_case": Drive(lambda a: {"case_id": a.case_id}),
    "change_export": Drive(lambda a: {"case_id": a.case_id, "skeleton": True}),
    "change_replay": Drive(lambda a: {"case_id": a.case_id}),
    # ---- Register: Article 14
    "register_cases": Drive(_none),
    "art14_register": Drive(_none),
    "art14_breaches": Drive(_none),
    "art14_case": Drive(lambda a: {"case_id": ART14_CASE}, prepare=_art14_case),
    "art14_history": Drive(lambda a: {"case_id": ART14_CASE}, prepare=_art14_case),
    "art14_export": Drive(lambda a: {"case_id": ART14_CASE, "skeleton": True},
                          prepare=_art14_case),
    # ---- the operator's public-source store (read-only; the fixture below fills one)
    "intel_history": Drive(_none),
    "intel_observation": Drive(lambda a: {"seq": 1}),
    "intel_cve": Drive(lambda a: {"cve_id": CVE_LISTED}),
    "intel_candidates": Drive(_none),
    # ---- SBOM and CSAF reads
    "sbom_drafts": Drive(_none),
    "sbom_draft": Drive(lambda a: {"draft_id": a.scratch["draft_id"]}, prepare=_imported_sbom),
    "csaf_records": Drive(_none),
    "csaf_record": Drive(lambda a: {"advisory_ref": a.scratch["advisory_ref"]},
                         prepare=_imported_csaf),
    "csaf_impact": Drive(lambda a: {"advisory_ref": a.scratch["advisory_ref"]},
                         prepare=_imported_csaf),
    # ---- the writers the site classifies as agent writes
    "change_claim": Drive(lambda a: {"case_id": a.case_id, "owner": PERSON, "actor": PERSON}),
    "change_advance": Drive(lambda a: {"case_id": a.case_id, "actor": PERSON},
                            prepare=_claimed),
    "change_reverify": Drive(lambda a: {
        "case_id": a.case_id, "manifest": a.manifest,
        "verification_content_hash": a.verification, "actor": PERSON},
        prepare=_awaiting_reverification),
    "change_assess_drift": Drive(lambda a: {
        "baseline": a.other_manifest, "observed": _drifted(a), "actor": PERSON}),
    "change_assess_intervention": Drive(lambda a: {
        "manifest": a.manifest, "intervention_id": "INT-CLASSIFY-1", "actor": PERSON},
        prepare=_sealed_intervention),
    "sbom_import": Drive(lambda a: {"document": _sbom_text(), "actor": PERSON}),
    "csaf_import": Drive(lambda a: {"document": _csaf_text(), "actor": PERSON}),
}

#: Tools this file cannot drive generically, each with the reason. Empty is the goal.
NOT_DRIVEN: dict[str, str] = {}


@pytest.fixture
def plant(live_api, tmp_path, monkeypatch) -> tuple[Plant, str]:
    """Two enrolled machines, one drifted (a case is open), one real validated verification, and
    the service's own attestation key (generated here, test-only) so the attestation tools answer,
    and a filled public-feed store for the intel tools."""
    from assurance.attest.keys import SigningKey

    key_path = tmp_path / "secrets" / "service.pem"
    SigningKey.generate().save(key_path)
    monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(key_path))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    # the operator's store of public feeds (KEV, EPSS, NVD, CSAF fixtures), so the intel tools
    # answer from data and not with the 503 of an unconfigured deployment
    build_store(tmp_path / "intel.db")
    monkeypatch.setenv(STORE_ENV, str(tmp_path / "intel.db"))
    built = Plant(tmp_path / "plant")
    built.enrol_and_change("cli")
    return built, CliDriver(built).verify(PERSON)


def _account(live_api: fx.LiveApi, plant: Plant, verification: str, tool: str) -> Acct:
    client, key, account_id = _host(live_api, plant.ledger_path, f"classify-{tool}@example.de")
    return Acct(tool=tool, account_id=account_id, http=client, headers={"X-API-Key": key},
                plant=plant, verification=verification)


def test_every_registered_tool_is_driven_or_listed_with_a_reason() -> None:
    import asyncio

    from assurance.mcp import server

    registered = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert set(DRIVES) | set(NOT_DRIVEN) == registered, (
        "a new MCP tool needs a Drive here (or a reason in NOT_DRIVEN): "
        f"{sorted(registered ^ (set(DRIVES) | set(NOT_DRIVEN)))}")
    assert not set(DRIVES) & set(NOT_DRIVEN)
    assert all(reason.strip() for reason in NOT_DRIVEN.values())


def test_the_classification_this_guard_checks_against_is_the_committed_one() -> None:
    writers = {n for n, (_route, _tier, write) in _page_tools().items() if write}
    assert writers == {"change_claim", "change_advance", "change_reverify",
                       "change_assess_drift", "change_assess_intervention",
                       "sbom_import", "csaf_import"}
    assert "machine_verify" not in writers


@pytest.mark.asyncio
async def test_a_tool_writes_the_ledger_if_and_only_if_it_is_classified_as_a_write(
        live_api, plant, monkeypatch) -> None:
    from assurance.mcp import server

    built, verification = plant
    writers = {n for n, (_r, _t, write) in _page_tools().items() if write}
    monkeypatch.setenv("ASSURANCE_API_URL", live_api.url)
    operator = _operator_ledger()
    wrong: list[str] = []
    driven = 0
    for tool, drive in sorted(DRIVES.items()):
        acct = _account(live_api, built, verification, tool)
        ledger = live_api.tenant_ledger(acct.account_id)
        if drive.prepare:
            drive.prepare(acct)
        args = drive.args(acct)
        monkeypatch.setenv("ASSURANCE_API_KEY", acct.headers["X-API-Key"])
        before = (_fingerprint(ledger), _fingerprint(operator))
        out = await getattr(server, tool)(**args)
        after = (_fingerprint(ledger), _fingerprint(operator))
        acct.http.close()

        # the route's real answer, not a 4xx that would write nothing whatever the route did
        if out.get("status") != 200:
            wrong.append(f"{tool}: did not reach the route's success path: "
                         f"{json.dumps(out, default=str)[:300]}")
            continue
        if after[1] != before[1]:
            wrong.append(f"{tool}: wrote the operator's SHARED ledger")
        driven += 1
        grew = after[0] != before[0]
        if tool in writers and not grew:
            wrong.append(f"{tool}: classified as a write but the account ledger did not change")
        if tool not in writers and grew:
            wrong.append(f"{tool}: classified as read-only but the account ledger grew "
                         f"{before[0][0]} -> {after[0][0]}")
        if grew and after[0][0] <= before[0][0]:
            wrong.append(f"{tool}: the ledger changed without growing")
    assert not wrong, "\n".join(wrong)
    assert driven == len(DRIVES) >= 50
