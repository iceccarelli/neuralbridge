"""A machine's own evidence is exportable over HTTP and MCP, and the export verifies.

``GET /v1/cases`` lists a machine key (``maker/model#serial``) beside the case ids, but
``/v1/cases/{id}/export`` cannot name one: the key holds ``/`` and ``#``, so a machine's manifests,
interventions, verifications and passports could be exported only with the offline CLI.
``GET /v1/machinery/export?machine=`` is the hosted route; ``machinery_export`` is its MCP tool.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from . import interfaces_fixtures as fx  # noqa: E402
from .test_assurance_passport_check import manifest  # noqa: E402

live_api = fx.live_api


@pytest.fixture
def world(live_api):
    acct, headers = live_api.account("machine-export@example.de")
    m = manifest()
    with live_api.client() as http:
        r = http.post("/v1/machinery/manifest", headers=headers,
                      json={"manifest": m.to_dict(), "actor": "V. Grimaldi"})
        assert r.status_code == 200, r.text
        # an unrelated subject in the same ledger, to prove the export is for one machine
        r = http.post("/v1/cases/CASE-OTHER/signal", headers=headers, json={
            "received_at": "2026-09-18T21:40:00Z", "channel": "other", "description": "d",
            "actor": {"identifier": "monitor", "kind": "automation"}})
        assert r.status_code == 201, r.text
    return live_api, headers, m


def test_the_export_holds_the_machines_records_and_no_other_subject(world):
    api, headers, m = world
    with api.client() as http:
        r = http.get("/v1/machinery/export", headers=headers, params={"machine": m.machine.key})
    assert r.status_code == 200, r.text
    bundle = r.json()
    subjects = {e["subject"] for e in bundle["entries"]}
    assert subjects == {m.machine.key}
    assert any(e["kind"] == "machinery.safety_manifest" for e in bundle["entries"])
    assert "CASE-OTHER" not in json.dumps(bundle)          # skeleton is off by default
    assert "skeleton" not in bundle or not bundle["skeleton"]


def test_the_skeleton_is_opt_in_and_names_the_other_subjects(world):
    api, headers, m = world
    with api.client() as http:
        r = http.get("/v1/machinery/export", headers=headers,
                     params={"machine": m.machine.key, "skeleton": "true"})
    assert r.status_code == 200
    assert any(row["subject"] == "CASE-OTHER" for row in r.json()["skeleton"])


def test_the_export_verifies_with_the_free_checker(world):
    api, headers, m = world
    with api.client() as http:
        bundle = http.get("/v1/machinery/export", headers=headers,
                          params={"machine": m.machine.key}).json()
        r = http.post("/v1/evidence/verify", content=json.dumps(bundle),
                      headers={"content-type": "application/json"})
    assert r.status_code == 200, r.text
    result = r.json()
    assert result["kind"] == "ledger_export" and result["ok"] is True
    assert result["outcome"] == "no_inconsistency_found"     # consistent; completeness not shown
    assert result["problems"] == [] and result["not_checked"]


def test_a_machine_with_no_record_is_a_404_not_an_empty_bundle(world):
    api, headers, _ = world
    with api.client() as http:
        r = http.get("/v1/machinery/export", headers=headers,
                     params={"machine": "Nobody/Nothing#0001"})
    assert r.status_code == 404 and r.json()["detail"]["error"] == "machine_not_found"


def test_it_reads_only_the_callers_own_ledger(world):
    api, _, m = world
    _, other = api.account("machine-export-other@example.de")
    with api.client() as http:
        r = http.get("/v1/machinery/export", headers=other, params={"machine": m.machine.key})
    assert r.status_code == 404


def test_it_is_gated_like_the_other_machine_routes(world):
    api, headers, m = world
    with api.client() as http:
        assert http.get("/v1/machinery/export", params={"machine": m.machine.key}
                        ).status_code == 401
        free_acct, free = api.account("machine-export-free@example.de", tier="free")
        assert http.get("/v1/machinery/export", headers=free,
                        params={"machine": m.machine.key}).status_code == 402


@pytest.mark.asyncio
async def test_the_mcp_tool_returns_the_same_bundle(world, monkeypatch) -> None:
    from assurance.mcp import server

    api, headers, m = world
    monkeypatch.setenv("ASSURANCE_API_URL", api.url)
    monkeypatch.setenv("ASSURANCE_API_KEY", headers["X-API-Key"])
    got = await server.machinery_export(m.machine.key)
    assert got["status"] == 200
    assert {e["subject"] for e in got["body"]["entries"]} == {m.machine.key}
    assert (await server.machinery_export(" "))["error"] == "invalid_machine"
    assert (await server.machinery_export("Nobody/Nothing#0001"))["status"] == 404


def test_the_cli_exports_the_same_machine_subject(world, tmp_path):
    """The CLI twin (`art14 export --case <subject>`) takes a machine key as the subject."""
    from assurance.security.art14.cli import main

    api, headers, m = world
    ledger = api.tenant_ledger(_account_id(api, headers))
    out = tmp_path / "machine.json"
    code = main(["--ledger", str(ledger.path), "export", "--case", m.machine.key,
                 "-o", str(out)])
    assert code == 0
    assert {e["subject"] for e in json.loads(out.read_text())["entries"]} == {m.machine.key}


def _account_id(api, headers) -> str:
    return api.accounts.resolve_key(headers["X-API-Key"]).account.id
