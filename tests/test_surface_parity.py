"""The CLI, the HTTP API and MCP must say the same thing about the same ledger.

``assurance/capabilities.py`` declares that a command, a route and a tool are *one capability*.
That declaration is only worth something if the three return the same answer. Each test here
builds one synthetic ledger, points every surface at that same ledger (the CLI at the file, the
API at a per-account copy of the same bytes, MCP at the live API it wraps), calls each surface and
compares the *normalised domain fields*: the verdict vocabulary and the evidence identifiers and
hashes. Envelopes are not compared (an exit code is not an HTTP status; MCP wraps the API's reply
in ``{status, body}``); the facts inside them must be identical.

A surface that genuinely disagrees is a finding: the assertion stays, and the test is
``xfail(strict=True)`` with the exact defect, so a fix turns it into an error to delete the mark.

Only read-only capabilities that need no secret are exercised. Nothing here records, decides or
waives anything on any surface.
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from assurance import capabilities as cat

from . import interfaces_fixtures as fx
from .interfaces_scenario import PERSON, CliDriver, Plant, rows_of, run_cli

live_api = fx.live_api

HEX64 = re.compile(r"\b[0-9a-f]{64}\b")


@dataclass
class World:
    """One ledger, reachable through every surface."""

    cli_ledger: Path          # what the CLI reads
    client: Any               # httpx client authenticated as an account holding the same bytes
    api_url: str
    api_key: str
    root: Path
    manifest: dict[str, Any] | None = None
    case_id: str | None = None
    verification: str | None = None


def _host(live: fx.LiveApi, ledger: Path, email: str) -> tuple[Any, str, str]:
    """Give a hosted account the same ledger bytes the CLI reads."""
    from assurance.api import deps

    account_id, headers = live.account(email)
    dest = deps.tenant_ledger_path(account_id)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(ledger, dest)
    client = live.client()
    client.headers.update(headers)
    return client, headers["X-API-Key"], account_id


@pytest.fixture
def plant_world(live_api, tmp_path) -> World:
    """Two enrolled machines, one drifted (a case is open), one real validated verification."""
    plant = Plant(tmp_path / "plant")
    plant.enrol_and_change("cli")
    verification = CliDriver(plant).verify(PERSON)
    client, key, _ = _host(live_api, plant.ledger_path, "parity-plant@example.de")
    return World(plant.ledger_path, client, live_api.url, key, plant.root,
                 manifest=plant.manifest_dict(), case_id=plant.expected_drift_case_id(),
                 verification=verification)


@pytest.fixture
def demo_world(live_api, tmp_path) -> World:
    """The fleet ``report demo`` builds: many machines, mixed verdicts."""
    out = tmp_path / "demo"
    done = run_cli("report", "demo", "--out", out)
    assert done.returncode == 0, done.stdout + done.stderr
    ledger = next(out.rglob("*.db"))
    client, key, _ = _host(live_api, ledger, "parity-demo@example.de")
    from assurance.evidence.ledger import EvidenceLedger
    from assurance.fleet.registry import Fleet
    from assurance.machinery.record import manifests_from_ledger

    machine = Fleet.from_ledger(EvidenceLedger(ledger)).to_dict()["machines"][0]["machine"]
    manifest = manifests_from_ledger(EvidenceLedger(ledger), machine)[-1].to_dict()
    return World(ledger, client, live_api.url, key, out, manifest=manifest)


@pytest.fixture(params=["plant_world", "demo_world"])
def world(request) -> World:
    return request.getfixturevalue(request.param)


# ------------------------------------------------------------------ surface callers
def cli(world: World, *argv: Any) -> Any:
    return run_cli(*argv, cwd=world.root)


def cli_json(world: World, *argv: Any) -> dict[str, Any]:
    done = cli(world, *argv)
    assert done.stdout.strip(), (argv, done.returncode, done.stderr)
    return json.loads(done.stdout)


def mcp(monkeypatch: pytest.MonkeyPatch, world: World, tool: str, **args: Any) -> dict[str, Any]:
    """Call a real registered MCP tool, which calls the live API over HTTP."""
    from assurance.mcp import server

    monkeypatch.setenv("ASSURANCE_API_URL", world.api_url)
    monkeypatch.setenv("ASSURANCE_API_KEY", world.api_key)
    return asyncio.run(getattr(server, tool)(**args))


def mcp_body(reply: dict[str, Any]) -> Any:
    assert reply.get("status") == 200, reply
    return reply["body"]


# ------------------------------------------------------------------ normalisers
MACHINE_FIELDS = ("machine", "site", "manifest_id", "configuration_hash", "verdict", "worst",
                  "functions", "stale", "uncovered", "interventions", "unrecorded_changes",
                  "verifications", "tier_ceiling", "evidence_tier_floor")


def norm_fleet(doc: dict[str, Any]) -> dict[str, Any]:
    return {"summary": doc["summary"],
            "machines": [{k: m[k] for k in MACHINE_FIELDS} for m in doc["machines"]],
            "chain_verified": doc["chain_verified"], "chain_problems": doc["chain_problems"]}


def norm_coverage(doc: dict[str, Any]) -> dict[str, Any]:
    return {"machine": doc["machine"], "manifest_id": doc["manifest_id"],
            "configuration_hash": doc["configuration_hash"], "verdict": doc["verdict"],
            "functions": [{k: f[k] for k in ("function_id", "coverage", "last_verified_hash",
                                             "invalidated_by", "invalidating_item",
                                             "evidence_tier")} for f in doc["functions"]],
            "unrevalidated_interventions": sorted(doc.get("unrevalidated_interventions", []))}


def norm_replay(doc: dict[str, Any]) -> dict[str, Any]:
    case = doc["case"]
    return {"case_id": doc["case_id"], "ok": doc["ok"], "entries": doc["entries"],
            "violations": doc["violations"], "status": case["status"],
            "trigger_id": case["trigger_id"], "machines": case["machines"],
            "affected_functions": case["affected_functions"],
            "before_hash": case["before_hash"], "after_hash": case["after_hash"],
            "change_severity": case["change_severity"]}


def norm_evidence(doc: dict[str, Any]) -> dict[str, Any]:
    return {"ok": doc["ok"], "entries": doc["entries"], "scope": doc["scope"],
            "problems": doc["problems"], "unestablished": doc["unestablished"],
            "completeness": doc.get("completeness", "not_checked")}


def report_facts(html: str, machines: list[str]) -> dict[str, Any]:
    """What a plant manager's page asserts that must not differ by surface: which machines it
    names and every identifier (a 64-hex hash) it prints."""
    return {"machines": sorted(m for m in machines if m in html), "hashes": sorted(set(HEX64.findall(html)))}


# ------------------------------------------------------------------ fleet list
def test_fleet_list_cli_and_api_agree(world):
    from_cli = cli_json(world, "fleet", "list", "--ledger", world.cli_ledger, "--json")
    from_api = world.client.get("/v1/fleet/machines")
    assert from_api.status_code == 200
    assert norm_fleet(from_cli) == norm_fleet(from_api.json())
    assert from_cli["chain_verified"] is True and from_cli["machines"]


def test_fleet_list_exit_code_matches_the_verdict_vocabulary(world):
    """The CLI's exit code and the API's per-machine verdicts are two spellings of one answer:
    exit 0 only when no machine has gaps."""
    doc = world.client.get("/v1/fleet/machines").json()
    done = cli(world, "fleet", "list", "--ledger", world.cli_ledger, "--json")
    any_gaps = any(m["verdict"] != "covered" for m in doc["machines"])
    assert (done.returncode != 0) == any_gaps, (done.returncode, doc["summary"])


# ------------------------------------------------------------------ fleet report
def test_fleet_report_cli_api_and_mcp_name_the_same_machines_and_hashes(world, monkeypatch):
    out = world.root / "cli-report.html"
    done = cli(world, "report", "build", "--ledger", world.cli_ledger, "--out", out)
    assert done.returncode == 0, done.stderr
    api = world.client.get("/v1/fleet/report")
    assert api.status_code == 200
    via_mcp = mcp_body(mcp(monkeypatch, world, "fleet_report"))
    mcp_html = via_mcp["raw"] if isinstance(via_mcp, dict) else via_mcp
    machines = [m["machine"] for m in world.client.get("/v1/fleet/machines").json()["machines"]]
    expected = report_facts(api.text, machines)
    assert expected["machines"] == sorted(machines)
    assert report_facts(out.read_text(encoding="utf-8"), machines) == expected
    assert report_facts(mcp_html, machines) == expected


# ------------------------------------------------------------------ machinery coverage
def test_machinery_coverage_cli_api_and_mcp_agree(world, monkeypatch):
    manifest = world.root / "manifest.json"
    manifest.write_text(json.dumps(world.manifest), encoding="utf-8")
    from_cli = cli_json(world, "machinery", "coverage", manifest, "--ledger",
                        world.cli_ledger, "--json")
    api = world.client.post("/v1/machinery/coverage", json={"manifest": world.manifest})
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, world, "machinery_coverage", manifest=world.manifest))
    assert norm_coverage(from_cli) == norm_coverage(api.json()) == norm_coverage(via_mcp)


def test_a_real_verification_is_named_identically_by_every_surface(plant_world, monkeypatch):
    """The sealed verification's hash is the evidence identifier: it must be the same string in
    the CLI's answer, the API's and MCP's, for the machine it was filed against."""
    w = plant_world
    manifest = w.root / "m.json"
    manifest.write_text(json.dumps(w.manifest), encoding="utf-8")
    hashes = [
        {f["last_verified_hash"] for f in cli_json(
            w, "machinery", "coverage", manifest, "--ledger", w.cli_ledger, "--json")["functions"]},
        {f["last_verified_hash"] for f in w.client.post(
            "/v1/machinery/coverage", json={"manifest": w.manifest}).json()["functions"]},
        {f["last_verified_hash"] for f in mcp_body(mcp(
            monkeypatch, w, "machinery_coverage", manifest=w.manifest))["functions"]},
    ]
    assert hashes[0] == hashes[1] == hashes[2]
    assert w.verification in hashes[0]


# ------------------------------------------------------------------ ledger verify
def _cli_verify(world: World, ledger: Path):
    return cli(world, "art14", "--ledger", ledger, "verify")


def test_ledger_verify_cli_and_api_agree_on_an_intact_chain(world):
    done = _cli_verify(world, world.cli_ledger)
    api = world.client.get("/v1/ledger/verify").json()
    assert done.returncode == 0 and api["verified"] is True and api["problems"] == []
    head = api["attestation"]["head_link_hash"]
    assert f"head link hash  {head}" in done.stdout
    assert f"chain verified: {api['attestation']['length']} records" in done.stdout


def test_ledger_verify_cli_and_api_agree_on_a_tampered_chain(live_api, tmp_path):
    plant = Plant(tmp_path / "plant")
    plant.enrol_and_change("cli")
    db = sqlite3.connect(plant.ledger_path)
    try:
        with db:
            db.execute("UPDATE chain SET actor = 'mallory' WHERE seq = 3")
    finally:
        db.close()          # a closed connection checkpoints, so the copy below holds the edit
    client, _, _ = _host(live_api, plant.ledger_path, "parity-tamper@example.de")
    world = World(plant.ledger_path, client, live_api.url, "", plant.root)
    done = _cli_verify(world, plant.ledger_path)
    api = client.get("/v1/ledger/verify").json()
    assert done.returncode == 1 and "CHAIN VERIFICATION FAILED" in done.stderr
    assert api["verified"] is False and api["problems"]
    for problem in api["problems"]:
        assert problem in done.stderr
    fleet_cli = cli_json(world, "fleet", "list", "--ledger", plant.ledger_path, "--json")
    assert fleet_cli["chain_verified"] is False
    assert client.get("/v1/fleet/machines").json()["chain_verified"] is False


# ------------------------------------------------------------------ change replay
def test_change_replay_cli_and_api_agree(plant_world):
    w = plant_world
    from_cli = cli_json(w, "change", "replay", w.case_id, "--ledger", w.cli_ledger, "--json")
    api = w.client.get(f"/v1/change/cases/{w.case_id}/replay")
    assert api.status_code == 200
    assert norm_replay(from_cli) == norm_replay(api.json())
    assert from_cli["ok"] is True and from_cli["case_id"] == w.case_id


def test_change_replay_of_an_unknown_case_is_not_found_on_both(plant_world):
    w = plant_world
    done = cli(w, "change", "replay", "case-doesnotexist", "--ledger", w.cli_ledger, "--json")
    api = w.client.get("/v1/change/cases/case-doesnotexist/replay")
    assert api.status_code == 404
    assert done.returncode == 2 and "no case" in done.stderr


# ------------------------------------------------------------------ evidence verify
def _export(w: World) -> Path:
    path = w.root / "export.json"
    done = cli(w, "change", "export", w.case_id, "--ledger", w.cli_ledger, "--out", path)
    assert done.returncode == 0, done.stderr
    return path


def test_evidence_verify_cli_api_and_mcp_agree_on_an_intact_export(plant_world, monkeypatch):
    w = plant_world
    path = _export(w)
    from_cli = cli_json(w, "evidence", "verify", path, "--json")
    api = w.client.post("/v1/evidence/verify", content=path.read_text(encoding="utf-8"),
                        headers={"content-type": "application/json"})
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "evidence_verify",
                           bundle=json.loads(path.read_text(encoding="utf-8"))))
    assert norm_evidence(from_cli) == norm_evidence(api.json()) == norm_evidence(via_mcp)
    assert from_cli["ok"] is True and from_cli["completeness"] == "not_checked"


def test_evidence_verify_cli_api_and_mcp_agree_on_a_tampered_export(plant_world, monkeypatch):
    w = plant_world
    path = _export(w)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    bundle["entries"][0]["evidence"]["body"]["case"]["status"] = "closed"      # edit sealed content
    path.write_text(json.dumps(bundle), encoding="utf-8")
    done = cli(w, "evidence", "verify", path, "--json")
    from_cli = json.loads(done.stdout)
    api = w.client.post("/v1/evidence/verify", content=path.read_text(encoding="utf-8"),
                        headers={"content-type": "application/json"}).json()
    via_mcp = mcp_body(mcp(monkeypatch, w, "evidence_verify", bundle=bundle))
    assert done.returncode == 1
    assert from_cli["ok"] is api["ok"] is via_mcp["ok"] is False
    assert norm_evidence(from_cli) == norm_evidence(api) == norm_evidence(via_mcp)
    assert from_cli["problems"]


# ------------------------------------------------------------------ attestation verify
def test_attest_verify_cli_and_api_agree(plant_world, tmp_path):
    w = plant_world
    key, log = tmp_path / "attest.pem", tmp_path / "attest.jsonl"
    assert cli(w, "attest", "keygen", "--out", key).returncode == 0
    assert cli(w, "attest", "sign", "--ledger", w.cli_ledger, "--key", key, "--log", log
               ).returncode == 0
    pub = Path(str(key) + ".pub")
    from_cli = cli_json(w, "attest", "verify", "--log", log, "--public-key", pub, "--json")
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    api = w.client.post("/v1/ledger/attest/verify", json={
        "attestations": records, "public_key_pem": pub.read_text(encoding="utf-8")})
    assert api.status_code == 200, api.text
    body = api.json()
    assert from_cli["ok"] is body["ok"] is True
    assert from_cli["checked"] == body["checked"]
    assert from_cli["key_fingerprint"] == body["key_fingerprint"]
    assert from_cli["problems"] == body["problems"] == []
    assert from_cli["latest"]["head_link_hash"] == body["latest"]["head_link_hash"]


# ------------------------------------------------------------------ change list / show / export
def test_change_list_show_and_export_agree_on_every_surface(plant_world, monkeypatch):
    w = plant_world
    listing_cli = cli_json(w, "change", "list", "--ledger", w.cli_ledger, "--json")
    listing_api = w.client.get("/v1/change/cases").json()
    listing_mcp = mcp_body(mcp(monkeypatch, w, "change_cases"))
    assert rows_of(listing_cli) == rows_of(listing_api) == rows_of(listing_mcp)
    assert [r[0] for r in rows_of(listing_cli)] == [w.case_id]

    fields = ("case_id", "status", "trigger_type", "trigger_id", "machines", "affected_functions",
              "before_hash", "after_hash")
    shown = [cli_json(w, "change", "show", w.case_id, "--ledger", w.cli_ledger, "--json"),
             w.client.get(f"/v1/change/cases/{w.case_id}").json(),
             mcp_body(mcp(monkeypatch, w, "change_case", case_id=w.case_id))]
    assert [{k: c[k] for k in fields} for c in shown][0] == \
        [{k: c[k] for k in fields} for c in shown][1] == \
        [{k: c[k] for k in fields} for c in shown][2]

    bundles = [json.loads(_export(w).read_text(encoding="utf-8")),
               w.client.get(f"/v1/change/cases/{w.case_id}/export").json(),
               mcp_body(mcp(monkeypatch, w, "change_export", case_id=w.case_id))]
    identity = [[(e["kind"], e["content_hash"], e["link_hash"]) for e in b["entries"]]
                for b in bundles]
    assert identity[0] == identity[1] == identity[2] and identity[0]


# ------------------------------------------------------------------ MCP legs of CLI/API reads
def test_fleet_list_mcp_agrees_with_the_cli_and_the_api(world, monkeypatch):
    from_cli = cli_json(world, "fleet", "list", "--ledger", world.cli_ledger, "--json")
    from_api = world.client.get("/v1/fleet/machines").json()
    via_mcp = mcp_body(mcp(monkeypatch, world, "fleet_machines"))
    assert norm_fleet(from_cli) == norm_fleet(from_api) == norm_fleet(via_mcp)
    assert from_cli["machines"]


def test_ledger_verify_mcp_agrees_with_the_api_and_the_cli(world, monkeypatch):
    api = world.client.get("/v1/ledger/verify").json()
    via_mcp = mcp_body(mcp(monkeypatch, world, "ledger_verify"))
    assert (via_mcp["verified"], via_mcp["problems"], via_mcp["completeness"],
            via_mcp["ledger_id"], via_mcp["attestation"]["head_link_hash"]) == \
        (api["verified"], api["problems"], api["completeness"], api["ledger_id"],
         api["attestation"]["head_link_hash"])
    done = _cli_verify(world, world.cli_ledger)
    assert done.returncode == 0 and via_mcp["verified"] is True
    assert f"head link hash  {via_mcp['attestation']['head_link_hash']}" in done.stdout


def test_ledger_verify_mcp_reports_a_tampered_chain_as_the_api_and_cli_do(
        live_api, tmp_path, monkeypatch):
    plant = Plant(tmp_path / "plant")
    plant.enrol_and_change("cli")
    db = sqlite3.connect(plant.ledger_path)
    try:
        with db:
            db.execute("UPDATE chain SET actor = 'mallory' WHERE seq = 3")
    finally:
        db.close()
    client, key, _ = _host(live_api, plant.ledger_path, "parity-tamper-mcp@example.de")
    w = World(plant.ledger_path, client, live_api.url, key, plant.root)
    done = _cli_verify(w, plant.ledger_path)
    api = client.get("/v1/ledger/verify").json()
    via_mcp = mcp_body(mcp(monkeypatch, w, "ledger_verify"))
    assert done.returncode == 1
    assert via_mcp["verified"] is api["verified"] is False
    assert via_mcp["problems"] == api["problems"] and via_mcp["problems"]
    for problem in via_mcp["problems"]:
        assert problem in done.stderr


def test_change_replay_mcp_agrees_with_the_cli_and_the_api(plant_world, monkeypatch):
    w = plant_world
    from_cli = cli_json(w, "change", "replay", w.case_id, "--ledger", w.cli_ledger, "--json")
    api = w.client.get(f"/v1/change/cases/{w.case_id}/replay").json()
    via_mcp = mcp_body(mcp(monkeypatch, w, "change_replay", case_id=w.case_id))
    assert norm_replay(from_cli) == norm_replay(api) == norm_replay(via_mcp)
    assert via_mcp["ok"] is True
    unknown = mcp(monkeypatch, w, "change_replay", case_id="case-doesnotexist")
    assert unknown["status"] == 404


# ------------------------------------------------------------------ art14 reads
ART14_CASE = "case-a"
AWARE_AT = "2026-01-02T12:00:00Z"


@pytest.fixture
def art14_world(live_api, tmp_path) -> World:
    """One Article 14 case, written by the CLI, whose deadlines have long passed unfiled; the
    same bytes hosted for an account."""
    ledger = tmp_path / "art14.db"
    for argv in (("signal", ART14_CASE, "--by", "m.braun:Lead", "--description",
                  "exploited on a line", "--at", "2026-01-02T10:00:00Z"),
                 ("awareness", ART14_CASE, "--by", "m.braun:Lead", "--at", AWARE_AT,
                  "--started", "2026-01-02T10:30:00Z", "--completed", AWARE_AT,
                  "--track", "actively_exploited_vulnerability", "--because",
                  "shell spawned from the service port")):
        done = run_cli("art14", "--ledger", ledger, *argv, cwd=tmp_path)
        assert done.returncode == 0, done.stdout + done.stderr
    client, key, _ = _host(live_api, ledger, "parity-art14@example.de")
    return World(ledger, client, live_api.url, key, tmp_path, case_id=ART14_CASE)


def norm_art14_case(doc: dict[str, Any]) -> dict[str, Any]:
    """The case's facts. ``hours_remaining`` and the overdue text move with the clock."""
    d = doc["deadlines"] or {}
    return {"case_id": doc["case_id"], "state": doc["state"], "track": doc["track"],
            "signal": doc["signal"], "awareness": doc["awareness"], "triage": doc["triage"],
            "deadlines": [{k: x[k] for k in ("stage", "due_at", "runs_from", "provision",
                                             "status", "submitted_at")}
                          for x in d.get("deadlines", [])],
            "pending_facts": d.get("pending_facts"), "breaches": d.get("breaches")}


def test_art14_fields_cli_api_and_mcp_agree(live_api, monkeypatch, tmp_path):
    client, key, _ = _host_empty(live_api, tmp_path, "parity-fields@example.de")
    w = World(tmp_path / "none.db", client, live_api.url, key, tmp_path)
    for track, stage in (("actively_exploited_vulnerability", "early_warning"),
                         ("severe_incident", "notification"),
                         ("severe_incident", "final")):
        from_cli = cli_json(w, "art14", "fields", "--track", track, "--stage", stage, "--json")
        api = client.get("/v1/spec/fields", params={"track": track, "stage": stage})
        assert api.status_code == 200
        via_mcp = mcp_body(mcp(monkeypatch, w, "spec_fields", track=track, stage=stage))
        assert from_cli == api.json() == via_mcp and from_cli
    bad = mcp(monkeypatch, w, "spec_fields", track="nope", stage="final")
    assert bad["status"] == 422                 # the API's refusal, not a tool-side check


def _host_empty(live: fx.LiveApi, tmp_path: Path, email: str) -> tuple[Any, str, str]:
    account_id, headers = live.account(email)
    client = live.client()
    client.headers.update(headers)
    return client, headers["X-API-Key"], account_id


def test_art14_case_cli_api_and_mcp_agree(art14_world, monkeypatch):
    w = art14_world
    from_cli = cli_json(w, "art14", "--ledger", w.cli_ledger, "case", ART14_CASE, "--json")
    api = w.client.get(f"/v1/cases/{ART14_CASE}")
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "art14_case", case_id=ART14_CASE))
    assert norm_art14_case(from_cli) == norm_art14_case(api.json()) == norm_art14_case(via_mcp)
    assert from_cli["awareness"]["established_at"] == AWARE_AT
    # an id nothing was recorded under is not a case, on every surface
    done = cli(w, "art14", "--ledger", w.cli_ledger, "case", "case-none", "--json")
    assert done.returncode == 2 and "no case" in done.stderr
    assert w.client.get("/v1/cases/case-none").status_code == 404
    assert mcp(monkeypatch, w, "art14_case", case_id="case-none")["status"] == 404


def test_art14_register_cli_api_and_mcp_agree(art14_world, monkeypatch):
    w = art14_world
    from_cli = cli_json(w, "art14", "--ledger", w.cli_ledger, "register", "--json")
    api = w.client.get("/v1/register").json()
    via_mcp = mcp_body(mcp(monkeypatch, w, "art14_register"))

    def facts(doc: dict[str, Any]) -> dict[str, Any]:
        return {"cases": [norm_art14_case(c) for c in doc["cases"]],
                "records": doc["ledger"]["records"],
                "chain_verified": doc["ledger"]["chain_verified"],
                "head": doc["ledger"]["attestation"]["head_link_hash"],
                "regulation": doc["regulation"], "field_spec": doc["field_spec"]}

    assert facts(from_cli) == facts(api) == facts(via_mcp)
    assert [c["case_id"] for c in from_cli["cases"]] == [ART14_CASE]


def test_art14_breaches_mcp_and_api_agree_and_the_cli_exit_code_says_the_same(
        art14_world, live_api, monkeypatch, tmp_path):
    w = art14_world
    api = w.client.get("/v1/register/breaches").json()
    via_mcp = mcp_body(mcp(monkeypatch, w, "art14_breaches"))
    assert api == via_mcp
    assert {(b["case_id"], b["stage"], b["status"]) for b in api} == {
        (ART14_CASE, "early_warning", "overdue_unfiled"),
        (ART14_CASE, "notification", "overdue_unfiled")}
    # the CLI has no breaches verb: `art14 register` exits 1 when there are any
    done = cli(w, "art14", "--ledger", w.cli_ledger, "register")
    assert done.returncode == 1
    for b in api:
        assert b["due_at"] in done.stdout
    # an account with no cases: no breaches on any surface, and the CLI exits 0
    client, key, _ = _host_empty(live_api, tmp_path, "parity-nobreach@example.de")
    empty = World(tmp_path / "empty.db", client, live_api.url, key, tmp_path)
    assert client.get("/v1/register/breaches").json() == [] == mcp_body(
        mcp(monkeypatch, empty, "art14_breaches"))
    assert cli(empty, "art14", "--ledger", tmp_path / "empty.db", "register").returncode == 0


def test_art14_export_cli_api_and_mcp_agree(art14_world, monkeypatch):
    w = art14_world
    out = w.root / "art14-export.json"
    done = cli(w, "art14", "--ledger", w.cli_ledger, "export", "--case", ART14_CASE, "-o", out)
    assert done.returncode == 0, done.stderr
    bundles = [json.loads(out.read_text(encoding="utf-8")),
               w.client.get(f"/v1/cases/{ART14_CASE}/export", params={"anchor": "false"}).json(),
               mcp_body(mcp(monkeypatch, w, "art14_export", case_id=ART14_CASE, anchor=False))]
    identity = [[(e["kind"], e["content_hash"], e["link_hash"]) for e in b["entries"]]
                for b in bundles]
    assert identity[0] == identity[1] == identity[2] and len(identity[0]) == 2
    assert all(b["subject"] == ART14_CASE for b in bundles)
    # what the tool exports is what `evidence verify` accepts
    out.write_text(json.dumps(bundles[2]), encoding="utf-8")
    assert cli_json(w, "evidence", "verify", out, "--json")["ok"] is True
    # an unknown case is a 404, never an empty bundle that reads as a clean record
    assert mcp(monkeypatch, w, "art14_export", case_id="case-none")["status"] == 404


# ------------------------------------------------------------------ pure reads of supplied input
def test_machine_separation_cli_api_and_mcp_agree(live_api, monkeypatch, tmp_path):
    from .interfaces_support import envelope_dict

    env = envelope_dict()
    path = tmp_path / "env.json"
    path.write_text(json.dumps(env), encoding="utf-8")
    client, key, _ = _host_empty(live_api, tmp_path, "parity-sep@example.de")
    w = World(tmp_path / "none.db", client, live_api.url, key, tmp_path)
    inputs = {
        "robot_speed_mm_s": 500.0, "reaction_time_s": env["stop"]["reaction_time_s"],
        "stop_time_s": env["stop"]["stop_time_s"], "stop_distance_mm": env["stop"]["stop_distance_mm"],
        "measured_at_speed_mm_s": env["stop"]["measured_at_speed_mm_s"],
        "intrusion_distance_mm": env["intrusion_distance_mm"],
        "human_position_uncertainty_mm": env["uncertainty"]["human_position_mm"],
        "robot_position_uncertainty_mm": env["uncertainty"]["robot_position_mm"]}
    from_cli = cli_json(w, "machine", "separation", "--envelope", path, "--speed", "500", "--json")
    api = client.post("/v1/machine/separation", json=inputs)
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "machine_separation", **inputs))
    assert from_cli["total_mm"] == 1730.0
    for name in ("Sh_human_travel_mm", "Sr_robot_reaction_travel_mm", "Ss_robot_stopping_travel_mm",
                 "C_intrusion_mm", "Zd_human_uncertainty_mm", "Zr_robot_uncertainty_mm",
                 "total_mm", "human_speed_mm_s", "robot_speed_mm_s"):
        assert from_cli[name] == api.json()["breakdown"][name] == via_mcp["breakdown"][name], name
    assert api.json() == via_mcp


def test_machinery_diff_cli_api_and_mcp_agree(plant_world, monkeypatch):
    w = plant_world
    base = w.manifest
    changed = json.loads(json.dumps(base))
    changed["items"][0]["content_hash"] = "d" * 64          # a hash changes: the finding
    paths = []
    for name, doc in (("base.json", base), ("changed.json", changed)):
        p = w.root / name
        p.write_text(json.dumps(doc), encoding="utf-8")
        paths.append(p)
    for observed, p in ((base, paths[0]), (changed, paths[1])):
        from_cli = cli_json(w, "machinery", "diff", "--baseline", paths[0], "--observed", p,
                            "--json")
        api = w.client.post("/v1/machinery/diff", json={"baseline": base, "observed": observed})
        assert api.status_code == 200, api.text
        via_mcp = mcp_body(mcp(monkeypatch, w, "machinery_diff", baseline=base, observed=observed))
        assert from_cli == api.json() == via_mcp
    assert from_cli["verdict"] != cli_json(w, "machinery", "diff", "--baseline", paths[0],
                                           "--observed", paths[0], "--json")["verdict"]


def test_fleet_declaration_cli_api_and_mcp_agree(plant_world, monkeypatch):
    w = plant_world
    man = w.root / "m.json"
    man.write_text(json.dumps(w.manifest), encoding="utf-8")
    decl = w.root / "decl.json"
    done = cli(w, "fleet", "declare", man, "--doc-id", "DOC-9", "--issued-by", "Grimaldi Engineering",
               "--legislation", "Regulation (EU) 2023/1230", "--out", decl)
    assert done.returncode == 0, done.stdout + done.stderr
    declaration = json.loads(decl.read_text(encoding="utf-8"))
    declaration = declaration.get("declaration", declaration)
    for with_coverage in (False, True):
        argv = ["fleet", "declaration", decl, "--manifest", man, "--json"]
        if with_coverage:
            argv += ["--ledger", w.cli_ledger]
        from_cli = cli_json(w, *argv)
        api = w.client.post("/v1/fleet/declaration/check", json={
            "declaration": declaration, "manifest": w.manifest, "with_coverage": with_coverage})
        assert api.status_code == 200, api.text
        via_mcp = mcp_body(mcp(monkeypatch, w, "fleet_declaration_check", declaration=declaration,
                               manifest=w.manifest, with_coverage=with_coverage))
        picked = [{k: d[k] for k in ("verdict", "configuration_matches", "evidence_assessed")
                   if k in d} for d in (from_cli, api.json(), via_mcp)]
        assert picked[0] == picked[1] == picked[2], with_coverage
        assert picked[0].get("verdict")
    # the unassessed answer is not a pass, on any surface
    unassessed = mcp_body(mcp(monkeypatch, w, "fleet_declaration_check", declaration=declaration,
                              manifest=w.manifest))
    assert unassessed["verdict"] != "describes_the_machine"


def test_fleet_value_cli_api_and_mcp_agree(world, monkeypatch):
    from_cli = cli_json(world, "value", "report", "--ledger", world.cli_ledger, "--json")
    api = world.client.get("/v1/value")
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, world, "value_position"))

    def facts(doc: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in doc.items() if k != "as_of"}

    assert facts(from_cli) == facts(api.json()) == facts(via_mcp)
    assert from_cli["ledger"]["chain_verified"] is True and from_cli["machines"]


# ------------------------------------------------------------------ supplier trust
@pytest.fixture
def supplier_world(live_api, tmp_path) -> tuple[World, Path]:
    """A supplier's signed feed, a key pinned in the account's ledger by the CLI, and the same
    ledger hosted. Returns the world and the feed file."""
    from .test_assurance_supplier import IDENTITY, _advisory

    key, feed, ledger = tmp_path / "k.pem", tmp_path / "feed.jsonl", tmp_path / "trust.db"
    (tmp_path / "identity.json").write_text(json.dumps(IDENTITY.to_dict()), encoding="utf-8")
    (tmp_path / "adv.json").write_text(json.dumps(_advisory().to_dict()), encoding="utf-8")
    for argv in (("supplier", "keygen", "--out", key),
                 ("supplier", "publish", tmp_path / "adv.json", "--feed", feed, "--key", key,
                  "--identity", tmp_path / "identity.json"),
                 ("supplier", "trust", "pin", "--ledger", ledger, "--supplier-id",
                  IDENTITY.supplier_id, "--public-key", Path(str(key) + ".pub"),
                  "--obtained-via", "read aloud on a call to the supplier", "--actor", PERSON)):
        done = run_cli(*argv, cwd=tmp_path)
        assert done.returncode == 0, (argv, done.stdout, done.stderr)
    client, api_key, _ = _host(live_api, ledger, "parity-supplier@example.de")
    return World(ledger, client, live_api.url, api_key, tmp_path), feed


def test_supplier_trust_list_cli_api_and_mcp_agree(supplier_world, monkeypatch):
    w, _ = supplier_world
    from_cli = cli_json(w, "supplier", "trust", "list", "--ledger", w.cli_ledger, "--json")
    api = w.client.get("/v1/supplier/trust")
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "supplier_trust_list"))

    def facts(doc: dict[str, Any]) -> dict[str, Any]:
        return {"pins": [{k: p.get(k) for k in ("supplier_id", "fingerprint")}
                         for p in doc["pins"]],
                "history": [(h.get("action"), h.get("supplier_id"), h.get("actor"))
                            for h in doc["history"]],
                "overrides": doc["overrides"], "integrity": doc["integrity_problems"]}

    assert facts(from_cli) == facts(api.json()) == facts(via_mcp)
    assert len(from_cli["pins"]) == 1


def test_supplier_trust_check_cli_api_and_mcp_agree(supplier_world, monkeypatch):
    w, feed = supplier_world
    text = feed.read_text(encoding="utf-8")
    from_cli = cli_json(w, "supplier", "trust", "check", "--ledger", w.cli_ledger, "--feed", feed,
                        "--json")
    api = w.client.post("/v1/supplier/trust/evaluate", json={"feed": text})
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "supplier_trust_check", feed=text))
    keys = ("trust_state", "policy_satisfied", "signature_state", "key_trust_state",
            "chain_valid", "supplier_id", "record_count", "structurally_readable")

    def facts(doc: dict[str, Any]) -> dict[str, Any]:
        trust = doc.get("trust", doc)
        return {**{k: trust[k] for k in keys},
                "advisories": [a["advisory_id"] for a in trust["advisories"]]}

    assert facts(from_cli) == facts(api.json()) == facts(via_mcp)
    # a feed that was tampered with after signing is not trusted, on every surface
    forged = text.replace("Parameter", "Parameters", 1) if "Parameter" in text else text + "x"
    forged_api = w.client.post("/v1/supplier/trust/evaluate", json={"feed": forged}).json()
    forged_mcp = mcp_body(mcp(monkeypatch, w, "supplier_trust_check", feed=forged))
    assert facts(forged_api) == facts(forged_mcp)
    assert facts(forged_mcp)["policy_satisfied"] is False


# ------------------------------------------------------------------ attestations
@pytest.fixture
def attest_world(plant_world, tmp_path, monkeypatch) -> tuple[World, Path, Path]:
    """The plant's account, a service attestation key (generated here, test-only) and one head
    signed through the API. Returns the world, the log file the service wrote and the public key."""
    from assurance.attest.keys import SigningKey

    key_path = tmp_path / "secrets" / "service.pem"
    SigningKey.generate().save(key_path)
    logs = tmp_path / "attestations"
    monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(key_path))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(logs))
    w = plant_world
    head = w.client.get("/v1/ledger/verify").json()["attestation"]
    signed = w.client.post("/v1/ledger/attest", json={
        "ledger_length": head["length"], "head_seq": head["head_seq"],
        "head_link_hash": head["head_link_hash"]})
    assert signed.status_code in (200, 201), signed.text
    (log,) = sorted(logs.glob("*.jsonl"))
    pub = tmp_path / "service.pub"
    pub.write_text(w.client.get("/v1/ledger/attest/key").json()["public_key_pem"], encoding="utf-8")
    return w, log, pub


def test_attest_verify_and_log_cli_api_and_mcp_agree(attest_world, monkeypatch):
    w, log, pub = attest_world
    from_cli = cli_json(w, "attest", "verify", "--log", log, "--public-key", pub, "--json")
    records = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]
    api = w.client.post("/v1/ledger/attest/verify", json={"attestations": records})
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "attest_verify", attestations=records))
    for doc in (api.json(), via_mcp):
        assert from_cli["ok"] is doc["ok"] is True
        assert from_cli["checked"] == doc["checked"]
        assert from_cli["key_fingerprint"] == doc["key_fingerprint"]
        assert from_cli["problems"] == doc["problems"] == []
        assert from_cli["latest"]["head_link_hash"] == doc["latest"]["head_link_hash"]
    # an edited record fails on every surface
    bad = [dict(records[0], head_link_hash="0" * 64)]
    bad_log = w.root / "bad.jsonl"
    bad_log.write_text("\n".join(json.dumps(r) for r in bad) + "\n", encoding="utf-8")
    done = cli(w, "attest", "verify", "--log", bad_log, "--public-key", pub, "--json")
    assert done.returncode != 0 and json.loads(done.stdout)["ok"] is False
    assert w.client.post("/v1/ledger/attest/verify", json={"attestations": bad}).json()["ok"] is False
    assert mcp_body(mcp(monkeypatch, w, "attest_verify", attestations=bad))["ok"] is False


def test_attest_log_cli_api_and_mcp_agree(attest_world, monkeypatch):
    w, log, _ = attest_world
    from_cli = cli_json(w, "attest", "log", "--log", log, "--json")
    api = w.client.get("/v1/ledger/attest/log")
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "attest_log"))

    def heads(doc: Any) -> list[str]:
        rows = doc["attestations"] if isinstance(doc, dict) else doc
        return [r["head_link_hash"] for r in rows]

    assert heads(from_cli) == heads(api.json()) == heads(via_mcp) and len(heads(from_cli)) == 1
    assert via_mcp["count"] == api.json()["count"] == 1


def test_fleet_observations_api_and_mcp_agree(plant_world, monkeypatch):
    """No CLI verb: `watch status` is the local run, this is the hosted view of pushed runs. The
    plant's ledger was never pushed, so both say the same thing: nothing was reported."""
    w = plant_world
    api = w.client.get("/v1/fleet/observations")
    assert api.status_code == 200, api.text
    via_mcp = mcp_body(mcp(monkeypatch, w, "fleet_observations"))

    def facts(doc: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in doc.items() if k not in ("as_of", "generated_at", "now")}

    assert facts(api.json()) == facts(via_mcp)


def test_attest_service_key_api_and_mcp_agree(attest_world, monkeypatch):
    w, _, pub = attest_world
    api = w.client.get("/v1/ledger/attest/key").json()
    via_mcp = mcp_body(mcp(monkeypatch, w, "attest_service_key"))
    assert api == via_mcp and via_mcp["public_key_pem"].strip() == pub.read_text("utf-8").strip()


# ------------------------------------------------------------------ the catalogue's promise
#: capability id -> the parity test above that exercises it, for each surface set it declares.
EXERCISED = {
    "fleet.machines": ("cli", "api", "mcp"),
    "fleet.report": ("cli", "api", "mcp"),
    "machinery.coverage": ("cli", "api", "mcp"),
    "evidence.ledger_verify": ("cli", "api", "mcp"),
    "change.replay": ("cli", "api", "mcp"),
    "change.list": ("cli", "api", "mcp"),
    "change.show": ("cli", "api", "mcp"),
    "change.export": ("cli", "api", "mcp"),
    "attest.verify": ("cli", "api", "mcp"),
    "attest.log": ("cli", "api", "mcp"),
    "evidence.verify": ("cli", "api", "mcp"),
    "art14.fields": ("cli", "api", "mcp"),
    "art14.case": ("cli", "api", "mcp"),
    "art14.register": ("cli", "api", "mcp"),
    "art14.breaches": ("cli", "api", "mcp"),
    "art14.export": ("cli", "api", "mcp"),
    "machine.separation": ("cli", "api", "mcp"),
    "machinery.diff": ("cli", "api", "mcp"),
    "fleet.declaration": ("cli", "api", "mcp"),
    "fleet.value": ("cli", "api", "mcp"),
    "supplier.trust_list": ("cli", "api", "mcp"),
    "supplier.trust_check": ("cli", "api", "mcp"),
    # no CLI verb by design (the CLI form is the local `watch status` / an HTTP-only key route):
    "fleet.observations": ("api", "mcp"),
    "attest.service_key": ("api", "mcp"),
}


def test_every_exercised_capability_is_present_on_the_surfaces_claimed_here():
    by_id = {c.id: c for c in cat.CAPABILITIES}
    for cap_id, surfaces in EXERCISED.items():
        for surface in surfaces:
            assert by_id[cap_id].claims(surface), (cap_id, surface)


def test_no_read_only_three_surface_capability_is_left_unexercised():
    """A capability catalogued as present on CLI, API and MCP is a promise of equivalence. If a
    new one appears, add a parity test above, or say here why it cannot be exercised."""
    declared_exempt = {
        "machine.verify": "a write (seals a verification); needs a recorder attestation and "
                          "trust list, driven by tests/test_interfaces_parity.py",
        "machine.check": "needs a sealed verification bundle; see the machine bundle tests",
        "machinery.passport_check": "needs a sealed passport, which is a write; see passport tests",
        "art14.validate": "a validator over a supplied draft with no ledger to compare; "
                          "see the spec tests",
        "catalogue.capabilities": "compared by tests/test_assurance_capabilities.py",
        "change.claim": "a write", "change.advance": "a write", "change.reverify": "a write",
        "change.assess_drift": "a write", "change.assess_intervention": "a write",
    }
    triple = [c.id for c in cat.CAPABILITIES if c.cli and c.api and c.mcp]
    missing = [i for i in triple if i not in EXERCISED and i not in declared_exempt]
    assert not missing, (
        f"present on CLI, API and MCP but with no parity test and no stated reason: {missing}")
