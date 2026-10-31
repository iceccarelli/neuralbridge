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


# ------------------------------------------------------------------ the catalogue's promise
#: capability id -> the parity test above that exercises it, for each surface set it declares.
EXERCISED = {
    "fleet.machines": ("cli", "api"),
    "fleet.report": ("cli", "api", "mcp"),
    "machinery.coverage": ("cli", "api", "mcp"),
    "evidence.ledger_verify": ("cli", "api"),
    "change.replay": ("cli", "api"),
    "change.list": ("cli", "api", "mcp"),
    "change.show": ("cli", "api", "mcp"),
    "change.export": ("cli", "api", "mcp"),
    "attest.verify": ("cli", "api"),
    "evidence.verify": ("cli", "api", "mcp"),
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
