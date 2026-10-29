"""The capability catalogue is generated from, and checked against, the real surfaces.

``assurance/capabilities.py`` declares which command, route and tool are one capability. These
tests read the live app, the real CLI parsers and the MCP server source, so a surface added
without a declaration, a declaration that names something that no longer exists, and a surface
left out with no stated reason all fail here, not in a customer's integration.
"""
# ruff: noqa: S603  (runs this repository's own CLI)
from __future__ import annotations

import dataclasses
import json
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from assurance import capabilities as cat
from assurance.api import deps
from assurance.api.service import create_app


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "l.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "a.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", "op-key-capabilities")
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield create_app()
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


def test_the_declared_catalogue_agrees_with_the_code(app):
    assert cat.problems(app) == []


def _mutated(caps, cap_id, **change):
    return tuple(dataclasses.replace(c, **change) if c.id == cap_id else c for c in caps)


@pytest.mark.parametrize("label,mutate,expect", [
    ("a real capability dropped", lambda cs: tuple(c for c in cs if c.id != "machine.verify"),
     "uncatalogued"),
    ("a CLI verb that does not exist",
     lambda cs: _mutated(cs, "machine.verify", cli=("machine teleport",)),
     "does not exist"),
    ("an API route that does not exist",
     lambda cs: _mutated(cs, "machine.verify", api=("POST /v1/nope",)), "does not exist"),
    ("an MCP tool that does not exist",
     lambda cs: _mutated(cs, "machine.verify", mcp=("machine_teleport",)), "does not exist"),
    ("a surface left empty with no reason",
     lambda cs: _mutated(cs, "art14.signal", gaps={}), "does not say why"),
    ("absent and present at once",
     lambda cs: _mutated(cs, "machine.verify", gaps={"mcp": (cat.PLANNED, "x")}),
     "declares mcp absent"),
    ("a gap with an empty reason",
     lambda cs: _mutated(cs, "art14.signal", gaps={"mcp": (cat.BY_DESIGN, "  ")}),
     "needs a kind and a reason"),
    ("an MCP tool attached to the wrong capability",
     lambda cs: _mutated(cs, "machine.verify", mcp=("plans",)), "wraps"),
    ("a duplicate capability id", lambda cs: (*cs, cs[0]), "duplicate capability id"),
])
def test_every_kind_of_drift_is_reported(app, monkeypatch, label, mutate, expect):
    monkeypatch.setattr(cat, "CAPABILITIES", mutate(cat.CAPABILITIES))
    found = cat.problems(app)
    assert found, label
    assert any(expect in line for line in found), (label, found)


def test_every_gap_is_by_design_or_planned_with_a_reason():
    for cap in cat.CAPABILITIES:
        for surface, (kind, reason) in cap.gaps.items():
            assert kind in (cat.BY_DESIGN, cat.PLANNED), (cap.id, surface)
            assert len(reason.split()) >= 3, (cap.id, surface, reason)


def test_no_human_decision_is_offered_to_an_agent():
    """The tools an agent drives must not reach a decision. This is the catalogue's statement of
    the same rule the MCP interface tests enforce from the outside."""
    human = {"art14.signal", "art14.awareness", "art14.triage", "art14.filing",
             "change.decide", "change.resolve_decision", "change.waive_reverification",
             "change.resume", "change.assess_advisory", "supplier.trust_override"}
    by_id = {c.id: c for c in cat.CAPABILITIES}
    for cap_id in human:
        assert not by_id[cap_id].mcp, f"{cap_id} must have no MCP tool"
        assert by_id[cap_id].gaps["mcp"][0] == cat.BY_DESIGN, cap_id


def test_the_route_is_free_stateless_and_reports_entitlements(app):
    client = TestClient(app)
    body = client.get("/v1/capabilities")                    # no key
    assert body.status_code == 200
    data = body.json()
    assert data["schema"] == cat.SCHEMA and len(data["capabilities"]) == len(cat.CAPABILITIES)
    verify = next(c for c in data["capabilities"] if c["id"] == "machine.verify")
    assert verify["api"]["gates"]["POST /v1/machine/verify"] == ["machine_verification"]
    free = next(c for c in data["capabilities"] if c["id"] == "machine.check")
    assert free["api"]["gates"]["POST /v1/machine/bundle/check"] == []
    assert client.get("/v1/capabilities").json() == data           # stable, cached
    for surface in ("cli", "api", "mcp"):
        counts = data["counts"][surface]
        assert sum(counts.values()) == len(cat.CAPABILITIES)


def test_the_catalogue_leaks_no_secret_or_server_path(app):
    text = json.dumps(TestClient(app).get("/v1/capabilities").json())
    for needle in ("/home/", "/private/", "op-key-capabilities", "sk_live", "BEGIN PRIVATE"):
        assert needle not in text


def test_the_command_line_check_and_json(tmp_path):
    env = {"ASSURANCE_LEDGER": str(tmp_path / "l.db"), "PATH": "/usr/bin:/bin"}
    check = subprocess.run([sys.executable, "-m", "assurance", "capabilities", "--check"],
                           capture_output=True, text=True, env=env, check=False)
    assert check.returncode == 0 and "matches the code" in check.stdout, check.stdout
    out = subprocess.run([sys.executable, "-m", "assurance", "capabilities", "--json"],
                         capture_output=True, text=True, env=env, check=False)
    assert out.returncode == 0 and json.loads(out.stdout)["schema"] == cat.SCHEMA
    gaps = subprocess.run([sys.executable, "-m", "assurance", "capabilities", "--gaps"],
                          capture_output=True, text=True, env=env, check=False)
    assert gaps.returncode == 0 and "by_design -" in gaps.stdout


def test_the_mcp_tool_for_the_catalogue_wraps_its_route():
    assert cat.discover_mcp()["capabilities"] == "GET /v1/capabilities"
