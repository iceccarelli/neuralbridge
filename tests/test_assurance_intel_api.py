"""The intel read routes: ``GET /v1/intel/*`` and the MCP tools that wrap them.

The store behind them is the operator's shared PUBLIC data, built here from the contract fixtures
in ``tests/fixtures/intel`` (minimized or synthetic; see ``tests/intel_support.py``). Nothing in
this file is live integration: no network is opened and no feed is fetched.

What is pinned: the provenance every answer carries; that an unconfigured or unreadable store is a
503 and never an empty list; that a CVE no source mentions is ``unknown``; that the not-established
notes ship; that hostile ids are refused before the store is touched; that the routes cannot write
(the file's bytes are unchanged); the 401/402 gate; and that an MCP tool returns what the API does.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from pathlib import Path
from typing import Any

import pytest

from assurance import capabilities as cat
from assurance.intel.fetch import ingest_bytes, ingest_file
from assurance.intel.sources import SOURCES
from assurance.intel.store import IntelStore

from . import interfaces_fixtures as fx
from .intel_support import FIXTURES, Clock

live_api = fx.live_api

STORE_ENV = "ASSURANCE_INTEL_STORE"
PROVENANCE = {"seq", "source", "retrieved_at", "sha256", "parser_version"}
CVE_LISTED = "CVE-2021-44228"        # in KEV, EPSS and NVD fixtures
CVE_NVD_ONLY = "CVE-2026-0001"       # NVD and CSAF synthetic fixtures; not in KEV, no EPSS
CVE_NOWHERE = "CVE-1999-0001"        # in no source


def build_store(path: Path, *, sources: tuple[str, ...] = ("kev", "epss", "nvd", "nvd2", "csaf")
                ) -> IntelStore:
    """A store of the fixture files, recorded as a file-fed operator would."""
    store = IntelStore(path)
    clock = Clock()
    files = {"kev": ("cisa_kev", "kev_min.json"), "epss": ("first_epss", "epss_min.json"),
             "nvd": ("nvd_cve_api", "nvd_min.json"), "csaf": ("csaf", "csaf_synthetic.json")}
    for name in sources:
        if name == "nvd2":                      # a second NVD series (a different CVE query)
            ingest_file(store, "nvd_cve_api", FIXTURES / "nvd_synthetic.json",
                        retrieved_at=clock(),
                        url=SOURCES["nvd_cve_api"].url + "?cveId=CVE-2026-0001")
            continue
        source, fixture = files[name]
        ingest_file(store, source, FIXTURES / fixture, retrieved_at=clock())
    return store


@pytest.fixture
def store_path(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "intel.db"
    build_store(path)
    monkeypatch.setenv(STORE_ENV, str(path))
    return path


@pytest.fixture
def cell(live_api):
    _, headers = live_api.account("intel-cell@example.de", tier="cell")
    return live_api, headers


def get(live, headers, path, **params):
    with live.client() as http:
        return http.get(path, headers=headers, params=params or None)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ------------------------------------------------------------------ history
def test_history_lists_every_observation_with_its_provenance(cell, store_path):
    live, headers = cell
    r = get(*cell, "/v1/intel/history")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok" and body["store"]["tenant_evidence"] is False
    assert body["store"]["writes"] is False
    rows = body["observations"]
    assert [o["seq"] for o in rows] == sorted(o["seq"] for o in rows) and len(rows) == 5
    for o in rows:
        assert PROVENANCE <= set(o)
        assert re.fullmatch(r"[0-9a-f]{64}", o["sha256"]) and o["parser_version"]
        assert o["retrieved_at"].endswith("Z")
    assert {o["source"] for o in rows} == {"cisa_kev", "first_epss", "nvd_cve_api", "csaf"}
    assert body["not_established"]


def test_history_filters_by_source_and_pages(cell, store_path):
    kev = get(*cell, "/v1/intel/history", source="kev").json()["observations"]
    assert [o["source"] for o in kev] == ["cisa_kev"]
    assert get(*cell, "/v1/intel/history", source="cisa_kev").json()["observations"] == kev
    first = get(*cell, "/v1/intel/history", limit=2).json()
    assert len(first["observations"]) == 2 and first["has_more"] is True
    second = get(*cell, "/v1/intel/history", limit=2, after_seq=first["next_after_seq"]).json()
    assert second["observations"][0]["seq"] > first["observations"][-1]["seq"]
    last = get(*cell, "/v1/intel/history", after_seq=first["next_after_seq"]).json()
    assert last["has_more"] is False and last["next_after_seq"] is None


@pytest.mark.parametrize("params", [
    {"source": "kev; DROP TABLE observations"}, {"source": "../x"}, {"source": "KEV"},
    {"limit": 0}, {"limit": 10_000}, {"limit": "x"}, {"after_seq": -1}, {"after_seq": "1 OR 1=1"},
])
def test_history_refuses_hostile_parameters_before_any_store_access(live_api, cell, params,
                                                                    monkeypatch):
    monkeypatch.delenv(STORE_ENV, raising=False)          # unconfigured: a 503 if it got that far
    r = get(*cell, "/v1/intel/history", **params)
    assert r.status_code == 422
    if "source" in params:      # our own validation, not a ValueError caught further down
        assert r.json()["detail"]["error"] == "invalid_source"


def test_a_rejected_observation_is_listed_and_says_it_stores_nothing(cell, tmp_path, monkeypatch):
    path = tmp_path / "rej.db"
    store = build_store(path, sources=("kev",))
    ingest_bytes(store, "cisa_kev", b"{not json", url=SOURCES["cisa_kev"].url, locator="t",
                 via="file", http_status=None, retrieved_at=Clock()())
    monkeypatch.setenv(STORE_ENV, str(path))
    rows = get(*cell, "/v1/intel/history").json()["observations"]
    assert [o["disposition"] for o in rows] == ["first", "rejected"]
    assert rows[1]["accepted"] is False and rows[1]["reason"]
    shown = get(*cell, f"/v1/intel/observations/{rows[1]['seq']}").json()
    assert any("Rejected" in n for n in shown["not_established"])


# ------------------------------------------------------------------ one observation
def test_one_observation_carries_provenance_and_the_unsigned_note(cell, store_path):
    r = get(*cell, "/v1/intel/observations/1")
    assert r.status_code == 200, r.text
    body = r.json()
    o = body["observation"]
    assert PROVENANCE <= set(o) and o["seq"] == 1 and o["url"] == SOURCES["cisa_kev"].url
    assert o["sha256"] == IntelStore(store_path).get(1).sha256
    assert any("UNSIGNED" in n for n in body["not_established"])
    assert any("file the operator supplied" in n for n in body["not_established"])


def test_an_unknown_observation_is_404_not_an_empty_answer(cell, store_path):
    r = get(*cell, "/v1/intel/observations/999")
    assert r.status_code == 404 and r.json()["detail"]["error"] == "observation_not_found"


HOSTILE_SEQ = ["0", "-1", "01", "1.5", "1e3", "1%20OR%201=1", "1;--", "１２", "9" * 19, "abc",
               "%2e%2e", "1 ", "+1", "0x10"]


@pytest.mark.parametrize("seq", HOSTILE_SEQ)
def test_hostile_sequences_are_refused_before_any_store_access(live_api, cell, seq, monkeypatch):
    monkeypatch.delenv(STORE_ENV, raising=False)
    r = get(*cell, f"/v1/intel/observations/{seq}")
    # 422 (ours), or the router's own 404 for a value that is not even one path segment
    assert r.status_code in (422, 404), (seq, r.status_code)
    assert r.status_code != 503


# ------------------------------------------------------------------ one CVE
def test_a_cve_in_every_source_is_answered_with_citations(cell, store_path):
    r = get(*cell, f"/v1/intel/cve/{CVE_LISTED}")
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["cve_id"] == CVE_LISTED and b["summary"]["status"] == "recorded"
    assert b["kev"]["status"] == "listed" and PROVENANCE - {"seq", "parser_version"} <= set(
        b["kev"]["citation"] | {"seq": 0, "parser_version": 0})
    assert b["epss"]["status"] == "available" and b["epss"]["score_date"] == "2026-10-31"
    assert 0 < float(b["epss"]["score"]) <= 1 and b["epss"]["citation"]["observation_seq"]
    assert b["nvd"]["status"] == "present" and b["nvd"]["citation"]["sha256"]
    assert b["cvss"], "NVD's metrics are carried as published"
    used = {o["source"]: o for o in b["sources_consulted"]["observations"]}
    assert set(used) == {"cisa_kev", "first_epss", "nvd_cve_api", "csaf"}
    assert all(o["parser_version"] and o["sha256"] and o["seq"] for o in used.values())
    assert b["sources_consulted"]["sources_without_an_accepted_observation"] == []
    assert any("Version ranges are not matched" in n for n in b["not_established"])


def test_not_listed_in_kev_is_not_not_exploited_and_epss_absent_is_unavailable(cell, store_path):
    b = get(*cell, f"/v1/intel/cve/{CVE_NVD_ONLY}").json()
    assert b["kev"]["status"] == "not_listed_in_kev"
    assert "does not establish" in b["kev"]["not_established"]
    assert b["kev"]["not_established"] in b["not_established"]
    assert b["epss"]["status"] == "unavailable" and b["epss"]["score"] is None
    assert "not a score of 0.0" in b["epss"]["note"] and b["epss"]["note"] in b["not_established"]
    assert b["nvd"]["status"] == "present" and b["summary"]["status"] == "recorded"
    assert isinstance(b["conflicts"], list) and b["csaf_advisories"]


def test_a_cve_absent_from_every_source_is_unknown_never_clear(cell, store_path):
    b = get(*cell, f"/v1/intel/cve/{CVE_NOWHERE}").json()
    assert b["summary"]["status"] == "unknown"
    assert b["nvd"]["status"] == "unknown" and b["epss"]["status"] == "unavailable"
    assert b["kev"]["status"] == "not_listed_in_kev" and b["conflicts"] == []
    assert any("unknown, not clear" in n for n in b["not_established"])
    flat = str(b).lower()
    for word in ("'clear'", "'safe'", "not_affected", "'ok_to'"):
        assert word not in flat


def test_kev_is_unchecked_when_no_catalogue_was_ever_recorded(cell, tmp_path, monkeypatch):
    path = tmp_path / "nokev.db"
    build_store(path, sources=("epss", "nvd"))
    monkeypatch.setenv(STORE_ENV, str(path))
    b = get(*cell, f"/v1/intel/cve/{CVE_LISTED}").json()
    assert b["kev"]["status"] == "unchecked"
    assert "cisa_kev" in b["sources_consulted"]["sources_without_an_accepted_observation"]
    assert any("KEV was not checked" in n for n in b["not_established"])
    assert get(*cell, f"/v1/intel/cve/{CVE_NOWHERE}").json()["summary"]["status"] == "unknown"


HOSTILE_CVE = ["cve-2026-0001", "CVE-2026-1", "CVE-26-0001", "CVE-2026-0001%20", "CVE-2026-0001;",
               "CVE-２０２６-0001", "CVE-2026-0001%0a", "CVE-2026-0001'--", "CVE-2026-" + "9" * 20,
               "CVE-2026-0001%2Fx", "..", "x"]


@pytest.mark.parametrize("cve", HOSTILE_CVE)
def test_hostile_cve_ids_are_refused_before_any_store_access(live_api, cell, cve, monkeypatch):
    monkeypatch.delenv(STORE_ENV, raising=False)           # a 503 if it reached the store
    r = get(*cell, f"/v1/intel/cve/{cve}")
    assert r.status_code in (422, 404), (cve, r.status_code)
    if r.status_code == 422:
        assert r.json()["detail"]["error"] == "invalid_cve_id"


# ------------------------------------------------------------------ candidates
def test_candidates_carry_citations_and_what_cannot_be_represented(cell, store_path):
    r = get(*cell, "/v1/intel/candidates")
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["status"] == "ok" and b["candidates"]
    for c in b["candidates"]:
        assert c["trust"] in ("unsigned_inspect_only", "unsigned_public_feed")
        assert PROVENANCE - {"seq", "parser_version"} <= set(
            c["citation"] | {"seq": 0, "parser_version": 0})
        assert c["citation"]["observation_seq"] and c["advisory"]["severity"] == "safety_relevant"
    assert isinstance(b["not_representable"], list) and isinstance(b["conflicts"], list)
    assert {o["source"] for o in b["sources_consulted"]["observations"]} >= {"csaf", "nvd_cve_api"}
    assert any("Version ranges are not matched" in n for n in b["not_established"])


def test_an_empty_store_is_empty_not_clear(cell, tmp_path, monkeypatch):
    path = tmp_path / "empty.db"
    IntelStore(path)
    monkeypatch.setenv(STORE_ENV, str(path))
    h = get(*cell, "/v1/intel/history").json()
    assert h["status"] == "empty" and h["observations"] == [] and "not that nothing" in h["note"]
    c = get(*cell, "/v1/intel/candidates").json()
    assert c["status"] == "empty" and c["candidates"] == []
    assert any("NOT 'no advisory exists'" in n for n in c["not_established"])
    assert sorted(c["sources_consulted"]["sources_without_an_accepted_observation"]) == \
        sorted(SOURCES)
    cve = get(*cell, f"/v1/intel/cve/{CVE_LISTED}").json()
    assert cve["summary"]["status"] == "unknown" and cve["kev"]["status"] == "unchecked"


# ------------------------------------------------------------------ gating
ROUTES = ["/v1/intel/history", "/v1/intel/observations/1", f"/v1/intel/cve/{CVE_LISTED}",
          "/v1/intel/candidates"]


@pytest.mark.parametrize("path", ROUTES)
def test_no_key_is_401_and_an_unentitled_key_is_402(live_api, store_path, path):
    anon = get(live_api, {}, path)
    assert anon.status_code == 401 and anon.headers["www-authenticate"] == "ApiKey"
    for tier in ("free", "register"):
        _, headers = live_api.account(f"intel-{tier}@example.de", tier=tier)
        denied = get(live_api, headers, path)
        assert denied.status_code == 402, (tier, denied.status_code)
        assert denied.json()["detail"]["error"] == "plan_does_not_include_machine_verification"
    _, bad = live_api.account("intel-bad@example.de")
    assert get(live_api, {"X-API-Key": "nb_not-a-real-key"}, path).status_code == 401


def test_entitlement_is_read_on_every_request(live_api, store_path):
    account = live_api.accounts.upsert_account(
        email="intel-flip@example.de", tier="cell", stripe_customer_id="cus_intel_flip")
    headers = {"X-API-Key": live_api.accounts.issue_key(account.id)}
    assert get(live_api, headers, "/v1/intel/history").status_code == 200
    live_api.accounts.set_status(stripe_customer_id="cus_intel_flip", status="cancelled",
                                 tier="free", event_created=5000)
    denied = get(live_api, headers, "/v1/intel/history")
    assert denied.status_code == 402, "a lapsed subscription is read on the very next request"


# ------------------------------------------------------------------ unconfigured / unreadable
@pytest.mark.parametrize("path", ROUTES)
def test_an_unconfigured_store_is_a_503_never_an_empty_list(cell, monkeypatch, path):
    monkeypatch.delenv(STORE_ENV, raising=False)
    r = get(*cell, path)
    assert r.status_code == 503, (path, r.status_code, r.text)
    d = r.json()["detail"]
    assert d["error"] == "no_intel_store_configured" and STORE_ENV in d["remedy"]
    assert "observations" not in r.json() and "candidates" not in r.json()
    assert "not an empty history" in d["not_established"]


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_setting_is_unconfigured(cell, monkeypatch, blank):
    monkeypatch.setenv(STORE_ENV, blank)
    assert get(*cell, "/v1/intel/history").json()["detail"]["error"] == "no_intel_store_configured"


def _garbage(tmp_path: Path) -> Path:
    p = tmp_path / "garbage.db"
    p.write_bytes(b"this is not a sqlite database" * 50)
    return p


def _other_sqlite(tmp_path: Path) -> Path:
    import sqlite3

    p = tmp_path / "other.db"
    with sqlite3.connect(p) as db:
        db.execute("CREATE TABLE t (x)")
    return p


def _wrong_schema(tmp_path: Path) -> Path:
    import sqlite3

    p = tmp_path / "wrong.db"
    with sqlite3.connect(p) as db:
        db.execute("PRAGMA application_id=1230196812")      # claims to be an intel store
        db.execute("CREATE TABLE t (x)")
    return p


@pytest.mark.parametrize("make", [lambda t: t / "does-not-exist.db", lambda t: t,
                                  _garbage, _other_sqlite, _wrong_schema],
                         ids=["missing", "directory", "garbage", "foreign-sqlite", "wrong-schema"])
@pytest.mark.parametrize("path", ROUTES)
def test_an_unreadable_store_is_a_503_and_nothing_is_created(cell, tmp_path, monkeypatch, make,
                                                              path):
    target = make(tmp_path)
    before = sorted(p.name for p in tmp_path.iterdir())
    monkeypatch.setenv(STORE_ENV, str(target))
    r = get(*cell, path)
    assert r.status_code == 503, (path, r.status_code, r.text)
    d = r.json()["detail"]
    assert d["error"] == "intel_store_unreadable" and "observations" not in r.json()
    assert str(tmp_path) not in r.text, "the server's path is not the caller's business"
    assert sorted(p.name for p in tmp_path.iterdir()) == before


def test_a_store_damaged_after_the_open_check_is_still_a_503(cell, store_path):
    import sqlite3

    with sqlite3.connect(store_path) as db:
        db.execute("PRAGMA journal_mode=DELETE")
    data = bytearray(store_path.read_bytes())
    for i in range(4096 * 3, len(data), 97):         # corrupt data pages, keep the header
        data[i] ^= 0xFF
    store_path.write_bytes(bytes(data))
    for path in ("/v1/intel/candidates", f"/v1/intel/cve/{CVE_LISTED}"):
        r = get(*cell, path)
        assert r.status_code == 503, (path, r.status_code, r.text)
        assert r.json()["detail"]["error"] == "intel_store_unreadable"


# ------------------------------------------------------------------ read-only
def test_the_routes_cannot_write_the_store(cell, store_path):
    before = sha(store_path)
    for path in [*ROUTES, "/v1/intel/history?source=nvd", "/v1/intel/observations/999",
                 f"/v1/intel/cve/{CVE_NOWHERE}", "/v1/intel/cve/bad"]:
        get(*cell, path)
    assert sha(store_path) == before
    assert IntelStore(store_path).observations()[-1].seq == 5     # nothing was appended


def test_there_is_no_ingest_or_refresh_route_and_no_write_method(live_api):
    from assurance.api.service import create_app

    intel = [r for r in _api_routes(create_app()) if r.path.startswith("/v1/intel")]
    assert len(intel) == 4
    for route in intel:
        assert route.methods <= {"GET", "HEAD"}, (route.path, route.methods)
    with live_api.client() as http:
        _, headers = live_api.account("intel-write@example.de")
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            for path in ("/v1/intel/history", "/v1/intel/ingest", "/v1/intel/refresh"):
                assert http.request(method, path, headers=headers, json={}).status_code in (
                    404, 405)


def test_the_read_only_store_refuses_to_write_even_if_asked(store_path):
    from assurance.api.intel_routes import _ReadOnlyIntelStore
    from assurance.intel.store import IntelStoreError

    ro = _ReadOnlyIntelStore(store_path)
    with pytest.raises(IntelStoreError):
        ro.append(source="cisa_kev", url="u", locator="l", via="file",
                  retrieved_at=Clock()(), http_status=None, byte_length=0, sha256="0" * 64,
                  parser_version="x", parse_result="malformed", reason="r")
    with pytest.raises(Exception):  # noqa: B017,PT011 - sqlite3 refuses a write on a ro handle
        with ro._read() as db:
            db.execute("DELETE FROM blobs")


# ------------------------------------------------------------------ MCP == API
def mcp_call(live, headers, tool: str, **args: Any) -> dict[str, Any]:
    import os

    from assurance.mcp import server

    os.environ["ASSURANCE_API_URL"] = live.url
    os.environ["ASSURANCE_API_KEY"] = headers["X-API-Key"]
    try:
        return asyncio.run(getattr(server, tool)(**args))
    finally:
        os.environ.pop("ASSURANCE_API_URL")
        os.environ.pop("ASSURANCE_API_KEY")


def test_each_mcp_tool_returns_what_the_api_returns(cell, store_path):
    live, headers = cell
    pairs = [
        ("intel_history", {}, "/v1/intel/history", None),
        ("intel_history", {"source": "kev", "limit": 5}, "/v1/intel/history",
         {"source": "kev", "limit": 5, "after_seq": 0}),
        ("intel_observation", {"seq": 2}, "/v1/intel/observations/2", None),
        ("intel_observation", {"seq": 999}, "/v1/intel/observations/999", None),
        ("intel_cve", {"cve_id": CVE_LISTED}, f"/v1/intel/cve/{CVE_LISTED}", None),
        ("intel_cve", {"cve_id": CVE_NOWHERE}, f"/v1/intel/cve/{CVE_NOWHERE}", None),
        ("intel_candidates", {}, "/v1/intel/candidates", None),
    ]
    for tool, args, path, params in pairs:
        via_mcp = mcp_call(live, headers, tool, **args)
        direct = get(live, headers, path, **(params or {}))
        assert via_mcp["status"] == direct.status_code, (tool, via_mcp)
        assert via_mcp["body"] == direct.json(), tool


def test_mcp_relays_the_503_and_the_401_402_unchanged(live_api, cell, monkeypatch, tmp_path):
    _, headers = cell
    monkeypatch.delenv(STORE_ENV, raising=False)
    out = mcp_call(live_api, headers, "intel_candidates")
    assert out["status"] == 503 and out["body"]["detail"]["error"] == "no_intel_store_configured"
    _, free = live_api.account("intel-mcp-free@example.de", tier="free")
    assert mcp_call(live_api, free, "intel_history")["status"] == 402
    assert mcp_call(live_api, {"X-API-Key": "nb_nope"}, "intel_history")["status"] == 401


def test_mcp_refuses_hostile_arguments_without_sending_anything(monkeypatch):
    from assurance.mcp import server

    sent: list[Any] = []

    async def record(*args: Any, **kwargs: Any) -> dict[str, Any]:
        sent.append((args, kwargs))
        return {"status": 200, "body": {}}

    monkeypatch.setattr(server, "_call", record)

    async def run() -> list[dict[str, Any]]:
        out = []
        for cve in [*HOSTILE_CVE, "", "CVE-2026-0001/../x", None, 5]:
            out.append(await server.intel_cve(cve))             # type: ignore[arg-type]
        for seq in [0, -1, 10**19, True, "1", "1/../x", None, 1.5]:
            out.append(await server.intel_observation(seq))     # type: ignore[arg-type]
        out.append(await server.intel_history(source="kev;x"))
        out.append(await server.intel_history(limit="9"))       # type: ignore[arg-type]
        out.append(await server.intel_history(after_seq=True))
        return out

    results = asyncio.run(run())
    assert not sent, "a hostile argument reached the network layer"
    assert all(r["error"].startswith("invalid_") and "status" not in r for r in results)


def test_mcp_tools_are_read_only_and_there_is_no_ingest_or_refresh_tool():
    from assurance.mcp import server

    names = {t.name for t in asyncio.run(server.mcp.list_tools())}
    assert {n for n in names if n.startswith("intel")} == {
        "intel_history", "intel_observation", "intel_cve", "intel_candidates"}
    for tool in asyncio.run(server.mcp.list_tools()):
        if tool.name.startswith("intel"):
            assert (tool.description or "").startswith("GET /v1/intel/")


# ------------------------------------------------------------------ surface parity
def test_the_capability_catalogue_declares_the_real_surfaces():
    from assurance.api.service import create_app

    by_id = {c.id: c for c in cat.CAPABILITIES}
    assert by_id["intel.history"].api == ("GET /v1/intel/history",)
    assert by_id["intel.history"].mcp == ("intel_history",)
    assert by_id["intel.candidates"].api == ("GET /v1/intel/candidates",)
    assert by_id["intel.candidates"].mcp == ("intel_candidates",)
    assert set(by_id["intel.show"].api) == {"GET /v1/intel/observations/{seq}",
                                            "GET /v1/intel/cve/{cve_id}"}
    assert set(by_id["intel.show"].mcp) == {"intel_observation", "intel_cve"}
    for cap_id in ("intel.ingest", "intel.refresh"):
        c = by_id[cap_id]
        assert c.api == () and c.mcp == () and c.cli
        for surface in ("api", "mcp"):
            kind, why = c.gaps[surface]
            assert kind == cat.BY_DESIGN and "operator" in why, (cap_id, surface)
    assert cat.problems(create_app()) == []


def test_the_intel_routes_are_gated_by_the_machine_entitlement():
    from assurance.api import deps
    from assurance.api.service import create_app

    seen = 0
    for route in _api_routes(create_app()):
        if route.path.startswith("/v1/intel"):
            assert deps.require_machine in _calls(route.dependant), route.path
            seen += 1
    assert seen == 4


def _calls(dependant) -> set:
    found = set()
    for sub in dependant.dependencies:
        found.add(sub.call)
        found |= _calls(sub)
    return found


def _api_routes(app):
    from fastapi.routing import APIRoute

    def walk(routes):
        for route in routes:
            if isinstance(route, APIRoute):
                yield route
            elif hasattr(route, "original_router"):
                yield from walk(route.original_router.routes)
            elif hasattr(route, "routes"):
                yield from walk(route.routes)

    yield from walk(app.routes)
