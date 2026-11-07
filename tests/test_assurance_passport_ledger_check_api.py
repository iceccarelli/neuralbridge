"""A hosted account can check a passport against ITS OWN ledger, over HTTP and MCP.

``POST /v1/machinery/passport/check`` has no ledger and says so (``against_ledger: false``), so
over HTTP a passport that the ledger has since overtaken read as fine: ``superseded`` detection
existed only in ``assurance machinery check --ledger``. ``POST /v1/machinery/passport/check-ledger``
is the authenticated twin (Cell, not metered, read-only) and the MCP tool
``machinery_passport_check_ledger`` wraps it.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from . import interfaces_fixtures as fx  # noqa: E402
from .test_assurance_passport_check import manifest  # noqa: E402

live_api = fx.live_api


def _moved(m):
    items = tuple(replace(i, content_hash="c" * 64, version="3.9.0") for i in m.items)
    return replace(m, manifest_id="M-2", items=items, taken_at=m.taken_at + timedelta(days=30))


@pytest.fixture
def sealed(live_api):
    acct, headers = live_api.account("passport-ledger@example.de")
    m = manifest()
    with live_api.client() as http:
        r = http.post("/v1/machinery/manifest", headers=headers,
                      json={"manifest": m.to_dict(), "actor": "V. Grimaldi"})
        assert r.status_code == 200, r.text
        r = http.post("/v1/machinery/passport", headers=headers,
                      json={"manifest": m.to_dict(), "actor": "V. Grimaldi"})
        assert r.status_code == 200, r.text
        passport = r.json()
    return live_api, headers, m, passport


def _free(http, passport):
    return http.post("/v1/machinery/passport/check", json={"passport": passport})


def _ledger(http, headers, passport):
    return http.post("/v1/machinery/passport/check-ledger", headers=headers,
                     json={"passport": passport})


def test_control_a_passport_nothing_has_overtaken_is_ok_against_the_ledger(sealed):
    api, headers, _, passport = sealed
    with api.client() as http:
        r = _ledger(http, headers, passport)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["ok"] is True and body["problems"] == []
    assert body["checked"]["against_ledger"] is True


def test_a_passport_the_ledger_has_overtaken_is_not_ok_over_http(sealed):
    api, headers, m, passport = sealed
    with api.client() as http:
        moved = http.post("/v1/machinery/manifest", headers=headers,
                          json={"manifest": _moved(m).to_dict(), "actor": "V. Grimaldi"})
        assert moved.status_code == 200, moved.text
        free = _free(http, passport).json()
        mine = _ledger(http, headers, passport).json()
    # the free check has no ledger and says so: it cannot see the overtaking
    assert free["ok"] is True and free["checked"]["against_ledger"] is False
    # the account's own ledger can
    assert mine["ok"] is False and mine["checked"]["against_ledger"] is True
    assert any("superseded" in p and "configuration" in p for p in mine["problems"])


def test_it_reads_only_the_callers_own_ledger(sealed):
    api, _, m, passport = sealed
    _, other = api.account("someone-else@example.de")
    with api.client() as http:
        r = _ledger(http, other, passport)
    body = r.json()
    # another account's ledger holds none of the records the passport names
    assert r.status_code == 200 and body["ok"] is False and body["problems"]


@pytest.mark.parametrize("who, status", [("none", 401), ("lapsed", 402)])
def test_it_is_gated_like_the_other_machine_routes(sealed, who, status):
    api, headers, _, passport = sealed
    if who == "lapsed":
        acct, lapsed = api.account("passport-lapsed@example.de")
        api.accounts.upsert_account(email="passport-lapsed@example.de", tier="free",
                                    status="cancelled", account_id=acct, event_created=9_000_000)
        headers = lapsed
    else:
        headers = {}
    with api.client() as http:
        assert _ledger(http, headers, passport).status_code == status


@pytest.mark.asyncio
async def test_the_mcp_tool_gives_the_same_answer(sealed, monkeypatch) -> None:
    from assurance.mcp import server

    api, headers, m, passport = sealed
    monkeypatch.setenv("ASSURANCE_API_URL", api.url)
    monkeypatch.setenv("ASSURANCE_API_KEY", headers["X-API-Key"])
    ok = await server.machinery_passport_check_ledger(passport)
    assert ok["status"] == 200 and ok["body"]["ok"] is True
    with api.client() as http:
        http.post("/v1/machinery/manifest", headers=headers,
                  json={"manifest": _moved(m).to_dict(), "actor": "V. Grimaldi"})
    overtaken = await server.machinery_passport_check_ledger(passport)
    assert overtaken["body"]["ok"] is False
    assert any("superseded" in p for p in overtaken["body"]["problems"])
