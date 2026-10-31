"""The read-only MCP tools, against a real API on a real socket.

Eighteen tools were added for capabilities that had an API route and a CLI verb and no MCP tool.
Each one wraps a GET, or a POST that answers a question and records nothing. For each this file
proves, from the outside: it returns what the route returns; no key is a 401 and a plan below
the route's is a 402 (the tool relays the API's real answer, it adds no check of its own); one
account's tool cannot read another's data; and it is on the read-only allow-list and cannot be
steered to a route that writes (the allow-list half is in ``test_interfaces_mcp.py``).

The data is the plant ``test_surface_parity`` builds: two enrolled machines, one drifted, a case
open, a real validated verification, and (added here) one Article 14 case.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest

pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")

from . import interfaces_fixtures as fx  # noqa: E402
from .test_interfaces_mcp import READ_ONLY_TOOLS  # noqa: E402
from .test_surface_parity import World, _host, plant_world  # noqa: E402, F401

live_api = fx.live_api

ART14_CASE = "case-art14-reads"
ACTOR = {"identifier": "m.braun", "role": "Entwicklungsleitung"}

#: tool -> the plan its route needs. Everything else here is free (no key needed).
REGISTER = ("art14_case", "art14_register", "art14_breaches", "art14_export", "ledger_verify")
CELL = ("attest_log", "fleet_machines", "fleet_observations", "value_position", "change_replay",
        "supplier_trust_list", "supplier_trust_check")
FREE = tuple(sorted(set(READ_ONLY_TOOLS) - set(REGISTER) - set(CELL)))


async def call(monkeypatch: pytest.MonkeyPatch, url: str, key: str | None, tool: str,
               **kwargs: Any) -> dict[str, Any]:
    from assurance.mcp import server

    monkeypatch.setenv("ASSURANCE_API_URL", url)
    if key is None:
        monkeypatch.delenv("ASSURANCE_API_KEY", raising=False)
    else:
        monkeypatch.setenv("ASSURANCE_API_KEY", key)
    return await getattr(server, tool)(**kwargs)


def args_for(tool: str, w: World) -> dict[str, Any]:
    """Arguments that make each tool's route a real success against ``w``'s data."""
    return {
        "spec_fields": {"track": "actively_exploited_vulnerability", "stage": "early_warning"},
        "art14_case": {"case_id": ART14_CASE},
        "art14_export": {"case_id": ART14_CASE},
        "change_replay": {"case_id": w.case_id},
        "attest_verify": {"attestations": [{}]},          # an unreadable log: a 422 is the answer
        "machine_separation": {
            "robot_speed_mm_s": 500.0, "reaction_time_s": 0.1, "stop_time_s": 0.3,
            "stop_distance_mm": 80.0, "measured_at_speed_mm_s": 500.0,
            "intrusion_distance_mm": 120.0},
        "machinery_diff": {"baseline": w.manifest, "observed": w.manifest},
        "fleet_declaration_check": {"declaration": {}, "manifest": w.manifest},
        "supplier_trust_check": {"feed": ""},
    }.get(tool, {})


@pytest.fixture
def world(plant_world: World, tmp_path, monkeypatch) -> World:  # noqa: F811
    """The plant, an Article 14 case, a service attestation key (generated here, test-only) and
    an operator key, so 'no key' is the 401 a deployment answers and not the open-mode 503."""
    from assurance.api import deps
    from assurance.attest.keys import SigningKey

    key_path = tmp_path / "secrets" / "service.pem"
    SigningKey.generate().save(key_path)
    monkeypatch.setenv("ASSURANCE_ATTEST_KEY", str(key_path))
    monkeypatch.setenv("ASSURANCE_ATTEST_LOGS", str(tmp_path / "attestations"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", "operator-key-for-this-test-only")
    deps._register_for.cache_clear()
    r =plant_world.client.post(f"/v1/cases/{ART14_CASE}/signal", json={
        "received_at": "2026-09-18T21:40:00Z", "channel": "customer_or_integrator",
        "description": "Integrator observed exploitation on a live line",
        "reference": "TICKET-8812", "actor": ACTOR})
    assert r.status_code in (200, 201), r.text
    return plant_world


def test_the_tier_tables_here_cover_every_read_only_tool() -> None:
    assert set(REGISTER) | set(CELL) | set(FREE) == set(READ_ONLY_TOOLS)
    assert not set(REGISTER) & set(CELL)


# ------------------------------------------------------------------ success, live
@pytest.mark.asyncio
@pytest.mark.parametrize("tool", sorted(READ_ONLY_TOOLS))
async def test_a_tool_returns_what_its_route_returns(world, monkeypatch, tool) -> None:
    method, path = READ_ONLY_TOOLS[tool]
    path = path.replace("case-0123456789abcdef", ART14_CASE if tool.startswith("art14") else
                        world.case_id)
    args = args_for(tool, world)
    reply = await call(monkeypatch, world.api_url, world.api_key, tool, **args)
    if method == "GET":
        direct = world.client.get(path, params={k: v for k, v in args.items()
                                                if tool == "spec_fields"})
    else:
        direct = world.client.post(path, json=args)
    assert reply["status"] == direct.status_code, (tool, reply, direct.text)
    assert reply["status"] < 500
    if direct.headers.get("content-type", "").startswith("application/json"):
        if tool not in ("ledger_verify", "value_position", "fleet_observations", "art14_register"):
            # (those carry a clock reading that can differ between two calls)
            assert reply["body"] == direct.json(), tool
    if tool in ("attest_verify", "fleet_declaration_check"):
        assert reply["status"] == 422          # nothing was verified and the tool says so
    else:
        assert reply["status"] == 200, (tool, reply)


@pytest.mark.asyncio
async def test_the_data_tools_return_real_data_not_an_empty_success(world, monkeypatch) -> None:
    async def body(tool: str, **kw: Any) -> Any:
        r = await call(monkeypatch, world.api_url, world.api_key, tool, **kw)
        assert r["status"] == 200, (tool, r)
        return r["body"]

    assert {m["machine"] for m in (await body("fleet_machines"))["machines"]}
    assert (await body("change_replay", case_id=world.case_id))["ok"] is True
    assert (await body("ledger_verify"))["verified"] is True
    assert (await body("art14_case", case_id=ART14_CASE))["signal"]
    assert ART14_CASE in str(await body("art14_register"))
    assert (await body("art14_export", case_id=ART14_CASE))["entries"]
    assert isinstance(await body("art14_breaches"), list)
    assert (await body("machinery_diff", baseline=world.manifest,
                       observed=world.manifest))["verdict"]
    assert (await body("machine_separation", **args_for("machine_separation", world))
            )["required_separation_mm"] > 0
    assert (await body("spec_fields", **args_for("spec_fields", world)))
    assert (await body("value_position"))
    assert "pins" in await body("supplier_trust_list")


# ------------------------------------------------------------------ 401 and 402
@pytest.mark.asyncio
@pytest.mark.parametrize("tool", REGISTER + CELL)
async def test_a_gated_tool_without_a_key_is_the_apis_401(world, monkeypatch, tool) -> None:
    reply = await call(monkeypatch, world.api_url, None, tool, **args_for(tool, world))
    assert reply["status"] == 401, (tool, reply)
    wrong = await call(monkeypatch, world.api_url, "not-a-key", tool, **args_for(tool, world))
    assert wrong["status"] == 401, (tool, wrong)


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", REGISTER)
async def test_a_register_tool_on_the_free_plan_is_the_apis_402(
        live_api, monkeypatch, tool) -> None:
    _, headers = live_api.account("reads-free@example.de", tier="free")
    reply = await call(monkeypatch, live_api.url, headers["X-API-Key"], tool,
                       **{k: "case-x" for k in inspect.signature(
                           getattr(__import__("assurance.mcp.server", fromlist=["x"]), tool)
                       ).parameters if k == "case_id"})
    assert reply["status"] == 402, (tool, reply)
    assert reply["body"]["detail"]["error"] if isinstance(reply["body"].get("detail"), dict) else True


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", CELL)
async def test_a_cell_tool_on_the_register_plan_is_the_apis_402(
        live_api, monkeypatch, tool) -> None:
    _, headers = live_api.account("reads-register@example.de", tier="register")
    kwargs = {"case_id": "case-x"} if tool == "change_replay" else (
        {"feed": ""} if tool == "supplier_trust_check" else {})
    reply = await call(monkeypatch, live_api.url, headers["X-API-Key"], tool, **kwargs)
    assert reply["status"] == 402, (tool, reply)


@pytest.mark.asyncio
async def test_the_402_is_the_apis_own_structured_answer_not_one_the_tool_made(
        live_api, monkeypatch) -> None:
    _, headers = live_api.account("reads-shape@example.de", tier="register")
    reply = await call(monkeypatch, live_api.url, headers["X-API-Key"], "fleet_machines")
    with live_api.client() as http:
        direct = http.get("/v1/fleet/machines", headers=headers)
    assert (reply["status"], reply["body"]) == (402, direct.json())


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ["spec_fields", "attest_verify", "machine_separation",
                                  "machinery_diff", "fleet_declaration_check"])
async def test_a_free_tool_needs_no_key(world, monkeypatch, tool) -> None:
    reply = await call(monkeypatch, world.api_url, None, tool, **args_for(tool, world))
    assert reply["status"] not in (401, 402), (tool, reply)


# ------------------------------------------------------------------ tenant isolation
@pytest.mark.asyncio
async def test_a_second_account_cannot_read_the_firsts_data_through_any_tool(
        world, live_api, monkeypatch) -> None:
    _, other = live_api.account("reads-second@example.de", tier="cell")
    key = other["X-API-Key"]

    async def second(tool: str, **kw: Any) -> dict[str, Any]:
        return await call(monkeypatch, world.api_url, key, tool, **kw)

    # a case that exists only in the first account's ledger is not found, never an empty success
    for tool, kw in (("art14_case", {"case_id": ART14_CASE}),
                     ("art14_export", {"case_id": ART14_CASE}),
                     ("change_replay", {"case_id": world.case_id})):
        reply = await second(tool, **kw)
        assert reply["status"] == 404, (tool, reply)
    mine = await call(monkeypatch, world.api_url, world.api_key, "change_replay",
                      case_id=world.case_id)
    assert mine["status"] == 200

    # a list is the second account's own, which is empty
    assert (await second("fleet_machines"))["body"]["machines"] == []
    assert (await second("art14_register"))["body"] is not None
    assert ART14_CASE not in str((await second("art14_register"))["body"])
    assert (await second("art14_breaches"))["body"] == []
    assert world.case_id not in str((await second("fleet_observations"))["body"])
    assert (await second("supplier_trust_list"))["body"]["pins"] == []

    # a different ledger: its verification names a different one
    theirs = (await second("ledger_verify"))["body"]
    ours = (await call(monkeypatch, world.api_url, world.api_key, "ledger_verify"))["body"]
    assert theirs["ledger_id"] != ours["ledger_id"]
    assert theirs["attestation"]["length"] != ours["attestation"]["length"]
    # and the fleet they see is not ours
    ours_fleet = (await call(monkeypatch, world.api_url, world.api_key, "fleet_machines"))["body"]
    assert ours_fleet["machines"]


@pytest.mark.asyncio
async def test_a_tool_cannot_be_steered_to_another_accounts_route(world, monkeypatch) -> None:
    """The id is checked in the tool, so an id cannot add a path segment, a query or a
    traversal; nothing is sent."""
    for tool in ("art14_case", "art14_export", "change_replay"):
        for hostile in ("../x", "x/../../v1/ledger/verify", "case-x/export", "a?b=c", "a b", ""):
            reply = await call(monkeypatch, world.api_url, world.api_key, tool, case_id=hostile)
            assert reply["error"] == "invalid_case_id" and "status" not in reply, (tool, hostile)
    reply = await call(monkeypatch, world.api_url, world.api_key, "supplier_trust_check",
                       hosted_feed_id="../operator")
    assert reply["error"] == "invalid_feed_id" and "status" not in reply


# ------------------------------------------------------------------ the verifier tools
@pytest.mark.asyncio
async def test_attest_verify_offers_no_way_to_name_the_key(world, monkeypatch) -> None:
    """The route takes ``public_key_pem``; the tool does not, so a log is judged under the
    service's own key only. Passing it anyway is a TypeError, not a quiet pass-through."""
    from assurance.mcp import server

    assert "public_key_pem" not in inspect.signature(server.attest_verify).parameters
    with pytest.raises(TypeError):
        await server.attest_verify(attestations=[{}], public_key_pem="x")   # type: ignore[call-arg]
    with pytest.raises(TypeError):
        await server.supplier_trust_check(feed="", candidate_public_key_pem="x")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_the_attestation_tools_read_and_check_a_real_signed_head(world, monkeypatch) -> None:
    """The setup signs through the API (a person's act, done here by the test, never by a
    tool); the tools then read the log and check it under the service's own key."""
    ours = (await call(monkeypatch, world.api_url, world.api_key, "ledger_verify"))["body"]
    head = ours["attestation"]
    signed = world.client.post("/v1/ledger/attest", json={
        "ledger_length": head["length"], "head_seq": head["head_seq"],
        "head_link_hash": head["head_link_hash"], "note": "test"})
    assert signed.status_code in (200, 201), signed.text
    log = await call(monkeypatch, world.api_url, world.api_key, "attest_log")
    assert log["status"] == 200 and log["body"]["count"] == 1
    checked = await call(monkeypatch, world.api_url, None, "attest_verify",
                         attestations=log["body"]["attestations"])
    assert checked["status"] == 200 and checked["body"]["ok"] is True
    # the key the tool checked under is the service's, and the tool can show it
    key = await call(monkeypatch, world.api_url, None, "attest_service_key")
    assert key["status"] == 200 and key["body"]["fingerprint"] == checked["body"]["key_fingerprint"]
    # a tampered record is not ok
    bad = [dict(log["body"]["attestations"][0], head_link_hash="0" * 64)]
    tampered = await call(monkeypatch, world.api_url, None, "attest_verify", attestations=bad)
    assert tampered["status"] == 200 and tampered["body"]["ok"] is False


@pytest.mark.asyncio
async def test_an_unreadable_attestation_log_is_not_reported_as_verified(
        world, monkeypatch) -> None:
    reply = await call(monkeypatch, world.api_url, None, "attest_verify", attestations=[{}])
    assert reply["status"] == 422 and reply["body"].get("ok") is not True
