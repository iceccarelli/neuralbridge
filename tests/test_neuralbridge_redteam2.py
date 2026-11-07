"""Red-team 2 regressions for the raw adapters route, the audit trail and the log export.

M2  POST /adapters/{type}/validate is gated, rate limited and audited like execute.
M3  an unknown adapter type never answers with another tenant's connection key.
M4  audit fields are bounded; unauthenticated refusals cannot grow the trail without limit.
L1  CSV export neutralises spreadsheet formulas.

No PostgreSQL needed: tenant connections are stood in for by registry entries.
"""

from __future__ import annotations

import csv
import io
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from neuralbridge.adapters.apis.rest import RestApiAdapter

OPERATOR = "nb-rt2-operator-key-0123456789abcdef0123456789"
BEARER = "rt2-operator-bearer-token-do-not-leak"
API = "/api/v1"


class _Recorder(BaseHTTPRequestHandler):
    seen: list[dict] = []

    def _any(self) -> None:
        type(self).seen.append({"method": self.command, "auth": self.headers.get("Authorization")})
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._any()

    def do_GET(self) -> None:  # noqa: N802
        self._any()

    def log_message(self, *args) -> None:  # silence
        pass


class LazyRest(RestApiAdapter):
    """The real REST adapter, connecting on first use inside the app's own event loop."""

    async def _do_validate_credentials(self):
        if not self._client:
            await self._do_connect()
        return await super()._do_validate_credentials()


class Probe:
    def __init__(self, adapter_type: str) -> None:
        self.adapter_type = adapter_type
        self.calls = 0
        self.status = type("S", (), {"value": "connected"})()
        self.category, self.description, self.supported_operations = "x", "x", ["send_message"]

    async def execute(self, operation, params):
        self.calls += 1
        return {"ok": True}

    async def validate_credentials(self):
        self.calls += 1
        from neuralbridge.adapters.base import AdapterResponse

        return AdapterResponse(success=True, data={"status": "ok"})

    def get_stats(self):
        return {}


@pytest.fixture
def recorder():
    handler = type("H", (_Recorder,), {"seen": []})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield {"url": f"http://127.0.0.1:{srv.server_address[1]}", "seen": handler.seen}
    srv.shutdown()
    srv.server_close()


class Env:
    def __init__(self, client, a, b, free, owners, rest_seen, registry) -> None:
        self.client, self.a, self.b, self.free, self.owners, self.rest_seen, self.registry = (
            client, a, b, free, owners, rest_seen, registry)

    def h(self, key=None, actor="rt2"):
        headers = {"X-NB-Actor": actor}
        if key:
            headers["X-API-Key"] = key
        return headers


@pytest.fixture
def env(monkeypatch, tmp_path, recorder):
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR)
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "ai.db"))
    monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "0")
    for k in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "NEURALBRIDGE_AI_PG_HOST", "NEURALBRIDGE_AI_PG_DATABASE",
              "NEURALBRIDGE_AI_PG_USER"):
        monkeypatch.delenv(k, raising=False)
    from assurance.api import deps as adeps
    from assurance.billing.accounts import AccountStore

    adeps._register_for.cache_clear()
    adeps._accounts_for.cache_clear()
    store = AccountStore(str(tmp_path / "accounts.db"))
    a = store.upsert_account(email="a@example.com", tier="register", company="A")
    b = store.upsert_account(email="b@example.com", tier="register", company="B")
    f = store.upsert_account(email="f@example.com", tier="free", company="F")
    keys = [store.issue_key(x.id, label="rt2") for x in (a, b, f)]

    import neuralbridge.api.dependencies as deps
    from neuralbridge.ai.audit_events import reset_refusal_limiter
    from neuralbridge.core.router import RequestRouter
    from neuralbridge.main import create_app

    deps._adapter_registry = deps._request_router = deps._audit_logger = deps._ai_store = None
    reset_refusal_limiter()
    with TestClient(create_app()) as client:
        reg = deps.get_adapter_registry()
        deps._request_router = RequestRouter(reg, deps.get_audit_logger())
        reg.register(LazyRest({"base_url": recorder["url"], "allow_private_network": True, "timeout": 5,
                               "auth_type": "bearer", "credentials": {"token": BEARER}}), key="rest")
        yield Env(client, keys[0], keys[1], keys[2], {"a": a.id, "b": b.id}, recorder["seen"], reg)
    reset_refusal_limiter()


def audit_rows(env: Env, **filters) -> list[dict]:
    r = env.client.get(f"{API}/logs", headers=env.h(OPERATOR), params={"limit": 1000, **filters})
    assert r.status_code == 200, r.text
    return r.json()["events"]


# ───────────────────────────── M2: /validate ─────────────────────────────


class TestValidateIsGated:
    def test_anonymous_and_free_cannot_make_the_server_use_its_bearer_token(self, env: Env) -> None:
        for key in (None, env.free):
            r = env.client.post(f"{API}/adapters/rest/validate", headers=env.h(key))
            assert r.status_code == 402, r.text
        assert env.rest_seen == []  # nothing was sent to the configured base_url
        denied = [e for e in audit_rows(env, event_type="entitlement_denied") if e["action"] == "validate"]
        assert denied and denied[0]["resource"] == "rest"

    def test_invalid_key_is_401(self, env: Env) -> None:
        r = env.client.post(f"{API}/adapters/rest/validate", headers=env.h("nb-not-a-real-key"))
        assert r.status_code == 401
        assert env.rest_seen == []

    def test_paid_and_operator_validate_and_it_is_audited_with_actor_and_tenant(self, env: Env) -> None:
        for key in (env.a, OPERATOR):
            r = env.client.post(f"{API}/adapters/rest/validate", headers=env.h(key, actor="validator-1"))
            assert r.status_code == 200, r.text
        assert [(s["method"], s["auth"]) for s in env.rest_seen] == [("HEAD", f"Bearer {BEARER}")] * 2
        rows = list(audit_rows(env, event_type="adapter_validate"))
        assert len(rows) == 2
        assert {e["details"]["owner"] for e in rows} == {env.owners["a"], "operator"}
        assert all(e["actor"] == "human_session:validator-1" and e["result"] == "success" for e in rows)
        assert BEARER not in str(rows)

    def test_postgres_is_gated_too(self, env: Env) -> None:
        env.registry.register(Probe("postgres"), key="postgres")
        assert env.client.post(f"{API}/adapters/postgres/validate", headers=env.h()).status_code == 402
        assert env.client.post(f"{API}/adapters/postgres/validate", headers=env.h(env.a)).status_code == 200

    def test_a_tenant_cannot_validate_another_tenants_connection_and_unknown_is_not_an_oracle(self, env: Env) -> None:
        probe = Probe("postgres")
        env.registry.register(probe, key=f"postgres:{uuid.uuid4()}")
        key = next(k for k in env.registry.list_all() if k.startswith("postgres:"))
        assert env.client.post(f"{API}/adapters/{key}/validate", headers=env.h(env.b)).status_code == 404
        assert env.client.post(f"{API}/adapters/{key}/validate", headers=env.h(env.free)).status_code == 404
        assert probe.calls == 0
        assert env.client.post(f"{API}/adapters/{key}/validate", headers=env.h(OPERATOR)).status_code == 200
        assert env.client.post(f"{API}/adapters/nothing/validate", headers=env.h()).status_code == 402
        assert env.client.post(f"{API}/adapters/nothing/validate", headers=env.h(env.a)).status_code == 404

    def test_validate_takes_the_owners_rate_limit_slot(self, env: Env, monkeypatch) -> None:
        import neuralbridge.api.dependencies as deps
        from neuralbridge.security.limits import SlidingWindowLimiter

        router = deps._request_router
        monkeypatch.setattr(router, "_rate", SlidingWindowLimiter(2, 60.0))
        codes = [env.client.post(f"{API}/adapters/rest/validate", headers=env.h(env.a)).status_code for _ in range(4)]
        assert codes == [200, 200, 429, 429]
        assert len(env.rest_seen) == 2


def test_the_gateway_and_raw_route_both_treat_rest_as_not_free() -> None:
    """The parity test only compares the two doors; pin the rule itself."""
    import asyncio

    from fastapi import HTTPException

    from neuralbridge.ai.entitlements import Principal
    from neuralbridge.ai.guard import _SAFE_DISCOVERY_OPS, enforce_write_gate

    assert "rest" not in _SAFE_DISCOVERY_OPS
    anonymous = Principal(account=None, key_prefix="", anonymous_subject="203.0.113.9")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(enforce_write_gate("rest", "get", {}, anonymous))
    assert exc.value.status_code == 402


# ───────────────────────────── M3: no registry echo ─────────────────────────────


class TestUnknownAdapterNeverEchoesTheRegistry:
    def test_tenant_a_sees_no_other_tenants_connection_key(self, env: Env) -> None:
        tenant_b_key = f"postgres:{uuid.uuid4()}"
        env.registry.register(Probe("postgres"), key=tenant_b_key)
        env.registry.register(Probe("slack"), key="slack")
        r = env.client.post(f"{API}/adapters/nothing/execute", headers=env.h(env.a),
                            json={"operation": "send_message", "params": {}})
        assert r.status_code == 400, r.text
        assert tenant_b_key not in r.text and tenant_b_key.split(":")[1] not in r.text
        assert "postgres:" not in r.text
        assert "slack" in r.text  # plain adapter types are not tenant data

    def test_the_mcp_gateway_error_does_not_leak_it_either(self, env: Env) -> None:
        import asyncio

        from neuralbridge.core.router import RequestRouter

        key = f"postgres:{uuid.uuid4()}"
        env.registry.register(Probe("postgres"), key=key)
        import neuralbridge.api.dependencies as deps

        router: RequestRouter = deps._request_router
        with pytest.raises(ValueError) as exc:
            asyncio.run(router.route(adapter_type="nothing", operation="x", params={}, actor="t", owner="acc_x"))
        assert key not in str(exc.value)


# ───────────────────────────── M4: bounded audit ─────────────────────────────


class TestAuditIsBounded:
    def test_long_actor_and_resource_are_truncated_visibly(self, env: Env) -> None:
        r = env.client.post(f"{API}/adapters/{'r' * 600}/execute", headers=env.h(None, actor="A" * 7000),
                            json={"operation": "o" * 128, "params": {}})
        assert r.status_code == 402
        rows = audit_rows(env, event_type="entitlement_denied")
        assert rows
        for e in rows:
            assert len(e["actor"]) <= 256 and len(e["action"]) <= 256 and len(e["resource"]) <= 256
        assert any("chars]" in e["actor"] for e in rows)  # truncation is marked, not silent

    def test_an_over_long_operation_is_rejected_at_ingress(self, env: Env) -> None:
        r = env.client.post(f"{API}/adapters/slack/execute", headers=env.h(),
                            json={"operation": "o" * 9000, "params": {}})
        assert r.status_code == 422
        assert audit_rows(env, event_type="entitlement_denied") == []

    def test_a_long_gateway_actor_and_operation_are_bounded(self, env: Env) -> None:
        import asyncio

        import neuralbridge.api.dependencies as deps
        from neuralbridge.core.gateway import MCPGateway, MCPToolDefinition

        env.registry.register(Probe("slack"), key="slack")
        gw = MCPGateway(deps._request_router, deps._audit_logger)
        gw.register_tool(MCPToolDefinition(name="slack_tool", description="", input_schema={}, adapter_type="slack"))
        asyncio.run(gw.handle_request({"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {
            "name": "slack_tool", "arguments": {"operation": "send_message" + "x" * 9000, "actor": "g" * 9000}}}))
        rows = audit_rows(env, event_type="entitlement_denied")
        assert rows and all(len(e["actor"]) <= 256 and len(e["action"]) <= 256 for e in rows)

    def test_300_anonymous_refusals_do_not_write_300_rows(self, env: Env) -> None:
        from neuralbridge.ai.audit_events import REFUSAL_BURST, refusals_suppressed_total

        for i in range(300):
            r = env.client.post(f"{API}/adapters/slack/execute", headers=env.h(None, actor=f"bot-{i}"),
                                json={"operation": "send_message", "params": {}})
            assert r.status_code == 402  # the caller's answer never changes
        rows = audit_rows(env, event_type="entitlement_denied")
        assert 0 < len(rows) <= REFUSAL_BURST + 2
        assert refusals_suppressed_total() >= 300 - (REFUSAL_BURST + 2)
        ready = env.client.get(f"{API}/health/ready").json()
        assert ready["audit_refusals_suppressed"] == refusals_suppressed_total()

    def test_suppression_is_itself_recorded_on_the_next_written_refusal(self, env: Env, monkeypatch) -> None:
        import neuralbridge.ai.audit_events as ae

        clock = [1000.0]
        monkeypatch.setattr(ae.time, "monotonic", lambda: clock[0])
        for _ in range(ae.REFUSAL_BURST + 25):
            env.client.post(f"{API}/adapters/slack/execute", headers=env.h(), json={"operation": "send_message", "params": {}})
        before = len(audit_rows(env, event_type="entitlement_denied"))
        clock[0] += 3600
        env.client.post(f"{API}/adapters/slack/execute", headers=env.h(), json={"operation": "send_message", "params": {}})
        rows = audit_rows(env, event_type="entitlement_denied")
        assert len(rows) == before + 1
        assert any(e["details"].get("suppressed_since_last", 0) >= 25 for e in rows)

    def test_one_tenants_refusals_do_not_silence_another(self, env: Env) -> None:
        import neuralbridge.ai.audit_events as ae

        for _ in range(ae.REFUSAL_BURST + 20):
            env.client.post(f"{API}/adapters/slack/execute", headers=env.h(env.free), json={"operation": "send_message", "params": {}})
        n_free = len([e for e in audit_rows(env, event_type="entitlement_denied") if e["details"]["owner"] == env.owners["a"]])
        assert n_free == 0
        # the free tenant filled only its own bucket; a different tenant's first refusal still lands
        env.client.post(f"{API}/adapters/slack/validate", headers=env.h(None), json={})
        owners = {e["details"]["owner"] for e in audit_rows(env, event_type="entitlement_denied")}
        assert len(owners) >= 2

    def test_authorized_events_are_never_dropped_by_the_limiter(self, env: Env) -> None:
        import neuralbridge.ai.audit_events as ae

        env.registry.register(Probe("slack"), key="slack")
        for _ in range(ae.REFUSAL_BURST + 50):  # exhaust the refusal buckets first
            env.client.post(f"{API}/adapters/slack/execute", headers=env.h(), json={"operation": "send_message", "params": {}})
        assert ae.refusals_suppressed_total() > 0
        for _ in range(60):
            assert env.client.post(f"{API}/adapters/slack/execute", headers=env.h(env.a),
                                   json={"operation": "send_message", "params": {}}).status_code == 200
        calls = [e for e in audit_rows(env, event_type="adapter_call") if e["details"].get("owner") == env.owners["a"]]
        assert len(calls) == 60


# ───────────────────────────── L1: CSV formulas ─────────────────────────────


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_csv_export_neutralises_formula_cells(env: Env, prefix: str) -> None:
    payload = f"{prefix}cmd|' /C calc'!A0"
    env.registry.register(Probe("slack"), key="slack")
    r = env.client.post(f"{API}/adapters/slack/execute", headers=env.h(env.a),
                        json={"operation": payload, "params": {}})
    assert r.status_code == 200
    export = env.client.get(f"{API}/logs/export", headers=env.h(OPERATOR), params={"file_format": "csv"})
    assert export.status_code == 200
    cells = [c for row in csv.reader(io.StringIO(export.text, newline="")) for c in row]
    dangerous = [c for c in cells if c.startswith(("=", "+", "-", "@", "\t", "\r"))]
    assert dangerous == []
    assert any(c.startswith("'") and "cmd|" in c for c in cells)
    # JSON export is unchanged: the raw value is preserved for machines (checked below)
    js = env.client.get(f"{API}/logs/export", headers=env.h(OPERATOR), params={"file_format": "json"})
    assert any(e["action"] == payload for e in js.json())


# ───────────────────────────── the sink itself bounds every identifying field ─────────────────────────────


def test_the_audit_sink_bounds_actor_resource_action_even_if_a_caller_did_not() -> None:
    import asyncio

    from neuralbridge.security.audit import (
        MAX_FIELD_CHARS,
        AuditLogger,
        InMemoryAuditStorage,
        bound_text,
    )

    audit = AuditLogger(InMemoryAuditStorage())
    entry = asyncio.run(audit.log_event(
        event_type="adapter_call", actor="a" * 7000, resource="r" * 5000, action="x" * 9000, result="ok" * 500))
    for value in (entry.actor, entry.resource, entry.action, entry.result):
        assert len(value) <= MAX_FIELD_CHARS and "chars]" in value
    assert bound_text("short") == "short"
    assert bound_text("z" * 300).endswith("chars]") and len(bound_text("z" * 300)) == MAX_FIELD_CHARS


def test_record_bounds_owner_and_detail_strings() -> None:
    import asyncio

    from neuralbridge.ai.audit_events import record, reset_refusal_limiter
    from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

    async def go():
        reset_refusal_limiter()
        audit = AuditLogger(InMemoryAuditStorage())
        await record(audit, event_type="plan_approve", actor="a", owner="o" * 1000, resource="r", action="x",
                     result="success", details={"note": "n" * 5000})
        return [e async for e in audit.query_events()]

    row = asyncio.run(go())[0]
    assert len(row.details["owner"]) <= 128 and len(row.details["note"]) <= 512
