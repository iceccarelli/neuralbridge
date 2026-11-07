# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Resource controls on the adapter, /ai and MCP routes: body size, rate, concurrency, timeout.

All limits are per process (documented in ``neuralbridge.security.limits``); these tests run
the real app, the real router and the real audit sink, with a controllable adapter standing in
only where a test needs a call that stays in flight or never returns.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient

from neuralbridge.security.limits import (
    BusyError,
    ConcurrencyGate,
    Limits,
    RateLimitedError,
    SlidingWindowLimiter,
)

from .platform_support import (
    API,
    OPERATOR_KEY,
    Keys,
    bind,
    client,
    env,
    h,
    keys,
    pg_run,
    read,
    requires_postgres,
    reset_singletons,
)


class ProbeAdapter:
    """A real-looking adapter the tests control: instant, slow, or held until released."""

    adapter_type = "probe"

    def __init__(self) -> None:
        self.calls = 0
        self.running = 0
        self.peak = 0
        self.release: asyncio.Event | None = None
        self.delay = 0.0

    async def execute(self, operation, params):
        self.calls += 1
        self.running += 1
        self.peak = max(self.peak, self.running)
        try:
            if self.release is not None:
                await self.release.wait()
            if self.delay:
                await asyncio.sleep(self.delay)
            return {"ok": True}
        finally:
            self.running -= 1


def install_probe(name: str = "probe") -> ProbeAdapter:
    from neuralbridge.api.dependencies import get_adapter_registry

    adapter = ProbeAdapter()
    get_adapter_registry().register(adapter, key=name)  # type: ignore[arg-type]
    return adapter


def call(c: TestClient, key: str = OPERATOR_KEY, name: str = "probe"):
    return c.post(f"/api/v1/adapters/{name}/execute", headers=h(key), json={"operation": "ping", "params": {}})


# ───────────────────────────── the primitives ─────────────────────────────


class TestPrimitives:
    def test_sliding_window_allows_the_limit_then_refuses_then_recovers(self) -> None:
        now = [0.0]
        lim = SlidingWindowLimiter(3, window=60, clock=lambda: now[0])
        for _ in range(3):
            lim.check("t")
        with pytest.raises(RateLimitedError) as exc:
            lim.check("t")
        assert 1 <= exc.value.retry_after <= 60
        lim.check("other")  # keyed per tenant
        now[0] = 61.0
        lim.check("t")

    def test_disabled_limiter_never_refuses(self) -> None:
        lim = SlidingWindowLimiter(0)
        for _ in range(1000):
            lim.check("t")

    def test_concurrency_gate_caps_total_and_per_key_and_releases(self) -> None:
        gate = ConcurrencyGate(total=3, per_key=2)
        with gate.slot("a"), gate.slot("a"):
            with pytest.raises(BusyError):
                with gate.slot("a"):
                    pass
            with gate.slot("b"):
                with pytest.raises(BusyError):
                    with gate.slot("c"):
                        pass
        assert gate.in_flight == 0
        with gate.slot("a"):
            pass

    def test_limits_read_the_environment_and_ignore_nonsense(self, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_MAX_BODY_BYTES", "4096")
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "7")
        monkeypatch.setenv("NEURALBRIDGE_MAX_CONCURRENT_CALLS", "banana")
        monkeypatch.setenv("NEURALBRIDGE_ADAPTER_CALL_TIMEOUT", "-3")
        lim = Limits.from_env()
        assert (lim.max_body_bytes, lim.rate_per_minute) == (4096, 7)
        assert lim.max_concurrent == Limits().max_concurrent and lim.call_timeout == Limits().call_timeout


# ───────────────────────────── request body size ─────────────────────────────


class TestBodySize:
    @pytest.fixture(autouse=True)
    def _small_cap(self, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_MAX_BODY_BYTES", "2000")

    def test_oversized_declared_body_is_413_on_every_route_family(self, client: TestClient, keys: Keys) -> None:
        big = {"operation": "x", "params": {"blob": "a" * 5000}}
        for path in ("/api/v1/adapters/probe/execute", f"{API}/read", f"{API}/plan", f"{API}/connections"):
            r = client.post(path, headers=h(keys.a), json=big)
            assert r.status_code == 413, (path, r.status_code)
            assert r.json()["detail"]["error"] == "request_too_large"

    def test_a_chunked_body_without_content_length_is_stopped_too(self, client: TestClient, keys: Keys) -> None:
        def chunks():
            for _ in range(10):
                yield b'{"operation":"x","params":{"b":"' + b"a" * 800 + b'"}}'

        r = client.post(f"{API}/read", headers={**h(keys.a), "content-type": "application/json"}, content=chunks())
        assert r.status_code == 413

    def test_bodies_under_the_cap_are_unaffected(self, client: TestClient, keys: Keys) -> None:
        r = read(client, keys.a, "nope", operation="health_check")
        assert r.status_code == 404  # reached the handler
        assert client.get("/api/v1/health/live").status_code == 200

    def test_the_mcp_gateway_applies_the_same_cap(self) -> None:
        from neuralbridge.core.gateway import MCPGateway
        from neuralbridge.core.router import AdapterRegistry, RequestRouter
        from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

        audit = AuditLogger(InMemoryAuditStorage())
        gw = MCPGateway(RequestRouter(AdapterRegistry(), audit), audit)
        resp = asyncio.run(gw.handle_request(json.dumps(
            {"jsonrpc": "2.0", "id": "1", "method": "tools/call", "params": {"name": "t", "arguments": {"x": "a" * 5000}}})))
        assert resp.error and resp.error["code"] == -32600 and "request_too_large" in resp.error["message"]


# ───────────────────────────── rate limit ─────────────────────────────


class TestRateLimit:
    def test_per_tenant_429_with_retry_after_on_the_adapters_route(self, client: TestClient, keys: Keys, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "3")
        reset_singletons_router()
        adapter = install_probe()
        assert [call(client, keys.a).status_code for _ in range(3)] == [200, 200, 200]
        limited = call(client, keys.a)
        assert limited.status_code == 429
        assert limited.json()["detail"]["error"] == "rate_limited"
        assert int(limited.headers["retry-after"]) >= 1
        assert adapter.calls == 3, "a rate-limited call reached the adapter"
        assert call(client, keys.b).status_code == 200, "one tenant's flood must not starve another"

    @requires_postgres
    def test_the_same_limit_covers_the_ai_read_path(self, client: TestClient, keys: Keys, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "2")
        reset_singletons_router()
        conn = bind(client, keys.a, "rl")
        assert read(client, keys.a, conn["id"]).status_code == 200
        assert read(client, keys.a, conn["id"]).status_code == 200
        third = read(client, keys.a, conn["id"])
        assert third.status_code == 429 and third.headers["retry-after"]

    def test_the_mcp_gateway_shares_the_limit_and_reports_it_as_a_jsonrpc_error(self, monkeypatch) -> None:
        from neuralbridge.core.gateway import MCPGateway, MCPToolDefinition
        from neuralbridge.core.router import AdapterRegistry, RequestRouter
        from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

        monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
        registry, audit = AdapterRegistry(), AuditLogger(InMemoryAuditStorage())
        registry.register(ProbeAdapter(), key="probe")  # type: ignore[arg-type]
        gw = MCPGateway(RequestRouter(registry, audit, Limits(rate_per_minute=2)), audit)
        gw.register_tool(MCPToolDefinition(name="probe", description="", input_schema={}, adapter_type="probe"))
        req = {"jsonrpc": "2.0", "id": "1", "method": "tools/call",
               "params": {"name": "probe", "arguments": {"operation": "ping", "api_key": OPERATOR_KEY}}}

        async def go():
            return [await gw.handle_request(req) for _ in range(3)]

        first, second, third = asyncio.run(go())
        assert first.error is None and second.error is None
        assert third.error["code"] == -32000 and third.error["data"]["status"] == 429
        assert third.error["data"]["retry_after"] >= 1


def reset_singletons_router() -> None:
    import neuralbridge.api.dependencies as deps

    deps._request_router = None


# ───────────────────────────── concurrency and timeout ─────────────────────────────


def asgi(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


class TestConcurrencyAndTimeout:
    def test_in_flight_calls_are_capped_per_adapter_and_released_afterwards(self, env, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_MAX_CONCURRENT_PER_ADAPTER", "2")
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "0")
        from neuralbridge.main import create_app

        reset_singletons()
        adapter = install_probe()

        async def go():
            adapter.release = asyncio.Event()
            async with asgi(create_app()) as c:
                url, hdr = "/api/v1/adapters/probe/execute", h(OPERATOR_KEY)
                body = {"operation": "ping", "params": {}}
                running = [asyncio.create_task(c.post(url, headers=hdr, json=body)) for _ in range(2)]
                while adapter.running < 2:
                    await asyncio.sleep(0.01)
                refused = await c.post(url, headers=hdr, json=body)
                adapter.release.set()
                done = await asyncio.gather(*running)
                after = await c.post(url, headers=hdr, json=body)
                return refused, done, after

        refused, done, after = asyncio.run(go())
        reset_singletons()
        assert refused.status_code == 503 and refused.json()["detail"]["error"] == "busy"
        assert refused.headers["retry-after"]
        assert [r.status_code for r in done] == [200, 200] and after.status_code == 200
        assert adapter.peak == 2, "more calls ran at once than the cap allows"

    def test_a_call_that_never_returns_is_cut_off_audited_and_frees_its_slot(self, env, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_ADAPTER_CALL_TIMEOUT", "0.3")
        monkeypatch.setenv("NEURALBRIDGE_MAX_CONCURRENT_PER_ADAPTER", "1")
        monkeypatch.setenv("NEURALBRIDGE_RATE_LIMIT_PER_MINUTE", "0")
        from neuralbridge.main import create_app

        reset_singletons()
        adapter = install_probe()
        adapter.delay = 30

        async def go():
            async with asgi(create_app()) as c:
                first = await c.post("/api/v1/adapters/probe/execute", headers=h(OPERATOR_KEY),
                                     json={"operation": "ping", "params": {}})
                adapter.delay = 0
                second = await c.post("/api/v1/adapters/probe/execute", headers=h(OPERATOR_KEY),
                                      json={"operation": "ping", "params": {}})
                logs = await c.get("/api/v1/logs", headers=h(OPERATOR_KEY), params={"event_type": "adapter_error"})
                return first, second, logs.json()

        first, second, logs = asyncio.run(go())
        reset_singletons()
        assert first.status_code == 504
        assert second.status_code == 200, "the timed-out call kept its concurrency slot"
        assert logs["events"][0]["details"]["error_type"] == "AdapterTimeoutError"


# ───────────────────────────── a refused approval does not burn the plan ─────────────────────────────


@requires_postgres
class TestRefusedBeforeDispatchKeepsThePlanPending:
    @pytest.fixture
    def table(self):
        pg_run("DROP TABLE IF EXISTS rc_t", "CREATE TABLE rc_t (id int)")
        yield
        pg_run("DROP TABLE IF EXISTS rc_t")

    def _plan(self, client, key, cid) -> str:
        r = client.post(f"{API}/plan", headers=h(key), json={
            "connection_id": cid, "operation": "execute_sql", "params": {"sql": "INSERT INTO rc_t VALUES (1)"}})
        assert r.status_code == 200, r.text
        return r.json()["plan"]["id"]

    def test_rate_limited_approval_leaves_the_plan_pending_and_unexecuted(
        self, client: TestClient, keys: Keys, table, monkeypatch
    ) -> None:
        import neuralbridge.api.dependencies as deps

        conn = bind(client, keys.a, "rc")
        pid = self._plan(client, keys.a, conn["id"])
        assert read(client, keys.a, conn["id"]).status_code == 200  # creates the router singleton
        live = deps._request_router
        assert live is not None
        live._rate = SlidingWindowLimiter(1)
        live._rate.check(live_owner(client, keys.a))  # this tenant's budget for the minute is spent
        refused = client.post(f"{API}/plan/{pid}/approve", headers=h(keys.a))
        assert refused.status_code == 429 and refused.headers["retry-after"]
        plan = client.get(f"{API}/plan/{pid}", headers=h(keys.a)).json()
        assert plan["status"] == "pending_approval" and plan["decided_by"] is None and plan["decided_at"] is None

        live._rate = SlidingWindowLimiter(100)
        ok = client.post(f"{API}/plan/{pid}/approve", headers=h(keys.a))
        assert ok.status_code == 200 and ok.json()["success"] is True
        assert client.get(f"{API}/plan/{pid}", headers=h(keys.a)).json()["status"] == "executed"

    def test_audit_sink_down_refuses_the_approval_before_anything_runs(
        self, client: TestClient, keys: Keys, table, tmp_path
    ) -> None:
        import shutil

        conn = bind(client, keys.a, "rc2")
        pid = self._plan(client, keys.a, conn["id"])
        db = tmp_path / "audit.db"
        parked = tmp_path / "parked"
        parked.mkdir()
        for p in tmp_path.glob("audit.db*"):
            shutil.move(str(p), str(parked / p.name))
        db.mkdir()
        try:
            refused = client.post(f"{API}/plan/{pid}/approve", headers=h(keys.a))
        finally:
            db.rmdir()
            for p in parked.iterdir():
                shutil.move(str(p), str(tmp_path / p.name))
        assert refused.status_code == 503
        assert client.get(f"{API}/plan/{pid}", headers=h(keys.a)).json()["status"] == "pending_approval"
        import asyncpg  # noqa: F401

        from .platform_support import PG_DATABASE, PG_HOST, PG_PASSWORD, PG_PORT, PG_USER

        async def rows():
            c = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
            try:
                return await c.fetchval("SELECT count(*) FROM rc_t")
            finally:
                await c.close()

        assert asyncio.run(rows()) == 0


def live_owner(client: TestClient, key: str) -> str:
    from assurance.billing.accounts import AccountStore

    return AccountStore(__import__("os").environ["ASSURANCE_ACCOUNTS"]).resolve_key(key).account.id
