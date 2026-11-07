# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Connection and credential lifecycle: create, rotate, revoke, delete — against real PostgreSQL.

* the shared dev cluster (``:5432``, trust auth) for everything that does not depend on a
  password being checked;
* a private throwaway cluster with scram-sha-256 password authentication (``scram_pg``) for
  "the target rejects these credentials" and "the old credentials stopped working".

Secrets are write-only: the bound password must appear in no response, log line, audit
record or stored file. Revocation takes effect on the next call, also for a worker process
that still holds a live adapter. Every cross-tenant attempt reads exactly like a missing id.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from .platform_support import (
    API,
    OPERATOR_KEY,
    PG_DATABASE,
    PG_HOST,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    Keys,
    audit_events,
    bind,
    client,
    env,
    h,
    keys,
    pg_run,
    read,
    requires_postgres,
    reset_singletons,
    scram_pg,
)

pytestmark = requires_postgres

LEAK = "Pw-LEAKCHECK-7731-zq"
LEAK2 = "Pw-LEAKCHECK-9902-xk"


@pytest.fixture
def table():
    pg_run("DROP TABLE IF EXISTS lc_t", "CREATE TABLE lc_t (id int)")
    yield
    pg_run("DROP TABLE IF EXISTS lc_t")


_DROP_ROLE = (
    "DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='lc_app') "
    "THEN DROP OWNED BY lc_app; DROP ROLE lc_app; END IF; END $$"
)


@pytest.fixture
def scram_role(scram_pg):
    scram_pg.run(_DROP_ROLE, f"CREATE ROLE lc_app LOGIN PASSWORD '{LEAK}'", "GRANT ALL ON SCHEMA public TO lc_app")
    yield scram_pg
    scram_pg.run(_DROP_ROLE)


def scram_body(cluster, name: str, password: str) -> dict:
    return {"name": name, "host": cluster.host, "port": cluster.port, "user": "lc_app",
            "password": password, "database": cluster.database}


def bind_scram(client, key, cluster, name="scram-conn", password=LEAK) -> dict:
    r = client.post(f"{API}/connections", headers=h(key), json=scram_body(cluster, name, password))
    assert r.status_code == 200, r.text
    return r.json()


def rotate(client, key, cid, user="lc_app", password=LEAK):
    return client.post(f"{API}/connections/{cid}/rotate", headers=h(key), json={"user": user, "password": password})


def revoke(client, key, cid):
    return client.post(f"{API}/connections/{cid}/revoke", headers=h(key))


def plan(client, key, cid, sql):
    return client.post(f"{API}/plan", headers=h(key),
                       json={"connection_id": cid, "operation": "execute_sql", "params": {"sql": sql}})


def approve(client, key, plan_id):
    return client.post(f"{API}/plan/{plan_id}/approve", headers=h(key))


def types(events: list[dict]) -> list[str]:
    return [e["event_type"] for e in events]


# ───────────────────────────── secrets are write-only ─────────────────────────────


class TestSecretsAreWriteOnly:
    def test_the_password_is_in_no_response_log_audit_record_or_file(
        self, client, keys: Keys, scram_role, capfd, caplog, tmp_path
    ) -> None:
        caplog.set_level("DEBUG")
        conn = bind_scram(client, keys.a, scram_role)
        responses = [json.dumps(conn)]
        assert set(conn) == {"id", "name", "adapter_type", "status", "source", "live"}
        assert isinstance(conn["live"], bool)
        responses.append(client.get(f"{API}/connections", headers=h(keys.a)).text)
        r = read(client, keys.a, conn["id"], operation="query", sql="SELECT current_user")
        assert r.status_code == 200 and r.json()["data"][0]["current_user"] == "lc_app"
        responses.append(r.text)
        responses.append(rotate(client, keys.a, conn["id"], password=LEAK).text)
        responses.append(client.get(f"{API}/capabilities", params={"connection_id": conn["id"]}, headers=h(keys.a)).text)
        responses.append(client.get(f"{API}/audit", headers=h(keys.a), params={"limit": 500}).text)
        responses.append(client.get("/api/v1/logs", headers=h(keys.a), params={"limit": 1000}).text)
        responses.append(client.get("/api/v1/logs", headers=h(OPERATOR_KEY), params={"limit": 1000}).text)
        responses.append(client.get("/api/v1/logs/export", headers=h(OPERATOR_KEY)).text)
        responses.append(revoke(client, keys.a, conn["id"]).text)
        responses.append(client.delete(f"{API}/connections/{conn['id']}", headers=h(keys.a)).text)

        assert all(LEAK not in text for text in responses)
        out = capfd.readouterr()
        assert LEAK not in out.out and LEAK not in out.err and LEAK not in caplog.text
        for db in list(tmp_path.glob("*.db*")):
            assert LEAK.encode() not in db.read_bytes(), db.name

    def test_a_rejected_request_does_not_echo_the_password_back(self, client, keys: Keys) -> None:
        body = {"name": "x", "user": PG_USER, "password": LEAK, "database": PG_DATABASE}  # no host
        r = client.post(f"{API}/connections", headers=h(keys.a), json=body)
        assert r.status_code == 422
        assert LEAK not in r.text
        assert any(e["loc"][-1] == "host" for e in r.json()["detail"])

    def test_a_wrong_password_surfaces_generically_and_leaks_nothing(
        self, client, keys: Keys, scram_role, capfd, caplog
    ) -> None:
        caplog.set_level("DEBUG")
        conn = bind_scram(client, keys.a, scram_role, password=LEAK2)  # not the role's password
        r = read(client, keys.a, conn["id"], operation="query", sql="SELECT 1")
        assert r.status_code == 502
        assert LEAK2 not in r.text and scram_role.host not in r.text and str(scram_role.port) not in r.text
        trail = client.get(f"{API}/audit", headers=h(keys.a), params={"limit": 500}).text
        assert LEAK2 not in trail
        out = capfd.readouterr()
        assert LEAK2 not in out.out + out.err + caplog.text


# ───────────────────────────── rotate ─────────────────────────────


class TestRotate:
    def test_rotation_swaps_the_live_credential_and_the_old_one_stops_working(
        self, client, keys: Keys, scram_role
    ) -> None:
        conn = bind_scram(client, keys.a, scram_role)
        assert read(client, keys.a, conn["id"], operation="query", sql="SELECT 1").status_code == 200

        scram_role.run(f"ALTER ROLE lc_app PASSWORD '{LEAK2}'")  # the DBA rotates the secret
        r = rotate(client, keys.a, conn["id"], password=LEAK2)
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "rotated" and r.json()["id"] == conn["id"]
        assert read(client, keys.a, conn["id"], operation="query", sql="SELECT 1").status_code == 200

        # the previous secret is no longer accepted by the target — and is refused cleanly
        stale = rotate(client, keys.a, conn["id"], password=LEAK)
        assert stale.status_code == 422
        assert LEAK not in stale.text and LEAK2 not in stale.text
        # a refused rotation left the working credential in place
        assert read(client, keys.a, conn["id"], operation="query", sql="SELECT current_user").status_code == 200

    def test_rotation_resupplies_credentials_after_a_restart(self, client, keys: Keys, scram_role) -> None:
        conn = bind_scram(client, keys.a, scram_role)
        reset_singletons()  # "restart": registry and router are gone, the store file remains
        down = read(client, keys.a, conn["id"], operation="query", sql="SELECT 1")
        assert down.status_code == 409 and "no live adapter" in down.json()["detail"]
        assert rotate(client, keys.a, conn["id"]).status_code == 200
        assert read(client, keys.a, conn["id"], operation="query", sql="SELECT 1").status_code == 200

    def test_unknown_id_is_404(self, client, keys: Keys) -> None:
        r = rotate(client, keys.a, "does-not-exist", user=PG_USER, password=PG_PASSWORD)
        assert r.status_code == 404 and r.json() == {"detail": "Connection 'does-not-exist' not found."}

    def test_the_seeded_demo_cannot_be_rotated_through_the_api(self, client, keys: Keys) -> None:
        demo = next(c for c in client.get(f"{API}/connections", headers=h()).json() if c["source"] == "seeded_from_env")
        assert rotate(client, keys.a, demo["id"], user=PG_USER, password=PG_PASSWORD).status_code == 404
        op = rotate(client, OPERATOR_KEY, demo["id"], user=PG_USER, password=PG_PASSWORD)
        assert op.status_code == 409 and "NEURALBRIDGE_AI_PG" in op.json()["detail"]


# ───────────────────────────── revoke ─────────────────────────────


class TestRevoke:
    def test_revocation_takes_effect_on_the_next_call_everywhere(self, client, keys: Keys, table) -> None:
        conn = bind(client, keys.a, "to-revoke")
        pending = plan(client, keys.a, conn["id"], "INSERT INTO lc_t VALUES (1)").json()["plan"]["id"]
        assert read(client, keys.a, conn["id"], operation="query", sql="SELECT 1").status_code == 200

        r = revoke(client, keys.a, conn["id"])
        assert r.status_code == 200 and r.json() == {"revoked": conn["id"], "already_revoked": False}

        after = read(client, keys.a, conn["id"], operation="query", sql="SELECT 1")
        assert after.status_code == 409 and "revoked" in after.json()["detail"]
        assert plan(client, keys.a, conn["id"], "INSERT INTO lc_t VALUES (2)").status_code == 409
        assert approve(client, keys.a, pending).status_code == 409  # the plan was denied with it
        decided = client.get(f"{API}/plan/{pending}", headers=h(keys.a)).json()
        assert decided["status"] == "denied" and decided["deny_reason"] == "connection revoked"
        assert client.get(f"{API}/capabilities", params={"connection_id": conn["id"]}, headers=h(keys.a)).json() == []
        listed = {c["id"]: c for c in client.get(f"{API}/connections", headers=h(keys.a)).json()}
        assert listed[conn["id"]]["status"] == "revoked"

        from neuralbridge.api.dependencies import get_adapter_registry

        assert f"postgres:{conn['id']}" not in get_adapter_registry()  # the credential left memory
        rows = asyncio.run(_rows("SELECT count(*) AS n FROM lc_t"))
        assert rows[0]["n"] == 0, "a write ran on a revoked connection"

    def test_a_worker_that_still_holds_the_adapter_refuses_too(self, client, keys: Keys, tmp_path) -> None:
        """Another process has its own registry (still holding a live adapter); revocation is
        recorded in the shared store, which every call re-reads."""
        from neuralbridge.adapters.databases.postgres import PostgresAdapter
        from neuralbridge.ai import orchestrator
        from neuralbridge.ai.identity import Actor
        from neuralbridge.ai.store import AiStore
        from neuralbridge.ai.tenancy import Scope
        from neuralbridge.core.router import AdapterRegistry, RequestRouter
        from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage

        conn = bind(client, keys.a, "two-workers")
        record = AiStore(tmp_path / "ai-store.db").get_connection(conn["id"])
        assert record is not None
        other_registry = AdapterRegistry()
        other_registry.register(PostgresAdapter(config={
            "host": PG_HOST, "port": PG_PORT, "user": PG_USER, "password": PG_PASSWORD, "database": PG_DATABASE}),
            key=record.registry_key)
        router = RequestRouter(other_registry, AuditLogger(InMemoryAuditStorage()))
        scope, actor = Scope(owner=record.owner), Actor(id="w2", session_id="s")
        store = AiStore(tmp_path / "ai-store.db")

        async def call():
            return await orchestrator.read(router, other_registry, scope, actor, store, conn["id"], "health_check", {})

        assert asyncio.run(call()).success is True
        assert revoke(client, keys.a, conn["id"]).status_code == 200
        with pytest.raises(orchestrator.OrchestratorError) as exc:
            asyncio.run(call())
        assert exc.value.status_code == 409 and "revoked" in exc.value.detail

    def test_revoke_is_idempotent_terminal_and_deletable(self, client, keys: Keys) -> None:
        conn = bind(client, keys.a, "terminal")
        assert revoke(client, keys.a, conn["id"]).json()["already_revoked"] is False
        again = revoke(client, keys.a, conn["id"])
        assert again.status_code == 200 and again.json()["already_revoked"] is True
        rot = rotate(client, keys.a, conn["id"], user=PG_USER, password=PG_PASSWORD)
        assert rot.status_code == 409 and "revoked" in rot.json()["detail"]
        assert client.delete(f"{API}/connections/{conn['id']}", headers=h(keys.a)).status_code == 200
        assert revoke(client, keys.a, conn["id"]).status_code == 404

    def test_a_lapsed_free_account_can_still_revoke_what_it_bound(self, client, keys: Keys, env) -> None:
        """Revoke/rotate/delete shrink exposure, so they are not behind the paid gate."""
        import sqlite3

        from assurance.billing.accounts import AccountStore

        conn = bind(client, keys.a, "lapsed")
        account = AccountStore(str(env)).resolve_key(keys.a).account
        with sqlite3.connect(env) as db:  # the subscription lapses
            db.execute("UPDATE accounts SET status='cancelled' WHERE id=?", (account.id,))
        assert plan(client, keys.a, conn["id"], "SELECT 1").status_code == 402  # paid path is closed ...
        assert revoke(client, keys.a, conn["id"]).status_code == 200            # ... revoking is not


async def _rows(sql: str):
    import asyncpg

    c = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
    try:
        return [dict(r) for r in await c.fetch(sql)]
    finally:
        await c.close()


# ───────────────────────────── tenant isolation ─────────────────────────────


class TestCrossTenantIsRefused:
    def test_b_cannot_read_execute_rotate_revoke_or_delete_a_connection_of_a(self, client, keys: Keys, table) -> None:
        a_conn = bind(client, keys.a, "A-ONLY")
        missing = "00000000-0000-0000-0000-000000000000"

        def same_404(response) -> None:
            assert response.status_code == 404, response.text
            assert response.json()["detail"].replace(a_conn["id"], missing) == f"Connection '{missing}' not found."

        same_404(read(client, keys.b, a_conn["id"], operation="query", sql="SELECT 1"))
        same_404(plan(client, keys.b, a_conn["id"], "INSERT INTO lc_t VALUES (9)"))
        same_404(rotate(client, keys.b, a_conn["id"], user=PG_USER, password=PG_PASSWORD))
        same_404(revoke(client, keys.b, a_conn["id"]))
        same_404(client.delete(f"{API}/connections/{a_conn['id']}", headers=h(keys.b)))
        same_404(client.get(f"{API}/capabilities", params={"connection_id": a_conn["id"]}, headers=h(keys.b)))
        # anonymous callers get the same answer
        same_404(revoke(client, None, a_conn["id"]))
        same_404(rotate(client, None, a_conn["id"], user=PG_USER, password=PG_PASSWORD))
        same_404(client.delete(f"{API}/connections/{a_conn['id']}", headers=h()))

        # nothing changed for A: still active, still usable, still listed
        assert read(client, keys.a, a_conn["id"], operation="query", sql="SELECT 1").status_code == 200
        listed = client.get(f"{API}/connections", headers=h(keys.a)).json()
        assert [c["status"] for c in listed if c["id"] == a_conn["id"]] == ["created"]

    def test_the_shared_demo_connection_is_not_revocable_or_deletable_by_customers(self, client, keys: Keys) -> None:
        demo = next(c for c in client.get(f"{API}/connections", headers=h()).json() if c["source"] == "seeded_from_env")
        assert revoke(client, keys.a, demo["id"]).status_code == 404
        assert client.delete(f"{API}/connections/{demo['id']}", headers=h(keys.a)).status_code == 404
        assert read(client, keys.b, demo["id"], operation="query", sql="SELECT 1").status_code == 200

    def test_the_operator_can_revoke_any_connection(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, "op-revokes")
        assert revoke(client, OPERATOR_KEY, a_conn["id"]).status_code == 200
        assert read(client, keys.a, a_conn["id"], operation="query", sql="SELECT 1").status_code == 409

    def test_refused_attempts_land_in_the_attackers_trail_not_the_victims(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, "A-ONLY")
        revoke(client, keys.b, a_conn["id"])
        b_trail = audit_events(client, keys.b)
        assert [(e["event_type"], e["result"]) for e in b_trail] == [("connection_revoke", "refused:404")]
        assert not any(e["event_type"] == "connection_revoke" for e in audit_events(client, keys.a))


# ───────────────────────────── audited events: actor + tenant, no secrets ─────────────────────────────


class TestSecurityRelevantEventsAreAudited:
    def _owner(self, env, key: str) -> str:
        from assurance.billing.accounts import AccountStore

        return AccountStore(str(env)).resolve_key(key).account.id

    def test_lifecycle_and_plan_events_carry_actor_and_tenant(self, client, keys: Keys, env, table) -> None:
        owner = self._owner(env, keys.a)
        conn = bind(client, keys.a, "audited")
        rotate(client, keys.a, conn["id"], user=PG_USER, password=PG_PASSWORD)
        sql = "INSERT INTO lc_t VALUES (41)"
        card = plan(client, keys.a, conn["id"], sql).json()
        pid = card["plan"]["id"]
        receipt = approve(client, keys.a, pid).json()
        assert receipt["success"] is True
        deny_me = plan(client, keys.a, conn["id"], "DELETE FROM lc_t").json()["plan"]["id"]
        client.post(f"{API}/plan/{deny_me}/deny", headers=h(keys.a), params={"reason": "not today"})
        revoke(client, keys.a, conn["id"])
        client.delete(f"{API}/connections/{conn['id']}", headers=h(keys.a))

        events = audit_events(client, keys.a)
        seen = types(events)
        for expected in ("connection_create", "connection_rotate", "plan_propose", "plan_approve",
                         "plan_execute", "adapter_call", "plan_deny", "connection_revoke", "connection_delete"):
            assert expected in seen, (expected, seen)
        for e in events:
            assert e["details"]["owner"] == owner, e
            assert e["actor"] == "human_session:plat-actor", e
        # the exact statement is attributable through its digest, but the SQL is not copied into the trail
        proposed = next(e for e in events if e["event_type"] == "plan_propose" and e["details"].get("plan_id") == pid)
        assert len(proposed["details"]["params_sha256"]) == 64
        assert "INSERT INTO lc_t" not in json.dumps(events)
        assert all(PG_PASSWORD not in json.dumps(e) for e in events)
        executed = next(e for e in events if e["event_type"] == "plan_execute")
        assert executed["result"] == "success" and executed["details"]["request_id"] == receipt["provenance"]["request_id"]

    def test_a_failed_execution_is_recorded_as_a_failure(self, client, keys: Keys, table) -> None:
        conn = bind(client, keys.a, "fails")
        pid = plan(client, keys.a, conn["id"], "INSERT INTO lc_no_such_table VALUES (1)").json()["plan"]["id"]
        receipt = approve(client, keys.a, pid).json()
        assert receipt["success"] is False
        executed = [e for e in audit_events(client, keys.a) if e["event_type"] == "plan_execute"]
        assert [e["result"] for e in executed] == ["failure"]

    def test_entitlement_and_policy_denials_are_audited_with_actor_and_tenant(self, client, keys: Keys, env) -> None:
        free_owner = self._owner(env, keys.free)
        demo = next(c for c in client.get(f"{API}/connections", headers=h()).json() if c["source"] == "seeded_from_env")
        assert plan(client, keys.free, demo["id"], "INSERT INTO lc_t VALUES (1)").status_code == 402
        raw = client.post("/api/v1/adapters/postgres/execute", headers=h(keys.free),
                          json={"operation": "execute_sql", "params": {"sql": "DELETE FROM lc_t"}})
        assert raw.status_code == 402
        ssrf = client.post("/api/v1/adapters/postgres/execute", headers=h(keys.free),
                           json={"operation": "query", "params": {"sql": "SELECT 'http://evil.example/x'"}})
        assert ssrf.status_code == 403

        events = audit_events(client, keys.free)
        by_type = {e["event_type"]: e for e in events}
        assert {"entitlement_denied", "policy_denied"} <= set(by_type)
        assert all(e["details"]["owner"] == free_owner and e["actor"] == "human_session:plat-actor" for e in events)
        surfaces = {e["details"]["surface"] for e in events if e["event_type"] == "entitlement_denied"}
        assert surfaces == {"ai_route", "adapters_route"}
        # another tenant never sees them
        assert audit_events(client, keys.b) == []


class TestLegacyOperatorConnectionTestIsHonest:
    def test_the_test_endpoint_does_not_invent_a_success(self, client) -> None:
        """``POST /api/v1/connections/{id}/test`` used to answer ``success`` with a hard-coded 42 ms
        without contacting anything. It must say that it checked nothing."""
        created = client.post("/api/v1/connections", headers=h(OPERATOR_KEY), json={
            "name": "legacy", "adapter_type": "postgres", "config": {"host": "10.255.255.1"},
            "auth": {"password": LEAK}}).json()
        assert LEAK not in json.dumps(created)
        r = client.post(f"/api/v1/connections/{created['id']}/test", headers=h(OPERATOR_KEY))
        assert r.status_code == 200
        body = r.json()
        assert body["test_result"] == "unchecked" and "latency_ms" not in body
        assert "no connection was attempted" in body["message"].lower()

    def test_secrets_are_masked_on_update_and_in_config_too(self, client) -> None:
        """PATCH used to store ``auth`` unmasked and return it; ``config`` was echoed verbatim."""
        created = client.post("/api/v1/connections", headers=h(OPERATOR_KEY), json={
            "name": "legacy2", "adapter_type": "postgres",
            "config": {"host": "db", "password": LEAK, "nested": {"api_key": LEAK2}},
            "auth": {"password": LEAK}}).json()
        patched = client.patch(f"/api/v1/connections/{created['id']}", headers=h(OPERATOR_KEY), json={
            "auth": {"token": LEAK2}, "config": {"host": "db2", "secret": LEAK}})
        assert patched.status_code == 200
        got = client.get(f"/api/v1/connections/{created['id']}", headers=h(OPERATOR_KEY))
        listed = client.get("/api/v1/connections", headers=h(OPERATOR_KEY))
        for response in (created and json.dumps(created), patched.text, got.text, listed.text):
            assert LEAK not in response and LEAK2 not in response
        assert patched.json()["config"]["host"] == "db2"
