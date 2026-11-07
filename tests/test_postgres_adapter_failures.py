# ruff: noqa: F811, F401  (fixtures are imported by name)
"""PostgreSQL adapter: what happens when things go wrong — against a real server.

* the shared dev cluster on ``127.0.0.1:5432`` for read-only enforcement, statement timeout,
  connection loss, permission errors, pool exhaustion and the row cap (roles are told apart by
  name there; it trusts local connections);
* a private scram-sha-256 cluster (``scram_pg``) wherever a wrong password has to be *rejected*.

Nothing is mocked. LOCAL evidence: it shows the adapter's behaviour against PostgreSQL 16 as
installed here, not against a managed cloud service, a pooler (pgbouncer) or other versions.
"""

from __future__ import annotations

import asyncio
import secrets
import time

import asyncpg
import pytest
from fastapi.testclient import TestClient

from neuralbridge.adapters.databases.postgres import PostgresAdapter

from .platform_support import (
    API,
    PG_DATABASE,
    PG_HOST,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    Keys,
    client,
    env,
    h,
    keys,
    pg_run,
    requires_postgres,
    scram_pg,
)

pytestmark = requires_postgres

SECRET = "Pw-ADAPTERLEAK-5150-qq"


def config(**extra) -> dict:
    cfg = {"host": PG_HOST, "port": PG_PORT, "user": PG_USER, "password": PG_PASSWORD, "database": PG_DATABASE,
           "ssl_mode": "disable"}
    cfg.update(extra)
    return cfg


async def with_adapter(cfg: dict, body):
    adapter = PostgresAdapter(config=cfg)
    outcome = await adapter.connect()
    assert outcome.success, outcome.error
    try:
        return await body(adapter)
    finally:
        await adapter.disconnect()


def sql_rows(sql: str):
    async def go():
        c = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
        try:
            return [dict(r) for r in await c.fetch(sql)]
        finally:
            await c.close()

    return asyncio.run(go())


@pytest.fixture
def table():
    pg_run("DROP TABLE IF EXISTS pgf_t", "DROP TABLE IF EXISTS pgf_new", "CREATE TABLE pgf_t (id int primary key, note text)",
           "INSERT INTO pgf_t VALUES (1,'a'),(2,'b'),(3,'c')", "DROP SEQUENCE IF EXISTS pgf_seq", "CREATE SEQUENCE pgf_seq")
    yield
    pg_run("DROP TABLE IF EXISTS pgf_t", "DROP TABLE IF EXISTS pgf_new", "DROP SEQUENCE IF EXISTS pgf_seq")


# ───────────────────────────── read-only means read-only ─────────────────────────────

MUTATING_READS = [
    "DELETE FROM pgf_t RETURNING *",
    "INSERT INTO pgf_t VALUES (99, 'x') RETURNING *",
    "UPDATE pgf_t SET note = 'pwned' RETURNING *",
    "WITH gone AS (DELETE FROM pgf_t RETURNING id) SELECT * FROM gone",
    "SELECT nextval('pgf_seq')",
    "CREATE TABLE pgf_new (id int)",
    "DROP TABLE pgf_t",
    "TRUNCATE pgf_t",
    "SELECT * FROM pgf_t FOR UPDATE",
]


class TestReadOnlyIsEnforcedByTheAdapter:
    @pytest.mark.parametrize("sql", MUTATING_READS)
    def test_a_query_operation_cannot_change_anything(self, table, sql: str) -> None:
        async def body(adapter):
            return await adapter.execute("query", {"sql": sql})

        r = asyncio.run(with_adapter(config(), body))
        assert r.success is False, f"{sql!r} ran as a read"
        assert sql_rows("SELECT id, note FROM pgf_t ORDER BY id") == [
            {"id": 1, "note": "a"}, {"id": 2, "note": "b"}, {"id": 3, "note": "c"}]
        assert sql_rows("SELECT to_regclass('pgf_new') AS t")[0]["t"] is None

    def test_a_session_setting_changed_by_a_read_does_not_outlive_it(self) -> None:
        """``SET statement_timeout = 0`` is a legal one-statement read; the pool must not keep it."""
        async def body(adapter):
            await adapter.execute("query", {"sql": "SET statement_timeout = 0"})
            return await adapter.execute("query", {"sql": "SELECT pg_sleep(30)"})

        r = asyncio.run(with_adapter(config(statement_timeout_ms=400, pool_size=1), body))
        assert r.success is False and r.error.startswith("statement_timeout")

    def test_ordinary_selects_still_work(self, table) -> None:
        async def body(adapter):
            return (await adapter.execute("query", {"sql": "SELECT id FROM pgf_t ORDER BY id"}),
                    await adapter.execute("list_tables", {}),
                    await adapter.execute("describe_table", {"table_name": "pgf_t"}),
                    await adapter.execute("health_check", {}))

        q, tables, desc, health = asyncio.run(with_adapter(config(), body))
        assert [r["id"] for r in q.data] == [1, 2, 3]
        assert "pgf_t" in tables.data and {c["column_name"] for c in desc.data} == {"id", "note"}
        assert health.success

    def test_execute_sql_remains_the_one_way_to_write(self, table) -> None:
        async def body(adapter):
            return await adapter.execute("execute_sql", {"sql": "INSERT INTO pgf_t VALUES (4, 'd')"})

        assert asyncio.run(with_adapter(config(), body)).success
        assert len(sql_rows("SELECT * FROM pgf_t")) == 4

    def test_the_free_read_route_cannot_be_used_to_write(self, client: TestClient, keys: Keys, table) -> None:
        """The policy gate classifies operation=query as READ whatever the SQL says; before the
        adapter enforced read-only, a keyless caller could delete rows through /ai/read."""
        demo = next(c for c in client.get(f"{API}/connections", headers=h()).json() if c["source"] == "seeded_from_env")
        # Two layers now. The policy refuses a read that does not start with SELECT/WITH/SHOW/EXPLAIN/VALUES
        # (403) ...
        for sql in ("DELETE FROM pgf_t RETURNING *", "UPDATE pgf_t SET note = 'pwned' RETURNING *"):
            r = client.post(f"{API}/read", headers=h(), json={
                "connection_id": demo["id"], "operation": "query", "params": {"sql": sql}})
            assert r.status_code == 403, r.text
        # ... and a write that gets past the policy's first-token rule is still stopped by the
        # adapter's READ ONLY transaction in the database.
        for sql in ("WITH d AS (DELETE FROM pgf_t RETURNING *) SELECT * FROM d",
                    "WITH u AS (UPDATE pgf_t SET note = 'pwned' RETURNING *) SELECT * FROM u"):
            r = client.post(f"{API}/read", headers=h(), json={
                "connection_id": demo["id"], "operation": "query", "params": {"sql": sql}})
            assert r.status_code == 200 and r.json()["success"] is False, r.text
        assert [row["note"] for row in sql_rows("SELECT note FROM pgf_t ORDER BY id")] == ["a", "b", "c"]


# ───────────────────────────── timeouts, caps, exhaustion ─────────────────────────────


class TestLimits:
    def test_statement_timeout_cancels_a_runaway_query_and_the_adapter_recovers(self) -> None:
        async def body(adapter):
            started = time.monotonic()
            slow = await adapter.execute("query", {"sql": "SELECT pg_sleep(30)"})
            elapsed = time.monotonic() - started
            after = await adapter.execute("query", {"sql": "SELECT 1 AS one"})
            return slow, elapsed, after

        slow, elapsed, after = asyncio.run(with_adapter(config(statement_timeout_ms=400), body))
        assert slow.success is False and slow.error.startswith("statement_timeout") and elapsed < 5
        assert after.success and after.data == [{"one": 1}]

    def test_a_result_larger_than_max_rows_is_refused_not_buffered(self) -> None:
        async def body(adapter):
            big = await adapter.execute("query", {"sql": "SELECT g FROM generate_series(1, 200000) g"})
            ok = await adapter.execute("query", {"sql": "SELECT g FROM generate_series(1, 50) g"})
            return big, ok

        big, ok = asyncio.run(with_adapter(config(max_rows=1000), body))
        assert big.success is False and big.error.startswith("result_too_large") and "1000" in big.error
        assert ok.success and len(ok.data) == 50

    def test_pool_exhaustion_fails_fast_and_recovers(self) -> None:
        async def body(adapter):
            holders = [asyncio.create_task(adapter.execute("query", {"sql": "SELECT pg_sleep(1.5)"})) for _ in range(2)]
            await asyncio.sleep(0.4)
            started = time.monotonic()
            starved = await adapter.execute("query", {"sql": "SELECT 1"})
            waited = time.monotonic() - started
            await asyncio.gather(*holders)
            after = await adapter.execute("query", {"sql": "SELECT 2 AS two"})
            return starved, waited, after

        starved, waited, after = asyncio.run(with_adapter(config(pool_size=2, acquire_timeout=0.4), body))
        assert starved.success is False and starved.error.startswith("pool_exhausted") and waited < 2
        assert after.success and after.data == [{"two": 2}]


# ───────────────────────────── connection loss, permissions ─────────────────────────────


class TestFailureModes:
    def test_connection_lost_mid_query_is_a_structured_failure_and_the_pool_heals(self) -> None:
        async def body(adapter):
            running = asyncio.create_task(adapter.execute("query", {"sql": "SELECT pg_sleep(30)"}))
            killer = await asyncpg.connect(
                host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
            try:
                for _ in range(50):
                    await asyncio.sleep(0.1)
                    killed = await killer.fetchval(
                        "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                        "WHERE application_name = $1 AND query LIKE '%pg_sleep(30)%' AND pid <> pg_backend_pid()",
                        "nb-conn-loss-test")
                    if killed:
                        break
            finally:
                await killer.close()
            started = time.monotonic()
            lost = await asyncio.wait_for(running, 10)
            after = await adapter.execute("query", {"sql": "SELECT 7 AS seven"})
            return killed, lost, time.monotonic() - started, after

        killed, lost, waited, after = asyncio.run(with_adapter(config(application_name="nb-conn-loss-test"), body))
        assert killed == 1
        assert lost.success is False and lost.error.startswith("connection_lost") and waited < 5
        assert after.success and after.data == [{"seven": 7}], "the pool kept a dead connection"

    def test_a_missing_privilege_is_reported_as_permission_denied(self, table) -> None:
        # A role WITH a password: a server that requires password authentication (CI's Postgres
        # service does; a local trust-auth cluster does not) cannot log in a role that has none, and
        # the test is about the missing privilege, not about login. A random value, never reused.
        password = secrets.token_urlsafe(18)
        pg_run("DROP ROLE IF EXISTS pgf_noperm", f"CREATE ROLE pgf_noperm LOGIN PASSWORD '{password}'")
        try:
            async def body(adapter):
                return await adapter.execute("query", {"sql": "SELECT * FROM pgf_t"})

            r = asyncio.run(with_adapter(config(user="pgf_noperm", password=password), body))
            assert r.success is False and r.error.startswith("permission_denied")
            assert "pgf_t" in r.error  # the server's own message is kept; it carries no credential
        finally:
            pg_run("DROP ROLE IF EXISTS pgf_noperm")

    def test_unreachable_server_is_a_clean_connection_error(self) -> None:
        adapter = PostgresAdapter(config=config(port=1, password=SECRET))
        outcome = asyncio.run(adapter.connect())
        assert outcome.success is False and outcome.error.startswith("PostgreSQL connection failed")
        assert SECRET not in outcome.error
        assert PG_HOST not in outcome.error and "port" not in outcome.error.lower(), "driver text leaked the target"

    def test_not_connected_never_falls_back_to_canned_data(self) -> None:
        adapter = PostgresAdapter(config=config(port=1))  # execute() auto-connects; this cannot
        with pytest.raises(ConnectionError):
            asyncio.run(adapter.execute("query", {"sql": "SELECT 1"}))


# ───────────────────────────── credentials never leak ─────────────────────────────


class TestCredentialsNeverLeak:
    @pytest.fixture
    def role(self, scram_pg):
        scram_pg.run(
            "DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='pgf_app') THEN DROP ROLE pgf_app; END IF; END $$",
            f"CREATE ROLE pgf_app LOGIN PASSWORD '{SECRET}'")
        yield scram_pg
        scram_pg.run("DROP ROLE IF EXISTS pgf_app")

    def _cfg(self, cluster, password: str) -> dict:
        return {"host": cluster.host, "port": cluster.port, "user": "pgf_app", "password": password,
                "database": cluster.database, "ssl_mode": "disable"}

    def test_the_right_password_connects(self, role) -> None:
        async def body(adapter):
            return await adapter.execute("query", {"sql": "SELECT current_user AS u"})

        assert asyncio.run(with_adapter(self._cfg(role, SECRET), body)).data == [{"u": "pgf_app"}]

    def test_a_wrong_password_is_rejected_and_nothing_secret_is_in_any_message(self, role, capfd, caplog) -> None:
        caplog.set_level("DEBUG")
        wrong = SECRET + "-wrong"
        adapter = PostgresAdapter(config=self._cfg(role, wrong))
        outcome = asyncio.run(adapter.connect())
        assert outcome.success is False
        with pytest.raises(ConnectionError) as exc:
            asyncio.run(adapter.execute("query", {"sql": "SELECT 1"}))
        validation = asyncio.run(adapter.validate_credentials())
        assert validation.success is False
        surfaces = [outcome.error, str(exc.value), validation.error or "", repr(adapter.get_stats()),
                    repr(adapter.get_metadata()), repr(adapter._get_config_schema())]
        out = capfd.readouterr()
        surfaces += [out.out, out.err, caplog.text]
        for text in surfaces:
            assert wrong not in text and SECRET not in text
            assert role.host not in (outcome.error + str(exc.value) + (validation.error or ""))
        assert "InvalidPassword" in outcome.error or "password" in outcome.error.lower()

    def test_a_query_error_never_contains_the_password(self, role, capfd, caplog) -> None:
        caplog.set_level("DEBUG")

        async def body(adapter):
            return await adapter.execute("query", {"sql": "SELECT * FROM table_that_is_not_there"})

        r = asyncio.run(with_adapter(self._cfg(role, SECRET), body))
        assert r.success is False and "table_that_is_not_there" in r.error
        out = capfd.readouterr()
        assert SECRET not in r.error + out.out + out.err + caplog.text
