"""The platform audit trail is durable by default, append-only, safe for concurrent writers,
free of secrets, and loud when its sink breaks.

Everything here uses the real storage classes (a real SQLite file; a real PostgreSQL for the
selectable backend). Process-restart and multi-process tests start real Python subprocesses.
"""

# ruff: noqa: S603, F811, F401  (subprocess runs this package's own interpreter; fixtures are imported by name)
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from neuralbridge.security.audit import (
    AuditLogger,
    AuditUnavailableError,
    InMemoryAuditStorage,
    PostgresAuditStorage,
    SQLiteAuditStorage,
    build_audit_logger,
    default_audit_path,
    redact,
    redact_text,
)

from .platform_support import (  # noqa: F401  (fixtures)
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
    postgres_reachable,
    read,
    reset_singletons,
)

REPO_SRC = str(Path(__file__).resolve().parents[1] / "src")


def run_py(code: str, *args: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run ``code`` in a fresh interpreter (a real process boundary)."""
    env_ = {**os.environ, "PYTHONPATH": REPO_SRC, **(env_extra or {})}
    return subprocess.run(
        [sys.executable, "-c", code, *args], env=env_, capture_output=True, text=True, timeout=120, check=False
    )


WRITER = """
import asyncio, sys
from neuralbridge.security.audit import AuditLogger, SQLiteAuditStorage
path, tag, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
async def main():
    log = AuditLogger(SQLiteAuditStorage(path))
    for i in range(n):
        await log.log_event("t", f"actor-{tag}", "res", "act", "success", details={"owner": tag, "i": i})
asyncio.run(main())
"""


async def _all(logger: AuditLogger, **kw):
    return [e async for e in logger.query_events(**kw)]


# ───────────────────────────── configuration ─────────────────────────────


class TestConfiguration:
    def test_default_is_a_durable_sqlite_file_next_to_the_ai_store(self, monkeypatch, tmp_path) -> None:
        monkeypatch.delenv("NEURALBRIDGE_AUDIT_DB", raising=False)
        monkeypatch.delenv("NEURALBRIDGE_AUDIT_BACKEND", raising=False)
        monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "state" / "ai.db"))
        assert default_audit_path() == tmp_path / "state" / "neuralbridge-audit.db"
        logger = build_audit_logger()
        assert isinstance(logger.storage, SQLiteAuditStorage)
        assert logger.storage.durable is True
        assert (tmp_path / "state" / "neuralbridge-audit.db").exists()

    def test_explicit_path_wins(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "x" / "my-audit.db"))
        assert default_audit_path() == tmp_path / "x" / "my-audit.db"

    def test_memory_is_opt_in_only_and_says_it_is_not_durable(self, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_BACKEND", "memory")
        logger = build_audit_logger()
        assert isinstance(logger.storage, InMemoryAuditStorage)
        assert logger.health()["durable"] is False

    def test_unknown_backend_and_missing_pg_dsn_fail_loudly(self, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_BACKEND", "carrier-pigeon")
        with pytest.raises(AuditUnavailableError):
            build_audit_logger()
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_BACKEND", "postgres")
        monkeypatch.delenv("NEURALBRIDGE_AUDIT_PG_DSN", raising=False)
        with pytest.raises(AuditUnavailableError):
            build_audit_logger()

    def test_the_app_default_singleton_is_the_sqlite_sink(self, monkeypatch, tmp_path) -> None:
        monkeypatch.delenv("NEURALBRIDGE_AUDIT_BACKEND", raising=False)
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "a.db"))
        reset_singletons()
        from neuralbridge.api.dependencies import get_audit_logger

        assert isinstance(get_audit_logger().storage, SQLiteAuditStorage)
        reset_singletons()


# ───────────────────────────── durability ─────────────────────────────


class TestSurvivesRestart:
    def test_records_and_the_chain_survive_a_process_restart(self, tmp_path) -> None:
        db = str(tmp_path / "audit.db")
        first = run_py(WRITER, db, "one", "3")
        assert first.returncode == 0, first.stderr
        # a *different* process reopens the file and keeps extending the same chain
        second = run_py(WRITER, db, "two", "2")
        assert second.returncode == 0, second.stderr

        logger = AuditLogger(SQLiteAuditStorage(db))
        events = asyncio.run(_all(logger))
        assert [e.actor for e in events] == ["actor-one"] * 3 + ["actor-two"] * 2
        assert asyncio.run(logger.verify_integrity()) is True
        assert events[3].previous_hash == events[2].current_hash

    def test_http_audit_survives_an_app_restart(self, env, keys: Keys) -> None:
        from neuralbridge.main import create_app

        reset_singletons()
        with TestClient(create_app()) as c1:
            conn = bind(c1, keys.a, "restart-conn")
            before = audit_events(c1, keys.a)
        assert any(e["event_type"] == "connection_create" for e in before)

        reset_singletons()  # a brand-new process-equivalent: nothing in memory
        with TestClient(create_app()) as c2:
            after = audit_events(c2, keys.a)
            logs = c2.get("/api/v1/logs", headers=h(keys.a)).json()
        reset_singletons()
        assert {e["event_id"] for e in before} <= {e["event_id"] for e in after}
        assert any(conn["id"] in json.dumps(e) for e in logs["events"])

    def test_timestamps_round_trip_so_the_hash_still_verifies(self, tmp_path) -> None:
        logger = AuditLogger(SQLiteAuditStorage(tmp_path / "a.db"))
        written = asyncio.run(logger.log_event("t", "a", "r", "x", "success", details={"n": 1.5, "u": "é"}))
        (read_back,) = asyncio.run(_all(AuditLogger(SQLiteAuditStorage(tmp_path / "a.db"))))
        assert read_back.timestamp == written.timestamp
        assert read_back.calculate_hash() == read_back.current_hash == written.current_hash


class TestConcurrentWriters:
    def test_processes_and_coroutines_extend_one_linear_chain(self, tmp_path) -> None:
        db = str(tmp_path / "audit.db")
        SQLiteAuditStorage(db)  # schema once, as a deployment would
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", WRITER, db, f"p{i}", "25"],
                env={**os.environ, "PYTHONPATH": REPO_SRC}, stderr=subprocess.PIPE, text=True,
            )
            for i in range(4)
        ]

        async def in_process() -> None:
            log = AuditLogger(SQLiteAuditStorage(db))
            await asyncio.gather(*(
                log.log_event("t", "actor-local", "res", "act", "success", details={"owner": "local", "i": i})
                for i in range(30)
            ))

        asyncio.run(in_process())
        for p in procs:
            _, err = p.communicate(timeout=120)
            assert p.returncode == 0, err

        logger = AuditLogger(SQLiteAuditStorage(db))
        events = asyncio.run(_all(logger))
        assert len(events) == 4 * 25 + 30
        assert len({e.previous_hash for e in events}) == len(events), "two writers extended the same head"
        assert asyncio.run(logger.verify_integrity()) is True
        by_actor = {a: sum(e.actor == a for e in events) for a in {e.actor for e in events}}
        assert by_actor == {"actor-p0": 25, "actor-p1": 25, "actor-p2": 25, "actor-p3": 25, "actor-local": 30}


# ───────────────────────────── append-only ─────────────────────────────


class TestAppendOnly:
    def _seed(self, tmp_path) -> tuple[AuditLogger, str]:
        db = str(tmp_path / "audit.db")
        logger = AuditLogger(SQLiteAuditStorage(db))
        for i in range(3):
            asyncio.run(logger.log_event("t", "a", "r", "x", "success", details={"i": i}))
        return logger, db

    def test_update_and_delete_are_refused_by_the_database(self, tmp_path) -> None:
        _, db = self._seed(tmp_path)
        raw = sqlite3.connect(db)
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            raw.execute("UPDATE audit_log SET actor='mallory'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            raw.execute("DELETE FROM audit_log")
        raw.close()

    def test_an_edit_made_around_the_triggers_is_caught_by_the_hash_chain(self, tmp_path) -> None:
        logger, db = self._seed(tmp_path)
        raw = sqlite3.connect(db, isolation_level=None)
        raw.execute("DROP TRIGGER audit_log_no_update")
        row = raw.execute("SELECT seq, entry_json FROM audit_log WHERE seq=2").fetchone()
        tampered = json.loads(row[1])
        tampered["actor"] = "mallory"
        raw.execute("UPDATE audit_log SET entry_json=? WHERE seq=2", (json.dumps(tampered),))
        raw.close()
        assert asyncio.run(logger.verify_integrity()) is False


# ───────────────────────────── queries ─────────────────────────────


class TestQueries:
    def test_owner_pushdown_limit_and_newest_first(self, tmp_path) -> None:
        logger = AuditLogger(SQLiteAuditStorage(tmp_path / "a.db"))
        for i in range(6):
            asyncio.run(logger.log_event("t", "a", "r", "x", "success", details={"owner": "o1" if i % 2 else "o2", "i": i}))
        mine = asyncio.run(_all(logger, owner="o1"))
        assert [e.details["i"] for e in mine] == [1, 3, 5]
        newest = asyncio.run(_all(logger, owner="o1", limit=2, newest_first=True))
        assert [e.details["i"] for e in newest] == [5, 3]
        assert [e.details["i"] for e in asyncio.run(_all(logger, limit=2))] == [0, 1]
        assert asyncio.run(_all(logger, owner="nobody")) == []

    def test_pages_past_the_page_size(self, tmp_path) -> None:
        logger = AuditLogger(SQLiteAuditStorage(tmp_path / "a.db"))

        async def go() -> int:
            await asyncio.gather(*(logger.log_event("t", "a", "r", "x", "success") for _ in range(1100)))
            return len(await _all(logger))

        assert asyncio.run(go()) == 1100
        assert asyncio.run(logger.verify_integrity()) is True


# ───────────────────────────── no secrets ─────────────────────────────


SECRETS = [
    "hunter2-very-secret-pw",
    "sk_live_abcdef1234567890",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fw",
    "Bearer abcdefghijklmnop123456",
]


class TestNoSecretsInRecords:
    def test_redact_masks_keys_and_credential_shaped_text(self) -> None:
        out = redact({
            "password": "hunter2-very-secret-pw",
            "nested": {"api_key": "sk_live_abcdef1234567890", "ok": "fine"},
            "err": "connection to postgresql://bob:hunter2-very-secret-pw@db:5432/x failed",
            "hdr": "Authorization: Bearer abcdefghijklmnop123456",
            "msg": "password=hunter2-very-secret-pw tried",
            "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fw",
        })
        blob = json.dumps(out)
        for secret in SECRETS:
            assert secret not in blob, secret
        assert out["nested"]["ok"] == "fine"
        assert "postgresql://bob:" in out["err"]  # the user stays, the password does not

    def test_nothing_secret_reaches_the_file_even_when_passed_in(self, tmp_path) -> None:
        db = tmp_path / "a.db"
        logger = AuditLogger(SQLiteAuditStorage(db))
        asyncio.run(logger.log_event(
            "adapter_error", "human_session:x", "postgres:1", "query", "error",
            details={"error": "FATAL password authentication failed; password=hunter2-very-secret-pw",
                     "password": "hunter2-very-secret-pw", "token": "sk_live_abcdef1234567890"},
        ))
        raw = b"".join(p.read_bytes() for p in tmp_path.glob("a.db*"))
        for secret in SECRETS:
            assert secret.encode() not in raw
        assert asyncio.run(logger.verify_integrity()) is True

    def test_redact_text_caps_runaway_strings(self) -> None:
        assert len(redact_text("x" * 100_000)) < 5000


# ───────────────────────────── fail loudly ─────────────────────────────


class _Probe:
    """Replace the audit file by a directory: every open now fails (works as root, unlike chmod)."""

    def __init__(self, db: Path) -> None:
        self.db = db
        self.parked = db.parent / "parked"

    def break_it(self) -> None:
        self.parked.mkdir()
        for p in self.db.parent.glob(self.db.name + "*"):
            shutil.move(str(p), str(self.parked / p.name))
        self.db.mkdir()

    def fix_it(self) -> None:
        self.db.rmdir()
        for p in self.parked.iterdir():
            shutil.move(str(p), str(self.db.parent / p.name))


class FakeAdapter:
    """Counts executions; stands in for any real adapter in the registry."""

    def __init__(self) -> None:
        from neuralbridge.adapters.base import AdapterStatus

        self.calls = 0
        self.status = AdapterStatus.CONNECTED
        self.adapter_type = "probe"
        self.supported_operations = ["ping"]

    async def execute(self, operation, params):
        self.calls += 1
        return {"pong": True}


class TestFailsLoudly:
    def test_unwritable_sink_is_reported_not_swallowed(self, tmp_path) -> None:
        db = tmp_path / "audit.db"
        logger = AuditLogger(SQLiteAuditStorage(db))
        asyncio.run(logger.ensure_writable())
        assert logger.health()["status"] == "ok"
        probe = _Probe(db)
        probe.break_it()
        with pytest.raises(AuditUnavailableError):
            asyncio.run(logger.log_event("t", "a", "r", "x", "success"))
        assert logger.health()["status"] == "degraded"
        assert logger.health()["last_error"]
        with pytest.raises(AuditUnavailableError):
            asyncio.run(logger.ensure_writable())
        probe.fix_it()
        asyncio.run(logger.ensure_writable())
        assert logger.health()["status"] == "ok"
        assert len(asyncio.run(_all(logger))) == 0

    def test_startup_refuses_when_the_sink_cannot_be_opened(self, monkeypatch, tmp_path) -> None:
        blocker = tmp_path / "file-not-dir"
        blocker.write_text("x")
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(blocker / "audit.db"))
        reset_singletons()
        from neuralbridge.main import create_app

        with pytest.raises(AuditUnavailableError), TestClient(create_app()):
            pass
        reset_singletons()

    def test_readiness_goes_503_and_calls_are_refused_without_running(self, client: TestClient, env, keys: Keys) -> None:
        from neuralbridge.api.dependencies import get_adapter_registry

        ok = client.get("/api/v1/health/ready")
        assert ok.status_code == 200
        assert ok.json()["checks"]["audit"] == "ok" and ok.json()["audit_durable"] is True
        assert ok.json()["audit_backend"] == "sqlite"

        adapter = FakeAdapter()
        get_adapter_registry().register(adapter, key="probe")  # type: ignore[arg-type]
        run = client.post("/api/v1/adapters/probe/execute", headers=h(OPERATOR_KEY), json={"operation": "ping", "params": {}})
        assert run.status_code == 200 and adapter.calls == 1

        probe = _Probe(Path(os.environ["NEURALBRIDGE_AUDIT_DB"]))
        probe.break_it()
        try:
            bad = client.get("/api/v1/health/ready")
            assert bad.status_code == 503
            assert bad.json()["status"] == "degraded" and bad.json()["checks"]["audit"] == "unwritable"
            assert str(probe.db) not in bad.text  # nothing about the sink's location
            assert client.get("/api/v1/health/live").status_code == 200

            refused = client.post(
                "/api/v1/adapters/probe/execute", headers=h(OPERATOR_KEY), json={"operation": "ping", "params": {}}
            )
            assert refused.status_code == 503
            assert refused.json()["detail"]["error"] == "audit_unavailable"
            assert refused.headers["retry-after"]
            assert adapter.calls == 1, "the adapter ran although the call could not be recorded"

            bind_refused = client.post(f"{API}/connections", headers=h(keys.a), json={
                "name": "n", "host": PG_HOST, "port": PG_PORT, "user": PG_USER, "password": PG_PASSWORD,
                "database": PG_DATABASE})
            assert bind_refused.status_code == 503
        finally:
            probe.fix_it()
        assert client.get("/api/v1/health/ready").status_code == 200




# ───────────────────────────── PostgreSQL backend ─────────────────────────────


pg = pytest.mark.skipif(not postgres_reachable(), reason="No reachable PostgreSQL for the postgres audit backend")


@pg
class TestPostgresBackend:
    DSN = f"postgresql://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{PG_DATABASE}"

    @pytest.fixture(autouse=True)
    def _clean(self):
        from .platform_support import pg_run

        pg_run("DROP TABLE IF EXISTS nb_audit_log CASCADE")
        yield
        pg_run("DROP TABLE IF EXISTS nb_audit_log CASCADE")

    def test_selectable_durable_chained_and_append_only(self) -> None:
        async def go() -> None:
            a = AuditLogger(PostgresAuditStorage(dsn=self.DSN))
            await asyncio.gather(*(
                a.log_event("t", f"a{i % 3}", "r", "x", "success", details={"owner": "o1", "i": i}) for i in range(40)
            ))
            # a second logger (another "process") sees and extends the same chain
            b = AuditLogger(PostgresAuditStorage(dsn=self.DSN))
            await b.log_event("t", "b", "r", "x", "success", details={"owner": "o2"})
            events = await _all(b)
            assert len(events) == 41
            assert len({e.previous_hash for e in events}) == 41
            assert await b.verify_integrity() is True
            assert len(await _all(b, owner="o2")) == 1
            assert [e.actor for e in await _all(b, limit=1, newest_first=True)] == ["b"]
            await b.ensure_writable()
            import asyncpg

            conn = await asyncpg.connect(self.DSN)
            try:
                with pytest.raises(asyncpg.PostgresError, match="append-only"):
                    await conn.execute("UPDATE nb_audit_log SET actor='mallory'")
                with pytest.raises(asyncpg.PostgresError, match="append-only"):
                    await conn.execute("DELETE FROM nb_audit_log")
            finally:
                await conn.close()

        asyncio.run(go())

    def test_backend_env_selects_postgres(self, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_BACKEND", "postgres")
        monkeypatch.setenv("NEURALBRIDGE_AUDIT_PG_DSN", self.DSN)
        logger = build_audit_logger()
        assert isinstance(logger.storage, PostgresAuditStorage)
        assert asyncio.run(logger.log_event("t", "a", "r", "x", "success")).current_hash

    def test_unreachable_postgres_is_an_audit_unavailable_error_without_the_dsn(self) -> None:
        bad = AuditLogger(PostgresAuditStorage(dsn="postgresql://u:hunter2-very-secret-pw@127.0.0.1:1/x"))
        with pytest.raises(AuditUnavailableError) as exc:
            asyncio.run(bad.log_event("t", "a", "r", "x", "success"))
        assert "hunter2" not in str(exc.value) and "hunter2" not in json.dumps(bad.health())
