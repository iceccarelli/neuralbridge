"""Shared fixtures for the platform (``src/neuralbridge``) hardening tests.

Real accounts (minted through ``AccountStore``), one running app, one registry/store/audit
sink per test, and the real PostgreSQL the other /ai suites use. Import the fixtures into a
test module with ``from .platform_support import *  # noqa``.
"""

from __future__ import annotations

import asyncio
import os

import asyncpg
import pytest
from fastapi.testclient import TestClient

PG_HOST = os.environ.get("NEURALBRIDGE_AI_PG_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("NEURALBRIDGE_AI_PG_PORT", "5432"))
PG_USER = os.environ.get("NEURALBRIDGE_AI_PG_USER", "neuralbridge")
PG_PASSWORD = os.environ.get("NEURALBRIDGE_AI_PG_PASSWORD", "neuralbridge_dev")
PG_DATABASE = os.environ.get("NEURALBRIDGE_AI_PG_TEST_DATABASE", "neuralbridge_ai_test")
OPERATOR_KEY = "test-platform-operator-key-0123456789abcdef0123456789"
API = "/api/v1/ai"


def postgres_reachable() -> bool:
    async def _check() -> bool:
        try:
            conn = await asyncpg.connect(
                host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD,
                database=PG_DATABASE, timeout=3,
            )
            await conn.close()
            return True
        except Exception:
            return False

    return asyncio.run(_check())


requires_postgres = pytest.mark.skipif(
    not postgres_reachable(),
    reason=(
        f"No reachable PostgreSQL at {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DATABASE} — "
        "see docs/ai-local-setup.md. Real-DB-only tests, skipped honestly rather than faked."
    ),
)


def pg_run(*statements: str) -> None:
    """Run SQL against the test database (setup / teardown)."""

    async def _go() -> None:
        conn = await asyncpg.connect(
            host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE
        )
        try:
            for stmt in statements:
                await conn.execute(stmt)
        finally:
            await conn.close()

    asyncio.run(_go())


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path):
    accounts_path = tmp_path / "accounts.db"
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(accounts_path))
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "ai-store.db"))
    monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_HOST", PG_HOST)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_PORT", str(PG_PORT))
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_USER", PG_USER)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_PASSWORD", PG_PASSWORD)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_DATABASE", PG_DATABASE)

    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    return accounts_path


class Keys:
    def __init__(self, a: str, b: str, free: str) -> None:
        self.a = a
        self.b = b
        self.free = free


@pytest.fixture
def keys(env) -> Keys:
    """Two paid accounts (A, B) and one free (Validator) account, each with its own key."""
    from assurance.billing.accounts import AccountStore

    store = AccountStore(str(env))
    acct_a = store.upsert_account(email="a@example.com", tier="register", company="Account A")
    acct_b = store.upsert_account(email="b@example.com", tier="register", company="Account B")
    acct_f = store.upsert_account(email="f@example.com", tier="free", company="Free")
    return Keys(
        store.issue_key(acct_a.id, label="plat-a"),
        store.issue_key(acct_b.id, label="plat-b"),
        store.issue_key(acct_f.id, label="plat-free"),
    )


def reset_singletons() -> None:
    import neuralbridge.api.dependencies as deps

    deps._adapter_registry = None
    deps._request_router = None
    deps._audit_logger = None
    deps._ai_store = None


@pytest.fixture
def client(env):
    """ONE TestClient (one event loop, so asyncpg pools live on it)."""
    from neuralbridge.main import create_app

    reset_singletons()
    with TestClient(create_app()) as c:
        yield c
    reset_singletons()


def h(key: str | None = None, actor: str = "plat-actor") -> dict[str, str]:
    headers = {"X-NB-Actor": actor, "X-NB-Session": "plat-session"}
    if key:
        headers["X-API-Key"] = key
    return headers


def bind_body(name: str, **extra) -> dict:
    return {
        "name": name, "host": PG_HOST, "port": PG_PORT, "user": PG_USER,
        "password": PG_PASSWORD, "database": PG_DATABASE, **extra,
    }


def bind(client: TestClient, key: str, name: str, **extra) -> dict:
    r = client.post(f"{API}/connections", headers=h(key), json=bind_body(name, **extra))
    assert r.status_code == 200, r.text
    return r.json()


def read(client: TestClient, key: str | None, cid: str, operation: str = "health_check", sql: str = "SELECT 1"):
    params = {"sql": sql} if operation == "query" else {}
    return client.post(
        f"{API}/read", headers=h(key), json={"connection_id": cid, "operation": operation, "params": params}
    )


def audit_events(client: TestClient, key: str, **params) -> list[dict]:
    r = client.get(f"{API}/audit", headers=h(key), params={"limit": 500, **params})
    assert r.status_code == 200, r.text
    return r.json()


# ───────────── a private PostgreSQL cluster with real password (scram) authentication ─────────────
# The shared dev cluster on :5432 trusts every local connection, so a wrong password is accepted
# there and credential rejection cannot be tested against it. This starts a throwaway cluster
# (own data dir, random port, scram-sha-256, removed afterwards) from the installed server
# binaries — the same thing CI's service container gives (password auth) — and nothing else.


class ScramCluster:
    def __init__(self, host: str, port: int, superuser: str, password: str, database: str) -> None:
        self.host, self.port, self.superuser, self.password, self.database = host, port, superuser, password, database

    def run(self, *statements: str, database: str | None = None) -> None:
        async def _go() -> None:
            conn = await asyncpg.connect(
                host=self.host, port=self.port, user=self.superuser, password=self.password,
                database=database or self.database,
            )
            try:
                for stmt in statements:
                    await conn.execute(stmt)
            finally:
                await conn.close()

        asyncio.run(_go())


def _pg_bindir() -> str | None:
    import glob
    import shutil

    found = shutil.which("initdb")
    if found:
        return os.path.dirname(found)
    candidates = sorted(glob.glob("/usr/lib/postgresql/*/bin/initdb"), reverse=True)
    return os.path.dirname(candidates[0]) if candidates else None


@pytest.fixture(scope="session")
def scram_pg():
    import shutil
    import socket
    import subprocess
    import tempfile

    bindir = _pg_bindir()
    if bindir is None:
        pytest.skip("PostgreSQL server binaries (initdb) not installed: cannot start a password-auth cluster")
    base = tempfile.mkdtemp(prefix="nb-scram-pg-", dir="/tmp")
    os.chmod(base, 0o755)
    prefix: list[str] = []
    if os.geteuid() == 0:  # initdb refuses to run as root
        shutil.chown(base, "postgres", "postgres")
        prefix = ["runuser", "-u", "postgres", "--"]
    password = "scram-superuser-pw-48151"
    pwfile = os.path.join(base, "pw")
    with open(pwfile, "w") as fh:
        fh.write(password)
    os.chmod(pwfile, 0o644)
    data, sock_dir = os.path.join(base, "data"), os.path.join(base, "sock")
    os.mkdir(sock_dir)
    if prefix:
        shutil.chown(sock_dir, "postgres", "postgres")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    try:
        subprocess.run(  # noqa: S603
            [*prefix, f"{bindir}/initdb", "-D", data, "-U", "nbsuper", "--auth=scram-sha-256",
             f"--pwfile={pwfile}", "-E", "UTF8", "--no-sync"],
            check=True, capture_output=True, timeout=120)
        subprocess.run(  # noqa: S603
            [*prefix, f"{bindir}/pg_ctl", "-D", data, "-w", "-l", os.path.join(base, "log"),
             "-o", f"-p {port} -k {sock_dir} -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=60",
             "start"],
            check=True, capture_output=True, timeout=120)
        cluster = ScramCluster("127.0.0.1", port, "nbsuper", password, "postgres")
        cluster.run("CREATE DATABASE nbtest")
        cluster.database = "nbtest"
        yield cluster
    finally:
        subprocess.run(  # noqa: S603
            [*prefix, f"{bindir}/pg_ctl", "-D", data, "-m", "immediate", "stop"], capture_output=True, timeout=60,
            check=False)
        shutil.rmtree(base, ignore_errors=True)
