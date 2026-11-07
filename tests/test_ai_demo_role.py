"""The seeded /ai demo role must be plain and read-only; if it is not, say so loudly (red-team 2, H1b).

Real roles on the real Postgres (no mocks): a superuser, a ``pg_read_server_files`` member and a plain
role are created for the test and dropped afterwards. Skips honestly without a server or without the
right to create roles.
"""

from __future__ import annotations

import asyncio
import os
import secrets

import asyncpg
import pytest
from fastapi.testclient import TestClient

PG_HOST = os.environ.get("NEURALBRIDGE_AI_PG_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("NEURALBRIDGE_AI_PG_PORT", "5432"))
PG_USER = os.environ.get("NEURALBRIDGE_AI_PG_USER", "neuralbridge")
PG_PASSWORD = os.environ.get("NEURALBRIDGE_AI_PG_PASSWORD", "neuralbridge_dev")
PG_DATABASE = os.environ.get("NEURALBRIDGE_AI_PG_TEST_DATABASE", "neuralbridge_ai_test")


async def _admin() -> asyncpg.Connection:
    return await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD,
                                 database=PG_DATABASE, timeout=3)


def _can_create_roles() -> bool:
    async def _check() -> bool:
        try:
            conn = await _admin()
        except Exception:
            return False
        try:
            return bool(await conn.fetchval(
                "SELECT rolsuper OR rolcreaterole FROM pg_roles WHERE rolname = current_user"))
        finally:
            await conn.close()

    return asyncio.run(_check())


pytestmark = pytest.mark.skipif(
    not _can_create_roles(),
    reason=f"no reachable PostgreSQL at {PG_HOST}:{PG_PORT}/{PG_DATABASE} whose user may create roles",
)

_PASSWORD = "role-test-" + secrets.token_hex(8)


@pytest.fixture
def roles():
    """name -> kind: a plain role, a superuser, a file-reader member."""
    suffix = secrets.token_hex(4)
    names = {"plain": f"nb_rt_plain_{suffix}", "super": f"nb_rt_super_{suffix}", "files": f"nb_rt_files_{suffix}"}

    async def _setup() -> None:
        c = await _admin()
        try:
            for kind, extra in (("plain", "NOSUPERUSER"), ("super", "SUPERUSER"), ("files", "NOSUPERUSER")):
                await c.execute(f"CREATE ROLE {names[kind]} LOGIN {extra} PASSWORD '{_PASSWORD}'")
            await c.execute(f"GRANT pg_read_server_files TO {names['files']}")
            await c.execute(f"GRANT CONNECT ON DATABASE {PG_DATABASE} TO {names['plain']}, {names['files']}")
        finally:
            await c.close()

    async def _teardown() -> None:
        c = await _admin()
        try:
            await c.execute(f"REVOKE ALL ON DATABASE {PG_DATABASE} FROM {names['plain']}, {names['files']}")
            for n in names.values():
                await c.execute(f"DROP ROLE IF EXISTS {n}")
        finally:
            await c.close()

    asyncio.run(_setup())
    yield names
    asyncio.run(_teardown())


def _config(user: str) -> dict:
    return {"host": PG_HOST, "port": PG_PORT, "user": user, "password": _PASSWORD,
            "database": PG_DATABASE, "ssl_mode": "prefer"}


def test_plain_role_is_not_flagged(roles) -> None:
    from neuralbridge.ai.connections import inspect_role_privileges

    result = asyncio.run(inspect_role_privileges(_config(roles["plain"])))
    assert result == {"checked": True, "privileged": False, "reasons": []}


def test_superuser_and_file_reader_are_flagged(roles) -> None:
    from neuralbridge.ai.connections import inspect_role_privileges

    sup = asyncio.run(inspect_role_privileges(_config(roles["super"])))
    assert sup["checked"] and sup["privileged"] and "superuser" in sup["reasons"]
    files = asyncio.run(inspect_role_privileges(_config(roles["files"])))
    assert files["checked"] and files["privileged"] and files["reasons"] == ["pg_read_server_files"]


def test_unreachable_target_is_unchecked_not_clean() -> None:
    from neuralbridge.ai.connections import inspect_role_privileges

    cfg = _config("nobody") | {"port": 1}
    result = asyncio.run(inspect_role_privileges(cfg))
    assert result["checked"] is False and result["privileged"] is None
    assert _PASSWORD not in str(result)


def _ready(monkeypatch: pytest.MonkeyPatch, tmp_path, user: str) -> dict:
    import neuralbridge.ai.connections as conns
    import neuralbridge.api.dependencies as deps

    monkeypatch.setenv("NEURALBRIDGE_AI_PG_HOST", PG_HOST)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_PORT", str(PG_PORT))
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_USER", user)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_PASSWORD", _PASSWORD)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_DATABASE", PG_DATABASE)
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "ai.db"))
    monkeypatch.setenv("NEURALBRIDGE_AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.setitem(conns._role_state, "value", None)
    deps._adapter_registry = None
    deps._request_router = None
    deps._audit_logger = None
    deps._ai_store = None
    from neuralbridge.main import create_app

    with TestClient(create_app()) as client:
        r = client.get("/api/v1/health/ready")
    assert r.status_code == 200, r.text  # a warning never takes the instance out of rotation
    return r.json()


def test_ready_warns_for_a_privileged_demo_role_and_not_for_a_plain_one(roles, monkeypatch, tmp_path) -> None:
    body = _ready(monkeypatch, tmp_path, roles["super"])
    assert body["ai_demo_role"]["privileged"] is True
    assert body["warnings"] and "ai_demo_role_privileged" in body["warnings"][0]

    body = _ready(monkeypatch, tmp_path, roles["plain"])
    assert body["ai_demo_role"]["privileged"] is False
    assert "warnings" not in body
    assert _PASSWORD not in str(body)


def test_startup_logs_the_privileged_role(roles, monkeypatch, tmp_path, capsys) -> None:
    _ready(monkeypatch, tmp_path, roles["super"])
    out = capsys.readouterr().out
    line = next(ln for ln in out.splitlines() if "ai_demo_role_privileged" in ln)
    assert "superuser" in line and "warning" in line
    assert _PASSWORD not in out
