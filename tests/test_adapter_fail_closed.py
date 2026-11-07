"""Adapters must not answer from canned data that looks like a real result.

Found by reading the code (not the README): MySQL swallowed a failed connection, reported "connected" and then
returned invented rows; MongoDB swallowed every connection error and a missing connection string the same way;
Slack returned ``{"ok": True, "ts": ...}`` and Salesforce invented "Acme" records without any call being made.
Nothing marked the data as canned. Policy now (neuralbridge/adapters/base.py): an adapter's ``backend`` is
"real", "partial" or "mock" (default "mock", so an unclassified adapter is untrusted), ``execute`` refuses a
"mock" adapter unless the caller opted in, and a failed connection raises instead of falling back.

The MySQL / MongoDB / BigQuery SDKs are not installed in CI (requirements/test.txt), so those adapters cannot
be imported there and have never been exercised. The tests below stub the SDK modules to test *our* policy
(failure raises; opt-in works), not the SDK. They prove nothing about a live MySQL, MongoDB or BigQuery.
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import sys
import types
from pathlib import Path

import pytest

from neuralbridge.adapters.base import (
    ALLOW_MOCK_ENV,
    BACKENDS,
    AdapterResponse,
    BaseAdapter,
    MockBackendRefusedError,
)

ADAPTERS = Path(__file__).resolve().parents[1] / "src" / "neuralbridge" / "adapters"


def _inventory() -> dict[str, tuple[str, str]]:
    """adapter_type -> (backend, file), from source, so it works without any adapter SDK installed."""
    found: dict[str, tuple[str, str]] = {}
    for path in sorted(ADAPTERS.rglob("*.py")):
        if path.name in ("__init__.py", "base.py"):
            continue
        for cls in (n for n in ast.parse(path.read_text(encoding="utf-8")).body if isinstance(n, ast.ClassDef)):
            if not any(getattr(b, "id", None) == "BaseAdapter" for b in cls.bases):
                continue
            attrs: dict[str, object] = {}
            for node in cls.body:
                if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                    name, value = node.target.id, node.value
                elif isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
                    name, value = node.targets[0].id, node.value
                else:
                    continue
                if isinstance(value, ast.Constant):
                    attrs[name] = value.value
            found[str(attrs["adapter_type"])] = (str(attrs.get("backend", "mock")), str(path.relative_to(ADAPTERS)))
    return found


# Promoting an adapter is an edit to this table, in review, with the evidence that justifies it.
EXPECTED_REAL = {
    "postgres",  # exercised against a real server by tests/test_ai.py (fails, not skips, in CI)
    "rest",  # exercised on the wire against a local HTTP server by tests/test_rest_adapter.py
}
EXPECTED_PARTIAL = {"mysql", "mongodb", "bigquery"}  # real client path; never run against a live service


def test_every_adapter_is_classified_and_only_postgres_and_rest_are_real():
    inv = _inventory()
    assert len(inv) == 22, sorted(inv)  # a new adapter must be added deliberately, and classified
    assert {b for b, _ in inv.values()} <= set(BACKENDS)
    assert {t for t, (b, _) in inv.items() if b == "real"} == EXPECTED_REAL
    assert {t for t, (b, _) in inv.items() if b == "partial"} == EXPECTED_PARTIAL


def test_an_unclassified_adapter_is_treated_as_canned():
    assert BaseAdapter.backend == "mock"


class _Canned(BaseAdapter):
    adapter_type = "canned_test"
    supported_operations = ["read"]

    async def _do_connect(self) -> None: ...
    async def _do_disconnect(self) -> None: ...
    async def _do_validate_credentials(self) -> dict:
        return {}

    async def _do_execute(self, operation, params):
        return {"rows": [{"id": 1, "name": "invented"}]}


def _run(coro):
    return asyncio.run(coro)


def test_a_canned_adapter_is_refused_by_default(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    with pytest.raises(MockBackendRefusedError, match="canned data"):
        _run(_Canned({}).execute("read"))


def test_opting_in_by_config_or_env_runs_it_and_flags_the_result(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    assert _run(_Canned({"allow_mock": True}).execute("read"))["mock"] is True
    monkeypatch.setenv(ALLOW_MOCK_ENV, "1")
    assert _run(_Canned({}).execute("read"))["mock"] is True


@pytest.mark.parametrize("value", ["true", "yes", 1, "True", None])
def test_only_an_exact_opt_in_counts(monkeypatch, value):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    with pytest.raises(MockBackendRefusedError):
        _run(_Canned({"allow_mock": value}).execute("read"))


def test_a_canned_adapter_in_the_registry_inventory_is_refused_by_default(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    from neuralbridge.adapters.messaging.slack import SlackAdapter

    with pytest.raises(MockBackendRefusedError):
        _run(SlackAdapter({"bot_token": "xoxb-test"}).execute("send_message", {"channel": "#g", "text": "t"}))


def test_postgres_refuses_canned_data_when_it_is_not_connected(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    from neuralbridge.adapters.databases.postgres import PostgresAdapter

    adapter = PostgresAdapter({})
    with pytest.raises(MockBackendRefusedError):
        _run(adapter._do_execute("query", {"sql": "SELECT 1"}))  # pool is None: used to return "Mock User"
    assert _run(PostgresAdapter({"allow_mock": True})._do_execute("query", {"sql": "SELECT 1"})).metadata["mock"]


# ── partial adapters, with the SDK modules stubbed (see the module docstring) ─────────────────────────────────


def _stub(monkeypatch, modules: dict[str, types.ModuleType], target: str):
    for name, mod in modules.items():
        monkeypatch.setitem(sys.modules, name, mod)
    monkeypatch.delitem(sys.modules, target, raising=False)
    try:
        return importlib.import_module(target)
    finally:
        # the next import of the target must see the real (or absent) SDK, not these stubs
        sys.modules.pop(target, None)


def _mod(name: str, **attrs) -> types.ModuleType:
    m = types.ModuleType(name)
    m.__dict__.update(attrs)
    return m


def _mysql(monkeypatch):
    async def create_pool(**_kw):
        raise ConnectionRefusedError("refused")

    err = types.SimpleNamespace(OperationalError=type("OperationalError", (Exception,), {}))
    return _stub(
        monkeypatch,
        {"aiomysql": _mod("aiomysql", create_pool=create_pool, Pool=object), "pymysql": _mod("pymysql", err=err)},
        "neuralbridge.adapters.databases.mysql",
    )


def test_mysql_connection_failure_raises_instead_of_serving_invented_rows(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    mysql = _mysql(monkeypatch)
    with pytest.raises(ConnectionError, match="MySQL connection failed"):
        _run(mysql.MySQLAdapter({"host": "db.invalid"}).execute("query", {"sql": "SELECT 1"}))


def test_mysql_serves_canned_rows_only_when_opted_in(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    mysql = _mysql(monkeypatch)
    result = _run(mysql.MySQLAdapter({"host": "db.invalid", "allow_mock": True}).execute("query", {"sql": "SELECT 1"}))
    assert isinstance(result, AdapterResponse) and result.success


def _mongo(monkeypatch):
    class Client:
        def __init__(self, *_a, **_k):
            self.admin = types.SimpleNamespace(command=self._fail)

        @staticmethod
        async def _fail(*_a, **_k):
            raise ConnectionRefusedError("refused")

    motor = _mod("motor")
    motor_asyncio = _mod("motor.motor_asyncio", AsyncIOMotorClient=Client, AsyncIOMotorDatabase=object)
    motor.motor_asyncio = motor_asyncio
    return _stub(
        monkeypatch,
        {"motor": motor, "motor.motor_asyncio": motor_asyncio, "bson": _mod("bson", ObjectId=str)},
        "neuralbridge.adapters.databases.mongodb",
    )


@pytest.mark.parametrize("config", [{"database": "d"}, {"connection_string": "mongodb://db.invalid", "database": "d"}])
def test_mongodb_connection_failure_or_missing_string_raises(monkeypatch, config):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    mongo = _mongo(monkeypatch)
    with pytest.raises(ConnectionError, match="MongoDB"):
        _run(mongo.MongodbAdapter(config).execute("find", {"collection": "c"}))


def _bigquery(monkeypatch):
    class Client:
        def __init__(self, *_a, **_k):
            raise RuntimeError("no credentials")

    cloud = _mod("google.cloud", bigquery=_mod("google.cloud.bigquery", Client=Client))
    exceptions = _mod("google.api_core.exceptions", GoogleAPICallError=type("GoogleAPICallError", (Exception,), {}))
    api_core = _mod("google.api_core", exceptions=exceptions)
    google = _mod("google", cloud=cloud, api_core=api_core)
    return _stub(
        monkeypatch,
        {
            "google": google,
            "google.cloud": cloud,
            "google.cloud.bigquery": cloud.bigquery,
            "google.api_core": api_core,
            "google.api_core.exceptions": exceptions,
        },
        "neuralbridge.adapters.databases.bigquery",
    )


def test_bigquery_connection_failure_raises_and_a_missing_client_is_refused(monkeypatch):
    monkeypatch.delenv(ALLOW_MOCK_ENV, raising=False)
    bq = _bigquery(monkeypatch)
    with pytest.raises(ConnectionError, match="BigQuery"):
        _run(bq.BigQueryAdapter({"project_id": "p"}).execute("query", {"query": "SELECT 1"}))
    adapter = bq.BigQueryAdapter({"project_id": "p"})
    with pytest.raises(MockBackendRefusedError):
        _run(adapter._do_execute("query", {"query": "SELECT 1"}))  # client is None: used to return a mock result
