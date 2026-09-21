"""Golden tasks for Phase 3, part A: "one key, two paid surfaces."

Proves — against a real Postgres for the /ai control plane and the same
SQLite-backed ``AccountStore`` the assurance product's own paid routes
use — that a single Cell-tier API key, minted through the *real*
``AccountStore`` the way a paying customer's key is actually minted (not
a test-only shortcut), unlocks both:

* an assurance paid route (``POST /v1/cases/{case_id}/signal``, gated by
  ``assurance.api.deps.require_register``), and
* the ``/ai`` control plane's WRITE path (plan -> approve), gated by
  ``neuralbridge.ai.entitlements.require_ai_control_plane``,

in one test session, with the free/no-key case refused on both surfaces
first. Both gates import the exact same ``assurance.api.deps`` module —
see ``src/neuralbridge/ai/entitlements.py``'s own docstring for why: one
entitlement engine, not two that can drift.
"""

from __future__ import annotations

import asyncio
import importlib
import os

import asyncpg
import pytest
from fastapi.testclient import TestClient

PG_HOST = os.environ.get("NEURALBRIDGE_AI_PG_HOST", "127.0.0.1")
PG_PORT = int(os.environ.get("NEURALBRIDGE_AI_PG_PORT", "5432"))
PG_USER = os.environ.get("NEURALBRIDGE_AI_PG_USER", "neuralbridge")
PG_PASSWORD = os.environ.get("NEURALBRIDGE_AI_PG_PASSWORD", "neuralbridge_dev")
PG_DATABASE = os.environ.get("NEURALBRIDGE_AI_PG_TEST_DATABASE", "neuralbridge_ai_test")


def _postgres_reachable() -> bool:
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


pytestmark = pytest.mark.skipif(
    not _postgres_reachable(),
    reason=(
        "No reachable PostgreSQL at "
        f"{PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DATABASE} — see docs/ai-local-setup.md. "
        "Skipped honestly rather than faked; these golden tasks are real-DB-only."
    ),
)

OPERATOR_KEY = "test-buyer-journey-operator-key"


@pytest.fixture
def shared_entitlement_env(monkeypatch: pytest.MonkeyPatch, tmp_path):
    """One ASSURANCE_ACCOUNTS file, read by both apps under test — the
    same file a real deployment would share between the assurance service
    and the neuralbridge platform (see entitlements.py's docstring on why
    they are one entitlement engine, not two)."""
    accounts_path = tmp_path / "accounts.db"
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(accounts_path))
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.setenv("NEURALBRIDGE_AI_STORE", str(tmp_path / "ai-store.db"))
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_HOST", PG_HOST)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_PORT", str(PG_PORT))
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_USER", PG_USER)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_PASSWORD", PG_PASSWORD)
    monkeypatch.setenv("NEURALBRIDGE_AI_PG_DATABASE", PG_DATABASE)

    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    return accounts_path


@pytest.fixture
def seeded_table():
    async def _setup() -> None:
        conn = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
        await conn.execute("DROP TABLE IF EXISTS ai_test_customers")
        await conn.execute("CREATE TABLE ai_test_customers (id serial primary key, name text, plan text)")
        await conn.execute("INSERT INTO ai_test_customers (name, plan) VALUES ('Acme Robotics', 'cell')")
        await conn.close()

    async def _teardown() -> None:
        conn = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
        await conn.execute("DROP TABLE IF EXISTS ai_test_customers")
        await conn.close()

    asyncio.run(_setup())
    yield
    asyncio.run(_teardown())


@pytest.fixture
def cell_key(shared_entitlement_env) -> str:
    """Mint a real Cell-tier API key the same way a paying customer's is
    minted — through ``AccountStore``, not a hand-typed fixture key."""
    from assurance.billing.accounts import AccountStore

    store = AccountStore(str(shared_entitlement_env))
    account = store.upsert_account(email="buyer@example.com", tier="cell", company="Acme Robotics")
    return store.issue_key(account.id, label="buyer-journey-test")


@pytest.fixture
def assurance_client(shared_entitlement_env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


@pytest.fixture
def ai_app_client_factory(shared_entitlement_env, seeded_table):
    """Build a fresh /ai TestClient with a given set of headers, resetting
    the platform's module-level singletons first — same pattern
    ``tests/test_ai.py`` uses so two independently-instantiated clients in
    one test still share one AdapterRegistry/AiStore."""
    import neuralbridge.api.dependencies as deps
    from neuralbridge.main import create_app

    def _build(headers: dict[str, str]) -> TestClient:
        deps._adapter_registry = None
        deps._request_router = None
        deps._audit_logger = None
        deps._ai_store = None
        return TestClient(create_app(), headers=headers)

    return _build


def _get_connection_id(client: TestClient) -> str:
    conns = client.get("/api/v1/ai/connections").json()
    assert conns, "expected the seeded postgres connection to be listed"
    return conns[0]["id"]


class TestGoldenOneKeyTwoSurfaces:
    def test_free_caller_blocked_on_both_paid_surfaces(self, assurance_client, ai_app_client_factory) -> None:
        # Assurance: no key at all on a paid route.
        r = assurance_client.post(
            "/v1/cases/case-free-1/signal",
            json={
                "received_at": "2026-09-21T10:00:00Z",
                "channel": "customer_or_integrator",
                "received_by": "ops@example.com",
                "description": "test signal",
                "product_name": "Line 4 welder",
                "actor": {"identifier": "ops@example.com", "role": "operator"},
            },
        )
        assert r.status_code in (401, 402)

        # /ai: no key, WRITE-shaped request.
        free_client = ai_app_client_factory({"X-NB-Actor": "free-buyer", "X-NB-Session": "s1"})
        with free_client as c:
            cid = _get_connection_id(c)
            r = c.post(
                "/api/v1/ai/plan",
                json={"connection_id": cid, "operation": "execute_sql", "params": {"sql": "UPDATE ai_test_customers SET plan='register' WHERE id=1"}},
            )
            assert r.status_code == 402
            assert r.json()["detail"]["error"] == "plan_does_not_include_ai_control_plane"

    def test_one_cell_key_unlocks_both_paid_surfaces(self, assurance_client, ai_app_client_factory, cell_key: str) -> None:
        # Surface 1: the assurance paid route — open a case with a real signal.
        r = assurance_client.post(
            "/v1/cases/case-buyer-1/signal",
            headers={"X-API-Key": cell_key},
            json={
                "received_at": "2026-09-21T10:00:00Z",
                "channel": "customer_or_integrator",
                "received_by": "ops@example.com",
                "description": "Unexpected outbound connection from line controller",
                "product_name": "Line 4 welder",
                "actor": {"identifier": "ops@example.com", "role": "operator"},
            },
        )
        assert r.status_code == 201, r.text
        receipt = r.json()
        assert receipt["case_id"] == "case-buyer-1"
        assert receipt["content_hash"]
        assert receipt["ledger_seq"] >= 1

        # Confirm the case is really on the register, not just echoed back.
        r = assurance_client.get("/v1/cases", headers={"X-API-Key": cell_key})
        assert "case-buyer-1" in r.json()

        # Surface 2: the SAME key unlocks /ai's WRITE path (plan -> approve).
        paid_ai = ai_app_client_factory({
            "X-NB-Actor": "buyer-operator", "X-NB-Session": "buyer-session", "X-API-Key": cell_key,
        })
        with paid_ai as c:
            cid = _get_connection_id(c)
            r = c.post(
                "/api/v1/ai/plan",
                json={"connection_id": cid, "operation": "execute_sql", "params": {"sql": "UPDATE ai_test_customers SET plan='cell' WHERE id=1"}},
            )
            assert r.status_code == 200, r.text
            plan = r.json()["plan"]
            assert plan["status"] == "pending_approval"

            r = c.post(f"/api/v1/ai/plan/{plan['id']}/approve")
            assert r.status_code == 200, r.text
            approve_receipt = r.json()
            assert approve_receipt["success"] is True
