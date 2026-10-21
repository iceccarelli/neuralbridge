"""Tenant isolation for the /ai control plane — real Postgres, real accounts.

Two customer accounts (minted through the real ``AccountStore`` the way
``tests/test_ai_buyer_journey.py`` does), an anonymous caller and the
operator, all against one running app and one AdapterRegistry/AiStore — the
way concurrent requests in a real process would share them.

The defect these pin down (proved by an independent reviewer): account A
bound a Postgres connection named ``A-PRIVATE-PROD-DB``; a caller with *no
key* then listed it and ran ``SELECT current_user`` through it. The rule now:
a connection, plan or audit entry belongs to the account that created it, an
id that is not yours behaves exactly like an id that does not exist, and the
credential a customer binds is never returned or logged.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
import uuid

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
        f"No reachable PostgreSQL at {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DATABASE} — "
        "see docs/ai-local-setup.md. Real-DB-only tests, skipped honestly rather than faked."
    ),
)

OPERATOR_KEY = "test-tenancy-operator-key"
A_NAME = "A-PRIVATE-PROD-DB"
B_NAME = "B-PRIVATE-WAREHOUSE"
API = "/api/v1/ai"


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch, tmp_path):
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
def seeded_tables():
    async def _run(sql: list[str]) -> None:
        conn = await asyncpg.connect(
            host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE
        )
        for stmt in sql:
            await conn.execute(stmt)
        await conn.close()

    asyncio.run(_run([
        "DROP TABLE IF EXISTS tenancy_a_secrets",
        "CREATE TABLE tenancy_a_secrets (id serial primary key, note text)",
        "INSERT INTO tenancy_a_secrets (note) VALUES ('a-only-row')",
    ]))
    yield
    asyncio.run(_run(["DROP TABLE IF EXISTS tenancy_a_secrets"]))


class Keys:
    def __init__(self, a: str, b: str) -> None:
        self.a = a
        self.b = b


@pytest.fixture
def keys(env) -> Keys:
    """Two real, separate customer accounts, each with its own real key."""
    from assurance.billing.accounts import AccountStore

    store = AccountStore(str(env))
    acct_a = store.upsert_account(email="a@example.com", tier="register", company="Account A")
    acct_b = store.upsert_account(email="b@example.com", tier="register", company="Account B")
    assert acct_a.id != acct_b.id
    return Keys(store.issue_key(acct_a.id, label="tenancy-a"), store.issue_key(acct_b.id, label="tenancy-b"))


@pytest.fixture
def client(env, seeded_tables):
    """ONE TestClient (one event loop, so the asyncpg pools live on it) —
    the caller identity is chosen per request via ``h(...)``."""
    import neuralbridge.api.dependencies as deps
    from neuralbridge.main import create_app

    deps._adapter_registry = None
    deps._request_router = None
    deps._audit_logger = None
    deps._ai_store = None
    with TestClient(create_app()) as c:
        yield c


def h(key: str | None = None, actor: str = "tenant-actor") -> dict[str, str]:
    headers = {"X-NB-Actor": actor, "X-NB-Session": "tenancy-session"}
    if key:
        headers["X-API-Key"] = key
    return headers


def bind(client: TestClient, key: str, name: str, **extra) -> dict:
    r = client.post(
        f"{API}/connections",
        headers=h(key),
        json={
            "name": name, "host": PG_HOST, "port": PG_PORT, "user": PG_USER,
            "password": PG_PASSWORD, "database": PG_DATABASE, **extra,
        },
    )
    assert r.status_code == 200, r.text
    return r.json()


def demo_id(client: TestClient) -> str:
    conns = client.get(f"{API}/connections", headers=h()).json()
    demo = [c for c in conns if c["source"] == "seeded_from_env"]
    assert len(demo) == 1
    return demo[0]["id"]


def read(client: TestClient, key: str | None, cid: str, operation: str = "query", sql: str = "SELECT current_user"):
    params = {"sql": sql} if operation == "query" else {}
    return client.post(
        f"{API}/read", headers=h(key), json={"connection_id": cid, "operation": operation, "params": params}
    )


def write_plan(client: TestClient, key: str | None, cid: str, sql: str):
    return client.post(
        f"{API}/plan", headers=h(key),
        json={"connection_id": cid, "operation": "execute_sql", "params": {"sql": sql}},
    )


def assert_same_404(response, real_id: str, missing_id: str) -> None:
    """A foreign id must look exactly like a missing one: same status, same
    body once the id itself is substituted."""
    assert response.status_code == 404, response.text
    assert response.json() == {"detail": f"Connection '{real_id}' not found."}
    assert response.json()["detail"].replace(real_id, missing_id) == f"Connection '{missing_id}' not found."


# ───────────────────────────── the proved defect ─────────────────────────────


class TestTheProvedDefect:
    def test_anonymous_cannot_list_or_read_another_accounts_connection(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)

        listing = client.get(f"{API}/connections", headers=h())
        assert listing.status_code == 200
        assert A_NAME not in listing.text
        assert a_conn["id"] not in listing.text

        r = read(client, None, a_conn["id"])
        assert r.status_code == 404
        assert "rows" not in r.text and "current_user" not in r.text

    def test_other_account_cannot_list_or_read_it_either(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)

        listing = client.get(f"{API}/connections", headers=h(keys.b))
        assert A_NAME not in listing.text
        assert a_conn["id"] not in listing.text
        assert read(client, keys.b, a_conn["id"]).status_code == 404


# ───────────────────────── visibility: list / describe / read ─────────────────────────


class TestListDescribeRead:
    def test_each_caller_sees_only_own_plus_demo(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        b_conn = bind(client, keys.b, B_NAME)
        demo = demo_id(client)

        def ids(key: str | None) -> set[str]:
            r = client.get(f"{API}/connections", headers=h(key))
            assert r.status_code == 200
            return {c["id"] for c in r.json()}

        assert ids(keys.a) == {a_conn["id"], demo}
        assert ids(keys.b) == {b_conn["id"], demo}
        assert ids(None) == {demo}

    def test_foreign_id_is_indistinguishable_from_missing_id(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        missing = str(uuid.uuid4())

        for caller in (None, keys.b):
            foreign = read(client, caller, a_conn["id"])
            absent = read(client, caller, missing)
            assert foreign.status_code == absent.status_code == 404
            assert foreign.json()["detail"].replace(a_conn["id"], "X") == absent.json()["detail"].replace(missing, "X")
            assert_same_404(foreign, a_conn["id"], missing)

            cap_foreign = client.get(f"{API}/capabilities", params={"connection_id": a_conn["id"]}, headers=h(caller))
            cap_absent = client.get(f"{API}/capabilities", params={"connection_id": missing}, headers=h(caller))
            assert cap_foreign.status_code == cap_absent.status_code == 404
            assert cap_foreign.json()["detail"].replace(a_conn["id"], "X") == cap_absent.json()["detail"].replace(missing, "X")

    def test_owner_can_describe_and_read_and_both_accounts_use_their_own(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        b_conn = bind(client, keys.b, B_NAME)

        assert client.get(f"{API}/capabilities", params={"connection_id": a_conn["id"]}, headers=h(keys.a)).status_code == 200
        r = read(client, keys.a, a_conn["id"], sql="SELECT note FROM tenancy_a_secrets")
        assert r.status_code == 200 and r.json()["data"] == [{"note": "a-only-row"}]
        assert r.json()["provenance"]["connection_name"] == A_NAME

        r = read(client, keys.b, b_conn["id"], sql="SELECT 1 AS one")
        assert r.status_code == 200 and r.json()["data"] == [{"one": 1}]
        assert r.json()["provenance"]["connection_name"] == B_NAME

    def test_owner_is_never_taken_from_the_request_body(self, client, keys: Keys) -> None:
        """Extra fields on bind (owner, account_id, ...) are ignored: the
        connection belongs to whoever's key made the call."""
        from assurance.billing.accounts import AccountStore

        store = AccountStore(os.environ["ASSURANCE_ACCOUNTS"])
        b_account = store.resolve_key(keys.b).account
        assert b_account is not None
        forged = bind(client, keys.a, "forged-owner", owner=b_account.id, account_id=b_account.id)

        assert forged["id"] in client.get(f"{API}/connections", headers=h(keys.a)).text
        assert forged["id"] not in client.get(f"{API}/connections", headers=h(keys.b)).text
        assert read(client, keys.b, forged["id"]).status_code == 404

    def test_forged_actor_header_does_not_grant_access(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        r = client.post(
            f"{API}/read",
            headers={**h(keys.b, actor="human_session:tenant-actor"), "X-NB-Owner": "x", "X-Account-Id": "x"},
            json={"connection_id": a_conn["id"], "operation": "health_check", "params": {}},
        )
        assert r.status_code == 404

    def test_invalid_key_is_still_a_401(self, client) -> None:
        assert client.get(f"{API}/connections", headers=h("nb-not-a-real-key")).status_code == 401


# ───────────────────────── plan / approve / deny ─────────────────────────


class TestPlansAndApprovals:
    def test_other_accounts_cannot_plan_on_a_foreign_connection(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        missing = str(uuid.uuid4())
        sql = "UPDATE tenancy_a_secrets SET note='pwned'"

        r = write_plan(client, keys.b, a_conn["id"], sql)
        assert_same_404(r, a_conn["id"], missing)
        assert write_plan(client, keys.b, missing, sql).status_code == 404

        # Anonymous: the paid gate answers first, identically for real and missing ids.
        anon_real = write_plan(client, None, a_conn["id"], sql)
        anon_missing = write_plan(client, None, missing, sql)
        assert anon_real.status_code == anon_missing.status_code == 402
        assert anon_real.json() == anon_missing.json()

        # Nothing was written.
        r = read(client, keys.a, a_conn["id"], sql="SELECT note FROM tenancy_a_secrets")
        assert r.json()["data"] == [{"note": "a-only-row"}]

    def test_only_the_proposing_account_can_approve_or_deny(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        plan = write_plan(client, keys.a, a_conn["id"], "UPDATE tenancy_a_secrets SET note='changed-by-a'")
        assert plan.status_code == 200, plan.text
        plan_id = plan.json()["plan"]["id"]
        missing_plan = str(uuid.uuid4())

        # B (paid, different account): 404, byte-identical to a plan id that does not exist.
        for method, suffix in (("post", "/approve"), ("post", "/deny"), ("get", "")):
            real = getattr(client, method)(f"{API}/plan/{plan_id}{suffix}", headers=h(keys.b))
            absent = getattr(client, method)(f"{API}/plan/{missing_plan}{suffix}", headers=h(keys.b))
            assert real.status_code == absent.status_code == 404, (suffix, real.text)
            assert real.json()["detail"].replace(plan_id, "X") == absent.json()["detail"].replace(missing_plan, "X")

        # Anonymous cannot approve either (402 at the paid gate; can't inspect a plan: 404).
        assert client.post(f"{API}/plan/{plan_id}/approve", headers=h()).status_code == 402
        assert client.get(f"{API}/plan/{plan_id}", headers=h()).status_code == 404

        # The plan is untouched and nothing ran.
        assert client.get(f"{API}/plan/{plan_id}", headers=h(keys.a)).json()["status"] == "pending_approval"
        r = read(client, keys.a, a_conn["id"], sql="SELECT note FROM tenancy_a_secrets")
        assert r.json()["data"] == [{"note": "a-only-row"}]

        # The owner can.
        r = client.post(f"{API}/plan/{plan_id}/approve", headers=h(keys.a))
        assert r.status_code == 200 and r.json()["success"] is True
        r = read(client, keys.a, a_conn["id"], sql="SELECT note FROM tenancy_a_secrets")
        assert r.json()["data"] == [{"note": "changed-by-a"}]

    def test_each_account_runs_its_own_plan_loop(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        b_conn = bind(client, keys.b, B_NAME)
        for key, conn in ((keys.a, a_conn), (keys.b, b_conn)):
            plan = write_plan(client, key, conn["id"], "UPDATE tenancy_a_secrets SET note=note")
            assert plan.status_code == 200, plan.text
            r = client.post(f"{API}/plan/{plan.json()['plan']['id']}/approve", headers=h(key))
            assert r.status_code == 200 and r.json()["success"] is True

    def test_denied_by_a_stranger_is_impossible_and_owner_can_deny(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        plan_id = write_plan(client, keys.a, a_conn["id"], "DELETE FROM tenancy_a_secrets").json()["plan"]["id"]
        assert client.post(f"{API}/plan/{plan_id}/deny", headers=h(keys.b)).status_code == 404
        r = client.post(f"{API}/plan/{plan_id}/deny", headers=h(keys.a))
        assert r.status_code == 200 and r.json()["status"] == "denied"


# ───────────────────────────── delete / unbind ─────────────────────────────


class TestDelete:
    def test_foreign_and_anonymous_delete_cannot_remove_it(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        missing = str(uuid.uuid4())

        r = client.delete(f"{API}/connections/{a_conn['id']}", headers=h(keys.b))
        assert_same_404(r, a_conn["id"], missing)
        assert client.delete(f"{API}/connections/{missing}", headers=h(keys.b)).status_code == 404

        anon = client.delete(f"{API}/connections/{a_conn['id']}", headers=h())
        anon_missing = client.delete(f"{API}/connections/{missing}", headers=h())
        assert anon.status_code == anon_missing.status_code == 402

        assert a_conn["id"] in client.get(f"{API}/connections", headers=h(keys.a)).text
        assert read(client, keys.a, a_conn["id"]).status_code == 200

    def test_owner_can_delete_and_it_is_really_gone(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        plan_id = write_plan(client, keys.a, a_conn["id"], "DELETE FROM tenancy_a_secrets").json()["plan"]["id"]

        r = client.delete(f"{API}/connections/{a_conn['id']}", headers=h(keys.a))
        assert r.status_code == 200 and r.json() == {"deleted": a_conn["id"]}
        assert read(client, keys.a, a_conn["id"]).status_code == 404
        assert a_conn["id"] not in client.get(f"{API}/connections", headers=h(keys.a)).text
        # A pending plan cannot outlive its connection.
        assert client.get(f"{API}/plan/{plan_id}", headers=h(keys.a)).json()["status"] == "denied"
        assert client.post(f"{API}/plan/{plan_id}/approve", headers=h(keys.a)).status_code == 409
        # And its live adapter is gone from the registry.
        assert f"postgres:{a_conn['id']}" not in client.get("/api/v1/adapters", headers=h(OPERATOR_KEY)).text
        # Deleting twice is a plain 404.
        assert client.delete(f"{API}/connections/{a_conn['id']}", headers=h(keys.a)).status_code == 404


# ───────────────────────────── the shared demo connection ─────────────────────────────


class TestSeededDemo:
    def test_anonymous_can_still_read_the_demo_for_discovery(self, client, keys: Keys) -> None:
        demo = demo_id(client)
        assert client.get(f"{API}/capabilities", params={"connection_id": demo}, headers=h()).status_code == 200
        r = read(client, None, demo, operation="list_tables")
        assert r.status_code == 200 and r.json()["success"] is True
        assert read(client, keys.b, demo, sql="SELECT 1 AS one").status_code == 200

    def test_anonymous_cannot_write_or_delete_the_demo(self, client, keys: Keys) -> None:
        demo = demo_id(client)
        assert write_plan(client, None, demo, "UPDATE tenancy_a_secrets SET note='x'").status_code == 402
        assert client.delete(f"{API}/connections/{demo}", headers=h()).status_code == 402

    def test_a_customer_account_cannot_delete_the_demo(self, client, keys: Keys) -> None:
        demo = demo_id(client)
        r = client.delete(f"{API}/connections/{demo}", headers=h(keys.a))
        assert r.status_code == 404
        assert demo_id(client) == demo
        assert read(client, None, demo, operation="list_tables").status_code == 200

    def test_a_plan_on_the_demo_belongs_to_the_account_that_proposed_it(self, client, keys: Keys) -> None:
        demo = demo_id(client)
        plan = write_plan(client, keys.a, demo, "UPDATE tenancy_a_secrets SET note=note")
        assert plan.status_code == 200
        plan_id = plan.json()["plan"]["id"]
        assert client.post(f"{API}/plan/{plan_id}/approve", headers=h(keys.b)).status_code == 404
        assert client.post(f"{API}/plan/{plan_id}/approve", headers=h(keys.a)).status_code == 200


# ───────────────────────────── audit trail ─────────────────────────────


class TestAudit:
    def test_audit_returns_only_the_callers_own_entries(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        b_conn = bind(client, keys.b, B_NAME)
        assert read(client, keys.a, a_conn["id"], operation="health_check").status_code == 200
        assert read(client, keys.b, b_conn["id"], operation="health_check").status_code == 200

        a_events = client.get(f"{API}/audit", headers=h(keys.a)).json()
        b_events = client.get(f"{API}/audit", headers=h(keys.b)).json()
        assert a_events and b_events
        assert {e["resource"] for e in a_events} == {f"postgres:{a_conn['id']}"}
        assert {e["resource"] for e in b_events} == {f"postgres:{b_conn['id']}"}

        anon = client.get(f"{API}/audit", headers=h()).json()
        assert anon == []

    def test_spoofing_the_actor_header_does_not_reveal_another_accounts_entries(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        assert read(client, keys.a, a_conn["id"], operation="health_check", ).status_code == 200
        r = client.get(f"{API}/audit", headers=h(keys.b, actor="tenant-actor"))
        assert a_conn["id"] not in r.text
        r = client.get(f"{API}/audit", headers=h(None, actor="tenant-actor"))
        assert a_conn["id"] not in r.text

    def test_audit_entries_carry_the_server_derived_owner(self, client, keys: Keys) -> None:
        from assurance.billing.accounts import AccountStore

        a_conn = bind(client, keys.a, A_NAME)
        read(client, keys.a, a_conn["id"], operation="health_check")
        a_account = AccountStore(os.environ["ASSURANCE_ACCOUNTS"]).resolve_key(keys.a).account
        events = client.get(f"{API}/audit", headers=h(keys.a)).json()
        assert events and all(e["details"]["owner"] == a_account.id for e in events)


# ───────────────────────────── operator keeps full access ─────────────────────────────


class TestOperator:
    def test_operator_sees_and_uses_everything(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        b_conn = bind(client, keys.b, B_NAME)
        read(client, keys.a, a_conn["id"], operation="health_check")

        ids = {c["id"] for c in client.get(f"{API}/connections", headers=h(OPERATOR_KEY)).json()}
        assert {a_conn["id"], b_conn["id"], demo_id(client)} <= ids
        assert read(client, OPERATOR_KEY, a_conn["id"], sql="SELECT 1 AS one").status_code == 200

        plan_id = write_plan(client, keys.a, a_conn["id"], "UPDATE tenancy_a_secrets SET note=note").json()["plan"]["id"]
        assert client.get(f"{API}/plan/{plan_id}", headers=h(OPERATOR_KEY)).status_code == 200
        assert client.post(f"{API}/plan/{plan_id}/approve", headers=h(OPERATOR_KEY)).status_code == 200

        events = client.get(f"{API}/audit", headers=h(OPERATOR_KEY)).json()
        assert any(e["resource"] == f"postgres:{a_conn['id']}" for e in events)

        r = client.delete(f"{API}/connections/{b_conn['id']}", headers=h(OPERATOR_KEY))
        assert r.status_code == 200


# ───────────────────────── the raw adapters route is not a way around /ai ─────────────────────────


class TestRawAdaptersRouteIsNotABypass:
    def test_a_paid_account_cannot_execute_on_another_accounts_registry_key(self, client, keys: Keys) -> None:
        a_conn = bind(client, keys.a, A_NAME)
        key = f"postgres:{a_conn['id']}"

        for caller in (None, keys.b):
            r = client.post(
                f"/api/v1/adapters/{key}/execute", headers=h(caller),
                json={"operation": "execute_sql", "params": {"sql": "UPDATE tenancy_a_secrets SET note='pwned'"}},
            )
            assert r.status_code in (402, 404), r.text
            assert r.status_code != 200
        r = client.post(
            f"/api/v1/adapters/{key}/execute", headers=h(keys.b),
            json={"operation": "query", "params": {"sql": "SELECT note FROM tenancy_a_secrets"}},
        )
        assert r.status_code == 404

        for caller in (None, keys.a, keys.b):
            listing = client.get("/api/v1/adapters", headers=h(caller))
            assert key not in listing.text
            assert client.get(f"/api/v1/adapters/{key}", headers=h(caller)).status_code == 404

        # The operator still sees it, as before.
        assert key in client.get("/api/v1/adapters", headers=h(OPERATOR_KEY)).text
        r = client.post(
            f"/api/v1/adapters/{key}/execute", headers=h(OPERATOR_KEY),
            json={"operation": "query", "params": {"sql": "SELECT note FROM tenancy_a_secrets"}},
        )
        assert r.status_code == 200

        r = read(client, keys.a, a_conn["id"], sql="SELECT note FROM tenancy_a_secrets")
        assert r.json()["data"] == [{"note": "a-only-row"}]


# ───────────────────────────── credentials never leave ─────────────────────────────


class TestCredentialsNeverReturnedOrLogged:
    def test_bound_password_is_in_no_response_no_store_and_no_log(
        self, client, keys: Keys, caplog: pytest.LogCaptureFixture, capfd: pytest.CaptureFixture[str], tmp_path
    ) -> None:
        caplog.set_level(logging.DEBUG)
        secret = PG_PASSWORD  # the real password the customer binds with
        bodies: list[str] = []

        bound = client.post(
            f"{API}/connections", headers=h(keys.a),
            json={"name": A_NAME, "host": PG_HOST, "port": PG_PORT, "user": PG_USER,
                  "password": secret, "database": PG_DATABASE},
        )
        assert bound.status_code == 200
        bodies.append(bound.text)
        cid = bound.json()["id"]

        for caller in (keys.a, keys.b, None, OPERATOR_KEY):
            bodies.append(client.get(f"{API}/connections", headers=h(caller)).text)
            bodies.append(client.get(f"{API}/capabilities", params={"connection_id": cid}, headers=h(caller)).text)
            bodies.append(client.get(f"{API}/audit", headers=h(caller)).text)
            bodies.append(client.get(f"{API}/session", headers=h(caller)).text)
            bodies.append(client.get("/api/v1/adapters", headers=h(caller)).text)
            bodies.append(client.get(f"/api/v1/adapters/postgres:{cid}", headers=h(caller)).text)
        bodies.append(read(client, keys.a, cid, sql="SELECT 1 AS one").text)
        bodies.append(read(client, keys.a, cid, operation="list_tables").text)
        plan = write_plan(client, keys.a, cid, "UPDATE tenancy_a_secrets SET note=note")
        bodies.append(plan.text)
        bodies.append(client.get(f"{API}/plan/{plan.json()['plan']['id']}", headers=h(keys.a)).text)
        bodies.append(client.post(f"{API}/plan/{plan.json()['plan']['id']}/approve", headers=h(keys.a)).text)

        for body in bodies:
            assert secret not in body

        # Not persisted: neither the SQLite store (incl. WAL) nor its config JSON holds it.
        store_path = os.environ["NEURALBRIDGE_AI_STORE"]
        for suffix in ("", "-wal", "-shm"):
            path = store_path + suffix
            if os.path.exists(path):
                with open(path, "rb") as fh:
                    assert secret.encode() not in fh.read(), path
        db = sqlite3.connect(store_path)
        try:
            configs = [row[0] for row in db.execute("SELECT config_json FROM connections")]
        finally:
            db.close()
        assert configs and all("password" not in c and secret not in c for c in configs)

        # Not logged: nothing captured via logging or stdout/stderr (structlog) carries it.
        logged = "\n".join(r.getMessage() for r in caplog.records)
        out, err = capfd.readouterr()
        assert secret not in logged and secret not in out and secret not in err

    def test_response_schema_has_no_credential_fields(self, client, keys: Keys) -> None:
        bind(client, keys.a, A_NAME)
        for entry in client.get(f"{API}/connections", headers=h(keys.a)).json():
            assert set(entry) == {"id", "name", "adapter_type", "status", "source"}


# ───────────────────────── additive migration of an existing store ─────────────────────────


V1_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE connections (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    adapter_type TEXT NOT NULL, registry_key TEXT NOT NULL, config_json TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'created',
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE plans (
    id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, adapter_type TEXT NOT NULL,
    operation TEXT NOT NULL, operation_class TEXT NOT NULL, params_json TEXT NOT NULL,
    proposed_by TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
    decided_by TEXT, decided_at TEXT, deny_reason TEXT
);
CREATE INDEX plans_by_connection ON plans (connection_id);
INSERT INTO meta (key, value) VALUES ('schema_version', '1');
"""


class TestLegacyStoreMigration:
    def _write_v1(self, path) -> None:
        db = sqlite3.connect(path)
        db.executescript(V1_SCHEMA)
        now = "2026-01-01T00:00:00+00:00"
        db.execute(
            "INSERT INTO connections VALUES ('legacy-private','LEGACY-PRIVATE','','postgres',"
            "'postgres:legacy-private','{}','bound_by_operator','created',?,?)", (now, now),
        )
        db.execute(
            "INSERT INTO plans VALUES ('legacy-plan','legacy-private','postgres','execute_sql','write',"
            "'{\"sql\": \"UPDATE tenancy_a_secrets SET note=note\"}','human_session:old','pending_approval',?,NULL,NULL,NULL)",
            (now,),
        )
        db.commit()
        db.close()

    def test_v1_file_is_migrated_additively_with_empty_owner(self, tmp_path) -> None:
        from neuralbridge.ai.store import SCHEMA_VERSION, AiStore

        path = tmp_path / "v1.db"
        self._write_v1(path)
        store = AiStore(path)

        conn = store.get_connection("legacy-private")
        plan = store.get_plan("legacy-plan")
        assert conn is not None and conn.owner == "" and conn.name == "LEGACY-PRIVATE"
        assert plan is not None and plan.owner == "" and plan.status == "pending_approval"

        db = sqlite3.connect(path)
        try:
            assert db.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == str(SCHEMA_VERSION)
        finally:
            db.close()
        AiStore(path)  # re-opening a migrated file is a no-op

    def test_unknown_future_schema_is_still_refused(self, tmp_path) -> None:
        from neuralbridge.ai.store import AiStore

        path = tmp_path / "future.db"
        self._write_v1(path)
        db = sqlite3.connect(path)
        db.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
        db.commit()
        db.close()
        with pytest.raises(RuntimeError):
            AiStore(path)

    def test_legacy_rows_are_operator_only_through_the_api(self, env, seeded_tables, keys: Keys) -> None:
        import neuralbridge.api.dependencies as deps
        from neuralbridge.main import create_app

        self._write_v1(os.environ["NEURALBRIDGE_AI_STORE"])
        deps._adapter_registry = None
        deps._request_router = None
        deps._audit_logger = None
        deps._ai_store = None
        with TestClient(create_app()) as c:
            for caller in (None, keys.a, keys.b):
                listing = c.get(f"{API}/connections", headers=h(caller))
                assert "legacy-private" not in listing.text and "LEGACY-PRIVATE" not in listing.text
                assert read(c, caller, "legacy-private").status_code == 404
                assert c.get(f"{API}/plan/legacy-plan", headers=h(caller)).status_code == 404
            assert c.post(f"{API}/plan/legacy-plan/approve", headers=h(keys.a)).status_code == 404
            assert c.delete(f"{API}/connections/legacy-private", headers=h(keys.a)).status_code == 404

            op = c.get(f"{API}/connections", headers=h(OPERATOR_KEY))
            assert "legacy-private" in op.text
            assert c.get(f"{API}/plan/legacy-plan", headers=h(OPERATOR_KEY)).status_code == 200
