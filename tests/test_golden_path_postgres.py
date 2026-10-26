"""One Cell key, two paid surfaces, two tenants, against a real PostgreSQL.

The assurance product and the ``/ai`` control plane answer to one entitlement engine and
one ``AccountStore``. A's Cell key opens an assurance route and an ``/ai`` plan ->
approve that really changes a row in Postgres; B, a different Cell account, cannot see,
approve, deny, describe or unbind A's connection or plan, and gets the SAME answer
(status and JSON body, once the id echoed back is normalised) as for a random id that
never existed, so there is no existence oracle. The row stays what A's own approval made
it.

Fixtures are those of ``test_ai_buyer_journey``. Like that file this needs a reachable
Postgres (``NEURALBRIDGE_AI_PG_*``); without one it skips, naming the server it looked
for. With ``NEURALBRIDGE_REQUIRE_POSTGRES=1`` (CI) ``tests/require_postgres_plugin.py``
turns that skip into a failure. Limitation: the Postgres tests drop and create
``ai_test_customers`` in one shared database, so two processes running them against the
same server at once can corrupt each other.
"""

from __future__ import annotations

import asyncio
import json
import uuid

import asyncpg
import pytest

from . import test_ai_buyer_journey as bj
from .test_ai_buyer_journey import (
    PG_DATABASE,
    PG_HOST,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    _postgres_reachable,
)

# the buyer journey's fixtures, by name
shared_entitlement_env = bj.shared_entitlement_env
seeded_table = bj.seeded_table
cell_key = bj.cell_key
assurance_client = bj.assurance_client
ai_app_client_factory = bj.ai_app_client_factory


@pytest.fixture(autouse=True)
def _postgres_or_say_so():
    if not _postgres_reachable():
        # NEURALBRIDGE_REQUIRE_POSTGRES=1 turns this skip into a failure (conftest hook)
        pytest.skip(f"No reachable PostgreSQL at {PG_USER}@{PG_HOST}:{PG_PORT}/{PG_DATABASE}; "
                    "see docs/ai-local-setup.md")


def same_as_never_existed(call, real_id: str) -> None:
    """``call(id)`` for A's real id and for a random one must be indistinguishable to B."""
    fake = str(uuid.uuid4())
    real_r, fake_r = call(real_id), call(fake)
    assert real_r.status_code == fake_r.status_code == 404, (real_r.status_code,
                                                            fake_r.status_code, real_r.text)
    assert json.dumps(real_r.json(), sort_keys=True).replace(real_id, "<id>") == \
        json.dumps(fake_r.json(), sort_keys=True).replace(fake, "<id>")


def plan_of(customer_plan: str) -> dict:
    return {"operation": "execute_sql", "params": {
        "sql": f"UPDATE ai_test_customers SET plan='{customer_plan}' WHERE id=1"}}


def row_plan() -> str:
    async def _read() -> str:
        conn = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER,
                                     password=PG_PASSWORD, database=PG_DATABASE)
        try:
            return await conn.fetchval("SELECT plan FROM ai_test_customers WHERE id=1")
        finally:
            await conn.close()
    return asyncio.run(_read())


def test_one_cell_key_two_surfaces_and_a_second_tenant_that_sees_nothing(
        assurance_client, ai_app_client_factory, cell_key, shared_entitlement_env):
    from assurance.billing.accounts import AccountStore

    store = AccountStore(str(shared_entitlement_env))
    b_account = store.upsert_account(email="other-buyer@example.com", tier="cell",
                                     company="Other Robotics")
    b_key = store.issue_key(b_account.id, label="other-buyer")
    signal = {
        "received_at": "2026-09-21T10:00:00Z", "channel": "customer_or_integrator",
        "received_by": "ops@example.com", "description": "Unexpected outbound connection",
        "product_name": "Line 4 welder", "actor": {"identifier": "ops@example.com",
                                                   "role": "operator"}}
    assert row_plan() == "cell"        # the seeded row, before anybody acts

    # no key: refused on both surfaces
    assert assurance_client.post("/v1/cases/pg-1/signal", json=signal).status_code == 401
    anon = ai_app_client_factory({"X-NB-Actor": "anon", "X-NB-Session": "s0"})
    with anon as c:
        assert c.post("/api/v1/ai/connections", json={"name": "x", "host": PG_HOST,
                                                      "user": PG_USER, "password": PG_PASSWORD,
                                                      "database": PG_DATABASE}).status_code == 402

    # surface 1: A's key opens an assurance case, in A's own ledger
    opened = assurance_client.post("/v1/cases/pg-1/signal", headers={"X-API-Key": cell_key},
                                   json=signal)
    assert opened.status_code == 201 and opened.json()["case_id"] == "pg-1"
    assert assurance_client.get("/v1/cases", headers={"X-API-Key": cell_key}).json() == ["pg-1"]
    assert assurance_client.get("/v1/cases", headers={"X-API-Key": b_key}).json() == []

    # surface 2: the same key binds a connection of its own and plans a write on it
    # (the factory resets the platform's singletons, so build both clients before either
    # is used: both then share the one registry and store a real deployment has)
    a = ai_app_client_factory({"X-NB-Actor": "a-ops", "X-NB-Session": "sa", "X-API-Key": cell_key})
    b = ai_app_client_factory({"X-NB-Actor": "b-ops", "X-NB-Session": "sb", "X-API-Key": b_key})
    with a as ca:
        bound = ca.post("/api/v1/ai/connections", json={
            "name": "A's database", "host": PG_HOST, "port": PG_PORT, "user": PG_USER,
            "password": PG_PASSWORD, "database": PG_DATABASE})
        assert bound.status_code == 200, bound.text
        a_conn = bound.json()["id"]
        planned = ca.post("/api/v1/ai/plan", json={"connection_id": a_conn,
                                                   **plan_of("register")})
        assert planned.status_code == 200, planned.text
        a_plan = planned.json()["plan"]
        assert a_plan["status"] == "pending_approval"

        # B: a different Cell account. A's connection and plan do not exist for B.
        with b as cb:
            assert a_conn not in [x["id"] for x in cb.get("/api/v1/ai/connections").json()]
            plan_id = a_plan["id"]
            for call, real in (
                    (lambda i: cb.post("/api/v1/ai/plan", json={"connection_id": i,
                                                                **plan_of("stolen")}), a_conn),
                    (lambda i: cb.get("/api/v1/ai/capabilities", params={"connection_id": i}),
                     a_conn),
                    (lambda i: cb.delete(f"/api/v1/ai/connections/{i}"), a_conn),
                    (lambda i: cb.get(f"/api/v1/ai/plan/{i}"), plan_id),
                    (lambda i: cb.post(f"/api/v1/ai/plan/{i}/approve"), plan_id),
                    (lambda i: cb.post(f"/api/v1/ai/plan/{i}/deny"), plan_id)):
                same_as_never_existed(call, real)
        assert row_plan() == "cell"    # B changed nothing

        # A is untouched by B's attempts: the plan is still pending, and A approves it
        still = ca.get(f"/api/v1/ai/plan/{a_plan['id']}")
        assert still.status_code == 200 and still.json()["status"] == "pending_approval"
        approved = ca.post(f"/api/v1/ai/plan/{a_plan['id']}/approve")
        assert approved.status_code == 200 and approved.json()["success"] is True
        assert a_conn in [x["id"] for x in ca.get("/api/v1/ai/connections").json()]

    # the row Postgres holds is the one A's approved plan wrote
    assert row_plan() == "register"
