# ruff: noqa: F811, F401  (fixtures are imported by name)
"""The raw adapters route is not a cheaper way to write the shared demo database.

The plain ``postgres`` registry key on ``POST /adapters/postgres/execute`` is the seeded demo
database: one database for every tenant. ``/ai`` refuses a paid account's write to it (tenancy.py),
but the raw route only checked the entitlement, so an independent red team wrote it with a plain
Register key: no plan, no approval, no four-eyes. Operators keep the route; reads stay free; the
documented local-development switch still lifts the refusal.
"""

from __future__ import annotations

import pytest

from .platform_support import API, OPERATOR_KEY, client, env, h, requires_postgres
from .test_ai_four_eyes import policy_on, rows, table, team

pytestmark = requires_postgres

RAW = "/api/v1/adapters/postgres/execute"


def _write(client, key, value):
    return client.post(RAW, headers=h(key), json={
        "operation": "execute_sql", "params": {"sql": f"INSERT INTO fe_t VALUES ('{value}')"}})


@pytest.fixture(autouse=True)
def _demo_not_writable(monkeypatch):
    monkeypatch.delenv("NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID", raising=False)


def test_a_paid_tenant_cannot_write_the_shared_demo_through_the_raw_route(client, team, table):
    client.get(f"{API}/connections", headers=h(team.proposer))      # seeds the demo adapter
    before = rows()
    r = _write(client, team.proposer, "raw")
    assert r.status_code == 403 and "read-only" in r.text
    assert rows() == before, "the write must not have reached the database"


def test_four_eyes_cannot_be_walked_around_by_the_raw_route(client, team, table):
    policy_on(client, team.proposer)
    client.get(f"{API}/connections", headers=h(team.proposer))
    before = rows()
    assert _write(client, team.proposer, "raw").status_code == 403
    assert rows() == before


def test_an_anonymous_caller_is_still_refused_by_the_entitlement_gate(client, table):
    client.get(f"{API}/connections", headers=h(None))
    assert _write(client, None, "anon").status_code == 402


def test_reads_through_the_raw_route_stay_available_to_a_paid_tenant(client, team):
    client.get(f"{API}/connections", headers=h(team.proposer))
    r = client.post(RAW, headers=h(team.proposer), json={"operation": "list_tables", "params": {}})
    assert r.status_code == 200


def test_the_operator_keeps_the_raw_write_route(client, table):
    client.get(f"{API}/connections", headers=h(OPERATOR_KEY))
    before = rows()
    assert _write(client, OPERATOR_KEY, "op").status_code == 200
    assert rows() == before + 1


def test_the_local_development_switch_still_lifts_the_refusal(client, team, table, monkeypatch):
    monkeypatch.setenv("NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID", "1")   # LOCAL ONLY, as in /ai
    client.get(f"{API}/connections", headers=h(team.proposer))
    before = rows()
    assert _write(client, team.proposer, "dev").status_code == 200
    assert rows() == before + 1
