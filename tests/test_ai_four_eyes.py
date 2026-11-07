# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Four-eyes approval for /ai write plans: opt-in, off by default, enforced by the server.

Independence is judged on server-derived key fingerprints, never on ``X-NB-Actor`` (a label the
client chooses). The default is OFF so no existing customer changes behaviour: that is pinned too.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections import Counter
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from assurance.billing.accounts import AccountStore
from neuralbridge.ai.approval import CallerRef, independence_problem

from .credential_support import sql, store_path
from .platform_support import (
    API,
    OPERATOR_KEY,
    audit_events,
    bind,
    client,
    env,
    h,
    pg_run,
    requires_postgres,
)

pytestmark = requires_postgres


@pytest.fixture
def table():
    pg_run("DROP TABLE IF EXISTS fe_t", "CREATE TABLE fe_t (v text)")
    yield
    pg_run("DROP TABLE IF EXISTS fe_t")


def rows() -> int:
    import asyncio

    import asyncpg

    from .platform_support import PG_DATABASE, PG_HOST, PG_PASSWORD, PG_PORT, PG_USER

    async def go() -> int:
        c = await asyncpg.connect(host=PG_HOST, port=PG_PORT, user=PG_USER, password=PG_PASSWORD, database=PG_DATABASE)
        try:
            return int(await c.fetchval("SELECT count(*) FROM fe_t"))
        finally:
            await c.close()

    return asyncio.run(go())


@pytest.fixture
def team(env):
    """One paid account with TWO keys (proposer / approver), a stranger account, and ids."""
    store = AccountStore(str(env))
    acct = store.upsert_account(email="team@example.com", tier="register", company="Team")
    other = store.upsert_account(email="stranger@example.com", tier="register", company="Stranger")
    return SimpleNamespace(
        id=acct.id, proposer=store.issue_key(acct.id, label="proposer"),
        approver=store.issue_key(acct.id, label="approver"), stranger=store.issue_key(other.id, label="x"),
        stranger_id=other.id,
    )


def propose(client, key, cid, value="x", actor="agent"):
    return client.post(f"{API}/plan", headers=h(key, actor=actor), json={
        "connection_id": cid, "operation": "execute_sql", "params": {"sql": f"INSERT INTO fe_t VALUES ('{value}')"}})


def approve(client, key, plan_id, actor="human"):
    return client.post(f"{API}/plan/{plan_id}/approve", headers=h(key, actor=actor))


def policy_on(client, key):
    r = client.put(f"{API}/policy", headers=h(key), json={"four_eyes": True})
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def conn(client, team, table):
    return bind(client, team.proposer, "fe")


# ───────────────────────────── default: OFF, nothing changes ─────────────────────────────


class TestDefaultIsOffAndCompatible:
    def test_the_policy_is_visible_and_off(self, client, team, conn) -> None:
        for key in (team.proposer, team.stranger):
            p = client.get(f"{API}/policy", headers=h(key)).json()
            assert p["four_eyes"] is False and p["source"] == "default" and p["approval_ttl_s"] is None
        assert client.get(f"{API}/policy", headers=h()).json()["four_eyes"] is False  # anonymous may look

    def test_the_same_key_can_still_propose_and_approve_exactly_as_before(self, client, team, conn) -> None:
        card = propose(client, team.proposer, conn["id"]).json()
        assert card["plan"]["four_eyes"] is False and card["plan"]["expires_at"] is None
        r = approve(client, team.proposer, card["plan"]["id"])
        assert r.status_code == 200 and r.json()["success"] is True
        assert rows() == 1
        assert approve(client, team.proposer, card["plan"]["id"]).status_code == 409

    def test_no_plan_expires_when_the_policy_is_off(self, client, team, conn) -> None:
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        sql("UPDATE plans SET created_at='2000-01-01T00:00:00+00:00'")
        assert client.get(f"{API}/plan/{pid}", headers=h(team.proposer)).json()["status"] == "pending_approval"
        assert approve(client, team.proposer, pid).status_code == 200

    def test_read_models_carry_the_read_only_flag(self, client, team, conn) -> None:
        listed = client.get(f"{API}/connections", headers=h(team.proposer)).json()
        assert listed and all(c["four_eyes"] is False for c in listed)


# ───────────────────────────── the policy itself ─────────────────────────────


class TestPolicyControl:
    def test_an_account_can_switch_it_on_and_the_read_models_show_it(self, client, team, conn) -> None:
        on = policy_on(client, team.proposer)
        assert on == {"four_eyes": True, "source": "tenant", "approval_ttl_s": 86400, "credential_custody": "shared_encrypted"}
        assert client.get(f"{API}/policy", headers=h(team.approver)).json()["four_eyes"] is True
        assert all(c["four_eyes"] is True for c in client.get(f"{API}/connections", headers=h(team.proposer)).json())
        card = propose(client, team.proposer, conn["id"]).json()
        assert card["plan"]["four_eyes"] is True
        expires = datetime.fromisoformat(card["plan"]["expires_at"])
        assert timedelta(hours=23) < expires - datetime.now(UTC) <= timedelta(hours=24)

    def test_it_is_per_tenant(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        assert client.get(f"{API}/policy", headers=h(team.stranger)).json()["four_eyes"] is False

    def test_the_key_it_constrains_cannot_switch_it_off(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        for key in (team.proposer, team.approver):
            r = client.put(f"{API}/policy", headers=h(key), json={"four_eyes": False})
            assert r.status_code == 403
        assert client.get(f"{API}/policy", headers=h(team.proposer)).json()["four_eyes"] is True

    def test_the_operator_can_set_and_lift_it_for_one_tenant(self, client, team, conn) -> None:
        r = client.put(f"{API}/policy", headers=h(OPERATOR_KEY), json={"four_eyes": True, "owner": team.id})
        assert r.status_code == 200 and client.get(f"{API}/policy", headers=h(team.proposer)).json()["four_eyes"] is True
        assert client.put(f"{API}/policy", headers=h(OPERATOR_KEY), json={"four_eyes": False, "owner": team.id}).status_code == 200
        assert client.get(f"{API}/policy", headers=h(team.proposer)).json()["four_eyes"] is False

    def test_a_customer_cannot_set_another_tenants_policy(self, client, team, conn) -> None:
        r = client.put(f"{API}/policy", headers=h(team.stranger), json={"four_eyes": True, "owner": team.id})
        assert r.status_code == 403
        assert client.get(f"{API}/policy", headers=h(team.proposer)).json()["four_eyes"] is False

    def test_a_free_or_anonymous_caller_cannot_set_it(self, client, team, env) -> None:
        free = AccountStore(str(env)).upsert_account(email="free@example.com", tier="free", company="F")
        free_key = AccountStore(str(env)).issue_key(free.id, label="f")
        assert client.put(f"{API}/policy", headers=h(free_key), json={"four_eyes": True}).status_code == 402
        assert client.put(f"{API}/policy", headers=h(), json={"four_eyes": True}).status_code == 402

    def test_the_environment_switch_applies_to_everyone_and_nothing_lifts_it(self, client, team, conn, monkeypatch) -> None:
        monkeypatch.setenv("NEURALBRIDGE_AI_FOUR_EYES", "1")
        p = client.get(f"{API}/policy", headers=h(team.stranger)).json()
        assert p["four_eyes"] is True and p["source"] == "environment"
        for key, body in ((OPERATOR_KEY, {"four_eyes": False, "owner": team.id}), (team.proposer, {"four_eyes": False})):
            assert client.put(f"{API}/policy", headers=h(key), json=body).status_code in (403, 409)
        card = propose(client, team.proposer, conn["id"]).json()
        assert approve(client, team.proposer, card["plan"]["id"]).status_code == 403

    def test_a_policy_change_is_audited(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        events = [e for e in audit_events(client, team.proposer) if e["event_type"] == "policy_change"]
        assert len(events) == 1 and events[0]["details"]["four_eyes_before"] is False
        assert events[0]["details"]["four_eyes_after"] is True and events[0]["details"]["owner"] == team.id


# ───────────────────────────── enforcement ─────────────────────────────


class TestIndependentApprover:
    def test_the_proposers_own_key_cannot_approve_and_nothing_runs(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        r = approve(client, team.proposer, pid)
        assert r.status_code == 403 and "four_eyes_required" in r.json()["detail"] and "same API key" in r.json()["detail"]
        assert rows() == 0
        assert client.get(f"{API}/plan/{pid}", headers=h(team.proposer)).json()["status"] == "pending_approval"

    def test_a_label_is_not_an_identity(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"], actor="alice").json()["plan"]["id"]
        # same key, a different X-NB-Actor and X-NB-Session: still the same principal
        r = client.post(f"{API}/plan/{pid}/approve", headers={**h(team.proposer, actor="bob"), "X-NB-Session": "other"})
        assert r.status_code == 403 and rows() == 0
        # a different KEY under the proposer's own actor label is independent
        assert approve(client, team.approver, pid, actor="alice").status_code == 200

    def test_a_second_key_approves_executes_once_and_the_decision_is_recorded(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        r = approve(client, team.approver, pid, actor="carol")
        assert r.status_code == 200 and r.json()["approved_by"].endswith("carol")
        assert rows() == 1
        row = sql("SELECT * FROM plans WHERE id=?", pid)[0]
        assert row["status"] == "executed" and row["four_eyes"] == 1
        assert row["proposed_key_ref"] and row["decided_key_ref"] and row["proposed_key_ref"] != row["decided_key_ref"]
        assert len(row["decided_key_ref"]) == 16 and team.approver not in json.dumps(dict(row))  # a fingerprint, never the key
        assert datetime.fromisoformat(row["decided_at"]) <= datetime.now(UTC)
        ev = [e for e in audit_events(client, team.proposer) if e["event_type"] == "plan_approve" and e["result"] == "success"]
        assert ev[0]["details"]["approver_key_ref"] == row["decided_key_ref"] and ev[0]["details"]["four_eyes"] is True

    def test_repeated_and_concurrent_approvals_execute_exactly_once(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        codes: list[int] = []
        barrier = threading.Barrier(6)

        def go() -> None:
            barrier.wait()
            codes.append(approve(client, team.approver, pid).status_code)

        threads = [threading.Thread(target=go) for _ in range(6)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        assert Counter(codes) == {200: 1, 409: 5}, codes
        assert rows() == 1
        assert approve(client, team.approver, pid).status_code == 409 and rows() == 1

    def test_a_denied_plan_never_executes(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        d = client.post(f"{API}/plan/{pid}/deny", headers=h(team.approver), params={"reason": "no"})
        assert d.status_code == 200 and d.json()["status"] == "denied"
        assert approve(client, team.approver, pid).status_code == 409
        assert approve(client, team.proposer, pid).status_code == 409
        assert rows() == 0

    def test_an_expired_plan_never_executes_and_is_reported_expired(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        sql("UPDATE plans SET expires_at=? WHERE id=?", past, pid)
        r = approve(client, team.approver, pid)
        assert r.status_code == 409 and "expired" in r.json()["detail"]
        assert rows() == 0
        plan = client.get(f"{API}/plan/{pid}", headers=h(team.proposer)).json()
        assert plan["status"] == "expired"
        assert approve(client, team.approver, pid).status_code == 409 and rows() == 0
        assert sql("SELECT decided_by FROM plans WHERE id=?", pid)[0][0] == "system:expired"

    def test_an_unexpired_plan_can_still_be_approved_at_the_edge(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        sql("UPDATE plans SET expires_at=? WHERE id=?", (datetime.now(UTC) + timedelta(seconds=30)).isoformat(), pid)
        assert approve(client, team.approver, pid).status_code == 200

    def test_tenant_boundaries_hold(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        # an independent key of ANOTHER tenant is not an approver: the plan does not exist for it
        assert approve(client, team.stranger, pid).status_code == 404
        assert client.get(f"{API}/plan/{pid}", headers=h(team.stranger)).status_code == 404
        assert client.post(f"{API}/plan/{pid}/deny", headers=h(team.stranger)).status_code == 404
        assert rows() == 0
        assert client.get(f"{API}/plan/{pid}", headers=h(team.proposer)).json()["status"] == "pending_approval"

    def test_the_setting_in_force_when_proposed_cannot_be_loosened_for_that_plan(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        client.put(f"{API}/policy", headers=h(OPERATOR_KEY), json={"four_eyes": False, "owner": team.id})
        assert approve(client, team.proposer, pid).status_code == 403
        assert approve(client, team.approver, pid).status_code == 200

    def test_switching_it_on_tightens_plans_already_waiting(self, client, team, conn) -> None:
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]  # policy off at proposal time
        policy_on(client, team.proposer)
        assert approve(client, team.proposer, pid).status_code == 403
        assert approve(client, team.approver, pid).status_code == 200

    def test_a_plan_with_no_recorded_proposer_cannot_be_approved_under_four_eyes(self, client, team, conn) -> None:
        from neuralbridge.ai.store import AiStore, PlanRecord

        pid = "legacy-plan"  # e.g. a plan written before the proposer's key was recorded
        AiStore(store_path()).create_plan(PlanRecord(
            id=pid, connection_id=conn["id"], adapter_type="postgres", operation="execute_sql",
            operation_class="write", params={"sql": "INSERT INTO fe_t VALUES ('legacy')"},
            proposed_by="agent", owner=team.id))
        policy_on(client, team.proposer)
        r = approve(client, team.approver, pid)
        assert r.status_code == 403 and "independence cannot be shown" in r.json()["detail"]
        assert rows() == 0

    def test_a_refused_approval_is_audited_with_actor_and_tenant(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        approve(client, team.proposer, pid)
        refusals = [e for e in audit_events(client, team.proposer)
                    if e["event_type"] == "plan_approve" and e["result"] == "refused:403"]
        assert refusals and refusals[0]["details"]["owner"] == team.id and refusals[0]["actor"].startswith("human_session:")


class TestIndependenceRule:
    """The rule itself, including cases the HTTP fixtures cannot mint (operator-bound keys, no key)."""

    def test_the_rule(self) -> None:
        a = CallerRef(key_ref="aaaa", operator="")
        assert independence_problem("aaaa", "", CallerRef("aaaa")) is not None
        assert independence_problem("aaaa", "", CallerRef("bbbb")) is None
        assert independence_problem("aaaa", "op_1", CallerRef("bbbb", "op_1")) is not None, "two keys, one operator"
        assert independence_problem("aaaa", "op_1", CallerRef("bbbb", "op_2")) is None
        assert independence_problem("aaaa", "", CallerRef("bbbb", "op_2")) is None
        assert independence_problem("", "", CallerRef("bbbb")) is not None, "an unidentified proposer"
        assert independence_problem("aaaa", "", CallerRef("")) is not None, "an unidentified approver"
        assert a.key_ref == "aaaa"

    def test_a_caller_ref_is_a_fingerprint_not_the_key(self) -> None:
        from assurance.billing.accounts import Principal

        ref = CallerRef.from_request("secret-key-value", Principal(account=None, key_prefix="x"))
        assert len(ref.key_ref) == 16 and "secret" not in ref.key_ref
        assert CallerRef.from_request(None, Principal(account=None, key_prefix="")).key_ref == ""
        assert CallerRef.from_request("  ", Principal(account=None, key_prefix="")).key_ref == ""


# ───────────────────────────── immutability in the store ─────────────────────────────


class TestApprovalRecordIsImmutable:
    def _executed_plan(self, client, team, conn) -> str:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        assert approve(client, team.approver, pid).status_code == 200
        return pid

    @pytest.mark.parametrize("column,value", [
        ("decided_by", "human_session:someone-else"), ("decided_at", "2001-01-01T00:00:00+00:00"),
        ("decided_key_ref", "0000000000000000"), ("proposed_key_ref", "1111111111111111"),
        ("proposed_by", "agent:forged"), ("owner", "someone-else"), ("four_eyes", 0),
    ])
    def test_the_store_refuses_to_rewrite_who_decided_and_when(self, client, team, conn, column, value) -> None:
        pid = self._executed_plan(client, team, conn)
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            sql(f"UPDATE plans SET {column}=? WHERE id=?", value, pid)

    def test_a_denied_plans_decision_is_immutable_too(self, client, team, conn) -> None:
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        client.post(f"{API}/plan/{pid}/deny", headers=h(team.proposer))
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            sql("UPDATE plans SET decided_by='x' WHERE id=?", pid)

    def test_the_proposer_and_the_policy_flag_cannot_be_rewritten_while_pending(self, client, team, conn) -> None:
        policy_on(client, team.proposer)
        pid = propose(client, team.proposer, conn["id"]).json()["plan"]["id"]
        for column, value in (("four_eyes", 0), ("proposed_key_ref", "x"), ("owner", "y")):
            with pytest.raises(sqlite3.DatabaseError, match="immutable"):
                sql(f"UPDATE plans SET {column}=? WHERE id=?", value, pid)

    def test_releasing_a_claim_that_never_ran_is_still_possible(self, tmp_path) -> None:
        from neuralbridge.ai.store import AiStore, PlanRecord

        s = AiStore(tmp_path / "s.db")
        s.create_plan(PlanRecord(id="p", connection_id="c", adapter_type="postgres", operation="execute_sql",
                                 operation_class="write", params={}, proposed_by="a", owner="o", four_eyes=True))
        assert s.transition_plan("p", expected="pending_approval", status="approved", decided_by="b",
                                 decided_at="2026-01-01T00:00:00+00:00", decided_key_ref="k") is not None
        back = s.transition_plan("p", expected="approved", status="pending_approval", reset_decision=True)
        assert back is not None and back.decided_by is None and back.decided_key_ref is None
