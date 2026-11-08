# ruff: noqa: F811, F401  (fixtures are imported by name)
"""Four-eyes needs two NAMED operators; an account-level key cannot take either part.

An independent red team proposed a write with one account key, minted a second account key
(``POST /v1/keys``, any holder may) and approved with it: 403 then 201 then 200, the INSERT ran.
Comparing key fingerprints proved two strings differed, not two people. An account-level key proves
the account (``Principal``); only an operator-bound key names someone, and an account-level key can
create just the account's first operator, so one holder cannot manufacture two.
"""

from __future__ import annotations

import pytest

from assurance.billing.accounts import AccountStore

from .platform_support import API, bind, client, env, h, requires_postgres
from .test_ai_four_eyes import approve, conn, policy_on, propose, rows, table, team

pytestmark = requires_postgres


def test_an_account_level_key_cannot_propose_under_four_eyes(client, team, table):
    cid = bind(client, team.service, "svc")["id"]
    policy_on(client, team.service)
    r = propose(client, team.service, cid)
    assert r.status_code == 403
    assert "four_eyes_required" in r.text and "named operator" in r.text


def test_the_red_team_attack_a_freshly_minted_account_key_cannot_approve(client, team, table, env):
    cid = bind(client, team.proposer, "fe")["id"]
    policy_on(client, team.proposer)
    plan = propose(client, team.proposer, cid).json()["plan"]["id"]
    minted = AccountStore(str(env)).issue_key(team.id, label="minted-a-moment-ago")   # what POST /v1/keys does
    before = rows()
    r = approve(client, minted, plan)
    assert r.status_code == 403 and "named operator" in r.text
    assert rows() == before, "the write must not have executed"


def test_a_plan_proposed_with_an_account_level_key_cannot_be_approved_by_a_named_operator(
        client, team, table):
    cid = bind(client, team.service, "svc")["id"]
    plan = propose(client, team.service, cid).json()["plan"]["id"]      # proposed BEFORE four-eyes was on
    policy_on(client, team.service)                               # tightened afterwards
    r = approve(client, team.approver, plan)
    assert r.status_code == 403 and "account-level key" in r.text


def test_two_different_named_operators_still_approve(client, team, table):
    cid = bind(client, team.proposer, "fe")["id"]
    policy_on(client, team.proposer)
    plan = propose(client, team.proposer, cid, "ok").json()["plan"]["id"]
    before = rows()
    assert approve(client, team.approver, plan).status_code == 200
    assert rows() == before + 1


def test_the_same_named_operator_cannot_approve_its_own_plan_with_another_key(client, team, table, env):
    cid = bind(client, team.proposer, "fe")["id"]
    policy_on(client, team.proposer)
    plan = propose(client, team.proposer, cid).json()["plan"]["id"]
    r = approve(client, team.proposer, plan)
    assert r.status_code == 403


def test_with_four_eyes_off_an_account_level_key_still_works(client, team, table):
    """The default is unchanged: nothing here is a new requirement unless an account turns it on."""
    cid = bind(client, team.service, "svc")["id"]
    plan = propose(client, team.service, cid).json()["plan"]["id"]
    assert approve(client, team.service, plan).status_code == 200
