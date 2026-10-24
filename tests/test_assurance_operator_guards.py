"""Operators and keys: an agent holding an account-level key cannot get itself a decider.

Pins the second review's findings B-F1 and B-F2. Each test failed before the guard:

* B-F1: disabling the only decider re-opened the "no operators" bootstrap, so any
  account-level key (an agent, the watch, an MCP client) could then mint a decider
  of its own and decide cases.
* B-F2: ``POST /v1/keys`` accepted an operator-bound key and minted an unattributed
  account-level key; ``POST /v1/keys/revoke`` let an account-level key revoke a
  decider's key, locking the humans out with no API recovery.
"""

from __future__ import annotations

from tests import test_assurance_watch_report as wr

_env = wr._env
_client = wr._client
_accounts = wr._accounts
_cell = wr._cell


def _op(client, headers, name, role="decider"):
    r = client.post("/v1/operators", headers=headers, json={"name": name, "role": role})
    assert r.status_code == 201, r.text
    return {"X-API-Key": r.json()["api_key"]}, r.json()["operator_id"]


def _decision(client, headers, case_id="CASE-NONE"):
    return client.post(f"/v1/change/cases/{case_id}/decision", headers=headers,
                       json={"disposition": "rejected", "reason": "r"})


class TestLastDecider:
    def test_the_only_decider_cannot_be_disabled(self, client, cell):
        _, h = cell
        boss, boss_id = _op(client, h, "Boss")
        r = client.post(f"/v1/operators/{boss_id}/disable", headers=boss)
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "last_decider"
        assert "create another decider" in detail["detail"].lower()
        # nothing changed: Boss still authenticates and is still enabled
        assert client.get("/v1/operators", headers=boss).status_code == 200
        ops = client.get("/v1/operators", headers=h).json()["operators"]
        assert [o["disabled"] for o in ops] == [False]

    def test_a_decider_can_be_disabled_once_another_exists(self, client, cell):
        _, h = cell
        boss, boss_id = _op(client, h, "Boss")
        boss2, _ = _op(client, boss, "Boss2")
        r = client.post(f"/v1/operators/{boss_id}/disable", headers=boss2)
        assert r.status_code == 200 and r.json()["outcome"] == "disabled"
        # and now Boss2 is the last one
        ops = client.get("/v1/operators", headers=h).json()["operators"]
        b2 = next(o for o in ops if o["name"] == "Boss2")["id"]
        assert client.post(f"/v1/operators/{b2}/disable", headers=boss2).status_code == 409

    def test_a_contributor_may_always_be_disabled(self, client, cell):
        _, h = cell
        boss, _ = _op(client, h, "Boss")
        _, lena_id = _op(client, boss, "Lena", "contributor")
        r = client.post(f"/v1/operators/{lena_id}/disable", headers=boss)
        assert r.status_code == 200 and r.json()["outcome"] == "disabled"

    def test_an_account_key_cannot_mint_a_decider_after_every_operator_is_gone(
            self, client, cell):
        """The reviewer's repro: the bootstrap is one-shot, not 'no active operators'."""
        acct, h = cell
        _op(client, h, "Boss")
        # A state an earlier build could reach: every operator disabled. The bootstrap
        # must not re-open.
        store = wr.deps.get_accounts()
        with store._txn() as db:
            db.execute("UPDATE operators SET disabled_at='2026-01-01T00:00:00Z' "
                       "WHERE account_id=?", (acct.id,))
        r = client.post("/v1/operators", headers=h, json={"name": "Mallory", "role": "decider"})
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "decider_role_required"

    def test_an_account_that_never_had_an_operator_can_still_bootstrap(self, client, cell):
        _, h = cell
        r = client.post("/v1/operators", headers=h, json={"name": "Boss", "role": "decider"})
        assert r.status_code == 201


class TestKeyManagementAndOperators:
    def test_a_contributor_key_cannot_mint_an_account_level_key(self, client, cell):
        _, h = cell
        boss, _ = _op(client, h, "Boss")
        lena, _ = _op(client, boss, "Lena", "contributor")
        before = client.get("/v1/keys", headers=h).json()["active"]
        r = client.post("/v1/keys", headers=lena, json={})
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "decider_role_required"
        assert client.get("/v1/keys", headers=h).json()["active"] == before

    def test_a_decider_may_mint_and_the_label_records_who(self, client, cell):
        _, h = cell
        boss, boss_id = _op(client, h, "Boss")
        r = client.post("/v1/keys", headers=boss, json={"label": "ci"})
        assert r.status_code == 201, r.text
        listing = client.get("/v1/keys", headers=h).json()["keys"]
        minted = next(k for k in listing if k["prefix"] == r.json()["prefix"])
        assert "Boss" in minted["label"] and boss_id in minted["label"]
        # the minted key is account-level: it still cannot make a decision
        assert _decision(client, {"X-API-Key": r.json()["api_key"]}).status_code == 403

    def test_an_account_key_cannot_revoke_an_operators_key(self, client, cell):
        _, h = cell
        boss, _ = _op(client, h, "Boss")
        boss_key = boss["X-API-Key"]
        r = client.post("/v1/keys/revoke", headers=h, json={"key_prefix": boss_key[:10]})
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "operator_key"
        assert "/v1/operators/" in detail["detail"]
        assert client.get("/v1/operators", headers=boss).status_code == 200

    def test_an_operator_key_cannot_revoke_itself_over_the_keys_route(self, client, cell):
        _, h = cell
        boss, _ = _op(client, h, "Boss")
        r = client.post("/v1/keys/revoke", headers=boss)
        assert r.status_code == 409 and r.json()["detail"]["error"] == "operator_key"
        assert client.get("/v1/operators", headers=boss).status_code == 200

    def test_a_contributor_cannot_revoke_an_account_key(self, client, cell):
        _, h = cell
        boss, _ = _op(client, h, "Boss")
        lena, _ = _op(client, boss, "Lena", "contributor")
        prefix = h["X-API-Key"][:10]
        r = client.post("/v1/keys/revoke", headers=lena, json={"key_prefix": prefix})
        assert r.status_code == 403, r.text
        assert client.get("/v1/keys", headers=h).status_code == 200

    def test_account_key_rotation_still_works(self, client, cell):
        _, h = cell
        new = client.post("/v1/keys", headers=h, json={"label": "rotate"})
        assert new.status_code == 201
        nh = {"X-API-Key": new.json()["api_key"]}
        assert client.post("/v1/keys/revoke", headers=nh,
                           json={"key_prefix": h["X-API-Key"][:10]}).status_code == 200
        assert client.get("/v1/keys", headers=h).status_code == 401

    def test_the_agent_cannot_lock_out_the_decider_then_mint_its_own(self, client, cell):
        _, h = cell
        boss, _ = _op(client, h, "Boss")
        client.post("/v1/keys/revoke", headers=h, json={"key_prefix": boss["X-API-Key"][:10]})
        r = client.post("/v1/operators", headers=h, json={"name": "Mallory", "role": "decider"})
        assert r.status_code == 403
        assert client.get("/v1/operators", headers=boss).status_code == 200
