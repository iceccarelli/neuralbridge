"""Article 14 human decisions are bound to a credential, not to a field the caller types.

``actor.kind`` in the request body defaults to ``person`` and the caller sets it, so a
check on it alone let ANY account-level key (an agent, an MCP client) start the statutory
clock, make the reportability call and record filings by writing a name. Awareness (and its
supersession), triage and filings now follow the change workflow's rule: an individual
operator key with the ``decider`` role is attributed to that operator (the body cannot name
someone else, and ``kind`` is ignored); an account-level key proves only the account and is
refused (403); open mode and the deployer's own operator key keep declared names.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

AWARE = "2026-09-19T06:30:00Z"
OPKEY = "operator-key-do-not-ship-0123456789abcdef0123456789"


@pytest.fixture
def world(tmp_path, monkeypatch):
    for k, v in {
        "ASSURANCE_LEDGER": str(tmp_path / "op.db"),
        "ASSURANCE_ACCOUNTS": str(tmp_path / "acc.db"),
        "ASSURANCE_TENANT_LEDGERS": str(tmp_path / "tenants"),
        "ASSURANCE_API_KEYS": OPKEY,
    }.items():
        monkeypatch.setenv(k, v)
    from assurance.api import deps

    deps._register_for.cache_clear()
    for name in ("get_accounts", "_tenant_register_for"):
        fn = getattr(deps, name, None)
        if hasattr(fn, "cache_clear"):
            fn.cache_clear()
    module = importlib.import_module("assurance.api.service")
    with TestClient(module.create_app(), raise_server_exceptions=False) as client:
        accounts = deps.get_accounts()
        acct = accounts.upsert_account(email="a@example.com", tier="cell", company="c",
                                       stripe_customer_id="cus_a", stripe_subscription_id="sub_a",
                                       status="active")
        account_key = accounts.issue_key(acct.id)
        _, decider = accounts.create_operator(acct.id, "Maria Rossi", "decider")
        _, analyst = accounts.create_operator(acct.id, "Ana Lyst", "contributor")
        yield client, {"account": account_key, "decider": decider, "analyst": analyst}


def _h(key):
    return {"X-API-Key": key}


def _signal(client, key, case):
    r = client.post(f"/v1/cases/{case}/signal", headers=_h(key), json={
        "received_at": "2026-09-18T21:40:00Z", "channel": "other", "description": "d",
        "actor": {"identifier": "monitor", "kind": "automation"}})
    assert r.status_code == 201, r.text


def _aware_body(actor):
    return {"established_at": AWARE, "assessment_started_at": "2026-09-18T22:05:00Z",
            "assessment_completed_at": AWARE, "track": "actively_exploited_vulnerability",
            "reasoning": "x", "actor": actor}


def _length(client, key):
    return client.get("/v1/ledger/verify", headers=_h(key)).json()["attestation"]["length"]


@pytest.mark.parametrize("claim", [
    {"identifier": "Maria Rossi"},
    {"identifier": "Maria Rossi", "kind": "person"},
    {"identifier": "an agent pretending", "kind": "person"},
])
def test_an_account_level_key_cannot_record_awareness_whatever_it_claims(world, claim):
    client, keys = world
    _signal(client, keys["account"], "C1")
    n = _length(client, keys["account"])
    r = client.post("/v1/cases/C1/awareness", headers=_h(keys["account"]),
                    json=_aware_body(claim))
    assert r.status_code == 403 and r.json()["detail"]["error"] == "operator_required"
    assert _length(client, keys["account"]) == n


def test_an_account_level_key_cannot_triage_supersede_or_file(world):
    client, keys = world
    _signal(client, keys["account"], "C2")
    claim = {"identifier": "Maria Rossi", "kind": "person"}
    n = _length(client, keys["account"])
    for path, body in [
        ("triage", {"answers": {}, "actor": claim}),
        ("awareness/supersede", {**{k: v for k, v in _aware_body(claim).items() if k != "track"},
                                 "reason": "r", "supersedes": "a" * 12}),
        ("filings", {"stage": "early_warning", "submitted_at": AWARE, "payload": {},
                     "actor": claim}),
    ]:
        r = client.post(f"/v1/cases/C2/{path}", headers=_h(keys["account"]), json=body)
        assert r.status_code == 403, (path, r.status_code, r.text)
    assert _length(client, keys["account"]) == n


def test_a_decider_operator_records_awareness_attributed_to_the_operator(world):
    client, keys = world
    _signal(client, keys["decider"], "C3")
    r = client.post("/v1/cases/C3/awareness", headers=_h(keys["decider"]),
                    json=_aware_body({"identifier": "Maria Rossi", "kind": "automation"}))
    assert r.status_code == 201, r.text           # the body's kind is ignored
    history = client.get("/v1/cases/C3/history", headers=_h(keys["decider"])).text
    assert "authenticated_operator" in history


def test_an_operator_key_cannot_record_a_decision_in_someone_elses_name(world):
    client, keys = world
    _signal(client, keys["decider"], "C4")
    r = client.post("/v1/cases/C4/awareness", headers=_h(keys["decider"]),
                    json=_aware_body({"identifier": "Somebody Else"}))
    assert r.status_code == 403 and r.json()["detail"]["error"] == "actor_mismatch"


def test_a_non_decider_operator_cannot_decide(world):
    client, keys = world
    _signal(client, keys["analyst"], "C5")
    r = client.post("/v1/cases/C5/awareness", headers=_h(keys["analyst"]),
                    json=_aware_body({"identifier": "Ana Lyst"}))
    assert r.status_code == 403


def test_the_deployers_own_operator_key_still_works_with_a_declared_person(world):
    client, _ = world[0], world[1]
    _signal(client, OPKEY, "C6")
    r = client.post("/v1/cases/C6/awareness", headers=_h(OPKEY),
                    json=_aware_body({"identifier": "m.braun", "role": "Lead"}))
    assert r.status_code == 201, r.text
