"""A Register-only account can make the decisions the Register plan lists, end to end.

The Register plan lists the Article 14 register: awareness, triage and filings. Those need an
individual operator with the ``decider`` role, and ``POST /v1/operators`` used to be Cell-only,
so a Register account could not make the decisions it was sold. Operators are now gated at the
Register plan (``deps.RegisteredAccount``, enforced in the backend); machine verification stays Cell.

Every test goes through the real HTTP app. Nothing here widens Register beyond the operator
routes: the negative tests pin what Register, a free account and a lapsed account still cannot do.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

AWARE = "2026-09-19T06:30:00Z"
OPKEY = "operator-key-register-decisions-0123456789abcdef"


def _h(key):
    return {"X-API-Key": key}


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

    caches = (deps._register_for, deps._tenant_register_for, deps._accounts_for)
    for cache in caches:
        cache.cache_clear()
    module = importlib.import_module("assurance.api.service")
    with TestClient(module.create_app(), raise_server_exceptions=False) as client:
        store = deps.get_accounts()

        def make(email, tier, status="active"):
            acct = store.upsert_account(email=email, tier=tier, company=email,
                                        stripe_customer_id=f"cus_{email}",
                                        stripe_subscription_id=f"sub_{email}", status=status)
            return acct, store.issue_key(acct.id)

        yield client, make, store
    for cache in caches:
        cache.cache_clear()


def _signal(client, key, case):
    r = client.post(f"/v1/cases/{case}/signal", headers=_h(key), json={
        "received_at": "2026-09-18T21:40:00Z", "channel": "other", "description": "d",
        "actor": {"identifier": "monitor", "kind": "automation"}})
    assert r.status_code == 201, r.text


def _aware(actor):
    return {"established_at": AWARE, "assessment_started_at": "2026-09-18T22:05:00Z",
            "assessment_completed_at": AWARE, "track": "actively_exploited_vulnerability",
            "reasoning": "x", "actor": actor}


def _operator(client, key, name, role="decider"):
    return client.post("/v1/operators", headers=_h(key), json={"name": name, "role": role})


# --- the positive path: Register alone is enough to decide --------------------------------------
def test_a_register_account_bootstraps_a_decider_and_records_awareness(world):
    client, make, _ = world
    _, account_key = make("reg@example.de", "register")

    # the account key alone is refused a human decision (unchanged) ...
    _signal(client, account_key, "C1")
    refused = client.post("/v1/cases/C1/awareness", headers=_h(account_key),
                          json=_aware({"identifier": "Maria Rossi", "kind": "person"}))
    assert refused.status_code == 403 and refused.json()["detail"]["error"] == "operator_required"

    # ... the first operator is created over HTTP on a Register plan, and must be a decider
    contributor_first = _operator(client, account_key, "Ana Lyst", "contributor")
    assert contributor_first.status_code == 422
    assert contributor_first.json()["detail"]["error"] == "first_operator_must_decide"
    created = _operator(client, account_key, "Maria Rossi")
    assert created.status_code == 201, created.text
    decider_key = created.json()["api_key"]

    # and that operator's key makes the decision, attributed to that operator by the server
    done = client.post("/v1/cases/C1/awareness", headers=_h(decider_key),
                       json=_aware({"identifier": "Maria Rossi", "kind": "person"}))
    assert done.status_code in (200, 201), done.text
    listed = client.get("/v1/operators", headers=_h(decider_key)).json()
    assert [o["name"] for o in listed["operators"]] == ["Maria Rossi"]
    assert listed["you"]["role"] == "decider"


def test_four_eyes_on_a_register_account_a_contributor_cannot_decide_or_manage(world):
    client, make, _ = world
    _, account_key = make("reg@example.de", "register")
    decider = _operator(client, account_key, "Maria Rossi").json()["api_key"]
    created = _operator(client, decider, "Ana Lyst", "contributor")
    assert created.status_code == 201
    contributor = created.json()["api_key"]
    _signal(client, account_key, "C2")

    r = client.post("/v1/cases/C2/awareness", headers=_h(contributor),
                    json=_aware({"identifier": "Ana Lyst", "kind": "person"}))
    assert r.status_code == 403
    assert _operator(client, contributor, "Mallory").status_code == 403
    # an account-level key cannot mint a second decider once an operator exists
    again = _operator(client, account_key, "Mallory")
    assert again.status_code == 403 and again.json()["detail"]["error"] == "decider_role_required"
    # and a decider cannot put a different name on the decision
    wrong = client.post("/v1/cases/C2/awareness", headers=_h(decider),
                        json=_aware({"identifier": "Someone Else", "kind": "person"}))
    assert wrong.status_code == 403 and wrong.json()["detail"]["error"] == "actor_mismatch"


def test_the_last_decider_on_a_register_account_cannot_be_disabled(world):
    client, make, _ = world
    _, account_key = make("reg@example.de", "register")
    created = _operator(client, account_key, "Maria Rossi").json()
    r = client.post(f"/v1/operators/{created['operator_id']}/disable",
                    headers=_h(created["api_key"]))
    assert r.status_code == 409 and r.json()["detail"]["error"] == "last_decider"


# --- tenant isolation ---------------------------------------------------------------------------
def test_register_operators_are_private_to_their_account(world):
    client, make, _ = world
    _, key_a = make("a@example.de", "register")
    _, key_b = make("b@example.de", "register")
    op_a = _operator(client, key_a, "Maria Rossi").json()
    op_b = _operator(client, key_b, "Bruno Bauer").json()

    assert [o["name"] for o in client.get("/v1/operators", headers=_h(op_a["api_key"]))
            .json()["operators"]] == ["Maria Rossi"]
    # B cannot disable A's operator, and A's decider cannot decide on B's ledger
    r = client.post(f"/v1/operators/{op_a['operator_id']}/disable", headers=_h(op_b["api_key"]))
    assert r.status_code in (404, 409)
    assert client.get("/v1/operators", headers=_h(op_a["api_key"])).json()["operators"][0][
        "name"] == "Maria Rossi"
    _signal(client, key_b, "B-ONLY")
    cross = client.post("/v1/cases/B-ONLY/awareness", headers=_h(op_a["api_key"]),
                        json=_aware({"identifier": "Maria Rossi", "kind": "person"}))
    assert cross.status_code >= 400


# --- the entitlement boundary is enforced in the backend, and did not move ----------------------
def test_register_still_gets_402_on_machine_verification_and_the_machinery_routes(world):
    client, make, _ = world
    _, key = make("reg@example.de", "register")
    for method, path in (("POST", "/v1/machine/verify"), ("GET", "/v1/machinery/export"),
                         ("POST", "/v1/machinery/passport/check-ledger"),
                         ("POST", "/v1/machinery/coverage")):
        r = client.request(method, path, headers=_h(key), json={} if method == "POST" else None)
        assert r.status_code == 402, (path, r.status_code, r.text)


@pytest.mark.parametrize("method,path", [
    ("GET", "/v1/operators"), ("POST", "/v1/operators"),
    ("POST", "/v1/operators/anything/disable")])
def test_no_key_a_bad_key_and_a_free_account_do_not_reach_the_operator_routes(world, method, path):
    client, make, _ = world
    body = {"name": "X Person", "role": "decider"} if method == "POST" else None
    assert client.request(method, path, json=body).status_code == 401
    assert client.request(method, path, headers=_h("asr_nope"), json=body).status_code == 401
    _, free_key = make("free@example.de", "free")
    r = client.request(method, path, headers=_h(free_key), json=body)
    assert r.status_code == 402, (r.status_code, r.text)


def test_a_cancelled_register_account_cannot_create_operators(world):
    client, make, _ = world
    _, key = make("gone@example.de", "register", status="cancelled")
    r = _operator(client, key, "Maria Rossi")
    assert r.status_code == 402, (r.status_code, r.text)


def test_the_platform_operator_key_still_cannot_make_or_disable_operators(world):
    client, _, _ = world
    r = _operator(client, OPKEY, "Maria Rossi")
    assert r.status_code == 403 and r.json()["detail"]["error"] == "account_required"


def test_cell_accounts_are_unchanged(world):
    client, make, _ = world
    _, key = make("cell@example.de", "cell")
    created = _operator(client, key, "Maria Rossi")
    assert created.status_code == 201
    assert client.get("/v1/operators", headers=_h(created.json()["api_key"])).status_code == 200
