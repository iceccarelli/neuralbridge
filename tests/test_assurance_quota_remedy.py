"""The 429 remedy tells the truth about THIS caller's plan and THIS route.

``/v1/evidence/verify`` is a daily guard (``spend()``), not a billed scope, yet
its 429 used to tell an account already on pay-as-you-go to "use pay-as-you-go",
which does not bill that route at all.
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing.accounts import AccountStore
from assurance.billing.plans import PLANS

ALLOWANCE = PLANS["free"].validations_per_day
VALIDATE = {"track": "actively_exploited_vulnerability", "stage": "early_warning",
            "payload": {}}
PAYG_PHRASE = "bills operations beyond the allowance"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", "operator-key-remedy")
    for name in ("ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL",
                 "ASSURANCE_TENANT_LEDGERS", "ASSURANCE_TRUST_FLY_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_payg_test")
    monkeypatch.setenv("ASSURANCE_PAYG_METER_EVENT", "nb_verification_ops")
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def store(env):
    return AccountStore(env / "accounts.db")


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


def account_and_headers(store, tier, *, customer=True, email="r@example.de"):
    account = store.upsert_account(
        email=email, tier=tier, stripe_customer_id=f"cus_{email}" if customer else "")
    return account, {"X-API-Key": store.issue_key(account.id)}


def exhaust_verify(store, account):
    for _ in range(ALLOWANCE):
        store.consume(account.id, "evidence_verify", ALLOWANCE, account.tier)


def verify_429(client, headers):
    r = client.post("/v1/evidence/verify", content=b"{}", headers={
        **headers, "content-type": "application/json"})
    assert r.status_code == 429, r.text
    return r.json()["detail"]


class TestEvidenceVerifyRemedy:
    def test_a_payg_account_is_not_told_to_move_to_payg(self, client, store):
        account, headers = account_and_headers(store, "payg")
        exhaust_verify(store, account)
        detail = verify_429(client, headers)
        remedy = detail["remedy"]
        assert PAYG_PHRASE not in remedy and "tier payg" not in remedy
        assert "not billed" in remedy.lower()
        assert "Register" in remedy or "Cell" in remedy      # a real way out is still named
        assert detail["tier"] == "payg" and detail["retry_after_seconds"] > 0

    def test_a_free_account_is_not_promised_billing_on_a_route_that_is_not_billed(
            self, client, store):
        account, headers = account_and_headers(store, "free", customer=False)
        exhaust_verify(store, account)
        remedy = verify_429(client, headers)["remedy"]
        assert PAYG_PHRASE not in remedy and "not billed" in remedy.lower()
        assert "GET /v1/plans" in remedy and "POST /v1/checkout" in remedy


class TestBilledScopeRemedy:
    def test_a_free_account_over_a_billed_scope_is_still_offered_payg(self, client, store):
        account, headers = account_and_headers(store, "free")
        for i in range(ALLOWANCE):
            store.record_usage(account.id, "validate", 1, f"k-{i}")
        r = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert r.status_code == 429, r.text
        assert PAYG_PHRASE in r.json()["detail"]["remedy"]

    def test_a_payg_account_whose_billing_is_not_active_is_not_told_to_choose_payg(
            self, client, store):
        # payg tier but no Stripe customer: overage is not allowed, so the
        # allowance is a hard cap. Suggesting the plan it is already on is wrong.
        account, headers = account_and_headers(store, "payg", customer=False)
        for i in range(ALLOWANCE):
            store.record_usage(account.id, "validate", 1, f"k-{i}")
        r = client.post("/v1/spec/validate", json=VALIDATE, headers=headers)
        assert r.status_code == 429, r.text
        remedy = r.json()["detail"]["remedy"]
        assert PAYG_PHRASE not in remedy and "tier payg" not in remedy
        assert "pay-as-you-go" in remedy.lower() and "GET /v1/usage" in remedy
