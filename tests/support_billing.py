"""Signed Stripe webhook helpers and a real-app fixture, shared by the billing order tests.

Everything here is local: a throwaway signing secret, throwaway price ids, the real
FastAPI app on a temporary accounts database. No Stripe host is ever contacted.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import time
from itertools import count

import pytest
from fastapi.testclient import TestClient

WEBHOOK_SECRET = "whsec_throwaway_order_tests"
T = 1_800_000_000  # a fixed, far-from-now base for Stripe "created" stamps

_ids = count(1)


@pytest.fixture(name="billing_env")
def _billing_env_fixture(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("ASSURANCE_TENANT_LEDGERS", str(tmp_path / "tenants"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    for name in ("ASSURANCE_API_KEYS", "ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_TRUST_FLY_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", "price_reg_test")
    monkeypatch.setenv("ASSURANCE_PRICE_CELL", "price_cell_test")
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    deps._tenant_register_for.cache_clear()
    return tmp_path


@pytest.fixture(name="billing_client")
def _billing_client_fixture(billing_env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


def sign(raw: bytes, secret: str = WEBHOOK_SECRET, stamp: int | None = None) -> dict[str, str]:
    stamp_text = str(int(time.time()) if stamp is None else stamp)
    digest = hmac.new(secret.encode(), f"{stamp_text}.".encode() + raw, hashlib.sha256).hexdigest()
    return {"stripe-signature": f"t={stamp_text},v1={digest}", "content-type": "application/json"}


def send(client: TestClient, event: dict, **kw):
    raw = json.dumps(event).encode()
    return client.post("/v1/billing/webhook", content=raw, headers=sign(raw, **kw))


def evt(kind: str, obj: dict, created: int, event_id: str | None = None) -> dict:
    return {"id": event_id or f"evt_{next(_ids)}", "type": kind, "created": created,
            "data": {"object": obj}}


def checkout_event(session: str, customer: str, sub: str, tier: str, created: int,
                   email: str = "buyer@example.invalid", event_id: str | None = None) -> dict:
    return evt("checkout.session.completed", {
        "id": session, "payment_status": "paid", "customer": customer, "subscription": sub,
        "customer_details": {"email": email}, "metadata": {"tier": tier, "company": "Co"},
    }, created, event_id)


def subscription_event(kind: str, customer: str, sub: str, price: str, status: str,
                       created: int, event_id: str | None = None) -> dict:
    return evt(kind, {"id": sub, "customer": customer, "status": status,
                      "items": {"data": [{"price": {"id": price}}]}, "metadata": {}},
               created, event_id)


def payment_failed_event(customer: str, created: int, sub: str = "",
                         event_id: str | None = None) -> dict:
    obj: dict = {"customer": customer}
    if sub:
        obj["subscription"] = sub
    return evt("invoice.payment_failed", obj, created, event_id)


def collect_key(client: TestClient, session: str) -> str:
    r = client.get("/v1/checkout/complete", params={"session_id": session})
    assert r.status_code == 200, r.text
    return r.json()["api_key"]


def account_state(client: TestClient, key: str) -> tuple[str, str]:
    body = client.get("/v1/me", headers={"X-API-Key": key}).json()
    return body["account"]["status"], body["tier"]


def stored_state(accounts_dir, customer: str = "cus_1") -> tuple[str, str, str]:
    """The stored (status, tier, subscription) of the account, read straight from the store.

    ``/v1/me`` reports the *effective* tier (a lapsed account shows ``free``); the stored
    tier is what a returning subscription restores.
    """
    from assurance.billing.accounts import AccountStore

    acct = AccountStore.open_readonly(str(accounts_dir / "accounts.db")).account_by_customer(
        customer)
    assert acct is not None
    return acct.status, acct.tier, acct.stripe_subscription_id
