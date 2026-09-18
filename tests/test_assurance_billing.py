"""The paid loop.

This is the money path, so it is tested like one: what a prospect can do
without paying, what stops when they hit the cap, what paying changes, what
happens when they stop paying, and whether a key can be recovered from the
database by anyone who steals it.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
import json
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from assurance.billing.accounts import AccountStore
from assurance.billing.plans import PLANS

WEBHOOK_SECRET = "whsec_test_do_not_ship"
OPERATOR_KEY = "operator-key-test"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", WEBHOOK_SECRET)
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    monkeypatch.delenv("ASSURANCE_PRICE_REGISTER", raising=False)
    monkeypatch.delenv("ASSURANCE_PRICE_CELL", raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    return tmp_path


@pytest.fixture()
def client(env):
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


@pytest.fixture()
def store(env):
    return AccountStore(str(env / "accounts.db"))


def _payload(**over):
    body = {
        "notification_type": "Vulnerability",
        "title": "Unauthenticated command injection",
        "summary": "Reachable on FW 2.1.0-2.4.6.",
        "product_name": "SK-4200",
        "product_version": "FW 2.4.6",
        "member_states_available": ["DE", "AT"],
        "awareness_datetime": "2026-09-19T06:30:00Z",
    }
    body.update(over)
    return {
        "track": "actively_exploited_vulnerability",
        "stage": "early_warning",
        "payload": body,
    }


def _signed(body: dict) -> tuple[bytes, dict[str, str]]:
    raw = json.dumps(body).encode()
    stamp = str(int(time.time()))
    sig = hmac.new(WEBHOOK_SECRET.encode(), f"{stamp}.".encode() + raw, hashlib.sha256).hexdigest()
    return raw, {"stripe-signature": f"t={stamp},v1={sig}", "content-type": "application/json"}


def _checkout_event(session_id="cs_test_1", tier="register", customer="cus_1"):
    return {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": session_id,
                "customer": customer,
                "subscription": "sub_1",
                "customer_details": {"email": "m.braun@sk-maschinenbau.de"},
                "metadata": {"tier": tier, "company": "SK Maschinenbau GmbH"},
            }
        },
    }


class TestCatalogue:
    def test_plans_are_public(self, client):
        plans = client.get("/v1/plans").json()
        assert [p["tier"] for p in plans] == ["free", "register", "cell"]

    def test_limits_come_from_what_is_enforced(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert plans["free"]["limits"]["register_access"] is False
        assert plans["register"]["limits"]["register_access"] is True
        assert plans["free"]["limits"]["validations_per_day"] == PLANS["free"].validations_per_day
        assert plans["cell"]["limits"]["product_families"] is None

    def test_a_plan_with_no_configured_price_is_not_purchasable(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert plans["register"]["purchasable"] is False


class TestFreeTier:
    def test_the_validator_needs_no_account(self, client):
        response = client.post("/v1/spec/validate", json=_payload())
        assert response.status_code == 200
        assert response.json()["submittable"] is True
        assert response.headers["X-Assurance-Tier"] == "free"

    def test_the_field_spec_needs_no_account(self, client):
        response = client.get(
            "/v1/spec/fields",
            params={"track": "severe_incident", "stage": "early_warning"},
        )
        assert response.status_code == 200

    def test_the_validator_still_catches_the_switzerland_error(self, client):
        body = client.post(
            "/v1/spec/validate",
            json=_payload(member_states_available=["DE", "CH"]),
        ).json()
        assert body["submittable"] is False
        assert any("not EU Member States" in i["message"] for i in body["issues"])

    def test_the_daily_cap_is_enforced_and_says_what_to_do(self, client):
        limit = PLANS["free"].validations_per_day
        assert limit is not None
        for _ in range(limit):
            assert client.post("/v1/spec/validate", json=_payload()).status_code == 200
        blocked = client.post("/v1/spec/validate", json=_payload())
        assert blocked.status_code == 429
        detail = blocked.json()["detail"]
        assert detail["error"] == "quota_exceeded"
        assert detail["limit"] == limit
        assert "/v1/checkout" in detail["remedy"]

    def test_remaining_quota_is_reported(self, client):
        response = client.post("/v1/spec/validate", json=_payload())
        assert int(response.headers["X-Assurance-Quota-Remaining"]) == (
            PLANS["free"].validations_per_day - 1
        )


class TestRegisterIsGated:
    def test_no_key_is_a_401(self, client):
        assert client.get("/v1/cases").status_code in (401, 503)

    def test_a_free_tier_key_is_a_402_not_a_403(self, client, store):
        # The obstacle is payment, and the status code should say so.
        account = store.upsert_account(email="a@b.de", tier="free")
        key = store.issue_key(account.id)
        response = client.get("/v1/cases", headers={"X-API-Key": key})
        assert response.status_code == 402
        assert response.json()["detail"]["error"] == "plan_does_not_include_register"
        assert "/v1/plans" in response.json()["detail"]["remedy"]

    def test_a_register_key_gets_in(self, client, store):
        account = store.upsert_account(email="a@b.de", tier="register")
        key = store.issue_key(account.id)
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 200

    def test_an_unknown_key_is_a_401(self, client):
        assert client.get("/v1/cases", headers={"X-API-Key": "asr_nope"}).status_code == 401

    def test_a_revoked_key_stops_working(self, client, store):
        account = store.upsert_account(email="a@b.de", tier="register")
        key = store.issue_key(account.id)
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 200
        store.revoke_key(hashlib.sha256(key.encode()).hexdigest())
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 401

    def test_an_operator_key_still_works(self, env, monkeypatch):
        monkeypatch.setenv("ASSURANCE_API_KEYS", OPERATOR_KEY)
        from assurance.api import deps

        deps._register_for.cache_clear()
        deps._accounts_for.cache_clear()
        service = importlib.import_module("assurance.api.service")
        with TestClient(service.create_app()) as c:
            assert c.get("/v1/cases", headers={"X-API-Key": OPERATOR_KEY}).status_code == 200


class TestCheckout:
    def test_checkout_refuses_when_no_price_is_configured(self, client):
        # Better a 503 than taking money for something that cannot be provisioned.
        response = client.post(
            "/v1/checkout",
            json={"tier": "register", "email": "m.braun@example.de", "company": "SK"},
        )
        assert response.status_code == 503
        assert response.json()["detail"]["error"] == "price_not_configured"

    def test_a_malformed_email_is_rejected_before_stripe(self, client):
        response = client.post(
            "/v1/checkout", json={"tier": "register", "email": "not-an-email"}
        )
        assert response.status_code == 422

    def test_an_unknown_tier_is_rejected(self, client):
        response = client.post(
            "/v1/checkout", json={"tier": "enterprise", "email": "a@b.de"}
        )
        assert response.status_code == 422

    def test_checkout_sends_the_browser_to_the_marketing_site_not_raw_json(
        self, env, monkeypatch
    ):
        # A customer who just paid should land on a page that explains what
        # happened, not the API's own JSON. Regression test for the redirect
        # that used to point straight at /v1/checkout/complete.
        monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", "price_test_register")
        monkeypatch.setenv("ASSURANCE_MARKETING_URL", "https://neuralbridge.io")
        from assurance.billing import stripe_gateway

        captured: dict[str, str] = {}

        def fake_create_checkout_session(*, success_url, cancel_url, **_kw):
            captured["success_url"] = success_url
            captured["cancel_url"] = cancel_url
            return stripe_gateway.CheckoutSession(id="cs_test_1", url="https://checkout.stripe.com/cs_test_1")

        monkeypatch.setattr(stripe_gateway, "create_checkout_session", fake_create_checkout_session)

        from assurance.api import service

        with TestClient(service.create_app()) as c:
            response = c.post(
                "/v1/checkout",
                json={"tier": "register", "email": "m.braun@example.de"},
            )
        assert response.status_code == 200
        assert captured["success_url"] == (
            "https://neuralbridge.io/checkout/success?session_id={CHECKOUT_SESSION_ID}"
        )
        assert captured["cancel_url"] == "https://neuralbridge.io/#pricing"

    def test_marketing_url_defaults_to_the_real_site(self, env, monkeypatch):
        monkeypatch.setenv("ASSURANCE_PRICE_CELL", "price_test_cell")
        monkeypatch.delenv("ASSURANCE_MARKETING_URL", raising=False)
        from assurance.billing import stripe_gateway

        captured: dict[str, str] = {}

        def fake_create_checkout_session(*, success_url, cancel_url, **_kw):
            captured["success_url"] = success_url
            return stripe_gateway.CheckoutSession(id="cs_test_2", url="https://checkout.stripe.com/cs_test_2")

        monkeypatch.setattr(stripe_gateway, "create_checkout_session", fake_create_checkout_session)

        from assurance.api import service

        with TestClient(service.create_app()) as c:
            response = c.post(
                "/v1/checkout", json={"tier": "cell", "email": "a@b.de"}
            )
        assert response.status_code == 200
        assert captured["success_url"].startswith("https://neuralbridge.io/checkout/success")


class TestWebhook:
    def test_an_unsigned_webhook_is_refused(self, client):
        # Without this, anyone on the internet can grant themselves a plan.
        response = client.post("/v1/billing/webhook", json=_checkout_event())
        assert response.status_code == 400
        assert response.json()["detail"]["error"] == "signature_rejected"

    def test_a_wrongly_signed_webhook_is_refused(self, client):
        raw = json.dumps(_checkout_event()).encode()
        stamp = str(int(time.time()))
        response = client.post(
            "/v1/billing/webhook",
            content=raw,
            headers={"stripe-signature": f"t={stamp},v1=deadbeef"},
        )
        assert response.status_code == 400

    def test_a_replayed_webhook_is_refused(self, client):
        raw = json.dumps(_checkout_event()).encode()
        stale = str(int(time.time()) - 100_000)
        sig = hmac.new(
            WEBHOOK_SECRET.encode(), f"{stale}.".encode() + raw, hashlib.sha256
        ).hexdigest()
        response = client.post(
            "/v1/billing/webhook",
            content=raw,
            headers={"stripe-signature": f"t={stale},v1={sig}"},
        )
        assert response.status_code == 400
        assert "replay" in response.json()["detail"]["detail"]

    def test_a_signed_checkout_grants_the_plan(self, client):
        raw, headers = _signed(_checkout_event())
        response = client.post("/v1/billing/webhook", content=raw, headers=headers)
        assert response.status_code == 200
        assert response.json()["tier"] == "register"

    def test_the_key_is_collected_once_and_works(self, client):
        raw, headers = _signed(_checkout_event())
        client.post("/v1/billing/webhook", content=raw, headers=headers)

        collected = client.get("/v1/checkout/complete", params={"session_id": "cs_test_1"})
        assert collected.status_code == 200
        key = collected.json()["api_key"]
        assert key.startswith("asr_")

        # It works.
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 200

        # And it cannot be collected a second time.
        assert (
            client.get("/v1/checkout/complete", params={"session_id": "cs_test_1"}).status_code
            == 202
        )

    def test_collecting_before_the_webhook_lands_is_202_not_a_free_key(self, client):
        # Landing on a success URL proves only that a browser followed a redirect.
        response = client.get("/v1/checkout/complete", params={"session_id": "cs_never"})
        assert response.status_code == 202
        assert response.json()["detail"]["status"] == "pending"

    def test_a_duplicate_webhook_does_not_create_a_second_account(self, client, store):
        raw, headers = _signed(_checkout_event())
        client.post("/v1/billing/webhook", content=raw, headers=headers)
        client.post("/v1/billing/webhook", content=raw, headers=headers)
        db = sqlite3.connect(store.path)
        try:
            count = db.execute("SELECT COUNT(*) FROM accounts").fetchone()[0]
        finally:
            db.close()
        assert count == 1

    def test_cancellation_downgrades_to_free(self, client, store):
        raw, headers = _signed(_checkout_event())
        client.post("/v1/billing/webhook", content=raw, headers=headers)
        key = client.get(
            "/v1/checkout/complete", params={"session_id": "cs_test_1"}
        ).json()["api_key"]
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 200

        cancel_raw, cancel_headers = _signed(
            {
                "type": "customer.subscription.deleted",
                "data": {"object": {"customer": "cus_1", "status": "canceled"}},
            }
        )
        client.post("/v1/billing/webhook", content=cancel_raw, headers=cancel_headers)

        # Paying stopped, so access stopped.
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 402

    def test_past_due_also_suspends_access(self, client):
        raw, headers = _signed(_checkout_event())
        client.post("/v1/billing/webhook", content=raw, headers=headers)
        key = client.get(
            "/v1/checkout/complete", params={"session_id": "cs_test_1"}
        ).json()["api_key"]
        due_raw, due_headers = _signed(
            {
                "type": "customer.subscription.updated",
                "data": {"object": {"customer": "cus_1", "status": "past_due"}},
            }
        )
        client.post("/v1/billing/webhook", content=due_raw, headers=due_headers)
        assert client.get("/v1/cases", headers={"X-API-Key": key}).status_code == 402

    def test_an_unrecognised_event_is_acknowledged_not_retried(self, client):
        raw, headers = _signed({"type": "invoice.created", "data": {"object": {}}})
        response = client.post("/v1/billing/webhook", content=raw, headers=headers)
        assert response.status_code == 200
        assert response.json()["ignored"] == "invoice.created"


class TestKeyStorage:
    def test_the_key_is_never_stored(self, client, store):
        raw, headers = _signed(_checkout_event())
        client.post("/v1/billing/webhook", content=raw, headers=headers)
        key = client.get(
            "/v1/checkout/complete", params={"session_id": "cs_test_1"}
        ).json()["api_key"]

        db = sqlite3.connect(store.path)
        try:
            blob = " ".join(
                str(r) for r in db.execute("SELECT * FROM api_keys").fetchall()
            )
            pending = db.execute("SELECT COUNT(*) FROM pending_keys").fetchone()[0]
        finally:
            db.close()
        # The key itself appears nowhere; only its digest does.
        assert key not in blob
        assert hashlib.sha256(key.encode()).hexdigest() in blob
        # And the staging row was deleted when it was collected.
        assert pending == 0


class TestMe:
    def test_an_anonymous_caller_is_told_they_are_on_free(self, client):
        body = client.get("/v1/me").json()
        assert body["authenticated"] is False
        assert body["tier"] == "free"
        assert "GET /v1/plans" in body["note"]

    def test_usage_is_reported(self, client):
        client.post("/v1/spec/validate", json=_payload())
        client.post("/v1/spec/validate", json=_payload())
        assert client.get("/v1/me").json()["usage_today"]["validate"] == 2

    def test_a_paid_key_sees_its_account_and_keys(self, client, store):
        account = store.upsert_account(
            email="m.braun@sk.de", tier="register", company="SK Maschinenbau"
        )
        key = store.issue_key(account.id, label="primary")
        body = client.get("/v1/me", headers={"X-API-Key": key}).json()
        assert body["authenticated"] is True
        assert body["account"]["company"] == "SK Maschinenbau"
        assert body["keys"][0]["label"] == "primary"
        assert body["keys"][0]["revoked"] is False

    def test_a_paid_key_has_no_validation_cap(self, client, store):
        account = store.upsert_account(email="a@b.de", tier="register")
        key = store.issue_key(account.id)
        for _ in range(PLANS["free"].validations_per_day + 5):
            response = client.post(
                "/v1/spec/validate", json=_payload(), headers={"X-API-Key": key}
            )
            assert response.status_code == 200
        assert "X-Assurance-Quota-Limit" not in response.headers
