"""Checkout and portal calls (``stripe_gateway._post``) are hardened like the others.

``_post`` used to catch nothing: a connect timeout was a 500 from
``POST /v1/checkout`` (the route only catches ``StripeError``), and a 4xx message
could carry a key fragment because it was not scrubbed.
"""

from __future__ import annotations

import importlib

import httpx
import pytest
from fastapi.testclient import TestClient

from assurance.api import deps
from assurance.billing import stripe_gateway
from assurance.billing.stripe_gateway import StripeError

KEY = "sk_test_NOTAREALKEY000"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.setenv("STRIPE_SECRET_KEY", KEY)
    monkeypatch.setenv("ASSURANCE_PRICE_REGISTER", "price_test_register")
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    yield tmp_path
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


def checkout():
    return stripe_gateway.create_checkout_session(
        price_id="price_1", email="a@example.de", company="A", success_url="https://x/y",
        cancel_url="https://x/z", tier="register")


def test_a_transport_error_becomes_a_stripe_error_without_the_url_or_key(env, monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectTimeout(f"timed out reaching {url} with {KEY}")

    monkeypatch.setattr(stripe_gateway.httpx, "post", boom)
    with pytest.raises(StripeError) as caught:
        checkout()
    text = str(caught.value)
    assert "ConnectTimeout" in text and "api.stripe.com" not in text
    assert "NOTAREALKEY" not in text and caught.value.status is None
    with pytest.raises(StripeError):
        stripe_gateway.create_billing_portal_session(customer_id="cus_1", return_url="https://x/r")


def test_a_4xx_message_is_scrubbed_and_carries_status_and_code(env, monkeypatch):
    reply = httpx.Response(401, json={"error": {
        "code": "api_key_invalid",
        "message": f"Invalid API Key provided: {KEY} (rk_live_abcd1234)"}})
    monkeypatch.setattr(stripe_gateway.httpx, "post", lambda url, **kw: reply)
    with pytest.raises(StripeError) as caught:
        checkout()
    assert "NOTAREALKEY" not in str(caught.value) and "rk_live_abcd1234" not in str(caught.value)
    assert (caught.value.status, caught.value.code) == (401, "api_key_invalid")


def test_a_non_json_error_body_is_a_stripe_error_not_a_decode_error(env, monkeypatch):
    reply = httpx.Response(502, text=f"<html>bad gateway {KEY}</html>")
    monkeypatch.setattr(stripe_gateway.httpx, "post", lambda url, **kw: reply)
    with pytest.raises(StripeError) as caught:
        checkout()
    assert caught.value.status == 502 and "NOTAREALKEY" not in str(caught.value)


def test_a_success_response_that_is_not_an_object_is_a_stripe_error(env, monkeypatch):
    monkeypatch.setattr(stripe_gateway.httpx, "post",
                        lambda url, **kw: httpx.Response(200, json=["nope"]))
    with pytest.raises(StripeError):
        checkout()


def test_post_checkout_is_a_503_when_stripe_cannot_be_reached(env, monkeypatch):
    def boom(url, **kw):
        raise httpx.ConnectTimeout("timed out")

    monkeypatch.setattr(stripe_gateway.httpx, "post", boom)
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app(), raise_server_exceptions=False) as c:
        response = c.post("/v1/checkout", json={"tier": "register", "email": "a@b.de"})
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["error"] == "checkout_unavailable"
    assert "NOTAREALKEY" not in response.text
