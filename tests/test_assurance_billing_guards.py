"""Two guards on the billing webhook that no test pinned down.

An independent review removed each one and the whole suite stayed green:

* ``verify_webhook`` must fail closed when ``STRIPE_WEBHOOK_SECRET`` is unset or empty.
  HMAC accepts an empty key, so without the guard anyone can sign a ``checkout`` event
  with the empty string and be granted a paid account.
* ``invoice.payment_failed`` moves only an ``active`` account. A retry that fails after
  the subscription was cancelled must not turn the account back into an entitled one.
"""

from __future__ import annotations

import json

import pytest

from assurance.billing import stripe_gateway

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    account_state,
    checkout_event,
    collect_key,
    payment_failed_event,
    send,
    sign,
    stored_state,
    subscription_event,
)


def _post_signed_with(client, event, secret):
    raw = json.dumps(event).encode()
    return client.post("/v1/billing/webhook", content=raw, headers=sign(raw, secret=secret))


# ---------------------------------------------------------------------------
# the signature guard
# ---------------------------------------------------------------------------
def test_an_unset_secret_fails_closed_and_grants_nothing(billing_client, monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET")
    r = _post_signed_with(billing_client, checkout_event("cs_1", "cus_1", "sub_1", "cell", T), "")
    assert r.status_code == 400
    assert r.json()["detail"]["error"] == "signature_rejected"
    assert billing_client.get("/v1/checkout/complete", params={"session_id": "cs_1"}).status_code == 202


def test_an_empty_secret_fails_closed_and_grants_nothing(billing_client, monkeypatch):
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "")
    r = _post_signed_with(billing_client, checkout_event("cs_1", "cus_1", "sub_1", "cell", T), "")
    assert r.status_code == 400
    assert billing_client.get("/v1/checkout/complete", params={"session_id": "cs_1"}).status_code == 202


def test_verify_webhook_refuses_an_empty_key_even_with_a_matching_signature(monkeypatch):
    monkeypatch.delenv("STRIPE_WEBHOOK_SECRET", raising=False)
    raw = json.dumps(checkout_event("cs_1", "cus_1", "sub_1", "cell", T)).encode()
    header = sign(raw, secret="")["stripe-signature"]
    with pytest.raises(stripe_gateway.SignatureError, match="STRIPE_WEBHOOK_SECRET"):
        stripe_gateway.verify_webhook(raw, header)
    with pytest.raises(stripe_gateway.SignatureError):
        stripe_gateway.verify_webhook(raw, header, secret="")


def test_the_configured_secret_still_verifies(billing_client):
    r = send(billing_client, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# the payment-failed guard
# ---------------------------------------------------------------------------
def test_a_payment_failure_marks_an_active_account_past_due(billing_client):
    c = billing_client
    send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    key = collect_key(c, "cs_1")
    r = send(c, payment_failed_event("cus_1", T + 10))
    assert r.json()["result"] == "marked_past_due"
    assert account_state(c, key) == ("past_due", "cell")


def test_a_late_payment_failure_cannot_resurrect_a_cancelled_account(billing_client, billing_env):
    c = billing_client
    send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    key = collect_key(c, "cs_1")
    send(c, subscription_event("customer.subscription.deleted", "cus_1", "sub_1",
                               "price_cell_test", "canceled", T + 10))
    assert stored_state(billing_env)[:2] == ("cancelled", "free")
    r = send(c, payment_failed_event("cus_1", T + 20))
    assert r.status_code == 200
    assert r.json()["result"] == "ignored_not_applicable"
    assert stored_state(billing_env)[:2] == ("cancelled", "free")
    assert c.get("/v1/register", headers={"X-API-Key": key}).status_code == 402
