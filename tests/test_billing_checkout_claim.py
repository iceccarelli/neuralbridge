"""The key handover is bound to a claim token and never travels in a URL.

Everything is local: a fake Stripe session creator, signed webhooks with a throwaway secret, the
real FastAPI app on a temporary accounts database. No Stripe host is contacted.

What is established here, and what is not:

* The key exists only after a verified ``checkout.session.completed``; the browser redirect
  (this route) proves nothing and mints nothing.
* The session id alone collects nothing. The claim token is a bearer secret: whoever holds
  both values collects the key first. That is a limit, asserted as such below, not a fix.
* A stranger's wrong guess consumes nothing, so the real buyer is not locked out.
"""

from __future__ import annotations

import sqlite3

import pytest

from assurance.billing import issue_key as issue
from assurance.billing import stripe_gateway as stripe_gw
from assurance.billing.accounts import AccountStore, hash_key

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    checkout_event,
    claim,
    send,
)


@pytest.fixture()
def started(billing_client, monkeypatch):
    """Start a checkout through the real route against a fake Stripe session creator."""
    seen: list[dict] = []

    def fake_create(**kw):
        seen.append(kw)
        return stripe_gw.CheckoutSession(id=f"cs_test_{len(seen)}", url="https://stripe.invalid/pay")

    monkeypatch.setattr(stripe_gw, "create_checkout_session", fake_create)

    def start(tier: str = "cell"):
        r = billing_client.post("/v1/checkout", json={"tier": tier, "email": "buyer@example.invalid"})
        assert r.status_code == 200, r.text
        return r.json(), seen[-1]

    return start


def test_checkout_issues_a_claim_token_and_keeps_it_out_of_the_query_string(started, billing_env):
    body, sent = started()
    token = body["claim_token"]
    assert len(token) >= 40
    url = sent["success_url"]
    # the session id may be in the query (Stripe fills it in); the claim token never is
    assert "session_id={CHECKOUT_SESSION_ID}" in url.split("#")[0]
    assert token not in url.split("#")[0]
    assert url.split("#")[1] == f"claim={token}"
    # only a hash is stored
    rows = sqlite3.connect(billing_env / "accounts.db").execute(
        "SELECT session_id, token_hash FROM checkout_claims").fetchall()
    assert rows == [("cs_test_1", hash_key(token))]
    assert token not in (billing_env / "accounts.db").read_bytes().decode("latin-1")


def test_full_handover_once_with_the_token_then_gone(billing_client, started):
    body, _ = started()
    token = body["claim_token"]
    # the redirect arrives before the webhook: pending, and nothing is minted by asking
    early = claim(billing_client, "cs_test_1", token)
    assert early.status_code == 202 and early.json()["detail"]["status"] == "pending"
    assert send(billing_client, checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    got = claim(billing_client, "cs_test_1", token)
    assert got.status_code == 200, got.text
    assert got.headers["cache-control"] == "no-store"
    key = got.json()["api_key"]
    assert billing_client.get("/v1/me", headers={"X-API-Key": key}).json()["tier"] == "cell"
    # the second claim, with the right token, is told plainly that it is gone: not "pending"
    again = claim(billing_client, "cs_test_1", token)
    assert again.status_code == 410
    assert again.json()["detail"]["error"] == "already_collected_or_expired"
    assert "api_key" not in again.text


def test_the_redirect_alone_is_not_proof_of_payment(billing_client, started, billing_env):
    body, _ = started()
    for _ in range(3):
        r = claim(billing_client, "cs_test_1", body["claim_token"])
        assert r.status_code == 202
    store = AccountStore.open_readonly(str(billing_env / "accounts.db"))
    assert store.account_by_customer("cus_1") is None
    assert store.list_accounts() == []
    # an unsigned or wrongly signed "webhook" grants nothing either
    ev = checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
    assert send(billing_client, ev, secret="whsec_wrong").status_code == 400  # noqa: S106
    assert claim(billing_client, "cs_test_1", body["claim_token"]).status_code == 202


def test_a_session_id_alone_collects_nothing_and_a_stranger_does_not_lock_out_the_buyer(
        billing_client, started):
    body, _ = started()
    token = body["claim_token"]
    assert send(billing_client, checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    # a stranger who saw the session id in a log or a Referer
    none = billing_client.post("/v1/checkout/complete", json={"session_id": "cs_test_1"})
    assert none.status_code == 403 and none.json()["detail"]["error"] == "claim_token_required"
    wrong = claim(billing_client, "cs_test_1", "x" * 43)
    assert wrong.status_code == 403 and wrong.json()["detail"]["error"] == "claim_token_invalid"
    assert "api_key" not in none.text + wrong.text
    # nothing was consumed: the real buyer still collects
    real = claim(billing_client, "cs_test_1", token)
    assert real.status_code == 200 and real.json()["api_key"].startswith("asr_")


def test_a_bearer_secret_is_still_a_bearer_secret(billing_client, started):
    """The stated limit: whoever holds both values first gets the key; the buyer is then told so."""
    body, _ = started()
    assert send(billing_client, checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    thief = claim(billing_client, "cs_test_1", body["claim_token"])  # holds both values
    assert thief.status_code == 200
    buyer = claim(billing_client, "cs_test_1", body["claim_token"])
    # the buyer does not wait on "pending" for ever: a definite answer with a recovery path
    assert buyer.status_code == 410
    assert "operator" in buyer.json()["detail"]["remedy"]


def test_a_session_we_never_started_cannot_be_claimed_by_id(billing_client):
    """A webhook for a session no POST /v1/checkout created has no claim token: fail closed."""
    assert send(billing_client, checkout_event("cs_foreign", "cus_9", "sub_9", "cell", T)
                ).status_code == 200
    for token in ("", "anything", "x" * 43):
        r = claim(billing_client, "cs_foreign", token)
        assert r.status_code == 403, r.text
        assert "api_key" not in r.text


def test_get_no_longer_hands_over_a_key_whatever_it_is_sent(billing_client, started):
    body, _ = started()
    assert send(billing_client, checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    for params in ({"session_id": "cs_test_1"},
                   {"session_id": "cs_test_1", "claim_token": body["claim_token"]}, {}):
        r = billing_client.get("/v1/checkout/complete", params=params)
        assert r.status_code == 410 and r.json()["detail"]["error"] == "moved"
        assert r.headers["cache-control"] == "no-store"
        assert "api_key" not in r.text
    # and the key is still there for the POST
    assert claim(billing_client, "cs_test_1", body["claim_token"]).status_code == 200


def test_the_claim_body_is_strict(billing_client):
    for bad in ({}, {"session_id": ""}, {"session_id": "cs 1"}, {"session_id": "cs_1", "x": 1},
                {"session_id": "cs_1", "claim_token": "t" * 300}):
        assert billing_client.post("/v1/checkout/complete", json=bad).status_code == 422, bad


def test_operator_recovery_discards_the_staged_key_and_issues_a_new_one(
        billing_client, started, billing_env, capsys):
    """The buyer lost the token: the staged key is revoked and cannot be collected afterwards."""
    body, _ = started()
    assert send(billing_client, checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    staged_key = sqlite3.connect(billing_env / "accounts.db").execute(
        "SELECT api_key FROM pending_keys").fetchone()[0]
    assert billing_client.get("/v1/me", headers={"X-API-Key": staged_key}).status_code == 200
    assert claim(billing_client, "cs_test_1", "lost").status_code == 403

    assert issue.main(["--customer", "cus_1", "--discard-staged", "cs_test_1"]) == 0
    fresh = capsys.readouterr().out.strip()
    assert fresh != staged_key
    # the staged copy is dead and uncollectable; the fresh key works
    assert billing_client.get("/v1/me", headers={"X-API-Key": staged_key}).status_code == 401
    assert claim(billing_client, "cs_test_1", body["claim_token"]).status_code == 410
    assert billing_client.get("/v1/me", headers={"X-API-Key": fresh}).status_code == 200


def test_discard_staged_for_another_accounts_session_issues_nothing(
        billing_client, started, billing_env, capsys):
    started()
    assert send(billing_client, checkout_event("cs_test_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    assert send(billing_client, checkout_event("cs_other", "cus_2", "sub_2", "cell", T + 1)
                ).status_code == 200
    assert issue.main(["--customer", "cus_2", "--discard-staged", "cs_test_1"]) == 1
    assert capsys.readouterr().out == ""
