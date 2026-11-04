"""Red-team findings on the money path (workstream I). Each test failed on the code before the fix.

1. The claim token was sent to Stripe in plaintext inside ``success_url``.
2. One address could exhaust the process-wide Stripe-call budget.
3. A contributor operator key could start a checkout.
4. Signed but malformed webhook bodies answered 500.
5. An expired, uncollected staged key stayed ACTIVE in ``api_keys``.

Everything is local: a fake Stripe session creator, signed webhooks with a throwaway secret and
the real FastAPI app on a temporary accounts database. No Stripe host is contacted.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta

import pytest

from assurance.api import deps
from assurance.billing import accounts as accounts_mod
from assurance.billing import stripe_gateway as stripe_gw
from assurance.billing.accounts import PENDING_KEY_TTL, hash_key
from assurance.core.identity import utc_now

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    checkout_event,
    claim,
    evt,
    send,
)

BODY = {"tier": "cell", "email": "buyer@example.invalid"}


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def shop(billing_client, monkeypatch):
    """The real app with a fake clock, and a Stripe session creator that records its calls."""
    clock = Clock()
    billing_client.app.state.rate_clock = clock
    seen: list[dict] = []

    def fake_create(**kw):
        seen.append(kw)
        return stripe_gw.CheckoutSession(id=f"cs_rt_{len(seen)}", url="https://stripe.invalid/pay")

    monkeypatch.setattr(stripe_gw, "create_checkout_session", fake_create)
    monkeypatch.setenv("ASSURANCE_RATE_CHECKOUT", "0")      # isolate the Stripe-call budget
    return billing_client, clock, seen


# -- 1. the claim token never reaches Stripe ------------------------------------------------
def test_the_claim_token_is_not_in_anything_sent_to_stripe(shop):
    c, _, seen = shop
    r = c.post("/v1/checkout", json=BODY)
    assert r.status_code == 200
    out = r.json()
    token = out["claim_token"]
    assert len(token) >= 40
    assert out["session_id"] == "cs_rt_1"                    # lets the client bind token to session
    sent = json.dumps(seen[-1], default=str)
    assert token not in sent                                 # not in success_url, cancel_url, anything
    assert "#" not in seen[-1]["success_url"]
    assert "claim" not in seen[-1]["success_url"]
    assert seen[-1]["success_url"].endswith("/checkout/success?session_id={CHECKOUT_SESSION_ID}")


def test_the_buyer_who_kept_the_response_token_still_collects_once(shop):
    c, _, _ = shop
    out = c.post("/v1/checkout", json=BODY).json()
    sid, token = out["session_id"], out["claim_token"]
    assert send(c, checkout_event(sid, "cus_rt", "sub_rt", "cell", T)).status_code == 200
    assert claim(c, sid, "").status_code == 403              # session id alone collects nothing
    got = claim(c, sid, token)
    assert got.status_code == 200 and got.json()["api_key"].startswith("asr_")
    assert claim(c, sid, token).status_code == 410


# -- 2. one address cannot monopolise the Stripe-call budget --------------------------------
def test_one_address_is_capped_at_its_share_and_others_still_get_through(shop, monkeypatch):
    c, clock, seen = shop
    monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET", "50/3600")
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS", "4/3600")
    attacker = {"Fly-Client-IP": "203.0.113.7"}
    codes = [c.post("/v1/checkout", json=BODY, headers=attacker).status_code for _ in range(8)]
    assert codes == [200] * 4 + [429] * 4
    assert len(seen) == 4                                    # the refused ones cost no Stripe call
    r = c.post("/v1/checkout", json=BODY, headers=attacker)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert r.json()["detail"]["retry_after_seconds"] == int(r.headers["retry-after"])
    # a different address is untouched: the attacker did not spend the whole shared budget
    assert c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": "198.51.100.1"}
                  ).status_code == 200
    clock.now += 3601                                        # the attacker's window has passed
    assert c.post("/v1/checkout", json=BODY, headers=attacker).status_code == 200


def test_a_refused_address_does_not_spend_the_shared_budget(shop, monkeypatch):
    c, _, seen = shop
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET", "6/3600")
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS", "2/3600")
    monkeypatch.setenv("ASSURANCE_TRUST_FLY_PROXY", "1")
    for _ in range(20):                                      # 18 of these are refused
        c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": "203.0.113.7"})
    assert len(seen) == 2
    # 4 units of the global budget are still there for other addresses
    codes = [c.post("/v1/checkout", json=BODY, headers={"Fly-Client-IP": f"198.51.100.{i}"}
                    ).status_code for i in range(1, 6)]
    assert codes == [200] * 4 + [429]


def test_failed_stripe_calls_still_count_against_the_address(shop, monkeypatch):
    c, _, _ = shop
    monkeypatch.setenv("ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS", "3/3600")
    calls: list[int] = []

    def boom(**_kw):
        calls.append(1)
        raise stripe_gw.StripeError("stripe is down")

    monkeypatch.setattr(stripe_gw, "create_checkout_session", boom)
    assert [c.post("/v1/checkout", json=BODY).status_code for _ in range(5)] == [503] * 3 + [429] * 2
    assert len(calls) == 3


def test_the_default_per_address_share_is_well_below_the_global_cap(shop):
    c, _, seen = shop
    codes = [c.post("/v1/checkout", json=BODY).status_code for _ in range(30)]
    assert codes.count(200) == 20 and codes.count(429) == 10 and len(seen) == 20


# -- 3. a contributor key cannot start a checkout -------------------------------------------
def _operator(client, headers, name, role):
    r = client.post("/v1/operators", headers=headers, json={"name": name, "role": role})
    assert r.status_code == 201, r.text
    return {"X-API-Key": r.json()["api_key"]}


def test_a_contributor_operator_key_cannot_start_a_checkout(billing_client, monkeypatch):
    calls: list[dict] = []

    def fake_create(**kw):
        calls.append(kw)
        return stripe_gw.CheckoutSession(id=f"cs_op_{len(calls)}", url="https://stripe.invalid/pay")

    monkeypatch.setattr(stripe_gw, "create_checkout_session", fake_create)
    monkeypatch.setenv("ASSURANCE_RATE_CHECKOUT", "0")
    accounts = deps.get_accounts()
    acct = accounts.upsert_account(email="o@e.invalid", tier="cell", company="O",
                                   stripe_customer_id="cus_op")
    h = {"X-API-Key": accounts.issue_key(acct.id, "boss")}
    boss = _operator(billing_client, h, "Boss", "decider")
    lena = _operator(billing_client, boss, "Lena", "contributor")
    r = billing_client.post("/v1/checkout", headers=lena, json=BODY)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "decider_role_required"
    assert calls == []                                       # no Stripe call, no customer touched
    # a decider and the plain account key are not refused by this gate (409: already subscribed)
    assert billing_client.post("/v1/checkout", headers=boss, json=BODY).status_code == 409
    assert billing_client.post("/v1/checkout", headers=h, json=BODY).status_code == 409


# -- 4. signed but malformed webhook bodies are a clean 400 --------------------------------
def _checkout_obj(**over):
    obj = {"id": "cs_x", "payment_status": "paid", "customer": "cus_x", "subscription": "sub_x",
           "customer_details": {"email": "a@e.invalid"}, "metadata": {"tier": "cell", "company": "C"}}
    obj.update(over)
    return obj


MALFORMED = [
    pytest.param({"id": "evt_1", "data": [1]}, id="data-list"),
    pytest.param({"id": "evt_1", "data": None}, id="data-null"),
    pytest.param({"id": "evt_1", "data": "x"}, id="data-string"),
    pytest.param({"id": "evt_1", "type": ["x"]}, id="type-list"),
    pytest.param({"id": "evt_1", "type": {"a": 1}}, id="type-dict"),
    pytest.param({"id": "evt_1", "type": 7}, id="type-int"),
    pytest.param({"id": "evt_1", "type": "x", "data": {"object": [1]}}, id="object-list"),
    pytest.param({"id": "evt_1", "type": "x", "data": {"object": "s"}}, id="object-string"),
    pytest.param(evt("checkout.session.completed", _checkout_obj(metadata=[1]), T),
                 id="metadata-list"),
    pytest.param(evt("checkout.session.completed", _checkout_obj(metadata="x"), T),
                 id="metadata-string"),
    pytest.param(evt("checkout.session.completed", _checkout_obj(metadata={"tier": ["cell"]}), T),
                 id="tier-list"),
    pytest.param(evt("checkout.session.completed", _checkout_obj(customer_details=[1]), T),
                 id="customer-details-list"),
    pytest.param(evt("checkout.session.completed", _checkout_obj(customer=["c"]), T),
                 id="customer-list"),
    pytest.param(evt("checkout.session.completed", _checkout_obj(id=["cs"]), T), id="id-list"),
    pytest.param(evt("customer.subscription.updated",
                     {"id": "sub_1", "customer": "cus_1", "status": ["active"], "items": []}, T),
                 id="subscription-status-list"),
    pytest.param(evt("customer.subscription.updated",
                     {"id": "sub_1", "customer": "cus_1", "status": "active", "items": [1]}, T),
                 id="subscription-items-list"),
    pytest.param(evt("invoice.payment_failed", {"customer": ["c"]}, T), id="invoice-customer-list"),
]


@pytest.mark.parametrize("event", MALFORMED)
def test_a_signed_but_malformed_webhook_is_a_400_never_a_500(billing_client, event):
    r = send(billing_client, event)
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["error"] == "invalid_payload"


def test_a_well_formed_unrelated_event_is_still_acknowledged(billing_client):
    r = send(billing_client, evt("customer.created", {"id": "cus_9", "metadata": {}}, T))
    assert r.status_code == 200 and r.json()["ignored"] == "customer.created"
    r = send(billing_client, {"id": "evt_2", "type": "ping"})        # no data at all
    assert r.status_code == 200


# -- 5. an expired, uncollected staged key is revoked, not left active ----------------------
def _api_key_row(db_path, key):
    with sqlite3.connect(db_path) as db:
        return db.execute("SELECT revoked_at FROM api_keys WHERE key_hash = ?",
                          (hash_key(key),)).fetchone()


def test_an_expired_uncollected_key_is_revoked_in_the_purge(billing_env, monkeypatch):
    now = [utc_now()]
    monkeypatch.setattr(accounts_mod, "utc_now", lambda: now[0])
    store = accounts_mod.AccountStore(billing_env / "accounts.db")
    store.register_checkout_claim("cs_old", "tok-old")
    result = store.apply_checkout(
        event_id="evt_old", session_id="cs_old", email="b@e.invalid", company="C", tier="cell",
        stripe_customer_id="cus_old", stripe_subscription_id="sub_old", event_created=T)
    account_id = result["account_id"]
    with sqlite3.connect(billing_env / "accounts.db") as db:
        staged = db.execute("SELECT api_key FROM pending_keys WHERE session_id='cs_old'"
                            ).fetchone()[0]
    assert _api_key_row(billing_env / "accounts.db", staged) == (None,)
    assert store.active_key_count(account_id) == 1

    now[0] += PENDING_KEY_TTL - timedelta(minutes=1)          # not yet expired: still claimable
    store.register_checkout_claim("cs_other", "tok-other")    # any billing write runs the purge
    assert _api_key_row(billing_env / "accounts.db", staged) == (None,)

    now[0] += timedelta(minutes=2)                            # now past the 24 h hold
    store.register_checkout_claim("cs_other2", "tok-other2")
    row = _api_key_row(billing_env / "accounts.db", staged)
    assert row is not None and row[0] is not None            # revoked, not just unclaimable
    assert store.active_key_count(account_id) == 0            # no phantom key against the cap
    with sqlite3.connect(billing_env / "accounts.db") as db:
        assert db.execute("SELECT COUNT(*) FROM pending_keys").fetchone()[0] == 0
    outcome, key = store.claim_checkout("cs_old", "tok-old")  # a late claim is a definite 410
    assert (outcome, key) == ("gone", None)


def test_a_collected_key_is_not_revoked_by_the_purge(billing_env, monkeypatch):
    now = [utc_now()]
    monkeypatch.setattr(accounts_mod, "utc_now", lambda: now[0])
    store = accounts_mod.AccountStore(billing_env / "accounts.db")
    store.register_checkout_claim("cs_ok", "tok-ok")
    store.apply_checkout(
        event_id="evt_ok", session_id="cs_ok", email="b@e.invalid", company="C", tier="cell",
        stripe_customer_id="cus_ok", stripe_subscription_id="sub_ok", event_created=T)
    outcome, key = store.claim_checkout("cs_ok", "tok-ok")
    assert outcome == "claimed" and key is not None
    now[0] += PENDING_KEY_TTL + timedelta(hours=1)
    store.register_checkout_claim("cs_next", "tok-next")      # runs the purge
    assert _api_key_row(billing_env / "accounts.db", key["api_key"]) == (None,)


def test_an_expanded_customer_object_is_still_read_as_its_id(billing_client):
    """The refund and dispute handlers always accepted ``customer`` as an object; so do the rest."""
    r = send(billing_client, evt("checkout.session.completed",
                                 _checkout_obj(id="cs_exp", customer={"id": "cus_exp"}), T))
    assert r.status_code == 200 and r.json()["tier"] == "cell"
