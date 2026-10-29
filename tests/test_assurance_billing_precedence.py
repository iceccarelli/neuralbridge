"""Which of a customer's subscriptions the account follows, and what reconcile leaves behind.

Found by an independent review: cancelling the NEWEST subscription locked out a customer
who still paid for an older live one, and ``reconcile --apply`` then restored access while
leaving the account pointed at the cancelled subscription, so the older subscription's own
cancellation was ignored and the access stayed on, unpaid, for good.
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from assurance.api import billing_routes
from assurance.billing import reconcile as rec
from assurance.billing.accounts import AccountStore

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    account_state,
    checkout_event,
    collect_key,
    send,
    subscription_event,
)
from .test_assurance_reconcile import FakeStripe
from .test_assurance_reconcile import sub as stripe_sub

REG, CELL = "price_reg_test", "price_cell_test"


def _row(store: AccountStore):
    a = store.account_by_customer("cus_1")
    assert a is not None
    return a.status, a.tier, a.stripe_subscription_id


def _checkout(store, eid, session, sub, tier, at, customer="cus_1"):
    obj = checkout_event(session, customer, sub, tier, at)["data"]["object"]
    return billing_routes._handle_checkout(store, "checkout.session.completed", obj, eid, at)


def _update(store, eid, sub, price, status, at, kind=None):
    kind = kind or ("customer.subscription.deleted" if status == "canceled"
                    else "customer.subscription.updated")
    obj = subscription_event(kind, "cus_1", sub, price, status, at)["data"]["object"]
    return billing_routes._handle_subscription(store, kind, obj, eid, at)


def _phase(store: AccountStore, sub: str) -> str:
    db = sqlite3.connect(store.path)
    try:
        return db.execute(
            "SELECT phase FROM subscription_states WHERE stripe_subscription_id=?", (sub,)
        ).fetchone()[0]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# the policy: the newest-bought subscription that has not ended
# ---------------------------------------------------------------------------
def test_cancelling_the_newest_subscription_keeps_an_older_live_one(billing_client):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T))
    key = collect_key(c, "cs_A")
    send(c, subscription_event("customer.subscription.updated", "cus_1", "sub_A", REG,
                               "paused", T + 100))
    assert account_state(c, key)[0] == "cancelled"                      # lapsed
    send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 200))   # re-bought, customer=
    assert account_state(c, key) == ("active", "cell")
    r = send(c, subscription_event("customer.subscription.updated", "cus_1", "sub_A", REG,
                                   "active", T + 300))                    # A resumes: both live
    assert r.json()["result"] == "ignored_other_subscription"
    assert account_state(c, key) == ("active", "cell")                    # the newer one leads
    r = send(c, subscription_event("customer.subscription.deleted", "cus_1", "sub_B", CELL,
                                   "canceled", T + 400))
    assert c.get("/v1/register", headers={"X-API-Key": key}).status_code == 200
    assert account_state(c, key) == ("active", "register"), r.text         # A still pays
    send(c, subscription_event("customer.subscription.deleted", "cus_1", "sub_A", REG,
                               "canceled", T + 500))
    assert account_state(c, key) == ("cancelled", "free")
    assert c.get("/v1/register", headers={"X-API-Key": key}).status_code == 402


def test_with_only_ended_subscriptions_the_newest_bought_one_decides(tmp_path, billing_env):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", T)
    _checkout(store, "e2", "cs_B", "sub_B", "cell", T + 10)
    _update(store, "e3", "sub_B", CELL, "canceled", T + 20)
    _update(store, "e4", "sub_A", REG, "canceled", T + 30)    # ended last, but bought first
    assert _row(store) == ("cancelled", "free", "sub_B")


def test_a_paused_older_sub_does_not_hold_the_account_when_the_newer_one_ended(
    tmp_path, billing_env
):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", T)
    _checkout(store, "e2", "cs_B", "sub_B", "cell", T + 10)
    _update(store, "e3", "sub_A", REG, "paused", T + 15)
    _update(store, "e4", "sub_B", CELL, "canceled", T + 20)
    # a paused subscription has not ended: it is the one the account follows (and denies)
    assert _row(store) == ("cancelled", "register", "sub_A")


# ---------------------------------------------------------------------------
# reconcile --apply points the account at the subscription it restored it for
# ---------------------------------------------------------------------------
def test_apply_reconciliation_records_the_subscription_it_restored_access_for(
    tmp_path, billing_env
):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_B", "sub_B", "cell", T)
    _update(store, "e2", "sub_B", CELL, "canceled", T + 10)
    assert _row(store) == ("cancelled", "free", "sub_B")
    acct = store.account_by_customer("cus_1")
    assert store.apply_reconciliation(
        run_id="r1", account_id=acct.id, category="stripe_active_but_we_deny",
        expect_status="cancelled", expect_tier="free", new_status="active",
        new_tier="register", snapshot_at=T + 5000, skew_seconds=0,
        stripe_subscription_id="sub_A", stripe_status="active") == "applied"
    assert _row(store) == ("active", "register", "sub_A")
    # the real end of that subscription now ends the access
    out = _update(store, "e3", "sub_A", REG, "canceled", T + 6000)
    assert out["result"] == "downgraded_to_free"
    assert _row(store) == ("cancelled", "free", "sub_A")


def test_reconcile_apply_then_the_restored_subscriptions_cancellation_ends_access(
    tmp_path, billing_env
):
    now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    base = int(now.timestamp()) - 30 * 86400
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", base)
    _update(store, "e2", "sub_A", REG, "canceled", base + 100)
    assert _row(store) == ("cancelled", "free", "sub_A")
    # Stripe has a live subscription whose checkout webhook we never received
    stripe = FakeStripe([
        stripe_sub("sub_A", "cus_1", status="canceled", price=REG, created=base),
        stripe_sub("sub_B", "cus_1", status="active", price=CELL, created=base + 200),
    ])
    report = rec.reconcile(store, stripe, apply=True, now=now)
    assert [f.category for f in report.findings] == ["stripe_active_but_we_deny"]
    assert _row(store) == ("active", "cell", "sub_B")
    out = _update(store, "e3", "sub_B", CELL, "canceled", int(now.timestamp()) + 60)
    assert out["result"] == "downgraded_to_free"
    assert _row(store)[:2] == ("cancelled", "free")


# ---------------------------------------------------------------------------
# the row is the truth, but not against a newer end the record already knows
# ---------------------------------------------------------------------------
def test_a_row_older_than_the_recorded_end_does_not_resurrect_the_subscription(
    tmp_path, billing_env
):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "cell", T)
    _update(store, "e2", "sub_A", CELL, "canceled", T + 400)
    assert _phase(store, "sub_A") == "terminal"
    # something that wrote the row without an event, and before that end, left it entitled
    db = sqlite3.connect(store.path)
    db.execute("UPDATE accounts SET status='active', tier='cell', last_event_at=?", (T + 100,))
    db.commit()
    db.close()
    billing_routes._handle_payment_failed(
        store, "invoice.payment_failed",
        {"customer": "cus_1", "subscription": "sub_unknown"}, "e3", T + 450)
    assert _phase(store, "sub_A") == "terminal"


# ---------------------------------------------------------------------------
# a paying older subscription is not locked out by a newer one that is merely paused
# ---------------------------------------------------------------------------
def test_a_newer_paused_sub_does_not_lock_out_an_older_active_one(tmp_path, billing_env):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", T)
    _checkout(store, "e2", "cs_B", "sub_B", "cell", T + 10)
    assert _row(store) == ("active", "cell", "sub_B")          # both live: the newer leads
    _update(store, "e3", "sub_B", CELL, "paused", T + 20)
    assert _row(store) == ("active", "register", "sub_A")      # A still pays


def test_a_newer_paused_sub_with_an_older_past_due_one_stays_entitled(tmp_path, billing_env):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", T)
    _checkout(store, "e2", "cs_B", "sub_B", "cell", T + 10)
    _update(store, "e3", "sub_A", REG, "past_due", T + 15)
    _update(store, "e4", "sub_B", CELL, "paused", T + 20)
    assert _row(store) == ("past_due", "register", "sub_A")


def test_when_the_older_active_sub_then_ends_the_paused_newer_one_denies(tmp_path, billing_env):
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", T)
    _checkout(store, "e2", "cs_B", "sub_B", "cell", T + 10)
    _update(store, "e3", "sub_B", CELL, "paused", T + 20)
    out = _update(store, "e4", "sub_A", REG, "canceled", T + 30)
    assert out["result"] == "downgraded_to_free"
    assert _row(store) == ("cancelled", "cell", "sub_B")       # paused: no entitlement, tier kept
    assert store.account_by_customer("cus_1").plan.tier == "free"
    # and a cancelled paused sub is the end of it
    _update(store, "e5", "sub_B", CELL, "canceled", T + 40)
    assert _row(store) == ("cancelled", "free", "sub_B")


def test_reconcile_agrees_with_the_webhook_when_a_newer_sub_is_paused(tmp_path, billing_env):
    now = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)
    base = int(now.timestamp()) - 30 * 86400
    store = AccountStore(str(tmp_path / "accounts.db"))
    _checkout(store, "e1", "cs_A", "sub_A", "register", base)
    _checkout(store, "e2", "cs_B", "sub_B", "cell", base + 100)
    _update(store, "e3", "sub_B", CELL, "paused", base + 200)
    stripe = FakeStripe([
        stripe_sub("sub_A", "cus_1", status="active", price=REG, created=base),
        stripe_sub("sub_B", "cus_1", status="paused", price=CELL, created=base + 100),
    ])
    report = rec.reconcile(store, stripe, apply=False, now=now)
    assert [f.category for f in report.findings] == []
    assert _row(store)[:2] == ("active", "register")
