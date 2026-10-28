"""Stripe events arrive late, twice and out of order; entitlement must not depend on it.

Regressions found by an independent review of the billing state machine:

* a cancellation of an OLD subscription delivered before the checkout of the NEW one
  left a paying customer cancelled (the checkout was dropped as "stale");
* an event about an old, or an unrelated, subscription rewrote the tier or status of the
  account's current subscription (including regaining paid access from a paused plan).

The last class is an event-ordering model: every delivery order of a fixed event set must
end in the same entitlement.
"""

from __future__ import annotations

import itertools
import os
import random

import pytest

from assurance.api import billing_routes
from assurance.billing.accounts import AccountStore

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    account_state,
    checkout_event,
    collect_key,
    evt,
    payment_failed_event,
    send,
    stored_state,
    subscription_event,
)


def sub(client, kind, sub_id, price, status, created, customer="cus_1"):
    return send(client, subscription_event(kind, customer, sub_id, price, status, created))


# ---------------------------------------------------------------------------
# M1: the cancellation of the old subscription overtakes the new checkout
# ---------------------------------------------------------------------------
def test_cancel_of_old_sub_delivered_before_new_checkout_keeps_the_new_paid_sub(billing_client):
    c = billing_client
    assert send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T)).status_code == 200
    key = collect_key(c, "cs_A")
    r = sub(c, "customer.subscription.deleted", "sub_A", "price_reg_test", "canceled", T + 20)
    assert r.status_code == 200
    assert send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 10)).status_code == 200
    assert account_state(c, key) == ("active", "cell")
    assert c.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 200


def test_a_later_cancel_of_the_new_sub_is_not_lost_after_the_reorder(billing_client):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T))
    key = collect_key(c, "cs_A")
    sub(c, "customer.subscription.deleted", "sub_A", "price_reg_test", "canceled", T + 20)
    send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 10))
    assert account_state(c, key) == ("active", "cell")
    r = sub(c, "customer.subscription.deleted", "sub_B", "price_cell_test", "canceled", T + 40)
    assert r.json()["result"] == "downgraded_to_free"
    assert account_state(c, key) == ("cancelled", "free")


def test_cancel_of_the_new_sub_delivered_before_its_checkout_stays_cancelled(billing_client):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T))
    key = collect_key(c, "cs_A")
    sub(c, "customer.subscription.deleted", "sub_B", "price_cell_test", "canceled", T + 40)
    send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 10))
    sub(c, "customer.subscription.deleted", "sub_A", "price_reg_test", "canceled", T + 20)
    assert account_state(c, key) == ("cancelled", "free")


# ---------------------------------------------------------------------------
# M2: events about ANOTHER subscription must not rewrite this account
# ---------------------------------------------------------------------------
def test_update_event_for_the_old_sub_does_not_change_the_tier_of_the_current_sub(billing_client):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T))
    key = collect_key(c, "cs_A")
    send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 10))
    assert account_state(c, key) == ("active", "cell")
    r = sub(c, "customer.subscription.updated", "sub_A", "price_reg_test", "active", T + 20)
    assert r.json()["result"] == "ignored_other_subscription"
    assert account_state(c, key) == ("active", "cell")


def test_a_foreign_products_active_event_does_not_reinstate_a_paused_plan(
    billing_client, billing_env
):
    c = billing_client
    send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    key = collect_key(c, "cs_1")
    sub(c, "customer.subscription.updated", "sub_1", "price_cell_test", "paused", T + 10)
    assert c.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 402
    r = sub(c, "customer.subscription.updated", "sub_OTHER", "price_unrelated", "active", T + 20)
    assert r.status_code == 200
    assert c.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 402
    assert stored_state(billing_env)[:2] == ("cancelled", "cell")


def test_a_foreign_products_active_event_does_not_clear_the_dunning_state(billing_client):
    c = billing_client
    send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    key = collect_key(c, "cs_1")
    sub(c, "customer.subscription.updated", "sub_1", "price_cell_test", "past_due", T + 10)
    assert account_state(c, key)[0] == "past_due"
    sub(c, "customer.subscription.updated", "sub_OTHER", "price_unrelated", "active", T + 20)
    assert account_state(c, key)[0] == "past_due"


def test_a_foreign_products_cancellation_does_not_end_our_plan(billing_client):
    c = billing_client
    send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    key = collect_key(c, "cs_1")
    sub(c, "customer.subscription.deleted", "sub_OTHER", "price_unrelated", "canceled", T + 20)
    assert account_state(c, key) == ("active", "cell")


def test_a_payment_failure_on_a_foreign_invoice_does_not_flag_our_plan(billing_client):
    c = billing_client
    send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T))
    key = collect_key(c, "cs_1")
    send(c, payment_failed_event("cus_1", T + 20, sub="sub_OTHER"))
    assert account_state(c, key) == ("active", "cell")


# ---------------------------------------------------------------------------
# the legitimate flows keep working
# ---------------------------------------------------------------------------
def test_a_new_subscription_replaces_a_cancelled_one_through_checkout(billing_client):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T))
    key = collect_key(c, "cs_A")
    sub(c, "customer.subscription.deleted", "sub_A", "price_reg_test", "canceled", T + 20)
    assert account_state(c, key) == ("cancelled", "free")
    send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 30))
    assert account_state(c, key) == ("active", "cell")


def test_downgrade_on_the_same_subscription_applies(billing_client):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "cell", T))
    key = collect_key(c, "cs_A")
    sub(c, "customer.subscription.updated", "sub_A", "price_reg_test", "active", T + 10)
    assert account_state(c, key) == ("active", "register")


def test_pause_and_resume_of_the_current_subscription_apply(billing_client, billing_env):
    c = billing_client
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "cell", T))
    key = collect_key(c, "cs_A")
    sub(c, "customer.subscription.updated", "sub_A", "price_cell_test", "paused", T + 10)
    assert stored_state(billing_env)[:2] == ("cancelled", "cell")
    assert c.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 402
    sub(c, "customer.subscription.updated", "sub_A", "price_cell_test", "active", T + 20)
    assert account_state(c, key) == ("active", "cell")


def test_an_older_checkout_delivered_late_does_not_replace_the_newer_one(billing_client):
    c = billing_client
    send(c, checkout_event("cs_B", "cus_1", "sub_B", "cell", T + 10))
    key = collect_key(c, "cs_B")
    send(c, checkout_event("cs_A", "cus_1", "sub_A", "register", T))
    assert account_state(c, key) == ("active", "cell")
    sub(c, "customer.subscription.deleted", "sub_A", "price_reg_test", "canceled", T + 20)
    assert account_state(c, key) == ("active", "cell")


# ---------------------------------------------------------------------------
# the model: delivery order must not matter
# ---------------------------------------------------------------------------
#: All permutations of a six-event set are 720; a seeded sample keeps the suite quick while
#: every run still covers the identity-adjacent and the reversed-adjacent orders by chance
#: of the fixed seed. ``NEURALBRIDGE_EXHAUSTIVE_ORDERS=1`` runs them all.
ORDERS_PER_SCENARIO = 720 if os.environ.get("NEURALBRIDGE_EXHAUSTIVE_ORDERS") else 150
PRICES = {"A": "price_reg_test", "B": "price_cell_test"}


def _apply(store: AccountStore, event: dict) -> None:
    kind = event["type"]
    obj = event["data"]["object"]
    created = event["created"]
    if kind == "checkout.session.completed":
        billing_routes._handle_checkout(store, kind, obj, event["id"], created)
    elif kind == "invoice.payment_failed":
        billing_routes._handle_payment_failed(store, kind, obj, event["id"], created)
    elif kind.startswith("customer.subscription."):
        billing_routes._handle_subscription(store, kind, obj, event["id"], created)
    # anything else (invoice.payment_succeeded) is acknowledged and ignored by the route


def _final(store: AccountStore) -> tuple[str, str, str]:
    acct = store.account_by_customer("cus_1")
    assert acct is not None
    return acct.status, acct.tier, acct.stripe_subscription_id


def _scenario(name: str):
    ck = checkout_event
    su = subscription_event
    scenarios = {
        # buy register, buy cell, cancel register, a late retry fails on the cell invoice
        # and the cell subscription heals at the end
        "upgrade_cancel_old_heal": (
            [ck("cs_A", "cus_1", "sub_A", "register", T, event_id="e1"),
             ck("cs_B", "cus_1", "sub_B", "cell", T + 10, event_id="e2"),
             su("customer.subscription.updated", "cus_1", "sub_A", PRICES["A"], "active", T + 15,
                event_id="e3"),
             su("customer.subscription.deleted", "cus_1", "sub_A", PRICES["A"], "canceled", T + 20,
                event_id="e4"),
             payment_failed_event("cus_1", T + 25, sub="sub_B", event_id="e5"),
             su("customer.subscription.updated", "cus_1", "sub_B", PRICES["B"], "active", T + 30,
                event_id="e6")],
            ("active", "cell", "sub_B"),
        ),
        # the same, without the heal: the cell plan is flagged past due
        "upgrade_cancel_old_past_due": (
            [ck("cs_A", "cus_1", "sub_A", "register", T, event_id="e1"),
             ck("cs_B", "cus_1", "sub_B", "cell", T + 10, event_id="e2"),
             su("customer.subscription.deleted", "cus_1", "sub_A", PRICES["A"], "canceled", T + 20,
                event_id="e3"),
             payment_failed_event("cus_1", T + 25, sub="sub_B", event_id="e4"),
             evt("invoice.payment_succeeded", {"customer": "cus_1"}, T + 26, "e5"),
             su("customer.subscription.updated", "cus_1", "sub_OTHER", "price_unrelated", "active",
                T + 27, event_id="e6")],
            ("past_due", "cell", "sub_B"),
        ),
        # everything is cancelled, a late payment failure and a foreign active event follow
        "all_cancelled": (
            [ck("cs_A", "cus_1", "sub_A", "register", T, event_id="e1"),
             ck("cs_B", "cus_1", "sub_B", "cell", T + 10, event_id="e2"),
             su("customer.subscription.deleted", "cus_1", "sub_A", PRICES["A"], "canceled", T + 20,
                event_id="e3"),
             su("customer.subscription.deleted", "cus_1", "sub_B", PRICES["B"], "canceled", T + 30,
                event_id="e4"),
             payment_failed_event("cus_1", T + 35, sub="sub_B", event_id="e5"),
             su("customer.subscription.updated", "cus_1", "sub_OTHER", "price_unrelated", "active",
                T + 36, event_id="e6")],
            ("cancelled", "free", "sub_B"),
        ),
        # pause, resume, pause again on one subscription; an unrelated product renews
        "pause_resume_pause": (
            [ck("cs_A", "cus_1", "sub_A", "cell", T, event_id="e1"),
             su("customer.subscription.updated", "cus_1", "sub_A", PRICES["B"], "paused", T + 10,
                event_id="e2"),
             su("customer.subscription.updated", "cus_1", "sub_A", PRICES["B"], "active", T + 20,
                event_id="e3"),
             su("customer.subscription.updated", "cus_1", "sub_A", PRICES["B"], "paused", T + 30,
                event_id="e4"),
             su("customer.subscription.updated", "cus_1", "sub_OTHER", "price_unrelated", "active",
                T + 40, event_id="e5")],
            ("cancelled", "cell", "sub_A"),
        ),
        # an in-place downgrade on one subscription, then a cancellation of an unrelated
        # earlier purchase
        "downgrade_in_place": (
            [ck("cs_A", "cus_1", "sub_A", "cell", T, event_id="e1"),
             su("customer.subscription.updated", "cus_1", "sub_A", PRICES["A"], "active", T + 10,
                event_id="e2"),
             su("customer.subscription.deleted", "cus_1", "sub_Z", PRICES["A"], "canceled", T - 5,
                event_id="e3"),
             payment_failed_event("cus_1", T + 5, event_id="e4"),
             su("customer.subscription.updated", "cus_1", "sub_A", PRICES["A"], "active", T + 20,
                event_id="e5")],
            ("active", "register", "sub_A"),
        ),
    }
    return scenarios[name]


@pytest.mark.parametrize("name", [
    "upgrade_cancel_old_heal", "upgrade_cancel_old_past_due", "all_cancelled",
    "pause_resume_pause", "downgrade_in_place",
])
def test_every_delivery_order_ends_in_the_same_entitlement(name, tmp_path, billing_env):
    events, expected = _scenario(name)
    seed = AccountStore(str(tmp_path / "seed.db"))  # create the schema once
    del seed
    import shutil

    outcomes: dict[tuple[str, str, str], list[tuple[str, ...]]] = {}
    orders = list(itertools.permutations(range(len(events))))
    random.Random(7).shuffle(orders)
    orders = orders[:ORDERS_PER_SCENARIO]
    for n, order in enumerate(orders):
        db = tmp_path / f"run{n % 2}.db"
        for suffix in ("", "-wal", "-shm"):
            (tmp_path / f"run{n % 2}.db{suffix}").unlink(missing_ok=True)
        shutil.copy(tmp_path / "seed.db", db)
        store = AccountStore(str(db))
        for i in order:
            _apply(store, events[i])
        outcomes.setdefault(_final(store), []).append(tuple(events[i]["id"] for i in order))
    assert set(outcomes) == {expected}, {
        state: orders_[:3] for state, orders_ in outcomes.items()}
