"""The small rules of the subscription state join, each pinned by one deterministic case.

The order-permutation tests prove delivery order does not matter; these prove *which* answer
it converges on at the edges, so that flipping a comparison (``>`` to ``>=``, a rank to its
opposite) cannot pass on the strength of a fuzz seed. Stripe stamps events with whole seconds,
so two reports about one subscription in the same second are normal.
"""

from __future__ import annotations

import itertools
import sqlite3

import pytest

from assurance.api import billing_routes
from assurance.billing.accounts import AccountStore

from .support_billing import (  # noqa: F401
    T,
    _billing_env_fixture,
    checkout_event,
    payment_failed_event,
    subscription_event,
)

REG, CELL = "price_reg_test", "price_cell_test"


def _store(tmp_path, name="a.db") -> AccountStore:
    return AccountStore(str(tmp_path / name))


def _buy(store, at=T, sub="sub_A", tier="cell"):
    obj = checkout_event("cs_" + sub, "cus_1", sub, tier, at)["data"]["object"]
    billing_routes._handle_checkout(store, "checkout.session.completed", obj, "e_" + sub, at)


_n = itertools.count(1)


def _report(store, status, at, sub="sub_A", price=CELL):
    kind = "customer.subscription.deleted" if status == "canceled" \
        else "customer.subscription.updated"
    obj = subscription_event(kind, "cus_1", sub, price, status, at)["data"]["object"]
    return billing_routes._handle_subscription(store, kind, obj, f"r{next(_n)}", at)


def _fail(store, at, sub="sub_A"):
    obj = payment_failed_event("cus_1", at, sub=sub)["data"]["object"]
    return billing_routes._handle_payment_failed(
        store, "invoice.payment_failed", obj, f"f{next(_n)}", at)


def _state(store):
    a = store.account_by_customer("cus_1")
    return a.status, a.tier


# ---------------------------------------------------------------------------
# two reports of one subscription in the same second: the more restrictive wins
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("restrictive,expected", [
    ("paused", ("cancelled", "cell")),
    ("past_due", ("past_due", "cell")),
    ("canceled", ("cancelled", "free")),
])
@pytest.mark.parametrize("order", ["restrictive_first", "restrictive_last"])
def test_at_the_same_second_the_more_restrictive_report_wins_in_either_order(
        tmp_path, billing_env, restrictive, expected, order):
    store = _store(tmp_path)
    _buy(store)
    steps = [("active", T + 10), (restrictive, T + 10)]
    for status, at in (steps if order == "restrictive_last" else steps[::-1]):
        _report(store, status, at)
    assert _state(store) == expected


def test_a_later_second_beats_a_more_restrictive_earlier_one_and_an_earlier_one_loses(
        tmp_path, billing_env):
    store = _store(tmp_path)
    _buy(store)
    _report(store, "paused", T + 10)
    assert _state(store) == ("cancelled", "cell")
    _report(store, "active", T + 11)                  # strictly newer: it wins
    assert _state(store) == ("active", "cell")
    _report(store, "paused", T + 9)                   # strictly older: it is stale
    assert _state(store) == ("active", "cell")


def test_an_exact_replay_of_a_report_is_stale_not_applied(tmp_path, billing_env):
    store = _store(tmp_path)
    _buy(store)
    assert _report(store, "paused", T + 10)["result"] != "ignored_stale"
    assert _report(store, "paused", T + 10)["result"] == "ignored_stale"


# ---------------------------------------------------------------------------
# the payment-failure rules
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("order", ["report_first", "failure_first"])
def test_a_failure_in_the_same_second_as_the_last_report_makes_it_past_due(
        tmp_path, billing_env, order):
    store = _store(tmp_path)
    _buy(store)
    steps = [lambda: _report(store, "active", T + 10), lambda: _fail(store, T + 10)]
    for step in (steps if order == "report_first" else steps[::-1]):
        step()
    assert _state(store) == ("past_due", "cell")


def test_a_failure_older_than_the_last_report_does_not_flag_it(tmp_path, billing_env):
    store = _store(tmp_path)
    _buy(store)
    _report(store, "active", T + 10)
    _fail(store, T + 9)
    assert _state(store) == ("active", "cell")


def test_only_a_strictly_newer_failure_is_news(tmp_path, billing_env):
    """The store answers ``stale`` for a failure no newer than the one it remembers."""
    store = _store(tmp_path)
    _buy(store)

    def failure(at):
        return store.apply_subscription_event(
            event_id=f"fe{next(_n)}", kind="invoice.payment_failed", stripe_customer_id="cus_1",
            status="past_due", tier=None, event_created=at, hold_if_unknown=False,
            stripe_subscription_id="sub_A", payment_failure=True)

    assert failure(T + 10) == "applied"
    assert failure(T + 10) == "stale"        # same second, new event id: nothing new
    assert failure(T + 9) == "stale"
    assert failure(T + 11) != "stale"


def test_a_failure_for_a_subscription_never_seen_creates_no_state_and_moves_no_clock(
        tmp_path, billing_env):
    store = _store(tmp_path)
    _buy(store)
    before = store.account_by_customer("cus_1")
    out = _fail(store, T + 500, sub="sub_never_seen")
    assert out["result"] == "ignored_other_subscription"
    after = store.account_by_customer("cus_1")
    assert (after.status, after.tier, after.last_event_at) == (
        before.status, before.tier, before.last_event_at)
    db = sqlite3.connect(store.path)
    try:
        assert db.execute("SELECT COUNT(*) FROM subscription_states "
                          "WHERE stripe_subscription_id='sub_never_seen'").fetchone()[0] == 0
    finally:
        db.close()


def test_the_failure_is_kept_and_counts_if_that_subscription_turns_out_to_be_ours(
        tmp_path, billing_env):
    store = _store(tmp_path)
    _buy(store)
    _fail(store, T + 20, sub="sub_B")                         # before sub_B is known
    _buy(store, at=T + 10, sub="sub_B", tier="cell")          # its purchase, older than the failure
    assert _state(store) == ("past_due", "cell")


# ---------------------------------------------------------------------------
# a cancelled subscription is stored as free, not as the plan it had
# ---------------------------------------------------------------------------
def test_a_cancelled_subscription_is_stored_as_the_free_tier(tmp_path, billing_env):
    store = _store(tmp_path)
    _buy(store)
    _report(store, "canceled", T + 10)
    assert _state(store) == ("cancelled", "free")
    # whereas a paused one keeps the plan it will return to
    store2 = _store(tmp_path, "b.db")
    _buy(store2)
    _report(store2, "paused", T + 10)
    assert _state(store2) == ("cancelled", "cell")
