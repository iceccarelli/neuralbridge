"""A cancellation of an old subscription must not end the account's current one.

Regression: events were matched on the Stripe customer only. A customer who upgraded
by buying a second subscription and then cancelled the first was downgraded to free
while the second was still paid and active.
"""

from __future__ import annotations

import pytest

from assurance.billing.accounts import AccountStore


@pytest.fixture
def store(tmp_path):
    return AccountStore(str(tmp_path / "accounts.db"))


def _checkout(store, sub, *, event="evt_c2", session="cs_2", created=2000):
    return store.apply_checkout(
        event_id=event, session_id=session, email="buyer@example.invalid", company="Acme",
        tier="cell", stripe_customer_id="cus_1", stripe_subscription_id=sub,
        event_created=created,
    )


def _state(store):
    return store.account_by_customer("cus_1")


def _cancel(store, sub, *, event, created):
    return store.apply_subscription_event(
        event_id=event, kind="customer.subscription.deleted", stripe_customer_id="cus_1",
        status="cancelled", tier="free", event_created=created, hold_if_unknown=True,
        stripe_subscription_id=sub,
    )


def test_cancelling_the_old_subscription_leaves_the_current_one_active(store):
    _checkout(store, "sub_A", event="evt_c1", session="cs_1", created=1000)
    _checkout(store, "sub_B", event="evt_c2", session="cs_2", created=2000)
    assert _state(store).stripe_subscription_id == "sub_B"
    assert _cancel(store, "sub_A", event="evt_d1", created=3000) == "other_subscription"
    row = _state(store)
    assert row.status == "active" and row.tier == "cell"


def test_cancelling_the_current_subscription_still_ends_access(store):
    _checkout(store, "sub_A", event="evt_c1", session="cs_1", created=1000)
    assert _cancel(store, "sub_A", event="evt_d1", created=3000) == "applied"
    row = _state(store)
    assert row.status == "cancelled" and row.tier == "free"


def test_a_cancellation_with_no_subscription_id_behaves_as_before(store):
    _checkout(store, "sub_A", event="evt_c1", session="cs_1", created=1000)
    assert _cancel(store, "", event="evt_d1", created=3000) == "applied"


def test_an_out_of_order_older_checkout_cannot_overwrite_the_current_subscription_id(store):
    """Regression for the guard above: a stale checkout used to replace the stored id with
    the OLD subscription's, after which the real cancellation was ignored as
    ``other_subscription`` and a cancelled customer kept access (and the event was spent).
    """
    _checkout(store, "sub_B", event="evt_c2", session="cs_2", created=2000)
    _checkout(store, "sub_A", event="evt_c1", session="cs_1", created=1000)  # arrives late
    assert _state(store).stripe_subscription_id == "sub_B"
    assert _cancel(store, "sub_B", event="evt_d", created=3000) == "applied"
    row = _state(store)
    assert row.status == "cancelled" and row.tier == "free"
