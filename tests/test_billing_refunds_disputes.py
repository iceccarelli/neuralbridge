"""Refunds and disputes: a full refund or a lost dispute lapses the entitlement; nothing here grants.

Local only: signed webhooks with a throwaway secret on the real app, and a fake for the one
Stripe read a dispute needs (its charge's customer). The policy under test:

* full refund, open dispute, lost dispute: the account is not entitled (the same lapsed state a
  paused subscription has: free plan, tier remembered, own evidence still readable);
* partial refund, warning-stage inquiry: recorded, nothing revoked;
* dispute won: the hold is released and the subscription states decide again;
* idempotent per event id, and order-safe: the outcome is a function of the set of events.

What this does not do: it cannot know that a refunded *customer* meant to cancel, so a full
refund is treated as the end of access until an operator or a newer purchase says otherwise.
"""

from __future__ import annotations

import sqlite3

import pytest

from assurance.billing import stripe_gateway as stripe_gw

from .support_billing import (  # noqa: F401
    T,
    _billing_client_fixture,
    _billing_env_fixture,
    account_state,
    checkout_event,
    collect_key,
    evt,
    send,
    stored_state,
    subscription_event,
)


def refund(amount_refunded=39000, *, charge="ch_1", customer="cus_1", invoice="in_1",
           created=T + 100, event_id=None, amount=39000):
    return evt("charge.refunded", {
        "id": charge, "customer": customer, "invoice": invoice, "amount": amount,
        "amount_refunded": amount_refunded, "refunded": amount_refunded >= amount,
    }, created, event_id)


def dispute(status, kind="charge.dispute.created", *, dp="dp_1", charge="ch_1", created=T + 100,
            event_id=None):
    return evt(kind, {"id": dp, "charge": charge, "status": status}, created, event_id)


@pytest.fixture()
def paid(billing_client, monkeypatch):
    """A paid Cell account (cus_1) with its key collected, and a fake charge lookup."""
    monkeypatch.setattr(stripe_gw, "retrieve_charge",
                        lambda charge_id: {"id": charge_id, "customer": "cus_1", "invoice": "in_1"})
    assert send(billing_client, checkout_event("cs_1", "cus_1", "sub_1", "cell", T)
                ).status_code == 200
    key = collect_key(billing_client, "cs_1")
    assert account_state(billing_client, key) == ("active", "cell")
    return billing_client, key


def _count(billing_env, sql):
    return sqlite3.connect(billing_env / "accounts.db").execute(sql).fetchone()[0]


def test_a_full_refund_lapses_the_entitlement_and_keeps_read_access(paid, billing_env):
    c, key = paid
    r = send(c, refund())
    assert r.status_code == 200
    assert r.json()["result"] == "revoked" and r.json()["account_changed"] is True
    assert account_state(c, key) == ("cancelled", "free")
    # the tier is remembered, not erased (the same lapsed state as a paused subscription)
    assert stored_state(billing_env)[:2] == ("cancelled", "cell")
    me = c.get("/v1/me", headers={"X-API-Key": key}).json()
    assert me["evidence_readout"] is True          # lapsed customers keep read/verify/export
    # the paid write path is closed
    assert c.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 402


def test_a_partial_refund_is_recorded_and_revokes_nothing(paid, billing_env):
    c, key = paid
    r = send(c, refund(amount_refunded=1000))
    assert r.status_code == 200 and r.json()["hold"] == "partial"
    assert r.json()["account_changed"] is False
    assert account_state(c, key) == ("active", "cell")
    assert _count(billing_env, "SELECT COUNT(*) FROM entitlement_holds WHERE state='partial'") == 1
    # ... and a later full refund of the same charge then does revoke
    assert send(c, refund()).status_code == 200
    assert account_state(c, key) == ("cancelled", "free")


def test_a_duplicate_refund_event_is_acknowledged_and_changes_nothing(paid, billing_env):
    c, key = paid
    first = send(c, refund(event_id="evt_r"))
    again = send(c, refund(event_id="evt_r"))
    assert first.json()["result"] == "revoked"
    assert again.status_code == 200 and again.json()["duplicate"] is True
    assert _count(billing_env, "SELECT COUNT(*) FROM entitlement_holds") == 1
    assert account_state(c, key) == ("cancelled", "free")


def test_refund_events_in_the_wrong_order_end_in_the_same_place(paid):
    c, key = paid
    # the full refund first, then an older partial report of the same charge arrives late
    assert send(c, refund()).status_code == 200
    assert send(c, refund(amount_refunded=1000, created=T + 50)).status_code == 200
    assert account_state(c, key) == ("cancelled", "free")
    # a newer "subscription is active" report does not undo a refund (only the money can)
    assert send(c, subscription_event("customer.subscription.updated", "cus_1", "sub_1",
                                      "price_cell_test", "active", T + 500)).status_code == 200
    assert account_state(c, key) == ("cancelled", "free")


def test_a_refund_before_the_checkout_never_grants(billing_client, billing_env):
    """The refund overtakes checkout.session.completed: the account is born lapsed."""
    c = billing_client
    r = send(c, refund())
    assert r.status_code == 200 and r.json()["account_changed"] is False
    assert _count(billing_env, "SELECT COUNT(*) FROM accounts") == 0     # a refund creates nothing
    assert _count(billing_env, "SELECT COUNT(*) FROM api_keys") == 0
    assert send(c, checkout_event("cs_1", "cus_1", "sub_1", "cell", T)).status_code == 200
    key = collect_key(c, "cs_1")
    assert account_state(c, key) == ("cancelled", "free")
    assert c.get("/v1/fleet/machines", headers={"X-API-Key": key}).status_code == 402


def test_a_later_purchase_after_a_refund_is_entitled(paid):
    c, _ = paid
    assert send(c, refund()).status_code == 200
    # the customer comes back and pays again: bought after the refund, so not held by it
    assert send(c, checkout_event("cs_2", "cus_1", "sub_2", "cell", T + 5000)).status_code == 200
    key2 = collect_key(c, "cs_2")
    assert account_state(c, key2) == ("active", "cell")


def test_a_refund_of_something_that_is_not_a_subscription_invoice_is_ignored(paid):
    c, key = paid
    r = send(c, refund(invoice=None))
    assert r.json()["ignored"] == "not_a_subscription_charge"
    assert account_state(c, key) == ("active", "cell")
    r = send(c, refund(customer=None))
    assert r.json()["ignored"] == "no_customer_or_charge"


def test_a_dispute_suspends_and_winning_it_restores(paid):
    c, key = paid
    r = send(c, dispute("needs_response"))
    assert r.json()["result"] == "suspended" and r.json()["account_changed"] is True
    assert account_state(c, key) == ("cancelled", "free")
    won = send(c, dispute("won", "charge.dispute.closed", created=T + 900))
    assert won.json()["result"] == "released"
    assert account_state(c, key) == ("active", "cell")


def test_a_dispute_closed_before_it_was_created_stays_closed(paid):
    c, key = paid
    assert send(c, dispute("won", "charge.dispute.closed", created=T + 900)).status_code == 200
    assert account_state(c, key) == ("active", "cell")
    # the create event is delivered late: it cannot re-open what is already won
    assert send(c, dispute("needs_response", created=T + 100)).status_code == 200
    assert account_state(c, key) == ("active", "cell")


def test_a_lost_dispute_revokes_and_a_stray_win_cannot_undo_it(paid):
    c, key = paid
    assert send(c, dispute("needs_response")).status_code == 200
    assert send(c, dispute("lost", "charge.dispute.closed", created=T + 900)).status_code == 200
    assert account_state(c, key) == ("cancelled", "free")
    assert send(c, dispute("won", "charge.dispute.updated", created=T + 950)).status_code == 200
    assert account_state(c, key) == ("cancelled", "free")


def test_a_warning_stage_inquiry_is_only_noted(paid):
    c, key = paid
    r = send(c, dispute("warning_needs_response"))
    assert r.json()["hold"] == "noted" and r.json()["account_changed"] is False
    assert account_state(c, key) == ("active", "cell")


def test_a_duplicate_dispute_event_is_idempotent(paid, billing_env):
    c, key = paid
    assert send(c, dispute("needs_response", event_id="evt_d")).status_code == 200
    again = send(c, dispute("needs_response", event_id="evt_d"))
    assert again.json()["duplicate"] is True
    assert _count(billing_env, "SELECT COUNT(*) FROM entitlement_holds") == 1


def test_a_dispute_whose_charge_cannot_be_read_is_retried_not_dropped(paid, monkeypatch):
    c, key = paid

    def down(_charge_id):
        raise stripe_gw.StripeError("unreachable")

    monkeypatch.setattr(stripe_gw, "retrieve_charge", down)
    r = send(c, dispute("needs_response", event_id="evt_retry"))
    assert r.status_code == 503 and r.json()["detail"]["error"] == "charge_lookup_failed"
    assert account_state(c, key) == ("active", "cell")
    monkeypatch.setattr(stripe_gw, "retrieve_charge",
                        lambda charge_id: {"customer": "cus_1", "invoice": "in_1"})
    # Stripe redelivers the same event id: it was not marked processed, so it applies now
    assert send(c, dispute("needs_response", event_id="evt_retry")).json()["result"] == "suspended"
    assert account_state(c, key) == ("cancelled", "free")


def test_holds_never_create_accounts_or_keys(billing_client, billing_env, monkeypatch):
    monkeypatch.setattr(stripe_gw, "retrieve_charge",
                        lambda charge_id: {"customer": "cus_ghost", "invoice": "in_9"})
    for ev in (refund(customer="cus_ghost"), dispute("lost", "charge.dispute.closed")):
        assert send(billing_client, ev).status_code == 200
    assert _count(billing_env, "SELECT COUNT(*) FROM accounts") == 0
    assert _count(billing_env, "SELECT COUNT(*) FROM api_keys") == 0
    assert _count(billing_env, "SELECT COUNT(*) FROM pending_keys") == 0
