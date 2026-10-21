"""What a Stripe subscription means for an account.

One mapping, two callers. The webhook (``api/billing_routes.py``) applies it to
the subscription object inside an event; the reconciler
(``billing/reconcile.py``) applies it to the subscription Stripe reports now.
If they ever disagreed, reconciliation would "correct" accounts the webhook had
set correctly, so there is exactly one copy.

The rules (unchanged from when they lived in the webhook module):

* ``active`` / ``trialing``: entitled; the tier comes from the price.
* ``past_due``: still entitled (Stripe's dunning decides); the tier is kept.
* ``canceled`` / ``unpaid`` / ``incomplete_expired`` / a ``deleted`` event: over;
  back to the free plan, tier record included.
* ``paused`` / ``incomplete``: not paying and not over; no entitlement, tier
  remembered so a return to ``active`` restores it.
* Anything else: unknown. Guessing in either direction is wrong, so the mapping
  returns ``None`` and callers change nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .plans import plan_for_price

__all__ = [
    "ENTITLED",
    "PURCHASABLE_TIERS",
    "SUSPENDED",
    "TERMINAL",
    "SubscriptionState",
    "map_subscription",
    "subscription_price_id",
    "subscription_tier",
    "subscription_tier_source",
]

#: Tiers a Stripe checkout may grant. Never ``free``, never ``supplier``
#: (sales-assigned), never anything a payload merely claims. ``payg`` is a
#: usage-based subscription: holding it grants nothing by itself (it has no
#: register, no machine verification) and bills only while the deployment has
#: pay-as-you-go configured (``plans.payg_available``).
PURCHASABLE_TIERS = ("register", "cell", "payg")

#: Stripe subscription statuses, and what each does to the entitlement.
ENTITLED = {"active", "trialing"}
#: The subscription is over: back to the free plan, tier record included.
TERMINAL = {"canceled", "unpaid", "incomplete_expired"}
#: Not paying right now and not yet over: no paid entitlement, tier remembered
#: so that a return to ``active`` restores it.
SUSPENDED = {"paused", "incomplete"}


@dataclass(frozen=True)
class SubscriptionState:
    """The account state a subscription maps to."""

    #: The account status: ``active``, ``past_due`` or ``cancelled``.
    status: str
    #: The tier to write, or None to leave the account's tier as it is.
    tier: str | None
    #: The webhook's response label for this transition.
    label: str
    #: ``entitled``, ``past_due``, ``suspended`` or ``terminal``.
    kind: str
    #: Whether the subscription is one of ours (a purchasable tier resolves).
    ours: bool


def subscription_price_id(obj: dict[str, Any]) -> str:
    return ((obj.get("items", {}).get("data") or [{}])[0].get("price") or {}).get("id", "")


def subscription_tier_source(obj: dict[str, Any]) -> tuple[str | None, str]:
    """``(tier, source)``: which purchasable tier a subscription is for.

    ``source`` is ``"price"`` (the price id resolves through ``plan_for_price``,
    authoritative) or ``"metadata"`` (the tier written into the subscription at
    checkout, the fallback), or ``""`` when it is not one of ours.
    """
    price = subscription_price_id(obj)
    plan = plan_for_price(price) if price else None
    if plan is not None and plan.tier in PURCHASABLE_TIERS:
        return plan.tier, "price"
    declared = (obj.get("metadata") or {}).get("tier")
    if declared in PURCHASABLE_TIERS:
        return declared, "metadata"
    return None, ""


def subscription_tier(obj: dict[str, Any]) -> str | None:
    """Which purchasable tier a subscription object is for, or None if not ours.

    The price id is authoritative; the tier written into the subscription's
    metadata at checkout is the fallback. Anything that is not a purchasable
    tier is None, which is also how another product's subscription on the same
    Stripe account is recognised and left alone.
    """
    return subscription_tier_source(obj)[0]


def map_subscription(obj: dict[str, Any], *, deleted: bool = False) -> SubscriptionState | None:
    """Map a subscription object to the account state it implies, or None if unknown.

    ``deleted`` is true for a ``customer.subscription.deleted`` event, which is
    terminal whatever status the object carries.
    """
    stripe_status = obj.get("status", "")
    ours = subscription_tier(obj) is not None

    if deleted or stripe_status in TERMINAL:
        return SubscriptionState("cancelled", "free", "downgraded_to_free", "terminal", ours)
    if stripe_status in SUSPENDED:
        return SubscriptionState("cancelled", None, "suspended", "suspended", ours)
    if stripe_status == "past_due":
        return SubscriptionState("past_due", None, "marked_past_due", "past_due", ours)
    if stripe_status in ENTITLED:
        return SubscriptionState(
            "active", subscription_tier(obj), "reactivated", "entitled", ours
        )
    return None
