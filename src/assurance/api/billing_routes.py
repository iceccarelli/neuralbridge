"""Plans, checkout, and the account behind a key.

The loop this closes: a prospect finds the free validator, hits the daily cap,
sees what the paid plan removes, pays, and gets a working API key in the
Stripe redirect. No email thread, no manual provisioning, no founder in the
middle of the transaction.

Two decisions worth stating.

**The key is minted by the webhook, not by the success page.** A browser that
lands on a success URL proves nothing; a signed ``checkout.session.completed``
event does. The success page looks the key up by session id, and says "not
ready yet" if the webhook has not landed, rather than issuing one on the
strength of a URL anyone could visit.

**The key is shown exactly once.** It is stored only as ``sha256``, so this is
not a policy but a fact about the store: nobody, including the operator, can
retrieve it later.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from ..billing import stripe_gateway as stripe
from ..billing.accounts import AccountStore, Principal
from ..billing.plans import PLANS, plan_for_price, public_catalogue
from .deps import current_principal, get_accounts, marketing_url, public_url

__all__ = ["billing_router"]

billing_router = APIRouter(prefix="/v1", tags=["billing"])


class CheckoutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tier: str = Field(pattern="^(register|cell)$")
    # A plain pattern rather than EmailStr: correctness here is Stripe's job,
    # and pulling in email-validator to reject "a@b" would be a dependency
    # bought for nothing.
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=320)
    company: str = Field(default="", max_length=200)


class CheckoutOut(BaseModel):
    checkout_url: str
    tier: str
    price: str


@billing_router.get("/plans", response_model=list, summary="What is on sale")
def get_plans() -> list[dict[str, Any]]:
    """Every tier and exactly what it permits.

    ``limits`` is generated from the same objects the service enforces, so the
    pricing page cannot drift from the software.
    """
    return public_catalogue()


@billing_router.post(
    "/checkout", response_model=CheckoutOut, summary="Start a subscription"
)
def post_checkout(body: CheckoutIn, request: Request) -> CheckoutOut:
    plan = PLANS[body.tier]
    if not plan.purchasable:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "price_not_configured",
                "detail": (
                    f"No Stripe price is configured for the {body.tier} plan "
                    f"({plan.price_env} is unset). Checkout is disabled rather than "
                    "taking money for something that cannot be provisioned."
                ),
            },
        )
    market = marketing_url()
    try:
        session = stripe.create_checkout_session(
            price_id=plan.price_id,
            email=body.email,
            company=body.company,
            success_url=f"{market}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{market}/#pricing",
            tier=plan.tier,
        )
    except stripe.StripeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "checkout_unavailable", "detail": str(exc)},
        ) from exc
    return CheckoutOut(checkout_url=session.url, tier=plan.tier, price=plan.price_label)


@billing_router.get(
    "/checkout/complete", response_model=dict, summary="Collect the key after paying"
)
def get_checkout_complete(
    session_id: str, accounts: AccountStore = Depends(get_accounts)
) -> dict[str, Any]:
    """Hand over the key the webhook minted for this checkout session.

    Returns 202 while the webhook is still in flight. It does not mint a key
    here: landing on this URL proves only that a browser followed a redirect.
    """
    pending = accounts.claim_pending_key(session_id)
    if pending is None:
        raise HTTPException(
            status_code=status.HTTP_202_ACCEPTED,
            detail={
                "status": "pending",
                "detail": (
                    "Payment is confirmed by Stripe's webhook, which has not arrived yet. "
                    "Retry in a few seconds. If this persists, the webhook endpoint is not "
                    "reachable or STRIPE_WEBHOOK_SECRET is wrong."
                ),
            },
        )
    return {
        "api_key": pending["api_key"],
        "tier": pending["tier"],
        "account_id": pending["account_id"],
        "keep_this": (
            "This key is shown once. Only its SHA-256 is stored, so it cannot be "
            "recovered — not by you and not by us. Store it now."
        ),
        "use_it": {"header": "X-API-Key", "start_here": "GET /v1/me"},
    }


@billing_router.post(
    "/billing/webhook", response_model=dict, summary="Stripe webhook (signature verified)"
)
async def post_webhook(
    request: Request, accounts: AccountStore = Depends(get_accounts)
) -> dict[str, Any]:
    """Grant, downgrade and cancel entitlements from signed Stripe events.

    Unverified payloads are refused. Without that, this endpoint is a way for
    anyone on the internet to grant themselves a paid subscription.
    """
    payload = await request.body()
    signature = request.headers.get("stripe-signature", "")
    try:
        event = stripe.verify_webhook(payload, signature)
    except stripe.SignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "signature_rejected", "detail": str(exc)},
        ) from exc

    kind = event.get("type", "")
    obj = event.get("data", {}).get("object", {})

    if kind == "checkout.session.completed":
        tier = (obj.get("metadata") or {}).get("tier", "register")
        email = obj.get("customer_details", {}).get("email") or obj.get("customer_email", "")
        company = (obj.get("metadata") or {}).get("company", "") or obj.get(
            "client_reference_id", ""
        )
        customer = obj.get("customer", "") or ""
        subscription = obj.get("subscription", "") or ""
        account = accounts.upsert_account(
            email=email,
            tier=tier,
            company=company,
            stripe_customer_id=customer,
            stripe_subscription_id=subscription,
            status="active",
        )
        key = accounts.issue_key(account.id, label="issued at checkout")
        accounts.stage_pending_key(obj.get("id", ""), account.id, key, tier)
        return {"handled": kind, "account_id": account.id, "tier": tier}

    if kind in {"customer.subscription.updated", "customer.subscription.deleted"}:
        customer = obj.get("customer", "") or ""
        stripe_status = obj.get("status", "")
        if kind == "customer.subscription.deleted" or stripe_status in {"canceled", "unpaid"}:
            accounts.set_status(
                stripe_customer_id=customer, status="cancelled", tier="free"
            )
            return {"handled": kind, "result": "downgraded_to_free"}
        if stripe_status == "past_due":
            accounts.set_status(stripe_customer_id=customer, status="past_due")
            return {"handled": kind, "result": "marked_past_due"}
        price = ((obj.get("items", {}).get("data") or [{}])[0].get("price") or {}).get("id", "")
        plan = plan_for_price(price)
        accounts.set_status(
            stripe_customer_id=customer,
            status="active",
            tier=plan.tier if plan else None,
        )
        return {"handled": kind, "result": "reactivated"}

    # Everything else is acknowledged and ignored, so Stripe stops retrying.
    return {"handled": None, "ignored": kind}


@billing_router.get("/me", response_model=dict, summary="Your account, plan and usage")
def get_me(
    principal: Principal = Depends(current_principal),
    accounts: AccountStore = Depends(get_accounts),
) -> dict[str, Any]:
    """What this key is entitled to, and what it has spent today."""
    plan = principal.plan
    body: dict[str, Any] = {
        "authenticated": principal.account is not None,
        "tier": plan.tier,
        "plan": plan.to_public_dict(),
        "usage_today": accounts.usage_today(principal.subject),
    }
    if principal.account is not None:
        body["account"] = {
            "id": principal.account.id,
            "company": principal.account.company,
            "email": principal.account.email,
            "status": principal.account.status,
        }
        body["keys"] = accounts.keys_for(principal.account.id)
    else:
        body["note"] = (
            "No key presented. You are on the free validator, limited per address. "
            "GET /v1/plans to see what a plan removes."
        )
    return body


@billing_router.post("/billing/portal", response_model=dict, summary="Manage your subscription")
def post_portal(principal: Principal = Depends(current_principal)) -> dict[str, Any]:
    """A self-service portal, so cancelling never requires emailing a human."""
    if principal.account is None or not principal.account.stripe_customer_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Stripe customer is associated with this key.",
        )
    try:
        url = stripe.create_billing_portal_session(
            customer_id=principal.account.stripe_customer_id,
            return_url=f"{public_url()}/v1/me",
        )
    except stripe.StripeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    return {"portal_url": url}
