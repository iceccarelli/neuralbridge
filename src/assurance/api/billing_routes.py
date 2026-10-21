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

**The key is shown exactly once.** Permanently it is stored only as ``sha256``,
so nobody, including the operator, can retrieve it later. The one exception is
the handover: from the webhook until the returning browser collects it, and
never longer than 24 hours, the new key waits in a staging row; collecting it
deletes the row. An uncollected one stops being claimable at expiry and is
removed the next time any billing event or collection touches the store, so
treat a backup of the accounts database as holding secrets.

**A webhook is applied once.** Stripe retries, and reorders, deliveries. Each
event id is recorded in the same transaction as its effects, subscription
events older than the newest one already applied for a customer are ignored,
and a subscription event that overtakes the checkout event is held until the
account exists.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from ..billing import stripe_gateway as stripe
from ..billing.accounts import (
    MAX_ACTIVE_KEYS,
    PENDING_KEY_TTL,
    AccountStore,
    KeyLimitError,
    Principal,
    hash_key,
)
from ..billing.plans import PLANS, public_catalogue
from ..billing.subscription_state import PURCHASABLE_TIERS, map_subscription
from .deps import current_principal, get_accounts, marketing_url, public_url

__all__ = ["billing_router"]

billing_router = APIRouter(prefix="/v1", tags=["billing"])

#: Tiers a Stripe checkout may grant (shared with the reconciler; the
#: subscription-status mapping lives in ``billing/subscription_state.py``).
_PURCHASABLE_TIERS = PURCHASABLE_TIERS


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
def post_checkout(
    body: CheckoutIn, request: Request, principal: Principal = Depends(current_principal)
) -> CheckoutOut:
    account = principal.account
    if account is not None and account.id != "operator" and account.status in {"active", "past_due"} \
            and account.tier in _PURCHASABLE_TIERS:
        # A second checkout would create a second Stripe customer, a second
        # account and a second, empty ledger — splitting the evidence the
        # customer is paying to keep — and could bill both subscriptions.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "already_subscribed",
                "tier": account.tier,
                "remedy": "Change or cancel your plan in the billing portal: "
                          "POST /v1/billing/portal with your key.",
            },
        )
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
            # The provider's own error text is not returned to an anonymous
            # caller: it can carry identifiers (a price id) and nothing the
            # caller can act on.
            detail={"error": "checkout_unavailable",
                    "detail": "The payment provider could not start checkout. Try again shortly."},
        ) from exc
    return CheckoutOut(checkout_url=session.url, tier=plan.tier, price=plan.price_label)


@billing_router.get(
    "/checkout/complete", response_model=dict, summary="Collect the key after paying"
)
def get_checkout_complete(
    session_id: str, response: Response, accounts: AccountStore = Depends(get_accounts)
) -> dict[str, Any]:
    """Hand over the key the webhook minted for this checkout session.

    Returns 202 while the webhook is still in flight. It does not mint a key
    here: landing on this URL proves only that a browser followed a redirect.
    """
    # The body of a successful reply is a secret: nothing may cache it.
    response.headers["Cache-Control"] = "no-store"
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
            "This key is shown once. It was held only until you collected it (at most "
            f"{int(PENDING_KEY_TTL.total_seconds() // 3600)} hours) and has now been "
            "deleted from that staging store; from here only its SHA-256 is kept, so it "
            "cannot be recovered — not by you and not by us. Store it now. If you lose "
            "it, issue another with POST /v1/keys from a key you still hold."
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
    obj = event.get("data", {}).get("object", {}) or {}
    event_id = str(event.get("id", "") or "")
    try:
        created = int(event.get("created") or 0)
    except (TypeError, ValueError):
        created = 0

    if kind in {"checkout.session.completed", "checkout.session.async_payment_succeeded"}:
        return _handle_checkout(accounts, kind, obj, event_id, created)

    if kind == "invoice.payment_failed":
        # Stripe retries the charge on its own schedule and tells us when it
        # gives up (customer.subscription.updated/deleted). Until then the
        # account keeps its plan and is flagged. Only an active account moves:
        # a retry that fails after the subscription was cancelled must not
        # turn a cancelled account back into one that is entitled.
        customer = obj.get("customer", "") or ""
        outcome = accounts.apply_subscription_event(
            event_id=event_id, kind=kind, stripe_customer_id=customer,
            status="past_due", tier=None, event_created=created,
            hold_if_unknown=False, only_from=frozenset({"active"}),
        )
        return _subscription_response(kind, outcome, "marked_past_due")

    if kind in {"customer.subscription.updated", "customer.subscription.deleted"}:
        return _handle_subscription(accounts, kind, obj, event_id, created)

    # Everything else is acknowledged and ignored, so Stripe stops retrying.
    return {"handled": None, "ignored": kind}


def _handle_checkout(
    accounts: AccountStore, kind: str, obj: dict[str, Any], event_id: str, created: int
) -> dict[str, Any]:
    metadata = obj.get("metadata") or {}
    tier = metadata.get("tier")
    if tier is None:
        # Not one of ours: a Stripe account that sells anything else sends this
        # endpoint those sessions too. Acknowledge (200) so Stripe does not retry
        # for days and, eventually, disable the endpoint that carries our own
        # cancellations. A tier that is present and wrong is still a 400.
        return {"handled": kind, "ignored": "no_neuralbridge_tier"}
    if tier not in _PURCHASABLE_TIERS:
        # Nothing from the payload is echoed back or logged: it is attacker-
        # or misconfiguration-controlled text and this endpoint is public.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_tier",
                "detail": f"checkout metadata.tier must be one of {list(_PURCHASABLE_TIERS)}.",
            },
        )
    session_id = obj.get("id", "") or ""
    customer = obj.get("customer", "") or ""
    if not session_id or not customer:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "incomplete_checkout_session",
                "detail": "checkout session id and customer are required.",
            },
        )
    payment_status = obj.get("payment_status", "")
    if payment_status == "unpaid":
        # A delayed payment method (SEPA debit, for instance): the session
        # completes before the money arrives. Grant on
        # checkout.session.async_payment_succeeded, not now.
        return {"handled": kind, "result": "awaiting_payment"}
    if payment_status not in {"paid", "no_payment_required"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_payment_status",
                    "detail": "checkout payment_status must be paid or no_payment_required."},
        )

    email = (obj.get("customer_details") or {}).get("email") or obj.get("customer_email", "") or ""
    company = metadata.get("company", "") or obj.get("client_reference_id", "") or ""
    outcome = accounts.apply_checkout(
        event_id=event_id,
        session_id=session_id,
        email=email,
        company=company,
        tier=tier,
        stripe_customer_id=customer,
        stripe_subscription_id=obj.get("subscription", "") or "",
        event_created=created,
    )
    if outcome["result"] == "duplicate":
        return {"handled": kind, "duplicate": True, "result": "duplicate"}
    return {"handled": kind, "account_id": outcome["account_id"], "tier": tier}


def _handle_subscription(
    accounts: AccountStore, kind: str, obj: dict[str, Any], event_id: str, created: int
) -> dict[str, Any]:
    customer = obj.get("customer", "") or ""
    state = map_subscription(obj, deleted=kind == "customer.subscription.deleted")
    if state is None:
        # A status this build does not know. Guessing in either direction is
        # wrong (the old code granted access); acknowledge and change nothing.
        return {"handled": kind, "result": "ignored_unknown_status"}

    outcome = accounts.apply_subscription_event(
        event_id=event_id, kind=kind, stripe_customer_id=customer,
        status=state.status, tier=state.tier, event_created=created,
        hold_if_unknown=state.ours,
    )
    return _subscription_response(kind, outcome, state.label)


def _subscription_response(kind: str, outcome: str, label: str) -> dict[str, Any]:
    if outcome == "applied":
        return {"handled": kind, "result": label}
    if outcome == "duplicate":
        return {"handled": kind, "duplicate": True, "result": "duplicate"}
    if outcome == "held":
        # The customer has no account yet; the state is kept and applied when
        # checkout.session.completed creates it. 200, because a retry would
        # change nothing.
        return {"handled": kind, "result": "held_until_checkout"}
    if outcome == "stale":
        return {"handled": kind, "result": "ignored_stale"}
    return {"handled": kind, "result": f"ignored_{outcome}"}


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
        if principal.account.warning:
            body["warning"] = principal.account.warning
    else:
        body["note"] = (
            "No key presented. You are on the free validator, limited per address. "
            "GET /v1/plans to see what a plan removes."
        )
    return body


class KeyIssueIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(default="", max_length=100)


class KeyRevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The ``prefix`` GET /v1/keys shows. Omit to revoke the key you are
    #: calling with.
    key_prefix: str = Field(default="", pattern=r"^(asr_[A-Za-z0-9_-]{6})?$")


def _own_account(principal: Principal) -> str:
    """The account id a key-management call acts on, or a refusal.

    Key management is available to any account regardless of plan or status:
    a customer whose subscription lapsed must still be able to revoke a leaked
    key.
    """
    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Key management needs an API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if principal.account.id == "operator":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "operator_key_not_managed",
                "detail": (
                    "Operator keys are not account keys. They are set in "
                    "ASSURANCE_API_KEYS by whoever deploys the service; rotate them there."
                ),
            },
        )
    return principal.account.id


@billing_router.get("/keys", response_model=dict, summary="List your API keys")
def get_keys(
    principal: Principal = Depends(current_principal),
    accounts: AccountStore = Depends(get_accounts),
) -> dict[str, Any]:
    """Prefixes, labels and dates. Never a key and never a hash."""
    account_id = _own_account(principal)
    return {
        "keys": accounts.keys_for(account_id),
        "active": accounts.active_key_count(account_id),
        "limit": MAX_ACTIVE_KEYS,
        "current_key_prefix": principal.key_prefix,
    }


@billing_router.post(
    "/keys",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Issue an additional API key for your account",
)
def post_key(
    body: KeyIssueIn | None = None,
    principal: Principal = Depends(current_principal),
    accounts: AccountStore = Depends(get_accounts),
) -> dict[str, Any]:
    """For rotation: issue the new key, move your systems over, revoke the old."""
    account_id = _own_account(principal)
    label = (body.label if body else "") or "issued via API"
    try:
        key = accounts.issue_key(account_id, label=label, max_active=MAX_ACTIVE_KEYS)
    except KeyLimitError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "key_limit", "limit": exc.limit,
                    "detail": f"An account may hold {exc.limit} active keys. Revoke one "
                              "with POST /v1/keys/revoke first."},
        ) from exc
    return {
        "api_key": key,
        "prefix": key[: len("asr_") + 6],
        "label": label,
        "keep_this": (
            "This key is shown once. Only its SHA-256 is stored, so it cannot be "
            "recovered — not by you and not by us. Store it now."
        ),
    }


@billing_router.post(
    "/keys/revoke",
    response_model=dict,
    summary="Revoke one of your API keys; it stops working immediately",
)
def post_key_revoke(
    body: KeyRevokeIn | None = None,
    x_api_key: str | None = Header(default=None),
    principal: Principal = Depends(current_principal),
    accounts: AccountStore = Depends(get_accounts),
) -> dict[str, Any]:
    """Revoke the key you present, or another of your own by ``key_prefix``.

    A prefix that belongs to a different account is reported exactly like one
    that does not exist.
    """
    account_id = _own_account(principal)
    prefix = body.key_prefix if body else ""
    if prefix:
        outcome = accounts.revoke_account_key(account_id, key_prefix=prefix)
    else:
        outcome = accounts.revoke_account_key(
            account_id, key_hash=hash_key((x_api_key or "").strip())
        )
    if outcome == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "no_such_key", "detail": "No key of yours matches."},
        )
    if outcome == "ambiguous":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "ambiguous_prefix",
                    "detail": "More than one live key shares that prefix. Revoke it by "
                              "calling with the key itself and no key_prefix."},
        )
    remaining = accounts.active_key_count(account_id)
    result: dict[str, Any] = {
        "revoked": outcome == "revoked",
        "already_revoked": outcome == "already_revoked",
        "active_keys_remaining": remaining,
    }
    if remaining == 0:
        result["warning"] = (
            "No active keys remain on this account. Nothing can authenticate as it "
            "until a key is issued, and issuing one needs a key."
        )
    return result


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
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The billing portal is unavailable. Try again shortly."
        ) from exc
    return {"portal_url": url}
