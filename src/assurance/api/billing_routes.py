"""Plans, checkout, and the account behind a key.

The loop this closes: a prospect finds the free validator, hits the daily cap,
sees what the paid plan removes, pays, and gets a working API key in the
Stripe redirect. No email thread, no manual provisioning, no founder in the
middle of the transaction.

Two decisions worth stating.

**The key is minted by the webhook, not by the success page.** A browser that
lands on a success URL proves nothing; a signed ``checkout.session.completed``
event does. The success page asks ``POST /v1/checkout/complete`` for the key and
is told "not ready yet" if the webhook has not landed, rather than being issued
one on the strength of a URL anyone could visit.

**The key never travels in a URL, and the session id alone collects nothing.**
``POST /v1/checkout`` mints a claim token, stores its hash against the Stripe session and
returns it, with the Stripe ``session_id``, **in the response to that call only**. The token is
*not* put in the success URL or anywhere else Stripe sees: Stripe's Checkout Session object, its
API logs and its webhook payloads hold the session id and nothing that can collect the key. The
browser that started checkout keeps the token itself (the site stores it in that tab's
``sessionStorage`` under ``nb-checkout-claim:<session_id>`` before redirecting; ``sessionStorage``
is per tab, so a different tab, browser or device has no token). The collection call is a POST
whose body carries both the session id and the token; a wrong or missing token consumes nothing,
so a stranger cannot lock the buyer out. The token is still a bearer secret: whoever saw the
response to ``POST /v1/checkout`` (the buyer's client, a proxy or log that records response
bodies) or can read that tab's ``sessionStorage`` can collect the key first, and holding the
session id alone cannot. A buyer who pays from one tab and returns in another gets a clear
"key is held" answer; recovery is an operator re-issue
(``python -m assurance.billing.issue_key --discard-staged cs_... --account acc_...``).

**Money coming back revokes, and never grants.** A full refund, an open or lost
dispute: the account lapses (free plan, evidence still readable); a partial
refund is recorded; a won dispute releases (see ``_handle_refund``).

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

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field, model_validator

from ..billing import stripe_gateway as stripe
from ..billing.accounts import (
    MAX_ACTIVE_KEYS,
    PENDING_KEY_TTL,
    AccountStore,
    KeyLimitError,
    Principal,
    hash_key,
)
from ..billing.metering import MAX_SPEND_LIMIT_UNITS, parse_period, usage_report
from ..billing.plans import PLANS, payg_available, public_catalogue
from ..billing.rate_limit import Limit, RateLimitedError, env_limit
from ..billing.subscription_state import PURCHASABLE_TIERS, map_subscription
from ..core.identity import utc_now
from .deps import (
    _client_address,
    current_principal,
    get_accounts,
    limiter_for,
    marketing_url,
    public_url,
    rate_limited,
    refuse_rate_limited,
    validate_startup_config,
)

__all__ = ["billing_router"]



@asynccontextmanager
async def _billing_lifespan(_app: Any) -> AsyncIterator[None]:
    """Refuse to start on an unsafe configuration (see ``deps.validate_startup_config``).

    Carried by this router so that ``uvicorn assurance.api.service:app`` -- the way the
    container runs it, with no ``main()`` in the path -- fails at start-up rather than serving.
    """
    validate_startup_config()
    yield


billing_router = APIRouter(prefix="/v1", tags=["billing"], lifespan=_billing_lifespan)

#: Per client address, per process (an edge limit is still the operator's job; see
#: ``billing/rate_limit.py``). Overridable with the named environment variable, ``0`` = off.
_CHECKOUT_LIMIT = Limit(5, 60.0)        # ASSURANCE_RATE_CHECKOUT, "<count>[/<seconds>]"
_CLAIM_LIMIT = Limit(20, 60.0)          # ASSURANCE_RATE_CLAIM
#: Calls to Stripe the whole process may start per hour, however many addresses ask.
_STRIPE_BUDGET = Limit(120, 3600.0)     # ASSURANCE_STRIPE_CHECKOUT_BUDGET
#: ... and the share of that budget one client address may spend, so a single address cannot
#: hold checkout shut for everyone. Failed Stripe calls count (the unit is spent before the call).
_STRIPE_BUDGET_PER_ADDRESS = Limit(20, 3600.0)   # ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS

_checkout_throttle = rate_limited(
    "checkout", _CHECKOUT_LIMIT, "ASSURANCE_RATE_CHECKOUT", what="checkout requests")
_claim_throttle = rate_limited(
    "claim", _CLAIM_LIMIT, "ASSURANCE_RATE_CLAIM", what="key-collection requests")


def _spend_stripe_budget(request: Request) -> None:
    """One unit of the Stripe-call budget, or a 429 (with Retry-After) before Stripe is called.

    Two gates, the address's own share first so that a refused address spends nothing of the
    shared budget: at most ``_STRIPE_BUDGET_PER_ADDRESS`` units per address per window, then the
    process-wide ``_STRIPE_BUDGET``. The residual, stated plainly: an attacker with many
    addresses can still exhaust the process-wide cap; this is per process and the edge limit
    (Fly proxy, Cloudflare, Vercel firewall) is the operator's job.
    """
    # Separate tables: the per-address table can fill with many addresses, and its eviction must
    # never be able to forget the single process-wide counter.
    address = _client_address(request, request.headers.get("fly-client-ip"))
    try:
        limiter_for(request, "stripe_budget_address").check(address, env_limit(
            "ASSURANCE_STRIPE_CHECKOUT_BUDGET_PER_ADDRESS", _STRIPE_BUDGET_PER_ADDRESS))
    except RateLimitedError as exc:
        raise refuse_rate_limited(exc.retry_after, what="checkouts from this address") from None
    try:
        limiter_for(request, "stripe_budget").check("all", env_limit("ASSURANCE_STRIPE_CHECKOUT_BUDGET", _STRIPE_BUDGET))
    except RateLimitedError as exc:
        raise refuse_rate_limited(exc.retry_after, what="checkouts across all callers") from None


#: Tiers a Stripe checkout may grant (shared with the reconciler; the
#: subscription-status mapping lives in ``billing/subscription_state.py``).
_PURCHASABLE_TIERS = PURCHASABLE_TIERS


class CheckoutIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tier: str = Field(pattern="^(register|cell|payg)$")
    # A plain pattern rather than EmailStr: correctness here is Stripe's job,
    # and pulling in email-validator to reject "a@b" would be a dependency
    # bought for nothing.
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=320)
    company: str = Field(default="", max_length=200)


class CheckoutOut(BaseModel):
    checkout_url: str
    tier: str
    price: str
    #: The Stripe Checkout Session id the claim token is bound to: the client keys its stored
    #: token on it (the success URL carries the same id back).
    session_id: str = ""
    #: A secret for collecting the key after paying. It is returned here, once, and nowhere
    #: else: it is NOT in the success URL, so Stripe never holds it. The client keeps it
    #: (per-tab ``sessionStorage``); only its hash is stored here.
    claim_token: str = ""


#: Every reply of the claim routes: nothing may cache a response that can carry a key.
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class ClaimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(pattern=r"^[A-Za-z0-9_\-]{1,255}$")
    claim_token: str = Field(default="", max_length=256)


@billing_router.get("/plans", response_model=list, summary="What is on sale")
def get_plans() -> list[dict[str, Any]]:
    """Every tier and exactly what it permits.

    ``limits`` is generated from the same objects the service enforces, so the
    pricing page cannot drift from the software.
    """
    return public_catalogue()


@billing_router.post(
    "/checkout", response_model=CheckoutOut, summary="Start a subscription",
    dependencies=[Depends(_checkout_throttle)],
)
def post_checkout(
    body: CheckoutIn,
    request: Request,
    principal: Principal = Depends(current_principal),
    accounts: AccountStore = Depends(get_accounts),
) -> CheckoutOut:
    if principal.operator_id:
        # A key bound to a person: starting a checkout acts on the account's Stripe customer
        # and subscription, so it needs the same role as the portal and the spend limit.
        _require_decider_for_keys(principal, "starting a checkout")
    account = principal.account
    if account is not None and account.is_manual_grant:
        # A pilot is not converted here: a checkout would create a second Stripe customer,
        # account and ledger beside it, and the billing portal has no customer to open.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "pilot_account",
                "tier": account.tier,
                "remedy": "This account is a pilot provisioned by an operator and invoiced "
                          "outside Stripe. Ask the operator who issued it to change or extend "
                          "it: a checkout would open a second account with a second, empty "
                          "ledger, splitting your evidence.",
            },
        )
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
    if body.tier == "payg" and not payg_available():
        # Off unless fully configured (a metered price, a meter, a test-mode
        # key): a subscription that cannot be metered must not be sold.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "payg_not_available",
                "detail": "Pay-as-you-go is not enabled on this deployment. Checkout is "
                          "disabled rather than selling a subscription that cannot be metered.",
            },
        )
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
    # Everything above is refused without costing a Stripe call. From here each request does,
    # so the process-wide budget is spent first: a flood from many addresses is stopped here.
    _spend_stripe_budget(request)
    claim_token = secrets.token_urlsafe(32)
    try:
        session = stripe.create_checkout_session(
            price_id=plan.price_id,
            email=body.email,
            company=body.company,
            # The claim token is deliberately NOT in this URL: Stripe stores the success URL on
            # the Checkout Session (API object, logs, webhook payload), so anything in it is
            # readable by anyone with Stripe access. The token reaches the buyer's browser only
            # in the reply to this call; the success page finds it in that tab's sessionStorage.
            success_url=f"{market}/checkout/success?session_id={{CHECKOUT_SESSION_ID}}",
            cancel_url=f"{market}/#pricing",
            tier=plan.tier,
            metered=plan.metered_overage,
            # A lapsed customer who comes back authenticated stays on their own Stripe
            # customer (and so their own account and ledger). An anonymous buyer is new.
            customer_id=(account.stripe_customer_id
                         if account is not None and account.id != "operator" else ""),
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
    accounts.register_checkout_claim(session.id, claim_token)
    return CheckoutOut(checkout_url=session.url, tier=plan.tier, price=plan.price_label,
                       session_id=session.id, claim_token=claim_token)


@billing_router.get(
    "/checkout/complete", response_model=dict, summary="Moved: collect the key with POST",
    deprecated=True, include_in_schema=False,
)
def get_checkout_complete(response: Response) -> dict[str, Any]:
    """Gone. The key used to be collected with a URL that carried the session id; it no longer is.

    A session id in a query string is written to browser history, sent in ``Referer``, and
    kept by analytics and proxies, and it used to be all a caller needed. This answers 410 and
    hands over nothing, whatever it is sent.
    """
    response.headers.update(_NO_STORE)
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail={
            "error": "moved",
            "detail": "A key is no longer collected from a URL.",
            "remedy": 'POST /v1/checkout/complete with JSON {"session_id": ..., '
                      '"claim_token": ...}. The claim token is in the reply to POST '
                      "/v1/checkout only (it is not in the success URL).",
        },
        headers=_NO_STORE,
    )


@billing_router.post(
    "/checkout/complete", response_model=dict, summary="Collect the key after paying",
    dependencies=[Depends(_claim_throttle)],
)
def post_checkout_complete(
    body: ClaimIn, response: Response, accounts: AccountStore = Depends(get_accounts)
) -> dict[str, Any]:
    """Hand over, once, the key the webhook minted for this checkout session.

    The browser's redirect proves nothing about payment and this route mints nothing: the key
    exists only after a signed ``checkout.session.completed``. What this adds is who may
    collect it: the caller must present the session id **and** the claim token that ``POST
    /v1/checkout`` returned, bound to that session and stored hashed. A leaked session id
    alone (history, ``Referer``, an analytics beacon, a log) claims nothing.

    The limit, stated plainly: the token is still a bearer secret. Whoever holds both values
    (anyone who saw the reply to ``POST /v1/checkout``, a script or extension that can read the
    buyer's tab ``sessionStorage``, a shared screen) can collect the key first. Stripe holds the
    session id but never the token.

    * 200: the key, exactly once.
    * 202 ``pending``: the webhook has not landed. Poll again.
    * 403 ``claim_token_required`` / ``claim_token_invalid``: a key is staged and this caller
      is not its holder. **Nothing is consumed**, so a stranger's guess does not lock the real
      buyer out.
    * 410 ``already_collected_or_expired``: the key was collected (by the buyer, or by whoever
      held both values), expired after 24 hours, or was lost in a restore. The buyer does not
      wait on this: an operator re-issues a key (``python -m assurance.billing.issue_key
      --account acc_...``, with ``--discard-staged cs_...`` first if one is still staged), and
      a key someone else collected is to be treated as exposed.
    """
    # The body of a successful reply is a secret: nothing may cache it.
    response.headers.update(_NO_STORE)
    outcome, pending = accounts.claim_checkout(body.session_id, body.claim_token)
    if outcome == "pending":
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
            headers=_NO_STORE,
        )
    if outcome == "forbidden":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "claim_token_required" if not body.claim_token
                else "claim_token_invalid",
                "detail": "A key is waiting for this checkout, but the claim token is missing "
                          "or does not match. Nothing was collected and the key is still "
                          "held for the buyer.",
                "remedy": "Use the browser that started the checkout. If the token is lost, "
                          "contact the operator with your session id: they can discard the "
                          "staged key and issue a new one.",
            },
            headers=_NO_STORE,
        )
    if outcome != "claimed" or pending is None:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={
                "error": "already_collected_or_expired",
                "detail": "This checkout completed, but no key is waiting for it: it was "
                          "already collected, it expired (24 hours), or it was lost in a "
                          "restore. It cannot be shown again.",
                "remedy": "If you did not collect it, treat it as exposed and contact the "
                          "operator with your session id: they issue a new key and revoke "
                          "the old. If you did, issue another with POST /v1/keys.",
            },
            headers=_NO_STORE,
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


def _invalid_payload(detail: str) -> HTTPException:
    # Correctly signed but not shaped like an event: a retry cannot fix it, so 400 (Stripe
    # reports it) rather than a 500 that Stripe retries for days. Nothing from the payload is
    # echoed back: this endpoint is public.
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": "invalid_payload", "detail": detail},
    )


#: Fields the handlers read as strings, and the objects they read as mappings. A signed body
#: can still carry any JSON, so each is type-checked once, here, before a handler indexes it.
_STR_FIELDS = ("id", "payment_status", "customer_email",
               "client_reference_id", "status")
_MAP_FIELDS = ("metadata", "customer_details", "items", "parent")


def _event_shape(event: Any) -> tuple[str, dict[str, Any]]:
    """``(type, data.object)`` of a verified event, or a clean 400 ``invalid_payload``."""
    if not isinstance(event, dict):
        raise _invalid_payload("the webhook body must be a JSON object.")
    kind = event.get("type", "")
    if not isinstance(kind, str):
        raise _invalid_payload("event type must be a string.")
    data = event.get("data", {})
    if not isinstance(data, dict):
        raise _invalid_payload("event data must be an object.")
    obj = data.get("object", {})
    if obj is None:
        obj = {}
    if not isinstance(obj, dict):
        raise _invalid_payload("event data.object must be an object.")
    for name in _MAP_FIELDS:
        if obj.get(name) is not None and not isinstance(obj[name], dict):
            raise _invalid_payload(f"event data.object.{name} must be an object.")
    for name in _STR_FIELDS:
        if obj.get(name) is not None and not isinstance(obj[name], str):
            raise _invalid_payload(f"event data.object.{name} must be a string.")
    customer = obj.get("customer")
    if customer is not None and not isinstance(customer, (str, dict)):
        raise _invalid_payload("event data.object.customer must be a string or an object.")
    metadata = obj.get("metadata") or {}
    for name in ("tier", "company"):
        if metadata.get(name) is not None and not isinstance(metadata[name], str):
            raise _invalid_payload(f"event metadata.{name} must be a string.")
    return kind, obj


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
    except stripe.PayloadError as exc:
        # Correctly signed, but not an event: nothing a retry could turn into success.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_payload", "detail": str(exc)},
        ) from exc
    except stripe.SignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "signature_rejected", "detail": str(exc)},
        ) from exc

    kind, obj = _event_shape(event)
    event_id = str(event.get("id", "") or "")
    try:
        created = int(event.get("created") or 0)
    except (TypeError, ValueError):
        created = 0

    if kind in {"checkout.session.completed", "checkout.session.async_payment_succeeded"}:
        return _handle_checkout(accounts, kind, obj, event_id, created)

    if kind == "invoice.payment_failed":
        return _handle_payment_failed(accounts, kind, obj, event_id, created)

    if kind in {"customer.subscription.updated", "customer.subscription.deleted"}:
        return _handle_subscription(accounts, kind, obj, event_id, created)

    if kind == "charge.refunded":
        return _handle_refund(accounts, kind, obj, event_id, created)

    if kind in _DISPUTE_EVENTS:
        return _handle_dispute(accounts, kind, obj, event_id, created)

    # Everything else is acknowledged and ignored, so Stripe stops retrying.
    return {"handled": None, "ignored": kind}


def _invoice_subscription(invoice: dict[str, Any]) -> str:
    """The subscription an invoice belongs to, or the empty string if it names none.

    Stripe puts it at ``subscription`` on older API versions and under
    ``parent.subscription_details.subscription`` on newer ones.
    """
    direct = invoice.get("subscription")
    if isinstance(direct, dict):
        direct = direct.get("id")
    if isinstance(direct, str) and direct:
        return direct
    parent = invoice.get("parent")
    details = parent.get("subscription_details") if isinstance(parent, dict) else None
    nested = details.get("subscription") if isinstance(details, dict) else None
    return nested if isinstance(nested, str) else ""


def _handle_payment_failed(
    accounts: AccountStore, kind: str, obj: dict[str, Any], event_id: str, created: int
) -> dict[str, Any]:
    # Stripe retries the charge on its own schedule and tells us when it
    # gives up (customer.subscription.updated/deleted). Until then the
    # account keeps its plan and is flagged. Only an active account moves:
    # a retry that fails after the subscription was cancelled must not
    # turn a cancelled account back into one that is entitled.
    customer = _stripe_id(obj.get("customer"))
    outcome = accounts.apply_subscription_event(
        event_id=event_id, kind=kind, stripe_customer_id=customer,
        status="past_due", tier=None, event_created=created,
        hold_if_unknown=False, only_from=frozenset({"active"}),
        stripe_subscription_id=_invoice_subscription(obj), payment_failure=True,
    )
    return _subscription_response(kind, outcome, "marked_past_due")


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
    customer = _stripe_id(obj.get("customer"))
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
    customer = _stripe_id(obj.get("customer"))
    state = map_subscription(obj, deleted=kind == "customer.subscription.deleted")
    if state is None:
        # A status this build does not know. Guessing in either direction is
        # wrong (the old code granted access); acknowledge and change nothing.
        return {"handled": kind, "result": "ignored_unknown_status"}

    outcome = accounts.apply_subscription_event(
        event_id=event_id, kind=kind, stripe_customer_id=customer,
        status=state.status, tier=state.tier, event_created=created,
        hold_if_unknown=state.ours,
        stripe_subscription_id=obj.get("id", "") or "",
        ours=state.ours,
    )
    return _subscription_response(kind, outcome, state.label)


#: Dispute lifecycle events that carry the dispute object. The state is read from the
#: dispute's own ``status``, never from which event brought it, so their order cannot matter.
_DISPUTE_EVENTS = frozenset({
    "charge.dispute.created", "charge.dispute.updated", "charge.dispute.closed",
    "charge.dispute.funds_withdrawn", "charge.dispute.funds_reinstated",
})

#: Stripe dispute status -> the hold state it implies (``billing/accounts.py:_HOLD_RANK``).
#: An open chargeback holds; a lost one revokes for good; a won one, or an inquiry that closed
#: without becoming a chargeback, releases; a warning-stage inquiry is only noted.
_DISPUTE_STATE = {
    "needs_response": "held",
    "under_review": "held",
    "lost": "lost",
    "won": "released",
    "warning_closed": "released",
    "warning_needs_response": "noted",
    "warning_under_review": "noted",
    "charge_refunded": "noted",
}


def _stripe_id(value: Any) -> str:
    """A Stripe id from a field that is a string or an expanded object."""
    if isinstance(value, dict):
        value = value.get("id")
    return value if isinstance(value, str) else ""


def _handle_refund(
    accounts: AccountStore, kind: str, obj: dict[str, Any], event_id: str, created: int
) -> dict[str, Any]:
    """A full refund revokes; a partial refund is recorded and revokes nothing.

    The account is moved to the same ``suspended`` phase a paused subscription has (free plan,
    tier remembered, read/verify/export of its own evidence kept), through
    ``AccountStore.apply_entitlement_hold``: idempotent per event id, a monotone join per
    charge so reordering cannot lose or invent it, and it never creates an account or a key.
    Only a charge that belongs to a subscription invoice counts: this Stripe account may sell
    other things, and refunding one of those is not about our plans.
    """
    customer = _stripe_id(obj.get("customer"))
    charge = obj.get("id", "") or ""
    if not customer or not charge:
        return {"handled": kind, "ignored": "no_customer_or_charge"}
    if not _stripe_id(obj.get("invoice")):
        return {"handled": kind, "ignored": "not_a_subscription_charge"}
    try:
        amount = int(obj.get("amount") or 0)
        refunded = int(obj.get("amount_refunded") or 0)
    except (TypeError, ValueError):
        return {"handled": kind, "ignored": "unreadable_amounts"}
    if obj.get("refunded") is True or (amount > 0 and refunded >= amount):
        state = "full"
    elif refunded > 0:
        state = "partial"
    else:
        return {"handled": kind, "ignored": "nothing_refunded"}
    outcome = accounts.apply_entitlement_hold(
        event_id=event_id, event_kind=kind, stripe_customer_id=customer,
        hold_id=f"refund:{charge}", kind="refund", state=state, event_created=created)
    return _hold_response(kind, outcome, state, "revoked" if state == "full" else "recorded")


def _handle_dispute(
    accounts: AccountStore, kind: str, obj: dict[str, Any], event_id: str, created: int
) -> dict[str, Any]:
    """An open dispute suspends, a lost one revokes, a won one releases. Never grants.

    The dispute names its charge, not its customer, so the charge is read from Stripe; if that
    fails the answer is 503 and Stripe redelivers (nothing was recorded, the event is not
    marked processed). Whether the event is the first or the fifth, its effect is the state
    in the dispute's ``status``, joined into the record so that a ``closed`` that arrives before
    its ``created`` leaves the dispute closed.
    """
    state = _DISPUTE_STATE.get(str(obj.get("status", "")))
    dispute = obj.get("id", "") or ""
    charge_id = _stripe_id(obj.get("charge"))
    if state is None or not dispute or not charge_id:
        return {"handled": kind, "ignored": "unreadable_dispute"}
    customer = _stripe_id(obj.get("customer"))
    invoice = _stripe_id(obj.get("invoice"))
    if not customer:
        try:
            charge = stripe.retrieve_charge(charge_id)
        except stripe.StripeError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "charge_lookup_failed",
                        "detail": "The dispute's charge could not be read from Stripe. "
                                  "Stripe will redeliver this event."},
            ) from exc
        customer = _stripe_id(charge.get("customer"))
        invoice = _stripe_id(charge.get("invoice"))
    if not customer:
        return {"handled": kind, "ignored": "no_customer_or_charge"}
    if not invoice:
        return {"handled": kind, "ignored": "not_a_subscription_charge"}
    outcome = accounts.apply_entitlement_hold(
        event_id=event_id, event_kind=kind, stripe_customer_id=customer,
        hold_id=f"dispute:{dispute}", kind="dispute", state=state, event_created=created)
    label = {"held": "suspended", "lost": "revoked", "released": "released"}.get(state, "recorded")
    return _hold_response(kind, outcome, state, label)


def _hold_response(kind: str, outcome: str, state: str, label: str) -> dict[str, Any]:
    if outcome == "duplicate":
        return {"handled": kind, "duplicate": True, "result": "duplicate"}
    return {"handled": kind, "result": label, "hold": state,
            "account_changed": outcome == "applied"}


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
        account = principal.account
        body["account"] = {
            "id": account.id,
            "company": account.company,
            "email": account.email,
            "status": account.status,
            # How this account came to exist. A manual grant is a pilot an operator
            # provisioned by hand and invoices outside Stripe; it is never shown as, or
            # mistaken for, a Stripe-paid account.
            "source": ("manual_grant" if account.is_manual_grant
                       else "stripe" if account.stripe_customer_id else "unbilled"),
        }
        if account.is_manual_grant:
            body["account"]["grant"] = {
                "note": account.grant_note,
                "granted_at": account.granted_at,
                "granted_by": account.granted_by,
                "expires_on": account.grant_expires_on,
                "lapsed": account.grant_lapsed,
                "invoiced_outside_stripe": True,
            }
        body["keys"] = accounts.keys_for(principal.account.id)
        body["usage"] = usage_report(
            accounts, principal.account, period=parse_period(None, utc_now()), now=utc_now())
        # A customer whose subscription ended keeps read/verify/export of their
        # own evidence (plans.EVIDENCE_READOUT_AFTER_LAPSE); writes are closed.
        body["evidence_readout"] = bool(
            principal.account.id != "operator" and principal.account.ever_paid
            and not plan.register
        )
        if principal.account.warning:
            body["warning"] = principal.account.warning
    else:
        body["note"] = (
            "No key presented. You are on the free validator, limited per address. "
            "GET /v1/plans to see what a plan removes."
        )
    return body


@billing_router.get("/usage", response_model=dict, summary="What your account has used")
def get_usage(
    principal: Annotated[Principal, Depends(current_principal)],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
    period: Annotated[
        str | None,
        Query(description="'current' (this UTC month, default), 'today' or YYYY-MM"),
    ] = None,
    events: Annotated[int, Query(ge=1, le=200, description="how many recent events")] = 50,
) -> dict[str, Any]:
    """Your own metered usage: per-scope totals, allowance, remaining, pay-as-you-go
    state and your recent events with their idempotency keys.

    Everything is read from the account store for the account the key belongs
    to. There is no parameter that names another account, and no total is ever
    taken from the client. The operator and anonymous callers have no account
    usage (anonymous gets a 401).
    """
    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usage needs an API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    now = utc_now()
    try:
        chosen = parse_period(period, now)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_period", "detail": str(exc)},
        ) from exc
    return usage_report(accounts, principal.account, period=chosen, now=now, events=events)


class UsageLimitsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: Most billable units (operations past the free daily allowance) per UTC
    #: month. 0 = never bill. Strict: a float or a string is refused, not coerced.
    spend_limit_units: int | None = Field(default=None, strict=True, ge=0, le=MAX_SPEND_LIMIT_UNITS)
    #: Percent of the limit at which GET /v1/usage raises ``budget_alert``.
    budget_alert_pct: int | None = Field(default=None, strict=True, ge=1, le=100)

    @model_validator(mode="after")
    def _something_to_set(self) -> UsageLimitsIn:
        if self.spend_limit_units is None and self.budget_alert_pct is None:
            raise ValueError("send spend_limit_units and/or budget_alert_pct")
        return self


@billing_router.post(
    "/usage/limits", response_model=dict, summary="Set your monthly spend limit and alert"
)
def post_usage_limits(
    body: UsageLimitsIn,
    principal: Annotated[Principal, Depends(current_principal)],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """Your guard against a surprise bill, in billable units per UTC month.

    Takes effect on the next call. Lowering it below what you have used stops
    billing at once. Setting a limit does not turn billing on: that needs the
    pay-as-you-go plan (a free or lapsed account stays at its daily cap).
    """
    account_id = _own_account(principal)
    if principal.operator_id:
        _require_decider_for_keys(principal, "setting the account's spend limit")
    account = accounts.set_spend_limit(
        account_id, units=body.spend_limit_units, budget_alert_pct=body.budget_alert_pct)
    now: datetime = utc_now()
    return usage_report(accounts, account, period=parse_period(None, now), now=now)


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


def _require_decider_for_keys(
    principal: Principal, action: str = "issuing or revoking account-level API keys"
) -> None:
    """Account-level credentials and billing are for account keys and deciders.

    A contributor operator's key is attributed to a person with no authority over
    the account's credentials, its subscription or its spend. Call this only for a
    key bound to a person (``principal.operator_id``); a plain account key passes.
    """
    if principal.operator_role != "decider":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "decider_role_required",
                    "detail": f"operator {principal.operator_name!r} has role "
                              f"{principal.operator_role!r}; {action} "
                              "needs an account key or a 'decider'."},
        )


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
    if principal.operator_id:
        # A key bound to a person may not mint an unattributed account-level key (that
        # would launder its role). A decider may; the label then says who did.
        _require_decider_for_keys(principal)
        label = f"{label} (issued by operator {principal.operator_name} {principal.operator_id})"
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
    if principal.operator_id:
        _require_decider_for_keys(principal)
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
    if outcome == "operator_key":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "operator_key",
                    "detail": "That key belongs to an individual operator. End it with "
                              "POST /v1/operators/{operator_id}/disable, which refuses to "
                              "remove the account's last decider."},
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
    if principal.operator_id:
        # The portal can cancel or change the subscription: not for a contributor's key.
        _require_decider_for_keys(principal, "managing the subscription")
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
