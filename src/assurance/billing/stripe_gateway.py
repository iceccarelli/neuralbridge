"""Stripe, over plain HTTP.

No SDK. Two operations are needed — create a Checkout session, and verify a
webhook signature — and both are short enough that a dependency costs more
than it saves. ``httpx`` is already present for the rest of the service.

The signature check is the part that matters. A webhook endpoint that does not
verify is an endpoint where anyone on the internet can grant themselves a paid
subscription by posting JSON at it.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any

import httpx

__all__ = [
    "StripeError",
    "SignatureError",
    "stripe_configured",
    "create_checkout_session",
    "create_billing_portal_session",
    "list_subscriptions",
    "retrieve_subscription",
    "verify_webhook",
]

API = "https://api.stripe.com/v1"
_TOLERANCE_SECONDS = 300


class StripeError(RuntimeError):
    """Stripe refused the call, or is not configured.

    ``status`` and ``code`` carry Stripe's HTTP status and error code when it
    answered (``resource_missing`` for an id it does not know); both are empty
    for a call that never reached Stripe.
    """

    def __init__(self, message: str = "", *, status: int | None = None, code: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class SignatureError(StripeError):
    """A webhook did not carry a signature this service can verify."""


def _secret_key() -> str:
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key:
        raise StripeError(
            "STRIPE_SECRET_KEY is not set. Checkout is disabled until it is; the service "
            "will not pretend to take payment."
        )
    return key


def stripe_configured() -> bool:
    return bool(os.environ.get("STRIPE_SECRET_KEY"))


def webhook_configured() -> bool:
    return bool(os.environ.get("STRIPE_WEBHOOK_SECRET"))


def _post(path: str, form: list[tuple[str, str]]) -> dict[str, Any]:
    response = httpx.post(
        f"{API}{path}",
        data=form,
        auth=(_secret_key(), ""),
        timeout=20.0,
        headers={"Stripe-Version": "2024-06-20"},
    )
    if response.status_code >= 400:
        detail = response.json().get("error", {}).get("message", response.text)
        raise StripeError(f"Stripe {response.status_code}: {detail}")
    return response.json()


_SECRET_LOOKING = re.compile(r"\b(?:sk|rk|pk|whsec)_[A-Za-z0-9_*]+")
_STRIPE_ID = re.compile(r"^[A-Za-z0-9_]{1,255}$")


def _scrub(text: str) -> str:
    """Remove anything key-shaped, and the configured key itself, from ``text``.

    Stripe's own message for a rejected key quotes part of it; it must not
    reach a log, an exception message or a terminal.
    """
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if key:
        text = text.replace(key, "[redacted]")
    return _SECRET_LOOKING.sub("[redacted]", text)


def _get(path: str, params: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    """A read-only Stripe call. Same auth, version and timeout as :func:`_post`."""
    try:
        response = httpx.get(
            f"{API}{path}",
            params=params or None,
            auth=(_secret_key(), ""),
            timeout=20.0,
            headers={"Stripe-Version": "2024-06-20"},
        )
    except httpx.HTTPError as exc:
        # The class name only: a transport error's text can carry the URL.
        raise StripeError(f"Stripe request failed ({type(exc).__name__})") from None
    try:
        body = response.json()
    except ValueError:
        body = None
    if response.status_code >= 400:
        error = body.get("error", {}) if isinstance(body, dict) else {}
        error = error if isinstance(error, dict) else {}
        detail = error.get("message") or f"HTTP {response.status_code}"
        raise StripeError(
            f"Stripe {response.status_code}: {_scrub(str(detail))}",
            status=response.status_code,
            code=str(error.get("code") or ""),
        )
    if not isinstance(body, dict):
        raise StripeError(f"Stripe {response.status_code}: response was not a JSON object")
    return body


def list_subscriptions(
    customer: str | None = None,
    status: str = "all",
    starting_after: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """One page of subscriptions: ``{"data": [...], "has_more": bool}``. Read-only.

    ``status="all"`` matters: Stripe's default listing leaves cancelled
    subscriptions out, which would make every ended subscription invisible to
    reconciliation. Callers page with ``starting_after`` (the last id seen).
    """
    params: list[tuple[str, str]] = [
        ("status", status),
        ("limit", str(max(1, min(int(limit), 100)))),
    ]
    if customer:
        params.append(("customer", customer))
    if starting_after:
        params.append(("starting_after", starting_after))
    return _get("/subscriptions", params)


def retrieve_subscription(subscription_id: str) -> dict[str, Any]:
    """One subscription by id. Read-only."""
    if not _STRIPE_ID.match(subscription_id or ""):
        raise StripeError("not a Stripe subscription id", status=400, code="invalid_id")
    return _get(f"/subscriptions/{subscription_id}")


@dataclass(frozen=True)
class CheckoutSession:
    id: str
    url: str


def create_checkout_session(
    *,
    price_id: str,
    email: str,
    company: str,
    success_url: str,
    cancel_url: str,
    tier: str,
) -> CheckoutSession:
    """A subscription checkout for one manufacturer.

    ``tier`` travels in metadata so the webhook can grant the right entitlement
    without having to map prices back to plans a second time, in a place where
    a mismatch would silently over- or under-grant.
    """
    form: list[tuple[str, str]] = [
        ("mode", "subscription"),
        ("line_items[0][price]", price_id),
        ("line_items[0][quantity]", "1"),
        ("customer_email", email),
        ("success_url", success_url),
        ("cancel_url", cancel_url),
        ("client_reference_id", company[:200] or email),
        ("metadata[tier]", tier),
        ("metadata[company]", company[:200]),
        ("subscription_data[metadata][tier]", tier),
        ("automatic_tax[enabled]", "true"),
        ("tax_id_collection[enabled]", "true"),
        ("billing_address_collection", "required"),
        ("allow_promotion_codes", "true"),
    ]
    payload = _post("/checkout/sessions", form)
    return CheckoutSession(id=payload["id"], url=payload["url"])


def create_billing_portal_session(*, customer_id: str, return_url: str) -> str:
    """A self-service portal so cancelling never requires emailing a human."""
    payload = _post(
        "/billing_portal/sessions",
        [("customer", customer_id), ("return_url", return_url)],
    )
    return payload["url"]


def verify_webhook(payload: bytes, signature_header: str, *, secret: str | None = None) -> dict[str, Any]:
    """Verify a Stripe signature and return the parsed event.

    Rejects a missing or malformed header, a wrong signature, and a timestamp
    outside the tolerance window — the last one is what stops a captured
    request being replayed later.
    """
    secret = secret or os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not secret:
        raise SignatureError(
            "STRIPE_WEBHOOK_SECRET is not set. This endpoint refuses unverified webhooks "
            "rather than trusting whatever arrives."
        )
    if not signature_header:
        raise SignatureError("no Stripe-Signature header")

    timestamp = ""
    candidates: list[str] = []
    for part in signature_header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            candidates.append(value)
    if not timestamp or not candidates:
        raise SignatureError("malformed Stripe-Signature header")

    try:
        age = abs(time.time() - int(timestamp))
    except ValueError:
        raise SignatureError("malformed timestamp in Stripe-Signature") from None
    if age > _TOLERANCE_SECONDS:
        raise SignatureError(
            f"signature timestamp is {age:.0f}s old, outside the "
            f"{_TOLERANCE_SECONDS}s tolerance; refusing a possible replay"
        )

    signed = f"{timestamp}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected.encode(), c.encode()) for c in candidates):
        raise SignatureError("signature does not match")

    return json.loads(payload.decode("utf-8"))
