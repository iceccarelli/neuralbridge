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
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

__all__ = [
    "StripeError",
    "SignatureError",
    "stripe_configured",
    "METER_API_VERSION",
    "Transport",
    "create_checkout_session",
    "create_billing_portal_session",
    "create_meter_event",
    "is_configuration_error",
    "is_definitive_rejection",
    "list_meter_event_summaries",
    "list_invoices",
    "list_subscriptions",
    "retrieve_subscription",
    "verify_webhook",
]

API = "https://api.stripe.com/v1"
_TOLERANCE_SECONDS = 300

#: Billing Meters (``/v1/billing/meter_events``) are generally available from
#: the 2024-09-30.acacia API version; the older ``2024-06-20`` this module pins
#: for everything else predates them. Sent per request on meter calls only.
#: **From Stripe's published contract as remembered, never exercised against
#: Stripe** - the first run in test mode is what confirms it.
METER_API_VERSION = "2024-09-30.acacia"

#: How a request reaches Stripe, injectable so every meter call can be tested
#: against a fake: ``transport(method, path, form, headers) -> (status, body)``.
#: A transport that cannot reach Stripe raises :class:`StripeError` (no status).
Transport = Callable[
    [str, str, Sequence[tuple[str, str]], Mapping[str, str]], tuple[int, Any]
]


class StripeError(RuntimeError):
    """Stripe refused the call, or is not configured.

    ``status`` and ``code`` carry Stripe's HTTP status and error code when it
    answered (``resource_missing`` for an id it does not know); both are empty
    for a call that never reached Stripe.
    """

    def __init__(
        self, message: str = "", *, status: int | None = None, code: str = "", param: str = "",
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        #: The request parameter Stripe blames (``event_name``), when it names one.
        self.param = param


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


_SECRET_LOOKING = re.compile(r"\b(?:sk|rk|pk|whsec)_[A-Za-z0-9_*]+")
_STRIPE_ID = re.compile(r"[A-Za-z0-9_]{1,255}")


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
    """A read-only Stripe call. Same auth, version, timeout and errors as :func:`_post`."""
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
    return _unwrap(response)


def _post(path: str, form: list[tuple[str, str]]) -> dict[str, Any]:
    """A write call (Checkout, portal).

    A transport error and Stripe's 4xx text are handled exactly as in
    :func:`_get`: a scrubbed :class:`StripeError`, never a raw ``httpx``
    exception (which the routes would turn into a 500).
    """
    try:
        response = httpx.post(
            f"{API}{path}",
            # A mapping: httpx treats a list of tuples as raw request content and
            # fails to send it (found when the metering calls were first tested
            # through a real httpx transport). Our form keys are unique.
            data=dict(form),
            auth=(_secret_key(), ""),
            timeout=20.0,
            headers={"Stripe-Version": "2024-06-20"},
        )
    except httpx.HTTPError as exc:
        # The class name only: a transport error's text can carry the URL.
        raise StripeError(f"Stripe request failed ({type(exc).__name__})") from None
    return _unwrap(response)


def _unwrap(response: httpx.Response) -> dict[str, Any]:
    """The JSON object of a successful reply, or a scrubbed :class:`StripeError`."""
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
            param=str(error.get("param") or ""),
        )
    if not isinstance(body, dict):
        raise StripeError(f"Stripe {response.status_code}: response was not a JSON object")
    return body


def _httpx_transport(
    method: str, path: str, form: Sequence[tuple[str, str]], headers: Mapping[str, str]
) -> tuple[int, Any]:
    """The real transport: plain HTTP with the configured secret key."""
    try:
        response = httpx.request(
            method, f"{API}{path}",
            data=dict(form) if method == "POST" else None,
            params=dict(form) if method == "GET" and form else None,
            auth=(_secret_key(), ""), timeout=20.0, headers=dict(headers),
        )
    except httpx.HTTPError as exc:
        # The class name only: a transport error's text can carry the URL.
        raise StripeError(f"Stripe request failed ({type(exc).__name__})") from None
    try:
        body: Any = response.json()
    except ValueError:
        body = None
    return response.status_code, body


def _call(
    method: str, path: str, form: Sequence[tuple[str, str]], headers: Mapping[str, str],
    transport: Transport | None,
) -> dict[str, Any]:
    status, body = (transport or _httpx_transport)(method, path, form, headers)
    if status >= 400:
        error = body.get("error", {}) if isinstance(body, dict) else {}
        error = error if isinstance(error, dict) else {}
        raise StripeError(
            f"Stripe {status}: {_scrub(str(error.get('message') or f'HTTP {status}'))}",
            status=status, code=str(error.get("code") or ""),
            param=str(error.get("param") or ""),
        )
    if not isinstance(body, dict):
        raise StripeError(f"Stripe {status}: response was not a JSON object", status=status)
    return body


def is_configuration_error(exc: StripeError) -> bool:
    """Is this refusal about OUR setup rather than about the event sent?

    A 401/403 (the key was rotated, revoked or lacks the permission), a 404 (the
    meter path is wrong) or a 400 that blames the meter or its ``event_name``
    would be returned for *every* event until an operator fixes the
    configuration. Treating one as a verdict on the event would throw away
    revenue that is perfectly billable, so callers abort the run and leave the
    rows as they were.
    """
    if exc.status in (401, 403, 404):
        return True
    if exc.status == 400:
        text = f"{exc} {exc.param}".lower()
        return exc.param == "event_name" or "event_name" in text or "meter" in text
    return False


def is_definitive_rejection(exc: StripeError) -> bool:
    """Did Stripe look at *this event* and refuse it for good?

    A 4xx other than 408 (timeout), 409 (a request with this idempotency key is
    in flight) and 429 (slow down) will fail the same way every time - unless it
    is a :func:`configuration error <is_configuration_error>`, which says nothing
    about the event. Anything else - a 5xx, a timeout, no answer at all - may
    have been received, and the caller must retry with the *same* identifier
    rather than conclude anything.
    """
    return (
        exc.status is not None and 400 <= exc.status < 500
        and exc.status not in (408, 409, 429)
        and not is_configuration_error(exc)
    )


def create_meter_event(
    *,
    event_name: str,
    customer_id: str,
    value: int,
    identifier: str,
    timestamp: int,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Report ``value`` units of usage for one Stripe customer: ``POST /v1/billing/meter_events``.

    ``identifier`` is the idempotency handle: Stripe enforces uniqueness of a
    meter event identifier within a rolling window of at least 24 hours, so a
    retry with the same identifier is never counted twice. The same value is
    sent as the ``Idempotency-Key`` header, so a retry whose first response was
    lost is replayed rather than re-executed. ``timestamp`` is unix seconds of
    when the usage *happened* (Stripe accepts up to 35 days back, and not more
    than a few minutes ahead). The customer is named in
    ``payload[stripe_customer_id]`` and the amount in ``payload[value]``, the
    default keys of a Billing Meter configured for ``sum`` aggregation.

    Acknowledgement is the HTTP 2xx and the returned object: Stripe validates
    the event asynchronously afterwards (a bad customer, say, surfaces later as a
    ``v1.billing.meter.error_report_triggered`` event, not here), which is why
    ``billing/reconcile.py`` also compares totals with the meter's summaries.

    **Exercised against a fake transport only.**
    """
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise StripeError("a meter event value must be a positive integer")
    if not _STRIPE_ID.fullmatch(customer_id or ""):
        raise StripeError("not a Stripe customer id", status=400, code="invalid_id")
    if not identifier or len(identifier) > 100:
        raise StripeError("a meter event identifier must be 1-100 characters")
    form = [
        ("event_name", event_name),
        ("payload[stripe_customer_id]", customer_id),
        ("payload[value]", str(value)),
        ("identifier", identifier),
        ("timestamp", str(int(timestamp))),
    ]
    headers = {"Stripe-Version": METER_API_VERSION, "Idempotency-Key": identifier}
    return _call("POST", "/billing/meter_events", form, headers, transport)


def list_meter_event_summaries(
    *,
    meter_id: str,
    customer_id: str,
    start_time: int,
    end_time: int,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """What Stripe has aggregated for one customer on one meter: ``GET .../event_summaries``.

    Read-only. ``start_time`` and ``end_time`` are unix seconds and must fall on
    minute boundaries (Stripe requires it); the caller sums ``aggregated_value``
    across the returned summaries. **Exercised against a fake transport only.**
    """
    if not _STRIPE_ID.fullmatch(meter_id or "") or not _STRIPE_ID.fullmatch(customer_id or ""):
        raise StripeError("not a Stripe id", status=400, code="invalid_id")
    form = [
        ("customer", customer_id),
        ("start_time", str(int(start_time) // 60 * 60)),
        ("end_time", str(-(-int(end_time) // 60) * 60)),
    ]
    return _call("GET", f"/billing/meters/{meter_id}/event_summaries", form,
                 {"Stripe-Version": METER_API_VERSION}, transport)


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


def list_invoices(
    subscription: str | None = None,
    status: str = "open",
    starting_after: str | None = None,
    limit: int = 100,
) -> dict[str, Any]:
    """One page of invoices: ``{"data": [...], "has_more": bool}``. Read-only.

    ``status="open"`` is the unpaid ones; the oldest of a past-due subscription
    shows how long it has really been unpaid, which Stripe's subscription
    object does not say.
    """
    params: list[tuple[str, str]] = [
        ("status", status),
        ("limit", str(max(1, min(int(limit), 100)))),
    ]
    if subscription:
        params.append(("subscription", subscription))
    if starting_after:
        params.append(("starting_after", starting_after))
    return _get("/invoices", params)


def retrieve_subscription(subscription_id: str) -> dict[str, Any]:
    """One subscription by id. Read-only."""
    if not _STRIPE_ID.fullmatch(subscription_id or ""):
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
    metered: bool = False,
) -> CheckoutSession:
    """A subscription checkout for one manufacturer.

    ``tier`` travels in metadata so the webhook can grant the right entitlement
    without having to map prices back to plans a second time, in a place where
    a mismatch would silently over- or under-grant.

    ``metered`` is a usage-based price (pay-as-you-go): Stripe takes no quantity
    for those - the amount is whatever the meter reports - and rejects one.
    """
    form: list[tuple[str, str]] = [
        ("mode", "subscription"),
        ("line_items[0][price]", price_id),
        *([] if metered else [("line_items[0][quantity]", "1")]),
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
