"""Usage metering: what is counted, when, and who may be billed for it.

The rules, each enforced in code and pinned by ``tests/test_assurance_usage.py``:

* **Only these four operations are metered** (:data:`~.plans.METERED_SCOPES`):
  Article 14 draft validation, the separation calculator, the manifest diff and
  the advisory check. One successful call is one unit. Cases, change-assurance
  cases and every other register write are *never* metered: a meter on filing a
  regulatory report, or on opening a case after an incident, would discourage
  exactly the behaviour this product exists to make routine.
* **A unit is counted at one moment**: when the operation has computed its whole
  response successfully, immediately before that response is returned
  (:meth:`api.deps.MeterTicket.commit`). A request that fails validation (422),
  is refused by the domain (4xx) or crashes (5xx) never reaches that point and
  records nothing. A request that has been refused for quota records nothing
  either. (Delivery of the response to the client is not part of "success": a
  client that disconnects after the commit has still been served, and retries
  safely with the same ``Idempotency-Key``.)
* **The count and the quota check are one transaction**
  (:meth:`~.accounts.AccountStore.record_usage`): no counting somewhere else
  and reconciling later, so no window in which a cap can be overshot.
* **Over the allowance, billing is opt-in twice**: the account must be on a
  plan with ``metered_overage`` *and* have set a spend limit above zero, and the
  deployment must have pay-as-you-go configured (:func:`~.plans.payg_available`).
  Otherwise the daily allowance is a hard cap and the API answers 429.

This service never learns a price. The unit price lives in the Stripe metered
Price; here a billable unit is a unit and the spend limit is in units.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Protocol

from ..core.identity import format_utc
from .plans import METERED_SCOPES, Plan, payg_available

if TYPE_CHECKING:
    from .accounts import Account


class AccountStoreLike(Protocol):
    """The reads :func:`usage_report` needs (``AccountStore`` provides them)."""

    def usage_today(self, subject: str) -> dict[str, int]: ...
    def usage_totals(
        self, account_id: str, *, start: str = ..., end: str = ...
    ) -> dict[str, dict[str, int]]: ...
    def billable_by_state(self, account_id: str = ...) -> dict[str, int]: ...
    def usage_events(
        self, account_id: str, *, start: str = ..., end: str = ..., limit: int = ...
    ) -> list[dict[str, Any]]: ...

__all__ = [
    "MAX_KEY_LENGTH",
    "MAX_SPEND_LIMIT_UNITS",
    "Period",
    "allowance_for",
    "month_bounds",
    "overage_allowed",
    "parse_period",
    "payg_available",
    "usage_report",
    "valid_idempotency_key",
]

#: Longest idempotency key accepted. Stripe's own limit on a meter event
#: ``identifier`` is far larger, and ours is never sent: the event id is.
MAX_KEY_LENGTH = 255

#: A ceiling on a self-set spend limit, so a typo cannot disable the guard.
MAX_SPEND_LIMIT_UNITS = 1_000_000

_KEY = re.compile(r"[A-Za-z0-9._:\-]{1,255}")
_PERIOD = re.compile(r"(?P<year>\d{4})-(?P<month>0[1-9]|1[0-2])")


def valid_idempotency_key(key: str) -> bool:
    """Printable, no spaces or slashes, 1 to 255 characters."""
    return isinstance(key, str) and _KEY.fullmatch(key) is not None


def allowance_for(plan: Plan, scope: str) -> int | None:
    """The free daily allowance of ``scope`` on ``plan``; ``None`` = not metered.

    ``ValueError`` for a scope that is not metered at all (cases, for one).
    """
    attribute = METERED_SCOPES.get(scope)
    if attribute is None:
        raise ValueError(f"{scope!r} is not a metered scope")
    value = getattr(plan, attribute)
    return value if value is None else int(value)


def overage_allowed(account: Account) -> bool:
    """May this account run past its daily allowance and be billed for it?

    Every condition is checked on every request, never cached on the account:
    the plan has ``metered_overage``, the account is entitled right now (a
    cancelled subscription is on the free plan and fails here), it is bound to a
    Stripe customer (so there is someone to bill), and the deployment has
    pay-as-you-go configured. Whether a *limit* has room is a separate check.
    """
    return (
        account.plan.metered_overage
        and account.tier == "payg"
        and bool(account.stripe_customer_id)
        and payg_available()
    )


def month_bounds(moment: datetime) -> tuple[str, str]:
    """``[start, end)`` of the UTC calendar month containing ``moment``, as ISO strings."""
    start = moment.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    following = (start + timedelta(days=32)).replace(day=1)
    return format_utc(start), format_utc(following)


@dataclass(frozen=True)
class Period:
    """A reporting window. ``end`` is exclusive."""

    label: str
    kind: str  # "month" | "today"
    start: str
    end: str

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "kind": self.kind, "start": self.start, "end": self.end}


def parse_period(text: str | None, now: datetime) -> Period:
    """``None``/``current`` = this UTC month, ``today``, or ``YYYY-MM``.

    ``ValueError`` for anything else. A month is the unit the spend limit is
    enforced over; it need not coincide with a Stripe invoice period.
    """
    if text in (None, "", "current"):
        start, end = month_bounds(now)
        return Period(now.strftime("%Y-%m"), "month", start, end)
    if text == "today":
        midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return Period(
            "today", "today", format_utc(midnight), format_utc(midnight + timedelta(days=1)))
    match = _PERIOD.fullmatch(text)
    if match is None:
        raise ValueError("period must be 'current', 'today' or YYYY-MM")
    first = now.replace(year=int(match["year"]), month=int(match["month"]), day=1)
    start, end = month_bounds(first)
    return Period(text, "month", start, end)


# ---------------------------------------------------------------------------
# what a caller sees
# ---------------------------------------------------------------------------
_PAYG_NOTE = (
    "Units, not money: the amount billed is computed by Stripe from the metered price "
    "it holds for pay-as-you-go. This service does not know that price and shows no "
    "amount. billable_units counts operations beyond the free daily allowance this "
    "UTC month; spend_limit_units caps them."
)


def usage_report(
    accounts: AccountStoreLike,
    account: Account | None,
    *,
    period: Period,
    now: datetime,
    events: int = 0,
) -> dict[str, Any]:
    """The caller's own metering state. Everything here is read from the store.

    ``account`` is always the authenticated principal's account, never a value
    taken from a request. No total is accepted from a client anywhere.
    """
    if account is None or account.id == "operator":
        return {
            "metered": False,
            "reason": "Operator keys and anonymous callers have no account usage; "
                      "an anonymous caller's daily allowance is counted per address and "
                      "is not recorded as events.",
            "period": period.to_dict(),
            "scopes": {},
            "events": [],
        }
    today = accounts.usage_today(account.id)
    totals = accounts.usage_totals(account.id, start=period.start, end=period.end)
    scopes: dict[str, Any] = {}
    for scope in METERED_SCOPES:
        allowance = allowance_for(account.plan, scope)
        used = today.get(scope, 0)
        row = totals.get(scope, {"quantity": 0, "billable_quantity": 0})
        scopes[scope] = {
            "included_per_day": allowance,
            "used_today": used,
            "remaining_today": None if allowance is None else max(0, allowance - used),
            "period_total": row["quantity"],
            "period_included": row["quantity"] - row["billable_quantity"],
            "period_billable": row["billable_quantity"],
        }
    month_start, month_end = month_bounds(now)
    billable = sum(
        v["billable_quantity"]
        for v in accounts.usage_totals(account.id, start=month_start, end=month_end).values()
    )
    by_state = accounts.billable_by_state(account.id)
    enabled = overage_allowed(account)
    limit = account.spend_limit_units
    report: dict[str, Any] = {
        "metered": True,
        "account_id": account.id,
        "tier": account.plan.tier,
        "period": period.to_dict(),
        "scopes": scopes,
        "payg": {
            "available": payg_available(),
            "enabled": enabled,
            "month": now.strftime("%Y-%m"),
            "spend_limit_units": limit,
            "billable_units": billable,
            "remaining_units": max(0, limit - billable) if enabled else None,
            "budget_alert_pct": account.budget_alert_pct,
            "budget_alert": bool(
                enabled and limit > 0 and billable * 100 >= limit * account.budget_alert_pct),
            "unreported_units": by_state.get("pending", 0) + by_state.get("sending", 0),
            "needs_attention_units": by_state.get("ambiguous", 0) + by_state.get("rejected", 0),
            "note": _PAYG_NOTE,
        },
        "not_metered": (
            "Article 14 cases, change-assurance cases, machine verification, attestation "
            "and the free re-verification routes are never metered."
        ),
    }
    if events:
        report["events"] = accounts.usage_events(
            account.id, start=period.start, end=period.end, limit=events)
    return report
