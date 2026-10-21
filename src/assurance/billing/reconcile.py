"""Reconcile the account store against Stripe, the system of record.

Entitlements are driven by webhooks, and webhooks get lost: the endpoint was
down, Stripe disabled it after repeated failures, a deploy left a gap. Then a
paying customer silently loses access, or a cancelled one silently keeps it,
and nobody finds out until someone complains. This module compares every
account that has a Stripe customer id with what Stripe says today, reports the
disagreements as a number (the **drift count**, an SLI: it should be 0), and
with ``--apply`` corrects the ones that can be corrected safely.

**Verified against a fake transport only.** It has never been run against real
Stripe. Run it with a Stripe *test-mode* key first, and read the dry-run report
before ever passing ``--apply``.

The rules this follows:

* **The same mapping as the webhook.** ``billing/subscription_state.py`` is
  shared; reconciliation cannot "correct" what the webhook set correctly.
* **Dry run by default.** ``apply=False`` writes nothing.
* **Only status and tier of existing accounts change.** Never an account's
  email, keys, ledger or customer id. Never the operator, never an account
  without a Stripe customer id, never a sales-assigned tier. A subscription with
  no account (an *orphan*) is reported and nothing is created: an account is
  born from a signed checkout event, and a key is minted once, there.
* **Nobody is upgraded on a guess.** An unknown Stripe status, two live
  subscriptions that disagree, or a tier only the (payload-writable) metadata
  names rather than a price id we recognise: reported as ``ambiguous``, never
  applied.
* **A webhook newer than the snapshot wins.** Stripe subscriptions carry no
  "updated" timestamp, so the snapshot instant is the start of the run (or a
  later Stripe-side time if Stripe's clock is ahead), less a clock-skew margin.
  An account whose newest applied webhook is later than that is *deferred*: the
  snapshot may predate the webhook. The comparison is repeated inside the write
  transaction, so a webhook that lands between planning and writing also wins.
* **All Stripe reads happen before any write.** An error from Stripe at any
  point leaves the store untouched and the report says it is incomplete.
* **Idempotent.** A second ``--apply`` finds nothing to do.
* **Secrets are never output.** Error text is scrubbed of key-shaped strings and
  the configured key; reports carry account ids, never emails.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.identity import utc_now
from . import stripe_gateway
from .accounts import ENTITLED_STATUSES, Account, AccountStore
from .payg import reconcile_usage
from .plans import payg_available
from .stripe_gateway import StripeError
from .subscription_state import (
    PURCHASABLE_TIERS,
    SubscriptionState,
    map_subscription,
    subscription_tier_source,
)

__all__ = [
    "CATEGORIES",
    "DEFAULT_PAST_DUE_DAYS",
    "NOTICE",
    "SKEW_SECONDS",
    "Finding",
    "ReconcileReport",
    "main",
    "reconcile",
]

NOTICE = (
    "Verified against a fake transport only; never run against real Stripe. "
    "Run with a Stripe test-mode key first."
)

DEFAULT_PAST_DUE_DAYS = 30

#: Margin between our clock and Stripe's. A webhook applied within this window
#: before the snapshot is treated as possibly newer than it.
SKEW_SECONDS = 60

#: Every kind of disagreement, and ``in_sync``.
CATEGORIES = (
    "in_sync",
    "stripe_active_but_we_deny",
    "stripe_ended_but_we_grant",
    "tier_mismatch",
    "status_mismatch",
    "past_due_too_long",
    "unknown_in_stripe",
    "stripe_subscription_without_account",
    "ambiguous",
)

_PAGE = 100
_MAX_PAGES = 1000
_DAY = 86400


@dataclass(frozen=True)
class Finding:
    """One account (or orphan subscription) that disagrees with Stripe."""

    category: str
    #: The account id; empty for an orphan subscription (no account exists).
    account_id: str = ""
    local_status: str = ""
    local_tier: str = ""
    #: What Stripe implies, when it is unambiguous.
    stripe_status: str = ""
    new_status: str = ""
    new_tier: str = ""
    stripe_customer_id: str = ""
    stripe_subscription_id: str = ""
    #: Whether ``--apply`` may correct it. Orphans, unknown customers and
    #: ambiguous states never can.
    correctable: bool = False
    #: Why it is not correctable, or a note.
    reason: str = ""
    #: ``reported`` | ``would_correct`` | ``corrected`` | ``noop`` | ``refused``
    #: | ``skipped``; ``reason`` carries the detail.
    action: str = "reported"
    #: The instant Stripe was read at for this account (run start, or a later
    #: Stripe-side time if Stripe's clock is ahead). The write is checked
    #: against it.
    observed_at: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "account_id": self.account_id,
            "local": {"status": self.local_status, "tier": self.local_tier},
            "stripe_status": self.stripe_status,
            "target": {"status": self.new_status, "tier": self.new_tier},
            "stripe_customer_id": self.stripe_customer_id,
            "stripe_subscription_id": self.stripe_subscription_id,
            "correctable": self.correctable,
            "action": self.action,
            "reason": self.reason,
        }


@dataclass
class ReconcileReport:
    run_id: str = ""
    apply: bool = False
    #: Unix seconds Stripe was read at (start of run), our clock.
    snapshot_at: int = 0
    past_due_days: int = DEFAULT_PAST_DUE_DAYS
    accounts_total: int = 0
    accounts_checked: int = 0
    in_sync: int = 0
    #: ``[{"account_id", "reason"}]``: operator, no customer id, sales-assigned tier.
    skipped: list[dict[str, str]] = field(default_factory=list)
    #: Accounts whose newest webhook is newer than the snapshot: not compared.
    deferred: list[dict[str, str]] = field(default_factory=list)
    #: Accounts Stripe could not be asked about (an error on their lookup).
    unchecked: list[dict[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    #: False when a Stripe error stopped the run. A partial report is still a
    #: report; nothing was written.
    complete: bool = True
    error: str = ""
    corrected: int = 0
    notice: str = NOTICE
    #: Pay-as-you-go usage against the provider's meter, or None when there is
    #: no billable usage and pay-as-you-go is off (the usual case): then the
    #: report is exactly what it was before usage metering existed.
    usage: Any = None

    @property
    def drift_count(self) -> int:
        """The SLI: accounts (and orphan subscriptions) that disagree with Stripe."""
        return len(self.findings)

    @property
    def by_category(self) -> dict[str, int]:
        counts = {c: 0 for c in CATEGORIES if c != "in_sync"}
        for f in self.findings:
            counts[f.category] = counts.get(f.category, 0) + 1
        return counts

    @property
    def drift_account_ids(self) -> list[str]:
        return sorted({f.account_id for f in self.findings if f.account_id})

    @property
    def fully_checked(self) -> bool:
        """True only when every eligible account was compared against Stripe.

        Deferred and unchecked accounts are *not* in sync: they were not
        verified, and "not verified" must never read as clean.
        """
        return self.complete and not self.deferred and not self.unchecked

    @property
    def exit_code(self) -> int:
        """0 in sync and fully checked; 1 drift found (corrected or not) or some
        account deferred (not checked this run); 2 could not complete."""
        code = 2 if not self.complete else (1 if (self.drift_count or self.deferred) else 0)
        if self.usage is not None:
            code = max(code, self.usage.exit_code)
        return code

    def to_dict(self) -> dict[str, Any]:
        payload = self._base_dict()
        if self.usage is not None:
            payload["usage"] = self.usage.to_dict()
        payload["exit_code"] = self.exit_code
        return payload

    def _base_dict(self) -> dict[str, Any]:
        return {
            "notice": self.notice,
            "run_id": self.run_id,
            "mode": "apply" if self.apply else "dry_run",
            "complete": self.complete,
            "fully_checked": self.fully_checked,
            "error": self.error,
            "snapshot_at": self.snapshot_at,
            "past_due_days": self.past_due_days,
            "drift_count": self.drift_count,
            "deferred_count": len(self.deferred),
            "by_category": self.by_category,
            "drift_account_ids": self.drift_account_ids,
            "accounts": {
                "total": self.accounts_total,
                "checked": self.accounts_checked,
                "in_sync": self.in_sync,
                "skipped": len(self.skipped),
                "deferred": len(self.deferred),
                "unchecked": len(self.unchecked),
            },
            "corrected": self.corrected,
            "findings": [f.to_dict() for f in self.findings],
            "skipped": self.skipped,
            "deferred": self.deferred,
            "unchecked": self.unchecked,
            "exit_code": self.exit_code,
        }

    def render(self) -> str:
        """Plain text. Account ids and Stripe object ids only; no emails, no keys."""
        mode = (
            "APPLY: corrections are written; the store is migrated additively if needed"
            if self.apply else
            "dry run: the account store is opened read-only and corrections are not written"
        )
        lines = [
            f"NeuralBridge billing reconciliation ({mode})",
            f"NOTICE: {self.notice}",
            f"run {self.run_id}  snapshot {self.snapshot_at}",
            f"accounts: total={self.accounts_total} checked={self.accounts_checked} "
            f"in_sync={self.in_sync} skipped={len(self.skipped)} "
            f"deferred={len(self.deferred)} unchecked={len(self.unchecked)}",
            f"drift_count={self.drift_count}",
            f"deferred_count={len(self.deferred)}",
        ]
        for category, n in self.by_category.items():
            if n:
                lines.append(f"  {category}={n}")
        for f in self.findings:
            who = f.account_id or f"orphan {f.stripe_subscription_id} ({f.stripe_customer_id})"
            move = ""
            if f.new_status or f.new_tier:
                move = (f"  {f.local_status}/{f.local_tier} -> "
                        f"{f.new_status or f.local_status}/{f.new_tier or f.local_tier}")
            lines.append(f"  {who}: {f.category}{move} [{f.action}] {f.reason}".rstrip())
        for d in self.deferred:
            lines.append(f"  deferred {d['account_id']}: {d['reason']}")
        for u in self.unchecked:
            lines.append(f"  unchecked {u['account_id']}: {u['reason']}")
        if self.apply:
            lines.append(f"corrected={self.corrected}")
        if not self.complete:
            lines.append(
                f"INCOMPLETE: {self.error} Nothing was written; this report covers only "
                "what could be read. Exit 2."
            )
        else:
            if self.drift_count:
                lines.append("DRIFT FOUND. Exit 1.")
            if self.deferred:
                lines.append(
                    f"NOT FULLY CHECKED: {len(self.deferred)} account(s) deferred (a newer "
                    "webhook exists); run again. Exit 1."
                )
            if not self.drift_count and not self.deferred:
                lines.append("IN SYNC. Exit 0.")
        text = "\n".join(lines)
        if self.usage is not None:
            text += "\n\n" + self.usage.render()
        return text


# ---------------------------------------------------------------------------
# reading Stripe
# ---------------------------------------------------------------------------
class _IncompleteError(Exception):
    """Stripe could not be read to the end; carries a scrubbed message."""


@dataclass(frozen=True)
class _Sub:
    id: str
    customer: str
    raw_status: str
    state: SubscriptionState | None
    tier: str | None
    tier_source: str
    #: Stripe-side times seen on the object (``created``, ``canceled_at``, ...).
    stamps: tuple[int, ...]

    @property
    def ours(self) -> bool:
        return self.tier is not None


def _customer_of(obj: dict[str, Any]) -> str:
    customer = obj.get("customer")
    if isinstance(customer, dict):
        customer = customer.get("id")
    return customer if isinstance(customer, str) else ""


def _parse(obj: dict[str, Any]) -> _Sub:
    stamps = tuple(
        v for v in (obj.get(k) for k in ("created", "canceled_at", "ended_at"))
        if isinstance(v, int) and not isinstance(v, bool)
    )
    try:
        state = map_subscription(obj)
        tier, source = subscription_tier_source(obj)
    except (AttributeError, TypeError, IndexError, KeyError):
        state, tier, source = None, None, ""
    return _Sub(
        id=str(obj.get("id") or ""),
        customer=_customer_of(obj),
        raw_status=str(obj.get("status") or ""),
        state=state,
        tier=tier,
        tier_source=source,
        stamps=stamps,
    )


def _scrub(text: str) -> str:
    return stripe_gateway._scrub(text)


def _observed(snapshot_at: int, subs: list[_Sub]) -> int:
    """The instant Stripe was read at for these subscriptions.

    Stripe's own timestamps may run ahead of our clock, but never by more than
    the skew margin is believed. Anything further out (a test clock, a corrupt
    object) is clamped, because this value is persisted into ``last_event_at``
    and a far-future one would make every later real webhook look stale.
    """
    latest = max([snapshot_at, *(t for s in subs for t in s.stamps)])
    return min(latest, snapshot_at + SKEW_SECONDS)


def _foreign_live(subs: list[_Sub]) -> _Sub | None:
    """A subscription not recognisably ours that may be what the customer pays for."""
    for s in subs:
        if s.ours:
            continue
        if s.state is None or s.state.kind in {"entitled", "past_due"}:
            return s
    return None


def _oldest_open_invoice(gateway: Any, subscription_id: str) -> int:
    """``created`` of the oldest unpaid invoice of a subscription, or 0 if Stripe gives none."""
    lister = getattr(gateway, "list_invoices", None)
    if lister is None:
        return 0
    oldest = 0
    cursor: str | None = None
    for _ in range(_MAX_PAGES):
        page = lister(subscription=subscription_id, status="open",
                      starting_after=cursor, limit=_PAGE)
        data = page.get("data") if isinstance(page, dict) else None
        if not isinstance(data, list):
            raise _IncompleteError("Stripe returned an invoice list without data.")
        for inv in data:
            created = inv.get("created") if isinstance(inv, dict) else None
            if isinstance(created, int) and not isinstance(created, bool) and created > 0:
                oldest = created if not oldest else min(oldest, created)
        if not page.get("has_more"):
            return oldest
        last = str(data[-1].get("id") or "") if data and isinstance(data[-1], dict) else ""
        if not last or last == cursor:
            raise _IncompleteError("Stripe pagination did not advance; refusing to guess.")
        cursor = last
    raise _IncompleteError("too many pages of invoices; refusing to guess.")


def _pages(gateway: Any, **kwargs: Any) -> Iterator[dict[str, Any]]:
    """Every subscription object, across pages. Raises ``_IncompleteError``."""
    cursor: str | None = None
    seen_ids: set[str] = set()
    for _ in range(_MAX_PAGES):
        try:
            page = gateway.list_subscriptions(
                status="all", starting_after=cursor, limit=_PAGE, **kwargs
            )
        except StripeError:
            raise
        except Exception as exc:  # a gateway that is not ours misbehaving
            raise _IncompleteError(f"{type(exc).__name__}: {_scrub(str(exc))}") from None
        data = page.get("data") if isinstance(page, dict) else None
        if not isinstance(data, list):
            raise _IncompleteError("Stripe returned a subscription list without data.")
        for obj in data:
            if isinstance(obj, dict):
                sid = str(obj.get("id") or "")
                if sid and sid in seen_ids:
                    continue
                seen_ids.add(sid)
                yield obj
        if not page.get("has_more"):
            return
        last = str(data[-1].get("id") or "") if data and isinstance(data[-1], dict) else ""
        if not last or last == cursor:
            raise _IncompleteError("Stripe pagination did not advance; refusing to guess.")
        cursor = last
    raise _IncompleteError(f"more than {_MAX_PAGES} pages of subscriptions; refusing to guess.")


# ---------------------------------------------------------------------------
# deciding
# ---------------------------------------------------------------------------
def _effective(subs: list[_Sub]) -> tuple[_Sub | None, str]:
    """The one subscription that decides the account, or ``(None, why not)``."""
    if any(s.state is None for s in subs):
        return None, "a subscription has a status this build does not know"
    live = [s for s in subs if s.state and s.state.kind in {"entitled", "past_due"}]
    if live:
        tiers = {s.tier for s in live}
        if len(tiers) > 1:
            return None, "two live subscriptions disagree on the tier"
        for s in live:  # an active one outranks a past_due one of the same tier
            if s.state and s.state.kind == "entitled":
                return s, ""
        return live[0], ""
    suspended = [s for s in subs if s.state and s.state.kind == "suspended"]
    pool = suspended or subs
    return max(pool, key=lambda s: (max(s.stamps, default=0), s.id)), ""


def _assess(
    acct: Account, subs: list[_Sub], *, snapshot_at: int, past_due_days: int,
    last_recon: dict[str, Any] | None, unpaid_since: Callable[[str], int],
) -> Finding | None:
    """Compare one account with its Stripe subscriptions. None means in sync."""
    ours = [s for s in subs if s.ours]
    base = {
        "account_id": acct.id, "local_status": acct.status, "local_tier": acct.tier,
        "stripe_customer_id": acct.stripe_customer_id, "observed_at": snapshot_at,
    }
    local_entitled = acct.status in ENTITLED_STATUSES

    def blocked_by_foreign() -> Finding | None:
        """Never revoke on an incomplete picture: a live subscription we cannot
        classify may be exactly what this customer pays for."""
        foreign = _foreign_live(subs)
        if foreign is None:
            return None
        return Finding(
            category="ambiguous", **base,
            stripe_subscription_id=foreign.id, stripe_status=foreign.raw_status,
            reason="a live subscription on a price or status we do not recognise exists "
                   "for this customer; not revoking access on an incomplete picture",
        )

    if not ours:
        if not local_entitled or acct.tier == "free":
            return None  # nothing paid is granted, so nothing is out of step
        if (blocked := blocked_by_foreign()) is not None:
            return blocked
        # A customer Stripe knows, with no subscription of ours: the access we
        # grant has nothing behind it. A human decides; this is not a status
        # Stripe reported, so it is never applied automatically.
        return Finding(
            category="stripe_ended_but_we_grant", **base,
            reason="Stripe has no subscription of ours for this customer; "
                   "needs a human, not corrected automatically",
        )

    eff, why = _effective(ours)
    if eff is None or eff.state is None:
        return Finding(category="ambiguous", **base, reason=why)
    state, sub_id = eff.state, eff.id
    common = {**base, "stripe_subscription_id": sub_id, "stripe_status": eff.raw_status}

    if state.kind in {"terminal", "suspended"}:
        if not local_entitled or acct.tier == "free":
            return None
        if (blocked := blocked_by_foreign()) is not None:
            return blocked
        return Finding(
            category="stripe_ended_but_we_grant", **common,
            new_status="cancelled", new_tier=state.tier or acct.tier, correctable=True,
        )

    # Stripe says the customer is paying (active/trialing) or in dunning (past_due).
    target_status = state.status
    price_tier = eff.tier if eff.tier_source == "price" else None
    if not local_entitled:
        if (state.kind == "past_due" and acct.status == "cancelled" and last_recon
                and last_recon["category"] == "past_due_too_long"
                and last_recon["stripe_subscription_id"] == sub_id
                and acct.last_event_at <= last_recon["snapshot_at"]):
            return None  # we ended this on purpose and Stripe has not recovered it
        if price_tier is None:
            return Finding(
                category="ambiguous", **common,
                reason="Stripe reports a paying customer but no price id we recognise "
                       "names the tier; not upgrading on metadata alone",
            )
        return Finding(
            category="stripe_active_but_we_deny", **common,
            new_status=target_status, new_tier=price_tier, correctable=True,
        )

    if acct.tier != eff.tier:
        if price_tier is None:
            return Finding(
                category="ambiguous", **common,
                reason="the tier differs and only metadata, not a recognised price id, "
                       "names Stripe's; not changing a tier on metadata alone",
            )
        return Finding(
            category="tier_mismatch", **common,
            new_status=target_status, new_tier=price_tier, correctable=True,
        )
    if acct.status != target_status:
        return Finding(
            category="status_mismatch", **common,
            new_status=target_status, new_tier=acct.tier, correctable=True,
            reason="no change to what the account may do; the past_due warning differs",
        )
    if target_status == "past_due":
        limit = past_due_days * _DAY
        since = acct.past_due_since or acct.last_event_at
        # Our own timer is only a prefilter: a lost "active" webhook between two
        # dunning episodes leaves it stale. Cutting someone off needs Stripe's
        # word: the oldest invoice still unpaid.
        if since and snapshot_at - since > limit:
            if (blocked := blocked_by_foreign()) is not None:
                return blocked
            oldest = unpaid_since(sub_id)
            if oldest and snapshot_at - oldest > limit:
                return Finding(
                    category="past_due_too_long", **common,
                    new_status="cancelled", new_tier=acct.tier, correctable=True,
                    reason=f"Stripe's oldest unpaid invoice is from {oldest}, over "
                           f"{past_due_days} days ago",
                )
            if not oldest:
                return Finding(
                    category="past_due_too_long", **common,
                    reason="our timer says past_due for over "
                           f"{past_due_days} days but Stripe gave no unpaid invoice to "
                           "prove it; reported, not applied",
                )
    return None


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------
def reconcile(
    accounts: AccountStore,
    gateway: Any,
    *,
    apply: bool = False,
    now: datetime | None = None,
    past_due_days: int = DEFAULT_PAST_DUE_DAYS,
) -> ReconcileReport:
    """Compare ``accounts`` with Stripe and report the drift; with ``apply``, correct it.

    ``gateway`` provides ``list_subscriptions(customer, status, starting_after,
    limit)`` and ``retrieve_subscription(id)`` (``billing.stripe_gateway`` does).
    Nothing is written unless ``apply`` is true, and nothing at all if Stripe
    cannot be read to the end.
    """
    moment = now or utc_now()
    snapshot_at = int(moment.timestamp())
    report = ReconcileReport(
        run_id=uuid.uuid4().hex[:16], apply=apply, snapshot_at=snapshot_at,
        past_due_days=past_due_days,
    )
    everyone = accounts.list_accounts()
    report.accounts_total = len(everyone)

    eligible: list[Account] = []
    for acct in everyone:
        if acct.id == "operator":
            report.skipped.append({"account_id": acct.id, "reason": "operator"})
        elif not acct.stripe_customer_id:
            report.skipped.append({"account_id": acct.id, "reason": "no Stripe customer id"})
        elif acct.tier not in {"free", *PURCHASABLE_TIERS}:
            report.skipped.append(
                {"account_id": acct.id, "reason": f"tier {acct.tier!r} is not Stripe-managed"}
            )
        else:
            eligible.append(acct)

    by_customer: dict[str, list[_Sub]] = {}
    unknown: set[str] = set()
    try:
        # 1. every subscription Stripe has, once.
        for obj in _pages(gateway):
            sub = _parse(obj)
            if sub.customer:
                by_customer.setdefault(sub.customer, []).append(sub)

        # 2. an account the listing did not account for: ask about it by name,
        #    to tell "customer has no subscription" from "Stripe has no such customer".
        for acct in eligible:
            cid = acct.stripe_customer_id
            if any(s.ours for s in by_customer.get(cid, [])):
                continue
            try:
                for obj in _pages(gateway, customer=cid):
                    sub = _parse(obj)
                    known = by_customer.setdefault(cid, [])
                    if all(k.id != sub.id for k in known):
                        known.append(sub)
            except StripeError as exc:
                if exc.status == 404 or exc.code == "resource_missing":
                    unknown.add(cid)
                else:
                    report.unchecked.append(
                        {"account_id": acct.id, "reason": _scrub(str(exc))}
                    )
                    report.complete = False
                    report.error = "Stripe could not be read for every account."
    except StripeError as exc:
        report.complete = False
        report.error = f"Stripe error: {_scrub(str(exc))}"
        report.unchecked.extend(
            {"account_id": a.id, "reason": "Stripe could not be read"} for a in eligible
        )
        return report
    except _IncompleteError as exc:
        report.complete = False
        report.error = str(exc)
        report.unchecked.extend(
            {"account_id": a.id, "reason": "Stripe could not be read"} for a in eligible
        )
        return report

    # -- compare ----------------------------------------------------------
    unchecked_ids = {u["account_id"] for u in report.unchecked}
    for acct in eligible:
        if acct.id in unchecked_ids:
            continue
        cid = acct.stripe_customer_id
        subs = by_customer.get(cid, [])
        observed = _observed(snapshot_at, subs)
        if acct.last_event_at > observed - SKEW_SECONDS:
            report.deferred.append({
                "account_id": acct.id,
                "reason": "a webhook newer than the Stripe snapshot was applied; "
                          "not compared. Run again.",
            })
            continue
        report.accounts_checked += 1
        if cid in unknown:
            report.findings.append(Finding(
                category="unknown_in_stripe", account_id=acct.id,
                local_status=acct.status, local_tier=acct.tier, stripe_customer_id=cid,
                reason="Stripe does not know this customer id (wrong mode or key?); "
                       "never corrected automatically",
            ))
            continue
        try:
            finding = _assess(
                acct, subs, snapshot_at=observed, past_due_days=past_due_days,
                last_recon=accounts.last_reconciliation(acct.id)
                if acct.status == "cancelled" else None,
                unpaid_since=lambda sub_id: _oldest_open_invoice(gateway, sub_id),
            )
        except (StripeError, _IncompleteError) as exc:
            report.accounts_checked -= 1
            report.unchecked.append({"account_id": acct.id, "reason": _scrub(str(exc))})
            report.complete = False
            report.error = "Stripe could not be read for every account."
            continue
        if finding is None:
            report.in_sync += 1
        else:
            report.findings.append(finding)

    # -- orphans: paying subscriptions with no account. Report only. -------
    known_customers = {a.stripe_customer_id for a in everyone if a.stripe_customer_id}
    for cid, subs in sorted(by_customer.items()):
        if cid in known_customers:
            continue
        for s in subs:
            if s.ours and s.state and s.state.kind in {"entitled", "past_due"}:
                report.findings.append(Finding(
                    category="stripe_subscription_without_account",
                    stripe_customer_id=cid, stripe_subscription_id=s.id,
                    stripe_status=s.raw_status, new_tier=s.tier or "",
                    reason="report only: no account is created and no key is minted "
                           "here; an account comes from a signed checkout event",
                ))

    if not report.complete:
        # A lookup failed for some account: say what we know, write nothing.
        _mark_actions(report)
        return report

    if not apply:
        _mark_actions(report)
        return report

    # -- apply ------------------------------------------------------------
    # Re-read each subscription we are about to act on, so a page that was
    # stale by the time we got here cannot cause a change. Still before any
    # write: an error here leaves the store untouched.
    targets = [f for f in report.findings if f.correctable]
    confirmed: list[Finding] = []
    changed: dict[int, str] = {}
    try:
        for f in targets:
            sub = _parse(gateway.retrieve_subscription(f.stripe_subscription_id))
            listed = next(
                (s for s in by_customer.get(f.stripe_customer_id, [])
                 if s.id == f.stripe_subscription_id), None,
            )
            if listed is None or (sub.raw_status, sub.tier, sub.tier_source) != (
                listed.raw_status, listed.tier, listed.tier_source
            ):
                changed[id(f)] = "the subscription changed while this run was reading it"
            elif f.new_status == "cancelled" and _picture(
                _list_customer(gateway, f.stripe_customer_id)
            ) != _picture(by_customer.get(f.stripe_customer_id, [])):
                # Revoking is the correction that costs a paying customer, so
                # the customer's whole set of subscriptions is read again just
                # before: a new one created since listing (with its webhook
                # lost) must stop the revocation.
                changed[id(f)] = (
                    "changed_since_read: the customer's subscriptions changed while "
                    "this run was reading them"
                )
            else:
                confirmed.append(f)
    except Exception as exc:
        report.complete = False
        report.error = f"Stripe error: {_scrub(f'{type(exc).__name__}: {exc}')}"
        _mark_actions(report)
        return report

    updated: list[Finding] = []
    store_failed = False
    for f in report.findings:
        if store_failed:
            updated.append(_with(f, action="skipped", reason="an earlier store error stopped the run"))
        elif not f.correctable:
            updated.append(_with(f, action="reported"))
        elif id(f) in changed:
            updated.append(_with(f, action="skipped", reason=changed[id(f)]))
        else:
            try:
                outcome = accounts.apply_reconciliation(
                    run_id=report.run_id, account_id=f.account_id, category=f.category,
                    expect_status=f.local_status, expect_tier=f.local_tier,
                    new_status=f.new_status, new_tier=f.new_tier,
                    snapshot_at=f.observed_at, skew_seconds=SKEW_SECONDS,
                    stripe_subscription_id=f.stripe_subscription_id,
                    stripe_status=f.stripe_status,
                )
            except Exception as exc:  # the store failed; stop, say so
                report.complete = False
                report.error = f"account store error: {type(exc).__name__}"
                updated.append(_with(f, action="refused", reason="store error"))
                store_failed = True
                continue
            if outcome == "applied":
                report.corrected += 1
                updated.append(_with(f, action="corrected"))
            elif outcome == "noop":
                updated.append(_with(f, action="noop", reason="already in the target state"))
            else:
                updated.append(_with(f, action="refused", reason=outcome))
    report.findings = updated
    return report


def _list_customer(gateway: Any, customer: str) -> list[_Sub]:
    return [_parse(obj) for obj in _pages(gateway, customer=customer)]


def _picture(subs: list[_Sub]) -> frozenset[tuple[str, str, str | None, str]]:
    return frozenset((s.id, s.raw_status, s.tier, s.tier_source) for s in subs)


def _with(f: Finding, **changes: Any) -> Finding:
    return replace(f, **changes)


def _mark_actions(report: ReconcileReport) -> None:
    report.findings = [
        _with(f, action="would_correct" if f.correctable else "reported")
        for f in report.findings
    ]


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------
def _emit(text: str, stream: Any) -> None:
    stream.write(text + "\n")
    stream.flush()


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def main(
    argv: list[str] | None = None,
    *,
    gateway: Any = None,
    now: datetime | None = None,
) -> int:
    """``python -m assurance.billing.reconcile [--apply] [--json] [--past-due-days N]``.

    Exit 0 in sync, 1 drift found (whether or not ``--apply`` corrected it),
    2 could not run or could not finish. Reads ``STRIPE_SECRET_KEY`` and
    ``ASSURANCE_ACCOUNTS`` from the environment; never prints either's value.
    """
    parser = argparse.ArgumentParser(
        prog="python -m assurance.billing.reconcile",
        description="Compare the account store with Stripe and report the drift. "
                    "Dry run unless --apply. " + NOTICE,
    )
    parser.add_argument("--apply", action="store_true",
                        help="correct status/tier of existing accounts (default: report only)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--usage", action="store_true",
                        help="always include the pay-as-you-go usage section (it is included "
                             "anyway when billable usage exists or pay-as-you-go is configured)")
    parser.add_argument("--i-have-run-this-in-test-mode", action="store_true",
                        dest="tested",
                        help="required with --apply when STRIPE_SECRET_KEY is a live key")
    parser.add_argument("--past-due-days", type=_positive_int, default=DEFAULT_PAST_DUE_DAYS,
                        help="end a past_due that Stripe has not recovered after N days "
                             f"(default {DEFAULT_PAST_DUE_DAYS})")
    args = parser.parse_args(argv)

    def fail(message: str) -> int:
        text = _scrub(message)
        if args.json:
            _emit(json.dumps({"notice": NOTICE, "complete": False, "error": text,
                              "exit_code": 2}), sys.stdout)
        else:
            _emit(f"reconcile: could not run: {text}\nNOTICE: {NOTICE}", sys.stderr)
        return 2

    if gateway is None:
        if not stripe_gateway.stripe_configured():
            return fail("STRIPE_SECRET_KEY is not set.")
        gateway = stripe_gateway
    if (args.apply and not args.tested
            and os.environ.get("STRIPE_SECRET_KEY", "").startswith(("sk_live_", "rk_live_"))):
        return fail(
            "--apply with a live Stripe key is refused: this tool has only been verified "
            "against a fake transport. Run it with a test mode key (and read its dry run) "
            "first, then pass --i-have-run-this-in-test-mode to confirm you have."
        )
    path = os.environ.get("ASSURANCE_ACCOUNTS", "accounts.db")
    if not Path(path).is_file():
        # AccountStore would create an empty database; a typo must not.
        return fail("ASSURANCE_ACCOUNTS does not point at an existing account store.")
    try:
        # A dry run must not even migrate the production database.
        store = AccountStore(path) if args.apply else AccountStore.open_readonly(path)
        report = reconcile(
            store, gateway, apply=args.apply, now=now, past_due_days=args.past_due_days
        )
        if args.usage or payg_available() or any(store.billable_by_state().values()):
            # Same safety rules: read-only unless --apply, Stripe read before any write.
            report.usage = reconcile_usage(
                store, gateway if hasattr(gateway, "list_meter_event_summaries") else None,
                now=now, apply=args.apply)
    except Exception as exc:
        return fail(f"{type(exc).__name__}: {exc}")

    _emit(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) if args.json
        else report.render(),
        sys.stdout,
    )
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
