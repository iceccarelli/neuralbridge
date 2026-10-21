"""Pay-as-you-go: the reporter that sends billable usage to Stripe once, and the
reconciliation that checks what it sent.

**OFF by default and verified against a fake Stripe transport only.** Nothing
here has ever spoken to Stripe. It sends nothing unless pay-as-you-go is fully
configured (:func:`~.plans.payg_available`: a metered price id *and* the Billing
Meter's event name, and a test-mode key unless live mode is explicitly
allowed). Run it first with a Stripe **test-mode** key.

How a unit becomes money, end to end:

1. A metered call succeeds and ``AccountStore.record_usage`` writes a
   ``usage_events`` row, in the transaction that checked the quota. A unit past
   the daily allowance on an account that has opted in is ``billable_quantity``
   and ``billed_state='pending'`` - the row *is* the outbox entry.
2. :func:`report_usage` claims pending rows (``sending``, stamped, before any
   network), sends each as one Billing Meter event whose ``identifier`` and
   ``Idempotency-Key`` are our event id, and marks it ``billed`` only when
   Stripe acknowledges it with that identifier.
3. A crash at any point leaves a row that is either still ``pending`` or
   ``sending``: both are picked up again, and the repeat carries the same
   identifier, so Stripe counts it once. Past the window in which Stripe
   dedupes (about 24 h; we stop at 20 h) a row we cannot prove was received is
   marked ``ambiguous`` and is **not** sent again.
4. :func:`reconcile_usage` compares our totals with the meter's own summaries
   and flags drift; with ``apply`` it settles an ambiguous row only when the
   totals prove which way it went.

What it cannot do: Stripe validates meter events asynchronously, so a 2xx is an
acknowledgement of receipt, not of acceptance. The reconciliation against the
meter's summaries is how a silently dropped event is found.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Protocol

from ..core.identity import format_utc, utc_now
from . import stripe_gateway
from .accounts import AccountStore, _parse_stamp
from .metering import month_bounds
from .plans import payg_available
from .stripe_gateway import (
    StripeError,
    Transport,
    is_configuration_error,
    is_definitive_rejection,
)

__all__ = [
    "NOTICE",
    "MeterGateway",
    "ReportError",
    "ReportResult",
    "StripeMeterGateway",
    "UsageFinding",
    "UsageReconciliation",
    "main",
    "reconcile_usage",
    "report_usage",
]

NOTICE = (
    "Pay-as-you-go is verified against a fake Stripe transport only; it has never "
    "spoken to Stripe. Run it with a test-mode key first."
)

#: Reported usage is allowed this long to show up in the meter's summaries
#: before a shortfall counts as drift.
SETTLE = timedelta(minutes=15)
#: An unreported billable event older than this means the reporter is not running.
STALE_AFTER = timedelta(hours=24)


class ReportError(RuntimeError):
    """The reporter refused to run (not configured, or live mode not allowed)."""


class MeterGateway(Protocol):
    """What the reporter and the reconciler need from Stripe."""

    def create_meter_event(
        self, *, event_name: str, customer_id: str, value: int, identifier: str, timestamp: int,
    ) -> dict[str, Any]: ...

    def list_meter_event_summaries(
        self, *, meter_id: str, customer_id: str, start_time: int, end_time: int,
    ) -> dict[str, Any]: ...


class StripeMeterGateway:
    """The real gateway, with the transport injectable (tests pass a fake one)."""

    def __init__(self, transport: Transport | None = None) -> None:
        self.transport = transport

    def create_meter_event(
        self, *, event_name: str, customer_id: str, value: int, identifier: str, timestamp: int,
    ) -> dict[str, Any]:
        return stripe_gateway.create_meter_event(
            event_name=event_name, customer_id=customer_id, value=value,
            identifier=identifier, timestamp=timestamp, transport=self.transport)

    def list_meter_event_summaries(
        self, *, meter_id: str, customer_id: str, start_time: int, end_time: int,
    ) -> dict[str, Any]:
        return stripe_gateway.list_meter_event_summaries(
            meter_id=meter_id, customer_id=customer_id, start_time=start_time,
            end_time=end_time, transport=self.transport)


# ---------------------------------------------------------------------------
# the reporter
# ---------------------------------------------------------------------------
@dataclass
class ReportResult:
    """What one run did. Event ids and counts only; never a customer id or a key."""

    dry_run: bool = False
    claimed: int = 0
    billed: int = 0
    #: Sent without a verdict (timeout, 5xx): left ``sending``, retried with the same id.
    retry_later: int = 0
    #: Stripe refused for good: ``rejected``, needs a human.
    rejected: int = 0
    #: Past the dedupe window or the provider's age limit: ``ambiguous``, not sent.
    ambiguous: int = 0
    #: Acknowledged with a different identifier: not marked, retried.
    mismatched: int = 0
    pending_seen: int = 0
    #: Claimed rows given back to ``pending`` because the run was aborted.
    released: int = 0
    #: Why the run stopped early (our key or meter configuration; key-scrubbed). "" = it did not.
    aborted: str = ""
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "notice": NOTICE, "dry_run": self.dry_run, "claimed": self.claimed,
            "billed": self.billed, "retry_later": self.retry_later,
            "rejected": self.rejected, "ambiguous": self.ambiguous,
            "mismatched": self.mismatched, "pending_seen": self.pending_seen,
            "released": self.released, "aborted": self.aborted,
            "errors": self.errors,
        }


def _check_enabled() -> str:
    if not payg_available():
        raise ReportError(
            "pay-as-you-go is not configured here (ASSURANCE_PRICE_PAYG and "
            "ASSURANCE_PAYG_METER_EVENT, with a test-mode STRIPE_SECRET_KEY): "
            "nothing is sent."
        )
    return os.environ["ASSURANCE_PAYG_METER_EVENT"]


def report_usage(
    accounts: AccountStore,
    gateway: MeterGateway,
    *,
    now: datetime | None = None,
    batch: int = 200,
    dry_run: bool = False,
) -> ReportResult:
    """Send unreported billable usage to Stripe, each event at most once.

    Safe to run repeatedly and from several processes: see the module docstring.
    ``dry_run`` reads and counts, claims nothing, sends nothing, writes nothing.
    """
    event_name = _check_enabled()
    moment = now or utc_now()
    result = ReportResult(dry_run=dry_run)
    if dry_run:
        result.pending_seen = sum(
            1 for e in accounts.usage_events_all() if e["billed_state"] in ("pending", "sending"))
        return result

    claimed = accounts.claim_usage_events(now=moment, limit=batch)
    for index, event in enumerate(claimed):
        result.claimed += 1
        event_id = event["event_id"]
        customer = event["stripe_customer_id"]
        if not customer:
            accounts.mark_usage_rejected(event_id, "the account has no Stripe customer to bill")
            result.rejected += 1
            continue
        try:
            ack = gateway.create_meter_event(
                event_name=event_name, customer_id=customer,
                value=event["billable_quantity"], identifier=event_id,
                timestamp=int(_parse_stamp(event["occurred_at"]).timestamp()),
            )
        except StripeError as exc:
            message = stripe_gateway._scrub(str(exc))
            if is_configuration_error(exc):
                # Every event would fail the same way until the operator fixes
                # the key or the meter name: stop, hand back what was claimed
                # (including this row), reject nothing.
                result.aborted = (
                    f"run aborted, nothing rejected: {message} - check STRIPE_SECRET_KEY "
                    "(rotated or restricted?) and ASSURANCE_PAYG_METER_EVENT")
                result.released = accounts.release_usage_events(
                    [e["event_id"] for e in claimed[index:]], result.aborted)
                result.errors.append(f"{event_id}: {message}")
                break
            if is_definitive_rejection(exc):
                accounts.mark_usage_rejected(event_id, message)
                result.rejected += 1
            else:
                accounts.note_usage_error(event_id, message)
                result.retry_later += 1
            result.errors.append(f"{event_id}: {message}")
            continue
        # Acknowledged only if Stripe names the event we sent. Anything else is
        # not proof, and the row stays ``sending`` for another go.
        if ack.get("identifier") != event_id:
            accounts.note_usage_error(event_id, "acknowledgement did not echo our identifier")
            result.mismatched += 1
            continue
        if accounts.mark_usage_billed(event_id, str(ack["identifier"])):
            result.billed += 1
    result.ambiguous = accounts.billable_by_state().get("ambiguous", 0)
    return result


# ---------------------------------------------------------------------------
# reconciliation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class UsageFinding:
    category: str
    account_id: str
    detail: str
    units: dict[str, int] = field(default_factory=dict)
    action: str = "reported"
    event_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"category": self.category, "account_id": self.account_id,
                "detail": self.detail, "units": self.units, "action": self.action,
                "event_id": self.event_id}


USAGE_CATEGORIES = (
    "provider_has_fewer_than_billed",
    "provider_has_more_than_sent",
    "stale_unreported",
    "needs_attention",
    "ack_mismatch",
    "no_customer",
)


@dataclass
class UsageReconciliation:
    """Our recorded usage against what was reported. The drift count should be 0."""

    apply: bool = False
    compared_with_provider: bool = False
    complete: bool = True
    error: str = ""
    by_state: dict[str, int] = field(default_factory=dict)
    findings: list[UsageFinding] = field(default_factory=list)
    deferred: list[dict[str, str]] = field(default_factory=list)
    settled: int = 0
    notes: list[str] = field(default_factory=list)
    notice: str = NOTICE

    @property
    def drift_count(self) -> int:
        return len(self.findings)

    @property
    def exit_code(self) -> int:
        if not self.complete:
            return 2
        return 1 if (self.findings or self.deferred) else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "notice": self.notice, "mode": "apply" if self.apply else "dry_run",
            "complete": self.complete, "error": self.error,
            "compared_with_provider": self.compared_with_provider,
            "drift_count": self.drift_count, "billable_units_by_state": self.by_state,
            "findings": [f.to_dict() for f in self.findings],
            "deferred": self.deferred, "settled": self.settled, "notes": self.notes,
            "exit_code": self.exit_code,
        }

    def render(self) -> str:
        lines = [
            "usage reconciliation "
            + ("(APPLY: provable ambiguous events are settled)" if self.apply
               else "(dry run: nothing is written)"),
            f"NOTICE: {self.notice}",
            f"billable units by state: {self.by_state or 'none recorded'}",
            f"compared with the provider's meter: {self.compared_with_provider}",
            f"usage drift_count={self.drift_count}",
        ]
        lines += [f"  {f.account_id or '-'}: {f.category} {f.units} [{f.action}] {f.detail}"
                  for f in self.findings]
        lines += [f"  deferred {d['account_id']}: {d['reason']}" for d in self.deferred]
        lines += [f"  note: {n}" for n in self.notes]
        if self.apply:
            lines.append(f"settled={self.settled}")
        if not self.complete:
            lines.append(f"INCOMPLETE: {self.error} Nothing was written. Exit 2.")
        return "\n".join(lines)


def _ceil_minute(moment: datetime) -> int:
    ts = int(moment.timestamp())
    return -(-ts // 60) * 60


def reconcile_usage(
    accounts: AccountStore,
    gateway: MeterGateway | None,
    *,
    now: datetime | None = None,
    apply: bool = False,
    meter_id: str | None = None,
    stale_after: timedelta = STALE_AFTER,
) -> UsageReconciliation:
    """Compare recorded billable usage with what was reported, and with Stripe's meter.

    Read-only unless ``apply``; and ``apply`` writes only one thing: it settles
    ``ambiguous`` events for an account-month when the provider's own total
    proves which way they went (``S == billed`` -> not received, send again;
    ``S == billed + ambiguous`` -> received, mark billed). Everything else is
    reported and left for a person. All provider reads happen before any write;
    an error from Stripe leaves the store untouched and the report incomplete.
    """
    moment = now or utc_now()
    meter_id = meter_id if meter_id is not None else os.environ.get("ASSURANCE_PAYG_METER_ID", "")
    report = UsageReconciliation(apply=apply)
    events = accounts.usage_events_all()
    for e in events:
        report.by_state[e["billed_state"]] = (
            report.by_state.get(e["billed_state"], 0) + e["billable_quantity"])

    # -- what our own records say, no provider needed ----------------------
    stale: dict[str, list[dict[str, Any]]] = {}
    for e in events:
        state, units = e["billed_state"], {"units": e["billable_quantity"]}
        if state in ("pending", "sending") and _parse_stamp(e["occurred_at"]) < moment - stale_after:
            stale.setdefault(e["account_id"], []).append(e)
        elif state in ("ambiguous", "rejected"):
            report.findings.append(UsageFinding(
                "needs_attention", e["account_id"],
                f"event {e['event_id']} is {state}: {e['last_error'] or 'no detail'}", units,
                event_id=e["event_id"]))
        elif state == "billed" and e["provider_event_id"] != e["event_id"]:
            report.findings.append(UsageFinding(
                "ack_mismatch", e["account_id"],
                f"event {e['event_id']} is marked billed without the provider echoing its "
                "identifier", units))
        if not e["customer"] and state != "included":
            report.findings.append(UsageFinding(
                "no_customer", e["account_id"],
                f"event {e['event_id']} is billable but the account has no Stripe customer",
                units))
    for account_id, rows in sorted(stale.items()):
        report.findings.append(UsageFinding(
            "stale_unreported", account_id,
            f"{len(rows)} billable event(s) unreported for over {stale_after}; is the "
            "reporter running? oldest " + min(r["occurred_at"] for r in rows),
            {"units": sum(r["billable_quantity"] for r in rows), "events": len(rows)}))

    # -- against the provider's meter ---------------------------------------
    if gateway is None or not meter_id:
        report.notes.append(
            "not compared with Stripe's meter: ASSURANCE_PAYG_METER_ID is not set (or "
            "no gateway); only our own records were checked.")
        return report
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for e in events:
        if e["customer"]:
            groups.setdefault((e["account_id"], month_bounds(_parse_stamp(e["occurred_at"]))[0]),
                              []).append(e)
    plans: list[tuple[tuple[str, str], dict[str, int], list[dict[str, Any]]]] = []
    for (account_id, month_start), rows in sorted(groups.items()):
        if any(r["billed_state"] == "billed" and _parse_stamp(r["last_attempt_at"]) > moment - SETTLE
               for r in rows if r["last_attempt_at"]):
            report.deferred.append({
                "account_id": account_id,
                "reason": f"{month_start[:7]}: events were reported in the last {SETTLE}; "
                          "Stripe aggregates asynchronously, so not compared yet. Run again."})
            continue
        month_end = month_bounds(_parse_stamp(month_start))[1]
        end = min(_parse_stamp(month_end), moment + timedelta(minutes=1))
        try:
            total = 0
            page = gateway.list_meter_event_summaries(
                meter_id=meter_id, customer_id=rows[0]["customer"],
                start_time=int(_parse_stamp(month_start).timestamp()),
                end_time=_ceil_minute(end))
            for summary in page.get("data") or []:
                total += int(summary.get("aggregated_value") or 0)
        except (StripeError, ValueError, TypeError) as exc:
            report.complete = False
            report.error = f"Stripe could not be read: {stripe_gateway._scrub(str(exc))}"
            return report
        by_state: dict[str, int] = {}
        for r in rows:
            by_state[r["billed_state"]] = by_state.get(r["billed_state"], 0) + r["billable_quantity"]
        plans.append(((account_id, month_start), {**by_state, "_stripe": total}, rows))
    report.compared_with_provider = True

    resolutions: list[tuple[list[dict[str, Any]], bool, str]] = []
    for (account_id, month_start), counts, rows in plans:
        billed = counts.get("billed", 0)
        sending = counts.get("sending", 0)
        ambiguous = counts.get("ambiguous", 0)
        stripe_total = counts["_stripe"]
        units = {"stripe": stripe_total, "billed": billed, "sending": sending,
                 "ambiguous": ambiguous}
        label = month_start[:7]
        if stripe_total < billed:
            report.findings.append(UsageFinding(
                "provider_has_fewer_than_billed", account_id,
                f"{label}: we marked {billed} unit(s) billed but the meter holds "
                f"{stripe_total}; some were dropped after acknowledgement", units))
        elif stripe_total > billed + sending + ambiguous:
            report.findings.append(UsageFinding(
                "provider_has_more_than_sent", account_id,
                f"{label}: the meter holds {stripe_total} but we sent at most "
                f"{billed + sending + ambiguous}; something else is writing to this meter, "
                "or an event was counted twice", units))
        if ambiguous and sending == 0 and stripe_total >= billed:
            ambiguous_rows = [r for r in rows if r["billed_state"] == "ambiguous"]
            if stripe_total == billed:
                resolutions.append((ambiguous_rows, False,
                    f"reconciled {format_utc(moment)}: the meter holds exactly the billed "
                    "units, so this was not received; queued to send once"))
            elif stripe_total == billed + ambiguous:
                resolutions.append((ambiguous_rows, True,
                    f"reconciled {format_utc(moment)}: the meter holds billed + ambiguous "
                    "units, so this was received"))

    settled_ids = {r["event_id"] for rows, _, _ in resolutions for r in rows}
    if apply:
        for rows, billed_flag, note in resolutions:
            for r in rows:
                if accounts.resolve_ambiguous_usage(r["event_id"], billed=billed_flag, note=note):
                    report.settled += 1
    report.findings = [
        replace(f, action="corrected" if apply else "would_correct")
        if f.event_id and f.event_id in settled_ids else f
        for f in report.findings
    ]
    return report


# ---------------------------------------------------------------------------
# command line
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None, *, gateway: MeterGateway | None = None,
         now: datetime | None = None) -> int:
    """``python -m assurance.billing.payg report [--dry-run] [--json]``, or
    ``... requeue (--all-rejected | --event-id ID) [--dry-run]``.

    Reads ``ASSURANCE_ACCOUNTS`` and (for a real run) ``STRIPE_SECRET_KEY``
    from the environment. Exit 0 all reported, 1 something failed or needs a
    person, 2 refused or could not run. Nothing schedules this: run it from cron.
    """
    import argparse
    import json
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="python -m assurance.billing.payg",
        description="Send unreported pay-as-you-go usage to Stripe. " + NOTICE)
    parser.add_argument("command", choices=["report", "requeue"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--all-rejected", action="store_true",
        help="requeue: put every rejected event back to pending (a person decides)")
    parser.add_argument(
        "--event-id", action="append", default=[], metavar="ID",
        help="requeue: only this rejected event (repeatable)")
    args = parser.parse_args(argv)

    def emit(payload: dict[str, Any], code: int) -> int:
        text = json.dumps(payload, indent=2, sort_keys=True) if args.json else "\n".join(
            f"{k}: {v}" for k, v in payload.items())
        sys.stdout.write(text + "\n")
        return code

    if args.command == "requeue":
        # A deliberate operator action, and it never talks to Stripe. Nothing
        # requeues a rejected event by itself.
        if not (args.all_rejected or args.event_id):
            return emit({"notice": NOTICE, "error": "name what to requeue: "
                         "--all-rejected or --event-id ID (rejected events are never "
                         "retried automatically)."}, 2)
        path = os.environ.get("ASSURANCE_ACCOUNTS", "accounts.db")
        if not Path(path).is_file():
            return emit({"notice": NOTICE, "error": "ASSURANCE_ACCOUNTS does not point at an "
                         "existing account store."}, 2)
        store = AccountStore(path)
        wanted = None if args.all_rejected else args.event_id
        matched = [e for e in store.rejected_usage_event_ids()
                   if wanted is None or e in wanted]
        moved = [] if args.dry_run else store.requeue_rejected_usage(matched)
        return emit({"notice": NOTICE, "dry_run": args.dry_run, "matched": matched,
                     "requeued": len(moved)}, 0)

    if gateway is None:
        if not stripe_gateway.stripe_configured():
            return emit({"notice": NOTICE, "error": "STRIPE_SECRET_KEY is not set."}, 2)
        gateway = StripeMeterGateway()
    path = os.environ.get("ASSURANCE_ACCOUNTS", "accounts.db")
    if not Path(path).is_file():
        return emit({"notice": NOTICE,
                     "error": "ASSURANCE_ACCOUNTS does not point at an existing account store."}, 2)
    try:
        result = report_usage(AccountStore(path), gateway, now=now, dry_run=args.dry_run)
    except ReportError as exc:
        return emit({"notice": NOTICE, "error": str(exc)}, 2)
    code = 2 if result.aborted else 1 if (
        result.retry_later or result.rejected or result.ambiguous or result.mismatched) else 0
    return emit(result.to_dict(), code)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
