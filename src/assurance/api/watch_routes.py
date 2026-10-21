"""Receiving a Watch report over HTTP: ``POST /v1/watch/report``.

Watch runs where the exports are, in the customer's kit or cron, and the hosted
API never sees a run, a failed run or a machine nobody has looked at. This route
is the opt-in way to change that: ``assurance watch push`` posts what the
customer's own Watch saw, and the workspace shows it
(``GET /v1/fleet/observations``).

Cell-tier only, gated exactly like ``/v1/change`` (the :data:`Machine`
dependency): 401 with no or an invalid key, 402 when authenticated but not
entitled, and the data lands in the caller's own per-account ledger
(:func:`~assurance.api.deps.get_register`) and nowhere else. The request body
cap applies; ``assurance watch push`` sends a large fleet in batches.

The route derives nothing. It calls :func:`assurance.watch.ingest.ingest_report`,
which records the manifest and then the same ``assess_drift`` the
``/v1/change/assess/drift`` route uses. A failed look is recorded as a failed
look. See ``deploy/assurance/WATCH.md`` for exactly what is sent and what is not.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from assurance.api.deps import Machine, get_register
from assurance.billing.accounts import Principal
from assurance.change.store import CaseStore
from assurance.core.errors import LedgerIntegrityError
from assurance.core.evidence import Actor
from assurance.core.identity import parse_utc, utc_now
from assurance.watch.ingest import FUTURE_SKEW, IngestBusyError, ingest_report
from assurance.watch.observations import MAX_CADENCE_HOURS, MIN_CADENCE_HOURS

__all__ = ["MAX_MACHINES_PER_REPORT", "watch_router"]

watch_router = APIRouter(prefix="/v1/watch", tags=["watch"])

#: A fleet of this size is the most one request carries. ``watch push`` batches
#: below the body cap long before this matters for manifest-heavy fleets.
MAX_MACHINES_PER_REPORT = 200


def _timestamp(value: str) -> str:
    try:
        parse_utc(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{value!r} is not an ISO-8601 timestamp with a timezone: {exc}") from exc
    return value


class MachineReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    serial: str = Field(min_length=1, max_length=200)
    #: ``manufacturer/model#serial``. Optional when a manifest carries it; the
    #: manifest wins and a disagreement is refused.
    machine_key: str = Field(default="", max_length=400)
    status: Literal["unchanged", "changed", "uncollectable", "incomplete"]
    observed_at: str = Field(min_length=10, max_length=40)
    collection_complete: bool
    #: Present for ``unchanged`` / ``changed``; refused on a failed look.
    manifest: dict[str, Any] | None = None
    detail: str = Field(default="", max_length=2000)
    #: The manifest is one the reporter sealed earlier for the configuration this
    #: look re-confirmed, so it may be older than the look (``watch push`` sets it
    #: for an unchanged machine). Without it, a manifest taken longer before the
    #: look than the cadence window is recorded as ``manifest_stale`` and does not
    #: count as an observation. Its age is recorded and shown either way. A reporter
    #: can set it for any manifest: it is the reporter's statement, not a check.
    manifest_relayed: bool = False
    #: Plan items a ``incomplete`` look did not find or read.
    missing_items: list[Annotated[str, Field(max_length=200)]] = Field(
        default_factory=list, max_length=500)

    @field_validator("observed_at")
    @classmethod
    def _observed_is_a_timestamp(cls, value: str) -> str:
        return _timestamp(value)


class WatchReportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    watch_id: str = Field(min_length=1, max_length=200)
    run_started_at: str = Field(min_length=10, max_length=40)
    #: The cadence the customer's Watch declares (1 to 720 hours). Staleness of the
    #: machines it reports as successfully observed is judged against it; a report
    #: with no successful look declares nothing.
    max_age_hours: float | None = Field(
        default=None, ge=MIN_CADENCE_HOURS, le=MAX_CADENCE_HOURS)
    verdict: Literal["quiet", "findings", "degraded"] | None = None
    #: Set by ``watch push`` when it split a large fleet over several requests.
    batch_index: int | None = Field(default=None, ge=1, le=10_000)
    batch_count: int | None = Field(default=None, ge=1, le=10_000)
    machines: list[MachineReportIn] = Field(min_length=1, max_length=MAX_MACHINES_PER_REPORT)

    @field_validator("run_started_at")
    @classmethod
    def _started_is_a_timestamp(cls, value: str) -> str:
        return _timestamp(value)

    @model_validator(mode="after")
    def _batch_is_coherent(self) -> WatchReportIn:
        if (self.batch_index is None) != (self.batch_count is None):
            raise ValueError("batch_index and batch_count go together.")
        if self.batch_index is not None and self.batch_count is not None \
                and self.batch_index > self.batch_count:
            raise ValueError("batch_index is past batch_count.")
        return self


def _actor(principal: Principal) -> Actor:
    """Automation, bound to the authenticated account and never to a body field.

    ``kind="automation"`` is what ``decide``, ``resume`` and ``resolve-decision``
    refuse: nothing a report does can close or settle a case.
    """
    account = principal.account.id if principal.account else "open-mode"
    return Actor(identifier="hosted-watch-report",
                 role=f"watch report via account {account}", kind="automation")


@watch_router.post(
    "/report",
    summary="Report what your Watch saw, to your own ledger",
)
def post_report(
    body: WatchReportIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Opt-in and idempotent. Records observations; derives no finding of its own.

    The response says, per machine, whether the entry was ``recorded``,
    ``already_recorded`` (a retry: nothing was written) or ``refused`` and why,
    which case a drift opened or found, and what this does not establish.

    A plain ``def`` on purpose: FastAPI runs it in the threadpool, so a large report
    from one tenant cannot hold the event loop and stall every other caller.
    """
    now = utc_now()
    started = parse_utc(body.run_started_at)
    if started > now + FUTURE_SKEW:
        raise HTTPException(status_code=422, detail={
            "error": "run_started_at_in_future",
            "detail": "run_started_at is later than this server's clock allows."})
    # An account whose chain does not verify records nothing: the same structured
    # refusal the case routes give, before a single observation is appended.
    # Incremental (see CaseStore.require_intact), so a 200-machine report pays for
    # the records appended since the last request, not for the whole ledger.
    try:
        CaseStore(register.ledger).require_intact()
        result = ingest_report(
            register.ledger, body.model_dump(mode="json"),
            actor=_actor(principal), now=now)
    except LedgerIntegrityError as exc:
        raise HTTPException(status_code=500, detail={
            "error": "ledger_integrity", "detail": str(exc)}) from exc
    except IngestBusyError as exc:
        # Nothing was recorded; reports are idempotent, so the retry is safe.
        raise HTTPException(
            status_code=503, headers={"Retry-After": "5"},
            detail={"error": "ingest_busy", "detail": str(exc)}) from exc
    return result.to_dict()
