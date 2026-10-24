"""Machine safety verification over HTTP.

Three endpoints and a deliberate commercial shape.

``POST /v1/machine/separation`` is free and needs no account. An integrator
types in the stop figures they already have and gets the ISO/TS 15066 protective
separation distance broken into its six terms. Most of them have never seen
their own number, and a great many of them have a light curtain set closer than
it. That is the entire top of the funnel and it costs us nothing to give away.

``POST /v1/machine/verify`` is the product. It needs the Cell plan.

``POST /v1/machine/bundle/check`` is free, permanently, for everyone. A customer
whose supplier hands them an evidence bundle must be able to check it without an
account, and so must their insurer and their notified body. A bundle that only a
paying customer can verify is not evidence, it is a certificate from a vendor —
which is the thing this whole package exists to replace. Giving the checker away
is what makes the sealed bundle worth buying.
"""

from __future__ import annotations

import os
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from assurance.api.change_routes import _actor as bound_actor

# `sanitise_declared_role` moved to assurance.api.declared_actor so every route that seals a
# caller-declared role shares one definition. Re-exported: other code imports it from here.
from assurance.api.declared_actor import (  # noqa: F401
    DEFAULT_ROLE,
    MAX_DECLARED_ROLE,
    sanitise_declared_role,
)
from assurance.api.deps import (
    Anyone,
    Machine,
    Metered,
    MeterTicket,
    get_accounts,
    get_register,
)
from assurance.billing.accounts import AccountStore, Principal
from assurance.core.errors import AssuranceError, EvidenceIncompleteError
from assurance.machine.bundle import BundleCheck, build_bundle, check_bundle_data
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.limits_review import ReviewTrust
from assurance.machine.ssm import separation_required
from assurance.machine.trace import Trace

__all__ = ["machine_router"]

machine_router = APIRouter(prefix="/v1/machine", tags=["machine safety"])

#: A trace bigger than this is a file upload problem, not an API problem, and
#: the CLI handles it without a round trip. Refusing early beats timing out.
MAX_SAMPLES = 200_000


class SeparationIn(BaseModel):
    """The six inputs an integrator already has written down somewhere."""

    model_config = ConfigDict(extra="forbid")

    robot_speed_mm_s: float = Field(ge=0, description="TCP speed under SSM, mm/s")
    reaction_time_s: float = Field(ge=0, description="Tr: detection to stop command")
    stop_time_s: float = Field(ge=0, description="Ts: stop command to standstill")
    stop_distance_mm: float = Field(ge=0, description="travel during Ts")
    measured_at_speed_mm_s: float = Field(
        gt=0, description="the speed the stop distance was actually measured at")
    intrusion_distance_mm: float = Field(
        ge=0, description="C, per ISO 13855, for the body part that can reach in")
    human_position_uncertainty_mm: float = Field(default=0.0, ge=0, description="Zd")
    robot_position_uncertainty_mm: float = Field(default=0.0, ge=0, description="Zr")
    human_speed_mm_s: float | None = Field(
        default=None, ge=0,
        description="closing speed if the sensing system reports it; "
                    "omit for the ISO 13855 walking figure")


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    envelope: dict[str, Any]
    trace: dict[str, Any]
    limits: dict[str, Any] | None = None
    limits_reviews: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32,
        description="signed reviews of the limits table. They are assessed against "
                    "the reviewer trust list the SERVER is configured with "
                    "(ASSURANCE_LIMITS_REVIEW_TRUST); a caller cannot supply its own "
                    "trust, which would let a table's author vouch for the table")
    actor: str = Field(min_length=1, max_length=200,
                       description="who is signing this verification")
    role: str = Field(default="verification engineer", max_length=200)
    seal: bool = Field(default=True,
                       description="append the sealed bundle to the evidence ledger")
    subject: str = Field(
        default="", max_length=400,
        description="file the sealed bundle under this ledger subject. Give the "
                    "machine's key (manufacturer/model#serial) for the verification "
                    "to count as evidence for that unit in coverage, re-verification "
                    "and the passport; omitted, it is filed under product@version, "
                    "a product line")


class BundleCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle: dict[str, Any]
    envelope: dict[str, Any] | None = None
    trace: dict[str, Any] | None = None
    limits_trust: dict[str, Any] | None = Field(
        default=None,
        description="YOUR reviewer trust list (format assurance.machine.limits-trust.v1), "
                    "obtained independently of the bundle, to re-assess the limits "
                    "review sealed in it. Without it a validated limits tier is not "
                    "reproduced")
    limits: dict[str, Any] | None = Field(
        default=None,
        description="the body-region limits table the bundle was verified against, "
                    "if its envelope names one; without it a power-and-force bundle "
                    "cannot be replayed and is reported as integrity-only")


def _server_review_trust() -> ReviewTrust | None:
    """The reviewer keys this deployment trusts, from its own configuration.

    Never from the request: whoever supplies the table must not also supply the
    list of reviewers who vouch for it.
    """
    path = os.environ.get("ASSURANCE_LIMITS_REVIEW_TRUST", "")
    if not path:
        return None
    try:
        return ReviewTrust.from_json(path)
    except AssuranceError:
        return None  # fail closed: a broken trust file trusts nobody


def _review_summary(rec: Any) -> dict[str, Any] | None:
    if not isinstance(rec, dict):
        return None
    return {k: rec.get(k) for k in ("status", "validated", "explanation", "assessed_on")}


def _bad(exc: Exception, what: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail={"error": f"invalid_{what}", "detail": str(exc)},
    )


@machine_router.post(
    "/separation",
    summary="The protective separation distance your cell actually needs",
)
async def separation(
    body: SeparationIn,
    response: Response,
    meter: Annotated[MeterTicket, Metered("separation")],
) -> dict[str, Any]:
    """S(t0) = Sh + Sr + Ss + C + Zd + Zr, term by term.

    Two things this returns that a spreadsheet usually gets wrong: Sh runs over
    the reaction time as well as the stop time, and Ss is flagged when the
    requested speed is above the speed the stopping distance was measured at.
    Counted once the answer is complete (``billing/metering.py``).
    """
    from assurance.machine.envelope import (
        FigureBasis,
        SensingUncertainty,
        StopPerformance,
        Workspace,
    )
    from assurance.machine.envelope import (
        SafetyEnvelope as _Env,
    )

    try:
        envelope = _Env(
            envelope_id="ad-hoc",
            product="ad-hoc",
            product_version="ad-hoc",
            workspace=Workspace(minimum=(-1.0, -1.0, -1.0), maximum=(1.0, 1.0, 1.0)),
            max_tcp_speed_mm_s={},
            stop=StopPerformance(
                reaction_time_s=body.reaction_time_s,
                stop_time_s=body.stop_time_s,
                stop_distance_mm=body.stop_distance_mm,
                measured_at_speed_mm_s=body.measured_at_speed_mm_s,
                basis=FigureBasis(kind="estimated", reference="supplied by the caller"),
            ),
            uncertainty=SensingUncertainty(
                human_position_mm=body.human_position_uncertainty_mm,
                robot_position_mm=body.robot_position_uncertainty_mm,
                basis=FigureBasis(kind="estimated", reference="supplied by the caller"),
            ),
            intrusion_distance_mm=body.intrusion_distance_mm,
        )
        breakdown = separation_required(
            envelope,
            robot_speed_mm_s=body.robot_speed_mm_s,
            human_speed_mm_s=body.human_speed_mm_s,
        )
    except (AssuranceError, ValueError) as exc:
        raise _bad(exc, "separation_inputs") from exc

    notes = [
        "Sh runs over the reaction time and the stop time together. A person "
        "keeps moving while the cell is still noticing them.",
        "C, Zd and Zr are the terms most often left out. They are usually the "
        "largest part of the answer.",
    ]
    if breakdown.rests_on_extrapolation:
        notes.append(
            f"Ss is extrapolated: {body.robot_speed_mm_s:.0f} mm/s is above the "
            f"{body.measured_at_speed_mm_s:.0f} mm/s the stopping distance was "
            "measured at, so it was scaled by the square of the speed ratio. That "
            "is a constant-deceleration model, not a measurement."
        )
    if body.human_speed_mm_s is None:
        notes.append(
            "No closing speed was supplied, so the ISO 13855 walking figure of "
            f"{breakdown.human_speed_mm_s:.0f} mm/s was used. A directed approach "
            "at short range is normally taken as 2000 mm/s."
        )

    result = {
        "required_separation_mm": breakdown.total_mm,
        "breakdown": breakdown.to_dict(),
        "explain": breakdown.explain(),
        "notes": notes,
        "checks_skipped": [
            "this is arithmetic on the figures you supplied. It does not confirm "
            "they describe your machine, and it is not a risk assessment.",
        ],
    }
    meter.commit(response)
    return result


@machine_router.post(
    "/verify",
    summary="Verify a recorded run against a declared safety envelope",
)
async def verify_run(
    body: VerifyIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Compare what the machine did against what its manufacturer declared."""
    # The sealed actor follows the credential, as on /v1/change: an operator key
    # attributes to that operator and a different `actor` is refused; an account key
    # is recorded as declared; open mode keeps the declared label.
    actor = bound_actor(body.actor, sanitise_declared_role(body.role), principal, named=True)

    try:
        envelope = SafetyEnvelope.from_dict(body.envelope)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "envelope") from exc

    samples = body.trace.get("samples")
    if isinstance(samples, list) and len(samples) > MAX_SAMPLES:
        raise HTTPException(
            # 413: content too large.
            status_code=413,
            detail={
                "error": "trace_too_large",
                "detail": f"{len(samples)} samples exceeds the {MAX_SAMPLES} this "
                          "endpoint accepts. Use `assurance machine verify` locally; "
                          "the bundle it produces is the same object.",
            },
        )

    try:
        trace = Trace.from_dict(body.trace)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "trace") from exc

    limits = None
    if body.limits is not None:
        try:
            limits = LimitsTable.from_dict(body.limits)
        except (AssuranceError, KeyError, ValueError, TypeError) as exc:
            raise _bad(exc, "limits") from exc

    try:
        bundle = build_bundle(
            envelope, trace,
            actor=actor,
            limits=limits,
            limits_reviews=body.limits_reviews,
            review_trust=_server_review_trust(),
            ledger=register.ledger if (body.seal and register is not None) else None,
            subject=body.subject,
        )
    except EvidenceIncompleteError as exc:
        # The seal refused a number its hash cannot protect (an integer beyond 2^53 or a
        # value finer than 6 decimals in a caller-supplied field). That is the caller's
        # input, not a server fault: say which value, never a 500.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "unsealable_number", "detail": str(exc)}) from exc
    payload = bundle.to_dict()
    payload["sealed"] = bool(body.seal)
    # The hash a re-verification cites (``verification_content_hash`` on
    # POST /v1/change/cases/{id}/reverification); also at evidence.content_hash.
    payload["content_hash"] = bundle.content_hash
    payload["verdict"] = bundle.verdict.value
    payload["tier"] = bundle.tier.value
    payload["may_claim_physical_behaviour"] = \
        bundle.result.may_claim_physical_behaviour
    # Why the tier is what it is: a provenance the filer declared never lifts it.
    payload["provenance_basis"] = bundle.result.provenance_basis
    payload["provenance_note"] = (bundle.result.provenance_assessment or {}).get(
        "explanation", "")
    return payload


def _check_bundle_sync(body: BundleCheckIn) -> BundleCheck:
    """Parse the optional originals and run the checker. CPU-bound: runs in a worker thread."""
    envelope = trace = limits = None
    try:
        if body.envelope is not None:
            envelope = SafetyEnvelope.from_dict(body.envelope)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "inputs") from exc
    if body.trace is not None:
        samples = body.trace.get("samples")
        if isinstance(samples, list) and len(samples) > MAX_SAMPLES:
            raise HTTPException(
                status_code=413,
                detail={
                    "error": "trace_too_large",
                    "detail": f"{len(samples)} samples exceeds the {MAX_SAMPLES} this "
                              "endpoint accepts. Use `assurance machine check` "
                              "locally; it applies the same rules.",
                },
            )
        try:
            trace = Trace.from_dict(body.trace)
        except (AssuranceError, KeyError, ValueError, TypeError) as exc:
            raise _bad(exc, "inputs") from exc
    if body.limits is not None:
        try:
            limits = LimitsTable.from_dict(body.limits)
        except (AssuranceError, KeyError, ValueError, TypeError) as exc:
            raise _bad(exc, "limits") from exc
    trust = None
    if body.limits_trust is not None:
        try:
            trust = ReviewTrust.from_dict(body.limits_trust)
        except AssuranceError as exc:
            raise _bad(exc, "limits_trust") from exc
    return check_bundle_data(body.bundle, envelope=envelope, trace=trace, limits=limits,
                             review_trust=trust)


@machine_router.post(
    "/bundle/check",
    summary="Re-verify an evidence bundle. Free, permanently, for anyone.",
)
async def check_bundle(
    body: BundleCheckIn,
    principal: Annotated[Principal, Anyone],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """Check somebody else's bundle without trusting them or us.

    Deliberately outside every paywall. If a bundle can only be checked by
    someone with a subscription, it is a vendor certificate rather than
    evidence, and the customer's auditor is right to ignore it.

    ``ok`` means no inconsistency was found. ``level`` says how far the check got:
    ``integrity_only`` (seal and coherence, the engine was not re-run on the
    originals, so nothing shows the machine behaved as recorded), ``reproduced``
    (the original envelope, trace and, if needed, limits table were supplied and
    re-running the engine reproduced every sealed field) or ``rejected``. Each flag
    under ``checked`` is true only if that check ran and passed. A seal is not a
    signature.

    The checking is CPU work, so it runs in a worker thread and cannot stall the
    event loop; the request size cap is unchanged.
    """
    del principal, accounts  # free and unmetered, on purpose

    result = await run_in_threadpool(_check_bundle_sync, body)

    evidence = body.bundle.get("evidence")
    recorded = evidence.get("body") if isinstance(evidence, dict) else None
    if not isinstance(recorded, dict):
        recorded = {}
    return {
        "ok": result.ok,
        "level": result.level,
        "reproduced": result.reproduced,
        # Problems first, then the "NOT CHECKED: ..." notes (the contract before
        # `limitations` existed); `limitations` repeats only the second kind.
        "problems": result.notes,
        "limitations": list(result.limitations),
        "checked": {
            "seal": result.seal_intact,
            "internal_consistency": result.internally_consistent,
            "against_original_envelope": result.reproduced,
            "against_original_trace": result.reproduced,
            "against_limits": result.reproduced and bool(recorded.get("limits_hash")),
            "limits_review": result.reproduced and isinstance(
                recorded.get("limits_review"), dict) and bool(
                recorded["limits_review"].get("validated")),
            "reproduced": result.reproduced,
        },
        "recorded_verdict": recorded.get("verdict"),
        "recorded_tier": recorded.get("tier"),
        "recorded_provenance_basis": recorded.get("provenance_basis"),
        # What the sealed bundle says about the review of its limits table (status
        # and explanation); whether THIS check accepted it is `checked.limits_review`.
        "recorded_limits_review": _review_summary(recorded.get("limits_review")),
        "product": recorded.get("product"),
        "product_version": recorded.get("product_version"),
    }
