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

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import (
    Anyone,
    Machine,
    get_accounts,
    get_register,
    spend,
)
from assurance.billing.accounts import AccountStore, Principal
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.machine.bundle import build_bundle
from assurance.machine.bundle import verify_bundle as _verify_bundle_file
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
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
    actor: str = Field(min_length=1, max_length=200,
                       description="who is signing this verification")
    role: str = Field(default="verification engineer", max_length=200)
    seal: bool = Field(default=True,
                       description="append the sealed bundle to the evidence ledger")


class BundleCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    bundle: dict[str, Any]
    envelope: dict[str, Any] | None = None
    trace: dict[str, Any] | None = None


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
    principal: Annotated[Principal, Anyone],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """S(t0) = Sh + Sr + Ss + C + Zd + Zr, term by term.

    Two things this returns that a spreadsheet usually gets wrong: Sh runs over
    the reaction time as well as the stop time, and Ss is flagged when the
    requested speed is above the speed the stopping distance was measured at.
    """
    limit = principal.plan.separations_per_day
    spend(principal, "separation", limit, accounts)

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

    response.headers["X-Assurance-Tier"] = principal.tier
    if limit is not None:
        used = accounts.usage_today(principal.subject).get("separation", 0)
        response.headers["X-Assurance-Quota-Limit"] = str(limit)
        response.headers["X-Assurance-Quota-Remaining"] = str(max(0, limit - used))

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

    return {
        "required_separation_mm": breakdown.total_mm,
        "breakdown": breakdown.to_dict(),
        "explain": breakdown.explain(),
        "notes": notes,
        "checks_skipped": [
            "this is arithmetic on the figures you supplied. It does not confirm "
            "they describe your machine, and it is not a risk assessment.",
        ],
    }


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

    bundle = build_bundle(
        envelope, trace,
        actor=Actor(identifier=body.actor, role=body.role, kind="person"),
        limits=limits,
        ledger=register.ledger if (body.seal and register is not None) else None,
    )
    payload = bundle.to_dict()
    payload["sealed"] = bool(body.seal)
    payload["verdict"] = bundle.verdict.value
    payload["tier"] = bundle.tier.value
    payload["may_claim_physical_behaviour"] = \
        bundle.result.may_claim_physical_behaviour
    return payload


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
    """
    del principal, accounts  # free and unmetered, on purpose

    import tempfile
    from pathlib import Path

    envelope = trace = None
    try:
        if body.envelope is not None:
            envelope = SafetyEnvelope.from_dict(body.envelope)
        if body.trace is not None:
            trace = Trace.from_dict(body.trace)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "inputs") from exc

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bundle.json"
        p.write_text(json.dumps(body.bundle), encoding="utf-8")
        ok, problems = _verify_bundle_file(p, envelope=envelope, trace=trace)

    recorded = (body.bundle.get("evidence") or {}).get("body") or {}
    return {
        "ok": ok,
        "problems": problems,
        "checked": {
            "seal": True,
            "internal_consistency": True,
            "against_original_envelope": envelope is not None,
            "against_original_trace": trace is not None,
        },
        "recorded_verdict": recorded.get("verdict"),
        "recorded_tier": recorded.get("tier"),
        "product": recorded.get("product"),
        "product_version": recorded.get("product_version"),
    }
