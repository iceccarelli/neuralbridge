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

import asyncio
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
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
from assurance.api.recorder_trust import server_recorder_trust_state
from assurance.billing.accounts import AccountStore, Principal
from assurance.core.errors import AssuranceError, EvidenceIncompleteError
from assurance.machine.bundle import (
    BundleCheck,
    MachineSubjectError,
    build_bundle,
    check_bundle_data,
)
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.limits_review import ReviewTrust
from assurance.machine.recorder_attestation import (
    MAX_ATTESTATIONS,
    RecorderAttestationError,
    RecorderTrust,
    refuse_private_key,
)
from assurance.machine.ssm import separation_required
from assurance.machine.trace import Trace

__all__ = ["machine_router"]

machine_router = APIRouter(prefix="/v1/machine", tags=["machine safety"])

#: A trace bigger than this is a file upload problem, not an API problem, and
#: the CLI handles it without a round trip. Refusing early beats timing out.
MAX_SAMPLES = 200_000

#: How many /verify engine runs one process executes at once. A maximum-size trace is
#: hundreds of megabytes of Python objects.
MAX_CONCURRENT_VERIFICATIONS = 4
#: How many more may wait for a turn. A waiting request has already been read and parsed
#: (the framework does that before the handler runs), so each one holds memory; beyond
#: this the answer is 503 with ``Retry-After`` rather than another parked body. At most
#: ``MAX_CONCURRENT_VERIFICATIONS + MAX_WAITING_VERIFICATIONS`` bodies are held at once.
MAX_WAITING_VERIFICATIONS = 8
#: How many of those one account may have in flight (running or waiting). One tenant
#: cannot fill every slot; the next one is told 429 with ``Retry-After``.
MAX_VERIFICATIONS_PER_ACCOUNT = 2
RETRY_AFTER_SECONDS = 5


class _LoopState:
    def __init__(self, size: int) -> None:
        self.slots = asyncio.Semaphore(size)
        self.waiting = 0
        self.in_flight: dict[str, int] = {}


class _Gate:
    """Admission to the verification engine: bounded running, bounded waiting, bounded per
    account. State is per running event loop (a semaphore belongs to one loop)."""

    def __init__(self, size: int, waiting: int, per_owner: int) -> None:
        self._size, self._waiting, self._per_owner = size, waiting, per_owner
        self._by_loop: dict[asyncio.AbstractEventLoop, _LoopState] = {}

    def for_running_loop(self) -> _LoopState:
        loop = asyncio.get_running_loop()
        for stale in [lp for lp in self._by_loop if lp.is_closed()]:
            del self._by_loop[stale]
        return self._by_loop.setdefault(loop, _LoopState(self._size))

    @asynccontextmanager
    async def admit(self, owner: str) -> AsyncIterator[None]:
        state = self.for_running_loop()
        retry = {"Retry-After": str(RETRY_AFTER_SECONDS)}
        # No await between these checks and the increments: the loop cannot interleave.
        if state.in_flight.get(owner, 0) >= self._per_owner:
            raise HTTPException(
                status_code=429, headers=retry,
                detail={"error": "too_many_verifications",
                        "detail": f"this account already has {self._per_owner} "
                                  "verification runs in flight; retry when one finishes."})
        queued = state.slots.locked()
        if queued and state.waiting >= self._waiting:
            raise HTTPException(
                status_code=503, headers=retry,
                detail={"error": "verification_queue_full",
                        "detail": "the service is running its limit of verifications and "
                                  "its queue is full; retry shortly."})
        state.in_flight[owner] = state.in_flight.get(owner, 0) + 1
        try:
            if queued:
                state.waiting += 1
                try:
                    await state.slots.acquire()
                finally:
                    state.waiting -= 1
            else:
                await state.slots.acquire()
            try:
                yield
            finally:
                state.slots.release()
        finally:
            state.in_flight[owner] -= 1
            if not state.in_flight[owner]:
                del state.in_flight[owner]


_VERIFY_GATE = _Gate(MAX_CONCURRENT_VERIFICATIONS, MAX_WAITING_VERIFICATIONS,
                     MAX_VERIFICATIONS_PER_ACCOUNT)


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
    recorder_attestations: list[dict[str, Any]] = Field(
        default_factory=list, max_length=MAX_ATTESTATIONS,
        description="signed recorder attestations of the trace "
                    "(format assurance.machine.recorder-attestation.v1, signed offline by "
                    "the recorder operator with `assurance machine recorder-sign`). They "
                    "are assessed against the recorder trust list the SERVER is "
                    "configured with (ASSURANCE_RECORDER_TRUST); a caller cannot supply "
                    "its own trust or a provenance basis, which would let a trace's filer "
                    "vouch for the trace. With no server trust nothing is accepted and "
                    "the trace's provenance stays declared by the filer (tier capped at "
                    "community). An accepted attestation proves a trusted key signed "
                    "these exact trace bytes; not that the recording is physically true")
    machine_serial: str = Field(
        default="", max_length=200,
        description="the unit this verification is about; a recorder attestation that "
                    "names a different serial is not accepted. Defaults to the serial in a "
                    "machine-key `subject` (maker/model#serial); if both are given they "
                    "must be the same (422 `invalid_subject` otherwise)")
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
                    "a product line. A key is read one way: the serial is everything "
                    "after the first '#', it must be present and must not contain "
                    "another '#'")


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
    recorder_trust: dict[str, Any] | None = Field(
        default=None,
        description="YOUR recorder trust list (format assurance.machine.recorder-trust.v1), "
                    "obtained independently of the bundle, to re-assess the recorder "
                    "attestation sealed in it (\"check as me\"). It affects only this "
                    "answer, never what the server seals. Without it a bundle that "
                    "claims `recorder_attested` is not believed: its tier is capped at "
                    "community and reported as unverifiable")
    machine_serial: str | None = Field(
        default=None, max_length=200,
        description="the unit you say the bundle is about; default: the one it records")
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


def _attestation_summary(rec: Any) -> dict[str, Any] | None:
    """The recorder-attestation assessment without the attestations themselves."""
    if not isinstance(rec, dict):
        return None
    return {k: rec.get(k) for k in (
        "status", "attested", "key_fingerprint", "attestation_hash", "trust_configured",
        "window_checked", "findings", "explanation", "assessed_on")}


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
    responses={
        429: {"description": "`too_many_verifications`: this account already has "
                             f"{MAX_VERIFICATIONS_PER_ACCOUNT} runs in flight. "
                             "`Retry-After` says when."},
        503: {"description": "`verification_queue_full`: the service is running its limit "
                             "and its queue is full. `Retry-After` says when."},
    },
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

    # The engine is CPU work on a trace of up to MAX_SAMPLES samples (seconds, for a large
    # one). Run inline it would stop the event loop for that long: nothing else on the
    # process would be served, health checks and every other tenant included. It runs in a
    # worker thread, like the bundle checker, and at most MAX_CONCURRENT_VERIFICATIONS at a
    # time per process, because the thread pool alone would let dozens of maximum-size
    # traces sit in memory at once (the event loop used to serialise them by accident).
    owner = principal.account.id if getattr(principal, "account", None) else "(unauthenticated)"
    async with _VERIFY_GATE.admit(owner):
        return await run_in_threadpool(_verify_sync, body, envelope, actor, register)


def _verify_sync(
    body: VerifyIn, envelope: SafetyEnvelope, actor: Any, register: Any,
) -> dict[str, Any]:
    """Parse the trace and run the engine (and seal, when asked). Runs in a worker thread."""
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
        refuse_private_key(body.recorder_attestations)
    except RecorderAttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "private_key_refused", "detail": str(exc)}) from exc

    server_trust = server_recorder_trust_state()
    try:
        bundle = build_bundle(
            envelope, trace,
            actor=actor,
            limits=limits,
            limits_reviews=body.limits_reviews,
            review_trust=_server_review_trust(),
            recorder_attestations=body.recorder_attestations,
            recorder_trust=server_trust.trust,
            machine_serial=body.machine_serial,
            ledger=register.ledger if (body.seal and register is not None) else None,
            subject=body.subject,
        )
    except MachineSubjectError as exc:
        # One strict grammar for a unit key, and one serial per verification: the caller's
        # input is ambiguous or contradicts itself. Nothing was verified or sealed.
        raise _bad(exc, "subject") from exc
    except EvidenceIncompleteError as exc:
        # The seal refused a number its hash cannot protect (an integer beyond 2^53 or a
        # value finer than 6 decimals in a caller-supplied field). That is the caller's
        # input, not a server fault: say which value, never a 500.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "unsealable_number", "detail": str(exc)}) from exc
    payload = bundle.to_dict()
    payload["sealed"] = bool(body.seal)
    if not body.seal and "#" in body.subject:
        # Nothing was compared with the ledger: whether this recording already belongs to
        # another unit (one recording, one unit) is checked only when sealing, and a refusal
        # or a downgrade can follow then. The tier above is the sealing engine's, not a reader's.
        payload["unit_binding_note"] = (
            "not sealed: the tier shown was not compared with the ledger, so whether this "
            f"recording is already the validated evidence of another unit than {body.subject!r} "
            "was not checked. Sealing may be refused (422 invalid_subject), and a reader never "
            "believes more than the unit key the bundle was sealed for.")
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
    # How the recorder attestations were assessed (statuses, findings, key fingerprint),
    # under the SERVER's trust list. `accepted` proves a trusted key signed these trace
    # bytes; it does not prove the recording is physically true.
    payload["recorder_attestation"] = _attestation_summary(
        bundle.result.recorder_attestation)
    # Whether this server has a recorder trust list at all: unset (the default: nothing
    # can be accepted), configured, or set but unusable (an operator fault: nobody is
    # trusted). Never the file's path.
    payload["recorder_trust"] = {"status": server_trust.status, "note": server_trust.note}
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
    recorder_trust = None
    if body.recorder_trust is not None:
        try:
            refuse_private_key(body.recorder_trust)
            recorder_trust = RecorderTrust.from_dict(body.recorder_trust)
        except RecorderAttestationError as exc:
            if "private key" in str(exc).lower():
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail={"error": "private_key_refused", "detail": str(exc)}) from exc
            raise _bad(exc, "recorder_trust") from exc
    return check_bundle_data(body.bundle, envelope=envelope, trace=trace, limits=limits,
                             review_trust=trust, recorder_trust=recorder_trust,
                             machine_serial=body.machine_serial)


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
            # True only if THIS check accepted the recorded attestation under the trust
            # list the caller supplied. A trusted key signed these trace bytes; that is
            # not physical authenticity of the recording, nor safety.
            "recorder_attestation": result.provenance_reassessed == "reproduced",
            "reproduced": result.reproduced,
        },
        "recorded_verdict": recorded.get("verdict"),
        "recorded_tier": recorded.get("tier"),
        "recorded_provenance_basis": recorded.get("provenance_basis"),
        "provenance_basis_recorded": result.provenance_basis,
        # not_applicable | reproduced | unverifiable (no trust supplied: NOT believed) |
        # not_reproduced (rejected)
        "provenance_reassessed": result.provenance_reassessed,
        # The recorded tier, capped at community unless this check re-ran the engine on
        # your envelope and trace, reproduced the whole result, AND accepted the recorder
        # attestation under YOUR trust list. The limits review is reported separately.
        "believed_tier": result.believed_tier,
        # "attestation re-assessed; checks not re-run" when the attestation was accepted
        # under your list but the checks were not re-run (so no tier is believed).
        "reassessment_note": result.reassessment_note,
        "recorder_attestation": _attestation_summary(recorded.get("recorder_attestation")),
        # What the sealed bundle says about the review of its limits table (status
        # and explanation); whether THIS check accepted it is `checked.limits_review`.
        "recorded_limits_review": _review_summary(recorded.get("limits_review")),
        "product": recorded.get("product"),
        "product_version": recorded.get("product_version"),
    }
