"""HTTP routes for the Article 14 register.

Every write returns what is now outstanding. The next question after recording
anything is always "and now what is due", so the answer travels with the
response rather than requiring a second call.

Refusals carry the provision they rest on. A 409 that says "invalid state"
teaches an integrator nothing; a 409 that says the 14-day clock has not started
because no corrective or mitigating measure is recorded, and cites Art. 14(2)(c),
is actionable.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from ..core.errors import ClockError, EvidenceIncompleteError, LedgerIntegrityError
from ..core.evidence import Actor
from ..security.art14.engine import Art14Register, CaseError
from ..security.art14.model import (
    Awareness,
    ProductVersion,
    Signal,
    SignalChannel,
    Stage,
    Track,
)
from ..security.art14.report import readiness_report
from ..security.art14.srp import GLOSSARY_DATE, GLOSSARY_VERSION, fields_for, validate_payload
from .deps import auth_mode, get_register, ledger_path, require_api_key
from .schemas import (
    ActorIn,
    AvailabilityIn,
    AwarenessIn,
    CaseOut,
    FilingIn,
    FilingOut,
    MeasureIn,
    RecordedOut,
    SignalIn,
    TriageIn,
    UserNotificationIn,
    ValidateIn,
    ValidationOut,
)

__all__ = ["router", "public_router"]

router = APIRouter(prefix="/v1", tags=["article 14"], dependencies=[Depends(require_api_key)])
public_router = APIRouter(tags=["service"])


def _actor(payload: ActorIn) -> Actor:
    return Actor(identifier=payload.identifier, role=payload.role, kind=payload.kind)


def _recorded(register: Art14Register, case_id: str, evidence) -> RecordedOut:
    entry = register.ledger.get(evidence.content_hash)
    return RecordedOut(
        case_id=case_id,
        content_hash=evidence.content_hash,
        kind=evidence.kind,
        ledger_seq=entry.seq if entry else 0,
        outstanding=register.case(case_id).outstanding(),
    )


def _refuse(exc: Exception) -> HTTPException:
    """Map a domain refusal onto a status code, keeping the reason intact."""
    if isinstance(exc, ClockError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "clock_not_started", "detail": str(exc)},
        )
    if isinstance(exc, EvidenceIncompleteError):
        return HTTPException(
            status_code=422,  # unprocessable content
            detail={"error": "evidence_incomplete", "detail": str(exc)},
        )
    if isinstance(exc, CaseError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "case_state", "detail": str(exc)},
        )
    if isinstance(exc, LedgerIntegrityError):
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "ledger_integrity", "detail": str(exc)},
        )
    raise exc


# =====================================================================
# recording
# =====================================================================
@router.post(
    "/cases/{case_id}/signal",
    response_model=RecordedOut,
    status_code=status.HTTP_201_CREATED,
    summary="Open a case with the first thing anyone heard",
)
def post_signal(
    case_id: str, body: SignalIn, register: Art14Register = Depends(get_register)
) -> RecordedOut:
    """No deadline starts here.

    The clock starts at awareness, which is a separate, reasoned record. The
    interval between the two is what a market surveillance authority asks
    about, and it cannot be reconstructed if the signal was never recorded.
    """
    try:
        signal = Signal(
            received_at=body.received_at,
            channel=SignalChannel(body.channel),
            received_by=body.received_by or body.actor.identifier,
            description=body.description,
            product_name=body.product_name,
            version=body.version,
            reference=body.reference,
        )
        evidence = register.record_signal(case_id, signal, _actor(body.actor))
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "bad_channel", "detail": str(exc)}
        ) from exc
    except Exception as exc:  # noqa: BLE001 - mapped, never swallowed
        raise _refuse(exc) from exc
    return _recorded(register, case_id, evidence)


@router.post(
    "/cases/{case_id}/awareness",
    response_model=RecordedOut,
    status_code=status.HTTP_201_CREATED,
    summary="Establish the moment every deadline runs from",
)
def post_awareness(
    case_id: str, body: AwarenessIn, register: Art14Register = Depends(get_register)
) -> RecordedOut:
    try:
        awareness = Awareness(
            established_at=body.established_at,
            assessment_started_at=body.assessment_started_at,
            assessment_completed_at=body.assessment_completed_at,
            determined_by=body.determined_by or body.actor.identifier,
            reasoning=body.reasoning,
        )
        evidence = register.record_awareness(
            case_id, awareness, Track(body.track), _actor(body.actor)
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail={"error": "bad_awareness", "detail": str(exc)}
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    return _recorded(register, case_id, evidence)


@router.post(
    "/cases/{case_id}/triage",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Work the reportability decision path",
)
def post_triage(
    case_id: str, body: TriageIn, register: Art14Register = Depends(get_register)
) -> dict[str, Any]:
    try:
        evidence, result = register.record_triage(
            case_id,
            dict(body.answers),
            _actor(body.actor),
            body.reasoning,
            reopen_trigger=body.reopen_trigger,
        )
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    recorded = _recorded(register, case_id, evidence)
    return {**recorded.model_dump(), "triage": result.to_dict()}


@router.post(
    "/cases/{case_id}/availability",
    response_model=RecordedOut,
    status_code=status.HTTP_201_CREATED,
    summary="Attach the product and Member State record the filing needs",
)
def post_availability(
    case_id: str, body: AvailabilityIn, register: Art14Register = Depends(get_register)
) -> RecordedOut:
    product = ProductVersion(
        product_name=body.product_name,
        version_range=body.version_range,
        member_states=tuple(body.member_states),
        other_markets=tuple(body.other_markets),
        placed_on_market_from=body.placed_on_market_from,
        placed_on_market_to=body.placed_on_market_to,
        end_of_support=body.end_of_support,
        units_in_field=body.units_in_field,
        product_type=body.product_type,
        annex_category=body.annex_category,
        components=tuple(body.components),
        evidence_source=body.evidence_source,
        owner=body.owner,
    )
    try:
        evidence = register.record_availability(case_id, product, _actor(body.actor))
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    return _recorded(register, case_id, evidence)


@router.post(
    "/cases/{case_id}/measure",
    response_model=RecordedOut,
    status_code=status.HTTP_201_CREATED,
    summary="Record a corrective or mitigating measure becoming available",
)
def post_measure(
    case_id: str, body: MeasureIn, register: Art14Register = Depends(get_register)
) -> RecordedOut:
    """Starts the 14-day final-report clock for a vulnerability, Art. 14(2)(c).

    A documented workaround starts it as surely as a patch does.
    """
    try:
        evidence = register.record_measure_available(
            case_id, body.available_at, body.description, _actor(body.actor)
        )
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    return _recorded(register, case_id, evidence)


@router.post(
    "/cases/{case_id}/filings",
    response_model=FilingOut,
    status_code=status.HTTP_201_CREATED,
    summary="Record a submission, validated against the platform field spec",
)
def post_filing(
    case_id: str,
    body: FilingIn,
    response: Response,
    register: Art14Register = Depends(get_register),
) -> FilingOut:
    """Recording a filing that is not submittable is allowed and flagged.

    A manufacturer who has already submitted something incomplete needs that
    fact in the record, not a refusal. ``validation.submittable`` is false and
    the response carries ``X-Assurance-Submittable: false``.
    """
    try:
        evidence, validation = register.record_filing(
            case_id,
            Stage(body.stage),
            body.submitted_at,
            body.payload,
            _actor(body.actor),
            body.platform_reference,
        )
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    response.headers["X-Assurance-Submittable"] = str(validation.submittable).lower()
    recorded = _recorded(register, case_id, evidence)
    return FilingOut(**recorded.model_dump(), validation=ValidationOut(**validation.to_dict()))


@router.post(
    "/cases/{case_id}/user-notification",
    response_model=RecordedOut,
    status_code=status.HTTP_201_CREATED,
    summary="Record the Article 14(8) notification to users",
)
def post_user_notification(
    case_id: str, body: UserNotificationIn, register: Art14Register = Depends(get_register)
) -> RecordedOut:
    try:
        evidence = register.record_user_notification(
            case_id,
            body.at,
            body.scope,
            body.content,
            _actor(body.actor),
            public=body.public_disclosure,
        )
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    return _recorded(register, case_id, evidence)


# =====================================================================
# reading
# =====================================================================
@router.get("/cases", response_model=list[str], summary="List case ids")
def get_cases(register: Art14Register = Depends(get_register)) -> list[str]:
    return register.case_ids()


@router.get("/cases/{case_id}", response_model=CaseOut, summary="One case, with deadlines")
def get_case(case_id: str, register: Art14Register = Depends(get_register)) -> CaseOut:
    case = register.case(case_id)
    if case.signal is None and case.awareness is None:
        raise HTTPException(
            status_code=404, detail={"error": "no_such_case", "detail": f"no records for {case_id}"}
        )
    return CaseOut(**case.to_dict())


@router.get(
    "/cases/{case_id}/export",
    response_model=dict,
    summary="A verifiable evidence bundle for one case",
)
def get_case_export(case_id: str, register: Art14Register = Depends(get_register)) -> dict[str, Any]:
    """Refuses if the chain does not verify.

    An export is the moment records leave the system and start being relied on.
    """
    try:
        return register.ledger.export(subject=case_id)
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc


@router.get("/register", response_model=dict, summary="Readiness across every case")
def get_register_report(register: Art14Register = Depends(get_register)) -> dict[str, Any]:
    return readiness_report(register)


@router.get("/register/breaches", response_model=list, summary="Deadlines missed or overdue")
def get_breaches(register: Art14Register = Depends(get_register)) -> list[dict[str, Any]]:
    return register.breaches()


@router.get("/ledger/verify", response_model=dict, summary="Verify the evidence chain")
def get_ledger_verify(register: Art14Register = Depends(get_register)) -> dict[str, Any]:
    ok, problems = register.ledger.verify_chain()
    return {
        "verified": ok,
        "problems": problems,
        "attestation": register.ledger.head_attestation(),
        "note": (
            "Sign or publish attestation.head_link_hash with a key held outside this service "
            "to make a silent rewind detectable. A self-recomputable chain detects accident "
            "and casual tampering, not a determined insider."
        ),
    }


# =====================================================================
# specification — no register state, safe to expose widely
# =====================================================================
@router.get("/spec/fields", response_model=list, summary="The platform field specification")
def get_fields(
    track: str = Query(..., pattern="^(actively_exploited_vulnerability|severe_incident)$"),
    stage: str = Query(..., pattern="^(early_warning|notification|final|intermediate)$"),
) -> list[dict[str, Any]]:
    return [f.to_dict() for f in fields_for(Track(track), Stage(stage))]


@router.post(
    "/spec/validate",
    response_model=ValidationOut,
    summary="Validate a draft submission without recording it",
)
def post_validate(body: ValidateIn) -> ValidationOut:
    validation = validate_payload(body.payload, Track(body.track), Stage(body.stage))
    return ValidationOut(**validation.to_dict())


# =====================================================================
# service
# =====================================================================
@public_router.get("/", response_model=dict, summary="What this service is")
def root() -> dict[str, Any]:
    """The front door.

    Someone who reaches the bare URL should learn what this is, and what they
    can try without an account, in one response.
    """
    return {
        "service": "Industrial Assurance — CRA Article 14 register",
        "regulation": "Regulation (EU) 2024/2847, Article 14",
        "applicable_since": "2026-09-11",
        "scope_note": (
            "By Art. 69(3) this applies to every in-scope product placed on the market "
            "before 11 December 2027. There is no grandfathering for reporting, and the "
            "duty outlives a product's support period."
        ),
        "deadlines": {
            "early_warning": "24 h from becoming aware",
            "notification": "72 h from becoming aware",
            "final_report_vulnerability": (
                "14 days from a corrective OR MITIGATING measure becoming available "
                "(Art. 14(2)(c))"
            ),
            "final_report_incident": (
                "1 calendar month from submission of the 72 h notification (Art. 14(4)(c))"
            ),
        },
        "start_here": {
            "interactive_docs": "/docs",
            "openapi_schema": "/openapi.json",
            "health": "/healthz",
            "try_without_an_account": {
                "method": "POST",
                "path": "/v1/spec/validate",
                "what_it_does": (
                    "Checks a draft filing against the 39-field ENISA platform "
                    "specification and reports what is missing, what exceeds a character "
                    "limit, and which listed territories are not EU Member States. "
                    "Records nothing."
                ),
            },
        },
        "field_spec": {"source": "ENISA CRA SRP Glossary", "version": GLOSSARY_VERSION,
                       "dated": GLOSSARY_DATE},
        "not_legal_advice": True,
    }


@public_router.get("/healthz", response_model=dict, summary="Liveness and configuration")
def healthz(register: Art14Register = Depends(get_register)) -> dict[str, Any]:
    """Reports what is actually true, including an unauthenticated deployment."""
    ok, _ = register.ledger.verify_chain()
    mode = auth_mode()
    payload: dict[str, Any] = {
        "status": "ok",
        "auth_mode": mode,
        "ledger": ledger_path(),
        "ledger_records": len(register.ledger),
        "chain_verified": ok,
        "field_spec": {"source": "ENISA CRA SRP Glossary", "version": GLOSSARY_VERSION,
                       "dated": GLOSSARY_DATE},
        "regulation": "Regulation (EU) 2024/2847, Article 14",
        "applicable_since": "2026-09-11",
    }
    if mode == "open":
        payload["warning"] = (
            "Running without authentication. Every caller can write to the register. "
            "Configure ASSURANCE_API_KEYS before this holds anything real."
        )
    if mode == "unconfigured":
        payload["status"] = "degraded"
        payload["warning"] = (
            "No API keys configured; register routes return 503. Set ASSURANCE_API_KEYS."
        )
    return payload
