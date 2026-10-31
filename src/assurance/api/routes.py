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

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from ..billing.accounts import AccountStore, Principal
from ..core.errors import ClockError, EvidenceIncompleteError, LedgerIntegrityError
from ..core.evidence import Actor
from ..evidence.ledger import AnchorContradictsLedgerError
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
from .attest_routes import EXPORT_RESPONSES, anchor_contradiction, latest_anchor
from .declared_actor import sanitise_declared_role
from .deps import (
    Metered,
    MeterTicket,
    auth_mode,
    current_principal,
    get_accounts,
    get_register,
    require_evidence_readout,
    require_register,
    shared_register,
)
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

__all__ = ["router", "evidence_router", "free_router", "public_router"]

#: The register. Every route here needs a plan that includes it.
router = APIRouter(prefix="/v1", tags=["article 14"], dependencies=[Depends(require_register)])

#: Reading, verifying and exporting your own evidence. The same door as the
#: register for a customer who is paying, and still open to one whose
#: subscription has ended (``plans.EVIDENCE_READOUT_AFTER_LAPSE``): evidence is
#: not held hostage to a payment, while every write above stays closed.
evidence_router = APIRouter(
    prefix="/v1", tags=["article 14"], dependencies=[Depends(require_evidence_readout)]
)

#: The free surface: the field specification and the dry-run validator. A
#: prospect must be able to get value here without signing up for anything,
#: because that is what makes the paid register worth buying.
free_router = APIRouter(prefix="/v1", tags=["free"])

public_router = APIRouter(tags=["service"])


def _actor(payload: ActorIn) -> Actor:
    """The recorded actor, exactly as the caller declared it, minus the server's grammar.

    This register builds no attribution of its own, so the declared role is sealed as the
    caller's own words: ``;`` and ``=`` are removed (``declared_actor``) so it cannot
    imitate the ``operator=``/``key=``/``attribution=`` tokens other routes write.
    An undeclared role stays empty.
    """
    return Actor(identifier=payload.identifier,
                 role=sanitise_declared_role(payload.role, default=""), kind=payload.kind)


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
@evidence_router.get("/cases", response_model=list[str], summary="List case ids")
def get_cases(register: Art14Register = Depends(get_register)) -> list[str]:
    return register.case_ids()


@evidence_router.get("/cases/{case_id}", response_model=CaseOut, summary="One case, with deadlines")
def get_case(case_id: str, register: Art14Register = Depends(get_register)) -> CaseOut:
    case = register.case(case_id)
    if case.signal is None and case.awareness is None:
        raise HTTPException(
            status_code=404, detail={"error": "no_such_case", "detail": f"no records for {case_id}"}
        )
    return CaseOut(**case.to_dict())


@evidence_router.get(
    "/cases/{case_id}/export",
    response_model=dict,
    summary="A verifiable evidence bundle for one case",
    responses=EXPORT_RESPONSES,
)
def get_case_export(
    case_id: str,
    register: Art14Register = Depends(get_register),
    principal: Principal = Depends(require_evidence_readout),
    anchor: bool = Query(
        True,
        description="embed the newest signed attestation from this account's own "
                    "attestation log as the bundle's `anchor`, so a verifier holding "
                    "the signer's public key can check the bundle is complete up to "
                    "it. Set false to export without one."),
    skeleton: bool = Query(
        False,
        description="true to also carry `skeleton`: the position, kind, subject, time and hashes of every OTHER entry of this account's ledger (no evidence), so a verifier can see a removed entry and check completeness. Off by default because it discloses the id, kind and time of this account's other cases and incidents to whoever receives the file."),
) -> dict[str, Any]:
    """Refuses if the chain does not verify.

    ``?skeleton=true`` adds a ``skeleton`` of the account's other entries
    (positions, kinds, subjects, times and hashes; no evidence) so removed entries
    are visible. It is **off by default**: the link hash covers the plain subject,
    so the skeleton cannot be anonymised and names every other case and incident of
    the account. Without it the bundle is internally consistent but its
    completeness cannot be checked. The bundle carries the account's newest
    *server-read* signed attestation as ``anchor`` when it has one (409
    ``anchor_contradicts_ledger`` if that does not match this ledger; counter-signed
    heads the customer declared are never embedded). Records after the anchor are
    covered by no signature; for a hosted ledger the service holds the signing key
    too, so the anchor helps only a customer who kept their own copy of a signed
    attestation.

    An export is the moment records leave the system and start being relied on.
    For a paying account it is gated on the plan's ``export`` entitlement as
    well as on the register itself, so the ``verifiable_export`` limit on
    ``GET /v1/plans`` is a statement about code that runs. A customer whose
    subscription has ended still gets it (``require_evidence_readout``): their
    evidence is not held hostage to a payment.

    **Completeness.** Without ``skeleton`` a bundle is internally consistent but a
    removed entry of the case cannot be seen, and a verifier reports completeness as
    *not checked*. With ``skeleton`` and a signed ``anchor``, a verifier holding the
    signer's public key can show nothing was removed up to the anchor; records after
    it are covered by no signature.

    **Anchor.** ``anchor`` is the newest attestation the service *read from this
    account's own ledger* (``read_from_ledger``). No customer route creates one: the
    operator runs ``assurance attest sign`` against the hosted ledger
    (``deploy/assurance/ATTEST.md``). Until then the export carries no ``anchor`` and
    its completeness is not checked. Counter-signed heads you declared about your own
    ledger (``POST /v1/ledger/attest``) are never embedded. If the embedded
    attestation does not match this ledger the answer is 409
    ``anchor_contradicts_ledger``, a rewind signal, and nothing is exported. A damaged
    attestation log is 500 ``attestation_log_damaged``, never a silently unanchored
    export; ``?anchor=false`` is the explicit way to export without one.
    """
    if principal.plan.register and not principal.plan.export:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "plan_does_not_include_export",
                "tier": principal.tier,
                "account_status": principal.account.status if principal.account else "",
                "remedy": "Verifiable export is included with the Register plan "
                          "and above. GET /v1/plans, then POST /v1/checkout.",
            },
        )
    signed_anchor = latest_anchor(principal) if anchor else None
    try:
        bundle = register.ledger.export(
            subject=case_id, anchor=signed_anchor, skeleton=skeleton)
    except AnchorContradictsLedgerError as exc:
        raise anchor_contradiction(exc) from exc
    except Exception as exc:  # noqa: BLE001
        raise _refuse(exc) from exc
    if not bundle["entries"]:
        # A well-formed, chain-verified bundle with nothing in it is what an id that
        # names nothing exports. It would read as a clean record of a case.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "case_not_found", "case_id": case_id},
        )
    return bundle


@router.get("/register", response_model=dict, summary="Readiness across every case")
def get_register_report(register: Art14Register = Depends(get_register)) -> dict[str, Any]:
    return readiness_report(register)


@router.get("/register/breaches", response_model=list, summary="Deadlines missed or overdue")
def get_breaches(register: Art14Register = Depends(get_register)) -> list[dict[str, Any]]:
    return register.breaches()


def _server_anchor(principal: Principal | None) -> Any:
    """The anchor this account's own attestation log can supply, or the reasons it cannot.

    Reads the log without its lock (verification never waits for a signer) and checks
    every record against the **service's own public key**, never a key found in the log.
    Only the account's own log is read, and only for a per-account ledger: the operator's
    shared ledger has no per-account log, so it is never anchored here.
    """
    from ..attest.anchor import AnchorChoice, choose_anchor
    from ..attest.attestation import AttestationError
    from .attest_routes import _LOG_LABEL, _log_for, _service_key

    account = principal.account if principal is not None else None
    if account is None or account.id == "operator":
        return AnchorChoice(None, [
            "this is the operator's shared ledger, which has no per-account attestation "
            "log; no anchor is used"])
    try:
        key = _service_key().verifying
    except HTTPException:
        key = None          # unconfigured or unusable; the detail may name a server path
    try:
        records, torn = _log_for(principal).scan()
    except (AttestationError, OSError):
        return AnchorChoice(None, [
            f"{_LOG_LABEL} could not be read; no anchor is used"],
            key.fingerprint if key else "")
    return choose_anchor(records, key, torn=torn, log_label=_LOG_LABEL)


@evidence_router.get("/ledger/verify", response_model=dict, summary="Verify the evidence chain")
def get_ledger_verify(
    register: Art14Register = Depends(get_register),
    principal: Principal | None = Depends(current_principal),
) -> dict[str, Any]:
    """Chain check, plus a completeness check against the service's own counter-signature.

    ``completeness`` is ``checked_against_anchor`` only when this account has an
    attestation log whose every record verifies against the *service's* public key and
    whose newest server-read head this ledger still contains; ``contradicted_by_anchor``
    (and ``verified`` false) when it does not. Otherwise ``not_checked``, and
    ``not_checked`` names the missing prerequisite. ``anchor_meaning`` says what that
    does and does not prove.
    """
    from ..attest.anchor import ANCHOR_MEANING, describe_choice

    choice = _server_anchor(principal)
    report = register.ledger.verify_report(
        anchor=choice.anchor, anchor_verified_by=choice.key_fingerprint or None)
    not_checked = list(report["not_checked"])
    if choice.anchor is None:
        not_checked.extend(f"anchor not used: {r}" for r in choice.reasons)
    elif report["completeness"] == "not_checked":
        not_checked.append(
            "anchor not compared: the chain itself does not verify, so no completeness "
            "statement is made")
    return {
        "verified": report["verified"],
        "problems": report["problems"],
        # "verified" is the chain's self-consistency only. Completeness (nothing removed
        # from the end) is stated by `completeness`; see not_checked.
        "completeness": report["completeness"],
        "not_checked": not_checked,
        "ledger_id": report["ledger_id"],
        "anchor": describe_choice(choice),
        "anchor_meaning": ANCHOR_MEANING,
        "attestation": register.ledger.head_attestation(),
        "note": (
            "Sign or publish attestation.head_link_hash with a key held outside this service "
            "to make a silent rewind detectable. A self-recomputable chain detects accident "
            "and casual tampering, not a determined insider. A hosted ledger's anchor comes "
            "from a key this service holds: it is as independent of the ledger's operator as "
            "that key's custody is."
        ),
    }


# =====================================================================
# specification — no register state, safe to expose widely
# =====================================================================
@free_router.get("/spec/fields", response_model=list, summary="The platform field specification")
def get_fields(
    track: str = Query(..., pattern="^(actively_exploited_vulnerability|severe_incident)$"),
    stage: str = Query(..., pattern="^(early_warning|notification|final|intermediate)$"),
) -> list[dict[str, Any]]:
    """Free, and deliberately so. The specification is not the product."""
    return [f.to_dict() for f in fields_for(Track(track), Stage(stage))]


@free_router.post(
    "/spec/validate",
    response_model=ValidationOut,
    summary="Validate a draft submission without recording it",
)
def post_validate(
    body: ValidateIn,
    response: Response,
    meter: Annotated[MeterTicket, Metered("validate")],
) -> ValidationOut:
    """The free tier, and the demo that sells the register behind it.

    Nothing is recorded about the filing. A prospect can paste a draft filing
    and immediately see which of the 39 fields are missing, which exceed a
    character limit, and which listed territories are not EU Member States.
    The call is counted (see ``billing/metering.py``) once the answer is
    complete; a draft that is not submittable is a successful answer.
    """
    validation = validate_payload(body.payload, Track(body.track), Stage(body.stage))
    out = ValidationOut(**validation.to_dict())
    meter.commit(response)
    return out


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
            "plans_and_pricing": "/v1/plans",
            "subscribe": "POST /v1/checkout",
            "your_account": "/v1/me",
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
def healthz(
    response: Response, accounts: AccountStore = Depends(get_accounts)
) -> dict[str, Any]:
    """Reports what is actually true, including an unauthenticated deployment.

    Unauthenticated and polled every few seconds, so it is cheap and says
    nothing about the host: no filesystem path, and no chain verification
    (that is O(n) in the ledger and lives at the authenticated
    ``GET /v1/ledger/verify``). It does confirm that both stores open, which
    exercises their schema-version checks, and reports the operator ledger's
    entry count.
    """
    mode = auth_mode()
    payload: dict[str, Any] = {"status": "ok", "auth_mode": mode}
    try:
        payload["ledger_records"] = len(shared_register().ledger)
        payload["ledger_ok"] = True
    except Exception:  # noqa: BLE001 - reported as a state, never echoed
        payload["ledger_ok"] = False
    try:
        accounts.usage_today("healthz")
        payload["accounts_ok"] = True
    except Exception:  # noqa: BLE001
        payload["accounts_ok"] = False
    if not (payload["ledger_ok"] and payload["accounts_ok"]):
        payload["status"] = "unavailable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    payload |= {
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
        if payload["status"] == "ok":
            payload["status"] = "degraded"
        payload["warning"] = (
            "No API keys configured; register routes return 503. Set ASSURANCE_API_KEYS."
        )
    return payload
