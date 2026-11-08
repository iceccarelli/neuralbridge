"""SBOM drafts and CSAF supplier advisories over HTTP: the same domain functions as the CLI.

Gated exactly like the other machine and fleet routes that read or write the account's ledger
(``Machine``: 401 with no or an invalid key, 402 for an authenticated account whose plan does not
include machine verification). Reviewing a draft is a human decision, so it takes what a case
decision takes: an operator key with the ``decider`` role, and an account-level key is refused 403.

The document travels as TEXT (``document``), not as a JSON object: the SHA-256 recorded is that of
the UTF-8 bytes of exactly that text, and re-serialising a parsed object would hash something the
sender never had. The request body is bounded by the service's body cap.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.change_routes import _actor
from assurance.api.declared_actor import sanitise_declared_role
from assurance.api.deps import Machine, get_register
from assurance.api.recorder_trust import reader_recorder_trust
from assurance.billing.accounts import Principal
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.ingest import csaf, sbom_store
from assurance.ingest.common import MAX_DOCUMENT_BYTES, IngestError, make_source
from assurance.machinery.enrol import EnrolmentError

__all__ = ["ingest_router"]

ingest_router = APIRouter(prefix="/v1/ingest", tags=["ingest"])

_STATUS = {
    "too_large": 413, "too_deep": 422, "draft_not_found": 404, "advisory_not_found": 404,
    "already_reviewed": 409, "ledger_chain_unverified": 409, "configuration_differs": 409,
    "identity_conflict": 409, "conflict": 409,
}


class DocumentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The document as text, exactly as received (JSON). Its UTF-8 bytes are what is hashed.
    document: str = Field(min_length=1, max_length=MAX_DOCUMENT_BYTES)
    #: As supplied by the caller and recorded as such; never verified.
    source_name: str | None = Field(default=None, max_length=300)
    supplied_at: str | None = Field(default=None, max_length=64)
    source_url: str | None = Field(default=None, max_length=2000)
    #: The SHA-256 the caller was told the document has; the request is refused if it differs.
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{64}$")
    #: Who is submitting; recorded as declared (an operator key is attributed by the server).
    actor: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=200)
    dry_run: bool = False


class CsafIn(DocumentIn):
    allow_draft: bool = False


class ReviewIn(BaseModel):
    """A named person's decision on a draft. The fields are checked by the domain function,
    which says what is wrong with each in ``violations``; ``extra`` is left open so an unknown
    field is reported there, in the same words as on the command line."""

    model_config = ConfigDict(extra="allow")

    decision: str = Field(min_length=1, max_length=20)
    reason: str = Field(min_length=1, max_length=2_000)
    identity: dict[str, Any] = Field(default_factory=dict)
    functions: list[Any] = Field(default_factory=list, max_length=100)
    components: list[Any] = Field(default_factory=list, max_length=5_000)
    actor: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=200)


def _refused(exc: IngestError) -> HTTPException:
    return HTTPException(
        status_code=_STATUS.get(exc.code, 422),
        detail={"error": exc.code, "detail": str(exc), "violations": list(exc.violations)})


def _bytes(body: DocumentIn) -> bytes:
    try:
        return body.document.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise HTTPException(status_code=422, detail={
            "error": "invalid_document",
            "detail": "the document text cannot be encoded as UTF-8 "
                      f"({exc.reason}); nothing was recorded."}) from exc


@ingest_router.post(
    "/sbom",
    summary="Import a CycloneDX SBOM as a DRAFT inventory pending named human review",
    responses={
        413: {"description": "`too_large`: the document is over the size this importer reads."},
        422: {"description": "`invalid_sbom` (the violations list every structural rule broken), "
                             "`unsupported_spec_version`, `no_components`, `too_deep`, "
                             "`invalid_source`, `source_hash_mismatch`. Nothing was recorded."},
    },
)
def post_sbom(
    body: DocumentIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Validate a CycloneDX JSON SBOM (1.4, 1.5, 1.6) and record it as a draft.

    The draft never carries a machine serial number, never marks a component safety-relevant and
    never marks one as read from the machine; a missing version, purl, supplier or digest is
    recorded as unknown. Every decision in it is `pending_review` until a named person reviews it
    (`POST /v1/ingest/sbom/{draft_id}/review`). The same bytes again are `already_imported`.
    """
    actor = _actor(body.actor, body.role or "importer", principal)
    raw = _bytes(body)
    try:
        source = make_source(raw, name=body.source_name, supplied_at=body.supplied_at,
                             url=body.source_url, claimed_sha256=body.source_sha256)
        return sbom_store.import_sbom(None if body.dry_run else register.ledger, raw,
                                      source=source, actor=actor, dry_run=body.dry_run)
    except IngestError as exc:
        raise _refused(exc) from exc


@ingest_router.get("/sbom", summary="The SBOM drafts in your ledger and their review state")
def get_sbom_drafts(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    return sbom_store.list_sbom_drafts(register.ledger)


@ingest_router.get(
    "/sbom/{draft_id}",
    summary="One SBOM draft in full, with its review state and a blank review template",
    responses={404: {"description": "`draft_not_found`."}},
)
def get_sbom_draft(
    draft_id: str,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        return sbom_store.get_sbom_draft(register.ledger, draft_id[:100])
    except IngestError as exc:
        raise _refused(exc) from exc


@ingest_router.post(
    "/sbom/{draft_id}/review",
    summary="A named decider approves (and enrols) or rejects an SBOM draft",
    responses={
        403: {"description": "`operator_required` / `decider_role_required`: an account-level "
                             "key cannot make a human decision."},
        404: {"description": "`draft_not_found`."},
        409: {"description": "`already_reviewed`, `configuration_differs`, `identity_conflict` "
                             "or `ledger_chain_unverified`. Nothing was recorded."},
        422: {"description": "`invalid_review`: the violations say what each decision lacks."},
    },
)
def post_sbom_review(
    draft_id: str,
    body: ReviewIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Approve or reject a draft. Approval enrols the machine through the enrolment front door.

    A human decision: it needs an operator key with the `decider` role. The machine's
    manufacturer, model and serial number, and an explicit include/exclude, kind and safety
    function for every component, are the reviewer's; nothing is defaulted. A review is made once.
    """
    attributed = _actor(body.actor, body.role or "reviewer", principal, human=True)
    # The domain function takes a person whose role is free text. How the SERVER established who
    # that is (an authenticated operator key) is passed beside it and recorded beside it.
    reviewer = Actor(identifier=attributed.identifier,
                     role=sanitise_declared_role(body.role, default="reviewer"), kind="person")
    request = dict(body.model_extra or {})
    request.update(decision=body.decision, reason=body.reason, identity=body.identity,
                   functions=body.functions, components=body.components)
    try:
        return sbom_store.review_sbom_draft(register.ledger, draft_id[:100], request,
                                            reviewer=reviewer, attribution=attributed.role)
    except IngestError as exc:
        raise _refused(exc) from exc
    except EnrolmentError as exc:
        text = str(exc)
        status = 409 if text.startswith("the ledger chain does not verify") else 422
        raise HTTPException(status_code=status, detail={
            "error": "ledger_chain_unverified" if status == 409 else "invalid_review",
            "detail": text, "violations": []}) from exc


@ingest_router.post(
    "/csaf",
    summary="Import a CSAF 2.0 advisory as a recorded, unsigned supplier advisory",
    responses={
        413: {"description": "`too_large`."},
        422: {"description": "`invalid_csaf` (the violations list every CSAF 2.0 structural "
                             "rule broken), `document_not_final`, `too_deep`, `invalid_source`, "
                             "`source_hash_mismatch`. Nothing was recorded."},
    },
)
def post_csaf(
    body: CsafIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Validate and record a CSAF 2.0 document: its SHA-256, publisher, tracking and dates, and
    each vulnerability's product statuses. It is unsigned third-party content and inspect-only.
    `GET /v1/ingest/csaf/{advisory_ref}/impact` matches it to the enrolled fleet."""
    actor = _actor(body.actor, body.role or "importer", principal)
    raw = _bytes(body)
    try:
        source = make_source(raw, name=body.source_name, supplied_at=body.supplied_at,
                             url=body.source_url, claimed_sha256=body.source_sha256)
        return csaf.import_csaf(None if body.dry_run else register.ledger, raw, source=source,
                                actor=actor, allow_draft=body.allow_draft, dry_run=body.dry_run)
    except IngestError as exc:
        raise _refused(exc) from exc


@ingest_router.get("/csaf", summary="The CSAF supplier advisories recorded in your ledger")
def get_csaf_advisories(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    return csaf.list_csaf_advisories(register.ledger)


@ingest_router.get(
    "/csaf/{advisory_ref}",
    summary="One recorded CSAF advisory in full",
    responses={404: {"description": "`advisory_not_found`."}},
)
def get_csaf_advisory(
    advisory_ref: str,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    try:
        return csaf.get_csaf_advisory(register.ledger, advisory_ref[:100])
    except IngestError as exc:
        raise _refused(exc) from exc


@ingest_router.get(
    "/csaf/{advisory_ref}/impact",
    summary="What a recorded CSAF advisory says about each enrolled machine",
    responses={404: {"description": "`advisory_not_found`."}},
)
def get_csaf_impact(
    advisory_ref: str,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Every enrolled machine is `affected`, `under_investigation`, `fixed`, `not_affected` or
    `unknown`, with the reason and the evidence. A match that is not certain is `unknown`; a
    machine the advisory does not name is `unknown` with the reason `not_named`. Inspect-only."""
    try:
        return csaf.csaf_impact(register.ledger, advisory_ref[:100],
                                recorder_trust=reader_recorder_trust())
    except IngestError as exc:
        raise _refused(exc) from exc
    except AssuranceError as exc:
        raise HTTPException(status_code=422, detail={
            "error": "invalid_advisory", "detail": str(exc)}) from exc
