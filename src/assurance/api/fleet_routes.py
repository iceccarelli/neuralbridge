"""The fleet, advisories, and declarations over HTTP.

Free, no account: ``POST /v1/fleet/advisory/check`` takes one advisory and one
manifest and says whether that machine matches. It is the demonstration — a
supplier bulletin landed this morning and an integrator can answer *is this cell
one of them* before finishing their coffee — and it needs nothing sealed.

Paid: the fan-out. One advisory against the whole enrolled fleet, reaching
serial numbers and the safety functions whose evidence it unsettles. That
requires the manifests to be in the ledger, which is exactly the thing worth
paying for, and the thing that gets more valuable with every machine enrolled.

``POST /v1/fleet/declaration/check`` is free too. A customer handed a machine
and a Declaration of Conformity must be able to check the declaration still
describes what they were sold, without an account with the people who sold it.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Anyone, Machine, get_accounts, get_register, spend
from assurance.billing.accounts import AccountStore, Principal
from assurance.core.errors import AssuranceError
from assurance.fleet.advisory import ComponentAdvisory, match_item
from assurance.fleet.declaration import DeclarationOfConformity, check_declaration
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord, assess_coverage

__all__ = ["fleet_router"]

fleet_router = APIRouter(prefix="/v1/fleet", tags=["fleet"])


class AdvisoryCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisory: dict[str, Any]
    manifest: dict[str, Any]


class AdvisoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisory: dict[str, Any]


class DeclarationCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    declaration: dict[str, Any]
    manifest: dict[str, Any]
    #: Assess the evidence as well as the configuration. Needs the ledger, so
    #: it needs a plan; without it only the configuration is compared.
    with_coverage: bool = False


class DeclareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    doc_id: str = Field(min_length=1, max_length=200)
    issued_by: str = Field(min_length=1, max_length=200)
    legislation: list[str] = Field(min_length=1)
    standards: list[str] = []
    notified_body: str = ""
    notified_body_number: str = ""
    signatory: str = ""
    place: str = ""


def _bad(exc: Exception, what: str) -> HTTPException:
    return HTTPException(
        # 422: unprocessable content.
        status_code=422,
        detail={"error": f"invalid_{what}", "detail": str(exc)},
    )


def _manifest(raw: dict[str, Any]) -> SafetyManifest:
    try:
        return SafetyManifest.from_dict(raw)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "manifest") from exc


def _advisory(raw: dict[str, Any]) -> ComponentAdvisory:
    try:
        return ComponentAdvisory.from_dict(raw)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "advisory") from exc


@fleet_router.post(
    "/advisory/check",
    summary="Is this one machine affected by this advisory?",
)
async def advisory_check(
    body: AdvisoryCheckIn,
    response: Response,
    principal: Annotated[Principal, Anyone],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """One advisory, one manifest, no account.

    The match basis is always reported. ``hash`` settles it; ``version`` rests on
    a label, and this system has already shown a label can be wrong;
    ``hash_mismatch`` means the machine's own label and artefact disagree against
    the supplier's published figures, which is neither affected nor clear.
    """
    limit = principal.plan.diffs_per_day
    spend(principal, "advisory_check", limit, accounts)
    response.headers["X-Assurance-Tier"] = principal.tier
    if limit is not None:
        used = accounts.usage_today(principal.subject).get("advisory_check", 0)
        response.headers["X-Assurance-Quota-Limit"] = str(limit)
        response.headers["X-Assurance-Quota-Remaining"] = str(max(0, limit - used))

    advisory = _advisory(body.advisory)
    manifest = _manifest(body.manifest)

    matches = []
    for item in manifest.items:
        matched = match_item(advisory, item)
        if matched is None:
            continue
        basis, detail = matched
        matches.append({
            "item_id": item.item_id,
            "item_name": item.name,
            "item_version": item.version,
            "basis": basis.value,
            "confidence": basis.confidence,
            "needs_a_human": basis.needs_a_human,
            "detail": detail,
            "implements": list(item.implements),
        })

    skipped = [
        "this compares one advisory against one manifest. It says nothing about "
        "any other machine, and it does not assess whether the safety evidence for "
        "the affected functions still stands — that needs the ledger.",
    ]
    if not advisory.publishes_hashes:
        skipped.append(
            f"{advisory.issued_by} published no artefact hashes, so any match here "
            "rests on a version label.")
    unhashed = [i.item_id for i in manifest.uncomparable_items]
    if unhashed:
        skipped.append(
            "item(s) " + ", ".join(unhashed) + " carry no hash, so an affected "
            "component hiding in them would not be found.")

    return {
        "advisory_id": advisory.advisory_id,
        "issued_by": advisory.issued_by,
        "severity": advisory.severity.value,
        "reference": advisory.reference,
        "machine": manifest.machine.key,
        "affected": bool(matches),
        "matches": matches,
        "remedy": advisory.remedy,
        "checks_skipped": skipped,
    }


@fleet_router.get("/machines", summary="Every enrolled machine, worst coverage first")
async def machines(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    return Fleet.from_ledger(register.ledger).to_dict()


@fleet_router.post(
    "/advisory",
    summary="Which of your machines does this advisory touch?",
)
async def advisory_impact(
    body: AdvisoryIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The fan-out: one advisory, every enrolled machine, down to safety functions.

    A machine whose coverage was already stale is reported, and is not counted
    as newly in question — an advisory does not make it worse, and mixing the two
    hides the machines that were fine until this morning.
    """
    advisory = _advisory(body.advisory)
    fleet = Fleet.from_ledger(register.ledger)
    return assess_impact(advisory, fleet).to_dict()


@fleet_router.post("/declare", summary="Bind a declaration to a configuration")
async def declare(
    body: DeclareIn,
    principal: Annotated[Principal, Machine],
) -> dict[str, Any]:
    from assurance.core.identity import utc_now

    manifest = _manifest(body.manifest)
    try:
        declaration = DeclarationOfConformity.bind(
            manifest, doc_id=body.doc_id, issued_by=body.issued_by,
            issued_at=utc_now(), legislation=tuple(body.legislation),
            standards=tuple(body.standards), notified_body=body.notified_body,
            notified_body_number=body.notified_body_number,
            signatory=body.signatory, place=body.place,
        )
    except (AssuranceError, ValueError) as exc:
        raise _bad(exc, "declaration") from exc
    return {
        "declaration": declaration.to_dict(),
        "content_hash": declaration.content_hash(),
        "note": "This declaration is bound to a configuration hash, so any later "
                "manifest of this machine either matches it or does not.",
    }


@fleet_router.post(
    "/declaration/check",
    summary="Does this declaration still describe the machine? Free for anyone.",
)
async def declaration_check(
    body: DeclarationCheckIn,
    principal: Annotated[Principal, Anyone],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Free, because the person who most needs this is the buyer, not the seller.

    Whether a changed configuration amounts to a substantial modification is a
    question for the manufacturer and their notified body. What this settles is
    the fact that question rests on.
    """
    try:
        declaration = DeclarationOfConformity.from_dict(body.declaration)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "declaration") from exc
    manifest = _manifest(body.manifest)

    coverage = None
    if body.with_coverage and principal.plan.machine_verification:
        key = manifest.machine.key
        coverage = assess_coverage(
            manifest,
            VerificationRecord.from_ledger(register.ledger, subject=key),
            interventions_from_ledger(register.ledger, key),
        )

    status = check_declaration(declaration, manifest, coverage)
    payload = status.to_dict()
    payload["coverage_assessed"] = coverage is not None
    if body.with_coverage and coverage is None:
        payload["checks_skipped"] = [
            "coverage was requested and not assessed: reading the evidence ledger "
            "needs a plan that includes machine verification. The configuration "
            "comparison above is unaffected.",
            *payload["checks_skipped"],
        ]
    return payload
