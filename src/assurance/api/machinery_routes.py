"""Machinery Regulation Annex III 1.1.9 over HTTP.

The same commercial shape as the machine routes, for the same reason.

Free, no account: ``POST /v1/machinery/diff`` compares a baseline manifest
against what was found on the machine. It is the demonstration — an integrator
who has a CE-marking configuration and a current one finds out in one call
whether the cell is still the cell they signed off, and usually it is not.

Free, permanently, unmetered: ``POST /v1/machinery/passport/check``. A customer,
their insurer and their notified body must be able to re-verify a machine
passport without an account, or it is a vendor certificate rather than evidence.

Paid: sealing manifests and interventions into the ledger, and the coverage
assessment that joins them to verification bundles. That join is the product.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.declared_actor import sanitise_declared_role
from assurance.api.deps import Anyone, Machine, Metered, MeterTicket, get_register
from assurance.api.recorder_trust import reader_recorder_trust
from assurance.billing.accounts import Principal
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.machinery.amend import amend_enrolment
from assurance.machinery.divergence import compare
from assurance.machinery.enrol import EnrolmentError, enrol_machine
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import (
    UnknownFunctionError,
    UnknownMachineError,
    build_passport,
    check_intervention,
    interventions_from_ledger,
    record_intervention,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import (
    VerificationRecord,
    affected_functions,
    assess_coverage,
)

__all__ = ["machinery_router"]

machinery_router = APIRouter(prefix="/v1/machinery", tags=["machinery"])

# Every handler here is a plain ``def``: FastAPI runs it in a worker thread. They read and
# verify a ledger, hash manifests and compare up to MAX_ITEMS items, which is CPU and disk
# work that must not stop the event loop (see ``machine_routes.verify_run``).

#: A manifest larger than this is a fleet export, not one machine.
MAX_ITEMS = 5_000


class DiffIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline: dict[str, Any]
    observed: dict[str, Any]


class ManifestIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    actor: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=200)


class EnrolIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    #: Required: enrolment is a declaration by a named person.
    actor: str = Field(min_length=1, max_length=200)
    role: str = Field(default="", max_length=200)
    site: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)


class AmendEnrolmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The machine key as enrolled (``manufacturer/model#serial``).
    machine: str = Field(min_length=1, max_length=400)
    #: Required: an amendment is a declaration by a named person.
    actor: str = Field(min_length=1, max_length=200)
    role: str = Field(default="", max_length=200)
    #: Required: why the declaration changed.
    reason: str = Field(min_length=1, max_length=1000)
    #: ``{"site": ..., "owner": ...}``. Left open on purpose so that an attribute that is not
    #: amendable (or is the machine key) is refused by the domain function with a receipt.
    changes: dict[str, str] = Field(min_length=1, max_length=20)


class InterventionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intervention: dict[str, Any]
    actor: str = Field(default="", max_length=200)
    role: str = Field(default="", max_length=200)


class CoverageIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]


class PassportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    manifest: dict[str, Any]
    actor: str = Field(min_length=1, max_length=200)
    role: str = Field(default="verification engineer", max_length=200)
    seal: bool = True


class PassportCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passport: dict[str, Any]


def _declared_actor(body: ManifestIn | InterventionIn) -> Actor | None:
    """The person the caller names, with the role they declare, minus the server's grammar.

    These routes add no attribution of their own, so the role is sealed as the caller's
    words; ``;`` and ``=`` are removed (``declared_actor``) so it cannot imitate an
    ``operator=``/``key=``/``attribution=`` token written by another route. An undeclared
    role stays empty.
    """
    if not body.actor:
        return None
    return Actor(identifier=body.actor,
                 role=sanitise_declared_role(body.role, default=""), kind="person")


def _bad(exc: Exception, what: str) -> HTTPException:
    return HTTPException(
        # 422: unprocessable content.
        status_code=422,
        detail={"error": f"invalid_{what}", "detail": str(exc)},
    )


def _manifest(raw: dict[str, Any], what: str = "manifest") -> SafetyManifest:
    items = raw.get("items")
    if isinstance(items, list) and len(items) > MAX_ITEMS:
        raise HTTPException(
            # 413: content too large.
            status_code=413,
            detail={"error": "manifest_too_large",
                    "detail": f"{len(items)} items exceeds the {MAX_ITEMS} this "
                              "endpoint accepts. One manifest describes one machine."},
        )
    try:
        return SafetyManifest.from_dict(raw)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, what) from exc


@machinery_router.post(
    "/diff",
    summary="Is the machine still the configuration you signed off?",
)
def diff(
    body: DiffIn,
    response: Response,
    meter: Annotated[MeterTicket, Metered("machinery_diff")],
) -> dict[str, Any]:
    """Compare an as-declared baseline against what was found on the machine.

    A version string changing while the artefact stays byte-identical is graded
    administrative; a hash changing on an item that implements a safety function
    is the finding. An item carrying no hash is reported as uncomparable — never
    as unchanged. Counted once the answer is complete (``billing/metering.py``).
    """
    baseline = _manifest(body.baseline, "baseline")
    observed = _manifest(body.observed, "observed")
    try:
        divergence = compare(baseline, observed)
    except ValueError as exc:
        raise _bad(exc, "comparison") from exc
    result = divergence.to_dict()
    meter.commit(response)
    return result


@machinery_router.post("/manifest", summary="Seal a safety software manifest")
def post_manifest(
    body: ManifestIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    manifest = _manifest(body.manifest)
    actor = _declared_actor(body)
    evidence = record_manifest(register.ledger, manifest, actor=actor)
    return {
        "content_hash": evidence.content_hash,
        "machine": manifest.machine.key,
        "manifest_id": manifest.manifest_id,
        "configuration_hash": manifest.configuration_hash(),
        "tier_ceiling": manifest.tier_ceiling.value,
        "items": len(manifest.items),
        "uncomparable_items": [i.item_id for i in manifest.uncomparable_items],
        "undemonstrable_functions": [f.function_id
                                     for f in manifest.undemonstrable_functions],
        "checks_skipped": list(evidence.checks_skipped),
    }


@machinery_router.post(
    "/enrol",
    summary="Enrol a machine: declare its identity, seal its baseline, get a receipt",
    responses={
        409: {"description": "`configuration_differs`: this key is already enrolled with a "
                             "different configuration (that is drift, not an enrolment: see "
                             "`POST /v1/machinery/diff`); `identity_conflict`: it is enrolled "
                             "with different declared attributes; `ledger_chain_unverified`. "
                             "Nothing was written. The body carries the receipt."},
        422: {"description": "`invalid_manifest`, or `invalid_enrolment`: the actor is not a "
                             "named person, or the declared site contradicts the manifest."},
    },
)
def post_enrol(
    body: EnrolIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The front door of the lifecycle: one call that makes a machine an enrolled machine.

    Idempotent: the same key with the same configuration is ``already_enrolled`` and
    writes nothing. The receipt lists what enrolment does **not** establish (not verified
    safe, no verification run yet, manifest completeness not shown, identity as declared and
    not authenticated to a physical unit). Gated exactly like ``POST /v1/machinery/manifest``.
    """
    manifest = _manifest(body.manifest)
    actor = Actor(identifier=body.actor,
                  role=sanitise_declared_role(body.role, default=""), kind="person")
    try:
        receipt = enrol_machine(register.ledger, manifest, actor=actor,
                                site=body.site, owner=body.owner)
    except EnrolmentError as exc:
        text = str(exc)
        if text.startswith("the ledger chain does not verify"):
            raise HTTPException(status_code=409, detail={
                "error": "ledger_chain_unverified", "detail": text}) from exc
        raise _bad(exc, "enrolment") from exc
    if receipt.refused:
        raise HTTPException(status_code=409, detail={
            "error": receipt.status, "detail": receipt.pointer,
            "receipt": receipt.to_dict()})
    return receipt.to_dict()


@machinery_router.post(
    "/enrol/amend",
    summary="Amend a machine's declared site or owner, as a new record",
    responses={
        409: {"description": "`not_enrolled`, `unknown_attribute` or `key_change_refused` "
                             "(the body carries the receipt), or `ledger_chain_unverified`. "
                             "Nothing was written."},
        422: {"description": "`invalid_amendment`: the actor is not a named person, the reason "
                             "is empty, or a value is empty or malformed."},
    },
)
def post_amend_enrolment(
    body: AmendEnrolmentIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Change the declared ``site`` / ``owner`` of an enrolled machine, as a new record.

    The enrolment is never rewritten: the amendment names it and the amendment before it, and
    the previous value stays in the ledger. Same values as in force write nothing
    (`no_change`). The identity remains as declared, not authenticated to a physical unit.
    Gated exactly like ``POST /v1/machinery/enrol``. No MCP tool: it is a named person's act.
    """
    actor = Actor(identifier=body.actor,
                  role=sanitise_declared_role(body.role, default=""), kind="person")
    try:
        receipt = amend_enrolment(register.ledger, body.machine, actor=actor,
                                  changes=body.changes, reason=body.reason)
    except EnrolmentError as exc:
        text = str(exc)
        if text.startswith("the ledger chain does not verify"):
            raise HTTPException(status_code=409, detail={
                "error": "ledger_chain_unverified", "detail": text}) from exc
        raise _bad(exc, "amendment") from exc
    if receipt.refused:
        raise HTTPException(status_code=409, detail={
            "error": receipt.status, "detail": receipt.pointer,
            "receipt": receipt.to_dict()})
    return receipt.to_dict()


@machinery_router.post(
    "/intervention",
    summary="Seal an intervention record",
    responses={
        409: {"description": "`unknown_machine`: no manifest is sealed under exactly this "
                             "unit key (another case, another serial, another unit, a "
                             "product line). Nothing was written."},
        422: {"description": "`invalid_intervention`, or `unknown_function`: the record names "
                             "a safety function the sealed manifest does not declare "
                             "(`unknown_functions` lists them). Nothing was written."},
    },
)
def post_intervention(
    body: InterventionIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Record a change to safety-relevant software.

    A change with no authorisation and no re-validation is recorded, not
    refused — and its findings travel with it. Refusing would push the change
    back to where it lives now, which is nowhere.

    What is refused is a change that could not be about anything the ledger holds:
    ``409 unknown_machine`` when no manifest is sealed under exactly this unit key (a key
    with another case or serial is a different unit), ``422 unknown_function`` naming any
    safety function the sealed manifest does not declare. Function ids are written back
    as the manifest spells them (``sf-1`` is ``SF-1``), and a blank list is accepted: the
    functions the manifest says the changed item implements are disturbed regardless
    (``effective_affects_functions``).
    """
    try:
        intervention = Intervention.from_dict(body.intervention)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "intervention") from exc
    actor = _declared_actor(body)
    try:
        intervention, sealed_manifest = check_intervention(register.ledger, intervention)
    except UnknownMachineError as exc:
        # 409: the request conflicts with what the ledger holds. A key that differs by
        # case or by a digit is a different unit; it is refused, never attributed.
        raise HTTPException(
            status_code=409,
            detail={"error": "unknown_machine", "detail": str(exc),
                    "machine": intervention.machine_key},
        ) from exc
    except UnknownFunctionError as exc:
        raise HTTPException(
            status_code=422,
            detail={"error": "unknown_function", "detail": str(exc),
                    "unknown_functions": list(exc.unknown)},
        ) from exc
    evidence = record_intervention(register.ledger, intervention, actor=actor)
    return {
        "content_hash": evidence.content_hash,
        "machine": intervention.machine_key,
        "intervention_id": intervention.intervention_id,
        "authorised": intervention.is_authorised,
        "revalidated": intervention.is_revalidated,
        # as the manifest spells them
        "affects_functions": list(intervention.affects_functions),
        # what coverage will treat this change as disturbing: the functions it names plus
        # those the manifest says the changed item implements
        "effective_affects_functions": sorted(
            affected_functions(sealed_manifest, intervention)),
        "findings": list(intervention.findings),
    }


@machinery_router.post(
    "/coverage",
    summary="Which safety functions a recorded verification still stands for, at what tier",
    responses={
        409: {"description": "`ledger_chain_unverified`: this account's ledger chain does not "
                             "verify, so no function is assessed. A coverage read from a "
                             "store whose records can be deleted or edited could be made to "
                             "pass. Nothing is assessed."},
    },
)
def coverage(
    body: CoverageIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The join: verification bundles against intervention records.

    A verification recorded before an intervention that touched an item
    implementing the same safety function no longer describes the machine, and
    this says so by name and by date.
    """
    manifest = _manifest(body.manifest)
    key = manifest.machine.key
    chain_ok, chain_problems = register.ledger.verify_chain()
    if not chain_ok:
        raise HTTPException(
            status_code=409,
            detail={"error": "ledger_chain_unverified",
                    "detail": "the ledger chain does not verify, so coverage was not "
                              "assessed: " + "; ".join(chain_problems[:3]),
                    "problems": chain_problems[:5]},
        )
    report = assess_coverage(
        manifest,
        VerificationRecord.from_ledger(
            register.ledger, subject=key, recorder_trust=reader_recorder_trust()),
        interventions_from_ledger(register.ledger, key),
    )
    return report.to_dict()


@machinery_router.post("/passport", summary="Seal the machine's evidence position")
def passport(
    body: PassportIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    manifest = _manifest(body.manifest)
    built = build_passport(
        register.ledger, manifest,
        actor=Actor(identifier=body.actor,
                    role=sanitise_declared_role(body.role), kind="person"),
        seal=body.seal,
        recorder_trust=reader_recorder_trust(),
    )
    payload = built.to_dict()
    payload["sealed"] = bool(body.seal)
    payload["verdict"] = built.verdict
    return payload


@machinery_router.post(
    "/passport/check",
    summary="Re-verify a machine passport. Free, permanently, for anyone.",
)
def check_passport(
    body: PassportCheckIn,
    principal: Annotated[Principal, Anyone],
) -> dict[str, Any]:
    """Check somebody else's passport without trusting them or us.

    No ledger is supplied over HTTP, so this confirms the seal and the passport's
    internal consistency and says plainly that it confirmed nothing else. Use
    ``assurance machinery check --ledger`` to check the records it names.
    """
    del principal  # free and unmetered, on purpose

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "passport.json"
        p.write_text(json.dumps(body.passport), encoding="utf-8")
        ok, problems = verify_passport(p)

    recorded = (body.passport.get("evidence") or {}).get("body") or {}
    functions = recorded.get("functions") or []
    return {
        "ok": ok,
        "problems": problems,
        "checked": {"seal": True, "internal_consistency": True,
                    "against_ledger": False},
        "machine": recorded.get("machine"),
        "recorded_verdict": recorded.get("verdict"),
        "configuration_hash": recorded.get("configuration_hash"),
        "functions_not_current": [
            {"function_id": f.get("function_id"), "coverage": f.get("coverage")}
            for f in functions if f.get("coverage") != "current"
        ],
    }
