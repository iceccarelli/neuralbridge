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

from assurance.api.deps import Anyone, Machine, get_accounts, get_register, spend
from assurance.billing.accounts import AccountStore, Principal
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.machinery.divergence import compare
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import (
    build_passport,
    interventions_from_ledger,
    record_intervention,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import VerificationRecord, assess_coverage

__all__ = ["machinery_router"]

machinery_router = APIRouter(prefix="/v1/machinery", tags=["machinery"])

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
async def diff(
    body: DiffIn,
    response: Response,
    principal: Annotated[Principal, Anyone],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """Compare an as-declared baseline against what was found on the machine.

    A version string changing while the artefact stays byte-identical is graded
    administrative; a hash changing on an item that implements a safety function
    is the finding. An item carrying no hash is reported as uncomparable — never
    as unchanged.
    """
    limit = principal.plan.diffs_per_day
    spend(principal, "machinery_diff", limit, accounts)
    response.headers["X-Assurance-Tier"] = principal.tier
    if limit is not None:
        used = accounts.usage_today(principal.subject).get("machinery_diff", 0)
        response.headers["X-Assurance-Quota-Limit"] = str(limit)
        response.headers["X-Assurance-Quota-Remaining"] = str(max(0, limit - used))

    baseline = _manifest(body.baseline, "baseline")
    observed = _manifest(body.observed, "observed")
    try:
        divergence = compare(baseline, observed)
    except ValueError as exc:
        raise _bad(exc, "comparison") from exc
    return divergence.to_dict()


@machinery_router.post("/manifest", summary="Seal a safety software manifest")
async def post_manifest(
    body: ManifestIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    manifest = _manifest(body.manifest)
    actor = (Actor(identifier=body.actor, role=body.role, kind="person")
             if body.actor else None)
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


@machinery_router.post("/intervention", summary="Seal an intervention record")
async def post_intervention(
    body: InterventionIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Record a change to safety-relevant software.

    A change with no authorisation and no re-validation is recorded, not
    refused — and its findings travel with it. Refusing would push the change
    back to where it lives now, which is nowhere.
    """
    try:
        intervention = Intervention.from_dict(body.intervention)
    except (AssuranceError, KeyError, ValueError, TypeError) as exc:
        raise _bad(exc, "intervention") from exc
    actor = (Actor(identifier=body.actor, role=body.role, kind="person")
             if body.actor else None)
    evidence = record_intervention(register.ledger, intervention, actor=actor)
    return {
        "content_hash": evidence.content_hash,
        "machine": intervention.machine_key,
        "intervention_id": intervention.intervention_id,
        "authorised": intervention.is_authorised,
        "revalidated": intervention.is_revalidated,
        "affects_functions": list(intervention.affects_functions),
        "findings": list(intervention.findings),
    }


@machinery_router.post(
    "/coverage",
    summary="Which safety functions still have valid evidence",
)
async def coverage(
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
    report = assess_coverage(
        manifest,
        VerificationRecord.from_ledger(register.ledger, subject=key),
        interventions_from_ledger(register.ledger, key),
    )
    return report.to_dict()


@machinery_router.post("/passport", summary="Seal the machine's evidence position")
async def passport(
    body: PassportIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    manifest = _manifest(body.manifest)
    built = build_passport(
        register.ledger, manifest,
        actor=Actor(identifier=body.actor, role=body.role, kind="person"),
        seal=body.seal,
    )
    payload = built.to_dict()
    payload["sealed"] = bool(body.seal)
    payload["verdict"] = built.verdict
    return payload


@machinery_router.post(
    "/passport/check",
    summary="Re-verify a machine passport. Free, permanently, for anyone.",
)
async def check_passport(
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
