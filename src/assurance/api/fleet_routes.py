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
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Anyone, Machine, Metered, MeterTicket, get_register
from assurance.api.recorder_trust import reader_recorder_trust
from assurance.billing.accounts import Principal
from assurance.core.errors import AssuranceError
from assurance.fleet.advisory import ComponentAdvisory, match_item
from assurance.fleet.declaration import DeclarationOfConformity, check_declaration
from assurance.fleet.impact import advisory_provenance, assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord, assess_coverage
from assurance.supplier.trust import TRUST_STATEMENT, SupplierTrustStore, evaluate_feed

__all__ = ["fleet_router"]

fleet_router = APIRouter(prefix="/v1/fleet", tags=["fleet"])


class AdvisoryCheckIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisory: dict[str, Any]
    manifest: dict[str, Any]


class AdvisoryIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    advisory: dict[str, Any]


class SignedFeedIn(BaseModel):
    """The feed fields shared by every route that judges a feed under the account's pins."""

    model_config = ConfigDict(extra="forbid")

    feed: str = Field(default="", max_length=4 * 1024 * 1024)
    hosted_feed_id: str = Field(default="", max_length=128)
    expect_supplier: str = Field(default="", max_length=200)
    candidate_public_key_pem: str = Field(default="", max_length=4096)


class SignedAdvisoryIn(SignedFeedIn):
    """A supplier feed to assess against the fleet, under the account's pinned keys."""

    #: Limit to these advisory ids. Empty: every standing advisory.
    advisory_ids: list[str] = []


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
def advisory_check(
    body: AdvisoryCheckIn,
    response: Response,
    meter: Annotated[MeterTicket, Metered("advisory_check")],
) -> dict[str, Any]:
    """One advisory, one manifest, no account.

    The match basis is always reported. ``hash`` settles it; ``version`` rests on
    a label, and this system has already shown a label can be wrong;
    ``hash_mismatch`` means the machine's own label and artefact disagree against
    the supplier's published figures, which is neither affected nor clear.
    Counted once the answer is complete (``billing/metering.py``).
    """
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
    record = advisory.import_record
    if record is not None:
        skipped.append(
            "this advisory is an unsigned CSAF import: nobody has authenticated it.")
        if record.partial:
            skipped.append(
                "this advisory is a PARTIAL translation (not imported: "
                + (", ".join(record.dropped_ids) or "; ".join(record.partial_reasons))
                + "), so 'not affected' here is not a statement that nothing is affected.")
    unhashed = [i.item_id for i in manifest.uncomparable_items]
    if unhashed:
        skipped.append(
            "item(s) " + ", ".join(unhashed) + " carry no hash, so an affected "
            "component hiding in them would not be found.")

    result = {
        "advisory_id": advisory.advisory_id,
        "issued_by": advisory.issued_by,
        "severity": advisory.severity.value,
        "reference": advisory.reference,
        "machine": manifest.machine.key,
        "affected": bool(matches),
        "matches": matches,
        "remedy": advisory.remedy,
        "checks_skipped": skipped,
        "provenance": advisory_provenance(advisory, _BARE_ADVISORY),
        "advisory_import": record.to_dict() if record is not None else None,
        "incomplete": bool(record is not None and record.partial),
    }
    meter.commit(response)
    return result


@fleet_router.get("/machines", summary="Every enrolled machine, worst coverage first")
def machines(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    return Fleet.from_ledger(register.ledger, recorder_trust=reader_recorder_trust()).to_dict()


@fleet_router.get(
    "/observations",
    summary="When was each machine last looked at, and did the last attempt work?",
)
def observations(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Per machine: last successful observation, last attempt, staleness, open cases.

    Reads the ``watch.observation`` records in the caller's own ledger, which
    are there only because the account holder reported them
    (``POST /v1/watch/report``). A failed attempt is never a positive one, and
    a machine is stale once its last *successful* observation is older than the
    cadence the customer declared. Nothing is derived here that Watch did not
    already record.
    """
    from assurance.watch.observations import fleet_observations

    return fleet_observations(register.ledger)


@fleet_router.post(
    "/advisory",
    summary="Which of your machines does this advisory touch?",
)
def advisory_impact(
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
    fleet = Fleet.from_ledger(register.ledger, recorder_trust=reader_recorder_trust())
    return assess_impact(advisory, fleet, provenance=_BARE_ADVISORY).to_dict()


#: An advisory handed over as a JSON body has no signature to check and no key to
#: pin. It can be assessed; it is not a trusted supplier statement.
_BARE_ADVISORY = {
    "source": "request_body", "trust_state": "unauthenticated_input",
    "trust_basis": "none", "signature_state": "none",
    "automated_consequences_permitted": False, "inspect_only": True,
    "override": None, "implications_reviewed": False,
    "trust_statement": TRUST_STATEMENT,
}


def evaluate_signed_feed(
    body: SignedFeedIn, principal: Principal, register: Any,
) -> tuple[list[Any], Any, str]:
    """Judge a feed under the *account's* pinned keys: ``(records, trust, error)``.

    The one place a signed feed is evaluated for a route: the fleet fan-out and the case
    route both call it, so they can never disagree about trust. An unreadable feed returns
    ``error`` (and no trust). The operator's shared ledger holds no pins, so an operator
    sees every feed as untrusted.
    """
    from assurance.api.supplier_routes import EvaluateIn, _candidate, load_feed_records

    account = principal.account
    store = (SupplierTrustStore(register.ledger)
             if account is not None and account.id != "operator" else None)
    records, error = load_feed_records(EvaluateIn(
        feed=body.feed, hosted_feed_id=body.hosted_feed_id,
        expect_supplier=body.expect_supplier,
        candidate_public_key_pem=body.candidate_public_key_pem))
    if error:
        return [], None, error
    trust = evaluate_feed(records, store, expect_supplier=body.expect_supplier,
                          candidate_key=_candidate(body.candidate_public_key_pem))
    return records, trust, ""


@fleet_router.post(
    "/advisory/signed",
    summary="Assess a signed supplier feed against your fleet, with its trust state",
)
def advisory_impact_signed(
    body: SignedAdvisoryIn,
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """The fan-out for a feed, under the account's pinned keys.

    Every advisory is assessed so an operator can inspect it, and each carries
    its own trust basis. An advisory that does not meet the policy has
    ``automated_consequences_permitted: false`` and a report marked
    ``inspect_only``: it must not drive stop-use or open a case as a trusted
    supplier statement. The pin store is the account's own; the operator's
    shared ledger holds none, so an operator sees every feed as untrusted.

    ``trust`` keeps readable / signature / key / chain apart. A signed advisory
    proves who signed the bytes, not that the advisory is correct, complete or
    timely.
    """
    from assurance.api.supplier_routes import unreadable_payload

    records, trust, error = evaluate_signed_feed(body, principal, register)
    if error or trust is None:
        return {"trust": unreadable_payload(error), "advisories": [],
                "inspect_only": True, "trust_statement": TRUST_STATEMENT}
    first = {r.advisory_id: r for r in records if not r.is_withdrawal}
    fleet = Fleet.from_ledger(register.ledger, recorder_trust=reader_recorder_trust())
    out: list[dict[str, Any]] = []
    for row in trust.advisories:
        aid = row["advisory_id"]
        if body.advisory_ids and aid not in body.advisory_ids:
            continue
        try:
            advisory = first[aid].component()
        except (AssuranceError, KeyError, ValueError, TypeError) as exc:
            out.append({**row, "impact": None, "error": f"unreadable advisory: {exc}"})
            continue
        prov = trust.provenance_for(aid)
        entry = {**row, "impact": assess_impact(
            advisory, fleet, provenance=prov).to_dict()}
        if advisory.import_record is not None:
            # The signature is over the supplier's file; the file says it is a translation
            # nobody has authenticated. A pinned key does not turn that into a statement
            # the supplier made, so no consequence is permitted whatever the policy says.
            entry.update(automated_consequences_permitted=False, inspect_only=True,
                         advisory_import=advisory.import_record.to_dict())
        out.append(entry)
    inspect_only = (trust.inspect_only if not out else
                    not any(r.get("automated_consequences_permitted") for r in out))
    return {"trust": trust.to_dict(), "advisories": out,
            "inspect_only": inspect_only, "trust_statement": TRUST_STATEMENT}


@fleet_router.get(
    "/report",
    response_class=HTMLResponse,
    summary="The whole fleet on one page a plant manager can read",
)
def report(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
    organisation: str = "",
    prepared_by: str = "",
) -> HTMLResponse:
    """One self-contained HTML page: no network, no scripts, and it prints.

    Every other output here is JSON or terminal text, which means the only
    people who ever see it are engineers. This is the surface for everyone who
    signs the cheque — and it carries every ``checks_skipped`` line verbatim,
    because a report that hides its own limits is worth less than no report.
    """
    from assurance.report.render import ReportInput, render_report

    return HTMLResponse(render_report(ReportInput(
        ledger=register.ledger,
        organisation=organisation[:200],
        prepared_by=prepared_by[:200],
        recorder_trust=reader_recorder_trust(),
    )))


@fleet_router.post("/declare", summary="Bind a declaration to a configuration")
def declare(
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
def declaration_check(
    body: DeclarationCheckIn,
    principal: Annotated[Principal, Anyone],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Free, because the person who most needs this is the buyer, not the seller.

    Whether a changed configuration amounts to a substantial modification is a
    question for the manufacturer and their notified body. What this settles is
    the fact that question rests on.

    ``verdict`` is ``describes_the_machine`` only when the configuration is the declared
    one AND the evidence was assessed (``evidence_assessed: true``: the caller has a plan
    that reads its ledger and asked for ``with_coverage``) and every declared safety
    function is current at ``validated`` or better. Without that, the answer is
    ``configuration_matches_coverage_not_assessed`` (the evidence was not looked at; this is
    the default for an anonymous caller) or
    ``configuration_intact_evidence_below_validated``: neither is a pass.
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
            VerificationRecord.from_ledger(
                register.ledger, subject=key, recorder_trust=reader_recorder_trust()),
            interventions_from_ledger(register.ledger, key),
        )

    status = check_declaration(declaration, manifest, coverage)
    payload = status.to_dict()
    # `coverage_assessed` is whether any evidence was actually assessed, not whether a
    # report object existed: a report over zero functions assesses nothing.
    payload["coverage_assessed"] = status.evidence_assessed
    if body.with_coverage and coverage is None:
        payload["checks_skipped"] = [
            "coverage was requested and not assessed: reading the evidence ledger "
            "needs a plan that includes machine verification. The configuration "
            "comparison above is unaffected.",
            *payload["checks_skipped"],
        ]
    return payload
