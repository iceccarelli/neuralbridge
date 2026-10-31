"""A recorded public-intelligence store as an advisory SOURCE for the watch.

``assurance.intel`` records provenance-stamped observations of CISA KEV / NVD / EPSS /
CSAF in an append-only store. This module lets the watch READ that store, so a refreshed
public source reaches a machine. It is wired as a second kind of subscription beside the
signed supplier feeds, and it is deliberately the weaker of the two.

The pipeline is two separate steps and the watch only ever does the second::

    intel refresh --live  (or: intel ingest FILE)   # fetches / records; the only networked verb
    watch run                                       # reads the store from disk, offline

What the watch does with a candidate
------------------------------------
* **Not a supplier statement.** A candidate is an unauthenticated public record
  (``trust_basis`` ``none``, ``trust_state`` ``unauthenticated_public_source``). Every
  finding from this source is ``inspect_only``: it lists the machines the existing impact
  logic matched (``inspect_machines``) and carries NO consequence - ``machines`` is empty so
  no stop-use and no regulatory intake is drafted, ``report`` is ``None`` so the watch
  opens no case. It still counts as a finding (exit 1) when new or changed: a person has
  something to review. A case from it is opened by a named person through
  :func:`assurance.change.service.assess_advisory`, exactly like an unsigned import
  (:func:`impact_for_case` rebuilds the report that call takes).
* **Matching is the existing impact logic.** No version arithmetic is added here; whether a
  candidate matches a machine is :func:`assurance.fleet.impact.assess_impact`'s answer.
* **Enrichment is context.** KEV / EPSS / NVD / CVSS statements and NVD-vs-CSAF conflicts
  are attached to the finding with their citations and never change the verdict or the
  match. KEV "not listed" carries its "does not establish" note; EPSS with no score is
  ``unavailable``, never 0.
* **Seen / changed.** Findings are keyed by advisory id as supplier findings are; the
  advisory's content hash is remembered too, so the same observation re-read is
  ``outstanding`` (not re-announced) and changed content is ``updated``.
* **Never quiet by accident.** A store that is missing, empty, unreadable, not a store, whose
  latest observation of a series was REJECTED, that lacks a source the watch was told to
  read, or that holds payloads which cannot be re-read, degrades the run (exit 2) with the
  reason. Data from older accepted observations is still assessed, and labelled.
* **Empty fleet.** As for feeds: nothing assessed, nothing cleared - ``not_assessed``,
  degraded.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from ..core.errors import AssuranceError
from ..fleet.impact import ImpactReport, assess_impact
from ..fleet.registry import Fleet
from ..intel.store import IntelStore
from ..intel.view import Candidate, Enrichment, IntelReport, build_report
from .advisories import AdvisoryFinding, AdvisoryPass, FeedOutcome
from .config import INTEL_SOURCES, IntelSubscription

__all__ = [
    "INTEL_TRUST_BASIS",
    "INTEL_TRUST_STATE",
    "check_intel",
    "impact_for_case",
    "intel_provenance",
    "merge_passes",
]

INTEL_TRUST_STATE = "unauthenticated_public_source"
INTEL_TRUST_BASIS = "none"


def intel_provenance(source: str = "intel_store") -> dict[str, Any]:
    """The provenance an intel candidate is assessed under (never more trusted)."""
    return {
        "source": source, "trust_state": INTEL_TRUST_STATE,
        "trust_basis": INTEL_TRUST_BASIS, "signature_state": "none", "override": None,
        "inspect_only": True, "automated_consequences_permitted": False,
        "implications_reviewed": False,
    }


def _problem_outcome(sub: IntelSubscription, status: str, detail: str,
                     problems: Sequence[str] = ()) -> FeedOutcome:
    return FeedOutcome(supplier_id=sub.supplier_id, status=status, detail=detail,
                       problems=tuple(problems), trust_basis=INTEL_TRUST_BASIS)


def _open(sub: IntelSubscription) -> tuple[IntelStore | None, FeedOutcome | None]:
    """Open an EXISTING store read-only in effect. Never creates or initialises a file."""
    path = Path(sub.store)
    blind = ("The watch is blind to this source; that is not the same as the source "
             "having nothing to say.")
    if not path.is_file():
        return None, _problem_outcome(
            sub, "absent", f"intel store {path} does not exist. {blind}")
    try:
        if path.stat().st_size == 0:
            # IntelStore would initialise an empty file as a new store: refuse to write.
            return None, _problem_outcome(
                sub, "empty", f"intel store {path} is an empty file; nothing has been "
                f"recorded in it. {blind}")
        return IntelStore(path), None
    except (AssuranceError, sqlite3.Error, OSError) as exc:
        return None, _problem_outcome(
            sub, "unreadable", f"intel store {path} could not be opened: {exc}. {blind}")


def _mask(e: Enrichment, selected: set[str]) -> dict[str, Any]:
    """An enrichment as shown for this subscription: unselected sources are not claimed."""
    d = e.to_dict()
    if "cisa_kev" not in selected:
        d["kev"] = {"status": "unchecked", "note": "KEV was not among the sources this "
                    "watch was told to read"}
    if "first_epss" not in selected:
        d["epss"] = {"status": "unavailable", "score": None,
                     "note": "EPSS was not among the sources this watch was told to read; "
                             "no score is not a score of 0.0",
                     "reason": "source not selected"}
    if "nvd_cve_api" not in selected:
        d["nvd"] = {"status": "unknown", "note": "NVD was not among the sources this "
                    "watch was told to read"}
        d["cvss"] = []
    return d


def _enrichment_for(cand: Candidate, report: IntelReport,
                    selected: set[str]) -> list[dict[str, Any]]:
    aid = cand.advisory.advisory_id
    out = []
    for e in report.enrichments:
        if aid == f"nvd:{e.cve_id}" or aid in e.csaf_advisories:
            out.append(_mask(e, selected))
    return out


def _assess_store(
    sub: IntelSubscription, store: IntelStore, fleet: Fleet,
    seen: dict[str, str], seen_hashes: dict[str, str],
) -> tuple[FeedOutcome, list[AdvisoryFinding], list[str]]:
    selected = set(sub.source_ids)
    caveats: list[str] = []
    problems: list[str] = []
    status = "verified"

    try:
        everything = store.observations()
    except (AssuranceError, sqlite3.Error, OSError) as exc:
        return _problem_outcome(sub, "unreadable",
                                f"intel store {sub.store} could not be read: {exc}"), [], []
    mine = [o for o in everything if o.source in selected]
    if not everything:
        return _problem_outcome(
            sub, "empty", f"intel store {sub.store} holds no observations. Nothing has "
            "been recorded, which is not the same as nothing being published."), [], []

    series: dict[tuple[str, str], Any] = {}
    for o in mine:
        series[(o.source, o.url)] = o               # observations() is in seq order
    rejected = [o for o in series.values() if o.disposition == "rejected"]
    for o in rejected:
        problems.append(
            f"latest observation #{o.seq} of {o.source} ({o.url or 'no url'}) was REJECTED: "
            f"{o.reason or 'no reason recorded'}. Anything older in the store is stale.")
    recorded = {o.source for o in mine}
    absent = [s for s in sub.sources if INTEL_SOURCES[s] not in recorded]
    for s in absent:
        problems.append(f"no observation of source '{s}' has been recorded, though this "
                        "watch was told to read it.")
    if rejected:
        status = "rejected_latest"
    elif absent or not mine:
        status = "incomplete"

    try:
        report = build_report(store)
    except (AssuranceError, sqlite3.Error, OSError) as exc:
        return _problem_outcome(sub, "unreadable",
                                f"intel store {sub.store} could not be assessed: {exc}",
                                problems), [], []
    if report.unreadable:
        problems.append("stored payload(s) could not be re-read: observation(s) "
                        + ", ".join(str(n) for n in report.unreadable))
        if status == "verified":
            status = "unreadable"

    findings: list[AdvisoryFinding] = []
    new_ids: list[str] = []
    unassessed: list[str] = []
    cleared = 0
    not_represented = 0
    for cand in report.candidates:
        if cand.source not in selected:
            continue
        adv = cand.advisory
        impact = assess_impact(adv, fleet, provenance=intel_provenance())
        ch = adv.content_hash()
        if cand.not_representable:
            not_represented += 1
        base: dict[str, Any] = {
            "advisory_id": adv.advisory_id, "supplier_id": sub.supplier_id,
            "severity": adv.severity.value, "title": adv.title, "remedy": adv.remedy,
            "reference": adv.reference, "impact": impact.verdict, "machines": (),
            "functions_in_question": (), "trust_basis": INTEL_TRUST_BASIS,
            "trust_state": INTEL_TRUST_STATE, "inspect_only": True, "content_hash": ch,
            "inspect_machines": tuple(impact.machines_affected), "report": None}
        if impact.verdict == "clear":
            if impact.machines_in_fleet == 0:
                unassessed.append(adv.advisory_id)
                findings.append(AdvisoryFinding(
                    **{**base, "impact": "not_assessed", "inspect_machines": ()},
                    state="not_assessed"))
            else:
                cleared += 1
            continue
        if adv.advisory_id not in seen:
            state = "new"
            new_ids.append(adv.advisory_id)
        elif seen_hashes.get(adv.advisory_id, ch) != ch:
            state = "updated"
        else:
            state = "outstanding"
        findings.append(AdvisoryFinding(
            **base, state=state, intel={
                "source": cand.source, "citation": cand.citation,
                "notes": list(cand.notes),
                "not_representable": list(cand.not_representable),
                "enrichment": _enrichment_for(cand, report, selected),
                "enrichment_note": "context only: KEV, EPSS, NVD and CVSS did not change "
                                   "this finding's match or verdict",
            }))

    if cleared:
        caveats.append(
            f"{sub.supplier_id}: {cleared} public-source candidate(s) matched nothing in "
            "this fleet's latest sealed manifests. That is what these candidates said, not "
            "that the fleet is unaffected: NVD names components by CPE strings that match "
            "a manifest only if it uses the same labels, and a bounded version range is "
            "not matched at all.")
    if not_represented:
        caveats.append(
            f"{sub.supplier_id}: {not_represented} candidate(s) carry version ranges or "
            "conditions the advisory model cannot represent; they are kept as text and "
            "were NOT matched against machines.")
    kev_unlisted = [e for e in report.enrichments if e.kev.get("status") == "not_listed_in_kev"]
    if "cisa_kev" in selected and kev_unlisted:
        caveats.append(
            f"{sub.supplier_id}: {len(kev_unlisted)} CVE(s) are not listed in KEV. "
            + next(iter(kev_unlisted)).kev["not_established"] + ".")
    if "cisa_kev" in selected and any(e.kev.get("status") == "unchecked"
                                      for e in report.enrichments):
        caveats.append(f"{sub.supplier_id}: no KEV catalogue is recorded, so KEV status is "
                       "unchecked, not 'not listed'.")
    epss_missing = [e for e in report.enrichments if e.epss.get("status") == "unavailable"]
    if "first_epss" in selected and epss_missing:
        caveats.append(
            f"{sub.supplier_id}: EPSS is unavailable for {len(epss_missing)} CVE(s); that "
            "is an unknown probability, not a score of 0.0.")
    if report.conflicts:
        caveats.append(f"{sub.supplier_id}: {len(report.conflicts)} NVD-versus-vendor "
                       "conflict(s) are carried on the findings; neither source is preferred.")
    caveats.append(
        f"{sub.supplier_id}: candidates come from an unauthenticated public-source store "
        "read offline; they are shown for human review and cause no stop-use, no intake and "
        "no automatic case. This watch never refreshes the store: run `intel refresh --live` "
        "(or `intel ingest`) first.")

    detail = (f"{len(report.candidates)} candidate(s) read from {sub.store}" if status ==
              "verified" else "; ".join(problems))
    outcome = FeedOutcome(
        supplier_id=sub.supplier_id, status=status, records=len(mine), new=tuple(new_ids),
        problems=tuple(problems), detail=detail, cleared=cleared,
        not_assessed=tuple(unassessed), trust_basis=INTEL_TRUST_BASIS,
        trust={"trust_state": INTEL_TRUST_STATE, "inspect_only": True,
               "sources": list(sub.sources)})
    return outcome, findings, caveats


def check_intel(
    subscriptions: Sequence[IntelSubscription], fleet: Fleet, *,
    previously_seen: dict[str, str] | None = None,
    previous_hashes: dict[str, str] | None = None,
) -> AdvisoryPass:
    """Read every subscribed intel store, offline, and say what is new for this fleet."""
    seen = {k: v for k, v in (previously_seen or {}).items() if v != "not_assessed"}
    hashes = dict(previous_hashes or {})
    outcomes: list[FeedOutcome] = []
    findings: list[AdvisoryFinding] = []
    caveats: list[str] = []
    for sub in subscriptions:
        store, failure = _open(sub)
        if failure is not None or store is None:
            assert failure is not None
            outcomes.append(failure)
            continue
        outcome, found, notes = _assess_store(sub, store, fleet, seen, hashes)
        outcomes.append(outcome)
        findings.extend(found)
        caveats.extend(notes)
    return AdvisoryPass(feeds=tuple(outcomes), findings=tuple(findings),
                        checks_skipped=tuple(dict.fromkeys(caveats)))


def merge_passes(*passes: AdvisoryPass) -> AdvisoryPass:
    """Combine the signed-feed pass and the intel-store pass into one."""
    return AdvisoryPass(
        feeds=tuple(f for p in passes for f in p.feeds),
        findings=tuple(f for p in passes for f in p.findings),
        checks_skipped=tuple(dict.fromkeys(c for p in passes for c in p.checks_skipped)))


def impact_for_case(sub: IntelSubscription, advisory_id: str, fleet: Fleet) -> ImpactReport:
    """The report a NAMED PERSON hands to ``assess_advisory`` to open a case from a finding.

    Carries the inspect-only provenance, so the change service refuses anyone who is not a
    named person (and, for a CSAF import, requires the unsigned-import override and reason).
    """
    store, failure = _open(sub)
    if store is None:
        raise AssuranceError(failure.detail if failure else "intel store unavailable")
    for cand in build_report(store).candidates:
        if cand.advisory.advisory_id == advisory_id and cand.source in sub.source_ids:
            return assess_impact(cand.advisory, fleet, provenance=intel_provenance())
    raise AssuranceError(f"no intel candidate {advisory_id!r} in {sub.store}")

