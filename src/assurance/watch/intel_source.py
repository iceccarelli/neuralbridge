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
* **Staleness (optional).** With ``max_age_hours`` on the subscription, each selected source's
  newest ACCEPTED observation must have been retrieved within that many hours of the run's
  clock (the recorded ``retrieved_at``, never the feed's own stamp); otherwise, or with no
  accepted observation, the feed is ``stale`` (DEGRADED). Without it, the run says that age
  was NOT checked. A rejected latest observation keeps status ``rejected_latest``.
* **Empty fleet.** As for feeds: nothing assessed, nothing cleared - ``not_assessed``,
  degraded.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from ..core.errors import AssuranceError
from ..core.identity import format_utc, parse_utc, utc_now
from ..fleet.impact import ImpactReport, assess_impact
from ..fleet.registry import Fleet
from ..intel.store import IntelStore
from ..intel.view import Candidate, Enrichment, IntelReport, build_report
from .advisories import AdvisoryFinding, AdvisoryPass, FeedOutcome
from .config import INTEL_SOURCES, IntelSubscription

__all__ = [
    "INTEL_TRUST_BASIS",
    "INTEL_TRUST_STATE",
    "SourceAge",
    "StoreAges",
    "check_intel",
    "impact_and_candidate_from_store",
    "impact_for_case",
    "intel_provenance",
    "merge_passes",
    "source_ages",
    "store_ages",
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


@dataclass(frozen=True)
class SourceAge:
    """How old one selected source's newest ACCEPTED observation is, against the limit.

    ``state``: ``fresh`` | ``stale`` | ``never_observed`` (no accepted observation) |
    ``unreadable`` (its recorded retrieval time cannot be read) | ``future`` (retrieved after
    the clock, so no age can be established). Everything but ``fresh`` is a problem, and
    ``message`` is the run's own wording for it (empty when fresh).
    """

    source: str
    state: str
    limit_hours: float
    retrieved_at: str = ""
    seq: int | None = None
    age_hours: float | None = None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.state == "fresh"

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "state": self.state, "limit_hours": self.limit_hours,
                "retrieved_at": self.retrieved_at, "seq": self.seq,
                "age_hours": None if self.age_hours is None else round(self.age_hours, 3),
                "message": self.message}


def source_ages(sub: IntelSubscription, mine: Sequence[Any], now: datetime) -> list[SourceAge]:
    """One :class:`SourceAge` per selected source; empty when ``max_age_hours`` is not set.

    Age is the clock minus the observation's recorded ``retrieved_at`` (when the store
    fetched or ingested it). The feed's own self-declared stamp is never the clock: a stale
    mirror can carry a fresh date. This is the ONE place the rule lives: the runner
    (:func:`_staleness`) and ``watch status`` / ``watch open-case`` all call it.
    """
    limit = sub.max_age_hours
    if limit is None:
        return []
    out: list[SourceAge] = []
    for name in sub.sources:
        source = INTEL_SOURCES[name]
        accepted = [o for o in mine if o.source == source and o.accepted]
        if not accepted:
            out.append(SourceAge(name, "never_observed", limit, message=(
                f"STALE: source '{name}' has no accepted observation in the store, so its "
                f"age cannot be established against the {limit:g} h limit.")))
            continue
        newest = max(accepted, key=lambda o: o.seq)
        try:
            age_h = (now - parse_utc(newest.retrieved_at)).total_seconds() / 3600
        except ValueError:
            out.append(SourceAge(name, "unreadable", limit, newest.retrieved_at, newest.seq,
                                 message=(
                f"STALE: source '{name}': the recorded retrieval time "
                f"{newest.retrieved_at!r} of observation #{newest.seq} cannot be read, "
                "so its age cannot be established.")))
            continue
        if age_h < 0:
            out.append(SourceAge(name, "future", limit, newest.retrieved_at, newest.seq,
                                 age_h, message=(
                f"STALE: source '{name}': last accepted retrieval {newest.retrieved_at} is "
                f"after this run's clock ({format_utc(now)}); its age cannot be established.")))
        elif age_h > limit:
            out.append(SourceAge(name, "stale", limit, newest.retrieved_at, newest.seq,
                                 age_h, message=(
                f"STALE: source '{name}' was last accepted (retrieved) at "
                f"{newest.retrieved_at}, {age_h:.1f} h before this run; the limit is "
                f"{limit:g} h. A refresh may have stopped; what is read below is that old.")))
        else:
            out.append(SourceAge(name, "fresh", limit, newest.retrieved_at, newest.seq, age_h))
    return out


def _staleness(sub: IntelSubscription, mine: Sequence[Any], now: datetime) -> list[str]:
    """One problem per selected source whose newest ACCEPTED observation is too old or absent."""
    return [a.message for a in source_ages(sub, mine, now) if not a.ok]


@dataclass(frozen=True)
class StoreAges:
    """What ``watch status`` / ``open-case`` say about one subscription's age."""

    supplier_id: str
    store: str
    #: ``max_age_hours`` is set; when False, ``ages`` is empty and age was NOT checked.
    checked: bool
    limit_hours: float | None
    #: Set when the store itself cannot be read (absent / empty / unreadable): the runner's
    #: own status word and wording for that, so no age can be shown.
    problem_status: str = ""
    problem: str = ""
    ages: tuple[SourceAge, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.problem and all(a.ok for a in self.ages)

    def to_dict(self) -> dict[str, Any]:
        return {"supplier_id": self.supplier_id, "store": self.store,
                "age_checked": self.checked, "limit_hours": self.limit_hours,
                "store_status": self.problem_status, "store_problem": self.problem,
                "sources": [a.to_dict() for a in self.ages], "ok": self.ok}


def store_ages(sub: IntelSubscription, now: datetime) -> StoreAges:
    """The age of each selected source of ``sub``'s store at ``now``. Reads only; no network."""
    base: dict[str, Any] = {
        "supplier_id": sub.supplier_id, "store": sub.store,
        "checked": sub.max_age_hours is not None, "limit_hours": sub.max_age_hours}
    store, failure = _open(sub)
    if store is None:
        assert failure is not None
        return StoreAges(**base, problem_status=failure.status, problem=failure.detail)
    try:
        everything = store.observations()
    except (AssuranceError, sqlite3.Error, OSError) as exc:
        return StoreAges(**base, problem_status="unreadable", problem=(
            f"intel store {sub.store} could not be read: {exc}"))
    if not everything:
        return StoreAges(**base, problem_status="empty", problem=(
            f"intel store {sub.store} holds no observations. Nothing has been recorded, "
            "which is not the same as nothing being published."))
    selected = set(sub.source_ids)
    mine = [o for o in everything if o.source in selected]
    return StoreAges(**base, ages=tuple(source_ages(sub, mine, now)))


def _assess_store(
    sub: IntelSubscription, store: IntelStore, fleet: Fleet,
    seen: dict[str, str], seen_hashes: dict[str, str], now: datetime,
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
    stale = _staleness(sub, mine, now)
    problems.extend(stale)
    if rejected:
        status = "rejected_latest"
    elif stale:
        status = "stale"
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
    now: datetime | None = None,
) -> AdvisoryPass:
    """Read every subscribed intel store, offline, and say what is new for this fleet.

    ``now`` is the run's clock (the runner passes its own, so a run is deterministic); it is
    used only to judge staleness, and only for subscriptions that set ``max_age_hours``.
    """
    clock = now if now is not None else utc_now()
    seen = {k: v for k, v in (previously_seen or {}).items() if v != "not_assessed"}
    hashes = dict(previous_hashes or {})
    outcomes: list[FeedOutcome] = []
    findings: list[AdvisoryFinding] = []
    caveats: list[str] = []
    for sub in subscriptions:
        if sub.max_age_hours is None:
            caveats.append(
                f"{sub.supplier_id}: the age of the intel store was NOT checked (no "
                "max_age_hours is set). A refresh job that silently stopped looks the same "
                "as a quiet week.")
        else:
            caveats.append(
                f"{sub.supplier_id}: store age is the run's clock minus the recorded "
                "retrieval time of each selected source's newest accepted observation "
                f"(limit {sub.max_age_hours:g} h). A recent retrieval says the store was "
                "refreshed, not that the source had nothing newer.")
        store, failure = _open(sub)
        if failure is not None or store is None:
            assert failure is not None
            outcomes.append(failure)
            continue
        outcome, found, notes = _assess_store(sub, store, fleet, seen, hashes, clock)
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


def impact_and_candidate_from_store(
    store: IntelStore, advisory_id: str, fleet: Fleet, source_ids: Sequence[str],
) -> tuple[ImpactReport, Candidate]:
    """The inspect-only impact report (and the candidate it came from) for one advisory id.

    The one place a candidate is looked up and matched against a fleet for a person opening a
    case: the CLI (:func:`impact_for_case`) and the hosted route both call it, over a store
    each opened their own way. Matching is :func:`assess_impact`; nothing is added here.
    """
    for cand in build_report(store).candidates:
        if cand.advisory.advisory_id == advisory_id and cand.source in source_ids:
            return assess_impact(cand.advisory, fleet, provenance=intel_provenance()), cand
    raise AssuranceError(f"no intel candidate {advisory_id!r} in the recorded observations")


def impact_for_case(sub: IntelSubscription, advisory_id: str, fleet: Fleet) -> ImpactReport:
    """The report a NAMED PERSON hands to ``assess_advisory`` to open a case from a finding.

    Carries the inspect-only provenance, so the change service refuses anyone who is not a
    named person (and, for a CSAF import, requires the unsigned-import override and reason).
    """
    store, failure = _open(sub)
    if store is None:
        raise AssuranceError(failure.detail if failure else "intel store unavailable")
    try:
        return impact_and_candidate_from_store(store, advisory_id, fleet, sub.source_ids)[0]
    except AssuranceError as exc:
        if str(exc).startswith("no intel candidate"):
            raise AssuranceError(f"no intel candidate {advisory_id!r} in {sub.store}") from exc
        raise
