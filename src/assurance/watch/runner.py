"""The thing that runs when nobody is looking.

Everything else in this package is invoked by a person who already suspects
something. A watch is what turns that into a subscription: it looks every week
whether or not anybody suspects anything, and it is the only component that can
find a change on the day it happened rather than the day somebody remembered.

Four decisions make the difference between a watch that gets read and a watch
that gets filtered to a folder.

**Seal only on change, but record every look.** A weekly watch over forty
machines that sealed forty identical manifests would add two thousand records a
year saying nothing, and the real changes would drown. But a ledger with no
record at all cannot tell "we looked and it was the same" from "we never looked"
— and those are opposite facts. So every run seals one lightweight observation
naming what was seen, and a full manifest only when the configuration actually
moved.

**New is not the same as outstanding.** A watch that reports the same stale
function every week trains its reader to skim. Each run diffs against the last,
and the findings it leads with are the ones that appeared since.

**A machine that could not be collected is not unchanged.** A missing export
folder is an absence of observation, not an observation of absence, and it is
reported in its own column.

**Silence expires.** A watch that stopped running looks exactly like a fleet
that stopped changing, and the second is the comfortable reading.
:attr:`WatchRun.stale_observations` names every machine whose last look is older
than the cadence the watch declared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from assurance.collect.collector import CollectionError, collect
from assurance.collect.plan import CollectionPlan
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    Origin,
    ValidationState,
)
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.machinery.divergence import Severity, compare
from assurance.machinery.manifest import ManifestSource
from assurance.machinery.record import (
    interventions_from_ledger,
    manifests_from_ledger,
    record_divergence,
    record_manifest,
)
from assurance.machinery.staleness import (
    Coverage,
    VerificationRecord,
    assess_coverage,
)
from assurance.watch.advisories import AdvisoryPass, check_feeds
from assurance.watch.config import WatchConfig, WatchTarget
from assurance.watch.filings import FilingsPass, draft_filings

__all__ = [
    "OBSERVATION_KIND",
    "RUN_KIND",
    "MachineOutcome",
    "WatchRun",
    "last_run",
    "run_watch",
]

OBSERVATION_KIND = "watch.observation"
RUN_KIND = "watch.run"
RUN_SCHEMA = "assurance.watch.run/1"


@dataclass(frozen=True)
class MachineOutcome:
    """What one look at one machine found."""

    serial: str
    machine_key: str
    #: observed | changed | uncollectable | first_seen
    status: str
    configuration_hash: str = ""
    previous_configuration: str = ""
    #: Safety functions that stopped being current since the last run.
    newly_uncovered: tuple[str, ...] = ()
    #: Functions not current now and not current last time either.
    still_uncovered: tuple[str, ...] = ()
    #: Functions that came back since the last run.
    recovered: tuple[str, ...] = ()
    #: Set when the observed configuration differs from the last sealed one.
    drift_severity: str = ""
    drift_items: tuple[str, ...] = ()
    affected_functions: tuple[str, ...] = ()
    detail: str = ""
    warnings: tuple[str, ...] = ()

    @property
    def is_finding(self) -> bool:
        """Whether a person needs to look at this machine because of this run."""
        return (self.status in ("changed", "uncollectable")
                or bool(self.newly_uncovered))

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial, "machine": self.machine_key,
            "status": self.status,
            "configuration_hash": self.configuration_hash,
            "previous_configuration": self.previous_configuration,
            "newly_uncovered": list(self.newly_uncovered),
            "still_uncovered": list(self.still_uncovered),
            "recovered": list(self.recovered),
            "drift_severity": self.drift_severity,
            "drift_items": list(self.drift_items),
            "affected_functions": list(self.affected_functions),
            "detail": self.detail,
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class WatchRun:
    """One pass of the watch, and what it changed about what anybody knows."""

    watch_id: str
    config_hash: str
    started_at: str
    finished_at: str
    outcomes: tuple[MachineOutcome, ...]
    #: Machines whose most recent observation is older than the declared cadence.
    stale_observations: tuple[str, ...]
    #: What the subscribed supplier feeds said. Empty when none are subscribed.
    advisories: AdvisoryPass = field(default_factory=AdvisoryPass)
    #: Article 14 intakes drafted, and signals still awaiting an assessment.
    filings: FilingsPass = field(default_factory=FilingsPass)
    previous_run_hash: str = ""
    checks_skipped: tuple[str, ...] = field(default_factory=tuple)
    sealed: tuple[str, ...] = field(default_factory=tuple)

    @property
    def findings(self) -> tuple[MachineOutcome, ...]:
        return tuple(o for o in self.outcomes if o.is_finding)

    @property
    def changed(self) -> tuple[MachineOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "changed")

    @property
    def uncollectable(self) -> tuple[MachineOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "uncollectable")

    @property
    def verdict(self) -> str:
        """``quiet`` | ``findings`` | ``degraded``.

        A feed that could not be checked degrades the run exactly as a machine
        that could not be collected does. Being blind to a supplier and hearing
        nothing from one are different states, and the exit code has to say so:
        otherwise a sync that quietly stopped reads as a quiet month.
        """
        if self.uncollectable or self.stale_observations \
                or self.advisories.degraded:
            return "degraded"
        if self.findings or self.advisories.is_finding or self.filings.is_finding:
            return "findings"
        return "quiet"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": RUN_SCHEMA,
            "watch_id": self.watch_id,
            "config_hash": self.config_hash,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "previous_run_hash": self.previous_run_hash,
            "verdict": self.verdict,
            "machines": len(self.outcomes),
            "outcomes": [o.to_dict() for o in self.outcomes],
            "stale_observations": list(self.stale_observations),
            "advisories": self.advisories.to_dict(),
            "filings": self.filings.to_dict(),
            "sealed": list(self.sealed),
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        head = {
            "quiet": "QUIET — every machine was looked at and nothing moved",
            "findings": "FINDINGS — something changed since the last run",
            "degraded": "DEGRADED — the watch could not see part of the fleet",
        }[self.verdict]
        lines = [f"{self.watch_id} — {head}",
                 f"  {self.started_at} → {self.finished_at}  "
                 f"{len(self.outcomes)} machine(s)"]
        mark = {"changed": "DRIFT", "uncollectable": "BLIND", "first_seen": "NEW  ",
                "observed": "ok   "}
        order = {"uncollectable": 0, "changed": 1, "first_seen": 2, "observed": 3}
        for o in sorted(self.outcomes, key=lambda o: (order[o.status], o.serial)):
            lines.append(f"  [{mark[o.status]}] {o.serial}  {o.detail}")
            if o.newly_uncovered:
                lines.append("           NEWLY UNCOVERED: "
                             + ", ".join(o.newly_uncovered))
            if o.recovered:
                lines.append("           recovered: " + ", ".join(o.recovered))
            if o.still_uncovered:
                lines.append("           still uncovered (reported before): "
                             + ", ".join(o.still_uncovered))
            for w in o.warnings:
                lines.append(f"           ! {w}")
        if self.stale_observations:
            lines.append("")
            lines.append("  NOT LOOKED AT RECENTLY ENOUGH: "
                         + ", ".join(self.stale_observations))
            lines.append("  A watch that stopped running looks exactly like a fleet "
                         "that stopped changing.")
        return "\n".join(lines)


def _seal_observation(
    ledger: EvidenceLedger, target: WatchTarget, machine_key: str,
    configuration_hash: str, status: str, actor: Actor, detail: str,
) -> Evidence:
    """Record that this machine was looked at, whatever the look found.

    Sealed on every run including the quiet ones, because a gap in the record
    would otherwise be ambiguous between "unchanged" and "never checked", and
    only one of those is reassuring.
    """
    evidence = Evidence(
        kind=OBSERVATION_KIND,
        body={
            "serial": target.serial,
            "machine": machine_key,
            "status": status,
            "configuration_hash": configuration_hash,
            "plan": target.plan,
            "root": target.root,
            "detail": detail,
        },
        actor=actor,
        origin=Origin(system="assurance.watch", reference=machine_key,
                      method=f"scheduled collection from {target.root}"),
        validation_state=ValidationState.VERIFIED if status != "uncollectable"
        else ValidationState.INDETERMINATE,
        confidence=Confidence.HIGH if status != "uncollectable" else Confidence.NONE,
        checks_skipped=(
            ("the exports could not be collected, so this records an attempt and "
             "not an observation. Nothing here says the machine is unchanged.",)
            if status == "uncollectable" else
            ("this records the configuration the plan looked for. Safety-relevant "
             "software the plan does not name is outside it.",)
        ),
    ).seal()
    ledger.append(evidence, subject=machine_key)
    return evidence


def last_run(ledger: EvidenceLedger, watch_id: str) -> dict[str, Any] | None:
    """The most recent sealed run of this watch, or None."""
    for entry in reversed(ledger.entries(kind=RUN_KIND)):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        if evidence.body.get("watch_id") == watch_id:
            return evidence.body
    return None


def _advisories_by_id(
    advisories: AdvisoryPass, config: WatchConfig,
) -> list[tuple[Any, Any]]:
    """Pair each finding with the advisory object behind it.

    Re-read from the feeds rather than carried through the advisory pass,
    because the pass deliberately hands on findings — what an advisory means for
    this fleet — and an intake needs the advisory itself.
    """
    from assurance.attest.keys import VerifyingKey
    from assurance.core.errors import AssuranceError
    from assurance.supplier.publish import AdvisoryFeed, verify_feed

    out: list[tuple[Any, Any]] = []
    wanted = {f.advisory_id for f in advisories.findings}
    for sub in config.feeds:
        try:
            records = AdvisoryFeed(sub.feed).read()
            verdict = verify_feed(records, VerifyingKey.from_file(sub.public_key),
                                  expect_supplier=sub.supplier_id)
        except (AssuranceError, OSError):
            # The advisory pass has already read this feed and reported exactly
            # why it could not be used, and that report is what degrades the
            # run. Reporting it a second time here would double every message.
            continue
        if not verdict.ok:
            continue
        for record in verdict.live:
            if record.advisory_id in wanted:
                finding = next(f for f in advisories.findings
                               if f.advisory_id == record.advisory_id)
                out.append((finding, record.component()))
    return out


def _previously_received(run: dict[str, Any] | None) -> dict[str, str]:
    """Advisory id -> when this operator first received it.

    Carried forward so that the interval from receipt is measured from the run
    that first saw it. Resetting it every run would turn the one number a market
    surveillance authority asks about into a number that is always small.
    """
    if not run:
        return {}
    body = run.get("filings") or {}
    return {
        str(p.get("advisory_id", "")): str(p.get("received_at", ""))
        for p in body.get("prompts", ())
        if p.get("advisory_id") and p.get("received_at")
    }


def _already_assessed(ledger: EvidenceLedger) -> frozenset[str]:
    """Advisories for which an awareness record already exists.

    Once a person has made the determination, the register is where the clock
    lives, and repeating the prompt here would be a second system nagging about
    a decision that has been taken.
    """
    out: set[str] = set()
    for entry in ledger.entries(kind="art14.awareness"):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        case_id = str(entry.subject or "")
        if case_id.startswith("CASE-"):
            out.add(case_id[len("CASE-"):])
    return frozenset(out)


def _previously_reported(run: dict[str, Any] | None) -> dict[str, str]:
    """Advisory id -> the state it was last reported in.

    This is what makes "new" mean new. Without it every run announces every
    standing advisory again, and a reader who is told the same four things every
    Monday stops reading on the third Monday — at which point the watch has
    become an expensive way to generate silence.
    """
    if not run:
        return {}
    body = run.get("advisories") or {}
    return {
        str(f.get("advisory_id", "")): str(f.get("state", ""))
        for f in body.get("findings", ())
        if f.get("advisory_id")
    }


def _previous_state(run: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if not run:
        return {}
    return {o["serial"]: o for o in run.get("outcomes", [])}


def run_watch(
    config: WatchConfig,
    ledger: EvidenceLedger,
    *,
    now: datetime | None = None,
    seal: bool = True,
) -> WatchRun:
    """Look at every target once, seal what changed, and report what is new."""
    # When a caller supplies the clock, the whole run reads from it. Mixing an
    # injected start with a wall-clock finish produces a run that appears to end
    # before it began, which is the kind of detail an auditor notices first.
    injected = now is not None
    started = now or utc_now()
    actor = Actor(identifier=config.operator, role="scheduled watch",
                  kind="automation")
    previous = last_run(ledger, config.watch_id)
    prior = _previous_state(previous)

    outcomes: list[MachineOutcome] = []
    sealed: list[str] = []
    caveats: list[str] = []

    for target in config.targets:
        machine_key = ""
        try:
            plan = CollectionPlan.from_json(target.plan)
            machine_key = f"{plan.manufacturer}/{plan.model}#{target.serial}"
            result = collect(
                plan, target.root, serial=target.serial, taken_by=actor,
                site=target.site, country=target.country, year=target.year,
                source=ManifestSource.AS_FOUND, taken_at=started,
            )
        except (CollectionError, FileNotFoundError, OSError) as exc:
            detail = f"could not be collected: {exc}"
            outcomes.append(MachineOutcome(
                serial=target.serial, machine_key=machine_key or target.serial,
                status="uncollectable", detail=detail,
                still_uncovered=tuple(
                    prior.get(target.serial, {}).get("still_uncovered", ())
                ),
                warnings=("an absent export is not an unchanged machine.",),
            ))
            if seal and machine_key:
                _seal_observation(ledger, target, machine_key, "", "uncollectable",
                                  actor, detail)
            continue

        manifest = result.manifest
        observed = manifest.configuration_hash()
        history = manifests_from_ledger(ledger, machine_key)
        baseline = history[-1] if history else None

        status = "first_seen" if baseline is None else (
            "changed" if baseline.configuration_hash() != observed else "observed")

        drift_severity = ""
        drift_items: tuple[str, ...] = ()
        affected: tuple[str, ...] = ()
        detail = ""

        if status == "first_seen":
            detail = (f"first observation; configuration {observed[:12]}, "
                      f"{len(manifest.items)} item(s)")
        elif status == "observed":
            detail = f"unchanged at {observed[:12]}"
        else:
            divergence = compare(baseline, manifest)
            worst = divergence.worst
            drift_severity = worst.value if worst else ""
            drift_items = tuple(c.item_id for c in divergence.changes)
            affected = divergence.affected_functions
            detail = (f"configuration moved {baseline.configuration_hash()[:12]} → "
                      f"{observed[:12]}: " + ", ".join(
                          f"{c.item_id} {c.kind.value}" for c in divergence.changes))
            if seal:
                record_divergence(ledger, divergence, actor=actor)
                sealed.append(f"divergence {divergence.observed_id}")
            if worst is Severity.SAFETY_RELEVANT:
                caveats.append(
                    f"{machine_key}: a safety-bearing item changed. Verification "
                    "evidence for " + ", ".join(affected) + " is in doubt until it "
                    "is re-run; the watch cannot re-run it.")

        if seal and status in ("first_seen", "changed"):
            record_manifest(ledger, manifest, actor=actor)
            sealed.append(f"manifest {manifest.manifest_id}")

        coverage = assess_coverage(
            manifest,
            VerificationRecord.from_ledger(ledger, subject=machine_key),
            interventions_from_ledger(ledger, machine_key),
        )
        uncovered_now = {f.function_id for f in coverage.functions
                         if f.coverage is not Coverage.CURRENT}
        before = prior.get(target.serial, {})
        uncovered_before = set(before.get("still_uncovered", [])) | set(
            before.get("newly_uncovered", []))

        newly = tuple(sorted(uncovered_now - uncovered_before))
        still = tuple(sorted(uncovered_now & uncovered_before))
        recovered = tuple(sorted(uncovered_before - uncovered_now))

        warnings: list[str] = []
        if not result.complete:
            warnings.append(
                f"{len(result.missing)} required item(s) were not found, so this "
                "configuration hash covers less than the plan describes.")
        if not target.country:
            warnings.append(
                "no country recorded: this unit cannot be named in a CRA Article "
                "14 filing's Member State list.")

        outcomes.append(MachineOutcome(
            serial=target.serial, machine_key=machine_key, status=status,
            configuration_hash=observed,
            previous_configuration=baseline.configuration_hash() if baseline else "",
            newly_uncovered=newly, still_uncovered=still, recovered=recovered,
            drift_severity=drift_severity, drift_items=drift_items,
            affected_functions=affected, detail=detail, warnings=tuple(warnings),
        ))

        if seal:
            _seal_observation(ledger, target, machine_key, observed, status,
                              actor, detail)

    # A machine whose last look is older than the declared cadence.
    cutoff = started - timedelta(hours=config.max_age_hours)
    stale: list[str] = []
    for target in config.targets:
        seen_now = any(o.serial == target.serial and o.status != "uncollectable"
                       for o in outcomes)
        if seen_now:
            continue
        last_seen = _last_observation_at(ledger, target.serial)
        if last_seen is None or last_seen < cutoff:
            stale.append(target.serial)

    # The advisory pass runs after the machines, because it asks its questions
    # against the manifests this run has just sealed. Asking first would report
    # yesterday's fleet against today's advisories, which is the one combination
    # guaranteed to be wrong.
    advisories = AdvisoryPass()
    if config.feeds:
        advisories = check_feeds(
            list(config.feeds),
            Fleet.from_ledger(ledger),
            previously_seen=_previously_reported(previous),
            now=started,
        )
        caveats.extend(advisories.checks_skipped)

    # Intakes are drafted from the advisories this run just established, and
    # only when the operator has declared the duty. See watch.filings.
    filings = FilingsPass()
    if config.feeds:
        filings = draft_filings(
            advisories.findings,
            {f.advisory_id: a for f, a in _advisories_by_id(advisories, config)},
            Fleet.from_ledger(ledger),
            as_manufacturer=config.article_14.as_manufacturer,
            received_by=config.article_14.received_by,
            now=started,
            previously_received=_previously_received(previous),
            assessed=_already_assessed(ledger),
        )
        caveats.extend(filings.checks_skipped)

    caveats.extend([
        "a watch reports what its plans look for in the folders it was pointed "
        "at. A machine not listed in the configuration is not watched, and its "
        "silence here means nothing.",
        "the configuration is compared against the last manifest sealed for this "
        "machine. A change made and reverted between two runs leaves no trace.",
    ])
    if config.targets_without_country:
        caveats.append(
            "target(s) " + ", ".join(t.serial for t in
                                     config.targets_without_country)
            + " have no country recorded; a CRA Article 14 filing cannot name "
              "their territory.")

    run = WatchRun(
        watch_id=config.watch_id,
        config_hash=config.content_hash(),
        started_at=format_utc(started),
        finished_at=format_utc(started if injected else utc_now()),
        outcomes=tuple(outcomes),
        stale_observations=tuple(sorted(stale)),
        advisories=advisories,
        filings=filings,
        previous_run_hash=str(previous.get("self_hash", "")) if previous else "",
        checks_skipped=tuple(dict.fromkeys(caveats)),
        sealed=tuple(sealed),
    )

    if seal:
        evidence = Evidence(
            kind=RUN_KIND,
            body=run.to_dict(),
            actor=actor,
            origin=Origin(system="assurance.watch", reference=config.watch_id,
                          method=f"scheduled run over {len(config.targets)} target(s)"),
            validation_state=ValidationState.VERIFIED if run.verdict == "quiet"
            else ValidationState.INDETERMINATE,
            confidence=Confidence.HIGH if run.verdict != "degraded"
            else Confidence.LOW,
            checks_skipped=run.checks_skipped,
        ).seal()
        ledger.append(evidence, subject=f"watch/{config.watch_id}")

    return run


def _last_observation_at(ledger: EvidenceLedger, serial: str) -> datetime | None:
    for entry in reversed(ledger.entries(kind=OBSERVATION_KIND)):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        if evidence.body.get("serial") != serial:
            continue
        if evidence.body.get("status") == "uncollectable":
            continue
        try:
            return parse_utc(entry.at)
        except (ValueError, TypeError):  # pragma: no cover - ledger writes UTC
            return None
    return None
