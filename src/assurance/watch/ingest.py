"""Recording a Watch report the customer chose to send, and deciding nothing.

``assurance watch push`` (``assurance.watch.push``) sends what the customer's own
Watch saw to their hosted ledger, so the hosted workspace can show a subscription's
actual product: the last successful observation, the attempts that failed, and
the machines nobody has looked at lately. This is the receiving side, as a plain
domain function so the HTTP route, a test and any future caller share one path.

What this does and, deliberately, does not do:

* It **records** the manifest with :func:`~assurance.machinery.record.record_manifest`
  and then calls :func:`~assurance.change.service.assess_drift` — the function the
  ``/v1/change/assess/drift`` route and ``run_watch`` already use — over the
  divergence :func:`~assurance.machinery.divergence.compare` computes against the
  manifest *this ledger* holds. It derives no safety finding of its own and
  trusts no ``changed`` / ``unchanged`` claim: the status the reporter sent is
  kept as ``reported_status`` and the one this ledger computed is what counts.
* A look that failed is recorded **as that**. ``uncollectable`` and ``incomplete``
  write an observation that counts for nothing (``observation_succeeded``), call
  no ``assess_*`` and move no case. Their manifest is refused outright: a failed
  look has no business supplying one.
* It is **idempotent**. Every machine entry has a digest; an entry already held
  writes nothing, and a case is keyed by its trigger, so a retry after a timeout
  cannot open a second one. An entry older than what is already recorded for the
  machine is ignored, so a delayed report cannot rewind the record.
* It **cannot reach another tenant**: the ledger is handed in by the caller
  (``api.deps.get_register``) and nothing here names an account.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any

from assurance.change.model import TriggerType
from assurance.change.service import (
    INCOMPLETE_COLLECTION_MARK,
    assess_drift,
    case_id_for,
)
from assurance.change.store import CaseStore
from assurance.core.errors import AssuranceError
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    Origin,
    ValidationState,
)
from assurance.core.identity import content_hash_of, format_utc, parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import (
    MANIFEST_KIND,
    interventions_from_ledger,
    manifests_from_ledger,
    record_divergence,
    record_manifest,
)
from assurance.machinery.staleness import VerificationRecord
from assurance.watch.observations import (
    FAILED_STATUSES,
    OBSERVATION_KIND,
    REPORT_KIND,
    observed_at_of,
)

__all__ = [
    "FUTURE_SKEW",
    "LIMITATIONS",
    "MAX_MACHINES_PER_ACCOUNT",
    "MAX_NEW_MACHINES_PER_REPORT",
    "MachineResult",
    "ReportResult",
    "ingest_report",
    "lock_path",
]

#: How far ahead of this server's clock a timestamp may claim to be. A plant
#: clock a few seconds fast is ordinary; anything further ahead is refused, and
#: whatever is accepted is read as no later than the moment it was written
#: (``observations.observed_at_of``), so it cannot outrank a real later failure.
FUTURE_SKEW = timedelta(seconds=60)
#: Bounds on what one account's ledger can be made to track through this route.
MAX_MACHINES_PER_ACCOUNT = 1000
MAX_NEW_MACHINES_PER_REPORT = 200
POSITIVE_STATUSES = frozenset({"unchanged", "changed"})
REPORT_SCHEMA = "assurance.watch.report/1"

#: Serialises the check-then-write sequence inside one process; the advisory file
#: lock below extends it across processes (several workers, or a CLI on the same
#: volume). The ledger is single-writer by design; this keeps two identical
#: retries that overlap from both passing the "already recorded?" check.
_INGEST_LOCK = threading.Lock()


def lock_path(ledger: EvidenceLedger) -> str:
    """The file whose advisory lock serialises ingest into this ledger."""
    return str(ledger.path) + ".ingest.lock"


@contextmanager
def _ingest_lock(ledger: EvidenceLedger) -> Iterator[None]:
    with _INGEST_LOCK:
        try:
            import fcntl
        except ImportError:  # pragma: no cover - not POSIX: one process only
            yield
            return
        with open(lock_path(ledger), "a+") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

LIMITATIONS: tuple[str, ...] = (
    "These are observations reported by the holder of this account's key. The "
    "hosted service cannot collect from a machine, did not watch any of these "
    "and cannot tell a true report from a false one.",
    "Only the manifest (item ids, hashes, versions, provenance) is recorded. No "
    "export file, program or firmware reached this service, so nothing here can "
    "be re-derived from the machine.",
    "uncollectable and incomplete observations are recorded as failed attempts. "
    "They never count as a successful observation, advance or close a case, or "
    "make a machine current.",
    "The hosted service re-derives drift from the manifest this ledger already "
    "holds. A machine with no earlier manifest here has nothing to be compared "
    "with: its first manifest is a baseline, not a finding.",
    "Supplier advisory findings and Article 14 drafts in the customer's run are "
    "not part of this report. Use POST /v1/change/assess/advisory for an "
    "advisory; awareness and the Art. 14 track remain human decisions.",
    "A machine absent from a report is not reported as anything: its silence is "
    "shown as staleness once the declared cadence has passed.",
)


@dataclass(frozen=True)
class MachineResult:
    """What happened to one machine entry of a report."""

    serial: str
    machine_key: str
    reported_status: str
    #: ``first_seen`` | ``observed`` | ``changed`` | ``uncollectable`` | ``incomplete``
    #: for a recorded entry; empty when refused.
    recorded_status: str
    #: ``recorded`` | ``already_recorded`` | ``refused``
    outcome: str
    reason: str = ""
    detail: str = ""
    observed_at: str = ""
    #: Whether this entry counts as a successful observation of the machine.
    counts_as_observation: bool = False
    case_id: str = ""
    case_status: str = ""
    case_opened: bool = False
    open_case_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial,
            "machine_key": self.machine_key,
            "reported_status": self.reported_status,
            "recorded_status": self.recorded_status,
            "outcome": self.outcome,
            "reason": self.reason,
            "detail": self.detail,
            "observed_at": self.observed_at,
            "counts_as_observation": self.counts_as_observation,
            "case_id": self.case_id,
            "case_status": self.case_status,
            "case_opened": self.case_opened,
            "open_case_ids": list(self.open_case_ids),
        }


@dataclass(frozen=True)
class ReportResult:
    watch_id: str
    report_digest: str
    results: tuple[MachineResult, ...]
    report_recorded: bool = False
    limitations: tuple[str, ...] = field(default=LIMITATIONS)

    @property
    def cases_opened(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(
            r.case_id for r in self.results if r.case_id and r.case_opened))

    @property
    def cases_touched(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(r.case_id for r in self.results if r.case_id))

    def to_dict(self) -> dict[str, Any]:
        def count(outcome: str) -> int:
            return sum(1 for r in self.results if r.outcome == outcome)

        return {
            "watch_id": self.watch_id,
            "report_digest": self.report_digest,
            "report_recorded": self.report_recorded,
            "summary": {
                "entries": len(self.results),
                "recorded": count("recorded"),
                "already_recorded": count("already_recorded"),
                "refused": count("refused"),
                "failed_observations": sum(
                    1 for r in self.results
                    if r.outcome == "recorded" and r.recorded_status in FAILED_STATUSES),
            },
            "machines": [r.to_dict() for r in self.results],
            "cases_opened": list(self.cases_opened),
            "cases_touched": list(self.cases_touched),
            "limitations": list(self.limitations),
        }


# -- helpers ---------------------------------------------------------------


def entry_digest(watch_id: str, entry: Mapping[str, Any], observed_at: datetime) -> str:
    """Identity of one machine entry, independent of how its time was spelled."""
    return content_hash_of({
        "watch_id": watch_id,
        "serial": str(entry.get("serial", "")),
        "machine_key": str(entry.get("machine_key", "")),
        "status": str(entry.get("status", "")),
        "observed_at": format_utc(observed_at),
        "collection_complete": bool(entry.get("collection_complete")),
        "manifest": entry.get("manifest"),
        "detail": str(entry.get("detail", "")),
        "missing_items": sorted(str(m) for m in entry.get("missing_items", ())),
    })


def _instant(entry: Mapping[str, Any]) -> datetime:
    """When the entry says it was observed, as an instant (text order is not time order)."""
    try:
        return parse_utc(str(entry.get("observed_at", "")))
    except (ValueError, TypeError):
        return datetime.max.replace(tzinfo=UTC)


def report_digest(report: Mapping[str, Any]) -> str:
    return content_hash_of(dict(report))


def _refuse(entry: Mapping[str, Any], key: str, reason: str, detail: str,
            observed_at: str = "") -> MachineResult:
    return MachineResult(
        serial=str(entry.get("serial", "")), machine_key=key,
        reported_status=str(entry.get("status", "")), recorded_status="",
        outcome="refused", reason=reason, detail=detail, observed_at=observed_at)


def _seal_observation(
    ledger: EvidenceLedger, *, key: str, serial: str, status: str, reported: str,
    observed_at: datetime, configuration_hash: str, complete: bool,
    missing: Sequence[str], detail: str, watch_id: str, run_started_at: str,
    digest: str, actor: Actor, cadence: float | None = None,
) -> Evidence:
    """Seal a ``watch.observation`` in exactly the shape ``run_watch`` seals.

    ``plan`` and ``root`` are present and empty on purpose: they are local
    filesystem paths and never leave the plant. The fields the hosted side adds
    (``source``, ``reported_status``, ``report_digest`` ...) sit beside the
    runner's, so everything that reads an observation reads this one.
    """
    failed = status in FAILED_STATUSES
    evidence = Evidence(
        kind=OBSERVATION_KIND,
        body={
            "serial": serial,
            "machine": key,
            "status": status,
            "observed_at": format_utc(observed_at),
            "configuration_hash": configuration_hash,
            "plan": "",
            "root": "",
            "detail": detail,
            "complete": complete and not failed,
            "missing": list(missing),
            "source": "hosted_report",
            "watch_id": watch_id,
            "run_started_at": run_started_at,
            "reported_status": reported,
            "report_digest": digest,
            # Declared by the reporting watch with a successful look, never with a
            # failed one: a report cannot lengthen what it did not observe.
            "cadence_hours": None if failed else cadence,
        },
        actor=actor,
        origin=Origin(system="assurance.watch.ingest", reference=key,
                      method=f"reported by watch {watch_id}"),
        validation_state=(ValidationState.INDETERMINATE if failed
                          else ValidationState.UNVERIFIED),
        confidence=Confidence.NONE if failed else Confidence.MEDIUM,
        checks_skipped=(
            ("this records an attempt that did not observe the machine. Nothing "
             "here says it is unchanged.",)
            if failed else
            ("reported by the holder of the account's key; the hosted service did "
             "not observe the machine.",)
        ),
    ).seal()
    ledger.append(evidence, subject=key)
    return evidence


def _held_observations(ledger: EvidenceLedger, key: str) -> list[tuple[datetime, str]]:
    """``(observed_at, report_digest)`` for every verifying observation of the machine."""
    out: list[tuple[datetime, str]] = []
    for entry in ledger.entries(subject=key, kind=OBSERVATION_KIND):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        at = observed_at_of(evidence.body, entry.at)
        if at is not None:
            out.append((at, str(evidence.body.get("report_digest", ""))))
    return out


@dataclass
class _Account:
    """What this ledger already knows, kept current as a report is applied."""

    enrolled: set[str]          # machines with a manifest
    known: set[str]             # machines with a manifest or an observation
    max_age_hours: float | None
    new: int = 0

    def resolve_failed(self, serial: str, declared_key: str) -> tuple[str, str, str]:
        """``(key, reason, detail)``: the enrolled machine a failed look belongs to.

        A failure may only be recorded against a machine this account has
        enrolled: it names the full ``mfr/model#serial`` key, or a bare serial
        that matches exactly one enrolled key. It never creates a machine.
        """
        if declared_key and "#" in declared_key:
            if declared_key in self.enrolled:
                return declared_key, "", ""
            return "", "unenrolled_machine", (
                f"{declared_key!r} is not a machine this account has enrolled (a "
                "failed look cannot create one, and a typo in the key would "
                "otherwise record the failure against nothing). Check the key.")
        if declared_key and declared_key != serial:
            return "", "machine_unidentified", (
                "machine_key must be the full manufacturer/model#serial key, or "
                "empty so the serial can be resolved.")
        matches = sorted(k for k in self.enrolled if k.rpartition("#")[2] == serial)
        if len(matches) == 1:
            return matches[0], "", ""
        if not matches:
            return "", "unenrolled_machine", (
                f"no machine with serial {serial!r} is enrolled in this account, so "
                "a failed look cannot be attributed to one. It is recorded once a "
                "look of that machine has succeeded.")
        return "", "ambiguous_serial", (
            f"serial {serial!r} matches {len(matches)} enrolled machines; send the "
            "full manufacturer/model#serial key.")


# -- one entry --------------------------------------------------------------


def _ingest_entry(
    ledger: EvidenceLedger, store: CaseStore, entry: Mapping[str, Any], *,
    watch_id: str, run_started_at: str, actor: Actor, now: datetime, account: _Account,
) -> MachineResult:
    serial = str(entry.get("serial", ""))
    status = str(entry.get("status", ""))
    try:
        observed_at = parse_utc(str(entry.get("observed_at", "")))
    except (ValueError, TypeError) as exc:
        return _refuse(entry, str(entry.get("machine_key", "")) or serial,
                       "invalid_observed_at", str(exc))
    stamp = format_utc(observed_at)
    declared_key = str(entry.get("machine_key", ""))
    complete = bool(entry.get("collection_complete"))
    raw_manifest = entry.get("manifest")
    fallback_key = declared_key or serial

    if status not in POSITIVE_STATUSES | FAILED_STATUSES:
        return _refuse(entry, fallback_key, "invalid_status",
                       f"status {status!r} is not one of unchanged, changed, "
                       "uncollectable, incomplete.", stamp)
    if observed_at > now + FUTURE_SKEW:
        return _refuse(entry, fallback_key, "observed_at_in_future",
                       f"{stamp} is later than this server's clock allows; an "
                       "observation cannot have happened yet.", stamp)

    positive = status in POSITIVE_STATUSES
    if positive and not complete:
        return _refuse(entry, fallback_key, "inconsistent_collection_flag",
                       f"status {status!r} with collection_complete=false. A look "
                       "that did not finish is reported as 'incomplete'.", stamp)
    if not positive and complete:
        return _refuse(entry, fallback_key, "inconsistent_collection_flag",
                       f"status {status!r} with collection_complete=true.", stamp)

    manifest: SafetyManifest | None = None
    if positive:
        if not raw_manifest:
            return _refuse(entry, fallback_key, "manifest_required",
                           f"a {status!r} observation must carry the manifest it "
                           "rests on; without it nothing can be compared.", stamp)
        try:
            manifest = SafetyManifest.from_dict(dict(raw_manifest))
        except (AssuranceError, KeyError, ValueError, TypeError) as exc:
            return _refuse(entry, fallback_key, "invalid_manifest", str(exc), stamp)
        key = manifest.machine.key
        if declared_key and declared_key != key:
            return _refuse(entry, key, "machine_key_mismatch",
                           f"the entry names {declared_key!r} but its manifest "
                           f"describes {key!r}.", stamp)
        if serial != manifest.machine.serial:
            return _refuse(entry, key, "serial_mismatch",
                           f"the entry names serial {serial!r} but its manifest "
                           f"describes {manifest.machine.serial!r}.", stamp)
        if INCOMPLETE_COLLECTION_MARK in manifest.notes:
            return _refuse(entry, key, "manifest_marked_incomplete",
                           "the manifest says its collection was incomplete, so it "
                           "cannot be a positive observation.", stamp)
        if manifest.taken_at > observed_at + FUTURE_SKEW:
            return _refuse(entry, key, "manifest_taken_after_observation",
                           "the manifest claims to have been taken after the "
                           "observation it supports.", stamp)
    else:
        if raw_manifest:
            return _refuse(entry, fallback_key, "manifest_not_accepted",
                           f"a {status!r} observation did not observe the machine "
                           "and cannot supply a manifest.", stamp)
        if declared_key and "#" in declared_key and not declared_key.endswith("#" + serial):
            return _refuse(entry, declared_key, "serial_mismatch",
                           f"machine_key {declared_key!r} does not end in the "
                           f"serial {serial!r}.", stamp)
        key, reason, why = account.resolve_failed(serial, declared_key)
        if reason:
            return _refuse(entry, fallback_key, reason, why, stamp)

    digest = entry_digest(watch_id, entry, observed_at)
    held = _held_observations(ledger, key)
    if any(d == digest for _, d in held):
        return MachineResult(
            serial=serial, machine_key=key, reported_status=status,
            recorded_status="", outcome="already_recorded", observed_at=stamp,
            detail="this exact observation is already in the ledger; nothing was written.",
            counts_as_observation=positive)
    if held:
        newest = max(at for at, _ in held)
        if observed_at < newest:
            return _refuse(entry, key, "superseded_by_newer_observation",
                           f"the ledger already holds an observation of {key} from "
                           f"{format_utc(newest)}; an older one is ignored so a "
                           "delayed report cannot rewind the record.", stamp)
        if observed_at == newest:
            return _refuse(entry, key, "conflicts_with_recorded_observation",
                           f"a different observation of {key} at {stamp} is "
                           "already recorded.", stamp)

    if key not in account.known:
        # Only a positive look (with its manifest) reaches here for a new machine.
        if len(account.known) >= MAX_MACHINES_PER_ACCOUNT:
            return _refuse(entry, key, "account_machine_limit",
                           f"this account already tracks {len(account.known)} "
                           "machines, the most one account may.", stamp)
        if account.new >= MAX_NEW_MACHINES_PER_REPORT:
            return _refuse(entry, key, "too_many_new_machines",
                           f"a report may introduce at most {MAX_NEW_MACHINES_PER_REPORT} "
                           "machines the account has not reported before.", stamp)

    missing = [str(m) for m in entry.get("missing_items", ())]
    detail = str(entry.get("detail", ""))

    if not positive:
        _seal_observation(
            ledger, key=key, serial=serial, status=status, reported=status,
            observed_at=observed_at, configuration_hash="", complete=False,
            missing=missing, detail=detail
            or "the look did not complete; nothing here says the machine is unchanged.",
            watch_id=watch_id, run_started_at=run_started_at, digest=digest,
            actor=actor)
        return MachineResult(
            serial=serial, machine_key=key, reported_status=status,
            recorded_status=status, outcome="recorded", observed_at=stamp,
            reason="failed_observation",
            detail="recorded as a failed attempt. It does not count as an "
                   "observation and no case was touched.",
            counts_as_observation=False)

    assert manifest is not None
    observed_hash = manifest.configuration_hash()
    history = manifests_from_ledger(ledger, key)
    baseline = history[-1] if history else None
    case_id = ""
    case_status = ""
    case_opened = False
    if baseline is None:
        recorded = "first_seen"
        note = (f"first observation held for this machine; configuration "
                f"{observed_hash[:12]}, {len(manifest.items)} item(s). A baseline, "
                "not a finding.")
        record_manifest(ledger, manifest, actor=actor)
    elif baseline.configuration_hash() == observed_hash:
        recorded = "observed"
        note = f"unchanged at {observed_hash[:12]}"
    else:
        recorded = "changed"
        try:
            divergence = compare(baseline, manifest)
        except ValueError as exc:  # pragma: no cover - same key, so cannot differ
            return _refuse(entry, key, "incomparable_manifest", str(exc), stamp)
        note = (f"configuration moved {baseline.configuration_hash()[:12]} → "
                f"{observed_hash[:12]}: " + ", ".join(
                    f"{c.item_id} {c.kind.value}" for c in divergence.changes))
        # The case before the manifest, the order run_watch keeps: if this
        # dies in between, the baseline here is still the old one, a retry sees
        # the same drift and assess_drift lands on the same case.
        trigger_case = case_id_for(TriggerType.MACHINE_DRIFT, observed_hash)
        existed = store.get(trigger_case) is not None
        case = assess_drift(
            store, divergence, manifest,
            VerificationRecord.from_ledger(ledger, subject=key),
            interventions_from_ledger(ledger, key), actor=actor)
        if case is not None:
            case_id, case_status, case_opened = case.case_id, case.status.value, not existed
        record_divergence(ledger, divergence, actor=actor)
        record_manifest(ledger, manifest, actor=actor)

    _seal_observation(
        ledger, key=key, serial=serial, status=recorded, reported=status,
        observed_at=observed_at, configuration_hash=observed_hash, complete=True,
        missing=(), detail=note, watch_id=watch_id, run_started_at=run_started_at,
        digest=digest, actor=actor, cadence=account.max_age_hours)
    if key not in account.known:
        account.new += 1
    account.known.add(key)
    account.enrolled.add(key)
    return MachineResult(
        serial=serial, machine_key=key, reported_status=status,
        recorded_status=recorded, outcome="recorded", observed_at=stamp,
        detail=note + ("" if recorded_matches(status, recorded) else
                       f" (the reporter said {status!r}; this ledger's own "
                       "comparison is what is recorded)"),
        counts_as_observation=True, case_id=case_id, case_status=case_status,
        case_opened=case_opened)


def recorded_matches(reported: str, recorded: str) -> bool:
    """Whether the status the reporter sent agrees with the one this ledger computed."""
    if recorded == "first_seen":
        return True  # nothing to compare with here: a baseline agrees with any claim
    return (reported == "unchanged") == (recorded == "observed")


# -- one report --------------------------------------------------------------


def ingest_report(
    ledger: EvidenceLedger, report: Mapping[str, Any], *, actor: Actor,
    now: datetime | None = None,
) -> ReportResult:
    """Record every entry of a validated report into ``ledger``, oldest first.

    ``report`` is the plain-dict form of the request body (see
    ``api.watch_routes.WatchReportIn``): ``watch_id``, ``run_started_at``,
    optional ``max_age_hours`` / ``verdict`` / ``batch_index`` / ``batch_count``,
    and ``machines``.
    """
    clock = now or utc_now()
    watch_id = str(report["watch_id"])
    started = parse_utc(str(report["run_started_at"]))
    if started > clock + FUTURE_SKEW:
        raise ValueError(
            f"run_started_at {format_utc(started)} is later than this server's "
            "clock allows.")
    run_started_at = format_utc(started)
    digest = report_digest(report)
    entries = list(report["machines"])
    # Oldest first, so an earlier good look and a later failed one arrive in the
    # order they happened and the later one is not rejected as "older".
    order = sorted(range(len(entries)), key=lambda i: (_instant(entries[i]), i))
    max_age = report.get("max_age_hours")

    with _ingest_lock(ledger):
        store = CaseStore(ledger)
        enrolled = {e.subject for e in ledger.entries(kind=MANIFEST_KIND) if e.subject}
        observed = {e.subject for e in ledger.entries(kind=OBSERVATION_KIND) if e.subject}
        account = _Account(enrolled=set(enrolled), known=enrolled | observed,
                           max_age_hours=float(max_age) if max_age else None)
        results: dict[int, MachineResult] = {}
        for i in order:
            results[i] = _ingest_entry(
                ledger, store, entries[i], watch_id=watch_id,
                run_started_at=run_started_at, actor=actor, now=clock, account=account)

        recorded = [i for i in order if results[i].outcome == "recorded"]
        report_recorded = False
        if recorded:
            had_success = any(results[i].counts_as_observation for i in recorded)
            evidence = Evidence(
                kind=REPORT_KIND,
                body={
                    "schema": REPORT_SCHEMA,
                    "watch_id": watch_id,
                    "run_started_at": run_started_at,
                    "received_at": format_utc(clock),
                    "max_age_hours": float(max_age) if max_age and had_success else None,
                    "verdict": report.get("verdict") or "",
                    "batch_index": report.get("batch_index"),
                    "batch_count": report.get("batch_count"),
                    "report_digest": digest,
                    "machines": [
                        {"machine": results[i].machine_key,
                         "serial": results[i].serial,
                         "reported_status": results[i].reported_status,
                         "recorded_status": results[i].recorded_status,
                         "observed_at": results[i].observed_at,
                         "case_id": results[i].case_id}
                        for i in recorded
                    ],
                },
                actor=actor,
                origin=Origin(system="assurance.watch.ingest", reference=watch_id,
                              method="report posted by the account holder"),
                validation_state=ValidationState.UNVERIFIED,
                confidence=Confidence.MEDIUM,
                checks_skipped=LIMITATIONS[:1],
            ).seal()
            ledger.append(evidence, subject=f"watch/{watch_id}")
            report_recorded = True

        # Open cases are listed after every write, from the ledger, so the
        # response says what is open and not what this call guesses.
        open_by_machine: dict[str, list[str]] = {}
        for case in store.list():
            if case.is_open:
                for machine in case.machines:
                    open_by_machine.setdefault(machine, []).append(case.case_id)

    final = tuple(
        _with_open_cases(results[i], open_by_machine) for i in range(len(entries)))
    return ReportResult(watch_id=watch_id, report_digest=digest, results=final,
                        report_recorded=report_recorded)


def _with_open_cases(result: MachineResult, open_by_machine: dict[str, list[str]]) -> MachineResult:
    return replace(result, open_case_ids=tuple(sorted(open_by_machine.get(result.machine_key, ()))))
