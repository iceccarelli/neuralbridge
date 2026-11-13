"""The enrolment kit: one command, inside the plant, with nothing leaving it.

The commercial problem this solves is not technical. Everything needed to
produce a machine's safety evidence already exists in this package, and none of
it is reachable by the person who needs it, because reaching it means installing
a toolchain, writing a collection plan, learning six verbs, and — fatally —
convincing a plant's IT department to let an unknown tool near an unknown
network. That review takes eleven weeks. Most pilots die in it.

So the kit inverts the order. The integrator copies a folder onto a machine that
is already inside the plant, runs one command, and gets back a sealed evidence
ledger, an HTML report, and a signed-attestation request — **their** ledger,
**their** data, on **their** disk, with the network provably untouched
(:mod:`assurance.kit.airgap`). No account. No upload. No key. Nothing to
procure and nothing to review, because nothing left.

What the kit deliberately does not do is the work that needs a second party:
fanning a supplier advisory across a fleet, counter-signing a head with a key
the plant does not hold, running every week without anybody remembering to, and
joining machines that belong to different sites. Those are named at the end of
every run, next to what was established, because the honest statement of the gap
is a better argument than any claim about the product — and because a kit that
pretended to cover them would be caught the first time it mattered.

The order of operations is fixed and the reason is the airgap record:

1. Everything substantive — collect, seal, render, write — happens inside the
   guard.
2. The airgap record is sealed **after** the guard releases, because a record of
   a guard cannot be written while the guard it describes is still running. That
   sentence is in the record.
3. The head is read last, so it covers the airgap record as well.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ..collect.collector import CollectionResult, ItemOutcome, collect
from ..collect.plan import CollectionPlan, read_json_object
from ..core.actor_names import actor_name_problem, declared_role_problem
from ..core.errors import AssuranceError
from ..core.evidence import Actor, Evidence, Origin, ValidationState
from ..core.identity import format_utc, utc_now
from ..core.placeholders import placeholder_problem, starter_values
from ..evidence.ledger import EvidenceLedger
from ..machinery.manifest import HashSource, ManifestSource
from ..machinery.record import record_manifest
from ..report.render import ReportInput, render_report
from .airgap import AIRGAP_LIMITS, AirgapResult, no_network

__all__ = [
    "describe_placeholders",
    "find_placeholders",
    "inspect_machine",
    "starter_warnings",
    "AIRGAP_KIND",
    "KIT_RUN_KIND",
    "KitConfig",
    "KitError",
    "KitRun",
    "MachineEntry",
    "MachineResult",
    "run_kit",
    "starter_config",
]

KIT_RUN_KIND = "kit.run"
AIRGAP_KIND = "kit.airgap"


class KitError(AssuranceError):
    """The kit cannot run, and the message says what to fix."""


def _is_placeholder(value: str) -> bool:
    """Whether *value* is a template value (the one definition, shared with SBOM and inventory)."""
    return placeholder_problem("value", value) is not None


def find_placeholders(config_path: str | Path) -> list[dict[str, str]]:
    """Every template value still in ``kit.json`` or in the plans it names, at once.

    Reads only, and tolerates what is not there yet: ``check`` calls this before the
    configuration is loaded, so a person who has not filled anything in is told about
    all of it in one answer instead of one refusal per run. Each entry is
    ``{"file", "field", "value"}``; ``file`` is the path as ``kit.json`` writes it.
    """
    path = Path(config_path)
    out: list[dict[str, str]] = []
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return out
    if not isinstance(data, dict):
        return out
    for name in ("organisation", "prepared_by", "site"):
        value = data.get(name)
        if isinstance(value, str) and _is_placeholder(value):
            out.append({"file": path.name, "field": name, "value": value})
    seen: set[str] = set()
    for entry in data.get("machines") or ():
        rel = entry.get("plan") if isinstance(entry, dict) else None
        if not isinstance(rel, str) or rel in seen:
            continue
        seen.add(rel)
        plan_path = Path(rel) if Path(rel).is_absolute() else path.parent / rel
        try:
            plan = json.loads(plan_path.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(plan, dict):
            continue
        for name in ("manufacturer", "model"):
            value = plan.get(name)
            if isinstance(value, str) and _is_placeholder(value):
                out.append({"file": rel, "field": name, "value": value})
        for item in plan.get("items") or ():
            if isinstance(item, dict):
                value = item.get("supplier")
                if isinstance(value, str) and _is_placeholder(value):
                    out.append({"file": rel,
                                "field": f"items.{item.get('item_id', '?')}.supplier",
                                "value": value})
    return out


def describe_placeholders(placeholders: list[dict[str, str]]) -> list[str]:
    """One sentence per file: what is still a template value there, named exactly."""
    by_file: dict[str, list[dict[str, str]]] = {}
    for ph in placeholders:
        by_file.setdefault(ph["file"], []).append(ph)
    lines = []
    for file, rows in by_file.items():
        is_plan = any(r["field"] in ("manufacturer", "model") or r["field"].startswith("items.")
                      for r in rows)
        names = []
        for r in rows:
            if r["field"].startswith("items."):
                names.append(f"supplier of {r['field'].split('.')[1]}")
            else:
                names.append(r["field"])
        if is_plan:
            lines.append(f"{file} still has CHANGE ME placeholders: {', '.join(names)}.")
        else:
            lines.append(f"{file} still has template values: "
                         + ", ".join(f"{r['field']}={r['value']!r}" for r in rows) + ".")
    return lines


@dataclass(frozen=True)
class MachineEntry:
    """One machine the kit will enrol."""

    serial: str
    plan: str
    exports: str
    year: str = ""
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> MachineEntry:
        if not isinstance(d, dict):
            raise KitError(f"each entry of `machines` in kit.json must be an object with "
                           f"serial, plan and exports, not {type(d).__name__}.")
        who = f"machine {d['serial']!r}" if d.get("serial") else "a machine entry"
        missing = [k for k in ("serial", "plan", "exports") if not d.get(k)]
        if missing:
            why = {
                "serial": "A machine with no serial cannot be told apart from another one "
                          "later, which is the only thing a fleet record is for.",
                "plan": "`plan` is the path of the collection plan for this machine "
                        "(for example plans/cell.json).",
                "exports": "`exports` is the folder holding this machine's exported files "
                           "(for example exports/<serial>).",
            }
            raise KitError(
                f"in kit.json, {who} is missing {', '.join(missing)}. "
                + " ".join(why[m] for m in missing))
        return cls(
            serial=str(d["serial"]), plan=str(d["plan"]),
            exports=str(d["exports"]), year=str(d.get("year", "")),
            notes=str(d.get("notes", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {"serial": self.serial, "plan": self.plan, "exports": self.exports,
                "year": self.year, "notes": self.notes}


@dataclass(frozen=True)
class KitConfig:
    """The one file an integrator fills in. Everything else is derived."""

    kit_id: str
    organisation: str
    prepared_by: str
    machines: tuple[MachineEntry, ...]
    site: str = ""
    country: str = ""
    role: str = "integrator"
    #: Directory paths in this file resolve against the file's own location, so
    #: the kit can be copied anywhere and still work.
    base: Path = field(default=Path("."), compare=False)

    def __post_init__(self) -> None:
        if not self.kit_id.strip():
            raise KitError("kit_id is empty.")
        if not self.organisation.strip():
            raise KitError(
                "organisation is empty. It is printed at the top of the report "
                "that somebody outside this room will read."
            )
        for field_name, value in (
            ("organisation", self.organisation),
            ("prepared_by", self.prepared_by),
            ("site", self.site),
        ):
            if _is_placeholder(value):
                raise KitError(
                    f"{field_name} is still the placeholder {value!r}. It is "
                    "printed at the top of a report that goes to an auditor, an "
                    "insurer or a customer. Refusing to produce evidence with a "
                    "template value on it."
                )
        if not self.prepared_by.strip():
            raise KitError(
                "prepared_by is empty. An unattributed record is not evidence — "
                "the first question anybody asks of a finding is who looked."
            )
        _problem = actor_name_problem(self.prepared_by) or declared_role_problem(self.role)
        if _problem:
            raise KitError(f"prepared_by / role cannot be recorded: {_problem}.")
        if not self.machines:
            raise KitError("no machines listed; there is nothing to enrol.")
        seen: set[str] = set()
        folders: dict[Path, str] = {}
        for m in self.machines:
            why = placeholder_problem("serial", m.serial)
            if why:
                raise KitError(
                    f"machine serial {m.serial!r}: {why}. The serial is what tells this "
                    "machine from every other one in a fleet record; type the number from "
                    "the unit's rating plate.")
            if m.serial in seen:
                raise KitError(
                    f"serial {m.serial} appears twice. Two machines sharing a "
                    "serial produce one record that describes neither."
                )
            seen.add(m.serial)
            folder = self.resolve(m.exports).resolve()
            if folder in folders:
                raise KitError(
                    f"machines {folders[folder]} and {m.serial} both read the export folder "
                    f"{m.exports!r}. They would be enrolled with identical evidence, and one "
                    "of them is not what that folder holds. Give each machine its own folder "
                    "of its own exports (exports/<serial>).")
            folders[folder] = m.serial
        if self.country and (len(self.country) != 2 or not self.country.isalpha()):
            raise KitError(
                f"country {self.country!r} is not an ISO 3166-1 alpha-2 code. It "
                "is carried into Article 14 filings, where a guess moves a legal "
                "deadline."
            )

    @property
    def actor(self) -> Actor:
        return Actor(identifier=self.prepared_by, role=self.role, kind="person")

    def resolve(self, relative: str) -> Path:
        p = Path(relative)
        return p if p.is_absolute() else (self.base / p)

    @classmethod
    def from_json(cls, path: str | Path) -> KitConfig:
        p = Path(path)
        if not p.exists():
            raise KitError(
                f"{p} does not exist. Run `assurance kit init <folder>` to write "
                "a working one and edit it."
            )
        try:
            data = read_json_object(p, "kit config", KitError)
        except OSError as exc:
            # A directory or a permissions problem is "the kit could not run" (exit 2), not an
            # uncaught crash that shares exit 1 with a finding.
            raise KitError(f"{p} could not be read as a kit config: {exc}") from exc
        return cls(
            kit_id=str(data.get("kit_id", "")),
            organisation=str(data.get("organisation", "")),
            prepared_by=str(data.get("prepared_by", "")),
            site=str(data.get("site", "")),
            country=str(data.get("country", "")).upper(),
            role=str(data.get("role", "integrator")),
            machines=tuple(
                MachineEntry.from_dict(m) for m in data.get("machines", [])),
            base=p.parent.resolve(),
        )


@dataclass(frozen=True)
class MachineResult:
    """What happened to one machine. ``recorded`` is not the only good outcome.

    ``recorded`` means the machine's manifest is sealed in this kit's ledger. It does not mean
    enrolled: that is ``assurance machinery enrol``, a named person's declaration
    (:func:`~assurance.machinery.enrol.enrol_machine`), which the kit never makes for them.
    """

    serial: str
    status: str            # recorded | incomplete | failed
    items: int = 0
    configuration_hash: str = ""
    plan_id: str = ""
    warnings: tuple[str, ...] = ()
    detail: str = ""
    #: One entry per item the plan names: collected, missing or unreadable, with the reason,
    #: the files it came from, its digest and the version found. Empty when the machine
    #: failed before any file was read.
    outcomes: tuple[ItemOutcome, ...] = ()
    #: Whether a manifest for this machine is in the ledger. An incomplete collection is
    #: not sealed unless the operator asked for it (``--seal-incomplete``).
    sealed: bool = False

    @property
    def missing(self) -> tuple[str, ...]:
        """The item ids the plan names that were not collected (missing or unreadable)."""
        return tuple(o.item_id for o in self.outcomes if not o.ok)

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial, "status": self.status, "items": self.items,
            "configuration_hash": self.configuration_hash, "plan_id": self.plan_id,
            "warnings": list(self.warnings), "detail": self.detail,
            "sealed": self.sealed, "missing": list(self.missing),
            "outcomes": [o.to_dict() for o in self.outcomes],
        }


@dataclass(frozen=True)
class KitRun:
    """One complete pass, and everything it is honest about not having done."""

    kit_id: str
    started_at: str
    finished_at: str
    organisation: str
    machines: tuple[MachineResult, ...]
    airgap: AirgapResult
    ledger_path: str
    report_path: str
    attest_request_path: str
    head: dict[str, Any]
    checks_skipped: tuple[str, ...]
    #: Whether the operator asserted (``--read-from-machine``) that the collector ran
    #: on the machines. False means the manifests are ``supplied_by_vendor``.
    read_from_machine_asserted: bool = False

    @property
    def recorded(self) -> tuple[MachineResult, ...]:
        return tuple(m for m in self.machines if m.status == "recorded")

    @property
    def enrolled(self) -> tuple[MachineResult, ...]:
        """Alias of :attr:`recorded`, kept for callers written before the rename."""
        return self.recorded

    @property
    def verdict(self) -> str:
        """``complete``, ``partial`` or ``failed``. Never a boolean.

        Deliberately not degraded by the standing caveat every collection
        carries — that a plan only finds what it names. That sentence is true of
        every run that will ever happen, so letting it force PARTIAL every time
        would teach the reader that the verdict means nothing, which is how a
        signal is destroyed. It belongs in what-was-not-checked, and that is
        where it goes. What moves the verdict is a machine that was not recorded,
        a required item that was not found, or a connection attempt.
        """
        if not self.recorded:
            return "failed"
        if len(self.recorded) != len(self.machines):
            return "partial"
        if not self.airgap.held:
            return "partial"
        return "complete"

    def summary(self) -> str:
        return (
            f"{self.kit_id} — {len(self.recorded)}/{len(self.machines)} machine(s) "
            f"recorded — {self.verdict.upper()}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kit_id": self.kit_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "organisation": self.organisation,
            "verdict": self.verdict,
            "machines": [m.to_dict() for m in self.machines],
            "airgap": self.airgap.to_dict(),
            "ledger": self.ledger_path,
            "report": self.report_path,
            "attest_request": self.attest_request_path,
            "head": self.head,
            "checks_skipped": list(self.checks_skipped),
            "read_from_machine_asserted": self.read_from_machine_asserted,
        }


#: What one offline run cannot establish, whatever it finds. Carried into the
#: run record and printed at the end, because the gap is the argument.
_KIT_LIMITS: tuple[str, ...] = (
    "COMPLETE, in this run's headline, means only that every item the collection plan "
    "names was found in an export folder and hashed. It does not say the plan names "
    "everything that is safety-relevant, that the files are current, that they came "
    "off the machine, or that anything was verified.",
    "This run recorded what was in the export folders at one moment. Nothing "
    "here watches for the next change; a firmware update tomorrow strands every "
    "sign-off in this ledger and nothing will say so until somebody runs this "
    "again.",
    "No supplier advisory was matched against these machines. A component with "
    "a published vulnerability would appear in this manifest as an ordinary "
    "item.",
    "The head of this ledger is not signed. A hash chain detects editing, not "
    "deletion: whoever holds this database can remove records and rebuild a "
    "chain that verifies. The attestation request written beside the report is "
    "the first half of closing that.",
    "No physical behaviour was verified. Nothing here says a machine stops in "
    "the distance its datasheet claims; that needs a recorded run against a "
    "declared safety envelope.",
    "Manifests were read from exported files, not from the machines. They are "
    "labelled supplied_by_vendor (tier ceiling community): the files are as good "
    "as the export, the export is as good as whoever produced it, and a folder of "
    "files cannot show which machine it came from. Such a manifest is not accepted "
    "as a look at the machine by the change workflow or by hosted ingest.",
)

#: The same last limit when the operator passed ``--read-from-machine``.
_ASSERTED_LIMIT = (
    "The operator asserted that this collector ran on the machines themselves "
    "(--read-from-machine), so the manifests are labelled read_from_machine. "
    "That label is the operator's statement; this software cannot check that the "
    "files in the export folders came off those machines, and the assertion is "
    "recorded in each manifest."
)


def kit_limits(read_from_machine: bool) -> tuple[str, ...]:
    """What one offline run cannot establish, with the provenance limit that applies."""
    if not read_from_machine:
        return _KIT_LIMITS
    return (*_KIT_LIMITS[:-1], _ASSERTED_LIMIT)


def starter_config(kit_id: str = "site-kit") -> dict[str, Any]:
    """A configuration that runs as written, so the first attempt succeeds."""
    return {
        "kit_id": kit_id,
        "organisation": "YOUR COMPANY GmbH",
        "site": "Plant 1",
        "country": "DE",
        "prepared_by": "your.name@yourcompany.example",
        "role": "integrator",
        "machines": [
            {
                "serial": "CELL-0412",
                "plan": "plans/cell.json",
                "exports": "exports/CELL-0412",
                "year": "2025",
                "notes": "",
            },
        ],
    }


def starter_warnings(entry: MachineEntry, config: KitConfig) -> tuple[str, ...]:
    """Fields of this machine still holding the value ``kit init`` wrote.

    Not refusals: "Plant 1", ``DE`` and 2025 can all be true. But a value nobody chose is
    sealed into the manifest and the report as if somebody had (the country is carried into
    Article 14 filings), so it is named, in ``check``, in the run output and in ``run.json``.
    """
    held = starter_values(site=config.site, country=config.country, year=entry.year,
                          serial=entry.serial)
    if not held:
        return ()
    names = ", ".join(f"{k}={v!r}" for k, v in held.items())
    return (f"{names} -- still the value `kit init` wrote. It is sealed as this machine's "
            "own and printed in the report. If it is correct, ignore this; if you did not "
            "choose it, edit kit.json.",)


def _prepare(
    entry: MachineEntry, config: KitConfig,
) -> tuple[CollectionPlan | None, Path, MachineResult | None]:
    """The plan and the export folder for one machine, or why it cannot be collected."""
    plan_path = config.resolve(entry.plan)
    exports = config.resolve(entry.exports)

    if not plan_path.exists():
        return None, exports, MachineResult(
            serial=entry.serial, status="failed",
            detail=f"plan {plan_path} does not exist")
    if not exports.is_dir():
        return None, exports, MachineResult(
            serial=entry.serial, status="failed",
            detail=f"export folder {exports} does not exist")
    try:
        plan = CollectionPlan.from_json(plan_path)
    except AssuranceError as exc:
        return None, exports, MachineResult(
            serial=entry.serial, status="failed",
            detail=f"plan {plan_path.name} is unusable: {exc}")
    return plan, exports, None


def _collect(
    entry: MachineEntry, config: KitConfig, plan: CollectionPlan, exports: Path,
    taken_at: datetime | None, read_from_machine: bool,
) -> tuple[CollectionResult | None, MachineResult | None]:
    try:
        result = collect(
            plan, exports,
            serial=entry.serial,
            taken_by=config.actor,
            site=config.site,
            country=config.country,
            year=entry.year,
            source=ManifestSource.AS_FOUND,
            taken_at=taken_at,
            notes=entry.notes,
            hash_source=HashSource.READ_FROM_MACHINE if read_from_machine
            else HashSource.SUPPLIED_BY_VENDOR,
        )
    except AssuranceError as exc:
        return None, MachineResult(
            serial=entry.serial, status="failed", plan_id=plan.plan_id, detail=str(exc))
    return result, None


def inspect_machine(
    entry: MachineEntry, config: KitConfig,
) -> tuple[CollectionPlan | None, CollectionResult | None, MachineResult | None]:
    """What ``run`` would read for one machine, read-only: no ledger, no sealing, no output.

    The same preparation and the same :func:`~assurance.collect.collector.collect` call
    ``run`` makes, so ``check`` cannot say "ready" about a file ``run`` then cannot read.
    The third element is the failure, when the machine cannot even be collected.
    """
    plan, exports, failed = _prepare(entry, config)
    if plan is None:
        return None, None, failed
    result, failed = _collect(entry, config, plan, exports, None, False)
    return plan, result, failed


def _enrol_one(
    entry: MachineEntry,
    config: KitConfig,
    ledger: EvidenceLedger,
    taken_at: datetime | None,
    read_from_machine: bool = False,
    seal_incomplete: bool = False,
) -> MachineResult:
    plan, exports, failed = _prepare(entry, config)
    if plan is None:
        assert failed is not None
        return failed
    plan_path = config.resolve(entry.plan)

    for label, value in (("manufacturer", plan.manufacturer), ("model", plan.model)):
        if _is_placeholder(value):
            return MachineResult(
                serial=entry.serial, status="failed", plan_id=plan.plan_id,
                detail=(
                    f"plan {plan_path.name} still says {label}={value!r}. The "
                    "manufacturer and model are the machine's identity; a "
                    "manifest carrying a template value describes nothing and "
                    "cannot be matched to a supplier advisory later."
                ))

    result, failed = _collect(entry, config, plan, exports, taken_at, read_from_machine)
    if result is None:
        assert failed is not None
        return failed

    template_suppliers = sorted(
        {i.item_id for i in plan.items if _is_placeholder(i.supplier)})
    warnings = starter_warnings(entry, config) + tuple(result.warnings) + ((
        f"the supplier of {', '.join(template_suppliers)} is still a template value in "
        f"{plan_path.name}; an advisory matches on the supplier, so it will not match "
        "these items until it is filled in.",) if template_suppliers else ())
    common: dict[str, Any] = {
        "serial": entry.serial, "items": len(result.manifest.items),
        "plan_id": plan.plan_id, "warnings": warnings, "outcomes": result.outcomes,
    }
    # The configuration hash names a manifest that is in the ledger; a machine whose
    # manifest was not sealed has none to name.
    sealed_hash = result.manifest.configuration_hash()

    if result.complete:
        record_manifest(ledger, result.manifest, actor=config.actor)
        return MachineResult(
            status="recorded", sealed=True, configuration_hash=sealed_hash,
            detail=result.summary().splitlines()[0] if result.summary() else "", **common)

    # An incomplete collection is a first-class outcome, but it is not THE configuration of
    # the machine: a sealed manifest becomes the baseline every later comparison starts from
    # with the missing items absent from it (COLLECT.md). So it is sealed only when the
    # operator asked for exactly that; otherwise the attempt is recorded in the run record
    # (with the missing item ids and why) and nothing describes this machine in the ledger.
    missing = ", ".join(
        f"{o.item_id} ({o.status})" for o in result.outcomes if not o.ok)
    if seal_incomplete:
        record_manifest(ledger, result.manifest, actor=config.actor)
        return MachineResult(
            status="incomplete", sealed=True, configuration_hash=sealed_hash,
            detail=f"SEALED INCOMPLETE at your request (--seal-incomplete); not collected: "
                   f"{missing}", **common)
    return MachineResult(
        status="incomplete", sealed=False,
        detail=f"NOT SEALED: the collection is incomplete; not collected: {missing}. Fix the "
               "export folder or the plan and run again", **common)


def _outcome_phrase(o: ItemOutcome) -> str:
    """One item, as the report and the terminal both say it: what it was, where from."""
    if o.ok:
        files = ", ".join(o.files) if o.files else "no file"
        return (f"{o.item_id} read from {files} (digest {o.digest[:12]}, "
                + (f"version {o.version}" if o.version else "version unknown") + ")")
    return f"{o.item_id} {o.status.upper()}: {o.detail}"


def machine_limits(results: Iterable[MachineResult]) -> tuple[str, ...]:
    """What the report must say about each machine that the fleet record cannot.

    The fleet record only knows what was sealed. A machine whose collection was
    incomplete, or that failed before any file was read, is invisible in it, and a report
    that is silent about that reads as a clean run. One entry per such machine, plus the
    per-item reading (what was read, from which file) for every machine the kit looked at.
    """
    out: list[str] = []
    for m in results:
        if m.status == "failed":
            out.append(f"Machine {m.serial} was NOT recorded: {m.detail.rstrip('.')}.")
            continue
        read = "; ".join(_outcome_phrase(o) for o in m.outcomes)
        if m.status == "incomplete" and m.sealed:
            out.append(
                f"Machine {m.serial} was sealed INCOMPLETE at the operator's request "
                f"(--seal-incomplete). Not collected: {', '.join(m.missing)}. Its manifest "
                "carries the incomplete-collection marker; nothing derived from it says "
                f"anything about those items. What was and was not read: {read}.")
        elif m.status == "incomplete":
            out.append(
                f"Machine {m.serial} was NOT sealed: its collection was incomplete "
                f"(not collected: {', '.join(m.missing)}), so no manifest of this machine is "
                "in this ledger and nothing here describes its configuration. What was and "
                f"was not read: {read}.")
        else:
            out.append(f"Machine {m.serial} was sealed. What was read: {read}.")
        for o in m.outcomes:
            out.extend(f"Machine {m.serial}, {o.item_id}: {w}" for w in o.warnings)
    return tuple(out)


def run_kit(
    config: KitConfig,
    out_dir: str | Path,
    *,
    allow_loopback: bool = False,
    now: datetime | None = None,
    read_from_machine: bool = False,
    seal_incomplete: bool = False,
) -> KitRun:
    """Enrol every machine in *config*, offline, into a ledger under *out_dir*.

    Everything substantive happens under the airgap guard. The airgap record is
    sealed afterwards — see the module docstring for why — and the head is read
    last so that it covers that record too.

    ``read_from_machine`` is the operator's assertion that the kit ran on the
    machines; without it every item is ``supplied_by_vendor``.

    ``seal_incomplete`` has the meaning it has for ``collect run``: a machine whose
    collection is incomplete is NOT sealed unless it is set, because a sealed manifest
    becomes the machine's current one with the missing items absent from every later
    comparison.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    started = format_utc(now if now is not None else utc_now())

    ledger_path = out / "evidence.db"
    report_path = out / "report.html"
    request_path = out / "attestation-request.json"
    run_path = out / "run.json"

    ledger = EvidenceLedger(ledger_path)
    # An existing ledger is appended to, so its chain is walked first: appending to a broken
    # chain would seal fresh records and an attestation request over a ledger that no longer
    # verifies. Refused with nothing written (the same rule as machinery enrolment).
    chain_ok, chain_problems = ledger.verify_chain()
    if not chain_ok:
        raise KitError(
            f"{ledger_path} does not verify as a hash chain, so nothing was recorded: "
            + "; ".join(chain_problems[:3])
            + ". Do not append to it. Keep it as evidence, and run into a new --out folder.")
    results: list[MachineResult] = []

    with no_network(allow_loopback=allow_loopback) as airgap:
        for entry in config.machines:
            results.append(_enrol_one(
                entry, config, ledger, now, read_from_machine, seal_incomplete))

    # Outside the guard, deliberately: a record of a guard cannot be written
    # while the guard it describes is still running.
    ledger.append(
        Evidence(
            kind=AIRGAP_KIND,
            body={
                **airgap.to_dict(),
                "covers": (
                    "Reading the export folders and sealing every manifest for "
                    "this run — the whole of the part that touches the "
                    "customer's files. Report rendering and this record itself "
                    "happened after the guard released."
                ),
            },
            actor=config.actor,
            origin=Origin(
                system="assurance.kit.airgap",
                reference=config.kit_id,
                method=("socket-layer guard and Python audit hook armed for the duration of "
                    "the run"),
            ),
            validation_state=ValidationState.VERIFIED,
            checks_skipped=AIRGAP_LIMITS,
        ).seal(),
        subject=config.kit_id,
    )

    finished = format_utc(now if now is not None else utc_now())
    limits = kit_limits(read_from_machine)
    run = KitRun(
        kit_id=config.kit_id,
        started_at=started,
        finished_at=finished,
        organisation=config.organisation,
        machines=tuple(results),
        airgap=airgap,
        ledger_path=str(ledger_path),
        report_path=str(report_path),
        attest_request_path=str(request_path),
        head={},
        checks_skipped=limits,
        read_from_machine_asserted=read_from_machine,
    )

    # The run record is sealed before the head is read, so that the attestation
    # request covers it. A head taken before the last append would be stale the
    # moment it was written, and an attestation of a stale head is worse than
    # none: it looks like coverage and is not.
    ledger.append(
        Evidence(
            kind=KIT_RUN_KIND,
            body={k: v for k, v in run.to_dict().items() if k != "head"},
            actor=config.actor,
            origin=Origin(
                system="assurance.kit",
                reference=config.kit_id,
                method="offline enrolment kit",
            ),
            validation_state=ValidationState.VERIFIED,
            checks_skipped=limits,
        ).seal(),
        subject=config.kit_id,
    )

    report_path.write_text(
        render_report(ReportInput(
            ledger=ledger,
            organisation=config.organisation,
            prepared_by=config.prepared_by,
            generated_at=now,
            extra_limits=machine_limits(results) + AIRGAP_LIMITS + limits,
        )),
        encoding="utf-8")

    head = ledger.head_attestation()
    request_path.write_text(json.dumps({
        "ledger_length": head["length"],
        "head_seq": head["head_seq"],
        "head_link_hash": head["head_link_hash"],
        "note": f"{config.kit_id} offline enrolment {finished}",
        "how": (
            "POST this body to /v1/ledger/attest with your API key to have the "
            "head counter-signed by a key you do not hold. Your ledger stays "
            "here; these three numbers are all that travels."
        ),
    }, indent=2) + "\n", encoding="utf-8")

    run = replace(run, head=head)
    run_path.write_text(
        json.dumps(run.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return run
