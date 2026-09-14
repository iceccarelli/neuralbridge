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
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from ..collect.collector import collect
from ..collect.plan import CollectionPlan
from ..core.errors import AssuranceError
from ..core.evidence import Actor, Evidence, Origin, ValidationState
from ..core.identity import format_utc, utc_now
from ..evidence.ledger import EvidenceLedger
from ..machinery.manifest import ManifestSource
from ..machinery.record import record_manifest
from ..report.render import ReportInput, render_report
from .airgap import AIRGAP_LIMITS, AirgapResult, no_network

__all__ = [
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


#: Values the starter files ship with. A run that reaches a report with one of
#: these still in it has produced a document nobody can act on, addressed from
#: nobody, about a machine made by nobody.
_PLACEHOLDERS = frozenset({
    "change me", "changeme", "your company gmbh", "your company",
    "your.name@yourcompany.example", "yourcompany", "tbd", "todo", "xxx",
})


def _is_placeholder(value: str) -> bool:
    return value.strip().lower() in _PLACEHOLDERS


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
        missing = [k for k in ("serial", "plan", "exports") if not d.get(k)]
        if missing:
            raise KitError(
                "a machine entry needs " + ", ".join(missing)
                + ". A machine with no serial cannot be told apart from another "
                "one later, which is the only thing a fleet record is for."
            )
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
        if not self.machines:
            raise KitError("no machines listed; there is nothing to enrol.")
        seen: set[str] = set()
        for m in self.machines:
            if m.serial in seen:
                raise KitError(
                    f"serial {m.serial} appears twice. Two machines sharing a "
                    "serial produce one record that describes neither."
                )
            seen.add(m.serial)
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
            data = json.loads(p.read_text("utf-8"))
        except json.JSONDecodeError as exc:
            raise KitError(f"{p} is not valid JSON: {exc}") from exc
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
    """What happened to one machine. ``enrolled`` is not the only good outcome."""

    serial: str
    status: str            # enrolled | incomplete | failed
    items: int = 0
    configuration_hash: str = ""
    plan_id: str = ""
    warnings: tuple[str, ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "serial": self.serial, "status": self.status, "items": self.items,
            "configuration_hash": self.configuration_hash, "plan_id": self.plan_id,
            "warnings": list(self.warnings), "detail": self.detail,
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

    @property
    def enrolled(self) -> tuple[MachineResult, ...]:
        return tuple(m for m in self.machines if m.status == "enrolled")

    @property
    def verdict(self) -> str:
        """``complete``, ``partial`` or ``failed``. Never a boolean.

        Deliberately not degraded by the standing caveat every collection
        carries — that a plan only finds what it names. That sentence is true of
        every run that will ever happen, so letting it force PARTIAL every time
        would teach the reader that the verdict means nothing, which is how a
        signal is destroyed. It belongs in what-was-not-checked, and that is
        where it goes. What moves the verdict is a machine that did not enrol,
        a required item that was not found, or a connection attempt.
        """
        if not self.enrolled:
            return "failed"
        if len(self.enrolled) != len(self.machines):
            return "partial"
        if not self.airgap.held:
            return "partial"
        return "complete"

    def summary(self) -> str:
        return (
            f"{self.kit_id} — {len(self.enrolled)}/{len(self.machines)} machine(s) "
            f"enrolled — {self.verdict.upper()}"
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
        }


#: What one offline run cannot establish, whatever it finds. Carried into the
#: run record and printed at the end, because the gap is the argument.
_KIT_LIMITS: tuple[str, ...] = (
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
    "as good as the export, and the export is as good as whoever produced it.",
)


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


def _enrol_one(
    entry: MachineEntry,
    config: KitConfig,
    ledger: EvidenceLedger,
    taken_at: datetime | None,
) -> MachineResult:
    plan_path = config.resolve(entry.plan)
    exports = config.resolve(entry.exports)

    if not plan_path.exists():
        return MachineResult(
            serial=entry.serial, status="failed",
            detail=f"plan {plan_path} does not exist")
    if not exports.is_dir():
        return MachineResult(
            serial=entry.serial, status="failed",
            detail=f"export folder {exports} does not exist")

    try:
        plan = CollectionPlan.from_json(plan_path)
    except AssuranceError as exc:
        return MachineResult(
            serial=entry.serial, status="failed",
            detail=f"plan {plan_path.name} is unusable: {exc}")

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
        )
    except AssuranceError as exc:
        return MachineResult(
            serial=entry.serial, status="failed",
            plan_id=plan.plan_id, detail=str(exc))

    record_manifest(ledger, result.manifest, actor=config.actor)
    return MachineResult(
        serial=entry.serial,
        # "incomplete" is a first-class outcome: a manifest missing a required
        # item is still evidence, and pretending otherwise loses the finding.
        status="enrolled" if result.complete else "incomplete",
        items=len(result.manifest.items),
        configuration_hash=result.manifest.configuration_hash(),
        plan_id=plan.plan_id,
        warnings=tuple(result.warnings),
        detail=result.summary().splitlines()[0] if result.summary() else "",
    )


def run_kit(
    config: KitConfig,
    out_dir: str | Path,
    *,
    allow_loopback: bool = False,
    now: datetime | None = None,
) -> KitRun:
    """Enrol every machine in *config*, offline, into a ledger under *out_dir*.

    Everything substantive happens under the airgap guard. The airgap record is
    sealed afterwards — see the module docstring for why — and the head is read
    last so that it covers that record too.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    started = format_utc(now if now is not None else utc_now())

    ledger_path = out / "evidence.db"
    report_path = out / "report.html"
    request_path = out / "attestation-request.json"
    run_path = out / "run.json"

    ledger = EvidenceLedger(ledger_path)
    results: list[MachineResult] = []

    with no_network(allow_loopback=allow_loopback) as airgap:
        for entry in config.machines:
            results.append(_enrol_one(entry, config, ledger, now))

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
                method="socket-layer guard armed for the duration of the run",
            ),
            validation_state=ValidationState.VERIFIED,
            checks_skipped=AIRGAP_LIMITS,
        ).seal(),
        subject=config.kit_id,
    )

    finished = format_utc(now if now is not None else utc_now())
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
        checks_skipped=_KIT_LIMITS,
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
            checks_skipped=_KIT_LIMITS,
        ).seal(),
        subject=config.kit_id,
    )

    report_path.write_text(
        render_report(ReportInput(
            ledger=ledger,
            organisation=config.organisation,
            prepared_by=config.prepared_by,
            generated_at=now,
            extra_limits=AIRGAP_LIMITS + _KIT_LIMITS,
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
