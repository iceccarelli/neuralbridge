"""A complete worked fleet, built from nothing, in one command.

Somebody who has just installed this has a package with seven domains and no
idea where to start. That person is an evaluating engineer with twenty minutes,
and if the first twenty minutes produce nothing they can see, there is no
twenty-first.

:func:`build_demo` writes a real ledger: four machines collected from real
files through real normalisation rules, verified against a real safety envelope,
one of them updated by a technician who re-ran nothing, one of them running an
artefact that contradicts its own version label. Every record is sealed and the
chain verifies. Nothing here is a fixture or a stub — it is the same code path a
customer runs, driven with invented data, and the findings it produces are the
findings the engine actually makes.

The data is invented and the module says so in the ledger itself: every evidence
object carries a ``checks_skipped`` line naming it as demonstration data, so a
demo ledger can never be mistaken for a real one.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.collect.collector import collect
from assurance.collect.plan import CollectionPlan
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
)
from assurance.fleet.declaration import DeclarationOfConformity
from assurance.machine.bundle import build_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.record import record_intervention, record_manifest

__all__ = ["DEMO_NOTICE", "DemoFleet", "build_demo"]

DEMO_NOTICE = (
    "DEMONSTRATION DATA. These machines do not exist. The engine, the rules and "
    "the findings are real; the figures were invented to exercise them."
)

ENG = Actor("a.integrator", "safety engineer")
TECH = Actor("m.tech", "service technician")

_FUNCTIONS = [
    {"function_id": "SF-01", "description": "Protective stop on zone intrusion",
     "required_performance": "PL d",
     "verified_by": ["ssm_separation", "stop_characterisation"]},
    {"function_id": "SF-02", "description": "Speed limit in collaborative operation",
     "required_performance": "PL d", "verified_by": ["speed_limit"]},
    {"function_id": "SF-03", "description": "Emergency stop, category 1",
     "required_performance": "PL d", "verified_by": []},
]

_PLAN: dict[str, Any] = {
    "plan_id": "PLAN-AR7",
    "manufacturer": "Grimaldi",
    "model": "AR-7",
    "procedure": "Export from the scanner tool, RParam and the PLC IDE into one "
                 "folder, then run the collection.",
    "notes": "Probed against two back-to-back exports and reported STABLE.",
    "functions": _FUNCTIONS,
    "items": [
        {"item_id": "ITM-ZONES", "kind": "safety_configuration",
         "name": "Safety scanner zone set", "source": "scanner-zones.cfg",
         "supplier": "ScanCo", "implements": ["SF-01"],
         "modifiable_in_field": True,
         "rule": {"kind": "text_excluding",
                  "patterns": [r"^#\s*Exported ", r"^#\s*Export sequence no:"],
                  "note": "the scanner tool stamps the export time, the operator "
                          "and a sequence number into a comment header."}},
        {"item_id": "ITM-PARAMS", "kind": "parameter_set",
         "name": "Robot safety parameter set", "source": "robot-params.json",
         "supplier": "RoboCo", "implements": ["SF-01", "SF-02"],
         "rule": {"kind": "json_excluding",
                  "keys": ["export.timestamp", "export.operator"],
                  "note": "RParam records who exported and when."},
         "version": {"kind": "json", "value": "firmware.version"}},
        {"item_id": "ITM-PLC", "kind": "safety_program",
         "name": "Safety PLC project", "source": "plc-project.zip",
         "supplier": "ControlCo", "implements": ["SF-01", "SF-03"],
         "rule": {"kind": "zip_members", "members": ["program/main.st"],
                  "note": "the archive's member timestamps move on every save."}},
        {"item_id": "ITM-FW", "kind": "firmware",
         "name": "Safety controller firmware", "source": "controller-fw.bin",
         "supplier": "ControlCo", "implements": ["SF-01", "SF-02"],
         "version": {"kind": "regex", "value": r"build (\d+\.\d+\.\d+)"}},
    ],
}

#: The firmware ControlCo shipped as 3.8.2, and the one the advisory names.
_FW_382 = b"\x7fELF" + b"ControlCo safety controller build 3.8.2\n" * 24
#: A different artefact wearing the same label: somebody applied a hotfix and
#: the version string did not move. This is the contradiction the fleet catches.
_FW_RELABELLED = (b"\x7fELF" + b"ControlCo safety controller build 3.8.2\n" * 24
                  + b"\nfield hotfix applied 2026-08-30, label unchanged\n")
#: The remedied release.
_FW_390 = b"\x7fELF" + b"ControlCo safety controller build 3.9.0\n" * 24


def _write_export(root: Path, *, stamp: str, operator: str, seq: str,
                  radius: int, firmware: bytes) -> Path:
    """A folder of vendor exports, stamped the way real tools stamp them."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "scanner-zones.cfg").write_text(
        f"# Exported {stamp} by {operator}\n"
        f"# Export sequence no: {seq}\n"
        f"[zone.1]\ntype=protective\nradius_mm={radius}\nresponse_ms=62\n"
        "[zone.2]\ntype=warning\nradius_mm=2600\nresponse_ms=62\n",
        encoding="utf-8")
    (root / "robot-params.json").write_text(json.dumps({
        "export": {"timestamp": stamp, "operator": operator, "tool": "RParam 4.2"},
        "safety": {"max_tcp_speed_mm_s": 400, "reduced_speed_mm_s": 250,
                   "stop_category": 1},
        "firmware": {"version": "3.8.2"},
    }, indent=2), encoding="utf-8")
    with zipfile.ZipFile(root / "plc-project.zip", "w") as z:
        z.writestr(zipfile.ZipInfo("program/main.st", date_time=(2026, 1, 1, 0, 0, 0)),
                   "PROGRAM Main\n  SafeStop := NOT ZoneClear;\nEND_PROGRAM\n")
        z.writestr(zipfile.ZipInfo("meta/build.txt",
                                   date_time=(2026, 9, max(int(seq[-1]), 1), 0, 0, 0)),
                   f"built {stamp} seq {seq}\n")
    (root / "controller-fw.bin").write_bytes(firmware)
    return root


def _envelope() -> SafetyEnvelope:
    return SafetyEnvelope(
        envelope_id="ENV-AR7-2.4.1", product="AR-7 Palletising Cell",
        product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0, OperatingMode.AUTOMATIC: 2000.0,
                            OperatingMode.STOPPED: 0.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-TEST-2026-03-11 rev B",
                                         "2026-03-11")),
        uncertainty=SensingUncertainty(100.0, 50.0,
                                       FigureBasis("measured", "CAL-2026-003",
                                                   "2026-01-18")),
        intrusion_distance_mm=850.0,
        declared_by=ENG,
        notes="Separation figures assume hand/arm detection at the cell perimeter.",
    )


def _trace(serial: str, when: datetime, *, speed: float, separation: float) -> Trace:
    return Trace(
        trace_id=f"RUN-{serial}-{when:%Y%m%d}", provenance=Provenance.FIELD,
        source_system="AR-7 controller fw 3.8.2 / safety scanner log",
        started_at=when, sample_rate_hz=50.0,
        conditions={"payload_kg": 12.5, "tool": "vacuum gripper VG-4"},
        samples=tuple(
            Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=speed,
                   mode=OperatingMode.SSM, separation=separation, human_speed=1400.0)
            for i in range(40)),
    )


@dataclass(frozen=True)
class DemoFleet:
    """Everything the demo built, so a caller can render or inspect it."""

    ledger_path: Path
    exports_root: Path
    plan: CollectionPlan
    advisory: ComponentAdvisory
    declarations: tuple[DeclarationOfConformity, ...]
    entries: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "ledger": str(self.ledger_path),
            "exports": str(self.exports_root),
            "plan_id": self.plan.plan_id,
            "advisory_id": self.advisory.advisory_id,
            "declarations": [d.doc_id for d in self.declarations],
            "entries": self.entries,
            "notice": DEMO_NOTICE,
        }


def build_demo(workdir: str | Path) -> DemoFleet:
    """Build a complete, sealed, four-machine fleet under ``workdir``.

    Returns the ledger and the artefacts a report needs. Every machine is a
    different situation on purpose, because a demo where everything is fine
    demonstrates nothing:

    ``#0412``  clean, covered, and about to be hit by an advisory
    ``#0418``  running an artefact that contradicts its own version label
    ``#0501``  a technician reshaped the safety zone and re-ran nothing
    ``#0620``  already on the remedied firmware
    """
    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    exports = work / "exports"
    ledger = EvidenceLedger(work / "register.db")
    plan = CollectionPlan.from_dict(_PLAN)
    envelope = _envelope()

    feb = datetime(2026, 2, 9, 6, 0, tzinfo=UTC)
    sept = datetime(2026, 9, 13, 7, 20, tzinfo=UTC)

    spec = [
        # serial, site, country, radius, firmware, verified, intervened
        ("0412", "Plant 2, Line 4", "DE", 1500, _FW_382, True, False),
        ("0418", "Plant 2, Line 6", "DE", 1500, _FW_RELABELLED, True, False),
        ("0501", "Plant 7, Cell A", "IT", 1200, _FW_382, True, True),
        ("0620", "Plant 7, Cell C", "CH", 1500, _FW_390, True, False),
    ]

    declarations: list[DeclarationOfConformity] = []

    for serial, site, country, radius, firmware, verified, intervened in spec:
        root = _write_export(
            exports / serial,
            stamp=f"2026-09-13T0{len(serial) % 7}:11:04Z", operator="m.tech",
            seq=f"41{serial[-2:]}", radius=radius, firmware=firmware)

        result = collect(plan, root, serial=serial, taken_by=ENG, site=site,
                         country=country, year="2026", taken_at=sept,
                         manifest_id=f"MAN-{serial}-2026-09")
        record_manifest(ledger, result.manifest)

        declarations.append(DeclarationOfConformity.bind(
            result.manifest, doc_id=f"DOC-AR7-{serial}",
            issued_by="Grimaldi Engineering",
            issued_at=datetime(2026, 1, 20, 9, 0, tzinfo=UTC),
            legislation=("Regulation (EU) 2023/1230", "Regulation (EU) 2024/2847"),
            standards=("EN ISO 10218-1:2025", "EN ISO 10218-2:2025",
                       "EN ISO 13849-1:2023"),
            signatory="V. Grimaldi", place="Turin"))

        if verified:
            # #0501's zone was reshaped to 1200 mm, which is inside the distance
            # the cell actually needs; the February run still passed because the
            # zone was 1500 mm then. That is the point.
            build_bundle(envelope, _trace(serial, feb, speed=400.0,
                                          separation=2200.0),
                         actor=ENG, ledger=ledger,
                         subject=result.manifest.machine.key)

        if intervened:
            record_intervention(ledger, Intervention(
                intervention_id=f"INT-{serial}-0007",
                machine_key=result.manifest.machine.key,
                item_id="ITM-ZONES", kind=InterventionKind.PARAMETER_CHANGE,
                occurred_at=datetime(2026, 8, 2, 11, 15, tzinfo=UTC),
                performed_by=TECH,
                reason="Protective zone reshaped after a conveyor was moved.",
                affects_functions=("SF-01",),
                notes="Recorded from the service report. Nothing was re-run."))

    advisory = ComponentAdvisory(
        advisory_id="CTRL-2026-11", issued_by="ControlCo",
        issued_at=datetime(2026, 9, 12, 8, 0, tzinfo=UTC),
        title="Watchdog may not trip under sustained safety-bus load",
        summary="Under sustained load on the safety bus the watchdog can fail to "
                "trigger the safety-rated stop within the specified reaction time. "
                "The declared stop performance is not achieved.",
        severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.0", "3.8.1", "3.8.2"),
            content_hashes=(__import__("hashlib").sha256(_FW_382).hexdigest(),),
            version_note="All 3.8.x releases before 3.9.0."),),
        remedy="Update to 3.9.0 and re-run the stop-performance test. The declared "
               "reaction time must be re-established, not assumed.",
        reference="https://controlco.example/advisories/CTRL-2026-11",
        fixed_versions=("3.9.0",),
        fixed_hashes=(__import__("hashlib").sha256(_FW_390).hexdigest(),),
    )

    (work / "advisory.json").write_text(
        json.dumps(advisory.to_dict(), indent=2) + "\n", encoding="utf-8")
    (work / "plan.json").write_text(
        json.dumps(plan.to_dict(), indent=2) + "\n", encoding="utf-8")

    return DemoFleet(
        ledger_path=work / "register.db", exports_root=exports, plan=plan,
        advisory=advisory, declarations=tuple(declarations), entries=len(ledger),
    )
