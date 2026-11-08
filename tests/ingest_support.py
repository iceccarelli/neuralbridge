"""Synthetic documents and helpers for the SBOM / CSAF import tests.

Everything here is SYNTHETIC: DemoCo, ControlCo, Open Motion GmbH, the firmware images, hashes
and advisories are invented for the tests (see ``examples/ingest/``). Nothing describes real
equipment, a real supplier or a real vulnerability.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import enrol_machine
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "ingest"

SERVICE = Actor("assurance-ingest", "importer", "automation")
PERSON = Actor("A. Integrator", "safety engineer", "person")
FW_SHA = "fe21623f37fada0422f8405c6f920036a8bdd84af16ece4f71dad17d6ec19f69"

FUNCTIONS = [
    {"function_id": "SF-01", "description": "Protective separation in speed-and-separation "
     "monitoring", "required_performance": "PL d",
     "verified_by": ["ssm_separation", "stop_characterisation"]},
    {"function_id": "SF-02", "description": "Speed limit in collaborative operation",
     "required_performance": "PL d", "verified_by": ["speed_limit"]},
]


def sbom_doc() -> dict[str, Any]:
    return json.loads((EXAMPLES / "synthetic-sbom.cdx.json").read_text("utf-8"))


def csaf_doc() -> dict[str, Any]:
    return json.loads((EXAMPLES / "synthetic-advisory.csaf.json").read_text("utf-8"))


def raw(doc: Any) -> bytes:
    return json.dumps(doc, indent=2).encode("utf-8")


def spec(doc: dict[str, Any], version: str) -> dict[str, Any]:
    out = copy.deepcopy(doc)
    out["specVersion"] = version
    return out


def approve(template: dict[str, Any], *, serial: str = "DEMO-0001", **identity: str
            ) -> dict[str, Any]:
    """A complete, approving review of the example SBOM's draft, made from its template."""
    req = copy.deepcopy(template)
    req["decision"] = "approve"
    req["reason"] = "checked against the integrator's own software list"
    req["identity"] = {"manufacturer": "DemoCo", "model": "AR-7", "serial": serial,
                       "site": "SYNTHETIC demo cell", "owner": "", "year": "2026",
                       "country": "", **identity}
    req["functions"] = copy.deepcopy(FUNCTIONS)
    for c in req["components"]:
        if c["name"] == "Safety controller firmware":
            c.update(include=True, kind="firmware", implements=["SF-01", "SF-02"],
                     modifiable_in_field=False)
        elif c["name"] == "libmotion":
            c.update(include=True, kind="library", implements=[], modifiable_in_field=False)
        else:
            c.update(include=False)
    return req


def item(name: str, version: str, supplier: str = "ControlCo", *, item_id: str = "",
         content_hash: str = "", source: HashSource = HashSource.DECLARED,
         implements: tuple[str, ...] = ()) -> SafetyItem:
    return SafetyItem(
        item_id=item_id or "ITM-" + name.replace(" ", "-")[:20], kind=ItemKind.FIRMWARE,
        name=name, version=version, content_hash=content_hash, hash_source=source,
        supplier=supplier, implements=implements)


def manifest(serial: str, *items: SafetyItem, notes: str = "",
             source: ManifestSource = ManifestSource.AS_DECLARED,
             manifest_id: str = "") -> SafetyManifest:
    has_functions = any(i.implements for i in items)
    return SafetyManifest(
        manifest_id=manifest_id or f"MAN-{serial}",
        machine=MachineIdentity("DemoCo", "AR-7", serial, site="SYNTHETIC demo cell"),
        source=source, taken_at=datetime(2026, 3, 1, 9, tzinfo=UTC), taken_by=PERSON, items=tuple(items), notes=notes,
        functions=(SafetyFunction("SF-01", "Protective separation", "PL d", ("ssm_separation",)),)
        if has_functions else ())


def enrol(ledger: EvidenceLedger, serial: str, *items: SafetyItem) -> str:
    receipt = enrol_machine(ledger, manifest(serial, *items), actor=PERSON)
    assert receipt.enrolled, receipt.status
    return receipt.machine_key
