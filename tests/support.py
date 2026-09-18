"""Synthetic vendor exports and collection plans, shared across test modules.

Deliberately free of a ``pytest`` import: the cold-start CI job
(``.github/workflows/assurance.yml``) imports ``write_export`` from a bare
``pip install -e '.[assurance-attest]'`` checkout, which does not install
pytest. A test module that pulls it in at import time makes that job fail for
a reason that has nothing to do with the offline kit — which is exactly what
happened before this module existed.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

from assurance.collect.plan import CollectionPlan

__all__ = ["FUNCS", "write_export", "plan_dict", "plan"]

FUNCS = [
    {"function_id": "SF-01", "description": "Protective stop on zone intrusion",
     "required_performance": "PL d",
     "verified_by": ["ssm_separation", "stop_characterisation"]},
    {"function_id": "SF-02", "description": "Speed limit in collaborative operation",
     "required_performance": "PL d", "verified_by": ["speed_limit"]},
]


def write_export(root: Path, *, stamp: str, operator: str, seq: str,
                 radius: int = 1500, fw: bytes = b"firmware 3.8.2") -> Path:
    """A folder of vendor exports, with the volatile headers real tools stamp."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "scanner-zones.cfg").write_text(
        f"# Exported {stamp} by {operator}\n"
        f"# Export sequence no: {seq}\n"
        f"[zone.1]\ntype=protective\nradius_mm={radius}\nresponse_ms=62\n",
        encoding="utf-8")
    (root / "robot-params.json").write_text(json.dumps({
        "export": {"timestamp": stamp, "operator": operator},
        "safety": {"max_tcp_speed_mm_s": 400, "stop_category": 1},
        "firmware": {"version": "3.8.2"},
    }), encoding="utf-8")
    with zipfile.ZipFile(root / "plc-project.zip", "w") as z:
        z.writestr(zipfile.ZipInfo("program/main.st", date_time=(2026, 1, 1, 0, 0, 0)),
                   "PROGRAM Main\n  SafeStop := NOT ZoneClear;\nEND_PROGRAM\n")
        z.writestr(zipfile.ZipInfo("meta/build.txt",
                                   date_time=(2026, 9, int(seq[-1]) or 1, 0, 0, 0)),
                   f"built {stamp} seq {seq}\n")
    (root / "controller-fw.bin").write_bytes(b"\x7fELF" + fw * 20)
    return root


def plan_dict(*, tuned: bool = True) -> dict:
    items = [
        {"item_id": "ITM-ZONES", "kind": "safety_configuration",
         "name": "Safety scanner zone set", "source": "scanner-zones.cfg",
         "supplier": "ScanCo", "implements": ["SF-01"],
         "modifiable_in_field": True},
        {"item_id": "ITM-PARAMS", "kind": "parameter_set",
         "name": "Robot safety parameter set", "source": "robot-params.json",
         "supplier": "RoboCo", "implements": ["SF-01", "SF-02"]},
        {"item_id": "ITM-PLC", "kind": "safety_program",
         "name": "Safety PLC project", "source": "plc-project.zip",
         "supplier": "ControlCo", "implements": ["SF-01"]},
        {"item_id": "ITM-FW", "kind": "firmware",
         "name": "Safety controller firmware", "source": "controller-fw.bin",
         "supplier": "ControlCo", "implements": ["SF-01", "SF-02"]},
    ]
    if tuned:
        items[0]["rule"] = {
            "kind": "text_excluding",
            "patterns": [r"^#\s*Exported ", r"^#\s*Export sequence no:"],
            "note": "the scanner tool stamps time, operator and sequence.",
        }
        items[1]["rule"] = {
            "kind": "json_excluding",
            "keys": ["export.timestamp", "export.operator"],
            "note": "RParam records who exported and when.",
        }
        items[1]["version"] = {"kind": "json", "value": "firmware.version"}
        items[2]["rule"] = {
            "kind": "zip_members", "members": ["program/main.st"],
            "note": "archive member timestamps move on every save.",
        }
    return {
        "plan_id": "PLAN-AR7", "manufacturer": "Grimaldi", "model": "AR-7",
        "procedure": "Export from the three vendor tools into one folder.",
        "functions": FUNCS, "items": items,
    }


def plan(**kw) -> CollectionPlan:
    return CollectionPlan.from_dict(plan_dict(**kw))
