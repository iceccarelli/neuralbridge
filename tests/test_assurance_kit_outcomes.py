"""What the kit tells the integrator about each item, and what it refuses to seal.

A first-time integrator installs the kit, fills in ``kit.json`` and the plan, runs it, and
has to learn (1) what is wrong before anything is sealed, (2) that template data is never
sealed as real, (3) that an incomplete machine is never sealed as THE configuration
without being told, and (4) from a readable report, what was and was not read and from
which file. These tests drive the real CLI entry point on synthetic exports.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.kit.cli import main as kit_main
from assurance.machinery.manifest import INCOMPLETE_COLLECTION_MARK
from assurance.machinery.record import MANIFEST_KIND

from .support import plan_dict, write_export


def make_kit(root: Path, serials=("AR7-1001",), **over) -> Path:
    """A filled-in kit: real-looking identity, a tuned plan, one export folder per serial."""
    plan = plan_dict()
    plan["manufacturer"], plan["model"] = "Acme Robotics", "AR-7"
    (root / "plans").mkdir(parents=True, exist_ok=True)
    (root / "plans" / "cell.json").write_text(json.dumps(plan), encoding="utf-8")
    for n, serial in enumerate(serials):
        write_export(root / "exports" / serial, stamp="2026-09-14T06:02:11Z",
                     operator="m.keller", seq=f"004{n}", radius=1500 + n)
    body = {
        "kit_id": "outcomes-kit", "organisation": "Acme Integration GmbH",
        "site": "Hamburg Works", "country": "DE", "prepared_by": "Jane Doe",
        "role": "integrator",
        "machines": [{"serial": s, "plan": "plans/cell.json", "exports": f"exports/{s}",
                      "year": "2024"} for s in serials],
    }
    body.update(over)
    (root / "kit.json").write_text(json.dumps(body), encoding="utf-8")
    return root / "kit.json"


def run_cli(*argv: str) -> int:
    return kit_main(list(argv))


def ledger_kinds(out: Path) -> list[str]:
    return [e.kind for e in EvidenceLedger(out / "evidence.db").entries()]


def run_record(out: Path) -> dict:
    ledger = EvidenceLedger(out / "evidence.db")
    return next(e for e in ledger.entries() if e.kind == "kit.run").payload["body"]


class TestAnIncompleteMachineIsNotSealedAsTheConfiguration:
    def test_a_machine_missing_an_export_is_not_sealed_and_the_attempt_is_recorded(
            self, tmp_path, capsys):
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
        out = tmp_path / "out"

        rc = run_cli("run", str(kit), "--out", str(out))
        text = capsys.readouterr().out

        assert rc == 2                                    # nothing was recorded
        assert MANIFEST_KIND not in ledger_kinds(out)     # no baseline for Watch to inherit
        machine = run_record(out)["machines"][0]
        assert machine["status"] == "incomplete"
        assert machine["sealed"] is False
        assert machine["missing"] == ["ITM-PLC"]
        assert machine["configuration_hash"] == ""        # there is no sealed manifest to name
        # The terminal says it, in words, before the integrator walks away
        assert "NOT sealed" in text and "ITM-PLC" in text
        # ... and run.json says it
        on_disk = json.loads((out / "run.json").read_text())
        assert on_disk["machines"][0]["missing"] == ["ITM-PLC"]
        assert on_disk["machines"][0]["sealed"] is False

    def test_the_report_names_the_machine_and_the_missing_item(self, tmp_path):
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
        out = tmp_path / "out"
        run_cli("run", str(kit), "--out", str(out))
        html = (out / "report.html").read_text()
        assert "AR7-1001 was NOT sealed" in html
        assert "not collected: ITM-PLC" in html

    def test_a_complete_machine_beside_an_incomplete_one_is_still_sealed(self, tmp_path):
        kit = make_kit(tmp_path, ("AR7-1001", "AR7-1002"))
        (tmp_path / "exports" / "AR7-1002" / "controller-fw.bin").unlink()
        out = tmp_path / "out"

        rc = run_cli("run", str(kit), "--out", str(out))

        assert rc == 1                                    # a finding; evidence was produced
        sealed = [e.subject for e in EvidenceLedger(out / "evidence.db").entries()
                  if e.kind == MANIFEST_KIND]
        assert sealed == ["Acme Robotics/AR-7#AR7-1001"]
        statuses = {m["serial"]: m["status"] for m in run_record(out)["machines"]}
        assert statuses == {"AR7-1001": "enrolled", "AR7-1002": "incomplete"}

    def test_seal_incomplete_seals_exactly_what_collect_run_would(self, tmp_path, capsys):
        """The flag has the meaning ``collect run --seal-incomplete`` has: the manifest is
        sealed with the incomplete-collection marker, and the operator was told."""
        kit = make_kit(tmp_path)
        (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
        out = tmp_path / "out"

        rc = run_cli("run", str(kit), "--out", str(out), "--seal-incomplete")
        text = capsys.readouterr().out

        assert rc == 2                                    # still not a clean run
        entries = [e for e in EvidenceLedger(out / "evidence.db").entries()
                   if e.kind == MANIFEST_KIND]
        assert len(entries) == 1
        assert INCOMPLETE_COLLECTION_MARK in entries[0].payload["body"]["manifest"]["notes"]
        machine = run_record(out)["machines"][0]
        assert machine["status"] == "incomplete" and machine["sealed"] is True
        assert "SEALED INCOMPLETE" in machine["detail"]
        assert "was sealed INCOMPLETE at the operator" in (out / "report.html").read_text()
        assert "NOT sealed" not in text

    def test_a_failed_machine_is_in_the_report_too(self, tmp_path):
        kit = make_kit(tmp_path, ("AR7-1001", "AR7-1002"))
        import shutil

        shutil.rmtree(tmp_path / "exports" / "AR7-1002")
        out = tmp_path / "out"
        assert run_cli("run", str(kit), "--out", str(out)) == 1
        assert "Machine AR7-1002 was NOT recorded" in (out / "report.html").read_text()


@pytest.mark.parametrize("flag", [[], ["--json"]])
def test_json_mode_carries_the_same_facts(tmp_path, capsys, flag):
    kit = make_kit(tmp_path)
    (tmp_path / "exports" / "AR7-1001" / "plc-project.zip").unlink()
    run_cli("run", str(kit), "--out", str(tmp_path / "out"), *flag)
    text = capsys.readouterr().out
    if flag:
        machine = json.loads(text)["machines"][0]
        assert machine["missing"] == ["ITM-PLC"] and machine["sealed"] is False
    else:
        assert "ITM-PLC" in text
