"""The kit as ``kit init`` ships it, run the way a first-day user runs it.

The existing kit tests build their own plan from ``tests/support.plan_dict``,
whose noise rules are written correctly. The plan that ``kit init`` actually
writes was never run, and its first rule had a doubled backslash: the regex it
compiled to was a literal backslash followed by ``s*``, which matches no
``# Exported ...`` header. The effect was a false drift on a safety
configuration whenever a scanner tool re-stamped its own header.
"""

from __future__ import annotations

import json
from pathlib import Path

from assurance.collect.cli import main as collect_main
from assurance.evidence.ledger import EvidenceLedger
from assurance.kit.cli import main as kit_main
from assurance.machinery.record import manifests_from_ledger

from .support import write_export

MACHINE = "Acme/Scan-9#CELL-0412"


def scaffold_filled_kit(root: Path, *, stamp: str, seq: str, fw: bytes = b"firmware 3.8.2",
                        radius: int = 1500) -> Path:
    """``kit init`` for real, then fill in what a person must fill in."""
    assert kit_main(["init", str(root)]) == 0
    kit = json.loads((root / "kit.json").read_text())
    kit.update(organisation="Acme Robotics S.r.l.", prepared_by="a.rossi@acme.example")
    (root / "kit.json").write_text(json.dumps(kit))
    plan = json.loads((root / "plans" / "cell.json").read_text())
    plan.update(manufacturer="Acme", model="Scan-9")
    for item in plan["items"]:
        item["supplier"] = "ScanCo"
    (root / "plans" / "cell.json").write_text(json.dumps(plan))
    exports = root / "exports" / "CELL-0412"
    (exports / "PUT-EXPORTS-HERE.txt").unlink()
    write_export(exports, stamp=stamp, operator="m.keller", seq=seq, fw=fw, radius=radius)
    return root


def run_kit_cli(root: Path, out: Path, *extra: str) -> dict:
    rc = kit_main(["run", str(root / "kit.json"), "--out", str(out), "--json", *extra])
    assert rc == 0
    return json.loads((out / "run.json").read_text())


def item_digests(out: Path) -> dict[str, str]:
    (manifest,) = manifests_from_ledger(EvidenceLedger(out / "evidence.db"), MACHINE)[-1:]
    return {i.item_id: i.content_hash for i in manifest.items}


class TestTheShippedTemplateNoiseRules:
    def test_a_changed_header_stamp_alone_does_not_move_the_zone_digest(self, tmp_path):
        kit = scaffold_filled_kit(tmp_path / "plant", stamp="2026-09-14T06:02:11Z", seq="0040")
        first = tmp_path / "out1"
        run_kit_cli(kit, first)
        # Only the two header lines a scanner tool stamps itself change.
        zones = kit / "exports" / "CELL-0412" / "scanner-zones.cfg"
        text = zones.read_text()
        zones.write_text(
            text.replace("2026-09-14T06:02:11Z", "2026-10-01T17:45:59Z")
            .replace("0040", "0057"))
        second = tmp_path / "out2"
        run_kit_cli(kit, second)
        before, after = item_digests(first), item_digests(second)
        assert before["ITM-ZONES"] == after["ITM-ZONES"], (
            "a re-stamped header read as a change to a safety configuration")

    def test_a_real_zone_change_still_moves_the_zone_digest(self, tmp_path):
        """The rule must not be so loose that it hides the thing it exists to see."""
        kit = scaffold_filled_kit(tmp_path / "plant", stamp="2026-09-14T06:02:11Z", seq="0040")
        run_kit_cli(kit, tmp_path / "out1")
        zones = kit / "exports" / "CELL-0412" / "scanner-zones.cfg"
        zones.write_text(zones.read_text().replace("radius_mm=1500", "radius_mm=900"))
        run_kit_cli(kit, tmp_path / "out2")
        assert (item_digests(tmp_path / "out1")["ITM-ZONES"]
                != item_digests(tmp_path / "out2")["ITM-ZONES"])

    def test_no_shipped_rule_warns_that_it_matched_no_line(self, tmp_path, capsys):
        kit = scaffold_filled_kit(tmp_path / "plant", stamp="2026-09-14T06:02:11Z", seq="0040")
        capsys.readouterr()
        rc = collect_main([
            "run", str(kit / "plans" / "cell.json"),
            "--root", str(kit / "exports" / "CELL-0412"),
            "--serial", "CELL-0412", "--actor", "a.rossi", "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        zones = next(o for o in payload["outcomes"] if o["item_id"] == "ITM-ZONES")
        assert zones["warnings"] == []
        # Both header patterns removed exactly one line each.
        assert sorted(zones["applied"].values()) == [1, 1]
        assert not any("matched no line" in w
                       for o in payload["outcomes"] for w in o["warnings"])

    def test_every_pattern_in_the_shipped_plan_is_a_regex_that_matches_its_own_header(self):
        """The template, not a copy of it: scaffold it and test each pattern."""
        import re

        from assurance.kit.cli import _PLAN

        patterns = _PLAN["items"][0]["rule"]["patterns"]
        # Survives a JSON round trip, which is how a user's file gets read.
        patterns = json.loads(json.dumps(patterns))
        headers = ["# Exported 2026-09-14T06:02:11Z by m.keller",
                   "# Export sequence no: 0040"]
        for header in headers:
            assert any(re.search(p, header) for p in patterns), header
