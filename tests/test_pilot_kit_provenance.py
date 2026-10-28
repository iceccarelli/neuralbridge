"""Files read from an export folder are not "read from the machine".

The collector hard-coded ``hash_source=read_from_machine`` for every item, so the
kit printed ``tier validated`` over evidence its own limit list described as "read
from exported files, not from the machines", and the change workflow accepted a kit
manifest as a look at the machine. A folder of files cannot show which machine, if
any, they came off. Only the operator knows whether the collector ran ON the
machine, so that label is now an explicit, recorded operator assertion.
"""

from __future__ import annotations

import json
import re

from assurance.collect.cli import main as collect_main
from assurance.collect.collector import collect
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.kit.cli import main as kit_main
from assurance.machinery.manifest import (
    HashSource,
    ManifestSource,
    SafetyManifest,
    not_a_look,
)
from assurance.machinery.record import manifests_from_ledger

from .support import plan, write_export
from .test_pilot_kit_template import MACHINE, scaffold_filled_kit


def _kit_manifest(tmp_path, *extra) -> tuple[SafetyManifest, dict, str]:
    kit = scaffold_filled_kit(tmp_path / "plant", stamp="2026-09-14T06:02:11Z", seq="0040")
    out = tmp_path / "out"
    assert kit_main(["run", str(kit / "kit.json"), "--out", str(out), "--json", *extra]) == 0
    manifest = manifests_from_ledger(EvidenceLedger(out / "evidence.db"), MACHINE)[-1]
    run = json.loads((out / "run.json").read_text())
    return manifest, run, (out / "report.html").read_text()


class TestTheKitDoesNotClaimItLookedAtTheMachine:
    def test_every_item_is_supplied_by_vendor_by_default(self, tmp_path):
        manifest, _, _ = _kit_manifest(tmp_path)
        assert {i.hash_source for i in manifest.items} == {HashSource.SUPPLIED_BY_VENDOR}
        assert manifest.tier_ceiling.value == "community"

    def test_a_kit_manifest_is_not_a_look_at_the_machine(self, tmp_path):
        manifest, _, _ = _kit_manifest(tmp_path)
        assert manifest.source is ManifestSource.AS_FOUND
        why = not_a_look(manifest)
        assert why and "supplied by a vendor" in why

    def test_the_report_does_not_print_tier_validated_for_export_folder_evidence(self, tmp_path):
        _, _, html = _kit_manifest(tmp_path)
        assert "tier validated" not in html
        # the machine block's own header, not just any mention elsewhere on the page
        assert re.search(r"item\(s\) · tier ceiling community</span>", html)

    def test_the_run_record_says_the_files_were_not_asserted_to_come_off_the_machine(
            self, tmp_path):
        _, run, _ = _kit_manifest(tmp_path)
        assert run["read_from_machine_asserted"] is False
        assert any("supplied_by_vendor" in c and "community" in c
                   for c in run["checks_skipped"])


class TestTheOperatorCanAssertTheCollectorRanOnTheMachine:
    def test_the_flag_labels_items_read_from_machine_and_records_who_said_so(self, tmp_path):
        manifest, run, html = _kit_manifest(tmp_path, "--read-from-machine")
        assert {i.hash_source for i in manifest.items} == {HashSource.READ_FROM_MACHINE}
        assert not_a_look(manifest) == ""
        assert run["read_from_machine_asserted"] is True
        # Recorded in the manifest itself, where a later reader finds it ...
        assert "OPERATOR ASSERTION" in manifest.method
        assert all("OPERATOR ASSERTION" in i.notes for i in manifest.items)
        # ... in the run record's limits, and in the report.
        assert any("operator asserted" in c.lower() for c in run["checks_skipped"])
        assert "operator asserted" in html.lower()

    def test_the_flag_is_not_implied_by_anything_else(self, tmp_path):
        """A loopback allowance or a json flag must not change the label."""
        manifest, _, _ = _kit_manifest(tmp_path, "--allow-loopback")
        assert {i.hash_source for i in manifest.items} == {HashSource.SUPPLIED_BY_VENDOR}


class TestCollectRun:
    def _run(self, tmp_path, capsys, *extra):
        root = write_export(tmp_path / "exports", stamp="2026-09-14T06:02:11Z",
                            operator="m.keller", seq="0040")
        plan_path = tmp_path / "plan.json"
        from .support import plan_dict
        plan_path.write_text(json.dumps(plan_dict()))
        out = tmp_path / "m.json"
        capsys.readouterr()
        rc = collect_main(["run", str(plan_path), "--root", str(root), "--serial", "0412",
                           "--actor", "a.rossi", "--out", str(out), *extra])
        capsys.readouterr()
        assert rc == 0
        return SafetyManifest.from_json(out)

    def test_default_is_supplied_by_vendor(self, tmp_path, capsys):
        manifest = self._run(tmp_path, capsys)
        assert {i.hash_source for i in manifest.items} == {HashSource.SUPPLIED_BY_VENDOR}

    def test_flag_is_read_from_machine_with_the_assertion_recorded(self, tmp_path, capsys):
        manifest = self._run(tmp_path, capsys, "--read-from-machine")
        assert {i.hash_source for i in manifest.items} == {HashSource.READ_FROM_MACHINE}
        assert "OPERATOR ASSERTION" in manifest.method

    def test_as_declared_cannot_be_combined_with_the_assertion(self, tmp_path, capsys):
        """A baseline built from a release is not a machine, whatever the flag says."""
        root = write_export(tmp_path / "exports", stamp="2026-09-14T06:02:11Z",
                            operator="m.keller", seq="0040")
        from .support import plan_dict
        plan_path = tmp_path / "plan.json"
        plan_path.write_text(json.dumps(plan_dict()))
        rc = collect_main(["run", str(plan_path), "--root", str(root), "--serial", "0412",
                           "--actor", "a.rossi", "--as-declared", "--read-from-machine"])
        assert rc == 2
        assert "as-declared" in capsys.readouterr().err


class TestTheLibraryDefault:
    def test_collect_defaults_to_the_fail_safe_label(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="2026-09-14T06:02:11Z",
                            operator="m.keller", seq="0040")
        result = collect(plan(), root, serial="0412",
                         taken_by=Actor(identifier="a.rossi", role="engineer", kind="person"))
        assert {i.hash_source for i in result.manifest.items} == {HashSource.SUPPLIED_BY_VENDOR}

    def test_a_collection_cannot_be_labelled_declared(self, tmp_path):
        import pytest

        from assurance.collect.collector import CollectionError

        root = write_export(tmp_path / "e", stamp="2026-09-14T06:02:11Z",
                            operator="m.keller", seq="0040")
        with pytest.raises(CollectionError):
            collect(plan(), root, serial="0412",
                    taken_by=Actor(identifier="a.rossi", role="engineer", kind="person"),
                    hash_source=HashSource.DECLARED)


class TestWatchTargetsCarryTheSameAssertion:
    """``watch run`` reads export folders too, and its manifests are what hosted ingest judges."""

    def _watch(self, tmp_path, *, asserted: bool):
        import json as _json

        from assurance.watch.config import WatchConfig
        from assurance.watch.runner import run_watch

        from .support import plan_dict

        (tmp_path / "plan.json").write_text(_json.dumps(plan_dict()))
        write_export(tmp_path / "0412", stamp="2026-09-14T06:00:00Z", operator="m.tech",
                     seq="4181")
        target = {"serial": "0412", "plan": "plan.json", "root": "0412",
                  "site": "Plant 2", "country": "DE"}
        if asserted:
            target["read_from_machine"] = True
        (tmp_path / "watch.json").write_text(_json.dumps({
            "watch_id": "W", "max_age_hours": 168, "targets": [target]}))
        config = WatchConfig.from_json(tmp_path / "watch.json")
        ledger = EvidenceLedger(tmp_path / "ev.db")
        run_watch(config, ledger)
        return config, manifests_from_ledger(ledger, "Grimaldi/AR-7#0412")[-1]

    def test_a_target_is_not_asserted_by_default(self, tmp_path):
        config, manifest = self._watch(tmp_path, asserted=False)
        assert config.targets[0].read_from_machine is False
        assert {i.hash_source for i in manifest.items} == {HashSource.SUPPLIED_BY_VENDOR}
        assert not_a_look(manifest)

    def test_the_assertion_survives_loading_the_config_and_labels_the_manifest(self, tmp_path):
        config, manifest = self._watch(tmp_path, asserted=True)
        assert config.targets[0].read_from_machine is True
        assert config.targets[0].to_dict()["read_from_machine"] is True
        assert {i.hash_source for i in manifest.items} == {HashSource.READ_FROM_MACHINE}
        assert "OPERATOR ASSERTION" in manifest.method
