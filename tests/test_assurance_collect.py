"""Tests for collection: plans, normalisation, and the volatility probe.

The test that carries this module is
``test_the_export_header_moves_and_the_manifest_does_not``. Everything else
exists so that a weekly drift report contains findings and not noise — because a
report that cries wolf is one a safety engineer stops reading, and the week it
matters is the week nobody looks.
"""

from __future__ import annotations

import json
import zipfile
from datetime import UTC, datetime

import pytest

from assurance.collect.collector import CollectionError, collect
from assurance.collect.normalise import (
    NormalisationError,
    Normaliser,
    Rule,
    normalise_bytes,
    normalise_file,
)
from assurance.collect.plan import CollectionPlan, ItemSpec, PlanError, VersionSource
from assurance.collect.volatility import probe
from assurance.core.evidence import Actor
from assurance.core.tiers import AssuranceTier
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import HashSource, ItemKind, ManifestSource

from .support import FUNCS, plan, plan_dict, write_export

ENG = Actor("a.integrator", "safety engineer")

__all__ = ["FUNCS", "plan", "plan_dict", "write_export"]


# =====================================================================
# normalisation
# =====================================================================

class TestNormalisation:
    def test_raw_hashes_the_bytes_as_they_are(self):
        r = normalise_bytes(b"hello", Rule())
        assert r.bytes_hashed == 5
        assert r.kind is Normaliser.RAW

    def test_text_excluding_drops_the_matching_lines(self):
        rule = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^# "],
                    note="header")
        a = normalise_bytes(b"# stamp one\nbody\n", rule)
        b = normalise_bytes(b"# stamp two\nbody\n", rule)
        assert a.digest == b.digest
        assert a.applied[r"^# "] == 1

    def test_a_pattern_that_matched_nothing_is_a_warning_not_a_success(self):
        rule = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^ZZZ"], note="x")
        r = normalise_bytes(b"body\n", rule)
        assert any("matched no line" in w for w in r.warnings)

    def test_json_excluding_ignores_key_order_and_whitespace(self):
        rule = Rule(kind=Normaliser.JSON_EXCLUDING, keys=["meta.when"], note="stamp")
        a = normalise_bytes(b'{"meta":{"when":"1"},"v":1}', rule)
        b = normalise_bytes(b'{ "v" : 1 , "meta" : { "when" : "2" } }', rule)
        assert a.digest == b.digest

    def test_json_excluding_still_sees_a_real_change(self):
        rule = Rule(kind=Normaliser.JSON_EXCLUDING, keys=["meta.when"], note="stamp")
        a = normalise_bytes(b'{"meta":{"when":"1"},"v":1}', rule)
        b = normalise_bytes(b'{"meta":{"when":"1"},"v":2}', rule)
        assert a.digest != b.digest

    def test_a_missing_json_key_is_a_warning(self):
        rule = Rule(kind=Normaliser.JSON_EXCLUDING, keys=["nope"], note="x")
        r = normalise_bytes(b'{"v":1}', rule)
        assert any("was not present" in w for w in r.warnings)

    def test_json_excluding_reaches_into_lists(self):
        rule = Rule(kind=Normaliser.JSON_EXCLUDING, keys=["rows.when"], note="x")
        a = normalise_bytes(b'{"rows":[{"when":"1","v":1},{"when":"2","v":2}]}', rule)
        b = normalise_bytes(b'{"rows":[{"when":"9","v":1},{"when":"8","v":2}]}', rule)
        assert a.digest == b.digest

    def test_zip_members_ignores_everything_else_in_the_archive(self, tmp_path):
        rule = Rule(kind=Normaliser.ZIP_MEMBERS, members=["program/main.st"],
                    note="build metadata moves")
        digests = []
        for day in (1, 2):
            p = tmp_path / f"p{day}.zip"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr(zipfile.ZipInfo("program/main.st",
                                           date_time=(2026, 1, day, 0, 0, 0)), "CODE")
                z.writestr("meta/build.txt", f"built on day {day}")
            digests.append(normalise_file(p, rule).digest)
        assert digests[0] == digests[1]

    def test_a_zip_member_that_is_not_there_is_a_warning_not_a_silent_pass(
            self, tmp_path):
        p = tmp_path / "p.zip"
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("other.txt", "x")
        r = normalise_file(p, Rule(kind=Normaliser.ZIP_MEMBERS,
                                   members=["program/main.st"], note="x"))
        assert any("is not in the archive" in w for w in r.warnings)

    def test_a_rule_that_drops_bytes_must_say_why(self):
        with pytest.raises(NormalisationError, match="carries no note"):
            Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^#"])

    def test_a_text_rule_with_no_patterns_is_refused(self):
        with pytest.raises(NormalisationError, match="drops nothing"):
            Rule(kind=Normaliser.TEXT_EXCLUDING, note="x")

    def test_a_bad_regex_is_refused_at_declaration_time(self):
        with pytest.raises(NormalisationError, match="not a regex"):
            Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=["("], note="x")

    def test_a_binary_file_under_a_text_rule_says_so(self, tmp_path):
        p = tmp_path / "fw.bin"
        p.write_bytes(b"\xff\xfe\x00binary")
        with pytest.raises(NormalisationError, match="binary export"):
            normalise_file(p, Rule(kind=Normaliser.TEXT_EXCLUDING,
                                   patterns=[r"^#"], note="x"))

    def test_the_rule_is_part_of_the_identity(self):
        a = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^#"], note="x")
        b = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^#", r"^;"], note="x")
        assert a.fingerprint() != b.fingerprint()

    def test_the_note_does_not_change_the_identity(self):
        a = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^#"], note="one")
        b = Rule(kind=Normaliser.TEXT_EXCLUDING, patterns=[r"^#"], note="two")
        assert a.fingerprint() == b.fingerprint()


# =====================================================================
# plans
# =====================================================================

class TestPlan:
    def test_a_plan_that_collects_nothing_is_refused(self):
        d = plan_dict()
        d["items"] = []
        with pytest.raises(PlanError, match="collects nothing"):
            CollectionPlan.from_dict(d)

    def test_an_item_crediting_an_undeclared_function_is_refused(self):
        d = plan_dict()
        d["items"][0]["implements"] = ["SF-99"]
        with pytest.raises(PlanError, match="does not declare"):
            CollectionPlan.from_dict(d)

    def test_a_duplicate_item_id_is_refused(self):
        d = plan_dict()
        d["items"].append(dict(d["items"][0]))
        with pytest.raises(PlanError, match="twice"):
            CollectionPlan.from_dict(d)

    def test_a_source_that_climbs_out_of_the_root_is_refused(self):
        with pytest.raises(PlanError, match="climb out"):
            ItemSpec(item_id="X", kind=ItemKind.FIRMWARE, name="x",
                     source="../secrets/key.bin")

    def test_an_absolute_source_is_refused(self):
        with pytest.raises(PlanError, match="relative to the collection root"):
            ItemSpec(item_id="X", kind=ItemKind.FIRMWARE, name="x",
                     source="/etc/passwd")

    def test_the_plan_hash_moves_when_a_rule_changes(self):
        a = plan()
        d = plan_dict()
        d["items"][0]["rule"]["patterns"].append(r"^;")
        assert CollectionPlan.from_dict(d).content_hash() != a.content_hash()

    def test_unmapped_items_are_surfaced(self):
        d = plan_dict()
        d["items"][3]["implements"] = []
        assert [i.item_id for i in CollectionPlan.from_dict(d).unmapped_items] \
            == ["ITM-FW"]

    def test_version_unknown_is_the_default_and_is_honest(self):
        assert VersionSource().read(b'{"v":"1"}') == ""

    def test_a_regex_version_needs_a_capturing_group(self):
        with pytest.raises(PlanError, match="no capturing group"):
            VersionSource(kind="regex", value=r"version")

    def test_a_regex_version_is_read_from_the_file(self):
        v = VersionSource(kind="regex", value=r"version\s*=\s*(\S+)")
        assert v.read(b"name=x\nversion = 3.8.2\n") == "3.8.2"

    def test_a_json_version_is_read_by_dotted_path(self):
        v = VersionSource(kind="json", value="firmware.version")
        assert v.read(b'{"firmware":{"version":"3.9.0"}}') == "3.9.0"

    def test_an_absent_version_reads_empty_rather_than_guessing(self):
        v = VersionSource(kind="json", value="firmware.version")
        assert v.read(b'{"other":1}') == ""

    def test_it_survives_json(self, tmp_path):
        p = tmp_path / "plan.json"
        p.write_text(json.dumps(plan().to_dict()))
        assert CollectionPlan.from_json(p).content_hash() == plan().content_hash()


# =====================================================================
# the probe
# =====================================================================

class TestProbe:
    def test_an_untuned_plan_is_volatile_on_every_stamped_export(self, tmp_path):
        write_export(tmp_path / "mon", stamp="2026-09-14T07:12:03Z",
                     operator="m.tech", seq="4181")
        write_export(tmp_path / "tue", stamp="2026-09-15T06:58:41Z",
                     operator="a.integrator", seq="4199")
        r = probe(plan(tuned=False), tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "volatile"
        assert {i.item_id for i in r.volatile} == {"ITM-ZONES", "ITM-PARAMS",
                                                   "ITM-PLC"}

    def test_the_opaque_firmware_is_stable_even_untuned(self, tmp_path):
        write_export(tmp_path / "mon", stamp="a", operator="x", seq="1")
        write_export(tmp_path / "tue", stamp="b", operator="y", seq="2")
        r = probe(plan(tuned=False), tmp_path / "mon", tmp_path / "tue")
        fw = next(i for i in r.items if i.item_id == "ITM-FW")
        assert fw.stable

    def test_it_shows_the_lines_that_actually_moved(self, tmp_path):
        write_export(tmp_path / "mon", stamp="2026-09-14T07:12:03Z",
                     operator="m.tech", seq="4181")
        write_export(tmp_path / "tue", stamp="2026-09-15T06:58:41Z",
                     operator="a.integrator", seq="4199")
        r = probe(plan(tuned=False), tmp_path / "mon", tmp_path / "tue")
        zones = next(i for i in r.volatile if i.item_id == "ITM-ZONES")
        assert any("Exported" in line for line in zones.differing_lines)

    def test_it_suggests_patterns_for_the_usual_suspects(self, tmp_path):
        write_export(tmp_path / "mon", stamp="2026-09-14T07:12:03Z",
                     operator="m.tech", seq="4181")
        write_export(tmp_path / "tue", stamp="2026-09-15T06:58:41Z",
                     operator="a.integrator", seq="4199")
        r = probe(plan(tuned=False), tmp_path / "mon", tmp_path / "tue")
        zones = next(i for i in r.volatile if i.item_id == "ITM-ZONES")
        looks = {w for _, w in zones.suggested_patterns}
        assert "a date" in looks
        assert "a sequence number" in looks

    def test_a_tuned_plan_is_stable(self, tmp_path):
        write_export(tmp_path / "mon", stamp="2026-09-14T07:12:03Z",
                     operator="m.tech", seq="4181")
        write_export(tmp_path / "tue", stamp="2026-09-15T06:58:41Z",
                     operator="a.integrator", seq="4199")
        r = probe(plan(), tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "stable", r.summary()

    def test_a_real_change_still_shows_as_volatile_and_says_why(self, tmp_path):
        """The probe cannot know the machine was unchanged, and says so."""
        write_export(tmp_path / "mon", stamp="s", operator="o", seq="1")
        write_export(tmp_path / "tue", stamp="s", operator="o", seq="1",
                     radius=1200)
        r = probe(plan(), tmp_path / "mon", tmp_path / "tue")
        assert r.verdict == "volatile"
        assert any("If the machine did change" in c for c in r.checks_skipped)

    def test_an_item_absent_from_both_exports_is_reported_not_passed(self, tmp_path):
        write_export(tmp_path / "mon", stamp="s", operator="o", seq="1")
        write_export(tmp_path / "tue", stamp="s", operator="o", seq="1")
        (tmp_path / "mon" / "controller-fw.bin").unlink()
        (tmp_path / "tue" / "controller-fw.bin").unlink()
        r = probe(plan(), tmp_path / "mon", tmp_path / "tue")
        assert "ITM-FW" not in {i.item_id for i in r.items}
        assert any("ITM-FW" in c for c in r.checks_skipped)


# =====================================================================
# collection
# =====================================================================

class TestCollect:
    def test_it_produces_a_usable_manifest(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        r = collect(plan(), root, serial="0412", taken_by=ENG, site="Plant 2")
        assert r.complete
        assert r.manifest.machine.key == "Grimaldi/AR-7#0412"
        assert len(r.manifest.items) == 4

    def test_everything_is_read_from_the_machine_so_the_tier_is_validated(
            self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        assert r.manifest.tier_ceiling is AssuranceTier.VALIDATED
        assert all(i.hash_source is HashSource.READ_FROM_MACHINE
                   for i in r.manifest.items)

    def test_the_version_is_read_where_the_plan_says_how(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        assert r.manifest.item("ITM-PARAMS").version == "3.8.2"

    def test_an_item_with_no_declared_version_source_is_left_blank(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        assert r.manifest.item("ITM-FW").version == ""

    def test_a_required_item_that_is_missing_is_left_out_not_invented(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        (root / "controller-fw.bin").unlink()
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        assert not r.complete
        assert r.manifest.item("ITM-FW") is None
        assert any("LEFT OUT" in o.detail for o in r.missing)
        assert any("says anything about it" in w for w in r.warnings)

    def test_an_optional_item_that_is_missing_is_quiet(self, tmp_path):
        d = plan_dict()
        d["items"][3]["required"] = False
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        (root / "controller-fw.bin").unlink()
        r = collect(CollectionPlan.from_dict(d), root, serial="0412", taken_by=ENG)
        assert not any("ITM-FW" in w for w in r.warnings)

    def test_a_plan_that_matches_nothing_at_all_is_refused(self, tmp_path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(CollectionError, match="matched nothing at all"):
            collect(plan(), empty, serial="0412", taken_by=ENG)

    def test_a_multi_file_item_is_hashed_as_a_set(self, tmp_path):
        root = tmp_path / "e"
        (root / "prog").mkdir(parents=True)
        (root / "prog" / "a.st").write_text("A")
        (root / "prog" / "b.st").write_text("B")
        d = {"plan_id": "P", "manufacturer": "G", "model": "M",
             "items": [{"item_id": "ITM-PROG", "kind": "safety_program",
                        "name": "prog", "source": "prog/*.st"}]}
        one = collect(CollectionPlan.from_dict(d), root, serial="1", taken_by=ENG)
        (root / "prog" / "c.st").write_text("C")
        two = collect(CollectionPlan.from_dict(d), root, serial="1", taken_by=ENG)
        assert one.manifest.item("ITM-PROG").content_hash != \
            two.manifest.item("ITM-PROG").content_hash
        assert two.outcomes[0].files == ("prog/a.st", "prog/b.st", "prog/c.st")

    def test_the_manifest_records_which_plan_and_rule_made_each_digest(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        notes = r.manifest.item("ITM-ZONES").notes
        assert "PLAN-AR7" in notes
        assert "rule " in notes

    def test_it_defaults_to_as_found_and_can_be_told_otherwise(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        assert collect(plan(), root, serial="1", taken_by=ENG).manifest.source \
            is ManifestSource.AS_FOUND
        assert collect(plan(), root, serial="1", taken_by=ENG,
                       source=ManifestSource.AS_DECLARED).manifest.source \
            is ManifestSource.AS_DECLARED

    def test_it_never_claims_the_plan_was_complete(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        assert any("the plan does not name" in w for w in r.warnings)


# =====================================================================
# the whole point
# =====================================================================

class TestEndToEnd:
    def test_the_export_header_moves_and_the_manifest_does_not(self, tmp_path):
        """Two exports, different stamps, unchanged machine: no drift reported."""
        a = write_export(tmp_path / "mon", stamp="2026-09-14T07:12:03Z",
                         operator="m.tech", seq="4181")
        b = write_export(tmp_path / "tue", stamp="2026-09-15T06:58:41Z",
                         operator="a.integrator", seq="4199")
        p = plan()
        m1 = collect(p, a, serial="0412", taken_by=ENG, manifest_id="M1",
                     taken_at=datetime(2026, 9, 14, 8, tzinfo=UTC)).manifest
        m2 = collect(p, b, serial="0412", taken_by=ENG, manifest_id="M2",
                     taken_at=datetime(2026, 9, 15, 8, tzinfo=UTC)).manifest
        assert m1.configuration_hash() == m2.configuration_hash()
        assert compare(m1, m2).verdict == "matches"

    def test_a_real_change_is_caught_and_carries_the_safety_function(self, tmp_path):
        a = write_export(tmp_path / "tue", stamp="2026-09-15T06:58:41Z",
                         operator="a.integrator", seq="4199")
        b = write_export(tmp_path / "wed", stamp="2026-09-16T14:02:10Z",
                         operator="m.tech", seq="4231", radius=1200)
        p = plan()
        m1 = collect(p, a, serial="0412", taken_by=ENG, manifest_id="M1").manifest
        m2 = collect(p, b, serial="0412", taken_by=ENG, manifest_id="M2").manifest
        d = compare(m1, m2)
        assert d.verdict == "safety_relevant_drift"
        assert [c.item_id for c in d.changes] == ["ITM-ZONES"]
        assert d.affected_functions == ("SF-01",)

    def test_only_the_changed_item_is_reported(self, tmp_path):
        """Three of four items also had their export headers move. None reported."""
        a = write_export(tmp_path / "tue", stamp="s1", operator="o1", seq="1")
        b = write_export(tmp_path / "wed", stamp="s2", operator="o2", seq="2",
                         radius=1200)
        p = plan()
        m1 = collect(p, a, serial="0412", taken_by=ENG, manifest_id="M1").manifest
        m2 = collect(p, b, serial="0412", taken_by=ENG, manifest_id="M2").manifest
        assert len(compare(m1, m2).changes) == 1

    def test_a_collected_manifest_seals_into_the_ledger_and_verifies(self, tmp_path):
        from assurance.machinery.record import record_manifest
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        ledger = EvidenceLedger(tmp_path / "l.db")
        r = collect(plan(), root, serial="0412", taken_by=ENG)
        evidence = record_manifest(ledger, r.manifest)
        ok, problems = ledger.verify_chain()
        assert ok, problems
        assert evidence.verify()

    def test_a_collected_fleet_reaches_the_advisory_fan_out(self, tmp_path):
        from assurance.fleet.advisory import (
            AdvisorySeverity,
            AffectedArtefact,
            ComponentAdvisory,
        )
        from assurance.fleet.impact import assess_impact
        from assurance.fleet.registry import Fleet
        from assurance.machinery.record import record_manifest

        ledger = EvidenceLedger(tmp_path / "l.db")
        p = plan()
        for serial in ("0412", "0418"):
            root = write_export(tmp_path / serial, stamp="s", operator="o", seq="1")
            record_manifest(ledger, collect(p, root, serial=serial,
                                            taken_by=ENG).manifest)

        fleet = Fleet.from_ledger(ledger)
        assert len(fleet) == 2
        collected_hash = fleet.records[0].manifest.item("ITM-PARAMS").content_hash

        advisory = ComponentAdvisory(
            advisory_id="ROBO-1", issued_by="RoboCo",
            issued_at=datetime(2026, 9, 20, tzinfo=UTC),
            title="Parameter set defect", summary="...",
            severity=AdvisorySeverity.SAFETY_RELEVANT,
            affected=(AffectedArtefact(supplier="RoboCo",
                                       name="Robot safety parameter set",
                                       content_hashes=(collected_hash,)),),
            reference="https://roboco.example/1")
        report = assess_impact(advisory, fleet)
        assert len(report.machines_affected) == 2
        assert report.confirmed
