"""A hash is compared before a name: identical bytes are the same artefact.

The component-name gate (a different supplier is a different product) is sound for a label
and wrong for a hash. A machine whose firmware is byte-identical to one the supplier named
as affected, but whose supplier was typed ``Control Co. GmbH`` where the advisory says
``ControlCo``, used to come out CLEAR: ``fleet advisory`` printed ``CLEAR`` and exited 0,
``bridge art14`` left the machine's Member State out of field 5 of an Article 14 early
warning, and a CSAF impact assessment called the same machine affected, so two matchers
disagreed. These tests pin the rule and that every consumer applies it the same way.

Still true (and pinned here too): a different supplier whose artefact ALSO differs does not
match, and a hash that was not read from the machine never confirms anything.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.bridge.art14 import draft_from_advisory
from assurance.bridge.cli import main as bridge_main
from assurance.change.service import assess_advisory
from assurance.change.store import CaseStore
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.fleet.advisory_check import check_one_machine
from assurance.fleet.cli import main as fleet_main
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import record_manifest

ENG = Actor("a.integrator", "safety engineer")
AFFECTED = "a" * 64
FIXED = "3" * 64
OTHER = "9" * 64

FUNCS = (SafetyFunction("SF-01", "Protective stop", "PL d", verified_by=("ssm_separation",)),)


def item(*, supplier="Control Co. GmbH", name="Safety controller firmware",
         version="3.8.2", content_hash=AFFECTED, source=HashSource.READ_FROM_MACHINE):
    return SafetyItem("ITM-FW", ItemKind.FIRMWARE, name, version, content_hash, source,
                      supplier=supplier, implements=("SF-01",))


def advisory(*affected, **over):
    kw = {
        "advisory_id": "CTRL-2026-11", "issued_by": "ControlCo",
        "issued_at": datetime(2026, 9, 12, 8, tzinfo=UTC), "title": "Watchdog",
        "summary": "The watchdog can fail to trip.",
        "severity": AdvisorySeverity.SAFETY_RELEVANT,
        "affected": affected or (AffectedArtefact(
            supplier="ControlCo", name="Safety controller firmware",
            versions=("3.8.0", "3.8.1", "3.8.2"), content_hashes=(AFFECTED,)),),
        "remedy": "Update to 3.9.0.", "reference": "https://controlco.example/a",
        "fixed_versions": ("3.9.0",), "fixed_hashes": (FIXED,),
    }
    kw.update(over)
    return ComponentAdvisory(**kw)


def manifest(serial, it, *, country="DE"):
    return SafetyManifest(
        manifest_id=f"MAN-{serial}",
        machine=MachineIdentity("Grimaldi", "AR-7", serial, site="Plant 2", country=country),
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 9, 14, tzinfo=UTC),
        taken_by=ENG, functions=FUNCS, items=(it,), method="synthetic")


# =====================================================================
# the rule, at the matcher
# =====================================================================

class TestHashBeforeName:
    def test_a_differently_spelled_supplier_with_identical_bytes_is_a_hash_match(self):
        basis, detail = match_item(advisory(), item(supplier="Control Co. GmbH"))
        assert basis is MatchBasis.HASH
        assert basis.confidence == "confirmed"
        assert "byte-identical" in detail
        # both spellings are named, so the person reconciling it can see what differed
        assert "'ControlCo'" in detail and "'Control Co. GmbH'" in detail
        assert "supplier differs" in detail

    def test_an_unrelated_supplier_with_identical_bytes_is_the_same_artefact(self):
        """A white-label copy of affected firmware is affected, whoever's name is on it."""
        basis, _ = match_item(advisory(), item(supplier="OtherCo"))
        assert basis is MatchBasis.HASH

    def test_a_differently_spelled_component_name_with_identical_bytes_is_a_hash_match(self):
        basis, detail = match_item(advisory(), item(supplier="ControlCo",
                                                    name="SafetyCtrl FW"))
        assert basis is MatchBasis.HASH
        assert "component name differs" in detail
        assert "'SafetyCtrl FW'" in detail and "'Safety controller firmware'" in detail

    def test_both_spellings_differing_are_both_named(self):
        _, detail = match_item(advisory(), item(supplier="Control Co. GmbH", name="SafetyCtrl"))
        assert "supplier and component name differ" in detail

    def test_no_supplier_recorded_with_identical_bytes_is_a_hash_match(self):
        basis, detail = match_item(advisory(), item(supplier=""))
        assert basis is MatchBasis.HASH
        assert "(no supplier recorded)" in detail

    def test_a_matching_supplier_and_name_carry_no_spelling_note(self):
        basis, detail = match_item(advisory(), item(supplier="controlco "))
        assert basis is MatchBasis.HASH
        assert "differ" not in detail

    def test_the_version_label_is_irrelevant_to_identical_bytes(self):
        basis, _ = match_item(advisory(), item(version="V9.9"))
        assert basis is MatchBasis.HASH

    def test_a_different_supplier_with_a_different_artefact_still_does_not_match(self):
        assert match_item(advisory(), item(supplier="Control Co. GmbH",
                                           content_hash=OTHER)) is None
        assert match_item(advisory(), item(supplier="OtherCo", content_hash=OTHER)) is None
        assert match_item(advisory(), item(name="SafetyCtrl", content_hash=OTHER)) is None

    def test_a_different_supplier_carrying_the_fixed_artefact_is_clear(self):
        assert match_item(advisory(), item(supplier="Control Co. GmbH",
                                           content_hash=FIXED, version="3.9.0")) is None

    def test_the_hash_comparison_is_as_exact_as_ever(self):
        # upper case and a sha256: prefix are the same digest; a prefix of one is not
        assert match_item(advisory(), item(content_hash="SHA256:" + AFFECTED.upper())) is not None
        assert match_item(advisory(), item(content_hash=AFFECTED[:60])) is None

    def test_which_entry_lists_the_hash_does_not_change_the_answer(self):
        first = AffectedArtefact("ScanCo", "Safety scanner", versions=("r4",))
        second = AffectedArtefact("ControlCo", "Safety controller firmware",
                                  versions=("3.8.2",), content_hashes=(AFFECTED,))
        a = match_item(advisory(first, second), item(supplier="Control Co. GmbH"))
        b = match_item(advisory(second, first), item(supplier="Control Co. GmbH"))
        assert a is not None and b is not None and a[0] is b[0] is MatchBasis.HASH

    def test_a_hash_listed_under_another_component_of_the_advisory_still_matches(self):
        """The advisory lists the hash for the scanner; a machine whose 'controller'
        carries those bytes is running the scanner's affected artefact."""
        scanner = AffectedArtefact("ScanCo", "Safety scanner firmware", versions=("r4",),
                                   content_hashes=(OTHER,))
        basis, detail = match_item(advisory(scanner), item(supplier="Control Co. GmbH",
                                                           content_hash=OTHER))
        assert basis is MatchBasis.HASH
        assert "'ScanCo'" in detail and "'Safety scanner firmware'" in detail

    def test_identical_bytes_outrank_a_label_that_contradicts_them(self):
        """Label names an affected version of the machine's own component, but the bytes
        are another listed artefact's: byte-identical wins, as it does for one component."""
        other = AffectedArtefact("ScanCo", "Safety scanner firmware", versions=("r4",),
                                 content_hashes=(OTHER,))
        adv = advisory(AffectedArtefact(
            "ControlCo", "Safety controller firmware", versions=("3.8.2",),
            content_hashes=(AFFECTED,)), other)
        basis, _ = match_item(adv, item(supplier="ControlCo", content_hash=OTHER))
        assert basis is MatchBasis.HASH

    @pytest.mark.parametrize("junk", ["n/a", "0", "unknown", "none", "abc123"])
    def test_a_placeholder_is_never_a_hash_across_components(self, junk):
        """Two 'n/a' must not meet: only a real SHA-256 digest takes part in the
        cross-component comparison."""
        adv = advisory(AffectedArtefact("ControlCo", "Safety controller firmware",
                                        versions=("3.8.2",), content_hashes=(junk,)))
        assert match_item(adv, item(supplier="Control Co. GmbH", content_hash=junk)) is None


class TestAHashThatWasNotReadFromTheMachineNeverConfirms:
    @pytest.mark.parametrize("source", [HashSource.DECLARED, HashSource.SUPPLIED_BY_VENDOR])
    def test_a_coinciding_recorded_hash_under_another_supplier_needs_a_human(self, source):
        m = match_item(advisory(), item(supplier="Control Co. GmbH", source=source))
        assert m is not None, "a recorded hash equal to an affected hash is never a clear"
        basis, detail = m
        assert basis is MatchBasis.NAME_ONLY and basis.needs_a_human
        assert "not read from this machine" in detail
        assert "'ControlCo'" in detail and "'Control Co. GmbH'" in detail
        assert "Somebody has to look" in detail

    @pytest.mark.parametrize("source", [HashSource.DECLARED, HashSource.SUPPLIED_BY_VENDOR])
    def test_the_same_holds_for_the_matching_supplier_with_an_unlisted_label(self, source):
        """Same supplier, label the advisory does not list, but the recorded hash is an
        affected one: this was a clear before, and a typed hash is not a reason to clear."""
        m = match_item(advisory(), item(supplier="ControlCo", version="V3.8.2", source=source))
        assert m is not None and m[0] is MatchBasis.NAME_ONLY

    @pytest.mark.parametrize("source", [HashSource.DECLARED, HashSource.SUPPLIED_BY_VENDOR])
    def test_a_label_match_keeps_its_own_basis(self, source):
        m = match_item(advisory(), item(supplier="ControlCo", source=source))
        assert m is not None and m[0] is MatchBasis.VERSION

    @pytest.mark.parametrize("source", [HashSource.DECLARED, HashSource.SUPPLIED_BY_VENDOR])
    def test_a_recorded_hash_that_is_not_an_affected_one_is_still_clear_for_another_supplier(
            self, source):
        assert match_item(advisory(), item(supplier="Control Co. GmbH", content_hash=OTHER,
                                           source=source)) is None


# =====================================================================
# every consumer applies it the same way
# =====================================================================

@pytest.fixture
def fleet_ledger(tmp_path):
    """0412 spelled as the advisory spells it (DE); 0602 spelled differently (IT)."""
    ledger = EvidenceLedger(tmp_path / "fleet.db")
    record_manifest(ledger, manifest("0412", item(supplier="ControlCo"), country="DE"))
    record_manifest(ledger, manifest("0602", item(supplier="Control Co. GmbH"), country="IT"))
    return ledger


class TestEveryConsumerAgrees:
    def test_the_library_entry_points_all_see_the_machine(self, fleet_ledger):
        adv = advisory()
        odd = manifest("0602", item(supplier="Control Co. GmbH"), country="IT")

        # 1. the matcher itself
        assert match_item(adv, odd.items[0])[0] is MatchBasis.HASH

        # 2. advisory-check (one machine, no ledger)
        checked = check_one_machine(adv, odd)
        assert [m["basis"] for m in checked["matches"]] == ["hash"]
        assert checked["affected"] is True

        # 3. fleet advisory (the fan-out)
        fleet = Fleet.from_ledger(fleet_ledger)
        impact = assess_impact(adv, fleet)
        assert set(impact.machines_affected) == {
            "Grimaldi/AR-7#0412", "Grimaldi/AR-7#0602"}
        assert impact.verdict != "clear"

        # 4. bridge art14: the Italian unit is in field 5
        draft = draft_from_advisory(adv, impact, fleet, received_by="a.integrator")
        assert draft.member_states == ("DE", "IT")
        assert set(draft.machines) == {"0412", "0602"}

        # 5. assess-advisory: the case names both machines
        case = assess_advisory(CaseStore(fleet_ledger), impact, actor=ENG,
                               accept_unsigned=False)
        assert case is not None
        assert set(case.machines) == set(impact.machines_affected)

    def test_a_fleet_of_only_the_odd_spelling_is_not_clear(self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "only0602.db")
        record_manifest(ledger, manifest("0602", item(supplier="Control Co. GmbH")))
        impact = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert impact.verdict != "clear"
        assert impact.machines_affected == ("Grimaldi/AR-7#0602",)

    def test_a_different_artefact_under_a_different_supplier_stays_clear_everywhere(
            self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "other.db")
        record_manifest(ledger, manifest(
            "0777", item(supplier="Control Co. GmbH", content_hash=OTHER, version="4.0.0")))
        impact = assess_impact(advisory(), Fleet.from_ledger(ledger))
        assert impact.verdict == "clear"
        assert assess_advisory(CaseStore(ledger), impact, actor=ENG) is None


# =====================================================================
# the command line
# =====================================================================

class TestCommandLine:
    def _files(self, tmp_path, supplier="Control Co. GmbH"):
        adv = tmp_path / "adv.json"
        adv.write_text(json.dumps(advisory().to_dict()))
        man = tmp_path / "man.json"
        man.write_text(json.dumps(manifest("0602", item(supplier=supplier),
                                           country="IT").to_dict()))
        ledger = EvidenceLedger(tmp_path / "fleet.db")
        record_manifest(ledger, manifest("0412", item(supplier="ControlCo"), country="DE"))
        record_manifest(ledger, manifest("0602", item(supplier=supplier), country="IT"))
        return adv, man, tmp_path / "fleet.db"

    def test_fleet_advisory_advisory_check_and_art14_agree(self, tmp_path, capsys):
        adv, man, db = self._files(tmp_path)

        # advisory-check: AFFECTED, exit 1 (it was "no match", exit 0)
        assert fleet_main(["advisory-check", str(adv), "--manifest", str(man)]) == 1
        out = capsys.readouterr().out
        assert "AFFECTED" in out and "no match" not in out

        # fleet advisory: both machines match, exit 1 (it printed CLEAR for 0602)
        assert fleet_main(["advisory", str(adv), "--ledger", str(db), "--json"]) == 1
        report = json.loads(capsys.readouterr().out)["advisories"][0]
        assert report["verdict"] != "clear"
        assert set(report["machines_affected"]) == {
            "Grimaldi/AR-7#0412", "Grimaldi/AR-7#0602"}

        # bridge art14: Member States DE and IT (it counted DE only)
        assert bridge_main(["art14", str(adv), "--ledger", str(db),
                            "--received-by", "a.integrator", "--json"]) == 0
        draft = json.loads(capsys.readouterr().out)
        assert draft["member_states"] == ["DE", "IT"]
