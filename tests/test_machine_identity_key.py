"""The machine key is ``maker/model#serial`` and two different units must never share one.

Red-team finding B6. ``(A, "B#1", 2)`` and ``(A, B, "1#2")`` both give ``A/B#1#2``;
``(A/B, C, 1)`` and ``(A, B/C, 1)`` both give ``A/B/C#1``; a blank or whitespace-only part was
accepted. The key format is in stored ledgers and does not change. Instead an ambiguous
identity is refused where a NEW record is made (enrolment, sealing a manifest, collecting),
two different component tuples claiming one key are an ``identity_conflict`` at enrolment, and
a ledger that already holds such an identity is still read in full.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from assurance.collect.collector import CollectionError, collect
from assurance.collect.plan import CollectionPlan
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import (
    ALREADY_ENROLLED,
    ENROLMENT_KIND,
    IDENTITY_CONFLICT,
    EnrolmentError,
    enrol_machine,
)
from assurance.machinery.manifest import MachineIdentity, ManifestError
from assurance.machinery.record import (
    MANIFEST_KIND,
    IdentityConflictError,
    manifests_from_ledger,
    record_manifest,
)

from .support import plan_dict, write_export
from .test_assurance_change import ENG, manifest

PERSON = Actor("Anna Keller", "safety engineer", kind="person")

AMBIGUOUS = [
    ("A", "B#1", "2"), ("A", "B", "1#2"), ("A/B", "C", "1"), ("A", "B/C", "1"),
    (" ", "m", "s"), ("a", "m", " "), ("a", "m", "s "),
    (" a", "m", "s"), ("a", "m\n", "s"), ("a", "m", "s\x00"), ("a", "m", "s​"),
]


def _ident(parts):
    return MachineIdentity(parts[0], parts[1], parts[2])


def _legacy(monkeypatch):
    """Make records the way a build without this check did: the check is switched off."""
    monkeypatch.setattr(MachineIdentity, "ambiguity_problems", lambda self: ())


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "identity.db")


class TestTheKeyFormatIsUntouched:
    def test_a_clean_identity_keeps_the_stored_key(self):
        assert MachineIdentity("Grimaldi", "AR-7", "0412").key == "Grimaldi/AR-7#0412"

    def test_an_ambiguous_identity_still_has_the_old_key(self):
        assert MachineIdentity("A", "B#1", "2").key == "A/B#1#2"
        assert MachineIdentity("A", "B", "1#2").key == "A/B#1#2"

    @pytest.mark.parametrize("parts", AMBIGUOUS)
    def test_it_can_still_be_constructed_and_read_back(self, parts):
        ident = _ident(parts)
        assert MachineIdentity.from_dict(ident.to_dict()).components == parts


class TestAmbiguousIdentitiesAreNamed:
    @pytest.mark.parametrize("parts", AMBIGUOUS)
    def test_each_is_a_problem(self, parts):
        assert _ident(parts).ambiguity_problems()
        with pytest.raises(ManifestError, match="ambiguous"):
            _ident(parts).require_unambiguous()

    def test_a_clean_identity_has_no_problem(self):
        assert MachineIdentity("Acme GmbH", "AR-7 mk2", "0412-A").ambiguity_problems() == ()

    def test_whitespace_inside_a_part_is_fine(self):
        assert MachineIdentity("Acme  Robotics", "AR 7", "04 12").ambiguity_problems() == ()

    def test_the_problem_says_which_part(self):
        (problem,) = MachineIdentity("A", "B#1", "2").ambiguity_problems()
        assert "model" in problem and "'#'" in problem


class TestNewRecordsRefuseAmbiguity:
    @pytest.mark.parametrize("parts", AMBIGUOUS)
    def test_enrolment_refuses_and_writes_nothing(self, ledger, parts):
        with pytest.raises(EnrolmentError, match="ambiguous"):
            enrol_machine(ledger, manifest(machine=_ident(parts)), actor=PERSON)
        assert len(ledger) == 0

    def test_sealing_a_manifest_refuses_too(self, ledger):
        with pytest.raises(ManifestError, match="ambiguous"):
            record_manifest(ledger, manifest(machine=MachineIdentity("A", "B#1", "2")))
        assert len(ledger) == 0

    def test_a_clean_identity_enrols_as_before(self, ledger):
        receipt = enrol_machine(ledger, manifest(), actor=PERSON)
        assert receipt.status == "enrolled"

    def test_collecting_refuses_an_ambiguous_serial(self, tmp_path):
        root = write_export(tmp_path / "e", stamp="s", operator="o", seq="1")
        with pytest.raises(CollectionError, match="ambiguous"):
            collect(CollectionPlan.from_dict(plan_dict()), root, serial="04#12", taken_by=ENG)


class TestTwoUnitsOneKeyIsAnIdentityConflict:
    """The ledger already holds one of them (sealed before the check existed)."""

    A = ("Acme", "B#1", "2")
    B = ("Acme", "B", "1#2")

    def test_the_second_tuple_is_refused_as_an_identity_conflict(self, ledger, monkeypatch):
        _legacy(monkeypatch)
        first = enrol_machine(ledger, manifest(manifest_id="X1", machine=_ident(self.A)),
                              actor=PERSON)
        assert first.status == "enrolled"
        monkeypatch.undo()

        n = len(ledger)
        second = enrol_machine(ledger, manifest(manifest_id="X2", machine=_ident(self.B)),
                               actor=PERSON)
        assert second.status == IDENTITY_CONFLICT
        assert second.written is False and second.refused
        assert second.conflicts[0]["attribute"] == "identity"
        assert "'B#1'" in second.conflicts[0]["enrolled"]
        assert "'1#2'" in second.conflicts[0]["claimed"]
        assert len(ledger) == n

    def test_the_slash_collision_too(self, ledger, monkeypatch):
        _legacy(monkeypatch)
        enrol_machine(ledger, manifest(machine=MachineIdentity("A/B", "C", "1")), actor=PERSON)
        monkeypatch.undo()
        second = enrol_machine(ledger, manifest(machine=MachineIdentity("A", "B/C", "1")),
                               actor=PERSON)
        assert second.status == IDENTITY_CONFLICT

    def test_sealing_a_manifest_of_the_other_tuple_is_refused(self, ledger, monkeypatch):
        _legacy(monkeypatch)
        record_manifest(ledger, manifest(manifest_id="X1", machine=_ident(self.A)))
        monkeypatch.undo()
        with pytest.raises(IdentityConflictError, match="identity_conflict"):
            record_manifest(ledger, manifest(manifest_id="X2", machine=_ident(self.B)))
        assert len(list(ledger.entries(kind=MANIFEST_KIND))) == 1


class TestAnExistingLedgerStaysReadable:
    def test_a_ledger_sealed_with_an_ambiguous_identity_is_read_in_full(
            self, ledger, monkeypatch):
        ident = MachineIdentity("Acme", "B#1", "2")
        _legacy(monkeypatch)
        enrol_machine(ledger, manifest(manifest_id="X1", machine=ident), actor=PERSON)
        monkeypatch.undo()
        read = manifests_from_ledger(ledger, ident.key)
        assert [m.machine.components for m in read] == [ident.components]
        assert len(list(ledger.entries(kind=ENROLMENT_KIND))) == 1

    def test_the_machine_it_already_knows_keeps_working(self, ledger, monkeypatch):
        ident = MachineIdentity("Acme", "B#1", "2")
        _legacy(monkeypatch)
        enrol_machine(ledger, manifest(manifest_id="X1", machine=ident), actor=PERSON)
        monkeypatch.undo()
        # The same tuple: enrolling again is the ordinary idempotent answer ...
        again = enrol_machine(ledger, manifest(manifest_id="X1", machine=ident), actor=PERSON)
        assert again.status == ALREADY_ENROLLED
        # ... and a later look at that machine can still be sealed.
        record_manifest(ledger, replace(manifest(manifest_id="X3", machine=ident),
                                        notes="a later look"))
        assert len(manifests_from_ledger(ledger, ident.key)) == 2


class TestAcceptedIdentitiesNeverCollide:
    """The rule must be exactly as strict as the collision surface, no stricter: a serial such as 2023/00123 is real."""

    def test_a_slash_in_the_serial_is_accepted(self):
        assert MachineIdentity("A", "B", "2023/00123").ambiguity_problems() == ()

    def test_no_two_different_accepted_identities_share_a_key(self):
        import itertools

        alphabet = ["a", "b", "/", "#", "a/", "#b"]
        parts = [p for r in (1, 2) for p in map("".join, itertools.product(alphabet, repeat=r))]
        seen: dict[str, tuple[str, str, str]] = {}
        accepted = 0
        for maker, model, serial in itertools.product(parts, repeat=3):
            ident = MachineIdentity(maker, model, serial)
            if ident.ambiguity_problems():
                continue
            accepted += 1
            assert seen.setdefault(ident.key, (maker, model, serial)) == (maker, model, serial), ident.key
        assert accepted >= 700  # the property was exercised, not vacuous (720 of 74,088 tuples are accepted)
