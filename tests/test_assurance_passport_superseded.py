"""A passport is a point-in-time position; a ledger that has moved on must not call it valid.

Invariant: evidence bound to the old identity of a machine is not reported as current for
its new state. ``verify_passport`` against a ledger used to answer ``ok`` for a passport
sealed before the machine's firmware changed (the seal, the named records and the printed
blocks were all still intact), so a passport for the old configuration read as valid for
the new one. It now rejects a passport the ledger itself shows has been overtaken, and
leaves untouched a passport nothing has happened since (a later look at the SAME
configuration, a plan, or a partial look that is not a configuration at all).
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.manifest import (
    INCOMPLETE_COLLECTION_MARK,
    ManifestSource,
    SafetyFunction,
)
from assurance.machinery.record import (
    build_passport,
    record_intervention,
    record_manifest,
    verify_passport,
)

from .test_assurance_passport_check import ENG, TECH, manifest, write


@pytest.fixture
def sealed(tmp_path):
    ledger = EvidenceLedger(tmp_path / "l.db")
    m = manifest()
    record_manifest(ledger, m)
    passport = build_passport(ledger, m, actor=ENG)
    raw = json.loads(json.dumps(passport.to_dict()))
    return ledger, m, raw, tmp_path


def _check(sealed):
    ledger, _, raw, tmp = sealed
    return verify_passport(write(tmp, raw), ledger=ledger)


def _moved(m, **over):
    items = tuple(replace(i, content_hash="c" * 64, version="3.9.0") for i in m.items)
    return replace(m, manifest_id="M-2", items=items,
                   taken_at=m.taken_at + timedelta(days=30), **over)


def test_control_a_passport_nothing_has_overtaken_verifies(sealed):
    ok, problems = _check(sealed)
    assert ok and problems == []


def test_a_newer_look_at_another_configuration_supersedes_the_passport(sealed):
    ledger, m, _, _ = sealed
    record_manifest(ledger, _moved(m))
    ok, problems = _check(sealed)
    assert not ok
    assert any("superseded" in p and "configuration" in p for p in problems)


def test_a_newer_look_at_another_configuration_is_rejected_by_the_cli(sealed, capsys):
    from assurance.machinery.cli import main
    ledger, m, raw, tmp = sealed
    record_manifest(ledger, _moved(m))
    path = write(tmp, raw)
    assert main(["check", str(path), "--ledger", str(ledger.path)]) == 1
    assert "superseded" in capsys.readouterr().out


def test_a_declared_baseline_for_another_configuration_supersedes_too(sealed):
    ledger, m, _, _ = sealed
    record_manifest(ledger, _moved(m, source=ManifestSource.AS_DECLARED))
    ok, problems = _check(sealed)
    assert not ok and any("superseded" in p for p in problems)


def test_a_recorded_change_after_the_passport_supersedes_it(sealed):
    ledger, m, _, _ = sealed
    record_intervention(ledger, Intervention(
        intervention_id="INT-LATE", machine_key=m.machine.key, item_id="ITM-FW",
        kind=InterventionKind.UPDATE, occurred_at=datetime(2026, 4, 1, tzinfo=UTC),
        performed_by=TECH, reason="update", from_hash="a" * 64, to_hash="d" * 64,
        affects_functions=("SF-01",)))
    ok, problems = _check(sealed)
    assert not ok
    assert any("superseded" in p and "INT-LATE" in p for p in problems)


def test_a_later_look_at_the_same_configuration_leaves_the_passport_standing(sealed):
    ledger, m, _, _ = sealed
    record_manifest(ledger, replace(m, manifest_id="M-same",
                                    taken_at=m.taken_at + timedelta(days=30)))
    ok, problems = _check(sealed)
    assert ok and problems == []


def test_a_later_plan_is_not_a_state_of_the_machine(sealed):
    ledger, m, _, _ = sealed
    record_manifest(ledger, _moved(m, source=ManifestSource.AS_INTENDED))
    ok, problems = _check(sealed)
    assert ok and problems == []


def test_a_later_partial_look_is_not_a_configuration_the_machine_was_in(sealed):
    ledger, m, _, _ = sealed
    record_manifest(ledger, _moved(
        m, notes=f"[{INCOMPLETE_COLLECTION_MARK}: ITM-FW not collected]"))
    ok, problems = _check(sealed)
    assert ok and problems == []


def test_a_later_look_that_moves_only_the_safety_declaration_supersedes(sealed):
    ledger, m, _, _ = sealed
    weaker = tuple(replace(f, required_performance="PL b") for f in m.functions)
    assert isinstance(weaker[0], SafetyFunction)
    record_manifest(ledger, replace(m, manifest_id="M-decl", functions=weaker,
                                    taken_at=m.taken_at + timedelta(days=30)))
    ok, problems = _check(sealed)
    assert not ok and any("superseded" in p for p in problems)


def test_the_passport_of_another_machine_is_not_superseded_by_this_ones_change(sealed):
    ledger, m, _, _ = sealed
    other = replace(_moved(m), manifest_id="M-other",
                    machine=replace(m.machine, serial="9999"))
    record_manifest(ledger, other)
    ok, problems = _check(sealed)
    assert ok and problems == []
