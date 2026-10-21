"""Re-verifying a passport somebody else produced.

Same shape as the bundle checker, same hole: the seal covers the evidence object,
and the passport file also prints the manifest, the coverage and the intervention
list beside it. Those printed blocks are what a reader looks at, and none of them
was compared with the sealed body.
"""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor, Evidence
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import (
    build_passport,
    record_intervention,
    record_manifest,
    verify_passport,
)

ENG = Actor("a.integrator", "safety engineer")
TECH = Actor("m.tech", "technician")

FUNCS = (
    SafetyFunction("SF-01", "Protective stop", "PL d", verified_by=("ssm_separation",)),
    SafetyFunction("SF-02", "Speed limit", "PL d", verified_by=("speed_limit",)),
)


def manifest():
    return SafetyManifest(
        manifest_id="M-1", machine=MachineIdentity("Grimaldi", "AR-7", "0412"),
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 1, 20, tzinfo=UTC),
        taken_by=ENG, functions=FUNCS, method="read",
        items=(SafetyItem("ITM-FW", ItemKind.FIRMWARE, "fw", "3.8.2", "a" * 64,
                          HashSource.READ_FROM_MACHINE, supplier="ControlCo",
                          implements=("SF-01", "SF-02")),))


@pytest.fixture
def made(tmp_path):
    ledger = EvidenceLedger(tmp_path / "l.db")
    m = manifest()
    record_manifest(ledger, m)
    record_intervention(ledger, Intervention(
        intervention_id="INT-1", machine_key=m.machine.key, item_id="ITM-FW",
        kind=InterventionKind.UPDATE, occurred_at=datetime(2026, 3, 14, tzinfo=UTC),
        performed_by=TECH, reason="update", from_hash="a" * 64, to_hash="d" * 64,
        affects_functions=("SF-01",)))
    passport = build_passport(ledger, m, actor=ENG)
    raw = json.loads(json.dumps(passport.to_dict()))
    return ledger, raw, tmp_path


def write(tmp_path, raw):
    p = tmp_path / "passport.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    return p


def reseal(raw):
    ev = Evidence.from_dict(raw["evidence"])
    raw["evidence"]["content_hash"] = ev.compute_hash()
    return raw


class TestAlreadyCaught:
    def test_a_clean_passport_verifies_against_its_ledger(self, made):
        ledger, raw, tmp = made
        ok, problems = verify_passport(write(tmp, raw), ledger=ledger)
        assert ok and problems == []

    def test_an_edited_sealed_body_is_caught(self, made):
        ledger, raw, tmp = made
        raw["evidence"]["body"]["verdict"] = "covered"
        ok, problems = verify_passport(write(tmp, raw), ledger=ledger)
        assert not ok and any("edited after sealing" in p for p in problems)


class TestThePrintedBlocksAreNotTrustedBecauseTheyAreBesideASeal:
    def test_a_stale_function_printed_as_current_is_caught(self, made):
        ledger, raw, tmp = made
        for f in raw["coverage"]["functions"]:
            f["coverage"] = "current"
        ok, problems = verify_passport(write(tmp, raw), ledger=ledger)
        assert not ok
        assert any("coverage" in p for p in problems)

    def test_a_printed_verdict_of_covered_is_caught(self, made):
        ledger, raw, tmp = made
        raw["coverage"]["verdict"] = "covered"
        ok, problems = verify_passport(write(tmp, raw))
        assert not ok

    def test_an_edited_printed_manifest_is_caught(self, made):
        ledger, raw, tmp = made
        raw["manifest"]["items"][0]["content_hash"] = "f" * 64
        ok, problems = verify_passport(write(tmp, raw))
        assert not ok
        assert any("manifest" in p for p in problems)

    def test_an_intervention_removed_from_the_printed_list_is_caught(self, made):
        ledger, raw, tmp = made
        raw["interventions"] = []
        ok, problems = verify_passport(write(tmp, raw))
        assert not ok
        assert any("intervention" in p for p in problems)

    def test_an_intervention_added_to_the_printed_list_is_caught(self, made):
        ledger, raw, tmp = made
        extra = copy.deepcopy(raw["interventions"][0])
        extra["intervention_id"] = "INT-FAKE"
        raw["interventions"].append(extra)
        ok, _ = verify_passport(write(tmp, raw))
        assert not ok

    def test_a_passport_with_no_printed_blocks_is_a_limitation_not_a_pass(self, made):
        ledger, raw, tmp = made
        for k in ("manifest", "coverage", "interventions"):
            del raw[k]
        ok, problems = verify_passport(write(tmp, raw))
        assert ok
        assert any("NOT CHECKED" in p for p in problems)


class TestResealedPassports:
    def test_a_function_listed_current_with_nothing_verified_is_incoherent(self, made):
        ledger, raw, tmp = made
        for f in raw["evidence"]["body"]["functions"]:
            f["coverage"] = "current"
            f["last_verified_hash"] = ""
        raw["evidence"]["body"]["verdict"] = "covered"
        raw["evidence"]["validation_state"] = "verified"
        ok, problems = verify_passport(write(tmp, reseal(raw)))
        assert not ok
        assert any("current" in p and "verification" in p for p in problems)

    def test_a_validation_state_that_disagrees_with_the_verdict_is_caught(self, made):
        ledger, raw, tmp = made
        assert raw["evidence"]["body"]["verdict"] == "gaps"
        raw["evidence"]["validation_state"] = "verified"
        ok, problems = verify_passport(write(tmp, reseal(raw)))
        assert not ok and any("validation" in p for p in problems)

    def test_high_confidence_on_gaps_is_caught(self, made):
        ledger, raw, tmp = made
        raw["evidence"]["confidence"] = "high"
        ok, problems = verify_passport(write(tmp, reseal(raw)))
        assert not ok and any("confidence" in p for p in problems)

    def test_an_unknown_coverage_state_is_caught(self, made):
        ledger, raw, tmp = made
        raw["evidence"]["body"]["functions"][0]["coverage"] = "excellent"
        ok, _ = verify_passport(write(tmp, reseal(raw)))
        assert not ok

    def test_evidence_of_another_kind_is_caught(self, made):
        ledger, raw, tmp = made
        raw["evidence"]["kind"] = "machine.safety_verification"
        ok, problems = verify_passport(write(tmp, reseal(raw)))
        assert not ok and any("kind" in p for p in problems)

    def test_a_stale_function_that_names_no_invalidating_change_is_caught(self, made):
        ledger, raw, tmp = made
        f = raw["evidence"]["body"]["functions"][0]
        f["coverage"] = "stale"
        f["invalidated_by"] = ""
        ok, problems = verify_passport(write(tmp, reseal(raw)))
        assert not ok
        assert any("stale" in p and "intervention" in p for p in problems)


class TestAVerifierReportsItDoesNotRaise:
    def test_not_json(self, tmp_path):
        p = tmp_path / "p.json"
        p.write_text("{nope", encoding="utf-8")
        ok, problems = verify_passport(p)
        assert not ok and problems

    def test_binary(self, tmp_path):
        p = tmp_path / "p.json"
        p.write_bytes(b"\xff\xfe\x00")
        ok, problems = verify_passport(p)
        assert not ok and problems

    def test_a_json_list(self, tmp_path):
        ok, problems = verify_passport(write(tmp_path, [1]))
        assert not ok and problems

    def test_deep_nesting(self, tmp_path):
        p = tmp_path / "p.json"
        p.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        ok, problems = verify_passport(p)
        assert not ok and problems

    def test_a_body_that_is_not_an_object(self, made):
        ledger, raw, tmp = made
        raw["evidence"]["body"] = [1, 2]
        ok, problems = verify_passport(write(tmp, raw))
        assert not ok and problems

    def test_functions_that_are_not_objects(self, made):
        ledger, raw, tmp = made
        raw["evidence"]["body"]["functions"] = ["x"]
        ok, problems = verify_passport(write(tmp, reseal(raw)))
        assert not ok and problems
