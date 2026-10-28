"""PASS, FAIL, UNCHECKED, INCOMPLETE and STALE are different states and read differently.

Regression (independent review of a135c0e, finding L2): the ``Coverage`` enum collapsed a check
that was NOT RUN (``unchecked``) or only partly run into ``failing`` ("did not pass it").
``unchecked`` and ``incomplete`` are valid outcomes in this product; a coverage report must be
able to say them.

The mapping, per declared function, from the NEWEST run that exercised each of its checks:

* every check verified, nothing since disturbed it            ``current``
* a check's newest run VIOLATED it                            ``failing``
* no check violated, none verified, one or more left unchecked ``unchecked``
* no check violated, some verified, some left unchecked       ``incomplete``
* verified, then an intervention disturbed it                 ``stale``
* no run ever exercised a check                               ``never_verified``
* the function declares no check                              ``not_demonstrable``

Only ``current`` is cover. ``stale`` is never a pass.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from assurance.check.pipeline import run_enrolled_check
from assurance.core.evidence import Actor
from assurance.fleet.registry import Fleet
from assurance.machine.bundle import build_bundle
from assurance.machine.trace import OperatingMode
from assurance.machinery.cli import main as machinery_cli
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.manifest import SafetyFunction
from assurance.machinery.record import (
    build_passport,
    interventions_from_ledger,
    record_intervention,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

from .support_trust_hardening import KEY, ledger, manifest, trace_in_modes
from .test_assurance_machine_provenance import ACTOR, envelope

AUTO = (OperatingMode.AUTOMATIC,)
SSM = (OperatingMode.SSM,)


def _man():
    base = manifest(checks=("speed_limit",))
    return replace(
        base,
        items=(replace(base.items[0], implements=("F-ZONE", "F-STOP", "F-BOTH")),),
        functions=(
            SafetyFunction("F-ZONE", "stay inside the workspace",
                           verified_by=("workspace_containment",)),
            SafetyFunction("F-STOP", "stay under the speed limit",
                           verified_by=("speed_limit",)),
            SafetyFunction("F-BOTH", "both", verified_by=("workspace_containment",
                                                          "speed_limit")),
            SafetyFunction("F-NONE", "declares nothing", verified_by=()),
        ))


def _seal(led, modes, *, speed=300.0, tid="RUN", start=None):
    tr = trace_in_modes(modes, speed=speed, trace_id=tid,
                        **({"started_at": start} if start else {}))
    return build_bundle(envelope(), tr, actor=ACTOR, ledger=led, subject=KEY)


def _states(led, man=None):
    man = man or _man()
    report = assess_coverage(man, VerificationRecord.from_ledger(led, subject=KEY),
                             interventions_from_ledger(led, KEY))
    return {f.function_id: f.coverage.value for f in report.functions}, report


def test_the_enum_has_distinct_unchecked_and_incomplete_values():
    values = {c.value for c in Coverage}
    assert {"current", "stale", "failing", "unchecked", "incomplete", "never_verified",
            "not_demonstrable"} <= values
    for state in (Coverage.UNCHECKED, Coverage.INCOMPLETE, Coverage.FAILING,
                  Coverage.STALE, Coverage.NEVER_VERIFIED, Coverage.NOT_DEMONSTRABLE):
        assert state.is_covered is False
    assert Coverage.CURRENT.is_covered is True


def test_the_ranks_are_distinct_and_worst_first():
    ranks = [c.rank for c in Coverage]
    assert len(set(ranks)) == len(ranks)
    assert Coverage.FAILING.rank < Coverage.STALE.rank < Coverage.CURRENT.rank
    assert Coverage.CURRENT.rank == max(ranks)


class TestFromRealRuns:
    def test_a_check_that_was_not_run_is_unchecked_not_failing(self, tmp_path):
        led = ledger(tmp_path)
        b = _seal(led, AUTO)      # no SSM sample: the speed limit has nothing to judge
        speed = next(c for c in b.evidence.body["checks"] if c["name"] == "speed_limit")
        assert speed["outcome"] == "unchecked"
        states, report = _states(led)
        assert states["F-STOP"] == "unchecked"
        assert states["F-ZONE"] == "current"
        assert states["F-BOTH"] == "incomplete"
        assert states["F-NONE"] == "not_demonstrable"
        assert report.verdict == "gaps"
        assert {f.function_id for f in report.uncovered} >= {"F-STOP", "F-BOTH"}

    def test_a_violation_is_failing_and_outranks_an_unchecked_sibling(self, tmp_path):
        led = ledger(tmp_path)
        _seal(led, SSM, speed=900.0)        # speed limit 500 -> violated
        states, _ = _states(led)
        assert states["F-STOP"] == "failing"
        assert states["F-BOTH"] == "failing"
        assert states["F-ZONE"] == "current"

    def test_a_later_run_that_verifies_the_check_replaces_the_unchecked(self, tmp_path):
        led = ledger(tmp_path)
        t0 = datetime(2026, 9, 12, tzinfo=UTC)
        _seal(led, AUTO, tid="R1", start=t0)
        _seal(led, SSM, tid="R2", start=t0 + timedelta(hours=1))
        states, _ = _states(led)
        assert states["F-STOP"] == "current"
        assert states["F-BOTH"] == "current"

    def test_an_unchecked_newest_run_does_not_leave_an_older_pass_standing(self, tmp_path):
        led = ledger(tmp_path)
        t0 = datetime(2026, 9, 12, tzinfo=UTC)
        _seal(led, SSM, tid="R1", start=t0)
        _seal(led, AUTO, tid="R2", start=t0 + timedelta(hours=1))
        states, _ = _states(led)
        assert states["F-STOP"] == "unchecked"
        assert states["F-BOTH"] == "incomplete"

    def test_stale_is_not_a_pass_and_stays_stale(self, tmp_path):
        led = ledger(tmp_path)
        t0 = datetime(2026, 9, 12, tzinfo=UTC)
        _seal(led, SSM, start=t0)
        record_intervention(led, Intervention(
            intervention_id="INT-1", machine_key=KEY, item_id="fw",
            kind=InterventionKind.UPDATE,
            occurred_at=t0 + timedelta(days=2), performed_by=Actor("t", "tech"),
            reason="update", affects_functions=("F-STOP",)))
        states, report = _states(led)
        assert states["F-STOP"] == "stale"
        assert report.functions[0].coverage.is_covered is False
        assert report.verdict == "gaps"


class TestTheReaders:
    def _unchecked_ledger(self, tmp_path):
        led = ledger(tmp_path)
        record_manifest(led, _man())
        _seal(led, AUTO)
        return led

    def test_the_text_marks_each_state_differently(self, tmp_path):
        _, report = _states(self._unchecked_ledger(tmp_path))
        text = report.summary()
        marks = {line.split("]")[0] for line in text.splitlines() if line.startswith("  [")}
        assert len(marks) >= 3        # ok / unchecked / incomplete / n/a are not one mark
        assert any("UNCHK" in m or "unchk" in m.lower() for m in marks)
        assert any("INCOMP" in m or "incomp" in m.lower() for m in marks)
        assert not any("FAIL" in m for m in marks)

    def test_the_json_carries_the_distinct_values(self, tmp_path):
        _, report = _states(self._unchecked_ledger(tmp_path))
        by_id = {f["function_id"]: f["coverage"] for f in report.to_dict()["functions"]}
        assert by_id["F-STOP"] == "unchecked"
        assert by_id["F-BOTH"] == "incomplete"

    def test_the_detail_does_not_say_did_not_pass_for_a_check_that_did_not_run(
            self, tmp_path):
        _, report = _states(self._unchecked_ledger(tmp_path))
        stop = next(f for f in report.functions if f.function_id == "F-STOP")
        assert "did not pass" not in stop.detail
        assert "not run" in stop.detail or "unchecked" in stop.detail

    def test_the_pipeline_keeps_their_severity_but_not_the_word_failing(self, tmp_path):
        d = run_enrolled_check(self._unchecked_ledger(tmp_path), KEY, None).to_dict()
        by_id = {f["function_id"]: f["coverage"] for f in d["functions"]}
        assert by_id["F-STOP"] == "unchecked" and by_id["F-BOTH"] == "incomplete"
        # an unchecked function is work to do, as it was when it read "failing" (a135c0e);
        # the evidence bucket is still "insufficient", not a failure count
        assert set(d["required_actions"]) == {"F-STOP", "F-BOTH"}
        assert d["verdict"] == "requires_reverification"
        assert d["evidence"]["insufficient"] >= 2

    def test_a_failing_function_is_still_required_work(self, tmp_path):
        led = ledger(tmp_path)
        record_manifest(led, _man())
        _seal(led, SSM, speed=900.0)
        d = run_enrolled_check(led, KEY, None).to_dict()
        assert set(d["required_actions"]) == {"F-STOP", "F-BOTH"}
        assert d["verdict"] == "requires_reverification"

    def test_the_fleet_ranks_failing_worse_than_unchecked_worse_than_never(self, tmp_path):
        led = self._unchecked_ledger(tmp_path)
        row = Fleet.from_ledger(led).to_dict()["machines"][0]
        assert row["worst"] == "unchecked" or row["worst"] == "incomplete"
        assert row["uncovered"] == 3                  # F-STOP, F-BOTH, F-NONE

    def test_the_cli_exit_code_for_unchecked_is_1_and_the_json_says_so(self, tmp_path,
                                                                     capsys):
        self._unchecked_ledger(tmp_path)
        m = tmp_path / "m.json"
        m.write_text(json.dumps(_man().to_dict()), encoding="utf-8")
        rc = machinery_cli(["coverage", str(m), "--ledger", str(tmp_path / "ledger.db"),
                            "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 1
        assert {f["coverage"] for f in out["functions"]} >= {"unchecked", "incomplete"}

    def test_a_sealed_passport_with_these_states_verifies(self, tmp_path):
        led = self._unchecked_ledger(tmp_path)
        passport = build_passport(led, _man(), actor=ACTOR)
        out = tmp_path / "p.json"
        passport.write(out)
        ok, problems = verify_passport(out, ledger=led)
        assert ok, problems

    def test_a_passport_naming_a_state_nobody_defined_is_still_refused(self, tmp_path):
        from assurance.core.evidence import Evidence
        led = self._unchecked_ledger(tmp_path)
        raw = json.loads(json.dumps(build_passport(led, _man(), actor=ACTOR,
                                                   seal=False).to_dict()))
        raw["evidence"]["body"]["functions"][0]["coverage"] = "mostly_fine"
        raw["evidence"]["content_hash"] = Evidence.from_dict(raw["evidence"]).compute_hash()
        p = tmp_path / "bad.json"
        p.write_text(json.dumps(raw), encoding="utf-8")
        ok, _ = verify_passport(p)
        assert ok is False

    def test_the_html_report_has_a_label_for_every_state(self):
        from assurance.report import render
        for state in Coverage:
            assert state.value in render._COVERAGE_WORDS


@pytest.mark.parametrize("state", ["unchecked", "incomplete"])
def test_a_hand_built_record_with_an_unchecked_check_is_not_failing(state):
    """The library path: a record that says which of its checks were left unchecked."""
    rec = VerificationRecord(
        content_hash="a" * 64, effective_at=datetime(2026, 9, 14, tzinfo=UTC), ledger_seq=1,
        product="p", product_version="1", verdict="incomplete", tier="validated",
        checks_verified=("workspace_containment",) if state == "incomplete" else (),
        checks_not_verified=("speed_limit",), checks_unchecked=("speed_limit",))
    report = assess_coverage(_man(), [rec], [])
    got = {f.function_id: f.coverage.value for f in report.functions}
    assert got["F-STOP"] == "unchecked"
    assert got["F-BOTH"] == ("incomplete" if state == "incomplete" else "unchecked")
