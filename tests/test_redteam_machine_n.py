"""Red-team round 4, machine/watch/fleet findings N1-N5.

Each test fails on the code before the fix. Principle: a failure to check never looks like a
successful check; unknown is never clear.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta

import pytest

from assurance.api.change_routes import _sealed_baseline
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet import cli as fleet_cli
from assurance.fleet.advisory import AffectedArtefact
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import ManifestSource, last_attribution, manifest_is_incomplete
from assurance.machinery.record import manifests_from_ledger, record_manifest
from assurance.watch.cli import main as watch_main
from assurance.watch.config import WatchConfig, WatchError
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export
from .test_assurance_change import HashSource, advisory, item, manifest

T0 = datetime(2026, 9, 14, 6, tzinfo=UTC)


# ---------------------------------------------------------------- N3
def _nomatch():
    return advisory(affected=(AffectedArtefact(
        supplier="Other", name="Other thing", versions=("1",), content_hashes=("f" * 64,)),))


def _cli(tmp_path, ledger_path, adv):
    p = tmp_path / "adv.json"
    p.write_text(json.dumps(adv.to_dict()))
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = fleet_cli.main(["advisory", "--ledger", str(ledger_path), str(p)])
    return code, buf.getvalue()


def test_n3_a_declared_only_machine_is_not_cleared_by_a_nonmatching_advisory(tmp_path):
    path = tmp_path / "d.db"
    led = EvidenceLedger(path)
    record_manifest(led, manifest(item(hash_source=HashSource.DECLARED, content_hash=""),
                                  manifest_id="D", source=ManifestSource.AS_DECLARED))
    report = assess_impact(_nomatch(), Fleet.from_ledger(led))
    assert report.unknown_machines and not report.clear_is_complete
    assert report.verdict == "needs_review"
    assert "NEEDS REVIEW" in report.summary() and "— CLEAR" not in report.summary()
    code, out = _cli(tmp_path, path, _nomatch())
    assert code == 3 and "— CLEAR" not in out


def test_n3_verdict_and_clear_is_complete_never_disagree(tmp_path):
    path = tmp_path / "v.db"
    led = EvidenceLedger(path)
    record_manifest(led, manifest(item(hash_source=HashSource.SUPPLIED_BY_VENDOR),
                                  manifest_id="V"))
    report = assess_impact(_nomatch(), Fleet.from_ledger(led))
    assert (report.verdict == "clear") == report.clear_is_complete


def test_n3_a_fully_assessed_fleet_with_no_match_is_still_clear(tmp_path):
    path = tmp_path / "ok.db"
    led = EvidenceLedger(path)
    record_manifest(led, manifest(item(hash_source=HashSource.SUPPLIED_BY_VENDOR),
                                  manifest_id="V"))
    report = assess_impact(_nomatch(), Fleet.from_ledger(led))
    assert not report.unknown_machines and not report.unknown_functions
    assert report.verdict == "clear" and report.clear_is_complete
    assert _cli(tmp_path, path, _nomatch())[0] == 0


def test_n3_an_empty_fleet_is_not_clear(tmp_path):
    path = tmp_path / "e.db"
    EvidenceLedger(path)
    assert _cli(tmp_path, path, _nomatch())[0] == 3


# ---------------------------------------------------------------- N1
def _watch(tmp_path):
    pd = plan_dict()
    (tmp_path / "plan.json").write_text(json.dumps(pd))
    write_export(tmp_path / "0412", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    (tmp_path / "watch.json").write_text(json.dumps({
        "watch_id": "W", "max_age_hours": 168,
        "targets": [{"serial": "0412", "plan": "plan.json", "root": "0412", "site": "P",
                     "country": "DE", "read_from_machine": True}]}))
    return pd


def test_n1_a_weakened_safety_declaration_is_a_change_not_quiet(tmp_path):
    pd = _watch(tmp_path)
    led = EvidenceLedger(tmp_path / "r.db")
    run_watch(WatchConfig.from_json(tmp_path / "watch.json"), led, now=T0)
    for f in pd["functions"]:
        f["verified_by"] = []
        f["required_performance"] = "PL a"
    (tmp_path / "plan.json").write_text(json.dumps(pd))
    run = run_watch(WatchConfig.from_json(tmp_path / "watch.json"), led,
                    now=T0 + timedelta(days=1))
    out = run.outcomes[0]
    assert out.status == "changed" and run.verdict != "quiet"
    assert "declaration" in out.detail
    assert len(manifests_from_ledger(led, out.machine_key)) == 2      # the new one is sealed
    again = run_watch(WatchConfig.from_json(tmp_path / "watch.json"), led,
                      now=T0 + timedelta(days=2))
    assert again.outcomes[0].status == "observed"


# ---------------------------------------------------------------- N2
def test_n2_the_drift_baseline_skips_plans_and_partial_looks_and_carries_attribution(tmp_path):
    led = EvidenceLedger(tmp_path / "a.db")

    def t(d):
        return datetime(2026, 3, 1, tzinfo=UTC) + timedelta(days=d)

    record_manifest(led, manifest(manifest_id="BASE"))
    record_manifest(led, manifest(item(content_hash="b" * 64, implements=()),
                                  manifest_id="PLAN", source=ManifestSource.AS_INTENDED,
                                  taken_at=t(1)))
    record_manifest(led, manifest(item(content_hash="9" * 64, implements=()),
                                  manifest_id="PART", taken_at=t(2),
                                  notes="[collection incomplete: ITM-X not collected]"))
    obs = manifest(item(content_hash="c" * 64, implements=()), manifest_id="OBS", taken_at=t(3))
    base = _sealed_baseline(led, obs)
    assert base.manifest_id == "BASE" and base.source is ManifestSource.AS_FOUND
    d = compare(base, obs,
                carried_attribution=last_attribution(manifests_from_ledger(led, obs.machine.key)))
    assert d.verdict == "safety_relevant_drift"


def test_n2_no_complete_as_found_baseline_means_none(tmp_path):
    led = EvidenceLedger(tmp_path / "n.db")
    record_manifest(led, manifest(manifest_id="P", source=ManifestSource.AS_INTENDED))
    obs = manifest(item(content_hash="c" * 64), manifest_id="OBS")
    assert _sealed_baseline(led, obs) is None


# ---------------------------------------------------------------- N4
@pytest.mark.parametrize("notes", [
    "[collection incomplete: X not collected]", "[Collection Incomplete: X]",
    "[COLLECTION   INCOMPLETE: X]", "[collection\nincomplete: X]", "ok [collection\tIncomplete"])
def test_n4_the_incomplete_marker_is_case_and_whitespace_insensitive(notes):
    assert manifest_is_incomplete(manifest(notes=notes))


def test_n4_a_normal_note_is_complete():
    assert not manifest_is_incomplete(manifest(notes="collection complete"))
    assert not manifest_is_incomplete(manifest(notes=""))


# ---------------------------------------------------------------- N5
@pytest.mark.parametrize("bad", [float("inf"), float("nan"), 1e12, 1e7, 0, -1, True, "168",
                                 24 * 366 + 1])
def test_n5_max_age_hours_is_validated(tmp_path, bad):
    _watch(tmp_path)
    d = json.loads((tmp_path / "watch.json").read_text())
    d["max_age_hours"] = bad
    with pytest.raises(WatchError):
        WatchConfig.from_dict(d)


def test_n5_the_bound_is_accepted_and_status_exits_2_on_a_bad_config(tmp_path, capsys):
    _watch(tmp_path)
    d = json.loads((tmp_path / "watch.json").read_text())
    d["max_age_hours"] = 24 * 366
    assert WatchConfig.from_dict(d).max_age_hours == 24 * 366
    d["max_age_hours"] = 1e12
    (tmp_path / "watch.json").write_text(json.dumps(d))
    EvidenceLedger(tmp_path / "r.db")
    code = watch_main(["status", str(tmp_path / "watch.json"), "--ledger",
                       str(tmp_path / "r.db"), "--json"])
    assert code == 2
    assert "max_age_hours" in capsys.readouterr().err
