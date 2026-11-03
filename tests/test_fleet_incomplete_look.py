"""A failure to check must never look like a successful check (issue #93).

A transient missing export used to seal an incomplete manifest that became the machine's
current configuration: a fleet advisory against the missing item then said "no match" (exit
0), during the gap and for ever after. Pinned here:

* the last COMPLETE manifest stays the machine's effective configuration;
* the machine whose latest look was incomplete is reported as such and is not cleared;
* when the export returns, a complete manifest is sealed again and the flag clears;
* history is never deleted or rewritten.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from datetime import UTC, datetime, timedelta

from assurance.core.identity import utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.record import manifests_from_ledger, record_manifest
from assurance.watch.runner import run_watch

from .test_assurance_change import item, manifest, seal_a_real_verification
from .test_assurance_watch import T0, config, ledger, work  # noqa: F401  (fixtures)

KEY = "Grimaldi/AR-7#0412"


def _fw_advisory():
    return ComponentAdvisory(
        advisory_id="ADV-FW", issued_by="ControlCo", issued_at=datetime(2026, 9, 1, tzinfo=UTC),
        title="firmware", summary="s", severity=AdvisorySeverity.SAFETY_RELEVANT,
        affected=(AffectedArtefact(supplier="ControlCo", name="Safety controller firmware",
                                   versions=("V1",)),),
        reference="https://example.invalid/adv")


def test_the_marker_in_the_registry_is_the_one_the_watch_writes():
    from assurance.change.service import INCOMPLETE_COLLECTION_MARK
    from assurance.fleet import registry

    assert registry._PARTIAL_LOOK_MARK == INCOMPLETE_COLLECTION_MARK


def test_the_registry_constants_match_the_watch():
    from assurance.fleet import registry
    from assurance.watch.observations import FAILED_STATUSES, MANIFEST_STALE, OBSERVATION_KIND

    assert registry._OBSERVATION_KIND == OBSERVATION_KIND
    assert registry._FAILED_LOOK_STATUSES == FAILED_STATUSES | {MANIFEST_STALE}


def _gap(work, config, ledger):  # noqa: F811
    run_watch(config, ledger, now=T0)
    (work / "0412" / "controller-fw.bin").rename(work / "fw.held")
    run = run_watch(config, ledger, now=T0 + timedelta(days=1))
    assert not run.outcomes[0].collection_complete
    return run


class TestWatchGap:
    def test_during_the_gap_the_machine_keeps_its_last_complete_configuration_and_is_not_cleared(
            self, work, config, ledger):  # noqa: F811
        _gap(work, config, ledger)
        fleet = Fleet.from_ledger(ledger)
        rec = fleet.record(KEY)
        assert "ITM-FW" in [i.item_id for i in rec.manifest.items]   # not the partial look
        assert rec.latest_look_incomplete and rec.verdict != "covered"
        report = assess_impact(_fw_advisory(), fleet)
        cls = {c.machine_key: c for c in report.classifications}
        assert cls[KEY].item_ids == ("ITM-FW",)   # matched, on the last complete baseline
        assert report.look_incomplete_machines == (KEY,)
        assert report.clear_is_complete is False and report.verdict != "clear"

    def test_a_machine_with_no_match_but_an_incomplete_look_is_not_clear(
            self, work, config, ledger):  # noqa: F811
        _gap(work, config, ledger)
        other = ComponentAdvisory.from_dict({
            **_fw_advisory().to_dict(),
            "advisory_id": "ADV-OTHER",
            "affected": [{"supplier": "Nobody", "name": "Other part", "versions": ["1"],
                          "content_hashes": [], "version_note": ""}]})
        report = assess_impact(other, Fleet.from_ledger(ledger))
        assert not report.exposures
        assert report.verdict == "needs_review" and not report.clear_is_complete
        assert any("incomplete" in r for r in report.not_clear_reasons)
        assert {c.machine_key: c.classification for c in report.classifications}[KEY] == "unknown"
        assert report.to_dict()["look_incomplete_machines"] == [KEY]

    def test_when_the_export_returns_a_complete_manifest_is_sealed_again(
            self, work, config, ledger):  # noqa: F811
        _gap(work, config, ledger)
        before = len(manifests_from_ledger(ledger, KEY))
        (work / "fw.held").rename(work / "0412" / "controller-fw.bin")
        run = run_watch(config, ledger, now=T0 + timedelta(days=2))
        out = {o.serial: o for o in run.outcomes}["0412"]
        assert out.collection_complete and out.status == "observed"
        history = manifests_from_ledger(ledger, KEY)
        assert len(history) == before + 1                   # history only grows
        assert "[collection incomplete" in " ".join(m.notes for m in history[:-1])
        rec = Fleet.from_ledger(ledger).record(KEY)
        assert not rec.latest_look_incomplete
        assert "ITM-FW" in [i.item_id for i in rec.manifest.items]
        report = assess_impact(_fw_advisory(), Fleet.from_ledger(ledger))
        assert KEY in report.machines_affected and report.look_incomplete_machines == ()

    def test_a_second_quiet_run_after_recovery_seals_nothing_more(
            self, work, config, ledger):  # noqa: F811
        _gap(work, config, ledger)
        (work / "fw.held").rename(work / "0412" / "controller-fw.bin")
        run_watch(config, ledger, now=T0 + timedelta(days=2))
        n = len(manifests_from_ledger(ledger, KEY))
        run_watch(config, ledger, now=T0 + timedelta(days=3))
        assert len(manifests_from_ledger(ledger, KEY)) == n

    def test_an_uncollectable_latest_look_also_blocks_a_clear(
            self, work, config, ledger):  # noqa: F811
        run_watch(config, ledger, now=T0)
        shutil.move(str(work / "0412"), str(work / "gone"))
        run_watch(config, ledger, now=T0 + timedelta(days=1))
        report = assess_impact(_fw_advisory(), Fleet.from_ledger(ledger))
        rec = {c.machine_key: c for c in report.classifications}[KEY]
        assert rec.look_problems and report.clear_is_complete is False


class TestPartialLookNeverBecomesTheMachine:
    """Red-team B1: a partial look holding only a non-safety item must not displace a full
    manifest for coverage or advisory matching."""

    def test_a_partial_look_with_only_a_non_safety_item(self):
        led = EvidenceLedger(os.path.join(tempfile.mkdtemp(), "g.db"))
        record_manifest(led, manifest(manifest_id="FULL"))
        seal_a_real_verification(led, when=datetime(2026, 2, 9, tzinfo=UTC))
        part = manifest(item("ITM-X", implements=(), content_hash="e" * 64),
                        manifest_id="PART", taken_at=utc_now() + timedelta(seconds=1),
                        notes="[collection incomplete: ITM-FW not collected]")
        record_manifest(led, part)
        rec = Fleet.from_ledger(led).records[0]
        assert rec.manifest.manifest_id == "FULL"
        assert [i.item_id for i in rec.manifest.items] == ["ITM-FW"]
        assert rec.latest_look_incomplete and "ITM-FW" in rec.look_problems[0]
        assert rec.verdict != "covered"
        assert rec.to_row()["latest_look_incomplete"] is True

    def test_only_a_partial_look_exists_it_is_used_but_flagged(self):
        led = EvidenceLedger(os.path.join(tempfile.mkdtemp(), "g.db"))
        record_manifest(led, manifest(
            manifest_id="PART", notes="[collection incomplete: A not collected]"))
        assert Fleet.from_ledger(led).records[0].latest_look_incomplete
