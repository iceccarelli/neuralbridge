"""Tests for the watch.

The watch is the component that decides what a customer reads on a Monday
morning, so the tests are about the four judgements that make it readable: a
quiet week is quiet even though every export header moved, a change is reported
the week it happened, a finding already reported is demoted rather than
repeated, and "I could not look" never shares an outcome with "nothing moved".
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.record import manifests_from_ledger
from assurance.watch.config import WatchConfig, WatchError, WatchTarget
from assurance.watch.runner import (
    OBSERVATION_KIND,
    RUN_KIND,
    last_run,
    run_watch,
)

from .support import plan_dict, write_export

T0 = datetime(2026, 9, 14, 6, tzinfo=UTC)


@pytest.fixture
def work(tmp_path) -> Path:
    (tmp_path / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in ("0412", "0501"):
        write_export(tmp_path / serial, stamp="2026-09-14T06:00:00Z",
                     operator="m.tech", seq="4181")
    (tmp_path / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-PLANT2", "max_age_hours": 168,
        "targets": [
            {"serial": "0412", "plan": "plan.json", "root": "0412",
             "site": "Plant 2", "country": "DE"},
            {"serial": "0501", "plan": "plan.json", "root": "0501",
             "site": "Plant 7", "country": "IT"},
        ],
    }))
    return tmp_path


@pytest.fixture
def config(work) -> WatchConfig:
    return WatchConfig.from_json(work / "watch.json")


@pytest.fixture
def ledger(work) -> EvidenceLedger:
    return EvidenceLedger(work / "register.db")


def reexport(work: Path, serial: str, **over) -> None:
    shutil.rmtree(work / serial)
    kw = {"stamp": "2026-09-21T06:12:41Z", "operator": "a.integrator",
          "seq": "4199"}
    kw.update(over)
    write_export(work / serial, **kw)


# =====================================================================
# the judgement that decides whether anybody reads it
# =====================================================================

class TestQuietWeeks:
    def test_a_first_look_reports_every_machine_as_new(self, config, ledger):
        run = run_watch(config, ledger, now=T0)
        assert {o.status for o in run.outcomes} == {"first_seen"}
        assert run.verdict == "findings"

    def test_a_week_where_only_the_export_headers_moved_is_quiet(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert run.verdict == "quiet"
        assert {o.status for o in run.outcomes} == {"observed"}
        assert run.changed == ()

    def test_a_quiet_week_seals_no_manifest(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        before = len(manifests_from_ledger(ledger, "Grimaldi/AR-7#0412"))
        reexport(work, "0412")
        reexport(work, "0501")
        run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert len(manifests_from_ledger(ledger, "Grimaldi/AR-7#0412")) == before

    def test_but_it_still_records_that_somebody_looked(self, work, config, ledger):
        """A gap in the record must not read as 'unchanged'."""
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501")
        run_watch(config, ledger, now=T0 + timedelta(days=7))
        observations = [e for e in ledger.entries(kind=OBSERVATION_KIND)
                        if e.evidence().body["serial"] == "0412"]
        assert len(observations) == 2
        assert observations[-1].evidence().body["status"] == "observed"

    def test_a_real_change_is_reported_the_week_it_happens(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501", radius=1200)
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert run.verdict == "findings"
        assert [o.serial for o in run.changed] == ["0501"]

    def test_and_names_the_item_and_the_safety_function(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        changed = run.changed[0]
        assert changed.drift_items == ("ITM-ZONES",)
        assert changed.affected_functions == ("SF-01",)
        assert changed.drift_severity == "safety_relevant"

    def test_a_changed_machine_seals_a_new_manifest_and_a_divergence(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert len(manifests_from_ledger(ledger, "Grimaldi/AR-7#0501")) == 2
        assert any("divergence" in s for s in run.sealed)

    def test_the_unchanged_machine_in_the_same_run_stays_quiet(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501", radius=1200)
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert next(o for o in run.outcomes if o.serial == "0412").status == \
            "observed"


# =====================================================================
# new is not the same as outstanding
# =====================================================================

class TestNewVersusOutstanding:
    def test_a_finding_is_new_the_first_time(self, config, ledger):
        run = run_watch(config, ledger, now=T0)
        assert set(run.outcomes[0].newly_uncovered) == {"SF-01", "SF-02"}
        assert run.outcomes[0].still_uncovered == ()

    def test_and_demoted_to_outstanding_afterwards(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert run.outcomes[0].newly_uncovered == ()
        assert set(run.outcomes[0].still_uncovered) == {"SF-01", "SF-02"}

    def test_an_outstanding_finding_does_not_make_the_run_a_finding(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert run.verdict == "quiet"
        assert run.findings == ()

    def test_a_recovered_function_is_reported_as_recovered(
            self, work, config, ledger, tmp_path):
        """Coverage returns when a verification lands between two runs."""
        from assurance.core.evidence import Actor
        from assurance.machine.bundle import build_bundle
        from assurance.machine.envelope import (
            FigureBasis,
            SafetyEnvelope,
            SensingUncertainty,
            StopPerformance,
            Workspace,
        )
        from assurance.machine.trace import (
            OperatingMode,
            Provenance,
            Sample,
            Trace,
        )

        run_watch(config, ledger, now=T0)
        env = SafetyEnvelope(
            envelope_id="E", product="AR-7", product_version="1",
            workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
            max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
            stop=StopPerformance(0.1, 0.25, 120.0, 500.0,
                                 FigureBasis("measured", "S1", "2026-01-01")),
            uncertainty=SensingUncertainty(100.0, 50.0,
                                           FigureBasis("measured", "C1")),
            intrusion_distance_mm=850.0)
        trace = Trace(trace_id="R", provenance=Provenance.FIELD, source_system="fw",
                      started_at=T0 + timedelta(days=1), sample_rate_hz=50.0,
                      samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0),
                                           tcp_speed=400.0, mode=OperatingMode.SSM,
                                           separation=2200.0) for i in range(10)))
        build_bundle(env, trace, actor=Actor("eng", "engineer"), ledger=ledger,
                     subject="Grimaldi/AR-7#0412")

        reexport(work, "0412")
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        o = next(x for x in run.outcomes if x.serial == "0412")
        assert set(o.recovered) == {"SF-01", "SF-02"}


# =====================================================================
# could not look is not nothing moved
# =====================================================================

class TestBlindSpots:
    def test_a_missing_export_folder_is_uncollectable_not_unchanged(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        shutil.rmtree(work / "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        o = next(x for x in run.outcomes if x.serial == "0501")
        assert o.status == "uncollectable"
        assert any("not an unchanged machine" in w for w in o.warnings)

    def test_and_degrades_the_whole_run(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        shutil.rmtree(work / "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert run.verdict == "degraded"

    def test_an_uncollectable_machine_seals_the_attempt(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        shutil.rmtree(work / "0501")
        run_watch(config, ledger, now=T0 + timedelta(days=7))
        last = [e for e in ledger.entries(kind=OBSERVATION_KIND)
                if e.evidence().body["serial"] == "0501"][-1].evidence()
        assert last.body["status"] == "uncollectable"
        assert any("not an observation" in c for c in last.checks_skipped)

    def test_silence_expires_when_a_machine_is_never_collectable(
            self, work, tmp_path, ledger):
        """A watch that stopped seeing a machine must say so, not go quiet."""
        shutil.rmtree(tmp_path / "0501")
        config = WatchConfig.from_json(tmp_path / "watch.json")
        run = run_watch(config, ledger, now=T0)
        assert "0501" in run.stale_observations
        assert run.verdict == "degraded"

    def test_a_machine_seen_this_run_is_never_stale(self, config, ledger):
        run = run_watch(config, ledger, now=T0)
        assert run.stale_observations == ()

    def test_an_old_observation_goes_stale_after_the_declared_cadence(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        shutil.rmtree(work / "0501")
        run = run_watch(config, ledger, now=T0 + timedelta(days=30))
        assert "0501" in run.stale_observations


# =====================================================================
# the record it leaves
# =====================================================================

class TestTheRecord:
    def test_the_chain_verifies_after_several_runs(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        run_watch(config, ledger, now=T0 + timedelta(days=7))
        reexport(work, "0501", radius=1200, stamp="2026-09-28T05:00:00Z")
        run_watch(config, ledger, now=T0 + timedelta(days=14))
        ok, problems = ledger.verify_chain()
        assert ok, problems

    def test_a_run_is_sealed_and_readable_afterwards(self, config, ledger):
        run_watch(config, ledger, now=T0)
        body = last_run(ledger, "WATCH-PLANT2")
        assert body is not None
        assert body["watch_id"] == "WATCH-PLANT2"
        assert len(body["outcomes"]) == 2

    def test_a_run_never_ends_before_it_began(self, config, ledger):
        run = run_watch(config, ledger, now=T0)
        assert run.finished_at >= run.started_at

    def test_dry_run_seals_nothing(self, config, ledger):
        before = len(ledger)
        run = run_watch(config, ledger, now=T0, seal=False)
        assert len(ledger) == before
        assert run.outcomes
        assert last_run(ledger, "WATCH-PLANT2") is None

    def test_the_run_record_carries_its_own_limits(self, config, ledger):
        run = run_watch(config, ledger, now=T0)
        assert any("not watched" in c for c in run.checks_skipped)
        assert any("made and reverted between two runs" in c
                   for c in run.checks_skipped)

    def test_a_safety_relevant_drift_is_raised_in_the_run_caveats(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        run = run_watch(config, ledger, now=T0 + timedelta(days=7))
        assert any("in doubt until it is re-run" in c for c in run.checks_skipped)

    def test_a_target_without_a_country_is_flagged_on_every_machine(
            self, tmp_path, ledger):
        (tmp_path / "watch.json").write_text(json.dumps({
            "watch_id": "W", "targets": [
                {"serial": "0412", "plan": "plan.json", "root": "0412"}]}))
        config = WatchConfig.from_json(tmp_path / "watch.json")
        run = run_watch(config, ledger, now=T0)
        assert any("Article 14" in w for w in run.outcomes[0].warnings)

    def test_the_run_kind_is_queryable(self, config, ledger):
        run_watch(config, ledger, now=T0)
        assert len(ledger.entries(kind=RUN_KIND)) == 1


# =====================================================================
# configuration
# =====================================================================

class TestConfig:
    def test_a_watch_with_no_targets_is_refused(self):
        with pytest.raises(WatchError, match="no targets"):
            WatchConfig(watch_id="W", targets=())

    def test_a_duplicate_serial_is_refused(self):
        t = WatchTarget(serial="1", plan="p", root="r")
        with pytest.raises(WatchError, match="twice"):
            WatchConfig(watch_id="W", targets=(t, t))

    def test_a_target_missing_a_root_is_refused(self):
        with pytest.raises(WatchError, match="needs a serial"):
            WatchTarget(serial="1", plan="p", root="")

    def test_a_non_positive_cadence_is_refused(self):
        with pytest.raises(WatchError, match="max_age_hours"):
            WatchConfig(watch_id="W", max_age_hours=0,
                        targets=(WatchTarget("1", "p", "r"),))

    def test_paths_are_resolved_relative_to_the_config(self, work):
        config = WatchConfig.from_json(work / "watch.json")
        assert Path(config.targets[0].plan).is_absolute()
        assert Path(config.targets[0].plan).exists()

    def test_the_config_hash_moves_when_a_target_moves(self, work):
        a = WatchConfig.from_json(work / "watch.json")
        b = WatchConfig(watch_id=a.watch_id, targets=a.targets[:1])
        assert a.content_hash() != b.content_hash()


# =====================================================================
# CLI
# =====================================================================

class TestCli:
    def test_exit_codes_separate_quiet_findings_and_blind(
            self, work, ledger, capsys):
        from assurance.watch.cli import main

        argv = ["run", str(work / "watch.json"), "--ledger", str(ledger.path)]
        assert main(argv) == 1          # first look: everything new
        capsys.readouterr()

        reexport(work, "0412")
        reexport(work, "0501")
        assert main(argv) == 0          # quiet
        capsys.readouterr()

        shutil.rmtree(work / "0501")
        assert main(argv) == 2          # could not look
        assert "BLIND" in capsys.readouterr().out

    def test_status_reads_the_last_run_without_looking_again(
            self, work, ledger, capsys):
        from assurance.watch.cli import main

        main(["run", str(work / "watch.json"), "--ledger", str(ledger.path)])
        capsys.readouterr()
        before = len(ledger)
        code = main(["status", str(work / "watch.json"),
                     "--ledger", str(ledger.path)])
        assert code == 1
        assert len(ledger) == before
        assert "WATCH-PLANT2" in capsys.readouterr().out

    def test_status_on_a_watch_that_never_ran_is_not_a_clean_exit(
            self, work, ledger):
        from assurance.watch.cli import main
        assert main(["status", str(work / "watch.json"),
                     "--ledger", str(ledger.path)]) == 2

    def test_a_dry_run_says_it_changed_nothing(self, work, ledger, capsys):
        from assurance.watch.cli import main
        main(["run", str(work / "watch.json"), "--ledger", str(ledger.path),
              "--dry-run"])
        assert "DRY RUN" in capsys.readouterr().out
        assert last_run(ledger, "WATCH-PLANT2") is None
