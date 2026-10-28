"""The watch opens and keeps cases itself.

Everything here runs the real engines end to end — collection plans over
synthetic vendor exports, the manifest ledger, ``compare()``, ``assess_coverage``,
``assess_impact`` over a signed supplier feed, the case store and its replay.
Nothing is mocked except, in two tests, the single call that is made to fail so
the crash window can be shown closed.

The path under test is: observation or advisory -> evidence assessment ->
change case -> responsible action -> re-verification -> human decision ->
verifiable closure. A watch may do the first three by itself; the last needs a
named person.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.attest.keys import SigningKey
from assurance.change import (
    CaseStatus,
    CaseStore,
    CaseTransitionError,
    advance,
    claim,
    decide,
    reconstruct_case,
    resolve_decision,
    reverify,
)
from assurance.change.store import CASE_KINDS
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, AffectedArtefact, ComponentAdvisory
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.record import (
    interventions_from_ledger,
    manifests_from_ledger,
    record_intervention,
)
from assurance.machinery.staleness import VerificationRecord
from assurance.supplier import AdvisoryFeed, SupplierIdentity, publish, withdraw
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export
from .support_recorder import build_attested_bundle

T0 = datetime(2026, 9, 14, 6, tzinfo=UTC)
WEEK = timedelta(days=7)
KEY_0412 = "Grimaldi/AR-7#0412"
KEY_0501 = "Grimaldi/AR-7#0501"
PERSON = Actor("v.grimaldi", "assurance reviewer")
ENGINEER = Actor("a.integrator", "safety engineer")


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture
def work(tmp_path) -> Path:
    (tmp_path / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in ("0412", "0501"):
        write_export(tmp_path / serial, stamp="2026-09-14T06:00:00Z",
                     operator="m.tech", seq="4181")
    (tmp_path / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-PLANT2", "max_age_hours": 168,
        "targets": [
            # read_from_machine: the harness plays a watch running ON the machine. An
            # export folder is no longer labelled that implicitly (B6).
            {"serial": "0412", "plan": "plan.json", "root": "0412",
             "site": "Plant 2", "country": "DE", "read_from_machine": True},
            {"serial": "0501", "plan": "plan.json", "root": "0501",
             "site": "Plant 7", "country": "IT", "read_from_machine": True},
        ],
    }))
    return tmp_path


@pytest.fixture
def config(work) -> WatchConfig:
    return WatchConfig.from_json(work / "watch.json")


@pytest.fixture
def ledger(work) -> EvidenceLedger:
    return EvidenceLedger(work / "register.db")


@pytest.fixture
def store(ledger) -> CaseStore:
    return CaseStore(ledger)


def reexport(work: Path, serial: str, **over) -> None:
    shutil.rmtree(work / serial)
    kw = {"stamp": "2026-09-21T06:12:41Z", "operator": "a.integrator", "seq": "4199"}
    kw.update(over)
    write_export(work / serial, **kw)


def verify_machine(ledger: EvidenceLedger, key: str, *, when: datetime):
    """A real machine-verification bundle sealed against this machine."""
    env = SafetyEnvelope(
        envelope_id="E", product="AR-7", product_version="1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.1, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "S1", "2026-01-01")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "C1")),
        intrusion_distance_mm=850.0)
    serial = key.rpartition("#")[2]
    trace = Trace(trace_id=f"R-{serial}-{when:%Y%m%d%H%M%S}", provenance=Provenance.FIELD,
                  source_system="fw", started_at=when, sample_rate_hz=50.0,
                  samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0),
                                       tcp_speed=400.0, mode=OperatingMode.SSM,
                                       separation=2200.0) for i in range(10)))
    return build_attested_bundle(env, trace, actor=ENGINEER, ledger=ledger, subject=key)


def case_kind_entries(ledger: EvidenceLedger):
    return [e for e in ledger.entries() if e.kind in CASE_KINDS]


def after_the_ledger(when: datetime) -> datetime:
    """A run the simulated timeline places after a change, started after the ledger
    recorded that change.

    The watch's timeline here is simulated (``T0`` is in the past) but the ledger stamps
    every record with the real clock, and a verification is only evidence about a state
    the ledger had already recorded when the run began. So a re-verification that follows
    a drift is dated no earlier than the present.
    """
    return max(when, datetime.now(UTC))


def work_to_closure(ledger, store, case_id, key, *, when):
    """Claim, advance, re-verify against a fresh real bundle, and have a person close."""
    case = claim(store, case_id, owner="v.grimaldi", actor=PERSON)
    while case.status is not CaseStatus.AWAITING_REVERIFICATION:
        case = advance(store, case.case_id, actor=PERSON)
    bundle = verify_machine(ledger, key, when=after_the_ledger(when))
    observed = manifests_from_ledger(ledger, key)[-1]
    case = reverify(store, case.case_id, observed,
                    VerificationRecord.from_ledger(ledger, subject=key),
                    interventions_from_ledger(ledger, key),
                    verification_content_hash=bundle.content_hash, actor=PERSON)
    assert case.status is CaseStatus.READY_TO_CLOSE
    return decide(store, case.case_id, disposition="closed",
                  reason="Stop performance re-run; SF-01 current again.", actor=PERSON), bundle


# --------------------------------------------------------------------------
# A. the watch opens the case itself
# --------------------------------------------------------------------------

class TestTheWatchOpensTheCase:
    def test_a_first_look_opens_no_case(self, config, ledger, store):
        run = run_watch(config, ledger, now=T0)
        assert store.list() == []
        assert all(o.case_id == "" for o in run.outcomes)

    def test_a_material_drift_opens_exactly_one_case_naming_the_function(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501", radius=1200)
        run = run_watch(config, ledger, now=T0 + WEEK)

        cases = store.list()
        assert len(cases) == 1
        case = cases[0]
        assert case.machines == (KEY_0501,)
        assert case.affected_functions == ("SF-01",)
        assert case.status is CaseStatus.OPEN
        assert [c["item_id"] for c in case.changed_items] == ["ITM-ZONES"]
        # The run says which case it opened, and seals that fact.
        drifted = next(o for o in run.outcomes if o.serial == "0501")
        assert drifted.case_id == case.case_id and drifted.case_status == "open"
        assert next(o for o in run.outcomes if o.serial == "0412").case_id == ""
        assert f"case {case.case_id}" in run.sealed
        assert f"case {case.case_id} [open]" in run.summary()
        sealed = json.loads(json.dumps(run.to_dict()))
        assert sealed["outcomes"][1]["case_id"] == case.case_id
        # Opened by the watch, which is an automation actor.
        opening = case_kind_entries(ledger)[0].evidence()
        assert opening.actor.kind == "automation"

    def test_a_dry_run_writes_no_case_and_nothing_else(self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        before = len(ledger)
        run = run_watch(config, ledger, now=T0 + WEEK, seal=False)
        assert len(ledger) == before
        assert store.list() == []
        assert run.changed and run.changed[0].case_id == ""

    def test_a_quiet_week_opens_nothing(self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0412")
        reexport(work, "0501")
        run_watch(config, ledger, now=T0 + WEEK)
        assert store.list() == []


# --------------------------------------------------------------------------
# B. idempotency
# --------------------------------------------------------------------------

class TestIdempotency:
    def test_a_second_run_over_the_same_state_adds_no_case_entry(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        run_watch(config, ledger, now=T0 + WEEK)
        entries = len(case_kind_entries(ledger))
        assert entries == 1

        for n in (2, 3):
            reexport(work, "0501", radius=1200, stamp=f"2026-10-0{n}T05:00:00Z")
            run = run_watch(config, ledger, now=T0 + n * WEEK)
            assert next(o for o in run.outcomes if o.serial == "0501").status == "observed"
        assert len(case_kind_entries(ledger)) == entries
        assert len(store.list()) == 1
        assert len(store.list()[0].history) == 1

    def test_re_running_the_very_same_drift_is_a_no_op(self, work, config, ledger, store):
        """The crash-recovery case, with the clock held still: not one new row."""
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        manifests = manifests_from_ledger(ledger, KEY_0501)
        # Re-assess the same observation the run just acted on.
        from assurance.change import assess_drift
        from assurance.machinery.divergence import compare

        run_watch(config, ledger, now=T0 + WEEK)
        before = len(ledger)
        observed = manifests_from_ledger(ledger, KEY_0501)[-1]
        again = assess_drift(store, compare(manifests[-1], observed), observed,
                             VerificationRecord.from_ledger(ledger, subject=KEY_0501),
                             interventions_from_ledger(ledger, KEY_0501),
                             actor=Actor("watch", kind="automation"))
        assert again is not None and len(ledger) == before


# --------------------------------------------------------------------------
# the crash window
# --------------------------------------------------------------------------

class TestTheCrashWindow:
    def test_a_failure_after_the_case_and_before_the_manifest_loses_nothing(
            self, work, config, ledger, store, monkeypatch):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)

        import assurance.watch.runner as runner

        real = runner.record_manifest
        calls = {"n": 0}

        def die_once(*a, **kw):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("power cut between the case and the manifest")
            return real(*a, **kw)

        monkeypatch.setattr(runner, "record_manifest", die_once)
        with pytest.raises(RuntimeError, match="power cut"):
            run_watch(config, ledger, now=T0 + WEEK)

        # The case is already on the record; the new manifest is not.
        assert len(store.list()) == 1
        assert len(manifests_from_ledger(ledger, KEY_0501)) == 1

        # The next run still sees the old baseline, so it sees the drift again.
        run = run_watch(config, ledger, now=T0 + 2 * WEEK)
        drifted = next(o for o in run.outcomes if o.serial == "0501")
        assert drifted.status == "changed"
        assert len(store.list()) == 1                      # no duplicate
        assert drifted.case_id == store.list()[0].case_id
        assert len(manifests_from_ledger(ledger, KEY_0501)) == 2
        # And the case points at the manifest that was actually sealed.
        sealed_hash = manifests_from_ledger(ledger, KEY_0501)[-1].content_hash()
        assert sealed_hash in {link["content_hash"]
                               for link in store.list()[0].linked_evidence}
        # ...and only that one: the reading that was never sealed is not left behind as a
        # second "observed manifest" pointer (a repeat look at the same drift is the same
        # fact read again, so the freshest reading replaces its evidence pointers).
        observed = [link["content_hash"] for link in store.list()[0].linked_evidence
                    if link.get("note") == "observed manifest"]
        assert observed == [sealed_hash]
        assert reconstruct_case(ledger, drifted.case_id).ok
        ok, problems = ledger.verify_chain()
        assert ok, problems

    def test_a_failure_before_the_case_leaves_the_drift_detectable(
            self, work, config, ledger, store, monkeypatch):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)

        import assurance.watch.runner as runner

        monkeypatch.setattr(runner, "assess_drift",
                            lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
        with pytest.raises(OSError, match="disk full"):
            run_watch(config, ledger, now=T0 + WEEK)
        # Nothing was sealed that would hide it: not the manifest, not the divergence.
        assert len(manifests_from_ledger(ledger, KEY_0501)) == 1
        assert ledger.entries(kind="machinery.divergence") == []

        monkeypatch.undo()
        run = run_watch(config, ledger, now=T0 + 2 * WEEK)
        drifted = next(o for o in run.outcomes if o.serial == "0501")
        assert drifted.status == "changed" and drifted.case_id
        assert len(store.list()) == 1


# --------------------------------------------------------------------------
# the reopen rule, over the watch
# --------------------------------------------------------------------------

class TestReopenOverTheWatch:
    def test_unchanged_after_closure_does_not_reopen_but_a_return_does(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)                          # A -> B
        run_watch(config, ledger, now=T0 + WEEK)
        case_b = store.list()[0]
        closed, _ = work_to_closure(ledger, store, case_b.case_id, KEY_0501,
                                    when=T0 + WEEK + timedelta(days=1))
        assert closed.status is CaseStatus.CLOSED
        entries = len(case_kind_entries(ledger))

        # Week 3: nothing moved. The closed case is left exactly as it is.
        reexport(work, "0501", radius=1200, stamp="2026-10-05T05:00:00Z")
        run = run_watch(config, ledger, now=T0 + 3 * WEEK)
        assert next(o for o in run.outcomes if o.serial == "0501").status == "observed"
        assert len(case_kind_entries(ledger)) == entries
        assert store.get(case_b.case_id).status is CaseStatus.CLOSED

        # Week 4: somebody puts it back (B -> A) — a different trigger, its own case.
        reexport(work, "0501", radius=1500, stamp="2026-10-12T05:00:00Z")
        run_watch(config, ledger, now=T0 + 4 * WEEK)
        assert len(store.list()) == 2
        assert store.get(case_b.case_id).status is CaseStatus.CLOSED

        # Week 5: and changed again (A -> B). The closed case's trigger recurred.
        reexport(work, "0501", radius=1200, stamp="2026-10-19T05:00:00Z")
        run = run_watch(config, ledger, now=T0 + 5 * WEEK)
        reopened = store.get(case_b.case_id)
        assert reopened.status is CaseStatus.OPEN
        assert len(reopened.prior_closures) == 1
        assert reopened.prior_closures[0]["closed_by"] == "v.grimaldi"
        assert next(o for o in run.outcomes if o.serial == "0501").case_id == case_b.case_id
        assert len(store.list()) == 2
        assert reconstruct_case(ledger, case_b.case_id).ok


# --------------------------------------------------------------------------
# E. failing to observe is explicit
# --------------------------------------------------------------------------

class TestFailingToObserve:
    def test_an_uncollectable_machine_neither_advances_nor_closes_its_case(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)
        run_watch(config, ledger, now=T0 + WEEK)
        case = store.list()[0]
        claim(store, case.case_id, owner="v.grimaldi", actor=PERSON)
        while store.get(case.case_id).status is not CaseStatus.AWAITING_REVERIFICATION:
            advance(store, case.case_id, actor=PERSON)
        before = case_kind_entries(ledger)

        shutil.rmtree(work / "0501")
        run = run_watch(config, ledger, now=T0 + 2 * WEEK)

        blind = next(o for o in run.outcomes if o.serial == "0501")
        assert blind.status == "uncollectable"
        assert run.verdict == "degraded"
        assert store.get(case.case_id).status is CaseStatus.AWAITING_REVERIFICATION
        assert case_kind_entries(ledger) == before
        # It says so, by name, rather than leaving the reader to infer it.
        assert blind.open_case_ids == (case.case_id,)
        assert any(case.case_id in w and "cannot advance or close" in w
                   for w in blind.warnings)

    def test_a_blind_machine_with_no_case_opens_none(self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        shutil.rmtree(work / "0501")
        run = run_watch(config, ledger, now=T0 + WEEK)
        assert run.verdict == "degraded" and store.list() == []


# --------------------------------------------------------------------------
# F. interventions
# --------------------------------------------------------------------------

class TestInterventions:
    def _intervene(self, ledger, key, *, at, **over):
        kw = {"intervention_id": "INT-0007", "machine_key": key, "item_id": "ITM-FW",
              "kind": InterventionKind.UPDATE, "occurred_at": at,
              "performed_by": Actor("m.tech", "service technician"),
              "reason": "Vendor advisory: watchdog timeout under bus load.",
              "from_hash": "a" * 64, "to_hash": "d" * 64,
              "affects_functions": ("SF-01", "SF-02")}
        kw.update(over)
        record_intervention(ledger, Intervention(**kw))

    def test_an_unreferenced_intervention_that_broke_evidence_opens_a_case_once(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        self._intervene(ledger, KEY_0412, at=T0 + timedelta(days=3))
        reexport(work, "0412")
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + WEEK)

        out = next(o for o in run.outcomes if o.serial == "0412")
        assert len(out.intervention_case_ids) == 1
        case = store.get(out.intervention_case_ids[0])
        assert case.trigger_type.value == "intervention"
        assert case.trigger_id == "INT-0007"
        assert set(case.affected_functions) == {"SF-01", "SF-02"}
        assert case.evidence_current["SF-01"] == "stale"

        entries = len(case_kind_entries(ledger))
        again = run_watch(config, ledger, now=T0 + 2 * WEEK)
        assert next(o for o in again.outcomes
                    if o.serial == "0412").intervention_case_ids == ()
        assert len(case_kind_entries(ledger)) == entries

    def test_an_intervention_with_nothing_verified_before_it_opens_no_case(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        self._intervene(ledger, KEY_0412, at=T0 + timedelta(days=3))
        run = run_watch(config, ledger, now=T0 + WEEK)
        assert next(o for o in run.outcomes
                    if o.serial == "0412").intervention_case_ids == ()

    def test_an_intervention_already_owned_by_an_open_drift_case_does_not_get_a_second(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        reexport(work, "0412", fw=b"firmware 3.9.0")                 # the real change
        self._intervene(ledger, KEY_0412, at=T0 + timedelta(days=3))  # its paperwork
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + WEEK)
        out = next(o for o in run.outcomes if o.serial == "0412")
        assert out.case_id and out.intervention_case_ids == ()
        assert len(store.list()) == 1


# --------------------------------------------------------------------------
# advisories, through a signed feed
# --------------------------------------------------------------------------

IDENTITY = SupplierIdentity(supplier_id="controlco", legal_name="ControlCo GmbH",
                            key_contact="the 2025 supply contract")


def _advisory(advisory_id="CTRL-2026-11") -> ComponentAdvisory:
    return ComponentAdvisory(
        advisory_id=advisory_id, issued_by="controlco",
        issued_at=datetime(2026, 9, 10, 8, tzinfo=UTC),
        title="Authentication bypass in safety controller firmware",
        summary="A crafted frame permits a safety parameter write.",
        severity=AdvisorySeverity.STOP_USE,
        reference="https://controlco.example/psirt/CTRL-2026-11",
        remedy="Update to 3.9.1.",
        affected=(AffectedArtefact(supplier="ControlCo",
                                   name="Safety controller firmware",
                                   versions=("3.8.2", "3.9.0")),))


@pytest.fixture
def plant(tmp_path):
    plan = plan_dict()
    for item in plan["items"]:
        item["supplier"] = {"ITM-ZONES": "ScanCo", "ITM-PARAMS": "RoboCo",
                            "ITM-PLC": "ControlCo", "ITM-FW": "ControlCo"}[item["item_id"]]
    (tmp_path / "plans").mkdir()
    (tmp_path / "plans" / "cell.json").write_text(json.dumps(plan))
    for n, serial in enumerate(("CELL-0412", "CELL-0501")):
        write_export(tmp_path / "exports" / serial, stamp="2026-09-14T06:02:11Z",
                     operator="ci", seq=f"004{n}")
    key = SigningKey.generate()
    (tmp_path / "controlco.pub").write_text(key.verifying.pem())
    (tmp_path / "watch.json").write_text(json.dumps({
        "watch_id": "plant-1", "organisation": "Grimaldi Engineering S.r.l.",
        "targets": [{"serial": s, "plan": "plans/cell.json", "root": f"exports/{s}",
                     "site": "Plant 1", "country": "IT",
                     "read_from_machine": True}      # the harness plays an on-machine watch (B6)
                    for s in ("CELL-0412", "CELL-0501")],
        "feeds": [{"supplier_id": "controlco", "feed": "feed.jsonl",
                   "public_key": "controlco.pub"}],
    }))
    ledger = EvidenceLedger(tmp_path / "evidence.db")
    return {"dir": tmp_path, "key": key, "feed": AdvisoryFeed(tmp_path / "feed.jsonl"),
            "ledger": ledger, "store": CaseStore(ledger)}


def _run(plant, **kw):
    return run_watch(WatchConfig.from_json(plant["dir"] / "watch.json"),
                     plant["ledger"], **kw)


class TestAdvisories:
    def test_a_signed_advisory_opens_one_case_naming_every_exposed_machine(self, plant):
        _run(plant, now=T0)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        run = _run(plant, now=T0 + WEEK)

        finding = run.advisories.new[0]
        cases = plant["store"].list()
        assert len(cases) == 1
        case = cases[0]
        assert finding.case_id == case.case_id
        assert case.trigger_id == "CTRL-2026-11"
        assert len(case.machines) == 2
        assert case.status is CaseStatus.OPEN
        sealed = [e.evidence().body for e in plant["ledger"].entries(kind="watch.run")][-1]
        assert sealed["advisories"]["findings"][0]["case_id"] == case.case_id

    def test_an_outstanding_advisory_writes_nothing_on_later_runs(self, plant):
        _run(plant, now=T0)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant, now=T0 + WEEK)
        entries = len(case_kind_entries(plant["ledger"]))
        for n in (2, 3):
            run = _run(plant, now=T0 + n * WEEK)
            assert run.advisories.findings[0].state == "outstanding"
            assert run.advisories.findings[0].case_id             # still named
        assert len(case_kind_entries(plant["ledger"])) == entries == 1

    def test_a_dry_run_opens_no_advisory_case(self, plant):
        _run(plant, now=T0)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        before = len(plant["ledger"])
        run = _run(plant, now=T0 + WEEK, seal=False)
        assert len(plant["ledger"]) == before
        assert plant["store"].list() == []
        assert run.advisories.new[0].case_id == ""

    def test_a_feed_that_does_not_verify_opens_no_case(self, plant):
        _run(plant, now=T0)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        raw = json.loads(plant["feed"].path.read_text().splitlines()[0])
        raw["advisory"]["remedy"] = "Flash http://evil.example/fw.bin."
        plant["feed"].path.write_text(json.dumps(raw) + "\n")
        run = _run(plant, now=T0 + WEEK)
        assert run.verdict == "degraded"
        assert plant["store"].list() == []

    def test_a_withdrawal_puts_a_question_to_the_owner_and_closes_nothing(self, plant):
        _run(plant, now=T0)
        publish(_advisory(), IDENTITY, plant["key"], plant["feed"])
        _run(plant, now=T0 + WEEK)
        case = plant["store"].list()[0]
        claim(plant["store"], case.case_id, owner="v.grimaldi", actor=PERSON)

        withdraw("CTRL-2026-11", "3.9.0 is not affected; the range was wrong",
                 IDENTITY, plant["key"], plant["feed"])
        run = _run(plant, now=T0 + 2 * WEEK)
        assert run.advisories.withdrawn[0].case_id == case.case_id

        after = plant["store"].get(case.case_id)
        assert after.status is CaseStatus.IN_REVIEW and after.owner == "v.grimaldi"
        # Name-only matches already put questions to a person; the withdrawal adds one.
        assert len(after.human_decisions_required) == len(case.human_decisions_required) + 1
        assert "range was wrong" in after.human_decisions_required[-1]
        # Announced once; the second look writes nothing.
        entries = len(case_kind_entries(plant["ledger"]))
        _run(plant, now=T0 + 3 * WEEK)
        assert len(case_kind_entries(plant["ledger"])) == entries
        # It cannot reach ready-to-close until a person has answered every question.
        with pytest.raises(CaseTransitionError):
            for _ in range(5):
                c = advance(plant["store"], case.case_id, actor=PERSON)
                assert c.status is not CaseStatus.READY_TO_CLOSE
        for question in after.human_decisions_required:
            resolve_decision(plant["store"], case.case_id, decision=question,
                             resolution="Looked at it; the remedy does not apply here.",
                             actor=PERSON)
        rejected = decide(plant["store"], case.case_id, disposition="rejected",
                          reason="Raised on an advisory the supplier retracted.",
                          actor=PERSON)
        assert rejected.status is CaseStatus.REJECTED
        assert reconstruct_case(plant["ledger"], case.case_id).ok


# --------------------------------------------------------------------------
# I. the whole path, real engines, no shortcuts
# --------------------------------------------------------------------------

class TestEndToEnd:
    def test_firmware_change_to_verifiable_closure(self, work, config, ledger, store):
        # -- week 0: two machines enrolled, each verified once ---------------
        run_watch(config, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        verify_machine(ledger, KEY_0501, when=T0 + timedelta(days=1))
        assert store.list() == []

        # -- week 1: somebody reflashed the safety controller on 0412 ------
        reexport(work, "0412", fw=b"firmware 3.9.0")
        reexport(work, "0501")
        run = run_watch(config, ledger, now=T0 + WEEK)
        assert [o.serial for o in run.changed] == ["0412"]

        (case,) = store.list()                                   # exactly one
        assert case.machines == (KEY_0412,)
        assert set(case.affected_functions) == {"SF-01", "SF-02"}
        assert any(c["item_id"] == "ITM-FW" for c in case.changed_items)
        assert case.status is CaseStatus.OPEN
        assert "intervention record" in case.required_actions[0]

        # -- week 2: the same state again is a no-op ------------------------
        entries = case_kind_entries(ledger)
        reexport(work, "0412", fw=b"firmware 3.9.0", stamp="2026-09-28T05:00:00Z")
        reexport(work, "0501", stamp="2026-09-28T05:00:00Z")
        run = run_watch(config, ledger, now=T0 + 2 * WEEK)
        assert run.changed == ()
        assert case_kind_entries(ledger) == entries
        assert [c.case_id for c in store.list()] == [case.case_id]

        # -- the integrator files the paperwork and re-verifies --------------
        record_intervention(ledger, Intervention(
            intervention_id="INT-0042", machine_key=KEY_0412, item_id="ITM-FW",
            kind=InterventionKind.UPDATE, occurred_at=T0 + timedelta(days=5),
            performed_by=Actor("m.tech", "service technician"),
            reason="Controller reflashed to 3.9.0 for the watchdog fix.",
            from_hash="a" * 64, to_hash="d" * 64, affects_functions=("SF-01", "SF-02")))
        c = claim(store, case.case_id, owner="v.grimaldi", actor=PERSON)
        c = advance(store, c.case_id, actor=PERSON)
        c = advance(store, c.case_id, actor=PERSON)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION

        # An AI or a scheduled job cannot close it, at any point.
        for bot in (Actor("watch", "scheduled watch", kind="automation"),
                    Actor("assistant", "agent", kind="agent")):
            with pytest.raises(CaseTransitionError):
                decide(store, c.case_id, disposition="closed", reason="r", actor=bot)

        bundle = verify_machine(ledger, KEY_0412, when=after_the_ledger(T0 + timedelta(days=9)))
        observed = manifests_from_ledger(ledger, KEY_0412)[-1]
        c = reverify(store, c.case_id, observed,
                     VerificationRecord.from_ledger(ledger, subject=KEY_0412),
                     interventions_from_ledger(ledger, KEY_0412),
                     verification_content_hash=bundle.content_hash, actor=PERSON)
        assert c.status is CaseStatus.READY_TO_CLOSE
        assert {"relation": "supports", "content_hash": bundle.content_hash,
                "note": f"re-verification evidence ({KEY_0412})"} in c.linked_evidence
        assert c.evidence_current == {"SF-01": "current", "SF-02": "current"}

        # -- a person closes it ------------------------------------------------
        closed = decide(store, c.case_id, disposition="closed",
                        reason="Stop performance re-run after the 3.9.0 reflash.",
                        actor=PERSON)
        assert closed.status is CaseStatus.CLOSED and closed.decision_by == "v.grimaldi"

        # -- week 3: unchanged configuration does not reopen it -----------------
        after_close = case_kind_entries(ledger)
        reexport(work, "0412", fw=b"firmware 3.9.0", stamp="2026-10-05T05:00:00Z")
        reexport(work, "0501", stamp="2026-10-05T05:00:00Z")
        run = run_watch(config, ledger, now=T0 + 3 * WEEK)
        assert run.changed == ()
        assert case_kind_entries(ledger) == after_close
        assert store.get(case.case_id).status is CaseStatus.CLOSED

        # -- and the whole thing replays from the record alone --------------------
        replay = reconstruct_case(ledger, case.case_id)
        assert replay.ok, replay.violations
        assert replay.case == store.get(case.case_id)
        ok, problems = ledger.verify_chain()
        assert ok, problems


class TestAnIncompleteCollectionIsNotAConfiguration:
    def test_a_week_with_an_export_missing_does_not_reopen_a_closed_case(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        reexport(work, "0501", radius=1200)                           # A -> B
        run_watch(config, ledger, now=T0 + WEEK)
        case_b = store.list()[0]
        closed, _ = work_to_closure(ledger, store, case_b.case_id, KEY_0501,
                                    when=T0 + WEEK + timedelta(days=1))
        assert closed.status is CaseStatus.CLOSED

        # A transient fault: one export is missing for one week.
        (work / "0501" / "robot-params.json").unlink()
        run = run_watch(config, ledger, now=T0 + 3 * WEEK)
        partial = next(o for o in run.outcomes if o.serial == "0501")
        assert partial.collection_complete is False
        assert any("were not found" in w for w in partial.warnings)
        observation = [e.evidence().body for e in ledger.entries(kind="watch.observation")
                       if e.evidence().body["serial"] == "0501"][-1]
        assert observation["complete"] is False and observation["missing"] == ["ITM-PARAMS"]
        marked = manifests_from_ledger(ledger, KEY_0501)[-1]
        assert "collection incomplete" in marked.notes
        assert store.get(case_b.case_id).status is CaseStatus.CLOSED   # not touched

        # The fault clears and the machine is as it was when the case was closed.
        reexport(work, "0501", radius=1200, stamp="2026-10-12T05:00:00Z")
        run_watch(config, ledger, now=T0 + 4 * WEEK)
        again = store.get(case_b.case_id)
        assert again.status is CaseStatus.CLOSED
        assert again.prior_closures == ()
        assert reconstruct_case(ledger, case_b.case_id).ok

    def test_an_incomplete_first_look_is_not_sealed_as_the_baseline(
            self, work, config, ledger, store):
        (work / "0501" / "robot-params.json").unlink()
        run = run_watch(config, ledger, now=T0)
        partial = next(o for o in run.outcomes if o.serial == "0501")
        assert partial.collection_complete is False
        assert partial.status != "observed"
        # Nothing was agreed as the configuration: the record holds no baseline.
        assert manifests_from_ledger(ledger, KEY_0501) == []
        assert "baseline" in partial.detail and "incomplete" in partial.detail
        # The attempt is recorded, as an incomplete one.
        body = [e.evidence().body for e in ledger.entries(kind="watch.observation")
                if e.evidence().body["serial"] == "0501"][-1]
        assert body["complete"] is False and body["missing"] == ["ITM-PARAMS"]

        # The fault clears: the first complete look is the baseline and is not a drift.
        reexport(work, "0501", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
        again = run_watch(config, ledger, now=T0 + WEEK)
        second = next(o for o in again.outcomes if o.serial == "0501")
        assert second.status == "first_seen" and second.collection_complete is True
        assert len(manifests_from_ledger(ledger, KEY_0501)) == 1
        assert store.list() == []
        assert case_kind_entries(ledger) == []

    def test_an_incomplete_look_is_never_the_baseline_the_next_look_is_judged_against(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        good = manifests_from_ledger(ledger, KEY_0501)[-1]
        (work / "0501" / "robot-params.json").unlink()
        run_watch(config, ledger, now=T0 + WEEK)       # may open a case: the gap is real
        after_gap = case_kind_entries(ledger)
        reexport(work, "0501", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
        run = run_watch(config, ledger, now=T0 + 2 * WEEK)
        back = next(o for o in run.outcomes if o.serial == "0501")
        # Compared with the last complete configuration, not with the partial one:
        # the machine is as it was, and that is not a second drift.
        assert back.status == "observed", back.detail
        assert back.previous_configuration == good.configuration_hash()
        assert case_kind_entries(ledger) == after_gap

    def test_a_complete_look_has_no_incomplete_mark(self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        assert "collection incomplete" not in manifests_from_ledger(ledger, KEY_0501)[-1].notes
        body = [e.evidence().body for e in ledger.entries(kind="watch.observation")][-1]
        assert body["complete"] is True and body["missing"] == []
