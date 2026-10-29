"""Round 2 x staleness integrity: the watch over an export folder, with damaged or explained records.

The two features meet in ``run_watch``: the "not a look" rule decides whether an unchanged hash
may be called QUIET, the staleness-integrity rules decide what the ledger's records may be
trusted to say. Neither may weaken the other:

* an unchanged hash over an unasserted export folder is never QUIET, and it opens no second
  case for a change the drift case already owns;
* a verification the reader cannot use is a stand-in assumed to have failed, so the watch
  never reports that function covered on the strength of it, asserted or not;
* a ledger whose chain does not verify never gives a machine cover.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from assurance.change.store import ChainBrokenError
from assurance.machine.bundle import BUNDLE_KIND
from assurance.machinery.staleness import Coverage
from assurance.watch.cli import main as watch_main
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from . import test_assurance_watch_cases as wc
from .test_assurance_staleness_integrity_round2 import corrupt_row, last_seq
from .test_assurance_watch_cases import KEY_0412, T0, WEEK, reexport, verify_machine

work, config, ledger, store = wc.work, wc.config, wc.ledger, wc.store


@pytest.fixture
def unasserted(work):
    """The same plant, but the operator never asserted the folders came off the machines."""
    doc = json.loads((work / "watch.json").read_text())
    for target in doc["targets"]:
        target.pop("read_from_machine", None)
    doc["targets"] = [t for t in doc["targets"] if t["serial"] == "0412"]   # one machine
    (work / "watch.json").write_text(json.dumps(doc))
    return WatchConfig.from_json(work / "watch.json")


def _out(run, serial="0412"):
    return next(o for o in run.outcomes if o.serial == serial)


class TestAnExportFolderDriftIsOwnedByItsCase:
    def test_the_week_after_a_drift_is_degraded_not_quiet_and_opens_no_second_case(
            self, work, unasserted, ledger, store):
        run_watch(unasserted, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        reexport(work, "0412", fw=b"firmware 3.9.0")
        drift = run_watch(unasserted, ledger, now=T0 + WEEK)
        assert _out(drift).status == "changed" and drift.verdict == "findings"
        case_id = _out(drift).case_id
        assert case_id
        after_drift = {c.case_id for c in store.list()}

        again = run_watch(unasserted, ledger, now=T0 + 2 * WEEK)
        out = _out(again)
        assert out.status == "observed" and out.not_a_look      # nothing moved, nobody looked
        assert again.verdict == "degraded"                      # so never QUIET
        assert out.intervention_case_ids == ()                  # the drift case owns the change
        assert {c.case_id for c in store.list()} == after_drift


    def test_a_change_with_its_paperwork_over_an_export_folder_is_still_one_case(
            self, work, unasserted, ledger, store):
        from datetime import UTC, datetime  # noqa: F401

        from assurance.core.evidence import Actor
        from assurance.machinery.intervention import Intervention, InterventionKind
        from assurance.machinery.record import record_intervention
        run_watch(unasserted, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        reexport(work, "0412", fw=b"firmware 3.9.0")                       # the real change
        record_intervention(ledger, Intervention(                           # its paperwork
            intervention_id="INT-0007", machine_key=KEY_0412, item_id="ITM-FW",
            kind=InterventionKind.UPDATE, occurred_at=T0 + timedelta(days=3),
            performed_by=Actor("m.tech", "service technician"), reason="vendor update",
            from_hash="a" * 64, to_hash="d" * 64, affects_functions=("SF-01", "SF-02")))
        run_watch(unasserted, ledger, now=T0 + WEEK)
        for week in (2, 3):
            again = run_watch(unasserted, ledger, now=T0 + week * WEEK)
            assert again.verdict == "degraded"                  # still not a look at the machine
            assert _out(again).intervention_case_ids == ()
        assert len(store.list()) == 1


    def test_a_rejected_drift_case_over_an_export_folder_gets_no_second_case(
            self, work, unasserted, ledger, store):
        from assurance.change import decide
        from assurance.core.evidence import Actor
        run_watch(unasserted, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        reexport(work, "0412", fw=b"firmware 3.9.0")
        drift = run_watch(unasserted, ledger, now=T0 + WEEK)
        decide(store, _out(drift).case_id, disposition="rejected", reason="not a real change",
               actor=Actor("v.grimaldi", "safety lead", kind="person"))
        before = {c.case_id for c in store.list()}
        again = run_watch(unasserted, ledger, now=T0 + 2 * WEEK)
        assert again.verdict == "degraded"
        assert {c.case_id for c in store.list()} == before


class TestADamagedVerificationIsNotCoverEvenWhenTheHashIsUnchanged:
    def test_an_asserted_unchanged_machine_is_not_covered_by_a_bundle_it_cannot_read(
            self, work, config, ledger, store):
        run_watch(config, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        run_watch(config, ledger, now=T0 + timedelta(days=2))
        corrupt_row(ledger, last_seq(ledger, BUNDLE_KIND))
        run = run_watch(config, ledger, now=T0 + WEEK)
        out = _out(run)
        assert out.status == "observed"
        # The hash did not move and the folder is asserted, but the one verification there is
        # cannot be read: it stands in as a failure, and the function is not current.
        assert out.newly_uncovered or out.still_uncovered
        assert run.verdict != "quiet"

    def test_the_coverage_the_watch_reasons_from_calls_it_failing(self, work, config, ledger):
        from assurance.machinery.manifest import ManifestSource  # noqa: F401
        from assurance.machinery.record import interventions_from_ledger, manifests_from_ledger
        from assurance.machinery.staleness import VerificationRecord, assess_coverage
        run_watch(config, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        corrupt_row(ledger, last_seq(ledger, BUNDLE_KIND))
        manifest = manifests_from_ledger(ledger, KEY_0412)[-1]
        report = assess_coverage(manifest, VerificationRecord.from_ledger(ledger, subject=KEY_0412),
                                 interventions_from_ledger(ledger, KEY_0412))
        assert all(f.coverage is not Coverage.CURRENT for f in report.functions)


class TestABrokenChainIsNeverQuiet:
    def test_a_ledger_that_does_not_verify_does_not_give_a_quiet_watch(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        verify_machine(ledger, KEY_0412, when=T0 + timedelta(days=1))
        assert run_watch(config, ledger, now=T0 + timedelta(days=2)).verdict in (
            "quiet", "findings")
        import sqlite3
        db = sqlite3.connect(ledger.path)
        db.execute("update chain set payload = replace(payload, 'Plant 2', 'Plant 9') "
                   "where seq = (select min(seq) from chain where payload like '%Plant 2%')")
        db.commit()
        db.close()
        assert not ledger.verify_chain()[0]
        # The watch reads cases and records through a store that refuses a chain that does not
        # verify. Raising is acceptable; saying QUIET (or covered) is not.
        try:
            run = run_watch(config, ledger, now=T0 + WEEK)
        except ChainBrokenError:
            return
        assert run.verdict != "quiet"


def test_the_cli_exit_code_for_an_unasserted_unchanged_folder_is_two(work, unasserted, capsys):
    ledger_path = work / "cli.db"
    args = ["run", str(work / "watch.json"), "--ledger", str(ledger_path)]
    watch_main(args)
    rc = watch_main(args)
    assert rc == 2


class TestUnitBindingAndTheWatch:
    """A unit-bound, validated recording does not turn an export folder into a look."""

    def _bind(self, ledger, key, *, validated):
        from .support_trust_hardening import attested_bundle, community_bundle
        if validated:
            bundle, _ = attested_bundle(key, file_under=ledger)
        else:
            bundle = community_bundle(key, file_under=ledger)
        return bundle

    def _floor(self, ledger):
        from assurance.fleet.registry import Fleet
        row = next(m for m in Fleet.from_ledger(ledger).to_dict()["machines"]
                   if KEY_0412 in json.dumps(m))
        return row["verdict"], row["evidence_tier_floor"]

    def test_validated_cover_over_an_unasserted_folder_is_still_not_quiet(
            self, work, unasserted, ledger):
        run_watch(unasserted, ledger, now=T0)                  # enrols the unit's manifest
        assert self._bind(ledger, KEY_0412, validated=True).tier.value == "validated"
        verdict, floor = self._floor(ledger)
        assert (verdict, floor) == ("covered", "validated")    # the strongest cover there is
        run = run_watch(unasserted, ledger, now=T0 + WEEK)
        assert _out(run).status == "observed" and _out(run).not_a_look
        assert run.verdict == "degraded"                       # but the folder is no look
        assert self._floor(ledger) == ("covered", "validated")  # and the watch changes no tier

    def test_community_capped_cover_over_an_asserted_folder_is_not_promoted(
            self, work, config, ledger):
        run_watch(config, ledger, now=T0)
        assert self._bind(ledger, KEY_0412, validated=False).tier.value == "community"
        verdict, floor = self._floor(ledger)
        assert (verdict, floor) == ("covered_at_community", "community")
        run = run_watch(config, ledger, now=T0 + WEEK)
        assert _out(run).status == "observed"
        # the asserted look is a look, but it never makes the evidence validated
        assert self._floor(ledger) == ("covered_at_community", "community")
