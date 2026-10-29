"""Staleness integrity, round 2: what a filer's dates, a damaged record or a clock can still do.

Round 1 bounded a *future* date, the join, silence about a change and an unreadable
change record. A second, independent review found the same classes still open:

* a FAIL is dated by its own start, which the filer controls: a backdated start (a
  logger with a dead clock) still sorted it under any older PASS;
* a verification bundle or manifest that fails its seal was still silently dropped, and a
  non-JSON row crashed the readers;
* the ledger's ``at`` is not monotone, and implied-change dating leant on it;
* a back-dated "explanation" erased a change the ledger shows;
* the watch opened a second case for a change a person had already ruled on.

Each class below states the invariant, not the implementation.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from assurance.core.evidence import Actor, Evidence, Origin
from assurance.core.identity import utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.machine.bundle import BUNDLE_KIND
from assurance.machinery.intervention import Intervention, InterventionKind
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    ManifestSource,
    SafetyItem,
)
from assurance.machinery.record import (
    INTERVENTION_KIND,
    MANIFEST_KIND,
    UnknownMachineError,
    interventions_from_ledger,
    record_intervention,
    record_manifest,
)
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

from . import interfaces_fixtures as fx
from .test_assurance_machine import client as _client
from .test_assurance_machine import store as _store
from .test_assurance_staleness_integrity import (
    CHECKS,
    HASH_A,
    HASH_B,
    KEY,
    TECH,
    _post_verify,
    coverage_of,
    edit_payload,
    manifest,
    raw_body,
    seal,
    seal_raw_body,
    update,
    verified_machine,
)
from .test_assurance_staleness_integrity import clock as _clock

client, store = _client, _store
live_api = fx.live_api

D1 = datetime(2026, 10, 1, tzinfo=UTC)


@pytest.fixture
def ledger(tmp_path: Path) -> EvidenceLedger:
    return EvidenceLedger(tmp_path / "ledger.db")


clock = _clock


def stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def fail_body(start: str) -> dict:
    return raw_body(start, verified=("workspace_containment",), violated=("speed_limit",),
                    verdict="fail")


def corrupt_row(ledger: EvidenceLedger, seq: int, payload: str = "this is not json") -> None:
    db = sqlite3.connect(ledger.path)
    db.execute("update chain set payload=? where seq=?", (payload, seq))
    db.commit()
    db.close()


def last_seq(ledger: EvidenceLedger, kind: str) -> int:
    return ledger.entries(kind=kind)[-1].seq


# =====================================================================
# A. A FAIL is dated when it was FILED, never by a start the filer chose
# =====================================================================

class TestAFailureIsDatedByTheLedgersClockNotTheFilers:
    def test_a_failing_run_with_a_start_backdated_a_month_still_fails(self, ledger):
        now = utc_now()
        seal(ledger, now - timedelta(days=10), tid="PASS", expect="pass")
        seal(ledger, now - timedelta(days=30), speed=900.0, tid="FAIL", expect="fail")
        assert coverage_of(ledger, [])[0].functions[0].coverage is Coverage.FAILING

    @pytest.mark.parametrize("start", ["0001-01-02T00:00:00Z", "1970-01-01T00:00:00Z",
                                       "2000-01-01T00:00:00Z"])
    def test_a_failing_run_from_a_logger_with_a_dead_clock_still_fails(self, ledger, start):
        seal_raw_body(ledger, raw_body(stamp(utc_now() - timedelta(days=5)), verified=CHECKS))
        seal_raw_body(ledger, fail_body(start))
        assert coverage_of(ledger, [])[0].functions[0].coverage is Coverage.FAILING

    def test_a_pass_that_began_a_second_after_the_failure_began_does_not_supersede_it(
            self, ledger, clock):
        clock.at(10)
        seal_raw_body(ledger, fail_body("2026-10-01T08:00:00Z"))       # filed 10:00
        clock.at(11)
        seal_raw_body(ledger, raw_body("2026-10-01T08:00:01Z", verified=CHECKS))   # filed 11:00
        report, recs = coverage_of(ledger, [])
        assert [r.date_suspect for r in recs] == [False, False]
        assert report.functions[0].coverage is Coverage.FAILING

    def test_a_pass_that_began_after_the_failure_was_filed_does_supersede_it(
            self, ledger, clock):
        clock.at(10)
        seal_raw_body(ledger, fail_body("2026-10-01T08:00:00Z"))       # filed 10:00
        clock.at(11)
        seal_raw_body(ledger, raw_body("2026-10-01T10:30:00Z", verified=CHECKS))   # began 10:30
        assert coverage_of(ledger, [])[0].functions[0].coverage is Coverage.CURRENT

    def test_the_record_carries_the_ledgers_filing_time(self, ledger, clock):
        clock.at(9, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:00:00Z", verified=CHECKS))
        (rec,) = VerificationRecord.from_ledger(ledger, subject=KEY)
        assert rec.filed_at == clock.now
        assert rec.effective_at == datetime(2026, 10, 1, 8, 0, tzinfo=UTC)

    def test_a_record_built_by_hand_with_no_filing_time_is_dated_by_its_start(self):
        def rec(seq, day, verified, not_verified):
            return VerificationRecord(
                content_hash=f"{seq:064x}", effective_at=datetime(2026, 9, day, tzinfo=UTC),
                ledger_seq=seq, product="p", product_version="1", verdict="x",
                tier="validated", checks_verified=verified, checks_not_verified=not_verified)

        newer_fail = rec(1, 20, (), CHECKS)
        older_pass = rec(2, 1, CHECKS, ())
        assert assess_coverage(manifest(), [newer_fail, older_pass], []
                               ).functions[0].coverage is Coverage.FAILING


# =====================================================================
# E. The ledger's `at` is not monotone; nothing may lean on it being so
# =====================================================================

class TestABackwardsClockStepDoesNotFreshenEvidence:
    def test_a_manifest_stamped_before_an_earlier_pass_still_shows_its_change_after_it(
            self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        clock.at(8, 5)
        seal_raw_body(ledger, raw_body("2026-10-01T08:01:00Z", verified=CHECKS))
        clock.at(7)       # the plant PC's clock stepped back two hours
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].invalidated_by.startswith("implied:")

    def test_a_failure_stamped_before_an_earlier_pass_still_outranks_it(self, ledger, clock):
        clock.at(8, 5)
        seal_raw_body(ledger, raw_body("2026-10-01T08:01:00Z", verified=CHECKS))
        clock.at(7)
        seal_raw_body(ledger, fail_body("2026-10-01T06:30:00Z"))
        report, recs = coverage_of(ledger, [])
        assert recs[1].filed_at >= recs[0].filed_at
        assert report.functions[0].coverage is Coverage.FAILING

    def test_the_filing_time_of_a_record_never_precedes_the_units_earlier_records(
            self, ledger, clock):
        clock.at(9)
        record_manifest(ledger, manifest(mid="M1"))
        clock.at(7)
        seal_raw_body(ledger, raw_body("2026-10-01T06:00:00Z", verified=CHECKS))
        (rec,) = VerificationRecord.from_ledger(ledger, subject=KEY)
        assert rec.filed_at == datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


class TestMoreOnWhichFilingIsLatest:
    def test_the_report_names_the_failure_that_was_filed_last_not_the_one_that_began_last(
            self, ledger, clock):
        clock.at(10)
        seal_raw_body(ledger, raw_body("2026-10-01T08:00:00Z",
                                       verified=("speed_limit",),
                                       violated=("workspace_containment",), verdict="fail"))
        clock.at(11)
        seal_raw_body(ledger, raw_body("2026-10-01T07:00:00Z",
                                       verified=("workspace_containment",),
                                       violated=("speed_limit",), verdict="fail"))
        report, recs = coverage_of(ledger, [])
        assert report.functions[0].coverage is Coverage.FAILING
        assert report.functions[0].last_verified_hash == recs[1].content_hash

    def test_a_change_record_that_cannot_be_read_is_dated_by_the_filing_clock(
            self, ledger, clock):
        clock.at(8, 5)
        seal_raw_body(ledger, raw_body("2026-10-01T08:01:00Z", verified=CHECKS))
        clock.at(7)       # stepped back: the row's raw `at` precedes the pass
        ledger.append(Evidence(kind=INTERVENTION_KIND, body={"intervention": {"oops": 1}},
                               actor=TECH, origin=Origin(system="test")).seal(), subject=KEY)
        report, _ = coverage_of(ledger)
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].invalidated_by.startswith("unreadable:")


# =====================================================================
# B. A damaged record is never read as "nothing happened"
# =====================================================================

class TestADamagedVerificationIsAssumedToHaveFailed:
    def _pass_then_fail(self, ledger):
        now = utc_now()
        seal(ledger, now - timedelta(days=10), tid="PASS", expect="pass")
        seal(ledger, now - timedelta(days=1), speed=900.0, tid="FAIL", expect="fail")
        return last_seq(ledger, BUNDLE_KIND)

    def test_a_failing_bundle_edited_after_sealing_is_not_dropped(self, ledger):
        seq = self._pass_then_fail(ledger)
        edit_payload(ledger, seq, lambda p: p["body"].update(trace_id="EDITED"))
        report, recs = coverage_of(ledger, [])
        assert [r.unreadable for r in recs] == [False, True]
        fn = report.functions[0]
        assert fn.coverage is Coverage.FAILING
        assert any("damaged" in c for c in report.checks_skipped)

    def test_a_passing_bundle_edited_after_sealing_covers_nothing(self, ledger):
        seal(ledger, utc_now() - timedelta(days=1), expect="pass")
        edit_payload(ledger, last_seq(ledger, BUNDLE_KIND),
                     lambda p: p["body"].update(verdict="pass-edited"))
        report, recs = coverage_of(ledger, [])
        assert [r.unreadable for r in recs] == [True]
        assert report.functions[0].coverage is Coverage.FAILING

    def test_a_sealed_bundle_of_the_wrong_shape_is_damaged_too(self, ledger):
        seal(ledger, utc_now() - timedelta(days=1), expect="pass")
        ledger.append(Evidence(kind=BUNDLE_KIND, body={"checks": "not a list"}, actor=TECH,
                               origin=Origin(system="test")).seal(), subject=KEY)
        report, recs = coverage_of(ledger, [])
        # a body whose checks cannot be read is read as having verified nothing and the
        # unit's next run decides; it must not raise
        assert report.functions[0].coverage in (Coverage.CURRENT, Coverage.FAILING)

    def test_a_row_that_is_not_json_does_not_raise_and_fails_the_function(self, ledger):
        seq = self._pass_then_fail(ledger)
        corrupt_row(ledger, seq)
        report, recs = coverage_of(ledger, [])
        assert recs[-1].unreadable and recs[-1].ledger_seq == seq
        assert report.functions[0].coverage is Coverage.FAILING

    def test_a_run_that_began_after_a_damaged_row_was_filed_stands(self, ledger, clock):
        clock.at(8)
        seal_raw_body(ledger, raw_body("2026-10-01T07:30:00Z", verified=CHECKS))
        clock.at(9)
        seal_raw_body(ledger, fail_body("2026-10-01T08:30:00Z"))
        corrupt_row(ledger, last_seq(ledger, BUNDLE_KIND))
        assert coverage_of(ledger, [])[0].functions[0].coverage is Coverage.FAILING
        clock.at(10)
        seal_raw_body(ledger, raw_body("2026-10-01T09:30:00Z", verified=CHECKS))
        report, recs = coverage_of(ledger, [])
        assert recs[1].filed_at == datetime(2026, 10, 1, 9, 0, tzinfo=UTC)   # the row's own `at`
        assert report.functions[0].coverage is Coverage.CURRENT


def tamper_newest_manifest(ledger: EvidenceLedger) -> int:
    seq = last_seq(ledger, MANIFEST_KIND)
    edit_payload(ledger, seq, lambda p: p["body"]["manifest"].update(notes="edited"))
    return seq


class TestADamagedManifestIsAssumedToHaveChangedEverything:
    def _changed_machine(self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        clock.at(8, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:10:00Z", verified=CHECKS))
        clock.at(9)
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))      # the change
        clock.at(9, 5)

    def test_the_newest_manifest_edited_after_sealing_is_not_dropped(self, ledger, clock):
        self._changed_machine(ledger, clock)
        tamper_newest_manifest(ledger)
        report, _ = coverage_of(ledger, m=manifest(mid="M1", fw=HASH_A))
        fn = report.functions[0]
        assert fn.coverage is Coverage.STALE
        assert fn.invalidated_by.startswith("unreadable:")

    def test_the_fleet_does_not_call_that_machine_covered(self, ledger, clock):
        self._changed_machine(ledger, clock)
        tamper_newest_manifest(ledger)
        fleet = Fleet.from_ledger(ledger).to_dict()
        assert fleet["chain_verified"] is False
        assert fleet["machines"][0]["verdict"] != "covered"
        assert fleet["summary"]["covered"] == 0

    def test_a_manifest_row_that_is_not_json_does_not_raise(self, ledger, clock):
        self._changed_machine(ledger, clock)
        corrupt_row(ledger, last_seq(ledger, MANIFEST_KIND))
        fleet = Fleet.from_ledger(ledger).to_dict()
        assert fleet["machines"][0]["verdict"] != "covered"
        report, _ = coverage_of(ledger, m=manifest(mid="M1", fw=HASH_A))
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_sealed_manifest_of_the_wrong_shape_is_damaged_too(self, ledger, clock):
        self._changed_machine(ledger, clock)
        ledger.append(Evidence(kind=MANIFEST_KIND, body={"manifest": {"oops": 1}}, actor=TECH,
                               origin=Origin(system="test")).seal(), subject=KEY)
        report, _ = coverage_of(ledger, m=manifest(mid="M1", fw=HASH_A))
        assert report.functions[0].invalidated_by.startswith(("unreadable:", "implied:"))
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_non_json_intervention_row_is_dated_by_its_own_filing_time(self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest())
        clock.at(8, 35)
        seal_raw_body(ledger, raw_body("2026-10-01T08:30:00Z", verified=CHECKS))
        clock.at(9)
        record_intervention(ledger, update(when=D1.replace(hour=8, minute=45)))
        corrupt_row(ledger, last_seq(ledger, INTERVENTION_KIND))
        assert coverage_of(ledger)[0].functions[0].coverage is Coverage.STALE
        clock.at(9, 35)
        seal_raw_body(ledger, raw_body("2026-10-01T09:30:00Z", verified=CHECKS))
        report, _ = coverage_of(ledger)
        assert report.functions[0].coverage is Coverage.CURRENT
        clock.at(11)
        (iv,) = interventions_from_ledger(ledger, KEY)
        assert iv.occurred_at == datetime(2026, 10, 1, 9, 0, tzinfo=UTC)


class TestAChainThatDoesNotVerifyIsNeverCovered:
    def test_the_fleet_does_not_call_a_machine_covered_when_the_chain_is_broken(self, ledger):
        verified_machine(ledger)
        assert Fleet.from_ledger(ledger).to_dict()["machines"][0]["verdict"] in (
            "covered", "gaps")
        ledger.append(Evidence(kind="test.unrelated", body={"x": 1}, actor=TECH,
                               origin=Origin(system="test")).seal(), subject="unrelated")
        edit_payload(ledger, ledger.entries()[-1].seq, lambda p: p["body"].update(x=2))
        fleet = Fleet.from_ledger(ledger).to_dict()
        assert fleet["chain_verified"] is False
        assert fleet["machines"][0]["verdict"] != "covered"
        assert fleet["summary"]["covered"] == 0

    def test_the_coverage_route_refuses_a_chain_that_does_not_verify(self, client, store):
        from assurance.api import deps

        account = store.upsert_account(email="chain@example.de", tier="cell")
        headers = {"X-API-Key": store.issue_key(account.id)}
        client.post("/v1/machinery/manifest", headers=headers,
                    json={"manifest": manifest().to_dict()})
        _post_verify(client, headers, datetime(2026, 9, 14, tzinfo=UTC), 300.0, "RUN")
        body = {"manifest": manifest().to_dict()}
        assert client.post("/v1/machinery/coverage", headers=headers, json=body
                           ).status_code == 200
        tenant = EvidenceLedger(deps.tenant_ledger_path(account.id))
        edit_payload(tenant, tenant.entries()[0].seq,
                     lambda p: p["body"]["manifest"].update(notes="edited"))
        r = client.post("/v1/machinery/coverage", headers=headers, json=body)
        assert r.status_code == 409
        assert r.json()["detail"]["error"] == "ledger_chain_unverified"
        fleet = client.get("/v1/fleet/machines", headers=headers).json()
        assert fleet["chain_verified"] is False
        assert fleet["summary"]["covered"] == 0


# =====================================================================
# D. An explanation never erases a change the ledger shows
# =====================================================================

def bot_update(*, when: datetime, to_hash: str = HASH_B) -> Intervention:
    return Intervention(
        intervention_id="INT-BOT", machine_key=KEY, item_id="fw", kind=InterventionKind.UPDATE,
        occurred_at=when, performed_by=Actor("ci-bot", "automation", kind="automation"),
        reason="x", from_hash=HASH_A, to_hash=to_hash, affects_functions=("SF-1",))


class TestAnExplanationDoesNotEraseAChange:
    def _timeline(self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        clock.at(8, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:10:00Z", verified=CHECKS))
        clock.at(9)
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))

    def test_a_backdated_record_filed_afterwards_leaves_the_function_stale(
            self, ledger, clock):
        self._timeline(ledger, clock)
        clock.at(9, 30)
        record_intervention(ledger, bot_update(when=datetime(2026, 9, 13, 12, tzinfo=UTC)))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].invalidated_by.startswith("implied:")

    def test_the_change_is_marked_explained_and_by_what(self, ledger, clock):
        self._timeline(ledger, clock)
        clock.at(9, 30)
        record_intervention(ledger, bot_update(when=datetime(2026, 9, 13, 12, tzinfo=UTC)))
        implied = [i for i in interventions_from_ledger(ledger, KEY)
                   if i.intervention_id.startswith("implied:")]
        assert [i.explained_by for i in implied] == ["INT-BOT"]

    def test_a_run_that_began_after_the_explanation_was_filed_clears_it(self, ledger, clock):
        self._timeline(ledger, clock)
        clock.at(9, 30)
        record_intervention(ledger, bot_update(when=datetime(2026, 9, 13, 12, tzinfo=UTC)))
        clock.at(10)
        seal_raw_body(ledger, raw_body("2026-10-01T09:45:00Z", verified=CHECKS))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_the_honest_order_record_then_reverify_then_look_stands(self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        clock.at(8, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:10:00Z", verified=CHECKS))
        clock.at(8, 41)
        record_intervention(ledger, update(when=D1.replace(hour=8, minute=40)))
        clock.at(8, 55)
        seal_raw_body(ledger, raw_body("2026-10-01T08:50:00Z", verified=CHECKS))
        clock.at(9)
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_run_that_began_before_the_record_was_filed_does_not(self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        clock.at(8, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:10:00Z", verified=CHECKS))
        clock.at(8, 45)
        seal_raw_body(ledger, raw_body("2026-10-01T08:35:00Z", verified=CHECKS))
        clock.at(8, 50)
        record_intervention(ledger, update(when=D1.replace(hour=8, minute=36)))
        clock.at(9)
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.STALE


    def test_an_explanation_filed_before_the_manifest_is_dated_by_its_filing_not_its_claim(
            self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A,
                                         taken=datetime(2026, 9, 13, tzinfo=UTC)))
        clock.at(8, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:10:00Z", verified=CHECKS))
        clock.at(8, 40)
        # claims it happened on 14 September, long before the pass it must not outrank
        record_intervention(ledger, bot_update(when=datetime(2026, 9, 14, 12, tzinfo=UTC)))
        clock.at(9)
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.STALE
        (marker,) = implied_of(ledger)
        assert marker.occurred_at == datetime(2026, 10, 1, 8, 40, tzinfo=UTC)

    def test_an_explanation_filed_after_a_run_that_followed_the_manifest_does_not_undo_it(
            self, ledger, clock):
        clock.at(8)
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A,
                                         taken=datetime(2026, 9, 13, tzinfo=UTC)))
        clock.at(8, 30)
        seal_raw_body(ledger, raw_body("2026-10-01T08:10:00Z", verified=CHECKS))
        clock.at(9)
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        clock.at(9, 20)
        seal_raw_body(ledger, raw_body("2026-10-01T09:15:00Z", verified=CHECKS))
        clock.at(9, 30)     # the paperwork arrives afterwards
        record_intervention(ledger, update(when=D1.replace(hour=8, minute=50)))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert report.functions[0].coverage is Coverage.CURRENT
        assert [i.explained_by for i in implied_of(ledger)] == ["INT-1"]


# =====================================================================
# the implied change: ids, scope, and what it tells the reader
# =====================================================================

def implied_of(ledger: EvidenceLedger):
    return [i for i in interventions_from_ledger(ledger, KEY)
            if i.intervention_id.startswith("implied:")]


class TestImpliedChangeIdentity:
    def test_two_items_changed_in_one_manifest_are_two_changes(self, ledger):
        doc = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                         HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        doc2 = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "2", "e" * 64,
                          HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A, extra_items=(doc,)))
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B, extra_items=(doc2,)))
        found = implied_of(ledger)
        assert sorted(i.item_id for i in found) == ["fw", "plc"]
        assert len({i.intervention_id for i in found}) == 2

    def test_the_same_change_seen_twice_over_time_is_two_events_with_two_ids(self, ledger):
        for mid, fw in (("M1", HASH_A), ("M2", HASH_B), ("M3", HASH_A), ("M4", HASH_B)):
            record_manifest(ledger, manifest(mid=mid, fw=fw))
        found = implied_of(ledger)
        assert len(found) == 3
        assert len({i.intervention_id for i in found}) == 3

    def test_sealing_the_same_manifest_again_is_not_a_change(self, ledger):
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        assert len(implied_of(ledger)) == 1

    def test_re_declaring_which_functions_an_item_implements_is_not_a_change(self, ledger):
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A, implements=("SF-1",)))
        record_manifest(ledger, manifest(mid="M2", fw=HASH_A, implements=()))
        assert implied_of(ledger) == []

    def test_an_item_that_added_is_not_explained_by_a_removal_record(self, ledger):
        record_manifest(ledger, manifest(mid="M1"))
        removal = Intervention(
            intervention_id="INT-R", machine_key=KEY, item_id="plc",
            kind=InterventionKind.REMOVAL, occurred_at=utc_now() - timedelta(hours=1),
            performed_by=TECH, reason="removed", affects_functions=("SF-1",))
        record_intervention(ledger, removal)
        added = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        record_manifest(ledger, manifest(mid="M2", extra_items=(added,)))
        assert [(i.item_id, i.explained_by) for i in implied_of(ledger)] == [("plc", "")]

    def test_the_report_tells_the_reader_to_verify_after_sealing(self, ledger):
        record_manifest(ledger, manifest(mid="M1", fw=HASH_A))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_manifest(ledger, manifest(mid="M2", fw=HASH_B))
        report, _ = coverage_of(ledger, m=manifest(mid="M2", fw=HASH_B))
        assert "run the verification again after" in report.functions[0].detail


class TestAssessingADriftDoesNotCountItsOwnImpliedChange:
    def test_assessing_before_and_after_the_manifest_is_sealed_is_the_same_case(self, ledger):
        from assurance.change import CaseStore, assess_drift
        from assurance.machinery.divergence import compare

        before = manifest(mid="M1", fw=HASH_A)
        after = manifest(mid="M2", fw=HASH_B)
        record_manifest(ledger, before)
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        store = CaseStore(ledger)
        actor = Actor("watch", kind="automation")
        divergence = compare(before, after)
        first = assess_drift(store, divergence, after,
                             VerificationRecord.from_ledger(ledger, subject=KEY),
                             interventions_from_ledger(ledger, KEY), actor=actor)
        record_manifest(ledger, after)
        rows = len(ledger)
        again = assess_drift(store, divergence, after,
                             VerificationRecord.from_ledger(ledger, subject=KEY),
                             interventions_from_ledger(ledger, KEY), actor=actor)
        assert again is not None and first is not None
        assert len(ledger) == rows
        assert again.evidence_current == first.evidence_current


# =====================================================================
# Low items
# =====================================================================

class TestTheLibraryIsTheSingleGate:
    def test_filing_a_change_under_a_key_with_no_manifest_is_refused_by_the_library(
            self, ledger):
        record_manifest(ledger, manifest())
        with pytest.raises(UnknownMachineError):
            record_intervention(
                ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC), key="ACME/AR-7#0412"))
        assert ledger.entries(kind=INTERVENTION_KIND) == []

    def test_the_library_writes_the_manifests_spelling_of_a_function(self, ledger):
        record_manifest(ledger, manifest())
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                           affects=("sf-1",)))
        (iv,) = interventions_from_ledger(ledger, KEY, include_implied=False)
        assert iv.affects_functions == ("SF-1",)


class TestAChangeIsCheckedAgainstWhatWasFoundNotWhatWasPlanned:
    def test_a_function_the_plan_leaves_out_is_still_known(self, ledger):
        from dataclasses import replace

        from assurance.machinery.manifest import SafetyFunction
        from assurance.machinery.record import check_intervention

        found = manifest(mid="FOUND")
        found = replace(found, functions=(*found.functions,
                                          SafetyFunction("SF-2", "second", verified_by=CHECKS)))
        record_manifest(ledger, found)
        record_manifest(ledger, manifest(mid="PLAN", source=ManifestSource.AS_INTENDED))
        checked, _ = check_intervention(
            ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC), affects=("sf-2",)))
        assert checked.affects_functions == ("SF-2",)


class TestAPlanDoesNotRewriteWhatAnItemImplements:
    def test_the_manifest_a_change_is_read_against_is_a_look_not_the_newer_plan(self, ledger):
        from assurance.machinery.record import check_intervention

        record_manifest(ledger, manifest(mid="FOUND", implements=("SF-1",)))
        record_manifest(ledger, manifest(mid="PLAN", implements=(),
                                         source=ManifestSource.AS_INTENDED))
        _, used = check_intervention(
            ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC), affects=()))
        assert used.manifest_id == "FOUND"
        assert used.item("fw").implements == ("SF-1",)


class TestTheNewestLookAndDeclarationAreBothHeard:
    def test_a_function_only_the_older_kind_declares_is_still_known(self, ledger):
        from dataclasses import replace

        from assurance.machinery.manifest import SafetyFunction
        from assurance.machinery.record import check_intervention

        found = manifest(mid="FOUND")
        found = replace(found, functions=(*found.functions,
                                          SafetyFunction("SF-2", "second", verified_by=CHECKS)))
        record_manifest(ledger, found)
        record_manifest(ledger, manifest(mid="DECLARED", source=ManifestSource.AS_DECLARED))
        checked, _ = check_intervention(
            ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC), affects=("sf-2",)))
        assert checked.affects_functions == ("SF-2",)


class TestTheHeavyRoutesAreOffTheEventLoop:
    @pytest.mark.parametrize("router", ["fleet_routes.fleet_router", "change_routes.change_router",
                                        "check_routes.check_router",
                                        "machinery_routes.machinery_router",
                                        "value_routes.value_router",
                                        "watch_routes.watch_router"])
    def test_no_handler_runs_on_the_loop_unless_it_awaits(self, router):
        import importlib
        import inspect

        module, _, name = router.partition(".")
        routes = getattr(importlib.import_module(f"assurance.api.{module}"), name).routes
        assert routes
        offenders = []
        for route in routes:
            endpoint = getattr(route, "endpoint", None)
            if endpoint is not None and inspect.iscoroutinefunction(endpoint) \
                    and "await " not in inspect.getsource(endpoint):
                offenders.append(f"{sorted(route.methods or [])} {route.path}")
        assert offenders == []

    def test_the_fleet_read_opens_a_bounded_number_of_connections_per_machine(
            self, ledger, monkeypatch):
        machines = 12
        for n in range(machines):
            serial = f"{n:04d}"
            record_manifest(ledger, manifest(mid=f"A{n}", serial=serial, fw=HASH_A))
            record_manifest(ledger, manifest(mid=f"B{n}", serial=serial, fw=HASH_B))
            seal_raw_body(ledger, raw_body("2026-10-01T08:00:00Z", verified=CHECKS),
                          subject=f"Acme/AR-7#{serial}")
        opened = {"n": 0}
        real = EvidenceLedger._connect

        def counting(self):
            opened["n"] += 1
            return real(self)

        monkeypatch.setattr(EvidenceLedger, "_connect", counting)
        fleet = Fleet.from_ledger(ledger)
        assert len(fleet.records) == machines
        # one connection per kind of record read for each machine (interventions, manifests,
        # verifications), plus a fixed handful for the fleet itself: linear, never quadratic
        assert opened["n"] <= 4 * machines + 10


class TestTheVerifyGateBoundsWhatWaits:
    def _hold(self, monkeypatch):
        from assurance.api import machine_routes

        release = threading.Event()
        real = machine_routes.build_bundle

        def spy(*args, **kwargs):
            release.wait(timeout=30)
            return real(*args, **kwargs)

        monkeypatch.setattr(machine_routes, "build_bundle", spy)
        return release

    def _fire(self, live_api, headers_list):
        statuses: list[tuple[int, dict]] = []
        gate = threading.Barrier(len(headers_list))

        def post(h):
            from .test_assurance_verify_event_loop import _body

            with httpx.Client(base_url=live_api.url, timeout=120.0) as c:
                gate.wait(timeout=30)
                r = c.post("/v1/machine/verify", json=_body(40), headers=h)
                statuses.append((r.status_code, dict(r.headers)))

        threads = [threading.Thread(target=post, args=(h,), daemon=True) for h in headers_list]
        for t in threads:
            t.start()
        return threads, statuses

    @staticmethod
    def _wait_for(statuses, code, timeout=30.0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if any(s == code for s, _ in statuses):
                return True
            time.sleep(0.05)
        return False

    def test_one_account_cannot_fill_every_slot(self, live_api, monkeypatch):
        release = self._hold(monkeypatch)
        _, headers = live_api.account("greedy@example.de")
        threads, statuses = self._fire(live_api, [headers] * 3)
        try:
            assert self._wait_for(statuses, 429), "a third in-flight run for one account was admitted"
        finally:
            release.set()
        for t in threads:
            t.join(timeout=60)
        assert sorted(s for s, _ in statuses) == [200, 200, 429]
        refused = next(h for s, h in statuses if s == 429)
        assert int(refused.get("retry-after", "0")) > 0

    def test_requests_beyond_the_waiting_bound_are_refused_not_held(
            self, live_api, monkeypatch):
        from assurance.api import machine_routes

        release = self._hold(monkeypatch)
        limit = machine_routes.MAX_CONCURRENT_VERIFICATIONS + machine_routes.MAX_WAITING_VERIFICATIONS
        heads = [live_api.account(f"crowd{n}@example.de")[1] for n in range(limit + 1)]
        threads, statuses = self._fire(live_api, heads)
        try:
            assert self._wait_for(statuses, 503), "every request was held"
        finally:
            release.set()
        for t in threads:
            t.join(timeout=120)
        assert sorted(s for s, _ in statuses).count(503) == 1
        assert sorted(s for s, _ in statuses).count(200) == limit
        refused = next(h for s, h in statuses if s == 503)
        assert int(refused.get("retry-after", "0")) > 0


class TestTheSpecAndTheTypesSayWhatTheServerDoes:
    def test_the_intervention_route_declares_its_refusals(self):
        from assurance.api.service import create_app

        ops = create_app().openapi()["paths"]
        post = ops["/v1/machinery/intervention"]["post"]["responses"]
        assert {"200", "409", "422"} <= set(post)
        assert "ledger_chain_unverified" in json.dumps(
            ops["/v1/machinery/coverage"]["post"]["responses"]["409"])

    def test_the_fleet_row_type_has_the_unrecorded_changes_count(self):
        text = (Path(__file__).resolve().parent.parent / "app" / "lib"
                / "assuranceApi.ts").read_text()
        assert "unrecorded_changes: number" in text
