"""Staleness integrity: dates, the change join, and records that cannot be read.

Evidence that looks fresher than it is, is the worst outcome this product can
produce. Each class here is the regression for one way the coverage join let it
happen, written against the invariant and not against the implementation:

* a date the *filer* controls (a trace's start) may never make a PASS look newer
  than a change or a later run the ledger itself ordered after it, and may never
  push a FAIL out of consideration;
* the join between a change and the functions it disturbs is not allowed to
  depend on a hand-typed list or on the spelling of an id;
* a configuration change visible in the ledger's own manifests is a change, with
  or without somebody having written an intervention record for it;
* a change record the reader cannot read is never read as "no change".
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from assurance.core.evidence import Actor, Evidence, Origin
from assurance.core.identity import utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.machine.bundle import BUNDLE_KIND, build_bundle
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
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
    INTERVENTION_KIND,
    interventions_from_ledger,
    record_intervention,
    record_manifest,
)
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage

from .support_recorder import Recorder
from .test_assurance_machine import client as _client
from .test_assurance_machine import keyed
from .test_assurance_machine import store as _store
from .test_assurance_machine_provenance import ACTOR, envelope

client, store = _client, _store

KEY = "Acme/AR-7#0412"
CHECKS = ("workspace_containment", "speed_limit")
TECH = Actor("tech", "technician")
HASH_A, HASH_B = "a" * 64, "b" * 64


# ---------------------------------------------------------------------
# builders
# ---------------------------------------------------------------------

def manifest(*, fw: str = HASH_A, taken: datetime = datetime(2026, 9, 13, tzinfo=UTC),
             source: ManifestSource = ManifestSource.AS_FOUND, mid: str = "M",
             serial: str = "0412", implements: tuple[str, ...] = ("SF-1",),
             extra_items: tuple[SafetyItem, ...] = ()) -> SafetyManifest:
    return SafetyManifest(
        manifest_id=mid, machine=MachineIdentity("Acme", "AR-7", serial),
        source=source, taken_at=taken, taken_by=Actor("t", "tech"),
        items=(SafetyItem("fw", ItemKind.FIRMWARE, "fw", "1", fw,
                          HashSource.READ_FROM_MACHINE, implements=implements),
               *extra_items),
        functions=(SafetyFunction("SF-1", "safe stop", verified_by=CHECKS),),
    )


def trace(start: datetime, speed: float = 300.0, tid: str = "RUN") -> Trace:
    return Trace(trace_id=tid, provenance=Provenance.FIELD, source_system="fw",
                 started_at=start, sample_rate_hz=50.0,
                 samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=speed,
                                      mode=OperatingMode.SSM, separation=3000.0)
                               for i in range(40)))


def seal(ledger: EvidenceLedger, start: datetime, *, speed: float = 300.0,
         tid: str = "RUN", expect: str | None = None):
    bundle = build_bundle(envelope(), trace(start, speed, tid), actor=ACTOR,
                          ledger=ledger, subject=KEY)
    if expect:
        assert bundle.verdict.value == expect
    return bundle


def seal_raw_body(ledger: EvidenceLedger, body: dict[str, Any], subject: str = KEY) -> None:
    """A sealed verification record whose body says whatever it likes (a re-sealed file)."""
    ledger.append(Evidence(kind=BUNDLE_KIND, body=body, actor=ACTOR,
                           origin=Origin(system="test")).seal(), subject=subject)


def raw_body(start: str, *, verified=(), violated=(), verdict="pass") -> dict[str, Any]:
    return {"trace_started_at": start, "product": "Cell", "product_version": "1.0.0",
            "verdict": verdict, "tier": "validated",
            "checks": ([{"name": n, "outcome": "verified"} for n in verified]
                       + [{"name": n, "outcome": "violated"} for n in violated])}


def update(*, when: datetime, affects: tuple[str, ...] = ("SF-1",), iid: str = "INT-1",
           key: str = KEY, item: str = "fw", to_hash: str = HASH_B,
           from_hash: str = HASH_A) -> Intervention:
    return Intervention(intervention_id=iid, machine_key=key, item_id=item,
                        kind=InterventionKind.UPDATE, occurred_at=when,
                        performed_by=TECH, reason="firmware update",
                        from_hash=from_hash, to_hash=to_hash, affects_functions=affects)


def coverage_of(ledger: EvidenceLedger, interventions=None, m: SafetyManifest | None = None):
    recs = VerificationRecord.from_ledger(ledger, subject=KEY)
    ivs = interventions if interventions is not None else interventions_from_ledger(ledger, KEY)
    return assess_coverage(m or manifest(), recs, ivs), recs


@pytest.fixture
def ledger(tmp_path: Path) -> EvidenceLedger:
    return EvidenceLedger(tmp_path / "ledger.db")


def edit_payload(ledger: EvidenceLedger, seq: int, edit) -> None:
    db = sqlite3.connect(ledger.path)
    payload = json.loads(db.execute("select payload from chain where seq=?", (seq,))
                         .fetchone()[0])
    edit(payload)
    db.execute("update chain set payload=? where seq=?",
               (json.dumps(payload, sort_keys=True, separators=(",", ":")), seq))
    db.commit()
    db.close()


# =====================================================================
# H2. Dates a filer controls
# =====================================================================

class TestADateTheFilerControlsNeverMakesEvidenceLookFresher:
    def test_a_newer_failing_run_with_a_start_dated_days_ahead_still_fails(self, ledger):
        now = utc_now()
        seal(ledger, now - timedelta(days=60), tid="OLD-PASS", expect="pass")
        # today's run violates the speed limit; the recorder's clock is three days fast
        seal(ledger, now + timedelta(days=3), speed=900.0, tid="TODAY-FAIL", expect="fail")
        report, recs = coverage_of(ledger)
        assert any(r.date_suspect for r in recs)
        assert report.functions[0].coverage is Coverage.FAILING

    def test_a_failing_run_whose_start_is_unreadable_still_fails_over_an_older_pass(
            self, ledger):
        seal_raw_body(ledger, raw_body("2026-01-01T00:00:00Z", verified=CHECKS))
        seal_raw_body(ledger, raw_body("not a date", verified=("workspace_containment",),
                                       violated=("speed_limit",), verdict="fail"))
        report, recs = coverage_of(ledger)
        assert [r.date_suspect for r in recs] == [False, True]
        assert report.functions[0].coverage is Coverage.FAILING

    def test_a_pass_dated_a_day_ahead_does_not_outrank_a_genuinely_later_fail(self, ledger):
        now = utc_now()
        seal(ledger, now + timedelta(hours=20), tid="PASS-AHEAD", expect="pass")
        later = utc_now()          # taken after the PASS was filed: really later
        seal(ledger, later, speed=900.0, tid="REAL-LATER-FAIL", expect="fail")
        report, _ = coverage_of(ledger)
        assert report.functions[0].coverage is Coverage.FAILING

    def test_a_pass_dated_ahead_does_not_hide_a_change_recorded_after_it_was_filed(
            self, ledger):
        now = utc_now()
        seal(ledger, now + timedelta(hours=20), tid="PASS-AHEAD", expect="pass")
        report, recs = coverage_of(ledger, [update(when=now + timedelta(hours=1))])
        assert report.functions[0].coverage is Coverage.STALE
        assert all(r.effective_at <= utc_now() for r in recs)

    def test_a_record_never_describes_a_moment_after_it_was_filed(self, ledger):
        now = utc_now()
        seal(ledger, now + timedelta(hours=20))
        seal(ledger, now + timedelta(days=40))
        (entry_a, entry_b) = ledger.entries(kind=BUNDLE_KIND)
        recs = VerificationRecord.from_ledger(ledger, subject=KEY)
        for rec, entry in zip(recs, (entry_a, entry_b), strict=True):
            assert rec.effective_at <= datetime.fromisoformat(entry.at.replace("Z", "+00:00"))

    def test_control_the_same_pair_with_honest_dates_fails(self, ledger):
        now = utc_now()
        seal(ledger, now - timedelta(days=60), tid="OLD-PASS")
        seal(ledger, now - timedelta(hours=1), speed=900.0, tid="TODAY-FAIL")
        report, recs = coverage_of(ledger)
        assert not any(r.date_suspect for r in recs)
        assert report.functions[0].coverage is Coverage.FAILING

    def test_control_an_honest_pass_with_no_change_is_current(self, ledger):
        seal(ledger, utc_now() - timedelta(hours=1), expect="pass")
        report, recs = coverage_of(ledger, [])
        assert not any(r.date_suspect for r in recs)
        assert report.functions[0].coverage is Coverage.CURRENT

    @pytest.mark.parametrize("ahead", [timedelta(days=3), timedelta(days=400)])
    def test_a_pass_whose_date_cannot_be_believed_is_never_current(self, ledger, ahead):
        # M08 killer: a tolerance of 1000 days would believe this date.
        seal(ledger, utc_now() + ahead, expect="incomplete")   # the engine's own input_dates
        report, recs = coverage_of(ledger, [])
        assert recs[0].date_suspect
        assert report.functions[0].coverage is not Coverage.CURRENT

    def test_a_pass_with_an_unreadable_start_is_never_current(self, ledger):
        seal_raw_body(ledger, raw_body("not a date", verified=CHECKS))
        report, recs = coverage_of(ledger, [])
        assert recs[0].date_suspect
        assert report.functions[0].coverage is not Coverage.CURRENT

    def test_a_function_resting_only_on_an_undatable_pass_names_why_it_is_stale(self, ledger):
        """A stale function must name what made it so (the passport checker requires it)."""
        seal_raw_body(ledger, raw_body("not a date", verified=CHECKS))
        report, recs = coverage_of(ledger, [])
        fn = report.functions[0]
        assert fn.coverage is Coverage.STALE
        assert fn.invalidated_by == f"undatable:{recs[0].content_hash[:12]}"
        assert fn.last_verified_hash == recs[0].content_hash

    def test_an_undatable_pass_older_than_any_change_is_stale_not_current(self, ledger):
        seal_raw_body(ledger, raw_body("not a date", verified=CHECKS))
        report, _ = coverage_of(ledger, [update(when=datetime(2026, 1, 1, tzinfo=UTC))])
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_later_honest_run_does_cure_an_undatable_failure(self, ledger):
        """A FAIL whose own date is useless is still bounded by when it was filed: a
        run that started after that has superseded it. The bound is the ledger's, not
        the filer's."""
        seal(ledger, utc_now() + timedelta(days=3), speed=900.0, expect="fail")
        seal(ledger, utc_now(), expect="pass")
        report, recs = coverage_of(ledger, [])
        assert [r.date_suspect for r in recs] == [True, False]
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_an_undatable_failure_filed_after_an_honest_pass_that_began_earlier_fails(
            self, ledger):
        seal(ledger, utc_now() - timedelta(minutes=5), expect="pass")
        seal(ledger, utc_now() + timedelta(days=3), speed=900.0, expect="fail")
        report, _ = coverage_of(ledger, [])
        assert report.functions[0].coverage is Coverage.FAILING

    def test_the_report_names_a_verification_whose_date_it_could_not_use(self, ledger):
        seal(ledger, utc_now() + timedelta(days=3))
        report, _ = coverage_of(ledger, [])
        assert any("start" in c and "filed" in c for c in report.checks_skipped)

    def test_a_run_newer_by_its_start_outranks_an_older_one_filed_after_it(self, ledger):
        """M10 killer: runs are ordered by the time they describe, not by filing order
        alone. (Both dates are honest here; the older run was uploaded later.)"""
        now = utc_now()
        seal(ledger, now - timedelta(hours=1), speed=900.0, tid="NEWER-FAIL")
        seal(ledger, now - timedelta(days=30), tid="OLDER-PASS-UPLOADED-LATE")
        report, recs = coverage_of(ledger, [])
        assert [r.date_suspect for r in recs] == [False, False]
        assert report.functions[0].coverage is Coverage.FAILING


class TestWhichRunACheckRestsOn:
    def test_a_pass_that_cannot_be_dated_does_not_displace_an_older_honest_one(self, ledger):
        seal(ledger, utc_now() - timedelta(days=5), tid="HONEST", expect="pass")
        seal(ledger, utc_now() + timedelta(days=3), tid="UNDATABLE", expect="incomplete")
        report, recs = coverage_of(ledger, [])
        assert [r.date_suspect for r in recs] == [False, True]
        fn = report.functions[0]
        assert fn.coverage is Coverage.CURRENT
        assert fn.last_verified_hash == recs[0].content_hash

    def test_a_function_is_only_as_current_as_the_oldest_run_it_rests_on(self):
        """Each check is judged by its newest run; the function by the OLDEST of those."""
        def rec(seq: int, day: int, check: str) -> VerificationRecord:
            return VerificationRecord(
                content_hash=f"{seq:064x}", effective_at=datetime(2026, 9, day, tzinfo=UTC),
                ledger_seq=seq, product="p", product_version="1", verdict="pass",
                tier="validated", checks_verified=(check,), checks_not_verified=())

        old, new = rec(1, 1, "workspace_containment"), rec(2, 20, "speed_limit")
        between = update(when=datetime(2026, 9, 10, tzinfo=UTC))
        report = assess_coverage(manifest(), [old, new], [between])
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].last_verified_hash == old.content_hash

    def test_a_record_that_says_a_check_both_passed_and_failed_does_not_cover_it(self):
        both = VerificationRecord(
            content_hash="a" * 64, effective_at=datetime(2026, 9, 1, tzinfo=UTC),
            ledger_seq=1, product="p", product_version="1", verdict="pass", tier="validated",
            checks_verified=CHECKS, checks_not_verified=("speed_limit",))
        report = assess_coverage(manifest(), [both], [])
        assert report.functions[0].coverage is Coverage.FAILING


class TestAnAttestedBundleIsBoundByTheSameDates:
    def _attested(self, ledger: EvidenceLedger, start: datetime):
        rec = Recorder()
        env, tr = envelope(), trace(start)
        att = rec.attest_for(env, tr, machine_serial="0412").to_dict()
        return build_bundle(env, tr, actor=ACTOR, ledger=ledger, subject=KEY,
                            recorder_attestations=[att], recorder_trust=rec.trust(),
                            machine_serial="0412")

    def test_an_attested_run_in_the_past_lifts_the_tier_and_a_later_change_stales_it(
            self, ledger):
        start = utc_now() - timedelta(days=2)
        bundle = self._attested(ledger, start)
        assert bundle.tier.value == "validated"
        recs = VerificationRecord.from_ledger(ledger, subject=KEY)
        assert not recs[0].date_suspect
        report = assess_coverage(manifest(), recs, [update(when=utc_now() - timedelta(hours=1))])
        assert report.functions[0].coverage is Coverage.STALE

    def test_an_attested_run_cannot_be_dated_into_the_future_to_stay_current(self, ledger):
        bundle = self._attested(ledger, utc_now() + timedelta(days=3))
        # an attestation dated before the recording began is not an attestation of it
        assert bundle.tier.value != "validated"
        recs = VerificationRecord.from_ledger(ledger, subject=KEY)
        assert recs[0].date_suspect
        report = assess_coverage(manifest(), recs, [])
        assert report.functions[0].coverage is not Coverage.CURRENT


class TestTheToleranceIsExactlyOneDay:
    """The edge of the tolerance, with the ledger's clock held still."""

    NOW = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)

    def _record(self, ledger, monkeypatch, start: datetime) -> VerificationRecord:
        monkeypatch.setattr("assurance.evidence.ledger.utc_now", lambda: self.NOW)
        seal_raw_body(ledger, raw_body(start.strftime("%Y-%m-%dT%H:%M:%SZ"), verified=CHECKS))
        (rec,) = VerificationRecord.from_ledger(ledger, subject=KEY)
        return rec

    def test_a_start_exactly_a_day_ahead_is_clock_skew_not_a_suspect_date(
            self, ledger, monkeypatch):
        rec = self._record(ledger, monkeypatch, self.NOW + timedelta(days=1))
        assert rec.date_suspect is False
        assert rec.effective_at == self.NOW

    def test_a_start_a_second_beyond_a_day_ahead_is_suspect(self, ledger, monkeypatch):
        rec = self._record(ledger, monkeypatch, self.NOW + timedelta(days=1, seconds=1))
        assert rec.date_suspect is True
        assert rec.effective_at == self.NOW

    def test_a_start_in_the_past_is_taken_as_it_is(self, ledger, monkeypatch):
        rec = self._record(ledger, monkeypatch, self.NOW - timedelta(days=3))
        assert (rec.date_suspect, rec.effective_at) == (False, self.NOW - timedelta(days=3))

    def test_a_start_equal_to_the_filing_time_is_taken_as_it_is(self, ledger, monkeypatch):
        rec = self._record(ledger, monkeypatch, self.NOW)
        assert (rec.date_suspect, rec.effective_at) == (False, self.NOW)

    def test_an_unreadable_start_is_dated_when_it_was_filed(self, ledger, monkeypatch):
        monkeypatch.setattr("assurance.evidence.ledger.utc_now", lambda: self.NOW)
        seal_raw_body(ledger, raw_body("yesterday-ish", verified=CHECKS))
        (rec,) = VerificationRecord.from_ledger(ledger, subject=KEY)
        assert (rec.date_suspect, rec.effective_at) == (True, self.NOW)


class TestTheReverifyGuardOnAnUndatableRecord:
    """M29 killer: a verification that cannot be dated cannot be shown to postdate the change."""

    def test_an_undatable_verification_clears_nothing(self, ledger, tmp_path):
        from assurance.change import CaseStatus, CaseStore, reverify
        from assurance.change.service import CaseTransitionError

        from .test_assurance_change import ENG as ENGINEER
        from .test_assurance_change import LATER, drive

        store = CaseStore(ledger)
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        every_check = ("ssm_separation", "stop_characterisation", "speed_limit")
        base = {"content_hash": "9" * 64, "effective_at": LATER, "ledger_seq": 10**6,
                "product": "AR-7", "product_version": "2.4.1", "verdict": "pass",
                "tier": "validated", "checks_verified": every_check}
        with pytest.raises(CaseTransitionError):
            reverify(store, case.case_id, observed,
                     [VerificationRecord(**base, date_suspect=True)], [],
                     verification_content_hash="9" * 64, actor=ENGINEER)
        # the same record with a believable date does clear: the refusal is about the date
        done = reverify(store, case.case_id, observed, [VerificationRecord(**base)], [],
                        verification_content_hash="9" * 64, actor=ENGINEER)
        assert done.status is CaseStatus.READY_TO_CLOSE


# =====================================================================
# H2 over HTTP: the same answer through the real app
# =====================================================================

def _post_verify(client, headers, start: datetime, speed: float, tid: str):
    return client.post("/v1/machine/verify", headers=headers, json={
        "envelope": envelope().to_dict(),
        "trace": trace(start, speed, tid).hashable_payload(),
        "actor": "ci", "subject": KEY})


class TestOverHttpANewerFailureIsNotMasked:
    def test_verify_and_coverage_and_fleet_agree_that_the_newest_run_failed(
            self, client, store):
        headers = keyed(store, "cell")
        now = utc_now()
        assert client.post("/v1/machinery/manifest", headers=headers,
                           json={"manifest": manifest().to_dict()}).status_code == 200
        first = _post_verify(client, headers, now - timedelta(days=60), 300.0, "OLD-PASS")
        second = _post_verify(client, headers, now + timedelta(days=3), 900.0, "TODAY-FAIL")
        assert (first.json()["verdict"], second.json()["verdict"]) == ("pass", "fail")
        cov = client.post("/v1/machinery/coverage", headers=headers,
                          json={"manifest": manifest().to_dict()}).json()
        assert cov["functions"][0]["coverage"] == "failing"
        fleet = client.get("/v1/fleet/machines", headers=headers).json()
        assert fleet["summary"]["covered"] == 0


# =====================================================================
# H3. The join between a change and what it disturbs
# =====================================================================

def fleet_verdict(ledger: EvidenceLedger) -> str:
    return Fleet.from_ledger(ledger).to_dict()["machines"][0]["verdict"]


def verified_machine(ledger: EvidenceLedger) -> None:
    record_manifest(ledger, manifest())
    seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")


class TestTheJoinDoesNotDependOnAHandTypedList:
    def test_control_a_correctly_attributed_change_stales(self, ledger):
        verified_machine(ledger)
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC)))
        assert fleet_verdict(ledger) == "gaps"

    @pytest.mark.parametrize("label,affects", [
        ("blank list on an item the manifest says implements SF-1", ()),
        ("function id spelled in another case", ("sf-1",)),
        ("function id with stray spaces", (" SF-1 ",)),
        ("a list that names only an unrelated function", ("SF-9",)),
    ])
    def test_a_change_to_a_safety_item_disturbs_what_the_manifest_says_it_implements(
            self, ledger, label, affects):
        verified_machine(ledger)
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                           affects=affects))
        report, _ = coverage_of(ledger)
        fn = report.functions[0]
        assert fn.coverage is Coverage.STALE, label
        assert fn.invalidated_by == "INT-1", label

    def test_a_change_to_an_item_that_implements_nothing_disturbs_nothing(self, ledger):
        extra = SafetyItem("doc", ItemKind.PARAMETER_SET, "readme", "1", "c" * 64,
                           HashSource.READ_FROM_MACHINE)
        m = manifest(extra_items=(extra,))
        record_manifest(ledger, m)
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC))
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                           affects=(), item="doc"))
        report, _ = coverage_of(ledger, m=m)
        assert report.functions[0].coverage is Coverage.CURRENT
        assert report.unrevalidated_interventions == ()

    def test_an_id_that_matches_no_declared_function_is_reported_not_swallowed(self, ledger):
        verified_machine(ledger)
        iv = update(when=datetime(2026, 10, 1, tzinfo=UTC), affects=("SF-9",), item="ghost")
        report, _ = coverage_of(ledger, [iv])
        assert any("SF-9" in c for c in report.checks_skipped)


class TestReadingHandTypedFunctionIds:
    @pytest.mark.parametrize("typed,resolved", [
        ("SF-1", ("SF-1",)), ("sf-1", ("SF-1",)), (" SF-1 ", ("SF-1",)),
        ("\tsf-1\n", ("SF-1",)),
    ])
    def test_an_id_is_read_as_the_manifests_own_spelling(self, typed, resolved):
        assert manifest().resolve_function_ids([typed]) == (resolved, ())

    def test_the_same_function_typed_twice_is_resolved_once(self):
        assert manifest().resolve_function_ids(["SF-1", "sf-1", " SF-1"]) == (("SF-1",), ())

    def test_an_id_that_matches_nothing_is_unknown_and_kept_as_typed(self):
        assert manifest().resolve_function_ids(["SF-1", "SF-9", "SF-9"]) == (
            ("SF-1",), ("SF-9",))

    def test_ids_that_differ_only_by_case_are_both_kept_rather_than_guessed_between(self):
        m = manifest()
        both = SafetyManifest(
            manifest_id="M", machine=m.machine, source=m.source, taken_at=m.taken_at,
            taken_by=m.taken_by, items=m.items,
            functions=(*m.functions, SafetyFunction("sf-1", "lower", verified_by=CHECKS)))
        assert both.resolve_function_ids(["Sf-1"]) == (("SF-1", "sf-1"), ())
        assert both.resolve_function_ids(["sf-1"]) == (("sf-1",), ())     # exact wins

    def test_a_blank_list_on_a_safety_item_is_not_called_unattributed(self, ledger):
        verified_machine(ledger)
        report, _ = coverage_of(ledger, [update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                                affects=())])
        assert not any("name no safety function" in c for c in report.checks_skipped)
        assert report.unrevalidated_interventions == ("INT-1",)

    def test_a_change_to_an_item_nothing_implements_with_no_list_is_unattributed(self, ledger):
        verified_machine(ledger)
        report, _ = coverage_of(ledger, [update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                                affects=(), item="ghost")])
        assert any("INT-1" in c and "name no safety function" in c
                   for c in report.checks_skipped)


class TestTheInterventionRouteChecksWhatItIsTold:
    def _ready(self, client, store):
        headers = keyed(store, "cell")
        assert client.post("/v1/machinery/manifest", headers=headers,
                           json={"manifest": manifest().to_dict()}).status_code == 200
        r = _post_verify(client, headers, datetime(2026, 9, 14, tzinfo=UTC), 300.0, "RUN")
        assert r.status_code == 200 and r.json()["verdict"] == "pass"
        return headers

    def _coverage(self, client, headers) -> str:
        return client.post("/v1/machinery/coverage", headers=headers,
                           json={"manifest": manifest().to_dict()}
                           ).json()["functions"][0]["coverage"]

    def _post(self, client, headers, iv: Intervention):
        return client.post("/v1/machinery/intervention", headers=headers,
                           json={"intervention": iv.to_dict(), "actor": "tech"})

    def test_control_the_right_key_and_function_is_recorded_and_stales(self, client, store):
        headers = self._ready(client, store)
        r = self._post(client, headers, update(when=datetime(2026, 10, 1, tzinfo=UTC)))
        assert r.status_code == 200
        assert self._coverage(client, headers) == "stale"

    @pytest.mark.parametrize("label,key", [
        ("case variant of the maker", "ACME/AR-7#0412"),
        ("serial typo", "Acme/AR-7#412"),
        ("another unit of the same model", "Acme/AR-7#0413"),
        ("a product line, not a unit", "Acme/AR-7"),
    ])
    def test_a_change_to_a_unit_with_no_sealed_manifest_is_refused_not_attributed(
            self, client, store, label, key):
        headers = self._ready(client, store)
        r = self._post(client, headers, update(when=datetime(2026, 10, 1, tzinfo=UTC), key=key))
        assert r.status_code == 409, label
        assert r.json()["detail"]["error"] == "unknown_machine"
        # nothing was written under the wrong key, and the right unit is unaffected
        assert self._coverage(client, headers) == "current"

    def test_a_function_id_that_matches_nothing_is_refused_and_named(self, client, store):
        headers = self._ready(client, store)
        r = self._post(client, headers, update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                               affects=("SF-1", "SF-9")))
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_function"
        assert detail["unknown_functions"] == ["SF-9"]
        assert self._coverage(client, headers) == "current"

    def test_a_function_id_in_another_case_is_read_as_the_declared_one(self, client, store):
        headers = self._ready(client, store)
        r = self._post(client, headers, update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                               affects=("sf-1",)))
        assert r.status_code == 200
        assert r.json()["affects_functions"] == ["SF-1"]
        assert self._coverage(client, headers) == "stale"

    def test_a_blank_list_on_a_safety_item_is_accepted_and_still_disturbs(
            self, client, store):
        headers = self._ready(client, store)
        r = self._post(client, headers, update(when=datetime(2026, 10, 1, tzinfo=UTC),
                                               affects=()))
        assert r.status_code == 200
        assert r.json()["effective_affects_functions"] == ["SF-1"]
        assert self._coverage(client, headers) == "stale"


# =====================================================================
# R4. A configuration change the ledger's own manifests show
# =====================================================================

class TestAChangeVisibleInTheManifestHistoryIsAChange:
    def _record_and_verify(self, ledger, *, first_taken=datetime(2026, 9, 13, tzinfo=UTC)):
        record_manifest(ledger, manifest(fw=HASH_A, taken=first_taken, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")

    def test_a_newer_as_found_manifest_with_another_firmware_hash_stales_the_function(
            self, ledger):
        self._record_and_verify(ledger)
        record_manifest(ledger, manifest(fw=HASH_B, taken=datetime(2026, 10, 20, tzinfo=UTC),
                                         mid="M-B"))
        report, _ = coverage_of(ledger, m=manifest(fw=HASH_B))
        fn = report.functions[0]
        assert fn.coverage is Coverage.STALE
        assert fn.invalidated_by.startswith("implied:")
        assert fn.invalidating_item == "fw"
        assert fleet_verdict(ledger) == "gaps"

    def test_the_implied_change_is_not_dated_by_the_manifests_own_taken_at(self, ledger):
        """A manifest taken_at is the filer's word: back-dating it must not make the
        verification before it look like it came after."""
        self._record_and_verify(ledger)
        record_manifest(ledger, manifest(fw=HASH_B, taken=datetime(2026, 9, 1, tzinfo=UTC),
                                         mid="M-B"))
        report, _ = coverage_of(ledger, m=manifest(fw=HASH_B))
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_verification_run_after_the_new_manifest_was_filed_is_current_again(
            self, ledger):
        self._record_and_verify(ledger)
        record_manifest(ledger, manifest(fw=HASH_B, taken=datetime(2026, 10, 20, tzinfo=UTC),
                                         mid="M-B"))
        seal(ledger, utc_now(), tid="AFTER", expect="pass")
        report, _ = coverage_of(ledger, m=manifest(fw=HASH_B))
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_manifest_that_agrees_with_the_last_one_changes_nothing(self, ledger):
        self._record_and_verify(ledger)
        record_manifest(ledger, manifest(fw=HASH_A, taken=datetime(2026, 10, 20, tzinfo=UTC),
                                         mid="M-A2"))
        report, _ = coverage_of(ledger)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_change_recorded_by_an_intervention_is_not_counted_twice(self, ledger):
        """verification (Sept), update recorded Oct 1, re-verified Oct 2, then the
        periodic as_found manifest of Oct 3 shows the new hash: the update is accounted
        for, and the Oct 2 verification stands."""
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_intervention(ledger, update(when=utc_now() - timedelta(hours=3)))
        seal(ledger, utc_now() - timedelta(hours=2), tid="REVERIFY", expect="pass")
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B"))
        report, _ = coverage_of(ledger, m=manifest(fw=HASH_B))
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_an_intervention_naming_another_hash_does_not_explain_the_change(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_intervention(ledger, update(when=utc_now() - timedelta(hours=3),
                                           to_hash="c" * 64))
        seal(ledger, utc_now() - timedelta(hours=2), tid="REVERIFY", expect="pass")
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B"))
        report, _ = coverage_of(ledger, m=manifest(fw=HASH_B))
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_new_safety_item_with_no_record_is_a_change(self, ledger):
        record_manifest(ledger, manifest(mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        added = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        newer = manifest(mid="M-B", extra_items=(added,))
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_change_to_an_item_that_implements_nothing_is_not_a_safety_change(
            self, ledger):
        doc = SafetyItem("doc", ItemKind.PARAMETER_SET, "readme", "1", "c" * 64,
                         HashSource.READ_FROM_MACHINE)
        record_manifest(ledger, manifest(mid="M-A", extra_items=(doc,)))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        doc2 = SafetyItem("doc", ItemKind.PARAMETER_SET, "readme", "2", "e" * 64,
                          HashSource.READ_FROM_MACHINE)
        newer = manifest(mid="M-B", extra_items=(doc2,))
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_planned_manifest_is_not_an_observation(self, ledger):
        self._record_and_verify(ledger)
        record_manifest(ledger, manifest(fw=HASH_B, source=ManifestSource.AS_INTENDED,
                                         mid="PLAN"))
        report, _ = coverage_of(ledger)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_plan_between_two_looks_is_not_a_machine_state_to_differ_from(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        record_manifest(ledger, manifest(fw=HASH_B, source=ManifestSource.AS_INTENDED,
                                         mid="PLAN"))
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A2"))
        assert interventions_from_ledger(ledger, KEY) == []

    def test_the_check_pipeline_does_not_verify_a_changed_machine(self, ledger):
        from assurance.check.pipeline import run_enrolled_check

        self._record_and_verify(ledger)
        record_manifest(ledger, manifest(fw=HASH_B, taken=datetime(2026, 10, 20, tzinfo=UTC),
                                         mid="M-B"))
        assert run_enrolled_check(ledger, KEY, None).verdict.value != "verified"


class TestATieAtTheClocksResolutionIsSettledByLedgerOrder:
    T = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)

    def _verification(self, seq: int) -> VerificationRecord:
        return VerificationRecord(
            content_hash=f"{seq:064x}", effective_at=self.T, ledger_seq=seq, product="p",
            product_version="1", verdict="pass", tier="validated",
            checks_verified=CHECKS, checks_not_verified=())

    def _derived(self, seq: int):
        from assurance.machinery.intervention import ImpliedIntervention
        return ImpliedIntervention(
            intervention_id="implied:x:fw", machine_key=KEY, item_id="fw",
            kind=InterventionKind.RECONSTRUCTED, occurred_at=self.T,
            performed_by=TECH, reason="derived", from_hash=HASH_A, to_hash=HASH_B,
            affects_functions=("SF-1",), ledger_seq=seq)

    def test_a_verification_filed_after_the_manifest_in_the_same_second_stands(self):
        report = assess_coverage(manifest(), [self._verification(9)], [self._derived(5)])
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_verification_filed_before_the_manifest_in_the_same_second_does_not(self):
        report = assess_coverage(manifest(), [self._verification(3)], [self._derived(5)])
        assert report.functions[0].coverage is Coverage.STALE

    def test_a_recorded_intervention_at_the_same_instant_still_counts_as_after(self):
        iv = update(when=self.T)
        report = assess_coverage(manifest(), [self._verification(9)], [iv])
        assert report.functions[0].coverage is Coverage.STALE


class TestWhichManifestDifferencesAreChanges:
    """The rule is narrow on purpose; each edge is pinned."""

    def _verified(self, ledger, first: SafetyManifest) -> None:
        record_manifest(ledger, first)
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")

    def _unhashed(self, version: str) -> SafetyItem:
        return SafetyItem("cfg", ItemKind.PARAMETER_SET, "zone config", version, "",
                          HashSource.DECLARED, implements=("SF-1",))

    def test_a_version_moving_on_a_safety_item_with_no_hash_is_a_change(self, ledger):
        self._verified(ledger, manifest(mid="M-A", implements=(),
                                        extra_items=(self._unhashed("1"),)))
        newer = manifest(mid="M-B", implements=(), extra_items=(self._unhashed("2"),))
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].invalidating_item == "cfg"

    def test_an_unhashed_safety_item_whose_version_did_not_move_is_not_a_change(self, ledger):
        self._verified(ledger, manifest(mid="M-A", implements=(),
                                        extra_items=(self._unhashed("1"),)))
        same = manifest(mid="M-B", implements=(), extra_items=(self._unhashed("1"),))
        record_manifest(ledger, same)
        report, _ = coverage_of(ledger, m=same)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_a_safety_item_that_vanished_is_a_change(self, ledger):
        extra = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        self._verified(ledger, manifest(mid="M-A", extra_items=(extra,)))
        newer = manifest(mid="M-B")
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].invalidating_item == "plc"

    def test_a_removal_that_was_recorded_is_explained(self, ledger):
        extra = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        self._verified(ledger, manifest(mid="M-A", extra_items=(extra,)))
        removal = Intervention(
            intervention_id="INT-R", machine_key=KEY, item_id="plc",
            kind=InterventionKind.REMOVAL, occurred_at=utc_now() - timedelta(hours=1),
            performed_by=TECH, reason="module removed", affects_functions=("SF-1",))
        record_intervention(ledger, removal)
        seal(ledger, utc_now() - timedelta(minutes=30), tid="AFTER", expect="pass")
        newer = manifest(mid="M-B")
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_an_install_does_not_explain_a_removal(self, ledger):
        extra = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        self._verified(ledger, manifest(mid="M-A", extra_items=(extra,)))
        install = Intervention(
            intervention_id="INT-I", machine_key=KEY, item_id="plc",
            kind=InterventionKind.INSTALL, occurred_at=utc_now() - timedelta(hours=1),
            performed_by=TECH, reason="module installed", affects_functions=("SF-1",))
        record_intervention(ledger, install)
        seal(ledger, utc_now() - timedelta(minutes=30), tid="AFTER", expect="pass")
        newer = manifest(mid="M-B")
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.STALE

    def test_an_install_explains_an_item_that_appeared(self, ledger):
        self._verified(ledger, manifest(mid="M-A"))
        install = Intervention(
            intervention_id="INT-I", machine_key=KEY, item_id="plc",
            kind=InterventionKind.INSTALL, occurred_at=utc_now() - timedelta(hours=1),
            performed_by=TECH, reason="module installed", affects_functions=("SF-1",))
        record_intervention(ledger, install)
        seal(ledger, utc_now() - timedelta(minutes=30), tid="AFTER", expect="pass")
        added = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        newer = manifest(mid="M-B", extra_items=(added,))
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_an_intervention_dated_before_the_earlier_look_does_not_explain_a_later_change(
            self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A",
                                         taken=datetime(2026, 9, 13, tzinfo=UTC)))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        # the update to B was recorded, but BEFORE the look that still found A
        record_intervention(ledger, update(when=datetime(2026, 9, 1, tzinfo=UTC)))
        seal(ledger, utc_now() - timedelta(minutes=30), tid="AFTER", expect="pass")
        newer = manifest(fw=HASH_B, mid="M-B")
        record_manifest(ledger, newer)
        report, _ = coverage_of(ledger, m=newer)
        assert report.functions[0].coverage is Coverage.STALE
        assert report.functions[0].invalidated_by.startswith("implied:")

    def test_a_record_for_another_item_does_not_explain_the_change(self, ledger):
        doc = SafetyItem("doc", ItemKind.PARAMETER_SET, "readme", "1", "c" * 64,
                         HashSource.READ_FROM_MACHINE)
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A", extra_items=(doc,)))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_intervention(ledger, update(when=utc_now() - timedelta(hours=1), item="doc",
                                           from_hash="c" * 64, to_hash=HASH_B, affects=()))
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B", extra_items=(doc,)))
        assert any(i.intervention_id.startswith("implied:") and i.item_id == "fw"
                   for i in interventions_from_ledger(ledger, KEY))

    def test_an_intervention_dated_after_the_manifest_was_filed_does_not_explain_it(
            self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B"))
        record_intervention(ledger, update(when=utc_now() + timedelta(days=30)))
        seal(ledger, utc_now(), tid="AFTER", expect="pass")
        ivs = interventions_from_ledger(ledger, KEY)
        assert any(i.intervention_id.startswith("implied:") for i in ivs)

    def test_a_record_whose_from_hash_is_not_the_one_before_does_not_explain_it(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_intervention(ledger, update(when=utc_now() - timedelta(hours=1),
                                           from_hash="c" * 64, to_hash=HASH_B))
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B"))
        ivs = interventions_from_ledger(ledger, KEY)
        assert any(i.intervention_id.startswith("implied:") for i in ivs)

    def test_a_digest_written_with_a_prefix_or_in_capitals_is_the_same_hash(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_intervention(ledger, update(when=utc_now() - timedelta(hours=1),
                                           to_hash="SHA256:" + HASH_B.upper()))
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B"))
        assert not [i for i in interventions_from_ledger(ledger, KEY)
                    if i.intervention_id.startswith("implied:")]

    def test_the_partial_look_mark_is_the_one_the_watch_writes(self):
        from assurance.change.service import INCOMPLETE_COLLECTION_MARK
        from assurance.machinery import record

        assert record._PARTIAL_LOOK_MARK == INCOMPLETE_COLLECTION_MARK

    def _partial(self, **kw) -> SafetyManifest:
        from dataclasses import replace

        from assurance.change.service import INCOMPLETE_COLLECTION_MARK

        return replace(manifest(**kw), notes=f"{INCOMPLETE_COLLECTION_MARK}: plc not collected]")

    def test_an_item_a_partial_look_did_not_collect_is_not_read_as_removed(self, ledger):
        extra = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        self._verified(ledger, manifest(mid="M-A", extra_items=(extra,)))
        partial = self._partial(mid="M-P")
        record_manifest(ledger, partial)
        report, _ = coverage_of(ledger, m=partial)
        assert report.functions[0].coverage is Coverage.CURRENT

    def test_the_whole_look_after_a_partial_one_is_compared_with_the_last_whole_look(
            self, ledger):
        extra = SafetyItem("plc", ItemKind.SAFETY_PROGRAM, "plc", "1", "d" * 64,
                           HashSource.READ_FROM_MACHINE, implements=("SF-1",))
        whole = manifest(mid="M-A", extra_items=(extra,))
        self._verified(ledger, whole)
        record_manifest(ledger, self._partial(mid="M-P"))
        record_manifest(ledger, manifest(mid="M-W", extra_items=(extra,)))
        assert interventions_from_ledger(ledger, KEY) == []

    def test_a_partial_look_that_did_collect_a_changed_hash_still_shows_the_change(
            self, ledger):
        self._verified(ledger, manifest(fw=HASH_A, mid="M-A"))
        partial = self._partial(fw=HASH_B, mid="M-P")
        record_manifest(ledger, partial)
        report, _ = coverage_of(ledger, m=partial)
        assert report.functions[0].coverage is Coverage.STALE

    def test_the_first_look_has_nothing_to_differ_from(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-A"))
        assert interventions_from_ledger(ledger, KEY) == []

    def test_only_recorded_changes_are_returned_when_asked(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B"))
        assert interventions_from_ledger(ledger, KEY, include_implied=False) == []
        assert len(interventions_from_ledger(ledger, KEY)) == 1

    def test_a_declaration_does_not_stand_in_for_a_look(self, ledger):
        """as_declared is a claim about the configuration, not an observation: it is never
        itself the later side of a comparison, though it can be the earlier side."""
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-D", source=ManifestSource.AS_DECLARED))
        assert interventions_from_ledger(ledger, KEY) == []
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-C"))
        assert len(interventions_from_ledger(ledger, KEY)) == 1


# =====================================================================
# M4. A change record that cannot be read is never read as "no change"
# =====================================================================

def _intervention_seq(ledger: EvidenceLedger) -> int:
    (entry,) = ledger.entries(kind=INTERVENTION_KIND)
    return entry.seq


class TestAnUnreadableChangeRecordFailsClosed:
    def _recorded(self, ledger):
        verified_machine(ledger)
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC)))
        assert coverage_of(ledger)[0].functions[0].coverage is Coverage.STALE
        return _intervention_seq(ledger)

    def _assert_fails_closed(self, ledger):
        report, _ = coverage_of(ledger)
        fn = report.functions[0]
        assert fn.coverage is not Coverage.CURRENT
        assert fn.coverage is Coverage.STALE
        assert fn.invalidated_by.startswith("unreadable:")
        assert report.verdict == "gaps"
        assert any("unreadable" in c.lower() or "could not be read" in c
                   for c in report.checks_skipped)
        assert fleet_verdict(ledger) == "gaps"

    def test_a_body_edited_in_place_is_not_dropped(self, ledger):
        seq = self._recorded(ledger)
        edit_payload(ledger, seq, lambda p: p["body"]["intervention"].update(reason="cosmetic"))
        assert ledger.verify_chain()[0] is False        # the chain notices too
        self._assert_fails_closed(ledger)

    def test_a_validly_sealed_body_of_the_wrong_shape_is_not_dropped(self, ledger):
        verified_machine(ledger)
        ledger.append(Evidence(kind=INTERVENTION_KIND, body={"intervention": {"oops": 1}},
                               actor=TECH, origin=Origin(system="test")).seal(), subject=KEY)
        self._assert_fails_closed(ledger)

    def test_a_validly_sealed_body_with_no_intervention_is_not_dropped(self, ledger):
        verified_machine(ledger)
        ledger.append(Evidence(kind=INTERVENTION_KIND, body={}, actor=TECH,
                               origin=Origin(system="test")).seal(), subject=KEY)
        self._assert_fails_closed(ledger)

    def test_a_row_whose_payload_is_not_json_is_not_dropped(self, ledger):
        seq = self._recorded(ledger)
        db = sqlite3.connect(ledger.path)
        db.execute("update chain set payload=? where seq=?", ("this is not json", seq))
        db.commit()
        db.close()
        self._assert_fails_closed(ledger)

    def test_a_row_whose_payload_is_json_but_not_an_object_is_not_dropped(self, ledger):
        seq = self._recorded(ledger)
        db = sqlite3.connect(ledger.path)
        db.execute("update chain set payload=? where seq=?", ("[1, 2]", seq))
        db.commit()
        db.close()
        self._assert_fails_closed(ledger)

    def test_a_record_filed_under_one_unit_that_names_another_is_not_dropped(self, ledger):
        verified_machine(ledger)
        other = update(when=datetime(2026, 10, 1, tzinfo=UTC), key="Acme/AR-7#0413")
        ledger.append(Evidence(kind=INTERVENTION_KIND,
                               body={"intervention": other.to_dict(), "findings": []},
                               actor=TECH, origin=Origin(system="test")).seal(), subject=KEY)
        self._assert_fails_closed(ledger)

    def test_it_stays_stale_over_http_too(self, client, store):
        from assurance.api import deps

        account = store.upsert_account(email="cell@example.de", tier="cell")
        headers = {"X-API-Key": store.issue_key(account.id)}
        client.post("/v1/machinery/manifest", headers=headers,
                    json={"manifest": manifest().to_dict()})
        _post_verify(client, headers, datetime(2026, 9, 14, tzinfo=UTC), 300.0, "RUN")
        r = client.post("/v1/machinery/intervention", headers=headers, json={
            "intervention": update(when=datetime(2026, 10, 1, tzinfo=UTC)).to_dict(),
            "actor": "tech"})
        assert r.status_code == 200
        tenant = EvidenceLedger(deps.tenant_ledger_path(account.id))
        edit_payload(tenant, _intervention_seq(tenant),
                     lambda p: p["body"]["intervention"].update(reason="cosmetic"))
        cov = client.post("/v1/machinery/coverage", headers=headers,
                          json={"manifest": manifest().to_dict()}).json()
        assert cov["functions"][0]["coverage"] == "stale"
        assert cov["functions"][0]["invalidated_by"].startswith("unreadable:")

    def test_an_intact_record_is_still_read_and_named(self, ledger):
        self._recorded(ledger)
        (iv,) = interventions_from_ledger(ledger, KEY)
        assert iv.intervention_id == "INT-1"
        assert coverage_of(ledger)[0].functions[0].invalidated_by == "INT-1"

    def test_a_later_verification_after_the_unreadable_record_was_filed_is_current_again(
            self, ledger):
        """The unreadable record is bounded by when the ledger says it was filed: a
        run that began afterwards describes the machine as it was left."""
        seq = self._recorded(ledger)
        edit_payload(ledger, seq, lambda p: p["body"]["intervention"].update(reason="x"))
        seal(ledger, utc_now(), tid="AFTER", expect="pass")
        report, _ = coverage_of(ledger)
        assert report.functions[0].coverage is Coverage.CURRENT
        assert any("unreadable" in c.lower() or "could not be read" in c
                   for c in report.checks_skipped)


# =====================================================================
# the chain: what a payload edit does and does not break
# =====================================================================

class TestWhichDateTheReaderUses:
    def test_the_filing_time_the_reader_uses_is_covered_by_the_chain(self, ledger):
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC))
        db = sqlite3.connect(ledger.path)
        db.execute("update chain set at='2020-01-01T00:00:00Z' where seq=1")
        db.commit()
        db.close()
        assert ledger.verify_chain()[0] is False

    def test_the_unsigned_recorded_at_in_a_payload_is_not_what_coverage_reads(self, ledger):
        """``recorded_at`` is documented as unhashed. A reader that used it would take a
        date from outside the chain; coverage uses the chain's own ``at``."""
        now = utc_now()
        seal(ledger, now - timedelta(hours=1), tid="PASS")
        before, _ = coverage_of(ledger, [])
        edit_payload(ledger, 1, lambda p: p.update(recorded_at="2099-01-01T00:00:00Z"))
        after, recs = coverage_of(ledger, [])
        assert after.functions[0].coverage is before.functions[0].coverage
        assert recs[0].effective_at <= utc_now()


# =====================================================================
# the same answers through the CLI, the fleet row and the passport
# =====================================================================

def _run_cli(argv: list[str], capsys) -> tuple[int, str, str]:
    from assurance.machinery.cli import main

    code = main(argv)
    out = capsys.readouterr()
    return code, out.out, out.err


class TestTheOfflineCommandsAgree:
    def _files(self, tmp_path: Path, ledger: EvidenceLedger):
        mpath = tmp_path / "manifest.json"
        mpath.write_text(json.dumps(manifest().to_dict()))
        return mpath

    def test_record_change_for_a_unit_with_no_sealed_manifest_is_refused(
            self, tmp_path, ledger, capsys):
        ipath = tmp_path / "iv.json"
        ipath.write_text(json.dumps(update(when=datetime(2026, 10, 1, tzinfo=UTC)).to_dict()))
        code, _, err = _run_cli(["record-change", str(ipath), "--ledger", str(ledger.path)],
                                capsys)
        assert code == 2
        assert "no manifest is sealed" in err
        assert ledger.entries(kind=INTERVENTION_KIND) == []

    def test_record_change_names_a_function_the_manifest_does_not_declare(
            self, tmp_path, ledger, capsys):
        record_manifest(ledger, manifest())
        ipath = tmp_path / "iv.json"
        ipath.write_text(json.dumps(
            update(when=datetime(2026, 10, 1, tzinfo=UTC), affects=("SF-9",)).to_dict()))
        code, _, err = _run_cli(["record-change", str(ipath), "--ledger", str(ledger.path)],
                                capsys)
        assert code == 2
        assert "SF-9" in err
        assert ledger.entries(kind=INTERVENTION_KIND) == []

    def test_record_change_writes_the_manifests_spelling(self, tmp_path, ledger, capsys):
        record_manifest(ledger, manifest())
        ipath = tmp_path / "iv.json"
        ipath.write_text(json.dumps(
            update(when=datetime(2026, 10, 1, tzinfo=UTC), affects=("sf-1",)).to_dict()))
        code, _, _ = _run_cli(["record-change", str(ipath), "--ledger", str(ledger.path)],
                              capsys)
        assert code == 0
        (iv,) = interventions_from_ledger(ledger, KEY)
        assert iv.affects_functions == ("SF-1",)

    def test_coverage_json_names_the_unreadable_record_and_exits_1(
            self, tmp_path, ledger, capsys):
        verified_machine(ledger)
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC)))
        edit_payload(ledger, _intervention_seq(ledger),
                     lambda p: p["body"]["intervention"].update(reason="cosmetic"))
        code, out, _ = _run_cli(["coverage", str(self._files(tmp_path, ledger)),
                                 "--ledger", str(ledger.path), "--json"], capsys)
        body = json.loads(out)
        assert code == 1
        assert body["verdict"] == "gaps"
        assert body["functions"][0]["coverage"] == "stale"
        assert body["functions"][0]["invalidated_by"].startswith("unreadable:")
        assert body["unrevalidated_interventions"] == [body["functions"][0]["invalidated_by"]]

    def test_coverage_json_names_the_implied_change(self, tmp_path, ledger, capsys):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B",
                                         taken=datetime(2026, 10, 20, tzinfo=UTC)))
        mpath = tmp_path / "manifest.json"
        mpath.write_text(json.dumps(manifest(fw=HASH_B).to_dict()))
        code, out, _ = _run_cli(["coverage", str(mpath), "--ledger", str(ledger.path),
                                 "--json"], capsys)
        fn = json.loads(out)["functions"][0]
        assert code == 1
        assert fn["coverage"] == "stale"
        assert fn["invalidated_by"].startswith("implied:")
        assert fn["invalidating_item"] == "fw"


class TestDerivedChangesAreNotCountedAsRecords:
    def test_the_fleet_row_counts_recorded_changes_and_unrecorded_ones_apart(self, ledger):
        record_manifest(ledger, manifest(fw=HASH_A, mid="M-A"))
        seal(ledger, datetime(2026, 9, 14, tzinfo=UTC), expect="pass")
        record_manifest(ledger, manifest(fw=HASH_B, mid="M-B",
                                         taken=datetime(2026, 10, 20, tzinfo=UTC)))
        row = Fleet.from_ledger(ledger).to_dict()["machines"][0]
        assert (row["interventions"], row["unrecorded_changes"]) == (0, 1)
        assert row["verdict"] == "gaps"

    def test_a_passport_over_an_unreadable_record_is_not_verified_and_is_otherwise_coherent(
            self, tmp_path, ledger):
        from assurance.machinery.record import build_passport, verify_passport

        verified_machine(ledger)
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC)))
        edit_payload(ledger, _intervention_seq(ledger),
                     lambda p: p["body"]["intervention"].update(reason="cosmetic"))
        built = build_passport(ledger, manifest(), actor=TECH, seal=False)
        assert built.verdict == "gaps"
        assert built.evidence.validation_state.value != "verified"
        out = built.write(tmp_path / "passport.json")
        ok, problems = verify_passport(out)
        # the only thing wrong with it is the thing that IS wrong: the chain did not verify
        assert not ok
        assert [p for p in problems if not p.startswith("NOT CHECKED")] == [
            "the passport itself records that the ledger chain did not verify when it "
            "was produced."]
        fn = built.coverage.functions[0]
        assert fn.coverage is Coverage.STALE and fn.invalidated_by.startswith("unreadable:")

    def test_cutting_the_tail_off_the_chain_passes_verify_chain_but_not_a_published_head(
            self, ledger):
        """The documented limit of an unsigned head (docs/claims-registry.md): the chain
        alone cannot show that records at its end are missing. A head attestation kept
        outside the ledger can."""
        verified_machine(ledger)
        record_intervention(ledger, update(when=datetime(2026, 10, 1, tzinfo=UTC)))
        published = ledger.head_attestation()
        db = sqlite3.connect(ledger.path)
        db.execute("delete from chain where seq=?", (published["head_seq"],))
        db.commit()
        db.close()
        assert ledger.verify_chain() == (True, [])
        assert ledger.head_attestation()["head_seq"] < published["head_seq"]
        assert ledger.head_attestation()["head_link_hash"] != published["head_link_hash"]
