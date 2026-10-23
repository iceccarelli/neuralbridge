"""Red-team hardening of the change lifecycle and its ledger.

Each class here is the regression for one finding, written to fail against the
code as it was before the fix.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from assurance.change import (
    CaseStatus,
    CaseStore,
    advance,
    decide,
    reconstruct_case,
    resolve_decision,
    resume,
    reverify,
    waive_reverification,
)
from assurance.change.service import _open_or_update
from assurance.change.store import ChainBrokenError
from assurance.evidence import chain_cache
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machinery.manifest import MachineIdentity
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord

from .support_recorder_attestation import simulate_verified_recorder_attestation
from .test_assurance_change import (
    BOT,
    ENG,
    LATER,
    MACHINE,
    REVIEWER,
    drive,
    item,
    manifest,
)


@pytest.fixture(autouse=True)
def _recorder_attestation_assumed(monkeypatch):
    """These tests are about what happens to a validated verification afterwards,
    not about how it is earned. The engine never lifts a declared provenance, so
    stand in for a verified recorder attestation (see the helper's docstring)."""
    simulate_verified_recorder_attestation(monkeypatch)



@pytest.fixture(autouse=True)
def fresh_cache(monkeypatch):
    monkeypatch.delenv("ASSURANCE_CHAIN_RECHECK_SECONDS", raising=False)
    chain_cache.reset()
    yield
    chain_cache.reset()


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "hardening.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def edit_old_record_in_place(ledger: EvidenceLedger) -> None:
    """Change one byte of the first (non-head) record's payload, as someone with
    write access to the database file could."""
    db = sqlite3.connect(ledger.path)
    try:
        cur = db.execute("UPDATE chain SET payload = replace(payload, 'Grimaldi', 'Grimaldx') "
                         "WHERE seq = 1")
        assert cur.rowcount == 1
        db.commit()
    finally:
        db.close()


# =====================================================================
# 6. A closure is never sealed on the strength of the cached chain check
# =====================================================================

class TestHumanDecisionsVerifyTheWholeChain:
    def _warm(self, store):
        # The cached check has passed within the recheck window.
        store.require_intact()
        assert chain_cache.lookup(chain_cache.identity(store.ledger.path)) is not None

    def test_the_cache_really_does_miss_the_edit(self, ledger, store):
        """The premise of every test below: the cached check alone does not see it."""
        drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        self._warm(store)
        edit_old_record_in_place(ledger)
        store.require_intact()                         # passes: that is the window
        assert not ledger.verify_chain()[0]

    def test_a_close_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)
        assert store.get(case.case_id).status is CaseStatus.READY_TO_CLOSE

    @pytest.mark.parametrize("disposition", ["rejected", "deferred"])
    def test_a_reject_or_defer_is_refused_after_an_in_place_edit(
            self, ledger, store, disposition):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            decide(store, case.case_id, disposition=disposition, reason="r", actor=REVIEWER)

    def test_a_waiver_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            waive_reverification(store, case.case_id, entry=case.required_reverifications[0],
                                 reason="accepted", actor=REVIEWER)

    def test_resolving_a_decision_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        asked = store.update(replace(case, human_decisions_required=("Is this in scope?",)),
                             actor=BOT, detail="a question")
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            resolve_decision(store, asked.case_id, decision="Is this in scope?",
                             resolution="yes", actor=REVIEWER)

    def test_a_resume_is_refused_after_an_in_place_edit(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.DEFERRED)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            resume(store, case.case_id, reason="back on it", actor=REVIEWER)

    def test_sealing_a_decision_entry_walks_the_whole_chain_at_the_store(self, ledger, store):
        """Below the service: whatever called the store, a decision entry is not
        appended on the cached check."""
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._warm(store)
        edit_old_record_in_place(ledger)
        with pytest.raises(ChainBrokenError):
            store.decide(replace(case, status=CaseStatus.REJECTED, decision="rejected",
                                 decision_reason="r", decision_by="v"),
                         actor=REVIEWER, detail="rejected: r")

    def test_a_clean_ledger_still_closes(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.READY_TO_CLOSE)
        self._warm(store)
        closed = decide(store, case.case_id, disposition="closed", reason="r", actor=REVIEWER)
        assert closed.status is CaseStatus.CLOSED

    def test_a_machine_driven_step_keeps_the_cheap_check(self, ledger, store, monkeypatch):
        """Only human decisions pay for a full walk: advancing a case is not one."""
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        self._warm(store)
        walks = []
        real = ledger.verify_full
        monkeypatch.setattr(ledger, "verify_full", lambda: walks.append(1) or real())
        advance(store, case.case_id, actor=REVIEWER)
        assert walks == []


# =====================================================================
# 2 + 3. What may clear a re-verification entry
# =====================================================================

def record(content_hash, *, checks, seq=10**6, when=LATER, tier="validated"):
    """A verification as the coverage check sees it, without sealing a bundle."""
    return VerificationRecord(
        content_hash=content_hash * 64, effective_at=when, ledger_seq=seq,
        product="AR-7", product_version="2.4.1", verdict="pass", tier=tier,
        checks_verified=tuple(checks))


def seal_bundle(ledger, *, provenance, when=LATER):
    """``seal_a_real_verification`` with a choice of where the trace came from."""
    env = SafetyEnvelope(
        envelope_id="ENV-1", product="AR-7", product_version="2.4.1",
        workspace=Workspace((-1200.0, -1200.0, 0.0), (1200.0, 1200.0, 2100.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 400.0},
        stop=StopPerformance(0.10, 0.25, 120.0, 500.0,
                             FigureBasis("measured", "STOP-11", "2026-01-18")),
        uncertainty=SensingUncertainty(100.0, 50.0, FigureBasis("measured", "CAL-003")),
        intrusion_distance_mm=850.0)
    run = Trace(trace_id=f"RUN-{provenance.value}", provenance=provenance,
                source_system="AR-7 fw", started_at=when, sample_rate_hz=50.0,
                samples=tuple(Sample(t=i / 50, tcp=(0.0, 0.0, 1000.0), tcp_speed=400.0,
                                     mode=OperatingMode.SSM, separation=2200.0)
                              for i in range(10)))
    return build_bundle(env, run, actor=ENG, ledger=ledger, subject=MACHINE.key)


# =====================================================================
# 4. The drift route's baseline is the ledger's; a fresh look cannot shrink work
# =====================================================================

@pytest.fixture
def cell_api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from assurance.api import deps
    from assurance.api.service import create_app

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "l.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "a.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    with TestClient(create_app()) as c:
        accounts = deps.get_accounts()
        account = accounts.upsert_account(email="cell-baseline@example.de", tier="cell")
        yield c, {"X-API-Key": accounts.issue_key(account.id)}
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


def seal(client, headers, m):
    r = client.post("/v1/machinery/manifest", json={"manifest": m.to_dict()}, headers=headers)
    assert r.status_code == 200, r.text


def assess(client, headers, baseline, observed):
    r = client.post("/v1/change/assess/drift", headers=headers, json={
        "baseline": baseline.to_dict(), "observed": observed.to_dict()})
    assert r.status_code == 200, r.text
    return r.json()


class TestAssessDriftUsesTheLedgersBaseline:
    A = manifest(manifest_id="BASE")
    B = manifest(item(content_hash="d" * 64), manifest_id="NOW")

    def test_a_sealed_baseline_wins_over_the_one_in_the_body(self, cell_api):
        client, headers = cell_api
        seal(client, headers, self.A)
        # A caller who says "the baseline is what I observed" would suppress the case.
        body = assess(client, headers, baseline=self.B, observed=self.B)
        assert body["opened"] is True
        assert body["case"]["before_hash"] == self.A.configuration_hash()
        assert body["baseline_source"] == "ledger"
        assert body["baseline_configuration"] == self.A.configuration_hash()
        assert body["request_baseline_ignored"] is True

    def test_a_made_up_baseline_does_not_shape_the_changed_items(self, cell_api):
        client, headers = cell_api
        seal(client, headers, self.A)
        invented = manifest(item(content_hash="e" * 64), manifest_id="INVENTED")
        body = assess(client, headers, baseline=invented, observed=self.B)
        assert body["case"]["before_hash"] == self.A.configuration_hash()

    def test_with_nothing_sealed_the_body_baseline_is_used_and_the_response_says_so(
            self, cell_api):
        client, headers = cell_api
        body = assess(client, headers, baseline=self.A, observed=self.B)
        assert body["opened"] is True
        assert body["case"]["before_hash"] == self.A.configuration_hash()
        assert body["baseline_source"] == "request"
        assert body["request_baseline_ignored"] is False

    def test_the_observed_configuration_is_never_its_own_baseline(self, cell_api):
        client, headers = cell_api
        seal(client, headers, self.A)
        seal(client, headers, self.B)            # a watch already sealed what it saw
        body = assess(client, headers, baseline=self.B, observed=self.B)
        assert body["opened"] is True
        assert body["case"]["before_hash"] == self.A.configuration_hash()
        assert body["baseline_source"] == "ledger"

    def test_another_machines_manifest_is_not_this_machines_baseline(self, cell_api):
        client, headers = cell_api
        other = MachineIdentity(manufacturer="Grimaldi", model="AR-7", serial="0999")
        seal(client, headers, manifest(manifest_id="OTHER", machine=other))
        body = assess(client, headers, baseline=self.A, observed=self.B)
        assert body["baseline_source"] == "request"


class TestAFreshLookCannotShrinkTheWorkList:
    def _in_review_with_everything(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.IN_REVIEW)
        return store.update(
            replace(case, required_actions=(*case.required_actions, "Do the thing."),
                    human_decisions_required=("Is this in scope?",)),
            actor=BOT, detail="seeded")

    def test_a_look_that_names_less_work_leaves_the_outstanding_work_alone(
            self, ledger, store):
        case = self._in_review_with_everything(ledger, store)
        assert case.required_reverifications
        shrunk = replace(case, status=CaseStatus.OPEN, required_reverifications=(),
                         required_actions=(), human_decisions_required=())
        result = _open_or_update(store, shrunk, actor=BOT, detail="a later look")
        assert result.required_reverifications == case.required_reverifications
        assert result.required_actions == case.required_actions
        assert result.human_decisions_required == case.human_decisions_required
        assert reconstruct_case(ledger, case.case_id).ok

    def test_work_a_later_look_adds_is_still_added(self, ledger, store):
        case = self._in_review_with_everything(ledger, store)
        wider = replace(case, status=CaseStatus.OPEN,
                        required_reverifications=(*case.required_reverifications, "SF-09"),
                        required_actions=(*case.required_actions, "Also do this."),
                        human_decisions_required=(*case.human_decisions_required, "New?"))
        result = _open_or_update(store, wider, actor=BOT, detail="a later look")
        assert result.required_reverifications == (*case.required_reverifications, "SF-09")
        assert result.required_actions == (*case.required_actions, "Also do this.")
        assert result.human_decisions_required == (*case.human_decisions_required, "New?")

    def test_an_answered_question_is_not_asked_again(self, ledger, store):
        case = self._in_review_with_everything(ledger, store)
        answered = resolve_decision(store, case.case_id, decision="Is this in scope?",
                                    resolution="yes", actor=REVIEWER)
        again = replace(answered, status=CaseStatus.OPEN,
                        human_decisions_required=("Is this in scope?",))
        result = _open_or_update(store, again, actor=BOT, detail="a later look")
        assert result.human_decisions_required == ()

    @pytest.mark.parametrize("field", ["required_reverifications", "required_actions",
                                       "human_decisions_required"])
    def test_replay_flags_an_update_that_quietly_drops_outstanding_work(
            self, ledger, store, field):
        case = self._in_review_with_everything(ledger, store)
        assert getattr(case, field)
        store.update(replace(case, **{field: ()}), actor=BOT, detail="forged shrink")
        replay = reconstruct_case(ledger, case.case_id)
        assert not replay.ok
        assert any("removed" in p for p in replay.violations)

    def test_a_persons_waiver_or_answer_before_any_work_still_replays_clean(
            self, ledger, store):
        case = self._in_review_with_everything(ledger, store)
        waive_reverification(store, case.case_id, entry=case.required_reverifications[0],
                             reason="accepted", actor=REVIEWER)
        resolve_decision(store, case.case_id, decision="Is this in scope?",
                         resolution="yes", actor=REVIEWER)
        assert reconstruct_case(ledger, case.case_id).ok


class TestTheCitedBundleMustCoverEveryCheck:
    """Survived mutation: ``not set(fn.verified_by) <= set(record.checks_verified)``."""

    def test_a_new_bundle_for_one_check_and_an_old_one_for_the_other_clears_nothing(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        # No intervention is on record. SF-01 declares ssm_separation AND
        # stop_characterisation; coverage reads it current because the older bundle
        # ran one and the newer ran the other. The newer one alone is not evidence
        # that SF-01 was re-verified after the change.
        before_the_change = record("1", checks=("stop_characterisation", "speed_limit"),
                                   seq=2, when=datetime(2026, 2, 9, tzinfo=UTC))
        after = record("2", checks=("ssm_separation",))
        c = reverify(store, case.case_id, observed, [before_the_change, after], [],
                     verification_content_hash=after.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert c.required_reverifications == ("SF-01", "SF-02")
        assert c.evidence_current["SF-01"] == "no_new_evidence"
        assert c.evidence_current["SF-02"] == "no_new_evidence"

    def test_a_bundle_that_covers_all_of_a_functions_checks_clears_that_function(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        before_the_change = record("1", checks=("stop_characterisation", "speed_limit"),
                                   seq=2, when=datetime(2026, 2, 9, tzinfo=UTC))
        full = record("3", checks=("ssm_separation", "stop_characterisation"))
        c = reverify(store, case.case_id, observed, [before_the_change, full], [],
                     verification_content_hash=full.content_hash, actor=REVIEWER)
        assert c.required_reverifications == ("SF-02",)       # SF-02's speed_limit is old
        assert c.evidence_current["SF-01"] == "current"


class TestWeakEvidenceDoesNotClear:
    def test_a_simulation_bundle_leaves_every_entry_awaiting_and_says_why(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_bundle(ledger, provenance=Provenance.SIMULATION)
        c = reverify(store, case.case_id, observed,
                     VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                     interventions_from_ledger(ledger, MACHINE.key),
                     verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert c.required_reverifications == case.required_reverifications
        for entry in case.required_reverifications:
            assert c.evidence_current[entry] == "below_validated:community"
        assert any("community" in s and "validated" in s for s in c.checks_skipped)
        assert "below 'validated'" in c.history[-1]["detail"]

    @pytest.mark.parametrize("tier", ["community", "profile", "", "nonsense"])
    def test_no_tier_below_validated_clears(self, ledger, store, tier):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        weak = record("4", checks=("ssm_separation", "stop_characterisation", "speed_limit"),
                      tier=tier)
        c = reverify(store, case.case_id, observed, [weak], [],
                     verification_content_hash=weak.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.AWAITING_REVERIFICATION
        assert c.required_reverifications == ("SF-01", "SF-02")

    @pytest.mark.parametrize("tier", ["validated", "certified"])
    def test_validated_and_above_still_clear(self, ledger, store, tier):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        strong = record("5", checks=("ssm_separation", "stop_characterisation", "speed_limit"),
                        tier=tier)
        c = reverify(store, case.case_id, observed, [strong], [],
                     verification_content_hash=strong.content_hash, actor=REVIEWER)
        assert c.status is CaseStatus.READY_TO_CLOSE
        assert c.required_reverifications == ()

    def test_a_person_can_still_waive_what_weak_evidence_left_outstanding(
            self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        weak = record("4", checks=("ssm_separation", "stop_characterisation", "speed_limit"),
                      tier="community")
        c = reverify(store, case.case_id, observed, [weak], [],
                     verification_content_hash=weak.content_hash, actor=REVIEWER)
        for entry in c.required_reverifications:
            c = waive_reverification(store, c.case_id, entry=entry,
                                     reason="simulation accepted for now", actor=REVIEWER)
        assert c.evidence_current["SF-01"] == "waived"
