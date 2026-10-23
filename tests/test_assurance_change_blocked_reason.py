"""A re-verification that cannot clear a case says so, on every interface.

Declared trace provenance is capped at ``community`` (``assurance.machine.
provenance_trust``), so no verification this package produces reaches
``validated`` and a required re-verification closes only through a person's
waiver. ``reverify`` used to answer "ok" and leave the case where it was with
``below_validated:community`` buried in ``evidence_current``. Each class here is
the regression for one place that has to say why.

Deliberately does NOT apply the recorder-attestation test double, except where a
test says so: these tests are about the cap itself.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime

import pytest

from assurance.change import (
    CaseStatus,
    CaseStore,
    advance,
    reverify,
    waive_reverification,
)
from assurance.change.service import blocked_reason
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord

from . import interfaces_fixtures as fx
from .support_recorder_attestation import simulate_verified_recorder_attestation
from .test_assurance_change import (
    LATER,
    MACHINE,
    REVIEWER,
    _inputs,
    drive,
    seal_a_real_verification,
)

live_api = fx.live_api


@pytest.fixture
def ledger(tmp_path):
    return EvidenceLedger(tmp_path / "blocked.db")


@pytest.fixture
def store(ledger):
    return CaseStore(ledger)


def _reverify_with_a_real_bundle(ledger, store):
    """A case at awaiting_reverification, re-verified by a bundle the real engine sealed."""
    case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
    bundle = seal_a_real_verification(ledger, when=LATER)
    done = reverify(store, case.case_id, observed,
                    VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                    interventions_from_ledger(ledger, MACHINE.key),
                    verification_content_hash=bundle.content_hash, actor=REVIEWER)
    return case, observed, bundle, done


# =====================================================================
# the service
# =====================================================================

class TestBlockedReasonFromTheService:
    def test_a_real_bundle_leaves_the_case_waiting_and_the_reason_names_the_floor(
            self, ledger, store):
        _, _, bundle, done = _reverify_with_a_real_bundle(ledger, store)
        assert done.status is CaseStatus.AWAITING_REVERIFICATION
        assert done.evidence_current["SF-01"] == "below_validated:community"

        reason = blocked_reason(done)
        assert reason is not None
        assert reason["code"] == "below_validated_tier"
        assert reason["tier_floor"] == "validated"
        assert reason["entries"] == {"SF-01": "below_validated:community",
                                     "SF-02": "below_validated:community"}
        msg = reason["message"]
        assert "community" in msg and "validated" in msg
        assert "attestation" in msg                  # what would lift the cap
        assert "decider" in msg and "waive" in msg   # who can still close it

    def test_nothing_outstanding_is_not_blocked(self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.OPEN)
        assert case.required_reverifications
        cleared = dataclasses.replace(case, required_reverifications=())
        assert blocked_reason(cleared) is None

    def test_evidence_that_is_not_current_is_a_different_code_not_a_tier_complaint(
            self, ledger, store):
        case, _ = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        stale = dataclasses.replace(
            case, evidence_current={"SF-01": "stale", "SF-02": "never_verified"})
        reason = blocked_reason(stale)
        assert reason["code"] == "evidence_not_current"
        assert reason["entries"] == {"SF-01": "stale", "SF-02": "never_verified"}
        assert "validated" not in reason["code"]

    def test_a_waiver_still_closes_what_the_reason_describes(self, ledger, store):
        _, _, _, done = _reverify_with_a_real_bundle(ledger, store)
        for entry in done.required_reverifications:
            done = waive_reverification(store, done.case_id, entry=entry,
                                        reason="accepted by the decider", actor=REVIEWER)
        assert done.required_reverifications == ()
        assert blocked_reason(done) is None
        assert advance(store, done.case_id, actor=REVIEWER).status is CaseStatus.READY_TO_CLOSE

    def test_a_cleared_case_has_no_blocked_reason(self, ledger, store, monkeypatch):
        simulate_verified_recorder_attestation(monkeypatch)
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_a_real_verification(ledger, when=LATER)
        done = reverify(store, case.case_id, observed,
                        VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                        interventions_from_ledger(ledger, MACHINE.key),
                        verification_content_hash=bundle.content_hash, actor=REVIEWER)
        assert done.status is CaseStatus.READY_TO_CLOSE
        assert blocked_reason(done) is None


class TestTheMessagesTellTheTruth:
    def test_checks_skipped_says_no_verification_can_reach_validated_yet(self, ledger, store):
        _, _, _, done = _reverify_with_a_real_bundle(ledger, store)
        text = " ".join(done.checks_skipped)
        assert "Re-verify on the machine" not in text    # nothing a person re-runs can clear it
        assert "attestation" in text
        assert "waive" in text
        assert "community" in text and "validated" in text

    def test_the_service_docstring_does_not_blame_simulations_and_datasheets(self):
        from assurance.change import service

        doc = service.reverify.__doc__ or ""
        assert "a simulation or" not in doc and "datasheet" not in doc
        assert "attestation" in doc

    def test_the_coverage_caveat_does_not_say_a_simulated_trace(self):
        from assurance.machinery.staleness import assess_coverage

        from .test_assurance_machinery import manifest, verification

        weak = dataclasses.replace(verification(), tier="community")
        caveats = " ".join(assess_coverage(manifest(), [weak], []).checks_skipped)
        assert "'community'" in caveats
        assert "simulated trace" not in caveats and "datasheet figure" not in caveats
        assert "attestation" in caveats


# =====================================================================
# the CLI
# =====================================================================

class TestCliSaysWhy:
    def test_reverify_prints_the_reason_and_still_exits_zero(self, tmp_path, capsys):
        from assurance.change.cli import main

        path = tmp_path / "cli.db"
        led = EvidenceLedger(path)
        case, observed = drive(led, CaseStore(led), CaseStatus.AWAITING_REVERIFICATION)
        bundle = seal_a_real_verification(led, when=LATER)
        manifest_path = tmp_path / "m.json"
        manifest_path.write_text(json.dumps(observed.to_dict()))
        capsys.readouterr()
        rc = main(["reverify", "--ledger", str(path), case.case_id,
                   "--manifest", str(manifest_path),
                   "--verification-hash", bundle.content_hash, "--actor", "v.grimaldi"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "awaiting_reverification" in out
        assert "blocked: below_validated_tier" in out
        assert "community" in out and "waive" in out and "attestation" in out


# =====================================================================
# the HTTP API and the MCP tool
# =====================================================================

def _world(live_api, email):
    account_id, headers = live_api.account(email)
    led = live_api.tenant_ledger(account_id)
    store = CaseStore(led)
    case, observed = drive(led, store, CaseStatus.AWAITING_REVERIFICATION)
    bundle = seal_a_real_verification(led, when=LATER)
    return headers, case, observed, bundle


class TestApiAndMcpSayWhy:
    def test_the_route_answers_200_with_a_blocked_reason(self, live_api):
        headers, case, observed, bundle = _world(live_api, "blocked-api@example.de")
        with live_api.client() as http:
            r = http.post(f"/v1/change/cases/{case.case_id}/reverification", headers=headers,
                          json={"manifest": observed.to_dict(), "actor": "v.grimaldi",
                                "verification_content_hash": bundle.content_hash})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["status"] == "awaiting_reverification"
        assert body["blocked_reason"]["code"] == "below_validated_tier"
        assert body["blocked_reason"]["tier_floor"] == "validated"
        assert "attestation" in body["blocked_reason"]["message"]
        assert "waive" in body["blocked_reason"]["message"]

    @pytest.mark.asyncio
    async def test_the_mcp_tool_relays_it(self, live_api, monkeypatch):
        pytest.importorskip("mcp", reason="needs the optional 'assurance-mcp' extra")
        from assurance.mcp import server

        headers, case, observed, bundle = _world(live_api, "blocked-mcp@example.de")
        monkeypatch.setenv("ASSURANCE_API_URL", live_api.url)
        monkeypatch.setenv("ASSURANCE_API_KEY", headers["X-API-Key"])
        with live_api.client():
            result = await server.change_reverify(
                case.case_id, manifest=observed.to_dict(),
                verification_content_hash=bundle.content_hash, actor="v.grimaldi")
        assert result["status"] == 200
        assert result["body"]["blocked_reason"]["code"] == "below_validated_tier"
        assert "blocked_reason" in (server.change_reverify.__doc__ or "")

    def test_a_cleared_case_carries_no_blocked_reason(self, live_api, monkeypatch):
        simulate_verified_recorder_attestation(monkeypatch)
        headers, case, observed, bundle = _world(live_api, "cleared-api@example.de")
        with live_api.client() as http:
            r = http.post(f"/v1/change/cases/{case.case_id}/reverification", headers=headers,
                          json={"manifest": observed.to_dict(), "actor": "v.grimaldi",
                                "verification_content_hash": bundle.content_hash})
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "ready_to_close"
        assert "blocked_reason" not in r.json()


# =====================================================================
# F7: a legacy "validated" already in a ledger does not clear anything
# =====================================================================

def _legacy_validated(ledger, *, when, engine="4", drop_basis=True, basis=None):
    """What an engine-4 ledger holds: a validated tier, no provenance basis, resealed."""
    env, run = _inputs(when)
    sealed = build_bundle(env, run, actor=REVIEWER, ledger=None, subject=MACHINE.key).evidence
    body = {**sealed.body, "tier": "validated", "engine_version": engine}
    if drop_basis:
        body.pop("provenance_basis", None)
        body.pop("provenance_assessment", None)
    if basis is not None:
        body["provenance_basis"] = basis
    forged = dataclasses.replace(sealed, body=body, content_hash="").seal()
    assert forged.verify()
    ledger.append(forged, subject=MACHINE.key)
    return forged


class TestALegacyValidatedBundleIsReadAtItsRealTier:
    def test_the_record_reads_community_not_the_stored_word(self, ledger):
        _legacy_validated(ledger, when=LATER)
        (rec,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert rec.tier == "community"

    def test_it_does_not_clear_a_case(self, ledger, store):
        case, observed = drive(ledger, store, CaseStatus.AWAITING_REVERIFICATION)
        legacy = _legacy_validated(ledger, when=LATER)
        done = reverify(store, case.case_id, observed,
                        VerificationRecord.from_ledger(ledger, subject=MACHINE.key),
                        interventions_from_ledger(ledger, MACHINE.key),
                        verification_content_hash=legacy.content_hash, actor=REVIEWER)
        assert done.status is CaseStatus.AWAITING_REVERIFICATION
        assert done.evidence_current["SF-01"] == "below_validated:community"
        assert blocked_reason(done)["code"] == "below_validated_tier"

    def test_it_does_not_count_as_validated_coverage(self, ledger):
        from assurance.machinery.staleness import assess_coverage

        from .test_assurance_machinery import manifest

        _legacy_validated(ledger, when=datetime(2026, 2, 9, tzinfo=UTC))
        report = assess_coverage(
            manifest(), VerificationRecord.from_ledger(ledger, subject=MACHINE.key), [])
        assert report.evidence_tier_floor == "community"
        assert any("'community'" in c for c in report.checks_skipped)

    @pytest.mark.parametrize("engine", ["4", "3", "", "garbage", None])
    def test_a_recorder_attested_basis_does_not_rescue_an_old_engine(
            self, ledger, monkeypatch, engine):
        simulate_verified_recorder_attestation(monkeypatch)
        _legacy_validated(ledger, when=LATER, engine=engine, drop_basis=False,
                          basis="recorder_attested")
        (rec,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert rec.tier == "community"

    def test_a_declared_basis_does_not_rescue_a_current_engine(self, ledger, monkeypatch):
        simulate_verified_recorder_attestation(monkeypatch)
        _legacy_validated(ledger, when=LATER, engine="5", drop_basis=False,
                          basis="declared_by_filer")
        (rec,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert rec.tier == "community"

    def test_engine_5_with_a_lifting_basis_keeps_validated(self, ledger, monkeypatch):
        simulate_verified_recorder_attestation(monkeypatch)
        seal_a_real_verification(ledger, when=LATER)     # a real engine-5 attested bundle
        (rec,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert rec.tier == "validated"

    def test_without_a_lifting_basis_even_a_current_validated_body_is_capped(self, ledger):
        _legacy_validated(ledger, when=LATER, engine="5", drop_basis=False,
                          basis="recorder_attested")     # basis not in LIFTING_BASES now
        (rec,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert rec.tier == "community"

    def test_a_profile_tier_is_never_raised(self, ledger):
        env, run = _inputs(LATER)
        sealed = build_bundle(env, run, actor=REVIEWER, ledger=None, subject=MACHINE.key).evidence
        forged = dataclasses.replace(
            sealed, body={**sealed.body, "tier": "profile"}, content_hash="").seal()
        ledger.append(forged, subject=MACHINE.key)
        (rec,) = VerificationRecord.from_ledger(ledger, subject=MACHINE.key)
        assert rec.tier == "profile"


class TestValidatedOrBetterAgreesWithTheCap:
    @pytest.mark.parametrize("tier,expected", [
        ("validated", True), ("certified", True),
        ("community", False), ("profile", False), ("", False), ("nonsense", False)])
    def test_the_two_ladders_agree(self, tier, expected):
        from assurance.change.service import _validated_or_better
        from assurance.machinery.staleness import tier_reaches_validated

        assert _validated_or_better(tier) is expected
        assert tier_reaches_validated(tier) is expected
