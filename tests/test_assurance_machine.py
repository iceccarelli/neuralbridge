"""Tests for machine safety verification.

The tests that matter here are not the ones that show a pass. They are the ones
that show the engine refuses to produce a pass it has not earned: a simulated
trace that cannot claim physical behaviour, a datasheet stopping distance that
caps the tier, a contact check with no limits table that reports unchecked
rather than verified, and a bundle whose verdict was edited after sealing.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor, ValidationState
from assurance.core.tiers import AssuranceTier
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle, verify_bundle
from assurance.machine.envelope import (
    EnvelopeError,
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsError, LimitsTable
from assurance.machine.ssm import separation_required
from assurance.machine.trace import (
    OperatingMode,
    Provenance,
    Sample,
    Trace,
    TraceError,
)
from assurance.machine.verify import CheckOutcome, Verdict, verify

MEASURED = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
DATASHEET = FigureBasis(kind="datasheet", reference="scanner rev D")


def envelope(**over):
    kw = {
        "envelope_id": "ENV-1",
        "product": "Cell",
        "product_version": "1.0.0",
        "workspace": Workspace(minimum=(-1000.0, -1000.0, 0.0),
                               maximum=(1000.0, 1000.0, 2000.0)),
        "max_tcp_speed_mm_s": {OperatingMode.SSM: 500.0,
                               OperatingMode.AUTOMATIC: 2000.0,
                               OperatingMode.STOPPED: 0.0, OperatingMode.PFL: 250.0},
        "stop": StopPerformance(reaction_time_s=0.1, stop_time_s=0.25,
                                stop_distance_mm=120.0, measured_at_speed_mm_s=500.0,
                                basis=MEASURED),
        "uncertainty": SensingUncertainty(human_position_mm=100.0,
                                          robot_position_mm=50.0, basis=MEASURED),
        "intrusion_distance_mm": 850.0,
    }
    kw.update(over)
    return SafetyEnvelope(**kw)


def trace(samples, **over):
    kw = {
        "trace_id": "RUN-1",
        "provenance": Provenance.FIELD,
        "source_system": "controller fw 1.0",
        "started_at": datetime(2026, 9, 12, 4, 31, tzinfo=UTC),
        "sample_rate_hz": 50.0,
    }
    kw.update(over)
    return Trace(samples=tuple(samples), **kw)


def sample(i, **over):
    kw = {"t": i / 50.0, "tcp": (0.0, 0.0, 1000.0), "tcp_speed": 500.0,
          "mode": OperatingMode.SSM, "separation": 2000.0}
    kw.update(over)
    return Sample(**kw)


ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")


# -- the arithmetic -------------------------------------------------------

class TestSeparation:
    def test_the_formula_is_the_sum_of_its_six_terms(self):
        b = separation_required(envelope(), robot_speed_mm_s=500.0)
        # Sh = 1600 * (0.1 + 0.25) = 560; Sr = 500 * 0.1 = 50; Ss = 120 measured
        assert b.human_travel_mm == pytest.approx(560.0)
        assert b.robot_reaction_travel_mm == pytest.approx(50.0)
        assert b.robot_stopping_travel_mm == pytest.approx(120.0)
        assert b.total_mm == pytest.approx(560 + 50 + 120 + 850 + 100 + 50)

    def test_the_human_keeps_moving_during_the_reaction_time(self):
        """Sh runs over Tr + Ts. Omitting Tr is the classic metre-short error."""
        b = separation_required(envelope(), robot_speed_mm_s=0.0)
        assert b.human_travel_mm == pytest.approx(1600.0 * 0.35)
        assert b.human_travel_mm > 1600.0 * 0.25

    def test_a_sensed_closing_speed_displaces_the_declared_one(self):
        b = separation_required(envelope(), robot_speed_mm_s=500.0,
                                human_speed_mm_s=800.0)
        assert b.human_speed_source == "sensed"
        assert b.human_travel_mm == pytest.approx(800.0 * 0.35)

    def test_the_declared_speed_is_labelled_as_declared(self):
        b = separation_required(envelope(), robot_speed_mm_s=500.0)
        assert b.human_speed_source == "declared"

    def test_stopping_distance_below_the_measured_point_is_used_unchanged(self):
        b = separation_required(envelope(), robot_speed_mm_s=200.0)
        assert b.stopping_basis == "measured"
        assert b.robot_stopping_travel_mm == pytest.approx(120.0)
        assert not b.rests_on_extrapolation

    def test_above_the_measured_point_it_is_a_model_and_says_so(self):
        b = separation_required(envelope(), robot_speed_mm_s=1000.0)
        assert b.stopping_basis == "extrapolated_quadratic"
        assert b.robot_stopping_travel_mm == pytest.approx(120.0 * 4)
        assert b.rests_on_extrapolation

    def test_every_term_survives_into_the_explanation(self):
        text = separation_required(envelope(), robot_speed_mm_s=500.0).explain()
        for term in ("Sh", "Sr", "Ss", "C", "Zd", "Zr"):
            assert f"({term}" in text or f"({term}," in text


# -- provenance and tiers -------------------------------------------------

class TestProvenance:
    def test_a_simulated_trace_can_never_claim_physical_behaviour(self):
        r = verify(envelope(), trace([sample(i) for i in range(5)],
                                     provenance=Provenance.SIMULATION))
        assert r.tier is AssuranceTier.COMMUNITY
        assert not r.may_claim_physical_behaviour

    def test_and_the_bundle_says_so_in_words(self):
        r = verify(envelope(), trace([sample(i) for i in range(5)],
                                     provenance=Provenance.SIMULATION))
        assert any("simulated" in c for c in r.checks_skipped)

    def test_a_field_trace_against_measured_figures_reaches_validated(self):
        r = verify(envelope(), trace([sample(i) for i in range(5)]))
        assert r.tier is AssuranceTier.VALIDATED
        assert r.may_claim_physical_behaviour

    def test_a_datasheet_stopping_distance_caps_the_tier_at_profile(self):
        """The verdict rests on a number nobody measured on this machine."""
        env = envelope(stop=StopPerformance(
            reaction_time_s=0.1, stop_time_s=0.25, stop_distance_mm=120.0,
            measured_at_speed_mm_s=500.0, basis=DATASHEET))
        r = verify(env, trace([sample(i) for i in range(5)]))
        assert r.tier is AssuranceTier.PROFILE
        assert not r.may_claim_physical_behaviour

    def test_a_figure_basis_with_no_reference_is_refused(self):
        with pytest.raises(EnvelopeError, match="reference"):
            FigureBasis(kind="measured", reference="")

    def test_an_invented_basis_kind_is_refused(self):
        with pytest.raises(EnvelopeError, match="not one of"):
            FigureBasis(kind="probably_fine", reference="x")


# -- the checks -----------------------------------------------------------

class TestChecks:
    def test_a_clean_run_passes_every_applicable_check(self):
        r = verify(envelope(), trace([sample(i) for i in range(10)]))
        assert r.verdict is Verdict.PASS
        assert not r.violations

    def test_a_separation_shortfall_is_caught_with_its_arithmetic(self):
        r = verify(envelope(), trace([sample(i, separation=900.0) for i in range(4)]))
        assert r.verdict is Verdict.FAIL
        v = r.check("ssm_separation").violations[0]
        assert v.measured == 900.0
        assert v.bound == pytest.approx(1730.0)
        assert v.exceedance == pytest.approx(830.0)
        assert v.breakdown["C_intrusion_mm"] == 850.0

    def test_a_speed_over_the_mode_limit_is_caught(self):
        r = verify(envelope(), trace([sample(i, tcp_speed=900.0, separation=4000.0)
                                      for i in range(3)]))
        assert r.check("speed_limit").outcome is CheckOutcome.VIOLATED
        assert r.check("speed_limit").violations[0].direction == "at_most"

    def test_leaving_the_workspace_is_caught_with_the_excursion(self):
        r = verify(envelope(), trace([sample(i, tcp=(1400.0, 0.0, 1000.0))
                                      for i in range(3)]))
        v = r.check("workspace_containment").violations[0]
        assert v.measured == pytest.approx(400.0)

    def test_a_person_detected_during_automatic_operation_is_a_finding(self):
        r = verify(envelope(), trace([
            sample(i, mode=OperatingMode.AUTOMATIC, tcp_speed=1500.0, separation=800.0)
            for i in range(3)]))
        assert r.check("mode_consistency").outcome is CheckOutcome.VIOLATED

    def test_automatic_mode_is_not_held_to_the_separation_formula(self):
        """A fenced cell is protected by the fence, not by a computed distance."""
        r = verify(envelope(), trace([
            sample(i, mode=OperatingMode.AUTOMATIC, tcp_speed=1500.0, separation=None)
            for i in range(3)]))
        assert r.check("ssm_separation").outcome is CheckOutcome.NOT_APPLICABLE

    def test_running_faster_than_the_stop_was_characterised_is_its_own_finding(self):
        env = envelope(max_tcp_speed_mm_s={OperatingMode.SSM: 1200.0})
        r = verify(env, trace([sample(i, tcp_speed=800.0, separation=9000.0)
                               for i in range(3)]))
        assert r.check("ssm_separation").outcome is CheckOutcome.VERIFIED
        assert r.check("stop_characterisation").outcome is CheckOutcome.VIOLATED

    def test_and_it_is_stated_as_a_limitation_not_buried(self):
        env = envelope(max_tcp_speed_mm_s={OperatingMode.SSM: 1200.0})
        r = verify(env, trace([sample(i, tcp_speed=800.0, separation=9000.0)
                               for i in range(3)]))
        assert any("constant-deceleration model" in c for c in r.checks_skipped)

    def test_a_mode_with_no_declared_limit_is_reported_not_passed(self):
        env = envelope(max_tcp_speed_mm_s={OperatingMode.AUTOMATIC: 2000.0})
        r = verify(env, trace([sample(i) for i in range(3)]))
        assert r.check("speed_limit").outcome is CheckOutcome.UNCHECKED
        assert r.verdict is Verdict.INCOMPLETE

    def test_samples_with_nobody_detected_are_declared_not_counted_as_safe(self):
        r = verify(envelope(), trace(
            [sample(i, separation=None) for i in range(5)]
            + [sample(5 + i, separation=2000.0) for i in range(5)]))
        assert r.check("ssm_separation").samples_examined == 5
        assert any("reported no detected person" in c for c in r.checks_skipped)

    def test_a_trace_where_nobody_was_ever_detected_is_unchecked_not_passed(self):
        r = verify(envelope(), trace([sample(i, separation=None) for i in range(5)]))
        assert r.check("ssm_separation").outcome is CheckOutcome.UNCHECKED
        assert r.verdict is Verdict.INCOMPLETE

    def test_the_worst_margin_is_reported_for_a_run_that_passed(self):
        r = verify(envelope(), trace([sample(i, separation=1730.0 + i) for i in range(5)]))
        assert r.check("ssm_separation").worst_margin == pytest.approx(0.0)

    def test_a_gap_in_the_recording_is_declared(self):
        s = [sample(0), sample(1), Sample(t=5.0, tcp=(0.0, 0.0, 1000.0),
                                          tcp_speed=500.0, mode=OperatingMode.SSM,
                                          separation=2000.0)]
        r = verify(envelope(), trace(s))
        assert any("gap" in c for c in r.checks_skipped)


# -- power and force limiting ---------------------------------------------

def limits_table(**over):
    kw = {
        "edition": "Example edition 2016",
        "transcribed_by": "a.person",
        "verified_by": "b.person",
        "verified_on": "2026-04-01",
        "transient_multiplier": 2.0,
        "regions": {"hand": BodyRegionLimit(key="hand", label="Hand",
                                            max_pressure_n_cm2=260.0,
                                            max_force_n=140.0)},
    }
    kw.update(over)
    return LimitsTable(**kw)


class TestPowerAndForce:
    def test_contact_with_no_limits_table_is_unchecked_never_verified(self):
        t = trace([sample(i, mode=OperatingMode.PFL, tcp_speed=200.0,
                          separation=None, contact_force=50.0, body_region="hand")
                   for i in range(3)])
        r = verify(envelope(), t)
        assert r.check("pfl_contact").outcome is CheckOutcome.UNCHECKED
        assert "NOT checked" in r.check("pfl_contact").reason

    def test_a_contact_within_the_limit_passes(self):
        lt = limits_table()
        env = envelope(pfl_limits_hash=lt.content_hash())
        t = trace([sample(i, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=100.0, contact_area=4.0, body_region="hand")
                   for i in range(3)])
        r = verify(env, t, limits=lt)
        assert r.check("pfl_contact").outcome is CheckOutcome.VERIFIED

    def test_a_contact_over_the_force_limit_fails(self):
        lt = limits_table()
        env = envelope(pfl_limits_hash=lt.content_hash())
        t = trace([sample(0, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=200.0, contact_area=4.0, body_region="hand")])
        r = verify(env, t, limits=lt)
        assert r.check("pfl_contact").outcome is CheckOutcome.VIOLATED

    def test_a_compliant_force_through_a_small_area_still_fails_on_pressure(self):
        """140 N is inside the force limit and lethal through a 0.2 cm² edge."""
        lt = limits_table()
        env = envelope(pfl_limits_hash=lt.content_hash())
        t = trace([sample(0, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=130.0, contact_area=0.2, body_region="hand")])
        r = verify(env, t, limits=lt)
        vs = r.check("pfl_contact").violations
        assert [v.unit for v in vs] == ["N/cm2"]

    def test_a_force_with_no_area_is_declared_unchecked_for_pressure(self):
        lt = limits_table()
        env = envelope(pfl_limits_hash=lt.content_hash())
        t = trace([sample(0, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=100.0, body_region="hand")])
        r = verify(env, t, limits=lt)
        assert any("no contact area" in c for c in r.checks_skipped)

    def test_an_unverified_transcription_caps_the_tier_at_community(self):
        lt = limits_table(verified_by="", verified_on="")
        env = envelope(pfl_limits_hash=lt.content_hash())
        t = trace([sample(0, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=100.0, contact_area=4.0, body_region="hand")])
        r = verify(env, t, limits=lt)
        assert r.tier is AssuranceTier.COMMUNITY
        assert any("UNVERIFIED" in c for c in r.checks_skipped)

    def test_a_limits_table_from_a_different_edition_is_refused(self):
        env = envelope(pfl_limits_hash="a" * 64)
        lt = limits_table()
        t = trace([sample(0, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=100.0, contact_area=4.0, body_region="hand")])
        r = verify(env, t, limits=lt)
        assert r.check("pfl_contact").outcome is CheckOutcome.UNCHECKED
        assert "not the one the envelope was declared against" in \
            r.check("pfl_contact").reason

    def test_a_region_the_table_does_not_cover_is_not_a_pass(self):
        lt = limits_table()
        env = envelope(pfl_limits_hash=lt.content_hash())
        t = trace([sample(0, mode=OperatingMode.PFL, tcp_speed=200.0, separation=None,
                          contact_force=10.0, contact_area=4.0, body_region="skull")])
        r = verify(env, t, limits=lt)
        assert r.check("pfl_contact").outcome is CheckOutcome.UNCHECKED
        assert any("does not cover them" in c for c in r.checks_skipped)

    def test_the_package_ships_no_limits_of_its_own(self, tmp_path):
        with pytest.raises(LimitsError, match="ships no body-region limits"):
            LimitsTable.from_json(tmp_path / "nothing.json")

    def test_a_table_that_does_not_name_its_edition_is_refused(self):
        with pytest.raises(LimitsError, match="edition"):
            limits_table(edition="")

    def test_transient_limits_are_a_declared_multiple_not_a_constant(self):
        lt = limits_table(transient_multiplier=3.0)
        assert lt.permitted_force_n("hand", transient=True) == pytest.approx(420.0)
        assert lt.permitted_force_n("hand", transient=False) == pytest.approx(140.0)


# -- traces ---------------------------------------------------------------

class TestTrace:
    def test_an_empty_trace_is_refused(self):
        with pytest.raises(TraceError, match="no samples"):
            trace([])

    def test_out_of_order_samples_are_refused(self):
        with pytest.raises(TraceError, match="not strictly increasing"):
            trace([sample(0), sample(5), sample(2)])

    def test_a_naive_start_time_is_refused(self):
        with pytest.raises(TraceError, match="timezone"):
            trace([sample(0)], started_at=datetime(2026, 9, 12, 4, 31))

    def test_a_negative_separation_is_refused(self):
        with pytest.raises(TraceError, match="separation is negative"):
            sample(0, separation=-5.0)

    def test_two_recordings_of_the_same_run_share_an_identity(self):
        a = trace([sample(i) for i in range(3)])
        b = trace([sample(i) for i in range(3)])
        assert a.content_hash() == b.content_hash()

    def test_changing_one_sample_changes_the_identity(self):
        a = trace([sample(i) for i in range(3)])
        b = trace([sample(i) for i in range(2)] + [sample(2, separation=1999.0)])
        assert a.content_hash() != b.content_hash()

    def test_csv_loading_demands_the_provenance_nobody_may_omit(self, tmp_path):
        p = tmp_path / "run.csv"
        p.write_text("t,x,y,z,tcp_speed,mode,separation\n"
                     "0.0,0,0,1000,500,ssm,2000\n"
                     "0.02,0,0,1000,500,ssm,2000\n", encoding="utf-8")
        t = Trace.from_csv(p, trace_id="R", provenance=Provenance.BENCH,
                           source_system="log", sample_rate_hz=50.0,
                           started_at=datetime(2026, 9, 12, tzinfo=UTC))
        assert len(t) == 2
        assert t.provenance is Provenance.BENCH


# -- bundles --------------------------------------------------------------

class TestBundle:
    def test_a_bundle_is_sealed_and_verifies(self, tmp_path):
        b = build_bundle(envelope(), trace([sample(i) for i in range(5)]), actor=ACTOR)
        assert b.evidence.verify()
        assert b.verdict is Verdict.PASS
        assert b.evidence.validation_state is ValidationState.VERIFIED

    def test_a_failing_run_is_sealed_as_refuted_not_discarded(self):
        b = build_bundle(envelope(),
                         trace([sample(i, separation=100.0) for i in range(3)]),
                         actor=ACTOR)
        assert b.verdict is Verdict.FAIL
        assert b.evidence.validation_state is ValidationState.REFUTED

    def test_an_unattributed_bundle_is_refused(self):
        with pytest.raises(Exception, match="(?i)actor|attribut"):
            build_bundle(envelope(), trace([sample(0)]),
                         actor=Actor(identifier="", role=""))

    def test_the_bundle_names_both_of_its_inputs_by_hash(self):
        env, t = envelope(), trace([sample(i) for i in range(3)])
        b = build_bundle(env, t, actor=ACTOR)
        relations = {r.relation: r.content_hash for r in b.evidence.relations}
        assert relations["concerns"] == env.content_hash()
        assert relations["derived_from"] == t.content_hash()

    def test_it_goes_into_the_ledger_and_the_chain_still_verifies(self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "l.db")
        build_bundle(envelope(), trace([sample(i) for i in range(3)]),
                     actor=ACTOR, ledger=ledger)
        ok, problems = ledger.verify_chain()
        assert ok, problems
        assert len(ledger) == 1

    def test_an_auditor_can_re_verify_it_from_the_originals(self, tmp_path):
        env, t = envelope(), trace([sample(i) for i in range(3)])
        p = build_bundle(env, t, actor=ACTOR).write(tmp_path / "b.json")
        ok, problems = verify_bundle(p, envelope=env, trace=t)
        assert ok, problems
        assert problems == []

    def test_editing_the_verdict_after_sealing_is_caught(self, tmp_path):
        env, t = envelope(), trace([sample(i, separation=100.0) for i in range(3)])
        p = build_bundle(env, t, actor=ACTOR).write(tmp_path / "b.json")
        d = json.loads(p.read_text())
        d["evidence"]["body"]["verdict"] = "pass"
        p.write_text(json.dumps(d))
        ok, problems = verify_bundle(p, envelope=env, trace=t)
        assert not ok
        assert any("edited after sealing" in x for x in problems)
        assert any("its own checks imply" in x for x in problems)

    def test_a_bundle_checked_against_the_wrong_trace_is_rejected(self, tmp_path):
        env = envelope()
        p = build_bundle(env, trace([sample(i) for i in range(3)]),
                         actor=ACTOR).write(tmp_path / "b.json")
        other = trace([sample(i, separation=1234.0) for i in range(3)])
        ok, problems = verify_bundle(p, envelope=env, trace=other)
        assert not ok
        assert any("not the one this bundle was produced against" in x for x in problems)

    def test_checking_only_the_seal_is_reported_as_a_limitation(self, tmp_path):
        p = build_bundle(envelope(), trace([sample(i) for i in range(3)]),
                         actor=ACTOR).write(tmp_path / "b.json")
        ok, problems = verify_bundle(p)
        assert ok
        assert any("NOT CHECKED" in x for x in problems)

    def test_a_file_that_is_not_a_bundle_is_rejected_by_schema(self, tmp_path):
        p = tmp_path / "x.json"
        p.write_text(json.dumps({"schema": "something.else/1"}))
        ok, problems = verify_bundle(p)
        assert not ok
        assert any("schema" in x for x in problems)


# -- round trip -----------------------------------------------------------

class TestRoundTrip:
    def test_an_envelope_survives_json(self, tmp_path):
        env = envelope()
        p = tmp_path / "e.json"
        p.write_text(json.dumps(env.to_dict()))
        assert SafetyEnvelope.from_json(p).content_hash() == env.content_hash()

    def test_a_trace_survives_json(self, tmp_path):
        t = trace([sample(i) for i in range(4)])
        p = tmp_path / "t.json"
        p.write_text(json.dumps(t.hashable_payload()))
        assert Trace.from_json(p).content_hash() == t.content_hash()

    def test_the_shipped_example_reproduces_its_findings(self):
        """The example files are part of the product and are checked like code."""
        from pathlib import Path
        root = Path(__file__).resolve().parents[1] / "examples" / "machine"
        env = SafetyEnvelope.from_json(root / "envelope.json")
        t = Trace.from_json(root / "trace.json")
        r = verify(env, t)
        assert r.verdict is Verdict.FAIL
        assert r.check("ssm_separation").outcome is CheckOutcome.VIOLATED
        assert r.tier is AssuranceTier.PROFILE  # the scanner figure is a datasheet


# -- the HTTP surface -----------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from assurance.api import deps

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "ledger.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    from assurance.api.service import create_app

    with TestClient(create_app()) as c:
        yield c
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture
def store(client):
    """The same AccountStore the client is using."""
    from assurance.api import deps
    return deps.get_accounts()


def keyed(store, tier: str) -> dict[str, str]:
    account = store.upsert_account(email=f"{tier}@example.de", tier=tier)
    return {"X-API-Key": store.issue_key(account.id)}


SEPARATION_BODY = {
    "robot_speed_mm_s": 500.0,
    "reaction_time_s": 0.1,
    "stop_time_s": 0.25,
    "stop_distance_mm": 120.0,
    "measured_at_speed_mm_s": 500.0,
    "intrusion_distance_mm": 850.0,
    "human_position_uncertainty_mm": 100.0,
    "robot_position_uncertainty_mm": 50.0,
}


class TestSeparationEndpoint:
    def test_it_needs_no_account(self, client):
        r = client.post("/v1/machine/separation", json=SEPARATION_BODY)
        assert r.status_code == 200
        assert r.json()["required_separation_mm"] == pytest.approx(1730.0)

    def test_it_returns_every_term_separately(self, client):
        b = client.post("/v1/machine/separation", json=SEPARATION_BODY).json()["breakdown"]
        assert b["Sh_human_travel_mm"] == pytest.approx(560.0)
        assert b["C_intrusion_mm"] == pytest.approx(850.0)

    def test_it_is_metered_on_the_free_tier(self, client):
        r = client.post("/v1/machine/separation", json=SEPARATION_BODY)
        assert r.headers["x-assurance-quota-limit"] == "20"
        assert r.headers["x-assurance-quota-remaining"] == "19"

    def test_it_warns_when_the_stopping_distance_was_extrapolated(self, client):
        body = {**SEPARATION_BODY, "robot_speed_mm_s": 1500.0}
        notes = client.post("/v1/machine/separation", json=body).json()["notes"]
        assert any("extrapolated" in n for n in notes)

    def test_it_says_when_it_substituted_the_walking_figure(self, client):
        notes = client.post("/v1/machine/separation",
                            json=SEPARATION_BODY).json()["notes"]
        assert any("ISO 13855 walking figure" in n for n in notes)

    def test_a_zero_measured_speed_is_refused_not_divided_by(self, client):
        body = {**SEPARATION_BODY, "measured_at_speed_mm_s": 0.0}
        assert client.post("/v1/machine/separation", json=body).status_code == 422

    def test_it_states_what_it_did_not_check(self, client):
        d = client.post("/v1/machine/separation", json=SEPARATION_BODY).json()
        assert d["checks_skipped"]


class TestVerifyEndpoint:
    def _payload(self):
        env, t = envelope(), trace([sample(i) for i in range(5)])
        return {"envelope": env.to_dict(), "trace": t.hashable_payload(),
                "actor": "v.grimaldi"}

    def test_it_is_a_402_without_the_cell_plan(self, client, store):
        r = client.post("/v1/machine/verify", json=self._payload(),
                        headers=keyed(store, "register"))
        assert r.status_code == 402
        assert r.json()["detail"]["error"] == \
            "plan_does_not_include_machine_verification"

    def test_the_402_points_at_the_free_endpoints(self, client, store):
        r = client.post("/v1/machine/verify", json=self._payload(),
                        headers=keyed(store, "register"))
        assert "separation" in r.json()["detail"]["remedy"]

    def test_it_is_a_401_with_no_key_at_all(self, client):
        assert client.post("/v1/machine/verify",
                           json=self._payload()).status_code == 401

    def test_the_cell_plan_gets_a_sealed_bundle(self, client, store):
        r = client.post("/v1/machine/verify", json=self._payload(),
                        headers=keyed(store, "cell"))
        assert r.status_code == 200, r.text
        d = r.json()
        assert d["verdict"] == "pass"
        assert d["tier"] == "validated"
        assert d["evidence"]["content_hash"]

    def test_an_oversized_trace_is_refused_with_the_local_alternative(
            self, client, store, monkeypatch):
        from assurance.api import machine_routes
        monkeypatch.setattr(machine_routes, "MAX_SAMPLES", 3)
        r = client.post("/v1/machine/verify", json=self._payload(),
                        headers=keyed(store, "cell"))
        assert r.status_code == 413
        assert "assurance machine verify" in r.json()["detail"]["detail"]


class TestBundleCheckEndpoint:
    def test_anyone_can_re_verify_a_bundle_with_no_account(self, client):
        env, t = envelope(), trace([sample(i) for i in range(3)])
        bundle = build_bundle(env, t, actor=ACTOR).to_dict()
        r = client.post("/v1/machine/bundle/check", json={
            "bundle": bundle, "envelope": env.to_dict(),
            "trace": t.hashable_payload()})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["checked"]["against_original_trace"] is True

    def test_it_is_not_metered(self, client):
        env, t = envelope(), trace([sample(i) for i in range(3)])
        bundle = build_bundle(env, t, actor=ACTOR).to_dict()
        for _ in range(25):
            r = client.post("/v1/machine/bundle/check", json={"bundle": bundle})
            assert r.status_code == 200

    def test_a_tampered_bundle_is_rejected_for_a_stranger_too(self, client):
        env, t = envelope(), trace([sample(i, separation=50.0) for i in range(3)])
        bundle = build_bundle(env, t, actor=ACTOR).to_dict()
        bundle["evidence"]["body"]["verdict"] = "pass"
        r = client.post("/v1/machine/bundle/check", json={"bundle": bundle})
        assert r.json()["ok"] is False
        assert any("edited after sealing" in p for p in r.json()["problems"])

    def test_it_reports_which_of_the_three_checks_it_could_run(self, client):
        env, t = envelope(), trace([sample(i) for i in range(3)])
        bundle = build_bundle(env, t, actor=ACTOR).to_dict()
        checked = client.post("/v1/machine/bundle/check",
                              json={"bundle": bundle}).json()["checked"]
        assert checked["seal"] is True
        assert checked["against_original_envelope"] is False


class TestPlanSurface:
    def test_only_the_cell_plan_carries_machine_verification(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert plans["cell"]["limits"]["machine_verification"] is True
        assert plans["register"]["limits"]["machine_verification"] is False
        assert plans["free"]["limits"]["machine_verification"] is False

    def test_the_free_tier_advertises_the_separation_calculator(self, client):
        plans = {p["tier"]: p for p in client.get("/v1/plans").json()}
        assert any("separation" in i for i in plans["free"]["includes"])
