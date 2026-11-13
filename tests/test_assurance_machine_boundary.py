"""Where the machine engine's answers stop: strict inputs, stated limits, reference cases.

This file grows with the work on the machine boundary. Each section says which finding it
pins; the reference cases at the end state their expected outcome in the fixture itself
(``tests/fixtures/machine_boundary/``) so that a future change to a verdict is a conscious one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from assurance.machine.cli import main as machine_cli
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.ssm import (
    SEPARATION_ARITHMETIC_ONLY,
    SEPARATION_UNVERIFIED_FORMULA,
    separation_disclosures,
)
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import FORMULA_LIMITATION, verify

SEPARATION_URL = "/v1/machine/separation"

#: The documented example: Tr 0.1 s, Ts 0.25 s, 120 mm at 500 mm/s, C 850, Zd 100, Zr 50.
#: Sh = 1600 * 0.35 = 560, Sr = 500 * 0.1 = 50, Ss = 120, so S = 560+50+120+850+100+50 = 1730.
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

NUMERIC_FIELDS = tuple(SEPARATION_BODY) + ("human_speed_mm_s",)


@pytest.fixture()
def store(client):
    from assurance.api import deps
    return deps.get_accounts()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import importlib

    from fastapi.testclient import TestClient

    from assurance.api import deps

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "service" / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "service" / "accounts.db"))
    for name in ("ASSURANCE_API_KEYS", "ASSURANCE_ALLOW_UNAUTHENTICATED",
                 "ASSURANCE_MAX_EVIDENCE_BODY_BYTES", "ASSURANCE_MAX_BODY_BYTES"):
        monkeypatch.delenv(name, raising=False)
    caches = (deps._register_for, deps._tenant_register_for, deps._accounts_for)
    for cache in caches:
        cache.cache_clear()
    with TestClient(importlib.import_module("assurance.api.service").create_app()) as c:
        yield c
    for cache in caches:
        cache.cache_clear()


def post_raw(client, field: str, literal: str):
    """POST the documented body with ``field`` replaced by the raw JSON ``literal``.

    A raw literal, not a Python value, because ``NaN``, ``Infinity`` and a 400-digit
    integer are tokens a JSON client can send that ``json.dumps`` would never produce.
    """
    base = {k: v for k, v in SEPARATION_BODY.items() if k != field}
    parts = [f"{json.dumps(k)}: {json.dumps(v)}" for k, v in base.items()]
    parts.append(f"{json.dumps(field)}: {literal}")
    return client.post(SEPARATION_URL, content="{" + ", ".join(parts) + "}",
                       headers={"content-type": "application/json"})


# -- F5: /v1/machine/separation reads numbers the way the engine does -------

class TestSeparationRouteTakesOnlyJsonNumbers:
    """``reaction_time_s: true`` and ``"1.0"`` used to return 200, and ``true`` counted as 1:
    3420 mm against 1710 mm for ``1.0``. The route is free and returns a safety distance, and
    docs/claims-registry.md promises it refuses strings, booleans, NaN and infinity."""

    def test_the_documented_body_still_gives_the_documented_answer(self, client):
        r = client.post(SEPARATION_URL, json=SEPARATION_BODY)
        assert r.status_code == 200
        assert r.json()["required_separation_mm"] == pytest.approx(1730.0)

    @pytest.mark.parametrize("field", NUMERIC_FIELDS)
    @pytest.mark.parametrize("literal", ["1", "1.0", "1e3", "1E3", "0.5", "250"])
    def test_json_integers_floats_and_exponents_are_accepted(self, client, field, literal):
        r = post_raw(client, field, literal)
        assert r.status_code == 200, (field, literal, r.text)
        assert r.json()["required_separation_mm"] > 0

    @pytest.mark.parametrize("field", NUMERIC_FIELDS)
    @pytest.mark.parametrize("literal", [
        "true", "false", '"1"', '"1.0"', '" 1 "', '"750 mm"', '""', "[1]", "{}",
        "NaN", "Infinity", "-Infinity", "1e999", "-1e999", "-1", "-0.001",
    ])
    def test_everything_else_is_a_422_and_no_distance_is_returned(self, client, field, literal):
        r = post_raw(client, field, literal)
        assert r.status_code == 422, (field, literal, r.status_code, r.text)
        assert "required_separation_mm" not in r.text

    @pytest.mark.parametrize("field", [f for f in NUMERIC_FIELDS if f != "human_speed_mm_s"])
    def test_null_is_not_a_number_for_a_figure_the_caller_must_state(self, client, field):
        assert post_raw(client, field, "null").status_code == 422

    def test_null_closing_speed_means_none_supplied_exactly_as_omitting_it(self, client):
        omitted = client.post(SEPARATION_URL, json=SEPARATION_BODY).json()
        nulled = post_raw(client, "human_speed_mm_s", "null").json()
        assert nulled["required_separation_mm"] == omitted["required_separation_mm"]
        assert nulled["breakdown"]["human_speed_source"] == "default"

    def test_a_boolean_no_longer_counts_as_one(self, client):
        """Tr = 1.0 s gives Sh = 1600 * 1.25 = 2000 and Sr = 500, so S = 3620 mm. ``true``
        used to return exactly that answer, as if the caller had typed 1.0."""
        honest = post_raw(client, "reaction_time_s", "1.0")
        assert honest.status_code == 200
        assert honest.json()["required_separation_mm"] == pytest.approx(3620.0)
        assert post_raw(client, "reaction_time_s", "true").status_code == 422

    def test_a_huge_integer_is_refused_not_overflowed(self, client):
        assert post_raw(client, "stop_distance_mm", "9" * 400).status_code == 422
        # Past Python's 4300-digit int limit the body is not decoded at all: the framework
        # answers 400 before the model sees it. Either way it is a refusal, never a 200.
        assert post_raw(client, "stop_distance_mm", "9" * 5000).status_code in (400, 422)

    def test_a_number_past_the_engines_plausibility_rail_is_refused(self, client):
        """Strict typing is not the rail: the engine's own rails still apply behind it."""
        assert post_raw(client, "stop_distance_mm", "1e30").status_code == 422

    def test_an_unknown_field_is_still_refused(self, client):
        r = client.post(SEPARATION_URL, json={**SEPARATION_BODY, "stop_distance": 1.0})
        assert r.status_code == 422


# -- F4: every surface that prints a separation distance says the formula is unverified ----

def _envelope() -> SafetyEnvelope:
    measured = FigureBasis(kind="measured", reference="STOP-TEST-1", date="2026-03-11")
    return SafetyEnvelope(
        envelope_id="ENV-1", product="Cell", product_version="1.0.0",
        workspace=Workspace(minimum=(-1000.0, -1000.0, 0.0), maximum=(1000.0, 1000.0, 2000.0)),
        max_tcp_speed_mm_s={OperatingMode.SSM: 500.0},
        stop=StopPerformance(reaction_time_s=0.1, stop_time_s=0.25, stop_distance_mm=120.0,
                             measured_at_speed_mm_s=500.0, basis=measured),
        uncertainty=SensingUncertainty(human_position_mm=100.0, robot_position_mm=50.0,
                                       basis=measured),
        intrusion_distance_mm=850.0)


@pytest.fixture()
def envelope_file(tmp_path):
    path = tmp_path / "envelope.json"
    path.write_text(json.dumps(_envelope().to_dict()), encoding="utf-8")
    return path


class TestTheUnverifiedFormulaLabelIsOnEverySeparationSurface:
    """The label was on ``verify`` only. ``assurance machine separation`` (text and --json) and
    ``POST /v1/machine/separation`` printed a distance with no hint that the formula and its
    constants are unchecked against the standards, and the API stated the 1600 mm/s walking
    figure as the ISO 13855 value."""

    def test_the_label_names_what_is_unverified_and_what_the_figure_is_not(self):
        text = SEPARATION_UNVERIFIED_FORMULA
        assert text.startswith("UNVERIFIED FORMULA")
        for term in ("1600 mm/s", "2000 mm/s", "850 mm", "ISO/TS 15066", "ISO 13855",
                     "quadratic extrapolation", "not a risk assessment",
                     "not a statement of conformity"):
            assert term in text
        assert separation_disclosures() == [SEPARATION_UNVERIFIED_FORMULA,
                                            SEPARATION_ARITHMETIC_ONLY]

    def test_the_cli_text_carries_the_label(self, envelope_file, capsys):
        assert machine_cli(["separation", "--envelope", str(envelope_file),
                            "--speed", "500"]) == 0
        out = " ".join(capsys.readouterr().out.split())
        assert " ".join(SEPARATION_UNVERIFIED_FORMULA.split()) in out
        assert " ".join(SEPARATION_ARITHMETIC_ONLY.split()) in out

    def test_the_cli_json_carries_the_label_and_keeps_every_old_key(self, envelope_file, capsys):
        assert machine_cli(["separation", "--envelope", str(envelope_file),
                            "--speed", "500", "--json"]) == 0
        d = json.loads(capsys.readouterr().out)
        assert d["formula_status"] == "unverified"
        assert d["checks_skipped"] == separation_disclosures()
        for old in ("Sh_human_travel_mm", "Sr_robot_reaction_travel_mm",
                    "Ss_robot_stopping_travel_mm", "C_intrusion_mm", "Zd_human_uncertainty_mm",
                    "Zr_robot_uncertainty_mm", "total_mm", "stopping_basis",
                    "human_speed_mm_s", "human_speed_source", "robot_speed_mm_s"):
            assert old in d
        assert d["total_mm"] == pytest.approx(1730.0)

    def test_the_api_carries_the_label_and_keeps_every_old_field(self, client):
        d = client.post(SEPARATION_URL, json=SEPARATION_BODY).json()
        assert d["formula_status"] == "unverified"
        assert d["checks_skipped"] == separation_disclosures()
        for old in ("required_separation_mm", "breakdown", "explain", "notes", "checks_skipped"):
            assert old in d
        assert d["required_separation_mm"] == pytest.approx(1730.0)

    def test_the_api_no_longer_states_the_default_closing_speed_as_the_standards_value(
            self, client):
        d = client.post(SEPARATION_URL, json=SEPARATION_BODY).json()
        note = next(n for n in d["notes"] if "No closing speed was supplied" in n)
        assert "default closing speed of 1600 mm/s" in note
        assert "UNVERIFIED" in note
        assert "is normally taken as 2000 mm/s" not in " ".join(d["notes"])
        assert "ISO 13855 walking figure of" not in " ".join(d["notes"])

    def test_a_supplied_closing_speed_adds_no_default_note(self, client):
        d = client.post(SEPARATION_URL, json={**SEPARATION_BODY, "human_speed_mm_s": 1200.0}).json()
        assert not any("No closing speed was supplied" in n for n in d["notes"])
        assert d["formula_status"] == "unverified"

    def test_the_openapi_description_of_the_closing_speed_does_not_state_the_value_as_fact(
            self, client):
        spec = client.get("/openapi.json").json()
        text = spec["components"]["schemas"]["SeparationIn"]["properties"][
            "human_speed_mm_s"]["description"]
        assert "UNVERIFIED" in text and "ISO 13855 walking figure" not in text

    def test_verify_still_carries_its_own_sealed_wording(self):
        """The sealed wording is part of every bundle's replay, so it is not the same string."""
        trace = Trace(
            trace_id="RUN-1", provenance=Provenance.SIMULATION, source_system="fw",
            started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
            samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                                 mode=OperatingMode.SSM, separation=3000.0)
                          for i in range(20)))
        assert FORMULA_LIMITATION in verify(_envelope(), trace).checks_skipped


# -- engine 7: bundles sealed by engine 6 still verify and replay exactly as before -----------
from pathlib import Path  # noqa: E402

from assurance.machine.bundle import build_bundle, check_bundle_data  # noqa: E402
from assurance.machine.limits import LimitsTable  # noqa: E402
from assurance.machine.recorder_attestation import RecorderTrust  # noqa: E402
from assurance.machine.verify import ENGINE_VERSION  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "machine_boundary"
ENGINE6 = sorted(p.name for p in (FIXTURES / "engine6").iterdir())
AS_OF = datetime(2026, 10, 1, tzinfo=UTC)
_FIELDS = ("ok", "level", "problems", "limitations", "verified", "seal_intact",
           "internally_consistent", "replayed", "provenance_basis", "provenance_reassessed",
           "believed_tier", "reassessment_note")


def _load(case: str):
    d = FIXTURES / "engine6" / case
    raw = json.loads((d / "bundle.json").read_text())
    env = SafetyEnvelope.from_dict(json.loads((d / "envelope.json").read_text()))
    tr = Trace.from_dict(json.loads((d / "trace.json").read_text()))
    limits = (LimitsTable.from_dict(json.loads((d / "limits.json").read_text()))
              if (d / "limits.json").exists() else None)
    trust = (RecorderTrust.from_dict(json.loads((d / "recorder-trust.json").read_text()))
             if (d / "recorder-trust.json").exists() else None)
    expected = json.loads((d / "expected.json").read_text())
    return raw, env, tr, limits, trust, expected


_ENGINE6_MODES = [
    (case, mode) for case in ENGINE6
    for mode in ("alone", "with_originals", "alone_with_trust", "with_originals_and_trust")
    if mode in json.loads((FIXTURES / "engine6" / case / "expected.json").read_text())]


def _summary(c):
    return {k: (list(getattr(c, k)) if isinstance(getattr(c, k), tuple) else getattr(c, k))
            for k in _FIELDS}


class TestEngine6BundlesStillVerifyAndReplay:
    """Fixtures generated by the UNCHANGED main code at 2b41ddb (engine 6); ``expected.json``
    is what that code's checker said. The current build must say the same, field for field,
    including the wording of every note. One deliberate correction: a ``profile`` bundle was
    believed at community because tier ``>`` compared names; it is believed at profile."""

    def test_the_fixtures_are_engine_6_and_this_build_is_newer(self):
        assert ENGINE_VERSION != "6"
        for case in ENGINE6:
            raw = _load(case)[0]
            assert raw["evidence"]["body"]["engine_version"] == "6", case

    @pytest.mark.parametrize(("case", "mode"), _ENGINE6_MODES)
    def test_every_check_gives_the_answer_engine_6_gave(self, case, mode):
        raw, env, tr, limits, trust, exp = _load(case)
        kw = {"as_of": AS_OF}
        if "originals" in mode:
            kw.update(envelope=env, trace=tr, limits=limits)
        if mode.endswith("trust"):
            kw["recorder_trust"] = trust
        got = _summary(check_bundle_data(raw, **kw))
        want = dict(exp[mode])
        want.update(exp.get("corrected_by_tier_order_fix", {}))
        assert got == want

    @pytest.mark.parametrize("case", ENGINE6)
    def test_the_engine_6_rules_are_reproduced_not_the_newest(self, case):
        raw, env, tr, limits, trust, exp = _load(case)
        c = check_bundle_data(raw, envelope=env, trace=tr, limits=limits,
                              recorder_trust=trust, as_of=AS_OF)
        assert c.ok and c.replayed

    def test_a_replay_that_is_not_the_sealing_engine_is_still_not_a_reproduction(self):
        raw, env, tr, limits, trust, _ = _load("declared_pass")
        raw["evidence"]["body"]["engine_version"] = "5"
        from tests.test_assurance_bundle_check import reseal
        c = check_bundle_data(reseal(raw), envelope=env, trace=tr)
        assert not c.ok and any("not a reproduction" in p for p in c.problems)


# -- F6: a sensed closing speed that replaces the declared one is disclosed --------------------

def _ssm_trace(separation, human_speed=None, n=20):
    return Trace(
        trace_id="RUN-S", provenance=Provenance.FIELD, source_system="fw",
        started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
        samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                             mode=OperatingMode.SSM, separation=separation,
                             human_speed=human_speed) for i in range(n)))


def _sensed_notes(result):
    return [c for c in result.checks_skipped if "the closing speed the trace itself reports" in c]


class TestASensedClosingSpeedIsDisclosed:
    """Required at 300 mm/s: Sr 30 + Ss 120 + C 850 + Zd 100 + Zr 50 = 1150 plus Sh = v * 0.35.
    With the default 1600 mm/s Sh is 560 (S = 1710); a sensed 0.0 makes it 0 (S = 1150)."""

    def test_the_same_separation_fails_on_the_default_and_passes_on_a_sensed_zero(self):
        sep = 1200.0
        assert verify(_envelope(), _ssm_trace(sep)).verdict.value == "fail"
        assert verify(_envelope(), _ssm_trace(sep, 0.0)).verdict.value == "pass"

    def test_engine_7_says_so_and_does_not_change_the_verdict_or_tier(self):
        r7 = verify(_envelope(), _ssm_trace(1200.0, 0.0))
        r6 = verify(_envelope(), _ssm_trace(1200.0, 0.0), engine_version="6")
        assert (r7.verdict, r7.tier) == (r6.verdict, r6.tier)
        assert r6.checks_skipped != r7.checks_skipped
        assert _sensed_notes(r6) == []
        (note,) = _sensed_notes(r7)
        assert "20 of 20 compared samples" in note
        assert "lowest reported value was 0 mm/s" in note
        assert "20 of those samples reported less than 1600 mm/s" in note
        assert "turn a failing separation into a passing one" in note

    def test_the_count_of_samples_below_the_fallback_is_exact(self):
        tr = Trace(
            trace_id="RUN-M", provenance=Provenance.FIELD, source_system="fw",
            started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
            samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                                 mode=OperatingMode.SSM, separation=3000.0,
                                 human_speed=(2000.0 if i % 2 else 900.0)) for i in range(20)))
        (note,) = _sensed_notes(verify(_envelope(), tr))
        assert "20 of 20 compared samples" in note and "lowest reported value was 900" in note
        assert "10 of those samples reported less than 1600" in note

    def test_no_sensed_speed_no_note(self):
        assert _sensed_notes(verify(_envelope(), _ssm_trace(3000.0))) == []

    def test_a_sealed_engine_7_bundle_carries_the_disclosure_and_replays(self):
        env, tr = _envelope(), _ssm_trace(1200.0, 0.0)
        from assurance.core.evidence import Actor
        raw = json.loads(json.dumps(build_bundle(
            env, tr, actor=Actor(identifier="v.grimaldi", role="engineer")).to_dict()))
        assert raw["evidence"]["body"]["engine_version"] == ENGINE_VERSION
        assert any("the closing speed the trace itself reports" in c
                   for c in raw["evidence"]["checks_skipped"])
        c = check_bundle_data(raw, envelope=env, trace=tr)
        assert c.ok and c.level == "reproduced"

    def test_dropping_the_disclosure_from_an_engine_7_bundle_is_caught_on_replay(self):
        env, tr = _envelope(), _ssm_trace(1200.0, 0.0)
        from assurance.core.evidence import Actor

        from .test_assurance_bundle_check import reseal
        raw = json.loads(json.dumps(build_bundle(
            env, tr, actor=Actor(identifier="v.grimaldi", role="engineer")).to_dict()))
        raw["evidence"]["checks_skipped"] = [
            c for c in raw["evidence"]["checks_skipped"]
            if "the closing speed the trace itself reports" not in c]
        del raw["result"]
        c = check_bundle_data(reseal(raw), envelope=env, trace=tr)
        assert not c.ok and any("limitations differ" in p for p in c.problems)


# -- F2: every result and check states its boundary, and a human must review it -----------------
from assurance.core.evidence import Actor  # noqa: E402
from assurance.machine.boundary import BOUNDARY_KEYS  # noqa: E402
from tests.test_assurance_bundle_check import reseal  # noqa: E402

_ACTOR = Actor(identifier="v.grimaldi", role="verification engineer")
_CHECK_NAMES = ("workspace_containment", "speed_limit", "ssm_separation",
                "stop_characterisation", "pfl_contact", "mode_consistency",
                "trace_coverage", "input_dates")


def _sealed(env=None, tr=None):
    env, tr = env or _envelope(), tr or _ssm_trace(3000.0)
    raw = json.loads(json.dumps(build_bundle(env, tr, actor=_ACTOR).to_dict()))
    return raw, env, tr


class TestEveryResultStatesItsBoundary:
    def test_the_result_and_every_check_carry_the_whole_block(self):
        r = verify(_envelope(), _ssm_trace(3000.0)).to_dict()
        assert tuple(r["boundary"]) == BOUNDARY_KEYS
        assert [c["name"] for c in r["checks"]] == list(_CHECK_NAMES)
        for c in r["checks"]:
            assert tuple(c["boundary"]) == BOUNDARY_KEYS, c["name"]
            assert c["boundary"]["tested"] and c["boundary"]["not_tested"]
            assert c["boundary"]["valid_for"]

    def test_human_review_is_required_on_every_block_whatever_the_outcome(self):
        for tr, env in ((_ssm_trace(3000.0), _envelope()), (_ssm_trace(10.0), _envelope()),
                        (_ssm_trace(3000.0, n=3), _envelope())):
            r = verify(env, tr).to_dict()
            blocks = [r["boundary"], *[c["boundary"] for c in r["checks"]]]
            assert all(b["human_review"]["required"] is True for b in blocks)
            assert all(b["human_review"]["reasons"] for b in blocks)

    def test_inputs_are_named_with_the_hashes_of_the_files_they_came_from(self):
        env, tr = _envelope(), _ssm_trace(3000.0)
        b = verify(env, tr).to_dict()["boundary"]
        assert b["inputs_used"]["hashes"] == {"envelope": env.content_hash(),
                                              "trace": tr.content_hash()}
        assert "trace.samples[].separation" in b["inputs_used"]["fields"]

    def test_observed_versus_declared_follows_the_samples(self):
        def source(tr):
            r = verify(_envelope(), tr).to_dict()
            return next(c for c in r["checks"] if c["name"] == "ssm_separation")[
                "boundary"]["observed_vs_declared"]["human_speed"]

        assert source(_ssm_trace(3000.0)) == "declared"
        assert source(_ssm_trace(3000.0, human_speed=800.0)) == "observed"
        mixed = Trace(
            trace_id="RUN-X", provenance=Provenance.FIELD, source_system="fw",
            started_at=datetime(2026, 9, 12, 4, 31, tzinfo=UTC), sample_rate_hz=50.0,
            samples=tuple(Sample(t=i / 50.0, tcp=(0.0, 0.0, 1000.0), tcp_speed=300.0,
                                 mode=OperatingMode.SSM, separation=3000.0,
                                 human_speed=800.0 if i % 2 else None) for i in range(20)))
        assert source(mixed) == "mixed"

    def test_a_check_that_could_not_run_says_why_in_its_review_reasons(self):
        r = verify(_envelope(), _ssm_trace(3000.0, n=3)).to_dict()
        cov = next(c for c in r["checks"] if c["name"] == "trace_coverage")
        assert cov["outcome"] == "unchecked"
        assert any("could not run" in x for x in cov["boundary"]["human_review"]["reasons"])

    def test_the_sensed_speed_reaches_the_review_reasons(self):
        r = verify(_envelope(), _ssm_trace(1200.0, 0.0)).to_dict()
        reasons = r["boundary"]["human_review"]["reasons"]
        assert any("20 of 20 compared samples used the trace's own closing speed "
                   "(20 below" in x for x in reasons)

    def test_engine_6_has_no_block_anywhere(self):
        r = verify(_envelope(), _ssm_trace(3000.0), engine_version="6").to_dict()
        assert "boundary" not in r and all("boundary" not in c for c in r["checks"])


class TestTheBoundaryIsSealedAndCannotBeEdited:
    def test_a_sealed_bundle_carries_it_and_replays(self):
        raw, env, tr = _sealed()
        assert tuple(raw["evidence"]["body"]["boundary"]) == BOUNDARY_KEYS
        assert raw["result"]["boundary"] == raw["evidence"]["body"]["boundary"]
        c = check_bundle_data(raw, envelope=env, trace=tr)
        assert c.ok and c.level == "reproduced"
        assert any("boundary block that says qualified human review is required" in v
                   for v in c.verified)

    def test_switching_review_off_and_resealing_is_rejected_without_the_originals(self):
        raw, _, _ = _sealed()
        raw["evidence"]["body"]["boundary"]["human_review"]["required"] = False
        c = check_bundle_data(reseal(raw))
        assert not c.ok
        assert any("does not say that qualified human review is required" in p
                   for p in c.problems)

    def test_switching_review_off_on_one_check_is_rejected(self):
        raw, _, _ = _sealed()
        raw["evidence"]["body"]["checks"][2]["boundary"]["human_review"]["required"] = False
        c = check_bundle_data(reseal(raw))
        assert not c.ok and any("ssm_separation" in p for p in c.problems)

    def test_dropping_the_block_from_an_engine_7_body_is_rejected(self):
        raw, _, _ = _sealed()
        del raw["evidence"]["body"]["boundary"]
        c = check_bundle_data(reseal(raw))
        assert not c.ok and any("records no boundary block" in p for p in c.problems)

    def test_rewording_a_limit_is_caught_on_replay(self):
        raw, env, tr = _sealed()
        raw["evidence"]["body"]["boundary"]["not_tested"][0] = "Nothing was left out."
        del raw["result"]
        c = check_bundle_data(reseal(raw), envelope=env, trace=tr)
        assert not c.ok and any("boundary" in p for p in c.problems)

    def test_a_printed_result_with_an_edited_block_is_caught(self):
        raw, _, _ = _sealed()
        raw["result"]["boundary"]["human_review"]["required"] = False
        c = check_bundle_data(raw)
        assert not c.ok and any("boundary" in p for p in c.problems)


class TestTheBoundaryOnEverySurface:
    def test_the_cli_prints_separate_headings_after_the_unchanged_not_checked_list(
            self, tmp_path, capsys):
        env, tr = _envelope(), _ssm_trace(3000.0)
        (tmp_path / "e.json").write_text(json.dumps(env.to_dict()))
        (tmp_path / "t.json").write_text(json.dumps(tr.hashable_payload()))
        code = machine_cli(["verify", "--envelope", str(tmp_path / "e.json"), "--trace",
                            str(tmp_path / "t.json"), "--actor", "a.person", "--role", "engineer"])
        out = capsys.readouterr().out
        assert code == 0
        order = [out.index(h) for h in ("  not checked:", "\n  tested:", "\n  not tested:",
                                        "\n  assumptions:", "\n  valid for:",
                                        "\n  qualified human review required:")]
        assert order == sorted(order)

    def test_the_api_returns_it_for_a_cell_account(self, client, store):
        from tests.test_assurance_machine import keyed
        env = _envelope()
        payload = {"envelope": env.to_dict(), "trace": _ssm_trace(3000.0).hashable_payload(),
                   "actor": "v.grimaldi"}
        d = client.post("/v1/machine/verify", json=payload, headers=keyed(store, "cell")).json()
        assert d["result"]["boundary"]["human_review"]["required"] is True
        assert all("boundary" in c for c in d["result"]["checks"])
