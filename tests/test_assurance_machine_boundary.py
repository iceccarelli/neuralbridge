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
