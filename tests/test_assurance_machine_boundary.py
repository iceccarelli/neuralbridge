"""Where the machine engine's answers stop: strict inputs, stated limits, reference cases.

This file grows with the work on the machine boundary. Each section says which finding it
pins; the reference cases at the end state their expected outcome in the fixture itself
(``tests/fixtures/machine_boundary/``) so that a future change to a verdict is a conscious one.
"""

from __future__ import annotations

import json

import pytest

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
