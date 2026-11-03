"""Every Article 14 route that takes a legal timestamp refuses a bad one, as a 422, before writing.

Issues #89 and #82. A legal timestamp starts or satisfies a statutory clock, so the API must
never guess (no offset, date only, a JSON number), never overflow (year 9999 / 0001, extreme
offsets) and never write a record whose deadlines cannot then be computed.
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.core import Actor
from assurance.core.identity import format_utc, utc_now
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import Art14Register
from assurance.security.art14.model import CASE_KIND

ACTOR = {"identifier": "m.braun", "role": "Entwicklungsleitung"}
KEY = "test-key-do-not-ship"
AWARE = "2026-09-19T06:30:00Z"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", KEY)
    from assurance.api import deps

    deps._register_for.cache_clear()
    app_module = importlib.import_module("assurance.api.service")
    with TestClient(app_module.create_app()) as client:
        client.headers.update({"X-API-Key": KEY})
        yield client, tmp_path / "art14.db"


def length(client) -> int:
    return client.get("/v1/ledger/verify").json()["attestation"]["length"]


BODIES = {
    "signal": {"received_at": "2026-09-18T21:40:00Z", "channel": "other", "description": "d",
               "actor": ACTOR},
    "awareness": {"established_at": AWARE, "assessment_started_at": "2026-09-18T22:05:00Z",
                  "assessment_completed_at": AWARE, "track": "actively_exploited_vulnerability",
                  "reasoning": "x", "actor": ACTOR},
    "measure": {"available_at": "2026-09-19T10:00:00Z", "description": "m", "actor": ACTOR},
    "filings": {"stage": "early_warning", "submitted_at": "2026-09-19T08:00:00Z", "payload": {},
                "actor": ACTOR},
    "user-notification": {"at": "2026-09-19T08:00:00Z", "scope": "all", "content": "c",
                          "actor": ACTOR},
}

#: (route, field) for every legal timestamp the register takes.
FIELDS = [
    ("signal", "received_at"),
    ("awareness", "established_at"),
    ("awareness", "assessment_started_at"),
    ("awareness", "assessment_completed_at"),
    ("measure", "available_at"),
    ("filings", "submitted_at"),
    ("user-notification", "at"),
]

BAD = {
    "no_offset": "2026-09-19T06:30:00",
    "date_only": "2026-09-19",
    "extreme_offset_plus": "2026-09-19T06:30:00+25:00",
    "extreme_offset_minus_23_59": "2026-09-19T06:30:00-23:59",
    "offset_beyond_any_zone": "2026-09-19T06:30:00+14:30",
    "year_9999": "9999-12-31T23:59:59Z",
    "year_9999_offset": "9999-12-31T23:59:59-23:59",
    "year_0001": "0001-01-01T00:00:00Z",
    "year_0001_offset": "0001-01-01T00:00:00+23:59",
    "json_integer": 1790000000,
    "json_float": 1.79e9,
    "json_bool": True,
    "json_null": None,
    "empty": "",
    "word": "yesterday",
    "bad_month": "2026-13-01T08:00:00Z",
    "bad_day": "2026-02-30T08:00:00Z",
    "leap_second": "2026-09-19T23:59:60Z",
}


def prepare(client, route, case):
    """A case in the state the route needs, built only from good values."""
    assert client.post(f"/v1/cases/{case}/signal", json=BODIES["signal"]).status_code == 201
    if route in ("filings", "measure", "user-notification"):
        assert client.post(f"/v1/cases/{case}/awareness", json=BODIES["awareness"]).status_code == 201


@pytest.mark.parametrize("bad", list(BAD), ids=list(BAD))
@pytest.mark.parametrize("route,field", FIELDS, ids=[f"{r}.{f}" for r, f in FIELDS])
def test_a_bad_legal_timestamp_is_a_422_and_writes_nothing(env, route, field, bad):
    client, _ = env
    case = "T1"
    if route == "signal":
        pass
    else:
        prepare(client, route, case)
    before = length(client)
    body = {**BODIES[route], field: BAD[bad]}
    response = client.post(f"/v1/cases/{case}/{route}", json=body)
    assert response.status_code == 422, (route, field, bad, response.status_code, response.text)
    assert response.json()  # structured, not a bare 500 page
    assert length(client) == before, "a refused request must not append a record"
    if route != "signal":
        # The case is still correctable: nothing half-written blocks the right value.
        assert client.get(f"/v1/cases/{case}").status_code == 200


#: One instant per field, chosen so the domain's own ordering rules hold whatever the notation.
INSTANT = {
    "received_at": (2026, 9, 18, 21, 40),
    "assessment_started_at": (2026, 9, 18, 22, 5),
    "assessment_completed_at": (2026, 9, 19, 6, 30),
    "established_at": (2026, 9, 19, 6, 30),
    "available_at": (2026, 9, 19, 10, 0),
    "submitted_at": (2026, 9, 19, 8, 0),
    "at": (2026, 9, 19, 8, 0),
}
NOTATIONS = [
    lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ"),
    lambda d: (d + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S+02:00"),
    lambda d: d.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
    lambda d: (d - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%S-05:00"),
    lambda d: (d + timedelta(hours=14)).strftime("%Y-%m-%dT%H:%M:%S+14:00"),
]


@pytest.mark.parametrize("notation", range(len(NOTATIONS)))
@pytest.mark.parametrize("route,field", FIELDS, ids=[f"{r}.{f}" for r, f in FIELDS])
def test_a_full_iso_timestamp_with_an_offset_is_still_accepted(env, route, field, notation):
    client, _ = env
    case = "T2"
    if route != "signal":
        prepare(client, route, case)
    instant = datetime(*INSTANT[field], tzinfo=UTC)
    body = {**BODIES[route], field: NOTATIONS[notation](instant)}
    response = client.post(f"/v1/cases/{case}/{route}", json=body)
    assert response.status_code == 201, (route, field, body[field], response.text)


def test_a_future_dated_filing_is_a_409_case_state_and_writes_nothing(env):
    client, _ = env
    prepare(client, "filings", "T3")
    before = length(client)
    far = format_utc(utc_now().replace(year=utc_now().year + 1))
    response = client.post("/v1/cases/T3/filings", json={**BODIES["filings"], "submitted_at": far})
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "case_state"
    assert "future" in response.json()["detail"]["detail"]
    assert length(client) == before


def test_a_complete_filing_is_201_and_an_empty_one_is_recorded_but_not_on_time(env):
    client, _ = env
    prepare(client, "filings", "T4")
    response = client.post("/v1/cases/T4/filings", json=BODIES["filings"])
    assert response.status_code == 201
    assert response.headers["X-Assurance-Submittable"] == "false"
    deadlines = {d["stage"]: d for d in client.get("/v1/cases/T4").json()["deadlines"]["deadlines"]}
    early = deadlines["early_warning"]
    assert early["status"] == "recorded_incomplete"
    assert early["verified_by_platform"] is False
    assert early["submission_evidence"] == "declared"
    outstanding = client.get("/v1/cases/T4").json()["outstanding"]
    assert any("INCOMPLETE CONTENT" in line for line in outstanding)


# -- a record whose deadlines cannot be computed ----------------------------------------
def test_the_last_computable_century_is_still_accepted(env):
    client, _ = env
    assert client.post("/v1/cases/H1/signal", json=BODIES["signal"]).status_code == 201
    before = length(client)
    body = {**BODIES["awareness"], "established_at": "2099-12-31T23:59:59Z",
            "assessment_completed_at": "2099-12-31T23:59:59Z",
            "assessment_started_at": "2099-12-31T23:00:00Z"}
    # 2099 is in range and its deadlines are computable; year 9999 is refused (see BAD above).
    assert client.post("/v1/cases/H1/awareness", json=body).status_code == 201
    assert length(client) == before + 1


def test_the_domain_itself_refuses_uncomputable_deadlines_before_the_append(tmp_path):
    from datetime import UTC, datetime, timedelta

    from assurance.security.art14 import Awareness, Signal, SignalChannel, Track

    reg = Art14Register(EvidenceLedger(tmp_path / "x.db"))
    far = datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC)
    reg.record_signal("c", Signal(received_at=far - timedelta(hours=2),
                                  channel=SignalChannel.OTHER, received_by="a", description="d"),
                      Actor("a", "r"))
    before = len(reg.ledger)
    with pytest.raises(ValueError, match="cannot be computed"):
        reg.record_awareness(
            "c",
            Awareness(established_at=far, assessment_started_at=far - timedelta(hours=1),
                      assessment_completed_at=far, determined_by="a", reasoning="r"),
            Track.VULNERABILITY, Actor("a", "r"))
    assert len(reg.ledger) == before


# -- one unreadable case must not blind the register ------------------------------------
def poison(path):
    """A legacy awareness record whose deadlines cannot be computed, as an old release wrote it."""
    reg = Art14Register(EvidenceLedger(path))
    reg._append("HZ", CASE_KIND["signal"],
                {"signal": {"received_at": "9999-12-31T20:00:00Z", "channel": "other",
                            "received_by": "a", "description": "d", "product_name": "",
                            "version": "", "reference": ""}},
                Actor("a", "r"))
    reg._append("HZ", CASE_KIND["awareness"],
                {"track": "actively_exploited_vulnerability",
                 "awareness": {"established_at": "9999-12-31T23:59:59Z",
                               "assessment_started_at": "9999-12-31T22:00:00Z",
                               "assessment_completed_at": "9999-12-31T23:59:59Z",
                               "determined_by": "a", "reasoning": "r"}},
                Actor("a", "r"))


def test_one_unreadable_case_is_flagged_and_the_register_still_answers(env):
    client, path = env
    assert client.post("/v1/cases/OK/signal", json=BODIES["signal"]).status_code == 201
    assert client.post("/v1/cases/OK/awareness", json=BODIES["awareness"]).status_code == 201
    poison(path)

    register = client.get("/v1/register")
    assert register.status_code == 200, register.text
    body = register.json()
    assert [c["case_id"] for c in body["cases"]] == ["OK"]
    assert [u["case_id"] for u in body["unreadable_cases"]] == ["HZ"]

    breaches = client.get("/v1/register/breaches")
    assert breaches.status_code == 200, breaches.text
    flagged = [b for b in breaches.json() if b["status"] == "case_unreadable"]
    assert [b["case_id"] for b in flagged] == ["HZ"]
    assert any(b["case_id"] == "OK" for b in breaches.json())  # the readable case still reports

    assert client.get("/v1/cases/OK").status_code == 200
    bad = client.get("/v1/cases/HZ")
    assert bad.status_code == 500
    assert bad.json()["detail"]["error"] == "case_unreadable"
    assert "HZ" in client.get("/v1/cases").json()
