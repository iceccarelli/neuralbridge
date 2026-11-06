"""A human decision is not made by an actor merely *labelled* a person.

The change workflow refuses a decision from an actor whose declared name is what automation
is called (``bot``, ``system``, ``agent``, ``AI`` ... also in look-alike letters), even when its
``kind`` says ``person``. The Article 14 register checked ``kind`` only, and its HTTP body
lets the caller declare the kind (defaulting to ``person``), so software that wrote
``{"identifier": "automation"}`` could record the legal moment of awareness, the
reportability call and a filing. The same rule now holds there: awareness, supersession of
awareness, triage and filing need a named person, by kind AND by name.
"""

from __future__ import annotations

import importlib
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.core import Actor
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import (
    Art14Register,
    Awareness,
    CaseError,
    Signal,
    SignalChannel,
    Stage,
    Track,
)

from .test_art14_semantics import AWARE, EW, KEY, NOW, YES, make

NOT_PEOPLE = ["automation", "bot-7", "System", "AI", "assistant", "agent", "watch",
              "аutomation"]  # the last one opens with a Cyrillic 'а'


@pytest.mark.parametrize("name", NOT_PEOPLE)
class TestDomain:
    def test_awareness_under_a_machine_name_is_refused_and_writes_nothing(self, tmp_path, name):
        reg = Art14Register(EvidenceLedger(tmp_path / "fresh.db"))
        reg.record_signal("c1", Signal(received_at=AWARE - timedelta(hours=1),
                                       channel=SignalChannel.OTHER, received_by="x",
                                       description="d"), Actor("monitor-1", "w", kind="automation"))
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_awareness(
                "c1", Awareness(established_at=AWARE, assessment_started_at=AWARE,
                                assessment_completed_at=AWARE, determined_by=name,
                                reasoning="r"),
                Track.VULNERABILITY, Actor(name, "reviewer", kind="person"), now=NOW)
        assert len(reg.ledger) == before and reg.case("c1").awareness is None

    def test_triage_and_filing_under_a_machine_name_are_refused(self, tmp_path, name):
        reg = make(tmp_path)
        actor = Actor(name, "reviewer", kind="person")
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_triage("c1", YES, actor)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), EW, actor,
                              now=NOW)
        assert len(reg.ledger) == before


def test_a_real_person_whose_name_contains_a_reserved_word_is_still_a_person(tmp_path):
    reg = make(tmp_path)
    reg.record_triage("c1", YES, Actor("Agent Smith", "reviewer", kind="person"))


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "api.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", KEY)
    from assurance.api import deps

    deps._register_for.cache_clear()
    module = importlib.import_module("assurance.api.service")
    with TestClient(module.create_app()) as client:
        client.headers.update({"X-API-Key": KEY})
        yield client


@pytest.mark.parametrize("name", ["automation", "bot-7", "AI"])
def test_the_api_refuses_a_machine_name_declared_as_a_person(api, name):
    iso = "%Y-%m-%dT%H:%M:%SZ"
    sig = {"received_at": (AWARE - timedelta(hours=2)).strftime(iso), "channel": "other",
           "description": "d", "actor": {"identifier": "monitor-1", "kind": "automation"}}
    assert api.post("/v1/cases/K9/signal", json=sig).status_code == 201
    aw = {"established_at": AWARE.strftime(iso), "assessment_started_at": AWARE.strftime(iso),
          "assessment_completed_at": AWARE.strftime(iso),
          "track": "actively_exploited_vulnerability", "reasoning": "x",
          "actor": {"identifier": name, "role": "reviewer"}}          # kind defaults to person
    before = api.get("/v1/ledger/verify").json()["attestation"]["length"]
    response = api.post("/v1/cases/K9/awareness", json=aw)
    assert response.status_code == 409 and "human decision" in response.text
    assert api.get("/v1/ledger/verify").json()["attestation"]["length"] == before
    ok = api.post("/v1/cases/K9/awareness",
                  json={**aw, "actor": {"identifier": "m.braun", "role": "reviewer"}})
    assert ok.status_code == 201
