"""Guards added by the Article 14 basis slice (audit findings F4 and F7).

F4: ``record_measure_available`` starts the 14-day legal clock and ``record_user_notification``
    answers Art. 14(8); both used to accept an ``automation`` actor. Awareness, triage and a
    filing were already refused. Both now need a named person (same grammar as awareness),
    and a legacy / hand-written record of either kind by a non-person is flagged on the case.
    Binding these two HTTP routes to a decider operator's credential is a larger entitlement
    change and is deliberately not made here.
F7: SRP field 5 (see ``tests/test_art14_field5.py`` classes below).
"""

from __future__ import annotations

import importlib
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.core import Actor
from assurance.core.identity import format_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import Art14Register, CaseError
from assurance.security.art14.model import CASE_KIND

from .test_art14_semantics import AWARE, BOT, KEY, NOW, PERSON, make

NOT_PEOPLE = [
    Actor("monitor-1", "watcher", kind="automation"),
    Actor("svc", "r", kind="service"),
    Actor("automation", "reviewer", kind="person"),   # labelled a person, named like software
    Actor("bot-7", "reviewer", kind="person"),
]


class TestMeasureAndUserNoticeNeedAPerson:
    @pytest.mark.parametrize("actor", NOT_PEOPLE, ids=lambda a: f"{a.identifier}/{a.kind}")
    def test_a_measure_by_software_is_refused_and_starts_no_clock(self, tmp_path, actor):
        reg = make(tmp_path)
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_measure_available(
                "c1", AWARE + timedelta(hours=5), "workaround", actor, now=NOW)
        assert len(reg.ledger) == before                      # nothing recorded
        assert reg.case("c1").measure_available_at is None
        assert reg.case("c1").deadlines.final is None          # the 14-day clock did not start

    @pytest.mark.parametrize("actor", NOT_PEOPLE, ids=lambda a: f"{a.identifier}/{a.kind}")
    def test_a_user_notice_by_software_is_refused_and_records_nothing(self, tmp_path, actor):
        reg = make(tmp_path)
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_user_notification(
                "c1", AWARE + timedelta(hours=1), "all users", "text", actor, now=NOW)
        assert len(reg.ledger) == before
        assert reg.case("c1").users_informed_at is None

    def test_the_refusal_comes_before_the_case_is_read(self, tmp_path):
        """A phantom case id and a software actor: the refusal names the actor, not the case."""
        reg = Art14Register(EvidenceLedger(tmp_path / "x.db"))
        with pytest.raises(CaseError, match="human decision"):
            reg.record_measure_available("nope", AWARE, "m", BOT, now=NOW)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_user_notification("nope", AWARE, "s", "c", BOT, now=NOW)

    def test_a_named_person_still_records_both(self, tmp_path):
        reg = make(tmp_path)
        reg.record_measure_available("c1", AWARE + timedelta(hours=5), "workaround", PERSON, now=NOW)
        reg.record_user_notification("c1", AWARE + timedelta(hours=6), "all", "c", PERSON, now=NOW)
        case = reg.case("c1")
        assert case.deadlines.final is not None and case.users_informed_at is not None
        assert case.non_person_records == []

    @pytest.mark.parametrize(
        "kind,body",
        [
            ("art14.measure", {"available_at": format_utc(AWARE + timedelta(hours=5)),
                               "description": "hand-written"}),
            (CASE_KIND["user_notice"], {"at": format_utc(AWARE + timedelta(hours=6)),
                                        "scope": "all", "content": "c", "public_disclosure": False}),
        ],
    )
    def test_a_legacy_non_person_record_is_flagged_on_the_case(self, tmp_path, kind, body):
        """Written before the refusal existed (or by hand): shown, never trusted silently."""
        reg = make(tmp_path)
        reg._append("c1", kind, body, BOT)
        case = reg.case("c1")
        assert any(f"({kind})" in n and "kind 'automation'" in n for n in case.non_person_records)
        assert any("kind 'automation'" in line and "a person must confirm" in line
                   for line in case.outstanding(NOW))

    def test_a_person_record_of_either_kind_is_not_flagged(self, tmp_path):
        reg = make(tmp_path)
        reg._append("c1", "art14.measure", {"available_at": format_utc(AWARE + timedelta(hours=5)),
                                            "description": "m"}, PERSON)
        assert reg.case("c1").non_person_records == []


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
    deps._register_for.cache_clear()


class TestOverHttp:
    """The same refusal on the HTTP binding (a 409 naming the human decision), nothing written."""

    def _open(self, api):
        sig = api.post("/v1/cases/c1/signal", json={
            "received_at": "2026-09-19T05:30:00Z", "channel": "other", "received_by": "x",
            "description": "d", "actor": {"identifier": "monitor", "kind": "automation"}})
        assert sig.status_code == 201, sig.text
        aw = api.post("/v1/cases/c1/awareness", json={
            "track": "actively_exploited_vulnerability",
            "established_at": "2026-09-19T06:30:00Z",
            "assessment_started_at": "2026-09-19T06:00:00Z",
            "assessment_completed_at": "2026-09-19T06:30:00Z",
            "reasoning": "judged", "actor": {"identifier": "Maria Rossi"}})
        assert aw.status_code == 201, aw.text

    def test_measure_and_user_notification_by_automation_are_409(self, api):
        self._open(api)
        m = api.post("/v1/cases/c1/measure", json={
            "available_at": "2026-09-19T08:00:00Z", "description": "w",
            "actor": {"identifier": "monitor", "kind": "automation"}})
        assert m.status_code == 409 and "human decision" in m.text, m.text
        u = api.post("/v1/cases/c1/user-notification", json={
            "at": "2026-09-19T08:00:00Z", "scope": "all", "content": "c",
            "actor": {"identifier": "monitor", "kind": "automation"}})
        assert u.status_code == 409 and "human decision" in u.text, u.text
        case = api.get("/v1/cases/c1").json()
        assert case["users_informed_at"] is None
        assert [d["stage"] for d in case["deadlines"]["deadlines"]] == [
            "early_warning", "notification"]                 # no final: the clock did not start

    def test_a_person_over_http_still_records_both(self, api):
        self._open(api)
        m = api.post("/v1/cases/c1/measure", json={
            "available_at": "2026-09-19T08:00:00Z", "description": "w",
            "actor": {"identifier": "Maria Rossi"}})
        assert m.status_code == 201, m.text
        u = api.post("/v1/cases/c1/user-notification", json={
            "at": "2026-09-19T08:00:00Z", "scope": "all", "content": "c",
            "actor": {"identifier": "Maria Rossi"}})
        assert u.status_code == 201, u.text
