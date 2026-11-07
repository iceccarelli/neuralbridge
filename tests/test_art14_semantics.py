"""Article 14 semantics found by an independent red team (workstream L).

Each test here fails on the code before the fix:

* awareness, triage, filing and closure are human decisions (an ``automation`` actor is refused);
* a case does not close on a final filing alone;
* a later record cannot declare an EARLIER filing time for a stage (it would rewrite lateness);
* a whitespace payload is not complete;
* the incident one-month clock runs from the EARLIEST notification, complete or not;
* timestamps: offset minutes < 60, and no future / pre-awareness dating of facts.
"""

from __future__ import annotations

import importlib
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.core import Actor
from assurance.core.identity import format_utc, parse_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import (
    Art14Register,
    Awareness,
    CaseError,
    Signal,
    SignalChannel,
    Stage,
    Track,
    validate_payload,
)
from assurance.security.art14.cli import main as cli
from assurance.security.art14.clock import add_one_month
from assurance.security.art14.model import CASE_KIND
from assurance.security.art14.timestamps import legal_timestamp

from .support_sqlite import scalar as sqlite_scalar

PERSON = Actor("m.braun", "Entwicklungsleitung")
BOT = Actor("monitor-1", "watcher", kind="automation")
AWARE = parse_utc("2026-09-19T06:30:00Z")
NOW = parse_utc("2026-10-30T12:00:00Z")
KEY = "test-key-do-not-ship-0123456789abcdef0123456789"

EW = {
    "notification_type": "Vulnerability", "title": "t", "summary": "s",
    "product_name": "SK-4200", "product_version": "FW 2.1", "member_states_available": ["DE"],
    "awareness_datetime": "2026-09-19T06:30:00Z",
}
NOTIF = {"vulnerability_general_information": "Command injection in the service port"}
FINAL = {
    "measures_taken": "m", "measures_users_can_take": "u",
    "measure_available_date": "2026-09-19T11:30:00Z", "security_update_details": "d",
    "vulnerability_severity": "High", "vulnerability_impact": "RCE",
}
YES = {
    "is_our_product_with_digital_elements_on_the_eu_market": "yes",
    "reliable_evidence_of_malicious_exploitation": "yes",
    "exploited_in_our_product_not_merely_in_a_component": "yes",
    "awareness_of_active_exploitation_on_or_after_2026_09_11": "yes",
}


def make(tmp_path, track=Track.VULNERABILITY, name="l.db"):
    reg = Art14Register(EvidenceLedger(tmp_path / name))
    reg.record_signal(
        "c1", Signal(received_at=AWARE - timedelta(hours=1), channel=SignalChannel.OTHER,
                     received_by="m.braun", description="d"), BOT)  # a signal MAY come from software
    reg.record_awareness(
        "c1", Awareness(established_at=AWARE, assessment_started_at=AWARE - timedelta(minutes=30),
                        assessment_completed_at=AWARE, determined_by="m.braun", reasoning="r"),
        track, PERSON, now=NOW)
    return reg


def dl(reg, stage):
    return {d["stage"]: d for d in reg.case("c1").to_dict()["deadlines"]["deadlines"]}[stage]


# -- 1: human decisions, and closure -------------------------------------------------------
class TestHumanDecisions:
    def test_signal_may_be_recorded_by_automation(self, tmp_path):
        make(tmp_path)  # make() records the signal as BOT

    def test_awareness_by_automation_is_refused_and_writes_nothing(self, tmp_path):
        reg = Art14Register(EvidenceLedger(tmp_path / "a.db"))
        reg.record_signal("c1", Signal(received_at=AWARE - timedelta(hours=1),
                                       channel=SignalChannel.OTHER, received_by="x",
                                       description="d"), BOT)
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_awareness(
                "c1", Awareness(established_at=AWARE, assessment_started_at=AWARE,
                                assessment_completed_at=AWARE, determined_by="x", reasoning="r"),
                Track.VULNERABILITY, BOT, now=NOW)
        assert len(reg.ledger) == before

    @pytest.mark.parametrize("kind", ["automation", "service"])
    def test_triage_and_filing_by_non_person_are_refused(self, tmp_path, kind):
        reg = make(tmp_path)
        actor = Actor("svc", "r", kind=kind)
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_triage("c1", YES, actor)
        with pytest.raises(CaseError, match="human decision"):
            reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), EW, actor,
                              now=NOW)
        assert len(reg.ledger) == before

    def test_a_final_filing_alone_does_not_close_the_case(self, tmp_path):
        reg = make(tmp_path)
        reg.record_triage("c1", YES, PERSON)
        reg.record_measure_available("c1", AWARE + timedelta(hours=5), "workaround", PERSON, now=NOW)
        reg.record_filing("c1", Stage.FINAL, NOW - timedelta(hours=1), FINAL, PERSON, now=NOW)
        case = reg.case("c1")
        assert case.state == "reportable_open"
        lines = case.outstanding(NOW)
        assert any("NOT CLOSED" in line and "Early warning" in line for line in lines)
        assert any("OVERDUE" in line and "Early warning" in line for line in lines)
        assert any("OVERDUE" in line and "Notification" in line for line in lines)

    def test_all_three_stages_close_the_case(self, tmp_path):
        reg = make(tmp_path)
        reg.record_triage("c1", YES, PERSON)
        reg.record_measure_available("c1", AWARE + timedelta(hours=5), "w", PERSON, now=NOW)
        for stage, payload, at in ((Stage.EARLY_WARNING, EW, 2), (Stage.NOTIFICATION, NOTIF, 3),
                                   (Stage.FINAL, FINAL, 30)):
            reg.record_filing("c1", stage, AWARE + timedelta(hours=at), payload, PERSON, now=NOW)
        assert reg.case("c1").state == "closed_filed"


# -- 1 (API) ------------------------------------------------------------------------------
@pytest.fixture()
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "api.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", KEY)
    from assurance.api import deps

    deps._register_for.cache_clear()
    module = importlib.import_module("assurance.api.service")
    with TestClient(module.create_app()) as client:
        client.headers.update({"X-API-Key": KEY})
        yield client


A = {"identifier": "m.braun", "role": "R"}
B = {"identifier": "bot-1", "role": "auto", "kind": "automation"}


def iso(dt):
    return format_utc(dt)


def api_case(client, case="K1", *, aware=AWARE):
    sig = {"received_at": iso(aware - timedelta(hours=2)), "channel": "other",
           "description": "d", "actor": B}
    assert client.post(f"/v1/cases/{case}/signal", json=sig).status_code == 201
    aw = {"established_at": iso(aware), "assessment_started_at": iso(aware - timedelta(hours=1)),
          "assessment_completed_at": iso(aware), "track": "actively_exploited_vulnerability",
          "reasoning": "x", "actor": A}
    r = client.post(f"/v1/cases/{case}/awareness", json=aw)
    assert r.status_code == 201, r.text


def length(client):
    return client.get("/v1/ledger/verify").json()["attestation"]["length"]


class TestApi:
    def test_automation_cannot_record_awareness_triage_or_filing(self, api):
        sig = {"received_at": "2026-09-19T05:00:00Z", "channel": "other", "description": "d",
               "actor": B}
        assert api.post("/v1/cases/K2/signal", json=sig).status_code == 201
        aw = {"established_at": iso(AWARE), "assessment_started_at": iso(AWARE),
              "assessment_completed_at": iso(AWARE), "track": "actively_exploited_vulnerability",
              "reasoning": "x", "actor": B}
        n = length(api)
        r = api.post("/v1/cases/K2/awareness", json=aw)
        assert r.status_code == 409 and "human decision" in r.text
        assert length(api) == n
        api_case(api)
        n = length(api)
        r = api.post("/v1/cases/K1/triage", json={"answers": YES, "actor": B})
        assert r.status_code == 409 and "human decision" in r.text
        f = {"stage": "early_warning", "submitted_at": iso(AWARE + timedelta(hours=2)),
             "payload": EW, "actor": B}
        r = api.post("/v1/cases/K1/filings", json=f)
        assert r.status_code == 409 and "human decision" in r.text
        assert length(api) == n

    def test_one_automation_final_filing_does_not_close_the_case(self, api):
        api_case(api)
        assert api.post("/v1/cases/K1/triage", json={"answers": YES, "actor": A}).status_code == 201
        m = {"available_at": iso(AWARE + timedelta(hours=5)), "description": "m", "actor": A}
        assert api.post("/v1/cases/K1/measure", json=m).status_code == 201
        f = {"stage": "final", "submitted_at": iso(AWARE + timedelta(days=1)), "payload": FINAL,
             "actor": B}
        assert api.post("/v1/cases/K1/filings", json=f).status_code == 409
        f["actor"] = A
        assert api.post("/v1/cases/K1/filings", json=f).status_code == 201
        body = api.get("/v1/cases/K1").json()
        assert body["state"] == "reportable_open"
        assert any("NOT CLOSED" in line for line in body["outstanding"])

    def test_backdated_duplicate_filing_is_409_and_the_original_stands(self, api):
        api_case(api)
        late = {"stage": "early_warning", "submitted_at": iso(AWARE + timedelta(days=2)),
                "payload": EW, "actor": A}
        assert api.post("/v1/cases/K1/filings", json=late).status_code == 201
        n = length(api)
        early = {**late, "submitted_at": iso(AWARE + timedelta(hours=1))}
        r = api.post("/v1/cases/K1/filings", json=early)
        assert r.status_code == 409
        assert iso(AWARE + timedelta(days=2)) in r.text  # names the recorded time
        assert length(api) == n
        deadlines = api.get("/v1/cases/K1").json()["deadlines"]["deadlines"]
        assert [d["status"] for d in deadlines if d["stage"] == "early_warning"] == ["filed_late"]

    def test_api_rejects_future_and_pre_awareness_facts(self, api):
        api_case(api)
        n = length(api)
        far = format_utc(parse_utc("2099-01-01T00:00:00Z"))
        r = api.post("/v1/cases/K1/measure", json={"available_at": far, "description": "m",
                                                   "actor": A})
        assert r.status_code == 409 and "future" in r.text
        r = api.post("/v1/cases/K1/measure", json={
            "available_at": iso(AWARE - timedelta(days=30)), "description": "m", "actor": A})
        assert r.status_code == 409 and "before awareness" in r.text
        r = api.post("/v1/cases/K1/user-notification",
                     json={"at": far, "scope": "a", "content": "c", "actor": A})
        assert r.status_code == 409 and "future" in r.text
        assert length(api) == n

    def test_future_awareness_is_409(self, api):
        sig = {"received_at": "2099-01-01T00:00:00Z", "channel": "other", "description": "d",
               "actor": A}
        assert api.post("/v1/cases/K3/signal", json=sig).status_code == 201
        aw = {"established_at": "2099-01-01T01:00:00Z",
              "assessment_started_at": "2099-01-01T00:30:00Z",
              "assessment_completed_at": "2099-01-01T01:00:00Z",
              "track": "actively_exploited_vulnerability", "reasoning": "x", "actor": A}
        r = api.post("/v1/cases/K3/awareness", json=aw)
        assert r.status_code == 409 and "future" in r.text


class TestCli:
    def test_cli_final_alone_leaves_the_case_open(self, tmp_path, capsys):
        led = str(tmp_path / "c.db")
        by = ["--by", "m.braun:R"]
        assert cli(["--ledger", led, "signal", "C1", *by, "--at", iso(AWARE - timedelta(hours=1)),
                    "--description", "d"]) == 0
        assert cli(["--ledger", led, "awareness", "C1", *by, "--at", iso(AWARE),
                    "--started", iso(AWARE), "--completed", iso(AWARE),
                    "--track", "actively_exploited_vulnerability", "--because", "r"]) == 0
        answers = [x for k, v in YES.items() for x in ("--answer", f"{k}={v}")]
        assert cli(["--ledger", led, "triage", "C1", *by, *answers]) == 0
        assert cli(["--ledger", led, "measure", "C1", *by, "--at", iso(AWARE + timedelta(hours=5)),
                    "--description", "w"]) == 0
        payload = tmp_path / "final.json"
        payload.write_text(json.dumps(FINAL))
        assert cli(["--ledger", led, "file", "C1", *by, "--stage", "final", "--at",
                    iso(AWARE + timedelta(days=1)), "--payload", str(payload)]) == 0
        capsys.readouterr()
        assert cli(["--ledger", led, "case", "C1", "--json"]) == 0
        body = json.loads(capsys.readouterr().out)
        assert body["state"] == "reportable_open"
        assert any("NOT CLOSED" in line for line in body["outstanding"])

    def test_cli_backdated_duplicate_is_exit_2_and_writes_nothing(self, tmp_path, capsys):
        led = str(tmp_path / "c.db")
        by = ["--by", "m.braun:R"]
        cli(["--ledger", led, "signal", "C1", *by, "--at", iso(AWARE - timedelta(hours=1)),
             "--description", "d"])
        cli(["--ledger", led, "awareness", "C1", *by, "--at", iso(AWARE), "--started", iso(AWARE),
             "--completed", iso(AWARE), "--track", "actively_exploited_vulnerability",
             "--because", "r"])
        payload = tmp_path / "ew.json"
        payload.write_text(json.dumps(EW))
        base = ["--ledger", led, "file", "C1", *by, "--stage", "early_warning",
                "--payload", str(payload)]
        assert cli([*base, "--at", iso(AWARE + timedelta(days=2))]) == 0
        capsys.readouterr()
        count = lambda: sqlite_scalar(led, "SELECT COUNT(*) FROM chain")  # noqa: E731
        n = count()
        assert cli([*base, "--at", iso(AWARE + timedelta(hours=1))]) == 2
        assert "EARLIER" in capsys.readouterr().err
        assert count() == n
        # the same time again is an idempotent duplicate and is accepted
        assert cli([*base, "--at", iso(AWARE + timedelta(days=2))]) == 0


# -- 2: filing time cannot move earlier ------------------------------------------------------
class TestBackdatedDuplicate:
    def test_domain_refuses_an_earlier_time_names_the_recorded_one(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(days=2), EW, PERSON, now=NOW)
        assert dl(reg, "early_warning")["status"] == "filed_late"
        n = len(reg.ledger)
        with pytest.raises(CaseError, match="EARLIER") as exc:
            reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=1), EW, PERSON,
                              now=NOW)
        assert format_utc(AWARE + timedelta(days=2)) in str(exc.value)
        assert len(reg.ledger) == n
        assert dl(reg, "early_warning")["status"] == "filed_late"

    def test_same_time_is_idempotent_and_later_time_is_accepted(self, tmp_path):
        reg = make(tmp_path)
        t = AWARE + timedelta(hours=2)
        reg.record_filing("c1", Stage.EARLY_WARNING, t, EW, PERSON, now=NOW)
        reg.record_filing("c1", Stage.EARLY_WARNING, t, EW, PERSON, now=NOW)
        reg.record_filing("c1", Stage.EARLY_WARNING, t + timedelta(hours=1), EW, PERSON, now=NOW)
        assert dl(reg, "early_warning")["status"] == "filed_on_time"

    def test_an_earlier_incomplete_record_cannot_precede_a_complete_one_either(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(days=2), EW, PERSON, now=NOW)
        with pytest.raises(CaseError, match="EARLIER"):
            reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=1), {}, PERSON,
                              now=NOW)

    def test_a_legacy_ledger_with_two_times_surfaces_the_conflict(self, tmp_path):
        """Written before the refusal existed: earliest wins in the fold, loudly."""
        reg = make(tmp_path)
        for at in (AWARE + timedelta(days=2), AWARE + timedelta(hours=1)):
            reg._append("c1", CASE_KIND["filing"], {
                "stage": "early_warning", "submitted_at": format_utc(at),
                "platform_reference": "", "payload": EW,
                "validation": {"submittable": True}}, PERSON)
        d = reg.case("c1").to_dict()
        assert d["deadlines"]["conflicting_filing_times"] == {
            "early_warning": [format_utc(AWARE + timedelta(hours=1)),
                              format_utc(AWARE + timedelta(days=2))]}
        assert any(line.startswith("CONFLICTING FILING TIMES for early_warning")
                   for line in d["outstanding"])

    def test_a_non_person_record_in_a_legacy_ledger_is_flagged(self, tmp_path):
        reg = make(tmp_path)
        reg._append("c1", CASE_KIND["filing"], {
            "stage": "early_warning", "submitted_at": format_utc(AWARE + timedelta(hours=1)),
            "platform_reference": "", "payload": EW, "validation": {"submittable": True}}, BOT)
        assert any("kind 'automation'" in line for line in reg.case("c1").outstanding(NOW))


# -- 3: whitespace and empty containers are not content ---------------------------------------
class TestEmptyPayloads:
    @pytest.mark.parametrize("empty", [" ", "\t\n", "   ", [], [" "], {}, {"a": ""}, [[], ""],
                                       (" ",), None, ""])
    def test_an_empty_value_does_not_satisfy_a_required_field(self, empty):
        payload = {**EW, "title": empty, "summary": empty}
        v = validate_payload(payload, Track.VULNERABILITY, Stage.EARLY_WARNING)
        assert not v.submittable
        assert {i.field_name for i in v.blocking} >= {"title", "summary"}

    def test_whitespace_for_every_required_field_is_not_submittable(self):
        payload = dict.fromkeys(EW, " ")
        payload["member_states_available"] = [" "]
        assert not validate_payload(payload, Track.VULNERABILITY, Stage.EARLY_WARNING).submittable

    def test_real_content_still_passes_including_zero_and_false(self):
        assert validate_payload(EW, Track.VULNERABILITY, Stage.EARLY_WARNING).submittable
        padded = {**EW, "title": "  t  "}
        assert validate_payload(padded, Track.VULNERABILITY, Stage.EARLY_WARNING).submittable
        assert validate_payload({**EW, "title": 0}, Track.VULNERABILITY,
                                Stage.EARLY_WARNING).submittable
        assert validate_payload({**EW, "title": False}, Track.VULNERABILITY,
                                Stage.EARLY_WARNING).submittable

    def test_a_whitespace_filing_reads_recorded_incomplete(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2),
                          dict.fromkeys(EW, " "), PERSON, now=NOW)
        assert dl(reg, "early_warning")["status"] == "recorded_incomplete"


# -- 4: the incident final-report clock runs from the earliest notification ------------------
class TestIncidentFinalClock:
    def test_a_later_complete_notification_does_not_move_the_final_deadline_later(self, tmp_path):
        reg = make(tmp_path, Track.INCIDENT)
        first = AWARE + timedelta(hours=60)
        reg.record_filing("c1", Stage.NOTIFICATION, first, {}, PERSON, now=NOW)
        due = dl(reg, "final")["due_at"]
        assert due == format_utc(add_one_month(first))
        inc_notification = {f.name: "x" for f in __import__(
            "assurance.security.art14.srp", fromlist=["fields_for"]).fields_for(
                Track.INCIDENT, Stage.NOTIFICATION) if f.requirement_at(
                    Stage.NOTIFICATION).must_be_present}
        inc_notification["member_states_available"] = ["DE"]
        reg.record_filing("c1", Stage.NOTIFICATION, NOW - timedelta(minutes=5), inc_notification,
                          PERSON, now=NOW)
        assert dl(reg, "notification")["status"] == "filed_late"
        assert dl(reg, "final")["due_at"] == due
        assert dl(reg, "final")["runs_from"] == format_utc(first)
        # and both notification times are surfaced
        assert "notification" in reg.case("c1").to_dict()["deadlines"]["conflicting_filing_times"]


# -- 6: timestamps ---------------------------------------------------------------------------
class TestTimestamps:
    @pytest.mark.parametrize("bad", ["+00:99", "+12:99", "-05:60", "+0160", "+01:60", "-12:75"])
    def test_offset_minutes_must_be_below_60(self, bad):
        with pytest.raises(ValueError, match="minutes"):
            legal_timestamp(f"2026-09-19T06:30:00{bad}", "f")

    @pytest.mark.parametrize("ok", ["+00:59", "+05:30", "-09:30", "+14:00", "Z", "+0530"])
    def test_valid_offsets_still_parse(self, ok):
        legal_timestamp(f"2026-09-19T06:30:00{ok}", "f")

    def test_api_returns_422_for_a_99_minute_offset(self, api):
        sig = {"received_at": "2026-09-19T05:00:00+00:99", "channel": "other",
               "description": "d", "actor": A}
        assert api.post("/v1/cases/Z1/signal", json=sig).status_code == 422


class TestFutureAndOrdering:
    def test_assessment_times_cannot_be_in_the_future(self, tmp_path):
        reg = Art14Register(EvidenceLedger(tmp_path / "x.db"))
        reg.record_signal("c1", Signal(received_at=AWARE, channel=SignalChannel.OTHER,
                                       received_by="a", description="d"), PERSON)
        n = len(reg.ledger)
        with pytest.raises(CaseError, match="future"):
            reg.record_awareness("c1", Awareness(
                established_at=AWARE + timedelta(hours=1),
                assessment_started_at=AWARE + timedelta(minutes=30),
                assessment_completed_at=AWARE + timedelta(hours=1), determined_by="a",
                reasoning="r"), Track.VULNERABILITY, PERSON, now=AWARE)
        assert len(reg.ledger) == n

    def test_measure_and_user_notification_domain_checks(self, tmp_path):
        reg = make(tmp_path)
        with pytest.raises(CaseError, match="future"):
            reg.record_measure_available("c1", NOW + timedelta(days=2), "m", PERSON, now=NOW)
        with pytest.raises(CaseError, match="before awareness"):
            reg.record_measure_available("c1", AWARE - timedelta(days=3), "m", PERSON, now=NOW)
        with pytest.raises(CaseError, match="future"):
            reg.record_user_notification("c1", NOW + timedelta(days=2), "s", "c", PERSON, now=NOW)
        reg.record_measure_available("c1", AWARE, "at awareness is fine", PERSON, now=NOW)

    def test_awareness_message_names_only_a_supersession_that_exists(self, tmp_path):
        reg = make(tmp_path)
        with pytest.raises(CaseError) as exc:
            reg.record_awareness("c1", Awareness(
                established_at=AWARE + timedelta(hours=1), assessment_started_at=AWARE,
                assessment_completed_at=AWARE + timedelta(hours=1), determined_by="a",
                reasoning="r"), Track.VULNERABILITY, PERSON, now=NOW)
        # The message may point at a correction only if the CLI verb and the route it names
        # exist (they did not when this guard was written, and it then forbade the promise).
        assert "supersede it explicitly" not in str(exc.value)
        assert "art14 supersede-awareness" in str(exc.value)
        from assurance.api.routes import router
        from assurance.security.art14.cli import build_parser
        assert "supersede-awareness" in build_parser().format_help()
        assert "/v1/cases/{case_id}/awareness/supersede" in {r.path for r in router.routes}
        assert "Nothing was recorded" in str(exc.value)

    def test_parse_helper_agrees_with_engine_iso(self):
        assert parse_utc("2026-09-19T06:30:00Z") == AWARE
