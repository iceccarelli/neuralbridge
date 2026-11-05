"""Append-only correction of a wrongly recorded awareness, and the lifecycle defects found driving it.

PR #106 left no way to correct an awareness recorded wrongly. The correction here is a NEW record
that supersedes the one in force. These tests pin what makes that safe:

* the original is never edited or deleted and stays in the chain and the audit history;
* a named person and a reason are mandatory, and the superseded record is named;
* the clocks run from the awareness in force and every moved deadline is listed with who/why;
* a deadline already missed cannot be moved later without staying a reported breach;
* a closed case and a case with a filing refuse supersession; the track cannot be changed;
* defects found on the way: phantom cases from availability / user notices, a mistyped triage
  question read as "undetermined" without a word, a not-reportable case listed as in breach,
  a misleading 14-day message on the incident track.
"""

from __future__ import annotations

import importlib
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from assurance.core import Actor
from assurance.core.errors import EvidenceIncompleteError
from assurance.core.identity import parse_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import (
    Art14Register,
    Awareness,
    CaseError,
    ProductVersion,
    Signal,
    SignalChannel,
    Stage,
    Track,
)
from assurance.security.art14.cli import main as cli
from assurance.security.art14.model import CASE_KIND

PERSON = Actor("m.braun", "Entwicklungsleitung")
OTHER = Actor("a.schmidt", "CISO")
BOT = Actor("monitor-1", "watcher", kind="automation")
SIGNAL_AT = parse_utc("2026-09-18T18:30:00Z")
AWARE = parse_utc("2026-09-19T06:30:00Z")
NOW = parse_utc("2026-10-30T12:00:00Z")
KEY = "test-key-do-not-ship-0123456789abcdef0123456789"

YES = {
    "is_our_product_with_digital_elements_on_the_eu_market": "yes",
    "reliable_evidence_of_malicious_exploitation": "yes",
    "exploited_in_our_product_not_merely_in_a_component": "yes",
    "awareness_of_active_exploitation_on_or_after_2026_09_11": "yes",
}


def aware(at=AWARE, reasoning="r"):
    return Awareness(established_at=at, assessment_started_at=at - timedelta(minutes=30),
                     assessment_completed_at=at, determined_by="m.braun", reasoning=reasoning)


def make(tmp_path, track=Track.VULNERABILITY, name="s.db"):
    reg = Art14Register(EvidenceLedger(tmp_path / name))
    reg.record_signal("c1", Signal(received_at=SIGNAL_AT, channel=SignalChannel.OTHER,
                                   received_by="m.braun", description="d"), BOT)
    reg.record_awareness("c1", aware(), track, PERSON, now=NOW)
    return reg


def supersede(reg, at, reason="entered the wrong day", actor=PERSON, ref=None, **kw):
    ref = ref or reg.case("c1").awareness_hash
    return reg.supersede_awareness("c1", aware(at), reason, ref, actor, now=NOW, **kw)


def due(reg, stage):
    return {d["stage"]: d for d in reg.case("c1").to_dict()["deadlines"]["deadlines"]}[stage]


# -- append-only ---------------------------------------------------------------------------
class TestAppendOnly:
    def test_original_stays_in_chain_and_history_and_clocks_follow_the_new_one(self, tmp_path):
        reg = make(tmp_path)
        first = reg.case("c1").awareness_hash
        n = len(reg.ledger)
        later = AWARE - timedelta(hours=3)
        supersede(reg, later)
        assert len(reg.ledger) == n + 1  # appended, nothing replaced
        kinds = [e.kind for e in reg.ledger.entries(subject="c1")]
        assert kinds.count(CASE_KIND["awareness"]) == 1
        assert kinds.count(CASE_KIND["awareness_supersession"]) == 1
        assert reg.ledger.verify_chain()[0]
        case = reg.case("c1")
        assert case.awareness.established_at == later
        statuses = [(h["content_hash"] == first, h["status"]) for h in case.awareness_history]
        assert statuses == [(True, "superseded"), (False, "in_force")]
        assert due(reg, "early_warning")["due_at"] == "2026-09-20T03:30:00Z"
        assert any("SUPERSEDED" in h["summary"] and "entered the wrong day" in h["summary"]
                   for h in case.history)
        assert any(h["summary"].startswith("awareness established") for h in case.history)

    def test_person_reason_and_target_are_mandatory(self, tmp_path):
        reg = make(tmp_path)
        n = len(reg.ledger)
        with pytest.raises(CaseError, match="human decision"):
            supersede(reg, AWARE + timedelta(hours=1), actor=BOT)
        with pytest.raises(EvidenceIncompleteError, match="reason"):
            supersede(reg, AWARE + timedelta(hours=1), reason="   ")
        with pytest.raises(CaseError, match="currently in force"):
            supersede(reg, AWARE + timedelta(hours=1), ref="deadbeef" * 8)
        with pytest.raises(CaseError, match="currently in force"):
            supersede(reg, AWARE + timedelta(hours=1), ref=reg.case("c1").awareness_hash[:8])
        assert len(reg.ledger) == n  # every refusal wrote nothing

    def test_a_second_supersession_must_name_the_first_not_the_original(self, tmp_path):
        reg = make(tmp_path)
        original = reg.case("c1").awareness_hash
        supersede(reg, AWARE - timedelta(hours=1))
        with pytest.raises(CaseError, match="currently in force"):
            supersede(reg, AWARE - timedelta(hours=2), ref=original)
        supersede(reg, AWARE - timedelta(hours=2))
        assert [h["status"] for h in reg.case("c1").awareness_history] == [
            "superseded", "superseded", "in_force"]

    def test_plain_awareness_still_refuses_to_replace(self, tmp_path):
        reg = make(tmp_path)
        with pytest.raises(CaseError, match="already has an awareness record"):
            reg.record_awareness("c1", aware(AWARE + timedelta(hours=1)), Track.VULNERABILITY,
                                 PERSON, now=NOW)


# -- deadlines are never moved silently -----------------------------------------------------
class TestShifts:
    def test_every_moved_deadline_names_who_why_from_and_to(self, tmp_path):
        reg = make(tmp_path)
        supersede(reg, AWARE + timedelta(hours=2), actor=OTHER, reason="CVD mail was a duplicate")
        shifts = reg.case("c1").deadline_shifts
        assert {s["stage"] for s in shifts} == {"early_warning", "notification"}
        s = shifts[0]
        assert (s["from_due_at"], s["to_due_at"]) == ("2026-09-20T06:30:00Z", "2026-09-20T08:30:00Z")
        assert "a.schmidt" in s["by"] and s["reason"] == "CVD mail was a duplicate"
        text = " ".join(reg.case("c1").outstanding(NOW))
        assert "DEADLINE" in text and "from 2026-09-20T06:30:00Z to 2026-09-20T08:30:00Z" in text
        assert "by a.schmidt (CISO), reason: CVD mail was a duplicate" in text
        assert "do not provide for correcting" in text  # the regulation's silence is said

    def test_pushing_awareness_later_past_a_missed_24h_is_flagged_and_stays_a_breach(self, tmp_path):
        reg = make(tmp_path)  # NOW is 40 days past the 24 h deadline, nothing filed
        supersede(reg, NOW - timedelta(hours=1), reason="hide it")  # would look 'on time'
        case = reg.case("c1")
        assert all(s["moved_later"] and s["original_already_passed"] for s in case.deadline_shifts)
        assert "MOVED LATER AFTER THE ORIGINAL HAD ALREADY PASSED" in " ".join(case.outstanding(NOW))
        flagged = [b for b in reg.breaches(NOW)
                   if b["status"] == "deadline_moved_later_after_original_passed"]
        assert {b["stage"] for b in flagged} == {"early_warning", "notification"}
        assert flagged[0]["original_due_at"] == "2026-09-20T06:30:00Z"
        assert "m.braun" in flagged[0]["moved_by"] and flagged[0]["reason"] == "hide it"

    def test_moving_earlier_is_listed_but_is_not_a_breach(self, tmp_path):
        reg = make(tmp_path)
        supersede(reg, AWARE - timedelta(hours=2))
        shifts = reg.case("c1").deadline_shifts
        assert shifts and all(not s["moved_later"] for s in shifts)
        assert "DEADLINE RECOMPUTED" in " ".join(reg.case("c1").outstanding(NOW))
        assert not [b for b in reg.breaches(NOW)
                    if b["status"] == "deadline_moved_later_after_original_passed"]

    def test_same_moment_with_a_new_reason_moves_nothing_and_says_so(self, tmp_path):
        reg = make(tmp_path)
        supersede(reg, AWARE, reason="reasoning clarified")
        case = reg.case("c1")
        assert case.deadline_shifts == []
        assert "no awareness-derived deadline moved" in " ".join(case.outstanding(NOW))


# -- refusals -------------------------------------------------------------------------------
class TestRefusals:
    def test_a_filed_case_refuses_and_says_the_regulation_gives_no_rule(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), {"title": "t"},
                          PERSON, now=NOW)
        n = len(reg.ledger)
        with pytest.raises(CaseError, match="does not provide a correction after filing"):
            supersede(reg, AWARE + timedelta(hours=1))
        assert len(reg.ledger) == n

    def test_a_closed_case_refuses(self, tmp_path):
        reg = make(tmp_path)
        reg.record_triage("c1", {"is_our_product_with_digital_elements_on_the_eu_market": "yes",
                                 "reliable_evidence_of_malicious_exploitation": "no"},
                          PERSON, "r", reopen_trigger="new evidence")
        assert reg.case("c1").state == "closed_not_reportable"
        with pytest.raises(CaseError, match="closed"):
            supersede(reg, AWARE + timedelta(hours=1))

    def test_no_awareness_signal_or_case_refuses(self, tmp_path):
        reg = Art14Register(EvidenceLedger(tmp_path / "n.db"))
        with pytest.raises(CaseError, match="no awareness record to supersede"):
            reg.supersede_awareness("nope", aware(), "r", "a" * 16, PERSON, now=NOW)

    def test_new_awareness_obeys_the_same_ordering_rules_as_the_first(self, tmp_path):
        reg = make(tmp_path)
        with pytest.raises(CaseError, match="precede the signal"):
            supersede(reg, SIGNAL_AT - timedelta(hours=1))
        with pytest.raises(CaseError, match="future"):
            supersede(reg, NOW + timedelta(days=2))
        with pytest.raises(EvidenceIncompleteError, match="reasoning"):
            reg.supersede_awareness("c1", aware(reasoning=" "), "why",
                                    reg.case("c1").awareness_hash, PERSON, now=NOW)
        reg.record_measure_available("c1", AWARE + timedelta(hours=1), "m", PERSON, now=NOW)
        with pytest.raises(CaseError, match="measure was recorded as available"):
            supersede(reg, AWARE + timedelta(hours=2))
        reg.record_user_notification("c1", AWARE + timedelta(hours=1), "all", "c", PERSON, now=NOW)
        with pytest.raises(CaseError, match="informed"):
            supersede(reg, AWARE + timedelta(hours=1, minutes=30))

    def test_a_forged_supersession_naming_a_stale_record_is_surfaced(self, tmp_path):
        reg = make(tmp_path)
        original = reg.case("c1").awareness_hash
        supersede(reg, AWARE - timedelta(hours=1))
        # a writer that bypasses the engine and names the original again
        reg._append("c1", CASE_KIND["awareness_supersession"],
                    {"track": "actively_exploited_vulnerability", "supersedes": original,
                     "reason": "x", "awareness": aware(AWARE - timedelta(hours=2)).to_dict(),
                     "previous_awareness": aware().to_dict()}, PERSON)
        assert any("ANOMALY" in o for o in reg.case("c1").outstanding(NOW))

    def test_a_software_written_supersession_is_listed_for_confirmation(self, tmp_path):
        reg = make(tmp_path)
        reg._append("c1", CASE_KIND["awareness_supersession"],
                    {"track": "actively_exploited_vulnerability",
                     "supersedes": reg.case("c1").awareness_hash, "reason": "x",
                     "awareness": aware(AWARE - timedelta(hours=1)).to_dict(),
                     "previous_awareness": aware().to_dict()}, BOT)
        assert any("a person must confirm" in o for o in reg.case("c1").outstanding(NOW))


# -- lifecycle defects found end to end --------------------------------------------------------
class TestLifecycleDefects:
    def test_availability_and_user_notice_cannot_open_a_phantom_case(self, tmp_path):
        reg = Art14Register(EvidenceLedger(tmp_path / "p.db"))
        with pytest.raises(CaseError, match="no signal"):
            reg.record_availability("TYPO-1", ProductVersion("P", "1", ("DE",), evidence_source="s"),
                                    PERSON)
        with pytest.raises(CaseError, match="no signal"):
            reg.record_user_notification("TYPO-2", AWARE, "all", "c", PERSON, now=NOW)
        assert reg.case_ids() == [] and len(reg.ledger) == 0

    def test_a_misspelt_triage_question_is_refused_not_read_as_undetermined(self, tmp_path):
        reg = make(tmp_path)
        n = len(reg.ledger)
        with pytest.raises(ValueError, match="unknown triage question"):
            reg.record_triage("c1", {"reliable_evidence": "yes"}, PERSON, "r")
        assert len(reg.ledger) == n
        reg.record_triage("c1", YES, PERSON, "r")

    def test_a_case_closed_as_not_reportable_is_not_listed_as_in_breach(self, tmp_path):
        reg = make(tmp_path)
        reg.record_triage("c1", {"is_our_product_with_digital_elements_on_the_eu_market": "yes",
                                 "reliable_evidence_of_malicious_exploitation": "no"},
                          PERSON, "r", reopen_trigger="new evidence")
        assert [b for b in reg.breaches(NOW) if b["case_id"] == "c1"] == []

    def test_an_open_case_past_due_is_still_a_breach(self, tmp_path):
        reg = make(tmp_path)
        reg.record_triage("c1", YES, PERSON, "r")
        assert {b["stage"] for b in reg.breaches(NOW)} >= {"early_warning", "notification"}


# -- CLI and API ----------------------------------------------------------------------------
BY = ["--by", "m.braun:eng"]


def _cli(tmp_path, *argv):
    return cli(["--ledger", str(tmp_path / "c.db"), *argv])


def _setup_cli(tmp_path, track="actively_exploited_vulnerability"):
    assert _cli(tmp_path, "signal", "C1", *BY, "--description", "d",
                "--at", "2026-09-19T05:00:00Z") == 0
    assert _cli(tmp_path, "awareness", "C1", *BY, "--at", "2026-09-19T06:30:00Z",
                "--started", "2026-09-19T06:00:00Z", "--completed", "2026-09-19T06:30:00Z",
                "--track", track, "--because", "evidence") == 0
    reg = Art14Register(EvidenceLedger.open_existing(tmp_path / "c.db"))
    return reg.case("C1").awareness_hash


class TestCli:
    def test_supersede_prints_the_move_the_silence_and_keeps_the_original(self, tmp_path, capsys):
        h = _setup_cli(tmp_path)
        capsys.readouterr()
        rc = _cli(tmp_path, "supersede-awareness", "C1", *BY, "--supersedes", h[:16],
                  "--at", "2026-09-19T08:30:00Z", "--started", "2026-09-19T08:00:00Z",
                  "--completed", "2026-09-19T08:30:00Z", "--because", "fixed", "--reason",
                  "wrong mailbox")
        out = capsys.readouterr().out
        assert rc == 0
        assert "deadline recomputed: Early warning (24 h) from 2026-09-20T06:30:00Z to " \
               "2026-09-20T08:30:00Z by m.braun (eng), reason: wrong mailbox" in out
        assert "do not provide for correcting" in out and "nothing was edited or deleted" in out
        assert "WARNING" in out  # the original deadline had long passed
        assert _cli(tmp_path, "case", "C1") == 0
        shown = capsys.readouterr().out
        assert "AWARENESS HISTORY" in shown and "SUPERSEDED" in shown and "IN FORCE" in shown
        assert "AUDIT HISTORY" in shown
        assert _cli(tmp_path, "verify") == 0

    def test_supersede_requires_reason_and_a_correct_target(self, tmp_path, capsys):
        h = _setup_cli(tmp_path)
        base = ["supersede-awareness", "C1", *BY, "--at", "2026-09-19T08:30:00Z",
                "--started", "2026-09-19T08:00:00Z", "--completed", "2026-09-19T08:30:00Z",
                "--because", "fixed"]
        with pytest.raises(SystemExit):
            _cli(tmp_path, *base, "--supersedes", h)  # no --reason
        assert _cli(tmp_path, *base, "--supersedes", "f" * 16, "--reason", "r") == 2
        assert "currently in force" in capsys.readouterr().err
        assert _cli(tmp_path, *base, "--supersedes", h, "--reason", "  ") == 2

    def test_measure_on_the_incident_track_does_not_claim_a_14_day_clock(self, tmp_path, capsys):
        _setup_cli(tmp_path, track="severe_incident")
        capsys.readouterr()
        assert _cli(tmp_path, "measure", "C1", *BY, "--at", "2026-09-19T09:00:00Z",
                    "--description", "workaround") == 0
        out = capsys.readouterr().out
        assert "14-day" not in out and "does not start a clock on the incident track" in out

    def test_case_json_carries_the_history(self, tmp_path, capsys):
        _setup_cli(tmp_path)
        capsys.readouterr()
        assert _cli(tmp_path, "case", "C1", "--json") == 0
        data = json.loads(capsys.readouterr().out)
        assert [h["kind"] for h in data["history"]] == ["art14.signal", "art14.awareness"]
        assert data["awareness_record"] == data["awareness_history"][0]["content_hash"]

    def test_filing_output_calls_it_a_declaration(self, tmp_path, capsys):
        _setup_cli(tmp_path)
        (tmp_path / "p.json").write_text(json.dumps({"title": "t"}))
        capsys.readouterr()
        _cli(tmp_path, "file", "C1", *BY, "--stage", "early_warning", "--at",
             "2026-09-19T08:00:00Z", "--payload", str(tmp_path / "p.json"))
        out = capsys.readouterr().out
        assert "declaration" in out and "nothing here checked it" in out


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "api.db"))
    monkeypatch.setenv("ASSURANCE_API_KEYS", KEY)
    from assurance.api import deps

    deps._register_for.cache_clear()
    app = importlib.import_module("assurance.api.service").create_app()
    with TestClient(app) as c:
        c.headers.update({"X-API-Key": KEY})
        yield c


ACTOR = {"identifier": "m.braun", "role": "eng"}


def _api_case(client):
    assert client.post("/v1/cases/C1/signal", json={
        "received_at": "2026-09-19T05:00:00Z", "channel": "other", "description": "d",
        "actor": ACTOR}).status_code == 201
    r = client.post("/v1/cases/C1/awareness", json={
        "established_at": "2026-09-19T06:30:00Z", "assessment_started_at": "2026-09-19T06:00:00Z",
        "assessment_completed_at": "2026-09-19T06:30:00Z",
        "track": "actively_exploited_vulnerability", "reasoning": "x", "actor": ACTOR})
    assert r.status_code == 201
    return r.json()["content_hash"]


def _body(h, **over):
    body = {"supersedes": h, "reason": "wrong mailbox", "established_at": "2026-09-19T08:30:00Z",
            "assessment_started_at": "2026-09-19T08:00:00Z",
            "assessment_completed_at": "2026-09-19T08:30:00Z", "reasoning": "fixed",
            "actor": ACTOR}
    body.update(over)
    return body


class TestApi:
    def test_supersede_history_breaches_and_verify(self, client):
        h = _api_case(client)
        r = client.post("/v1/cases/C1/awareness/supersede", json=_body(h))
        assert r.status_code == 201, r.text
        shifts = r.json()["deadline_shifts"]
        assert {s["stage"] for s in shifts} == {"early_warning", "notification"}
        assert shifts[0]["reason"] == "wrong mailbox" and "m.braun" in shifts[0]["by"]
        case = client.get("/v1/cases/C1").json()
        assert case["awareness"]["established_at"] == "2026-09-19T08:30:00Z"
        assert [x["status"] for x in case["awareness_history"]] == ["superseded", "in_force"]
        history = client.get("/v1/cases/C1/history").json()
        assert [x["kind"] for x in history["history"]] == [
            "art14.signal", "art14.awareness", "art14.awareness_supersession"]
        assert any(b["status"] == "deadline_moved_later_after_original_passed"
                   for b in client.get("/v1/register/breaches").json())
        assert client.get("/v1/ledger/verify").json()["verified"] is True
        assert client.get("/v1/cases/NOPE/history").status_code == 404

    def test_refusals_are_409_and_422_and_write_nothing(self, client):
        h = _api_case(client)
        n = client.get("/v1/ledger/verify").json()["attestation"]["length"]
        assert client.post("/v1/cases/C1/awareness/supersede",
                           json=_body("f" * 16)).status_code == 409
        assert client.post("/v1/cases/C1/awareness/supersede",
                           json=_body(h, reason="")).status_code == 422
        assert client.post("/v1/cases/C1/awareness/supersede",
                           json=_body(h, established_at="2026-09-19T08:30:00")).status_code == 422
        bot = {"identifier": "bot", "kind": "automation"}
        assert client.post("/v1/cases/C1/awareness/supersede",
                           json=_body(h, actor=bot)).status_code == 409
        assert client.get("/v1/ledger/verify").json()["attestation"]["length"] == n

    def test_filed_case_refuses_over_http(self, client):
        h = _api_case(client)
        assert client.post("/v1/cases/C1/filings", json={
            "stage": "early_warning", "submitted_at": "2026-09-19T08:00:00Z",
            "payload": {"title": "t"}, "actor": ACTOR}).status_code == 201
        r = client.post("/v1/cases/C1/awareness/supersede", json=_body(h))
        assert r.status_code == 409 and "filing" in r.json()["detail"]["detail"]

    def test_a_future_dated_filing_is_refused_and_a_filing_is_a_declaration(self, client):
        _api_case(client)
        far = client.post("/v1/cases/C1/filings", json={
            "stage": "early_warning", "submitted_at": "2099-01-01T00:00:00Z",
            "payload": {"title": "t"}, "actor": ACTOR})
        assert far.status_code == 409 and "future" in far.json()["detail"]["detail"]
        ok = client.post("/v1/cases/C1/filings", json={
            "stage": "early_warning", "submitted_at": "2026-09-19T08:00:00Z",
            "payload": {}, "actor": ACTOR})
        assert ok.status_code == 201 and ok.headers["X-Assurance-Submittable"] == "false"
        ew = [d for d in client.get("/v1/cases/C1").json()["deadlines"]["deadlines"]
              if d["stage"] == "early_warning"][0]
        assert ew["status"] == "recorded_incomplete" and ew["verified_by_platform"] is False
        assert ew["submission_evidence"] == "declared"

    def test_misspelt_triage_question_is_422(self, client):
        _api_case(client)
        r = client.post("/v1/cases/C1/triage", json={
            "answers": {"reliable_evidence": "yes"}, "actor": ACTOR})
        assert r.status_code == 422 and r.json()["detail"]["error"] == "bad_triage_answer"

    def test_availability_on_an_unknown_case_is_409_not_a_phantom_case(self, client):
        r = client.post("/v1/cases/TYPO/availability", json={
            "product_name": "P", "version_range": "1", "member_states": ["DE"],
            "evidence_source": "s", "actor": ACTOR})
        assert r.status_code == 409 and client.get("/v1/cases").json() == []
