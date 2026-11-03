"""A filing must not read as a met deadline unless it could have been one.

Issue #90 and the mandate behind it: a submission dated in the future, or one whose
content fails the platform field specification's blocking checks, must never show
``filed_on_time``. What the register holds is the manufacturer's own declaration that a
submission happened; it is never presented as verified by the platform.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

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
from assurance.security.art14.engine import CLOCK_SKEW_SECONDS
from assurance.security.art14.model import CASE_KIND
from assurance.security.art14.report import case_report, register_report

ACTOR = Actor("m.braun", "Entwicklungsleitung")
AWARE = parse_utc("2026-09-19T06:30:00Z")
NOW = parse_utc("2026-09-19T12:00:00Z")

COMPLETE = {
    "notification_type": "Vulnerability",
    "title": "Unauthenticated command injection",
    "summary": "Reachable on FW 2.1.0-2.4.6.",
    "product_name": "SK-4200",
    "product_version": "FW 2.1.0-2.4.6",
    "member_states_available": ["DE", "AT"],
    "awareness_datetime": "2026-09-19T06:30:00Z",
}

FINAL_COMPLETE = {
    **COMPLETE,
    "measures_taken": "Disabled the service port by default",
    "measures_users_can_take": "Apply firmware 2.4.7",
    "measure_available_date": "2026-09-19T11:30:00Z",
    "security_update_details": "FW 2.4.7 closes the injection",
    "vulnerability_severity": "High",
    "vulnerability_impact": "Remote command execution",
}


def make(tmp_path, track=Track.VULNERABILITY, name="ledger.db"):
    reg = Art14Register(EvidenceLedger(tmp_path / name))
    reg.record_signal(
        "c1",
        Signal(received_at=AWARE - timedelta(hours=1), channel=SignalChannel.OTHER,
               received_by="m.braun", description="d"),
        ACTOR,
    )
    reg.record_awareness(
        "c1",
        Awareness(established_at=AWARE, assessment_started_at=AWARE - timedelta(minutes=30),
                  assessment_completed_at=AWARE, determined_by="m.braun", reasoning="because"),
        track,
        ACTOR,
    )
    return reg


def deadline(reg, stage):
    return {d["stage"]: d for d in reg.case("c1").to_dict()["deadlines"]["deadlines"]}[stage]


class TestFutureDatedFilings:
    def test_a_future_filing_is_refused_and_nothing_is_written(self, tmp_path):
        reg = make(tmp_path)
        before = len(reg.ledger)
        with pytest.raises(CaseError, match="future"):
            reg.record_filing("c1", Stage.EARLY_WARNING, NOW + timedelta(hours=10), COMPLETE,
                              ACTOR, now=NOW)
        assert len(reg.ledger) == before
        assert deadline(reg, "early_warning")["status"] == "open"

    def test_the_skew_allowance_is_the_whole_tolerance(self, tmp_path):
        reg = make(tmp_path)
        edge = NOW + timedelta(seconds=CLOCK_SKEW_SECONDS)
        with pytest.raises(CaseError, match="future"):
            reg.record_filing("c1", Stage.EARLY_WARNING, edge + timedelta(seconds=1), COMPLETE,
                              ACTOR, now=NOW)
        reg.record_filing("c1", Stage.EARLY_WARNING, edge, COMPLETE, ACTOR, now=NOW)
        assert deadline(reg, "early_warning")["status"] == "filed_on_time"

    def test_the_default_now_is_the_real_clock(self, tmp_path):
        reg = make(tmp_path)
        far = parse_utc("2090-01-01T00:00:00Z")
        with pytest.raises(CaseError, match="future"):
            reg.record_filing("c1", Stage.EARLY_WARNING, far, COMPLETE, ACTOR)

    def test_a_ledger_that_already_holds_one_does_not_count_it_as_filed(self, tmp_path):
        # Written before the refusal existed: the entry is in the chain, dated after the moment
        # the ledger recorded it. The fold must not read it as a met deadline.
        reg = make(tmp_path)
        future = parse_utc("2090-01-01T00:00:00Z")
        reg._append(
            "c1", CASE_KIND["filing"],
            {"stage": "early_warning", "submitted_at": format_utc(future),
             "platform_reference": "", "payload": COMPLETE,
             "validation": validate_payload(COMPLETE, Track.VULNERABILITY,
                                            Stage.EARLY_WARNING).to_dict()},
            ACTOR,
        )
        case = reg.case("c1")
        assert deadline(reg, "early_warning")["status"] == "open"
        assert [f["stage"] for f in case.uncounted_filings] == ["early_warning"]
        assert any("NOT COUNTED AS FILED" in line for line in case.outstanding())
        assert case.to_dict()["uncounted_filings"][0]["submitted_at"] == format_utc(future)
        assert len(reg.ledger.entries(subject="c1")) == 3  # history is kept, not deleted

    def test_an_uncounted_incident_notification_does_not_start_the_final_clock(self, tmp_path):
        reg = make(tmp_path, Track.INCIDENT)
        reg._append(
            "c1", CASE_KIND["filing"],
            {"stage": "notification", "submitted_at": "2090-01-01T00:00:00Z",
             "platform_reference": "", "payload": {}, "validation": {"submittable": True}},
            ACTOR,
        )
        assert reg.case("c1").deadlines.final is None


class TestIncompleteFilings:
    def test_an_empty_filing_in_time_is_recorded_not_met(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), {}, ACTOR, now=NOW)
        d = deadline(reg, "early_warning")
        assert d["status"] == "recorded_incomplete"
        assert d["content_complete"] is False
        assert d["submitted_at"] == "2026-09-19T08:30:00Z"  # history kept
        assert reg.case("c1").deadlines.early_warning.met is None
        assert any("INCOMPLETE CONTENT" in line for line in reg.case("c1").outstanding())

    def test_a_complete_filing_exactly_on_the_deadline_is_on_time(self, tmp_path):
        reg = make(tmp_path)
        due = AWARE + timedelta(hours=24)
        reg.record_filing("c1", Stage.EARLY_WARNING, due, COMPLETE, ACTOR, now=due)
        assert deadline(reg, "early_warning")["status"] == "filed_on_time"

    def test_one_second_after_the_deadline_is_late(self, tmp_path):
        reg = make(tmp_path)
        due = AWARE + timedelta(hours=24)
        reg.record_filing("c1", Stage.EARLY_WARNING, due + timedelta(seconds=1), COMPLETE, ACTOR,
                          now=due + timedelta(hours=1))
        assert deadline(reg, "early_warning")["status"] == "filed_late"

    def test_a_late_incomplete_filing_is_still_late_and_says_it_is_incomplete(self, tmp_path):
        reg = make(tmp_path)
        late = AWARE + timedelta(hours=30)
        reg.record_filing("c1", Stage.EARLY_WARNING, late, {}, ACTOR, now=late)
        assert deadline(reg, "early_warning")["status"] == "filed_late"
        assert any("also incomplete" in line for line in reg.case("c1").outstanding())

    def test_a_late_complete_filing_after_an_early_empty_one_is_filed_late(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), {}, ACTOR, now=NOW)
        later = AWARE + timedelta(hours=40)
        reg.record_filing("c1", Stage.EARLY_WARNING, later, COMPLETE, ACTOR, now=later)
        assert deadline(reg, "early_warning")["status"] == "filed_late"

    def test_an_incomplete_incident_notification_still_starts_the_final_clock(self, tmp_path):
        # The recorded time is kept so no deadline that runs FROM a filing is hidden.
        reg = make(tmp_path, Track.INCIDENT)
        sent = AWARE + timedelta(hours=50)
        reg.record_filing("c1", Stage.NOTIFICATION, sent, {}, ACTOR, now=sent)
        d = reg.case("c1").deadlines
        assert d.notification.status == "recorded_incomplete"
        assert d.final is not None
        assert format_utc(d.final.due_at) == format_utc(sent.replace(month=10))

    def test_an_incomplete_final_filing_does_not_close_the_case(self, tmp_path):
        reg = make(tmp_path)
        reg.record_triage(
            "c1",
            {
                "is_our_product_with_digital_elements_on_the_eu_market": "yes",
                "reliable_evidence_of_malicious_exploitation": "yes",
                "exploited_in_our_product_not_merely_in_a_component": "yes",
                "awareness_of_active_exploitation_on_or_after_2026_09_11": "yes",
            },
            ACTOR,
        )
        reg.record_measure_available("c1", AWARE + timedelta(hours=5), "workaround", ACTOR)
        # Closing needs all three stages (workstream L): the early warning and the notification
        # are filed first, so this test still isolates the incomplete FINAL filing.
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), COMPLETE, ACTOR,
                          now=NOW)
        reg.record_filing("c1", Stage.NOTIFICATION, AWARE + timedelta(hours=3),
                          {"vulnerability_general_information": "Command injection in the service port"},
                          ACTOR, now=NOW)
        reg.record_filing("c1", Stage.FINAL, AWARE + timedelta(days=2), {}, ACTOR, now=NOW + timedelta(days=3))
        case = reg.case("c1")
        assert case.state == "reportable_open"
        assert any("INCOMPLETE CONTENT" in line and "Final" in line for line in case.outstanding())
        reg.record_filing("c1", Stage.FINAL, AWARE + timedelta(days=3), FINAL_COMPLETE, ACTOR,
                          now=NOW + timedelta(days=4))
        assert reg.case("c1").state == "closed_filed"

    def test_the_breach_list_and_reports_agree(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), {}, ACTOR, now=NOW)
        # Judged long after the deadline: the stage was only ever recorded incomplete.
        reference = AWARE + timedelta(days=10)
        found = {(b["stage"], b["status"]) for b in reg.breaches(reference)}
        assert ("early_warning", "recorded_incomplete_past_due") in found
        text = case_report(reg.case("c1"), now=reference)
        assert "CONTENT INCOMPLETE" in text and "not verified by the platform" in text
        assert "recorded_incomplete_past_due" in register_report(reg, now=reference)


class TestNothingIsPresentedAsVerified:
    def test_every_deadline_says_it_is_declared_not_verified(self, tmp_path):
        reg = make(tmp_path)
        reg.record_filing("c1", Stage.EARLY_WARNING, AWARE + timedelta(hours=2), COMPLETE, ACTOR,
                          "REF-1", now=NOW)
        reg.record_filing("c1", Stage.NOTIFICATION, AWARE + timedelta(hours=3), COMPLETE, ACTOR,
                          now=NOW)
        ds = reg.case("c1").to_dict()["deadlines"]["deadlines"]
        assert all(d["verified_by_platform"] is False for d in ds)
        by = {d["stage"]: d["submission_evidence"] for d in ds}
        assert by == {
            "early_warning": "declared_with_platform_reference",
            "notification": "declared",
        }

    def test_an_open_deadline_claims_no_submission_evidence(self, tmp_path):
        reg = make(tmp_path)
        d = deadline(reg, "early_warning")
        assert d["submission_evidence"] is None and d["verified_by_platform"] is False


class TestMemberStateCodeForGreece:
    def _text(self, codes):
        v = validate_payload({"member_states_available": codes}, Track.VULNERABILITY,
                             Stage.EARLY_WARNING)
        return " ".join(i.message for i in v.issues if i.field_name == "member_states_available")

    def test_el_is_told_to_use_gr_and_is_never_called_a_non_member(self):
        text = self._text(["DE", "EL"])
        assert "GR" in text and "Greece" in text
        assert "not EU Member States" not in text
        assert "has not been checked" in text  # no claim about what the platform expects

    def test_gr_is_accepted(self):
        assert self._text(["GR"]) == ""

    def test_a_genuinely_unknown_code_is_still_blocking(self):
        assert "not EU Member States" in self._text(["US"])
