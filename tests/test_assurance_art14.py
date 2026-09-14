"""Article 14 of the Cyber Resilience Act.

The tests are written against the provisions, not against the implementation,
so that a change in the code that quietly moves a legal deadline fails here.
Every deadline assertion names the article it comes from.
"""

from __future__ import annotations

import pytest

from assurance.core import Actor, ClockError, EvidenceIncompleteError
from assurance.core.identity import format_utc, parse_utc
from assurance.evidence import EvidenceLedger
from assurance.security.art14 import (
    FIELDS,
    Art14Register,
    Awareness,
    CaseError,
    Deadlines,
    NonReportGround,
    ProductVersion,
    Signal,
    SignalChannel,
    Stage,
    Track,
    add_one_month,
    fields_for,
    platform_displayed_notification_due,
    triage,
    validate_payload,
)
from assurance.security.art14.report import case_report, readiness_report, register_report
from assurance.security.art14.srp import Requirement
from assurance.security.art14.triage import Answer, Question

AWARE = parse_utc("2026-09-19T06:30:00Z")
ACTOR = Actor("m.braun", "Entwicklungsleitung")


# =====================================================================
# deadlines
# =====================================================================
class TestDeadlines:
    def test_early_warning_is_24_hours_from_awareness(self):
        # Art. 14(2)(a) and 14(4)(a): within 24 hours of becoming aware.
        for track in Track:
            d = Deadlines(track=track, awareness_at=AWARE)
            assert format_utc(d.early_warning.due_at) == "2026-09-20T06:30:00Z"
            assert d.early_warning.runs_from == AWARE

    def test_notification_is_72_hours_from_awareness_not_from_the_early_warning(self):
        # A common and expensive misreading: the 72-hour clock runs from
        # awareness, not from submission of the early warning.
        d = Deadlines(
            track=Track.VULNERABILITY,
            awareness_at=AWARE,
            early_warning_submitted_at=parse_utc("2026-09-20T05:00:00Z"),
        )
        assert format_utc(d.notification.due_at) == "2026-09-22T06:30:00Z"

    def test_vulnerability_final_runs_14_days_from_the_measure_not_from_awareness(self):
        # Art. 14(2)(c): 14 days after a corrective OR MITIGATING measure is
        # available. A documented workaround starts it as surely as a patch.
        d = Deadlines(
            track=Track.VULNERABILITY,
            awareness_at=AWARE,
            measure_available_at=parse_utc("2026-09-30T16:00:00Z"),
        )
        assert format_utc(d.require_final().due_at) == "2026-10-14T16:00:00Z"
        assert d.final.provision == "Art. 14(2)(c)"

    def test_vulnerability_final_does_not_exist_until_a_measure_does(self):
        d = Deadlines(track=Track.VULNERABILITY, awareness_at=AWARE)
        assert d.final is None
        with pytest.raises(ClockError, match="mitigating measure"):
            d.require_final()
        assert any("not computable" in gap for gap in d.pending_facts())

    def test_incident_final_runs_one_month_from_the_72_hour_submission(self):
        # Art. 14(4)(c): one month after the notification under point (b) was
        # submitted. Not from awareness, and not from remediation.
        d = Deadlines(
            track=Track.INCIDENT,
            awareness_at=AWARE,
            notification_submitted_at=parse_utc("2026-09-21T09:00:00Z"),
        )
        assert format_utc(d.require_final().due_at) == "2026-10-21T09:00:00Z"
        assert d.final.runs_from_fact.startswith("submission")

    def test_incident_final_does_not_exist_until_the_notification_is_filed(self):
        d = Deadlines(track=Track.INCIDENT, awareness_at=AWARE)
        assert d.final is None
        with pytest.raises(ClockError, match="72-hour"):
            d.require_final()

    @pytest.mark.parametrize(
        "start,expected",
        [
            ("2026-01-31T09:00:00Z", "2026-02-28T09:00:00Z"),  # clamps to a short month
            ("2024-01-31T09:00:00Z", "2024-02-29T09:00:00Z"),  # leap year
            ("2026-12-15T09:00:00Z", "2027-01-15T09:00:00Z"),  # year boundary
            ("2026-03-31T09:00:00Z", "2026-04-30T09:00:00Z"),
        ],
    )
    def test_one_month_is_a_calendar_month_not_thirty_days(self, start, expected):
        assert format_utc(add_one_month(parse_utc(start))) == expected

    def test_lateness_is_reported_per_stage(self):
        d = Deadlines(
            track=Track.VULNERABILITY,
            awareness_at=AWARE,
            early_warning_submitted_at=parse_utc("2026-09-19T11:15:00Z"),
            notification_submitted_at=parse_utc("2026-09-23T09:00:00Z"),
        )
        assert d.early_warning.status == "filed_on_time"
        assert d.notification.status == "filed_late"
        assert [b.stage for b in d.breaches()] == [Stage.NOTIFICATION]

    def test_platform_counter_defect_is_surfaced_rather_than_hidden(self):
        # ENISA CRA SRP FAQ 26: the displayed 72-hour counter is computed as 48
        # hours after the early warning, so it can show a filing as overdue
        # while it is still in time. Show both and let the legal one govern.
        submitted = parse_utc("2026-09-19T11:15:00Z")
        displayed = platform_displayed_notification_due(submitted)
        d = Deadlines(
            track=Track.VULNERABILITY, awareness_at=AWARE, early_warning_submitted_at=submitted
        )
        assert displayed < d.notification.due_at
        counter = d.to_dict()["platform_counter"]
        assert counter["agrees"] is False
        assert "FAQ 26" in counter["note"]


# =====================================================================
# triage
# =====================================================================
class TestTriage:
    def test_published_proof_of_concept_is_not_active_exploitation(self):
        # Art. 3(42) needs reliable evidence that a MALICIOUS ACTOR exploited
        # it. Recital 68 and FAQ 5.2: good-faith testing is not that.
        result = triage(
            Track.VULNERABILITY,
            {Question.IN_SCOPE_PRODUCT: Answer.YES, Question.RELIABLE_EVIDENCE: Answer.NO},
        )
        assert result.reportable is False
        assert result.ground is NonReportGround.NO_RELIABLE_EVIDENCE
        assert result.reopen_trigger_required

    def test_unreached_component_vulnerability_leaves_the_upstream_duty(self):
        # Guidance §218: not our reportable event, but Art. 13(6) still applies.
        result = triage(
            Track.VULNERABILITY,
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.RELIABLE_EVIDENCE: Answer.YES,
                Question.EXPLOITED_IN_OUR_PRODUCT: Answer.NO,
            },
        )
        assert result.reportable is False
        assert result.upstream_duty_remains

    def test_pre_cutoff_awareness_closes_the_case_but_demands_a_trigger(self):
        result = triage(
            Track.VULNERABILITY,
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.RELIABLE_EVIDENCE: Answer.YES,
                Question.EXPLOITED_IN_OUR_PRODUCT: Answer.YES,
                Question.AWARENESS_AFTER_CUTOFF: Answer.NO,
            },
        )
        assert result.ground is NonReportGround.PRE_CUTOFF_AWARENESS
        assert result.reopen_trigger_required

    def test_undetermined_is_not_a_negative(self):
        # Treating an unanswered question as "no" is how a reportable event
        # gets filed away.
        result = triage(Track.VULNERABILITY, {Question.IN_SCOPE_PRODUCT: Answer.YES})
        assert result.reportable is None
        assert result.status == "undetermined"
        assert Question.RELIABLE_EVIDENCE.value in result.unanswered

    def test_full_yes_path_is_reportable(self):
        result = triage(
            Track.VULNERABILITY,
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.RELIABLE_EVIDENCE: Answer.YES,
                Question.EXPLOITED_IN_OUR_PRODUCT: Answer.YES,
                Question.AWARENESS_AFTER_CUTOFF: Answer.YES,
            },
        )
        assert result.reportable is True

    def test_severity_limb_a_alone_establishes_a_severe_incident(self):
        result = triage(
            Track.INCIDENT,
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.AFFECTS_PRODUCT_SECURITY: Answer.YES,
                Question.SEVERE_SENSITIVE_OR_IMPORTANT: Answer.YES,
            },
        )
        assert result.reportable is True

    def test_a_no_on_limb_a_falls_through_to_limb_b(self):
        # Art. 14(5)(b) has no severity qualifier; a "no" on (a) must not close
        # the case before (b) has been asked.
        result = triage(
            Track.INCIDENT,
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.AFFECTS_PRODUCT_SECURITY: Answer.YES,
                Question.SEVERE_SENSITIVE_OR_IMPORTANT: Answer.NO,
                Question.SEVERE_MALICIOUS_CODE: Answer.YES,
            },
        )
        assert result.reportable is True

    def test_no_on_both_limbs_is_not_severe(self):
        result = triage(
            Track.INCIDENT,
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.AFFECTS_PRODUCT_SECURITY: Answer.YES,
                Question.SEVERE_SENSITIVE_OR_IMPORTANT: Answer.NO,
                Question.SEVERE_MALICIOUS_CODE: Answer.NO,
            },
        )
        assert result.reportable is False
        assert result.ground is NonReportGround.NOT_SEVERE

    def test_corporate_only_incident_is_out_of_scope(self):
        result = triage(
            Track.INCIDENT,
            {Question.IN_SCOPE_PRODUCT: Answer.YES, Question.AFFECTS_PRODUCT_SECURITY: Answer.NO},
        )
        assert result.ground is NonReportGround.NO_PRODUCT_SECURITY_IMPACT

    def test_every_ground_cites_its_authority(self):
        for ground in NonReportGround:
            assert ground.authority.strip()


# =====================================================================
# platform field specification
# =====================================================================
class TestFieldSpec:
    def test_the_specification_is_complete(self):
        assert len(FIELDS) == 39
        assert len({f.number for f in FIELDS}) == 39

    def test_tracks_see_only_their_own_fields(self):
        vuln = {f.number for f in fields_for(Track.VULNERABILITY, Stage.EARLY_WARNING)}
        incident = {f.number for f in fields_for(Track.INCIDENT, Stage.EARLY_WARNING)}
        assert "v21" in vuln and "v21" not in incident
        assert "i31" in incident and "i31" not in vuln

    def test_incident_early_warning_requires_the_malicious_cause_flag(self):
        # Art. 14(4)(a) names this as required content at 24 hours.
        spec = next(f for f in FIELDS if f.number == "i31")
        assert spec.requirement_at(Stage.EARLY_WARNING) is Requirement.REQUIRED

    def test_fields_the_platform_cannot_yet_capture_are_marked(self):
        gaps = {f.number for f in FIELDS if f.platform_gap}
        assert gaps == {"v26", "i37"}

    def test_missing_required_field_blocks_submission(self):
        result = validate_payload({}, Track.VULNERABILITY, Stage.EARLY_WARNING)
        assert not result.submittable
        assert any(i.field_number == "5" for i in result.blocking)

    def test_over_length_value_blocks_submission(self):
        # v27 accepts 100 characters. Name the actor; the analysis does not fit.
        payload = _early_warning_payload(malicious_actor="x" * 140)
        result = validate_payload(payload, Track.VULNERABILITY, Stage.EARLY_WARNING)
        assert not result.submittable
        assert any(i.field_number == "v27" for i in result.blocking)

    def test_non_member_state_in_field_five_blocks_submission(self):
        # The classic DACH error: Switzerland is not a Member State. It still
        # matters for Art. 14(8), which is a different duty.
        payload = _early_warning_payload(member_states_available=["DE", "AT", "CH"])
        result = validate_payload(payload, Track.VULNERABILITY, Stage.EARLY_WARNING)
        assert not result.submittable
        assert any("not EU Member States" in i.message for i in result.blocking)

    def test_eea_states_are_flagged_but_not_blocked(self):
        payload = _early_warning_payload(member_states_available=["DE", "NO"])
        result = validate_payload(payload, Track.VULNERABILITY, Stage.EARLY_WARNING)
        assert result.submittable
        assert any("EEA states" in i.message for i in result.advisory)

    def test_valid_early_warning_is_submittable(self):
        result = validate_payload(
            _early_warning_payload(), Track.VULNERABILITY, Stage.EARLY_WARNING
        )
        assert result.submittable, result.summary()

    def test_validation_declares_what_it_could_not_check(self):
        result = validate_payload(
            _early_warning_payload(), Track.VULNERABILITY, Stage.EARLY_WARNING
        )
        assert result.checks_skipped
        assert any("v26" in c for c in result.checks_skipped)

    def test_final_report_requires_the_measures_fields(self):
        result = validate_payload({}, Track.VULNERABILITY, Stage.FINAL)
        blocked = {i.field_number for i in result.blocking}
        assert {"16", "17", "v22", "v23", "v24", "v25"} <= blocked


def _early_warning_payload(**overrides):
    payload = {
        "notification_type": "Vulnerability",
        "title": "Unauthenticated command injection on the service port",
        "summary": "Reachable on FW 2.1.0-2.4.6; exploitation observed at one integrator site.",
        "product_name": "SK-4200 Palletising Cell",
        "product_version": "FW 2.1.0-2.4.6",
        "member_states_available": ["DE", "AT", "NL"],
        "awareness_datetime": "2026-09-19T06:30:00Z",
    }
    payload.update(overrides)
    return payload


# =====================================================================
# availability record
# =====================================================================
class TestProductVersion:
    def test_an_empty_member_state_list_is_reported_as_a_gap(self):
        gaps = ProductVersion(product_name="SK-4200", version_range="2.x").gaps()
        assert any("member_states" in g for g in gaps)

    def test_a_complete_record_has_no_gaps(self):
        product = ProductVersion(
            product_name="SK-4200",
            version_range="FW 2.1.0-2.4.6",
            member_states=("DE", "AT"),
            evidence_source="ERP delivery export 2026-09",
        )
        assert product.gaps() == []

    def test_end_of_support_does_not_remove_a_product_from_scope(self):
        # Art. 69(3) plus guidance §210: the reporting duty outlives support.
        product = ProductVersion(
            product_name="SK-3000",
            version_range="1.x",
            member_states=("DE",),
            evidence_source="ERP",
            end_of_support=True,
        )
        assert product.gaps() == []


# =====================================================================
# the register, end to end
# =====================================================================
@pytest.fixture()
def register(tmp_path):
    return Art14Register(EvidenceLedger(tmp_path / "art14.db"))


def _signal(**overrides):
    defaults = {
        "received_at": parse_utc("2026-09-18T21:40:00Z"),
        "channel": SignalChannel.CUSTOMER,
        "received_by": "m.braun",
        "description": "Integrator reports the service port reached from an external host",
        "reference": "TICKET-8812",
    }
    defaults.update(overrides)
    return Signal(**defaults)


def _awareness(**overrides):
    defaults = {
        "established_at": AWARE,
        "assessment_started_at": parse_utc("2026-09-18T22:05:00Z"),
        "assessment_completed_at": AWARE,
        "determined_by": "m.braun",
        "reasoning": (
            "SIEM export from the integrator shows a shell spawned from the service port."
        ),
    }
    defaults.update(overrides)
    return Awareness(**defaults)


class TestRegisterOrdering:
    def test_awareness_requires_a_signal_first(self, register):
        # The interval between the two is the evidence; it cannot be
        # reconstructed if the signal was never recorded.
        with pytest.raises(CaseError, match="no signal"):
            register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)

    def test_awareness_cannot_precede_its_signal(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        with pytest.raises(CaseError, match="cannot precede"):
            register.record_awareness(
                "C1",
                _awareness(
                    established_at=parse_utc("2026-09-18T20:00:00Z"),
                    assessment_started_at=parse_utc("2026-09-18T19:00:00Z"),
                    assessment_completed_at=parse_utc("2026-09-18T20:00:00Z"),
                ),
                Track.VULNERABILITY,
                ACTOR,
            )

    def test_awareness_without_reasoning_is_refused(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        with pytest.raises(EvidenceIncompleteError, match="reasoning"):
            register.record_awareness("C1", _awareness(reasoning="  "), Track.VULNERABILITY, ACTOR)

    def test_awareness_cannot_be_silently_moved(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)
        with pytest.raises(CaseError, match="already has an awareness record"):
            register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)

    def test_filing_requires_awareness(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        with pytest.raises(CaseError, match="no awareness record"):
            register.record_filing(
                "C1", Stage.EARLY_WARNING, AWARE, _early_warning_payload(), ACTOR
            )

    def test_non_reportable_ground_requiring_a_trigger_refuses_without_one(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)
        with pytest.raises(EvidenceIncompleteError, match="reopen trigger is required"):
            register.record_triage(
                "C1", {Question.IN_SCOPE_PRODUCT: Answer.YES, Question.RELIABLE_EVIDENCE: Answer.NO}, ACTOR
            )

    def test_final_filing_refused_before_its_clock_starts(self, register):
        _open_reportable_case(register)
        with pytest.raises(ClockError, match="mitigating measure"):
            register.record_filing("C1", Stage.FINAL, AWARE, {}, ACTOR)

    def test_filing_on_a_closed_case_is_refused(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)
        register.record_triage(
            "C1",
            {Question.IN_SCOPE_PRODUCT: Answer.YES, Question.RELIABLE_EVIDENCE: Answer.NO},
            ACTOR,
            reopen_trigger="any customer report of exploitation",
        )
        with pytest.raises(CaseError, match="closed as not reportable"):
            register.record_filing(
                "C1", Stage.EARLY_WARNING, AWARE, _early_warning_payload(), ACTOR
            )


def _open_reportable_case(register, case_id: str = "C1"):
    register.record_signal(case_id, _signal(), ACTOR)
    register.record_awareness(case_id, _awareness(), Track.VULNERABILITY, ACTOR)
    register.record_triage(
        case_id,
        {
            Question.IN_SCOPE_PRODUCT: Answer.YES,
            Question.RELIABLE_EVIDENCE: Answer.YES,
            Question.EXPLOITED_IN_OUR_PRODUCT: Answer.YES,
            Question.AWARENESS_AFTER_CUTOFF: Answer.YES,
        },
        ACTOR,
        "SIEM export attached to the ticket.",
    )
    return register.case(case_id)


class TestRegisterLifecycle:
    def test_state_progresses_through_the_case(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        assert register.case("C1").state == "signal_received"
        register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)
        assert register.case("C1").state == "awaiting_triage"
        _open_reportable_case_triage(register)
        assert register.case("C1").state == "reportable_open"

    def test_case_is_rebuilt_from_the_ledger_not_from_memory(self, register, tmp_path):
        _open_reportable_case(register)
        reopened = Art14Register(EvidenceLedger(register.ledger.path))
        case = reopened.case("C1")
        assert case.awareness is not None
        assert case.awareness.established_at == AWARE
        assert case.triage_result is not None and case.triage_result.reportable is True

    def test_assessment_lag_is_recoverable(self, register):
        case = _open_reportable_case(register)
        assert case.awareness.lag_hours_from(case.signal) == pytest.approx(8.83, abs=0.02)

    def test_measure_starts_the_final_clock(self, register):
        _open_reportable_case(register)
        register.record_measure_available(
            "C1", parse_utc("2026-09-30T16:00:00Z"), "Documented workaround published", ACTOR
        )
        case = register.case("C1")
        assert format_utc(case.deadlines.require_final().due_at) == "2026-10-14T16:00:00Z"

    def test_outstanding_reports_an_overdue_deadline(self, register):
        _open_reportable_case(register)
        items = register.case("C1").outstanding(now=parse_utc("2026-09-23T09:00:00Z"))
        assert any("OVERDUE" in i for i in items)

    def test_outstanding_names_the_user_notification_duty(self, register):
        _open_reportable_case(register)
        items = register.case("C1").outstanding(now=parse_utc("2026-09-19T12:00:00Z"))
        assert any("Art. 14(8)" in i for i in items)

    def test_user_notification_clears_that_item(self, register):
        _open_reportable_case(register)
        register.record_user_notification(
            "C1", parse_utc("2026-09-19T14:00:00Z"), "impacted users", "advisory sent", ACTOR
        )
        items = register.case("C1").outstanding(now=parse_utc("2026-09-19T15:00:00Z"))
        assert not any("Art. 14(8)" in i for i in items)

    def test_breaches_are_found_across_the_register(self, register):
        _open_reportable_case(register, "C1")
        _open_reportable_case(register, "C2")
        breaches = register.breaches(now=parse_utc("2026-09-25T09:00:00Z"))
        assert {b["case_id"] for b in breaches} == {"C1", "C2"}
        assert all(b["status"] == "overdue_unfiled" for b in breaches)

    def test_closed_case_without_a_trigger_is_impossible_but_upstream_duty_persists(self, register):
        register.record_signal("C1", _signal(), ACTOR)
        register.record_awareness("C1", _awareness(), Track.VULNERABILITY, ACTOR)
        register.record_triage(
            "C1",
            {
                Question.IN_SCOPE_PRODUCT: Answer.YES,
                Question.RELIABLE_EVIDENCE: Answer.YES,
                Question.EXPLOITED_IN_OUR_PRODUCT: Answer.NO,
            },
            ACTOR,
            reopen_trigger="exploitation observed in our product",
        )
        case = register.case("C1")
        assert case.state == "closed_not_reportable"
        assert any("Art. 13(6)" in i for i in case.outstanding())

    def test_every_step_lands_in_the_verifiable_chain(self, register):
        _open_reportable_case(register)
        register.record_availability(
            "C1",
            ProductVersion(
                product_name="SK-4200",
                version_range="FW 2.1.0-2.4.6",
                member_states=("DE", "AT"),
                evidence_source="ERP export",
            ),
            ACTOR,
        )
        register.record_filing(
            "C1",
            Stage.EARLY_WARNING,
            parse_utc("2026-09-19T11:15:00Z"),
            _early_warning_payload(),
            ACTOR,
            "SRP-2026-000123",
        )
        ok, problems = register.ledger.verify_chain()
        assert ok, problems
        assert len(register.ledger.entries(subject="C1")) == 5
        assert register.ledger.export(subject="C1")["chain_verified"] is True


def _open_reportable_case_triage(register, case_id: str = "C1"):
    register.record_triage(
        case_id,
        {
            Question.IN_SCOPE_PRODUCT: Answer.YES,
            Question.RELIABLE_EVIDENCE: Answer.YES,
            Question.EXPLOITED_IN_OUR_PRODUCT: Answer.YES,
            Question.AWARENESS_AFTER_CUTOFF: Answer.YES,
        },
        ACTOR,
    )


# =====================================================================
# reporting
# =====================================================================
class TestReports:
    def test_case_report_leads_with_what_is_wrong(self, register):
        _open_reportable_case(register)
        text = case_report(register.case("C1"), now=parse_utc("2026-09-23T09:00:00Z"))
        assert "OUTSTANDING" in text
        assert "OVERDUE" in text
        assert "Art. 14(2)(b)" in text

    def test_case_report_shows_the_platform_disagreement(self, register):
        _open_reportable_case(register)
        register.record_filing(
            "C1",
            Stage.EARLY_WARNING,
            parse_utc("2026-09-19T11:15:00Z"),
            _early_warning_payload(),
            ACTOR,
        )
        text = case_report(register.case("C1"), now=parse_utc("2026-09-20T09:00:00Z"))
        assert "PLATFORM COUNTER DISAGREES" in text

    def test_register_report_counts_breaches(self, register):
        _open_reportable_case(register)
        text = register_report(register, now=parse_utc("2026-09-25T09:00:00Z"))
        assert "BREACHES" in text
        assert "chain verified       yes" in text

    def test_readiness_report_declares_its_own_limits(self, register):
        _open_reportable_case(register)
        report = readiness_report(register, now=parse_utc("2026-09-25T09:00:00Z"))
        assert report["legacy_products_in_scope"] is True
        assert report["legacy_basis"] == "Art. 69(3)"
        assert report["ledger"]["chain_verified"] is True
        assert any("non-binding" in c for c in report["checks_skipped"])
        assert any("sensitive or important" in c for c in report["checks_skipped"])
