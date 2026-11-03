"""Regulatory statements the product makes, pinned to the Official Journal text they were checked against.

Checked 2026-11-03 against the Official Journal text of Regulation (EU) 2024/2847 (Cyber Resilience Act),
retrieved from the EU Publications Office (https://publications.europa.eu/resource/celex/32024R2847 with
``Accept: application/xhtml+xml``; the EUR-Lex HTML page answers automated clients with an empty challenge page).

    Art. 14(2)(a)  early warning "without undue delay and in any event within 24 hours of the manufacturer
                   becoming aware", "indicating, where applicable, the Member States on the territory of which the
                   manufacturer is aware that their product ... has been made available"
    Art. 14(2)(b)  vulnerability notification "within 72 hours of the manufacturer becoming aware"
    Art. 14(2)(c)  final report "no later than 14 days after a corrective or mitigating measure is available"
    Art. 14(4)(a)  incident early warning within 24 hours; (b) incident notification within 72 hours;
    Art. 14(4)(c)  incident final report "within one month after the submission of the incident notification"
    Art. 69(3)     Art. 14 obligations apply to products placed on the market before 11 December 2027
    Art. 71(2)     Art. 14 applies from 11 September 2026

These tests keep the software's clocks and the public wording equal to that text. They do not make the product a
legal-compliance tool: it computes and records clocks; people decide and file.

NOT pinned, on purpose: the Machinery Regulation (EU) 2023/1230 application date. The Official Journal text retrieved
the same way (English and French copies) says Art. 54 "shall apply from 14 January 2027", while this repository says
20 January 2027 in about a dozen places. That conflict is unresolved and is for the owner to confirm on EUR-Lex.
"""

from __future__ import annotations

from pathlib import Path

from assurance.security.art14 import clock

ROOT = Path(__file__).resolve().parents[1]


def test_clock_constants_equal_the_cra_article_14_text():
    assert clock.EARLY_WARNING_HOURS == 24  # 14(2)(a), 14(4)(a)
    assert clock.NOTIFICATION_HOURS == 72  # 14(2)(b), 14(4)(b)
    assert clock.VULNERABILITY_FINAL_DAYS == 14  # 14(2)(c): after a measure is AVAILABLE, not after awareness


def test_incident_final_report_is_one_calendar_month_not_thirty_days():
    from datetime import datetime

    assert clock.add_one_month(datetime(2026, 1, 31, 9, 0)) == datetime(2026, 2, 28, 9, 0)


def test_public_wording_does_not_overstate_the_member_state_duty():
    # 14(2)(a): "indicating, where applicable, the Member States ... the manufacturer is aware ..."
    for rel in ("README.md", "app/lib/productPages.ts"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "naming the Member States where the product is available" not in text, rel
        assert "must name the Member States" not in text, rel
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "indicates, where applicable, the Member States where you know the product has been made available" in readme


def test_application_dates_stated_for_article_14():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Applies since **11 Sep 2026**" in readme  # Art. 71(2)
    assert "Art. 69(3) extends the duty to products placed on the market before 11 Dec 2027" in readme
