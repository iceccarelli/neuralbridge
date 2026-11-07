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

Machinery Regulation (EU) 2023/1230, application date: **20 January 2027** (Art. 54), resolved 2026-11-03.
The Official Journal text as first published (OJ L 165, 29.6.2023) carries 14 January 2027; that was a material error
corrected by Corrigendum OJ L 169, 4.7.2023, p. 35. The consolidated text of 27.07.2026 (CELEX 02023R1230-20260727,
same Publications Office route) states it as "Corrected by: C1 Corrigendum ..." and shows 20 January 2027 in
Art. 54 (and 20 January 2024 for Arts. 26-42, 20 October 2026 for Art. 50(1), 20 July 2024 for Arts. 6(2)-(6), (8),
(11), 47 and 53(3)). Regulation (EU) 2026/1744 (Digital Omnibus on AI, OJ L 24.7.2026) amends 2023/1230 only in
Arts. 8, 20 and 47 (AI-related presumptions and delegated acts); it does NOT amend Art. 54, so it is not the source
of the 20 January date and must not be cited as such. Annex III 1.1.9 is unchanged by it.

Re-verified 2026-11-06 against the Official Journal PDFs from EUR-Lex (``/legal-content/EN/TXT/PDF/?uri=OJ:L_202402847``
and ``...?uri=CELEX:32023R1230``) and the corrigendum OJ L 169, 4.7.2023, p. 35 (items 5 and 10: Art. 51(2) and
Art. 54 second paragraph, 14 -> 20 January 2027; Directive 2006/42/EC is therefore repealed with effect from
20 January 2027, Art. 51(2)). CRA: Art. 14(1)/(3)/(7) notifications go via the ENISA single reporting platform
(Art. 16) to the CSIRT designated as coordinator and to ENISA; Art. 14(5) defines "severe"; Art. 24(3) extends
Art. 14(1) to open-source software stewards only to the extent stated; main CRA obligations apply from 11 December
2027 and Chapter IV from 11 June 2026 (Art. 71(2)); Art. 64(2) fine ceiling EUR 15 000 000 / 2.5 % applies to
Arts. 13 and 14. Machinery Annex III 1.1.9: the machine identifies "the software installed on it that is necessary
for it to operate safely" and "collect[s] evidence of a legitimate or illegitimate intervention in the software or a
modification of the software installed on the machinery ... or its configuration".
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


def test_machinery_application_date_is_20_january_2027_everywhere_and_never_14():
    """Pinned to the consolidated, corrigendum-marked text (see the module docstring)."""
    import re

    paths = [
        "README.md", "app/page.tsx", "app/lib/solutions.ts", "app/lib/productPages.ts",
        "src/assurance/machinery/__init__.py", "src/assurance/machinery/manifest.py",
        "deploy/assurance/MACHINERY.md", "deploy/assurance/MACHINE.md",
    ]
    mentions = 0
    for rel in paths:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert not re.search(r"14 Jan(uary)? 2027", text), rel  # the uncorrected, erroneous date
        mentions += len(re.findall(r"20 Jan(uary)? 2027", text))
    assert mentions >= 8


def test_annex_iii_1_1_9_is_described_as_the_official_text_describes_it():
    paths = ["README.md", "app/page.tsx", "app/lib/solutions.ts", "app/lib/productPages.ts",
             "deploy/assurance/MACHINERY.md", "deploy/assurance/MACHINE.md",
             "src/assurance/machinery/__init__.py", "src/assurance/machinery/manifest.py"]
    for rel in paths:
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert "identify its safety-relevant software" not in text, rel
        assert "identify the safety-relevant software on the machine" not in text, rel


def test_article_14_is_not_described_as_reporting_to_unnamed_authorities():
    pp = (ROOT / "app/lib/productPages.ts").read_text(encoding="utf-8")
    assert "to the authorities on fixed deadlines" not in pp
    assert "CSIRT designated as coordinator and to ENISA" in pp
    sol = (ROOT / "app/lib/solutions.ts").read_text(encoding="utf-8")
    assert "naming every Member State" not in sol


def test_nothing_shipped_calls_a_product_compliant_or_cra_ready():
    # The retired src/dashboard screens were checked here; the customer workspace that replaced them
    # is checked instead, over every workspace component (a wider set than the two files before).
    workspace = sorted(
        [*(ROOT / "app/components/assurance").glob("*.tsx"), *(ROOT / "app/components/ai").glob("*.tsx"),
         *(ROOT / "app/components").glob("*Workspace.tsx"), ROOT / "app/components/Console.tsx"]
    )
    assert len(workspace) >= 20
    assert not (ROOT / "src/dashboard").exists()
    for path in workspace:
        text = path.read_text(encoding="utf-8")
        for banned in ("CRA Ready", "Fully Compliant", "% compliant", "Compliance deadline"):
            assert banned not in text, (path.name, banned)
    legacy = (ROOT / "src/neuralbridge/compliance/cra_report.py").read_text(encoding="utf-8")
    assert "Compliant with CRA requirements" not in legacy
