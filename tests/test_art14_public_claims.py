"""Public wording about the Article 14 clocks says what the code can stand behind.

The product computes 24 h, 72 h, 14-day and one-month deadlines from recorded facts and shows the
rule behind each (`Deadline.basis`). Whether Regulation 1182/71 applies, which calendar "the day" is
read in, what "submission" means and the 14(4)(c) trigger on a waived notification are open legal
questions listed with every case (`clock.OPEN_LEGAL_QUESTIONS`). A sentence that the clocks are
"computed correctly" claims a legal determination nothing here makes, so it is banned from every
public surface.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SURFACES = [
    "README.md",
    "src/assurance/billing/plans.py",
    "app/lib/plans.ts",
    "app/page.tsx",
    "app/lib/solutions.ts",
    "app/lib/services.ts",
    "app/applications/page.tsx",
    "app/lib/productPages.ts",
    "scripts/site_static/llms.txt.tmpl",
    "scripts/site_static/agent.json.tmpl",
    "src/assurance/api/service.py",
    "public/openapi.json",
    "src/assurance/README.md",
]
BANNED = re.compile(
    r"(clocks?|deadlines?)\s+(are\s+)?(computed|calculated)\s+correctly"
    r"|computes?\s+(both\s+)?(the\s+)?(final[- ]report\s+)?(clocks?|deadlines?)\s+(correctly|accurately)"
    r"|(platform|countdown)[^.\n]{0,40}\bis\s+wrong"
    r"|does\s+not\s+yet\s+capture[^.\n]{0,80}(awareness|vulnerabilit)"
    r"|counter\s+defect\s+surfaced",
    re.I,
)


def test_no_public_surface_claims_the_article_14_clocks_are_computed_correctly() -> None:
    hits = []
    for rel in SURFACES:
        path = ROOT / rel
        if not path.exists():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if BANNED.search(line):
                hits.append(f"{rel}:{number}")
    assert hits == [], hits


def test_the_plan_card_says_the_rule_is_shown_and_the_legal_questions_are_listed() -> None:
    plans = (ROOT / "src/assurance/billing/plans.py").read_text(encoding="utf-8")
    assert "with the rule behind" in plans and "open legal questions" in plans
