"""The /assurance workspace must not widen the page on a phone.

Source-level guard (the repo's pattern for the site: read ``app/**``). The browser behaviour is
``tests-e2e/assurance-no-horizontal-overflow.spec.ts``. Background: a case-detail ``<select>`` was
as wide as its longest option, which made the whole page ~1000px wide at a 412px viewport.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSS = (ROOT / "app" / "globals.css").read_text(encoding="utf-8")
COMP = ROOT / "app" / "components" / "assurance"


def rules(selector: str) -> list[str]:
    """Bodies of every top-level rule whose selector list contains ``selector`` verbatim."""
    found = []
    for m in re.finditer(r"(?m)^([^{}/@][^{}]*)\{([^{}]*)\}", CSS):
        if selector in [s.strip() for s in m.group(1).split(",")]:
            found.append(m.group(2))
    return found


def test_aw_scroll_scrolls_inside_itself():
    body = " ".join(rules(".aw-scroll"))
    assert "overflow-x: auto" in body
    assert "max-width: 100%" in body


def test_detail_grid_children_may_shrink():
    assert any("min-width: 0" in b for b in rules(".aw-detail")), ".aw-detail needs min-width:0"
    assert any("min-width: 0" in b for b in rules(".aw-cols > *")), ".aw-cols children need min-width:0"
    # The column floor may never exceed the container, or the grid forces the page wider.
    assert "minmax(min(18rem, 100%), 1fr)" in " ".join(rules(".aw-cols"))


def test_selects_in_the_workspace_are_capped_to_their_container():
    body = " ".join(rules(".aw-actions select"))
    assert "width: 100%" in body and "max-width: 32rem" in body


def test_every_sideways_scroller_is_keyboard_reachable_and_named():
    seen = 0
    for path in sorted(COMP.glob("*.tsx")):
        src = path.read_text(encoding="utf-8")
        for m in re.finditer(r"<div className=\"aw-scroll\"([^>]*)>", src):
            seen += 1
            attrs = m.group(1)
            assert "tabIndex={0}" in attrs, f"{path.name}: .aw-scroll without tabIndex"
            assert 'role="region"' in attrs, f"{path.name}: .aw-scroll without role=region"
            assert re.search(r'aria-label="[^"]+"', attrs), f"{path.name}: .aw-scroll without aria-label"
    assert seen >= 12, "expected the workspace's tables to be wrapped in .aw-scroll"


def test_no_workspace_table_sits_outside_a_scroller():
    """Each ``<table className="aw-table"`` is the first thing inside an ``.aw-scroll`` wrapper."""
    tables = wrapped = 0
    for path in sorted(COMP.glob("*.tsx")):
        src = path.read_text(encoding="utf-8")
        tables += len(re.findall(r"<table className=\"aw-table\"", src))
        wrapped += len(re.findall(r"<div className=\"aw-scroll\"[^>]*>\s*<table className=\"aw-table\"", src))
    assert tables >= 12 and tables == wrapped, f"{tables} tables, {wrapped} wrapped in .aw-scroll"
