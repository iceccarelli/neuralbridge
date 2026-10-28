"""The HTML report never reads a chain that does not verify as cover.

``Fleet`` already refuses to call a machine ``covered`` or ``covered_at_community`` on a ledger
whose chain does not verify (verdict ``gaps``). The report's tiles and pills are drawn from the
per-function coverage underneath that verdict, so they have to respect the same rule: the banner
above them says the store is in question, and the numbers beneath it must not say "covered".
"""

from __future__ import annotations

import re

from assurance.report.render import ReportInput, render_report

from .test_assurance_community_is_not_verified import _community_ledger, _validated_ledger
from .test_assurance_merge_interactions import _break_the_chain


def _tiles(html: str) -> dict[str, tuple[str, str]]:
    """label -> (tone, value)"""
    return {m.group(3): (m.group(1).strip(), m.group(2)) for m in re.finditer(
        r'<div class="tile ([^"]*)"><div class="n">([^<]*)</div><div class="k">([^<]*)</div>',
        html)}


def _coverage_tile(tiles):
    (label,) = [k for k in tiles if k.startswith("functions with a recorded verification")]
    return label, tiles[label]


class TestABrokenChainIsNotCover:
    def _page(self, tmp_path, make):
        led = make(tmp_path)
        _break_the_chain(led)
        return render_report(ReportInput(ledger=led))

    def test_the_coverage_tile_is_not_good_and_says_why_for_validated_evidence(self, tmp_path):
        html = self._page(tmp_path, _validated_ledger)
        assert "THE LEDGER CHAIN DOES NOT VERIFY" in html
        label, (tone, _) = _coverage_tile(_tiles(html))
        assert tone in ("warn", "bad")
        assert "chain" in label and "not verif" in label

    def test_the_coverage_tile_is_not_good_for_community_evidence_either(self, tmp_path):
        html = self._page(tmp_path, _community_ledger)
        label, (tone, _) = _coverage_tile(_tiles(html))
        assert tone in ("warn", "bad") and "chain" in label

    def test_no_count_is_presented_as_zero_when_nothing_was_assessed(self, tmp_path):
        tiles = _tiles(self._page(tmp_path, _validated_ledger))
        for label in ("stale", "otherwise uncovered"):
            tone, value = tiles[label]
            assert value != "0", label
            assert tone in ("warn", "bad"), label

    def test_no_function_wears_the_green_current_pill(self, tmp_path):
        html = self._page(tmp_path, _validated_ledger)
        assert "class='pill current'" not in html


class TestAChainThatVerifiesIsUnchanged:
    def test_validated_cover_is_a_good_tile_with_real_counts(self, tmp_path):
        html = render_report(ReportInput(ledger=_validated_ledger(tmp_path)))
        tiles = _tiles(html)
        assert _coverage_tile(tiles) == (
            "functions with a recorded verification (tier validated)", ("good", "1"))
        assert tiles["otherwise uncovered"] == ("", "0") and tiles["stale"] == ("", "0")
        assert "class='pill current'" in html

    def test_community_only_cover_stays_a_warn_tile_naming_its_tier(self, tmp_path):
        html = render_report(ReportInput(ledger=_community_ledger(tmp_path)))
        assert _coverage_tile(_tiles(html)) == (
            "functions with a recorded verification (tier community)", ("warn", "1"))
