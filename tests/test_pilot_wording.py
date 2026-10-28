"""Wording that read as more than the code establishes, pinned so it cannot drift back.

Each assertion here is the other half of a deliberate edit: the headline of a PASS over a trace
nobody attested, the coverage line that said "verified ... at tier profile; no recorded
intervention since has touched an item", the report tile and footer, the plan card, the kit's
COMPLETE, and the claims about what is uploaded.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import UTC, datetime
from pathlib import Path

from assurance.billing.plans import PLANS
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import build_bundle
from assurance.machine.verify import Verdict
from assurance.machinery.record import record_manifest
from assurance.machinery.staleness import Coverage, assess_coverage
from assurance.report.demo import build_demo
from assurance.report.render import ReportInput, render_report

from .support_recorder import build_attested_bundle
from .test_assurance_change import _inputs
from .test_assurance_machinery import manifest, verification

ROOT = Path(__file__).resolve().parent.parent
ACTOR = Actor(identifier="v.grimaldi", role="verification engineer", kind="person")


def _bundle(*, attested: bool, tier_floor: bool = False):
    env, run = _inputs(datetime(2026, 3, 1, tzinfo=UTC))
    if tier_floor:
        # A zero position uncertainty is a claim of perfect sensing: the envelope's own
        # figure sits at the profile tier whatever basis it names.
        env = dataclasses.replace(
            env, uncertainty=dataclasses.replace(env.uncertainty, human_position_mm=0.0))
    return (build_attested_bundle if attested else build_bundle)(env, run, actor=ACTOR)


class TestTheVerifyHeadline:
    def test_a_pass_over_a_self_declared_trace_says_so_in_the_headline(self):
        result = _bundle(attested=False).result
        assert result.verdict is Verdict.PASS
        head = result.summary().splitlines()[0]
        assert head.endswith(
            f"PASS (self-declared trace, not hardware-validated; tier {result.tier.value})")

    def test_a_pass_over_an_attested_trace_does_not_carry_that_label(self):
        result = _bundle(attested=True).result
        assert result.verdict is Verdict.PASS and result.provenance_basis == "recorder_attested"
        head = result.summary().splitlines()[0]
        assert "self-declared" not in head
        assert head.endswith(f"PASS at tier {result.tier.value}")

    def test_a_fail_keeps_its_plain_headline(self):
        env, run = _inputs(datetime(2026, 3, 1, tzinfo=UTC))
        run = dataclasses.replace(
            run, samples=tuple(dataclasses.replace(s, tcp_speed=900.0) for s in run.samples))
        result = build_bundle(env, run, actor=ACTOR).result
        assert result.verdict is Verdict.FAIL
        assert re.search(r"— FAIL at tier \w+$", result.summary().splitlines()[0])

    def test_the_caveat_never_mixes_a_lower_tier_with_a_community_cap(self):
        text = _bundle(attested=False, tier_floor=True).result.summary()
        # The sentence about the trace talks only about what the TRACE can do ...
        assert "so the trace itself cannot lift this result above community" in text
        assert "does not lift the tier above community" not in text
        # ... and a result below community says why it is lower, in its own sentence.
        lines = text.splitlines()
        head_tier = re.search(r"tier (\w+)\)?$", lines[0]).group(1)
        if head_tier in ("profile",):
            assert any(f"This result is at tier {head_tier}, below community" in ln
                       for ln in lines)


class TestTheCoverageLine:
    def _detail(self, tier):
        report = assess_coverage(manifest(), [dataclasses.replace(verification(), tier=tier)], [])
        return next(f for f in report.functions if f.function_id == "SF-01"), report

    def test_below_validated_it_says_the_evidence_is_recorded_not_validated(self):
        for tier in ("profile", "community"):
            fn, _ = self._detail(tier)
            assert fn.coverage is Coverage.CURRENT          # the state is unchanged
            assert f"evidence recorded, NOT validated (tier {tier})" in fn.detail
            assert "no intervention recorded since" in fn.detail
            assert "no recorded intervention since has touched" not in fn.detail

    def test_the_summary_line_carries_the_tier_beside_the_ok_mark(self):
        _, report = self._detail("community")
        row = next(ln for ln in report.summary().splitlines() if "SF-01" in ln and "[" in ln)
        assert "(evidence recorded, tier floor=community, NOT validated)" in row

    def test_validated_evidence_is_not_called_unvalidated(self):
        fn, report = self._detail("validated")
        assert "NOT validated" not in fn.detail and "tier validated" in fn.detail
        assert "NOT validated" not in report.summary()


class TestTheReport:
    def test_the_tile_says_recorded_verification_with_its_tier_and_the_footer_its_limit(
            self, tmp_path):
        fleet = build_demo(tmp_path)
        page = render_report(ReportInput(ledger=EvidenceLedger(fleet.ledger_path)))
        assert "functions with current evidence" not in page
        assert re.search(r"functions with a recorded verification \(tier \w+\)", page)
        assert "the run is not bound to the configuration found" in page
        assert "still describes the configuration found" not in page

    def _tile(self, tmp_path, *, attested):
        from .test_assurance_change import manifest as change_manifest
        from .test_assurance_change import seal_a_real_verification

        ledger = EvidenceLedger(tmp_path / f"l-{attested}.db")
        record_manifest(ledger, change_manifest(manifest_id="BASE"))
        seal_a_real_verification(ledger, when=datetime(2026, 2, 9, tzinfo=UTC), attested=attested)
        page = render_report(ReportInput(ledger=ledger))
        tile = re.search(r'<div class="tile ([^"]*)"><div class="n">(\d+)</div>'
                         r'<div class="k">functions with a recorded verification \(tier (\w+)\)',
                         page)
        assert tile, "no tile"
        return tile.group(1).strip(), int(tile.group(2)), tile.group(3)

    def test_with_every_function_covered_the_tile_is_good_only_at_validated(self, tmp_path):
        tone, count, tier = self._tile(tmp_path, attested=False)
        assert (count, tier) == (2, "community") and tone != "good"
        tone, count, tier = self._tile(tmp_path, attested=True)
        assert (count, tier) == (2, "validated") and tone == "good"


class TestThePlanCard:
    def test_the_cell_card_promises_what_the_join_computes_and_no_more(self):
        cell = PLANS["cell"]
        blob = " | ".join([cell.blurb, *cell.included])
        assert "have a recorded verification dated after the last recorded change" in cell.blurb
        assert "still have evidence that describes the machine" not in blob
        assert "still have valid evidence" not in blob

    def test_the_counter_signature_line_says_the_key_is_not_configured_and_what_is_uploaded(self):
        line = next(i for i in PLANS["cell"].included if i.startswith("Counter-signed head"))
        assert "none is configured on any deployment today" in line
        assert "machine verification" in line and "full trace you submit" in line
        assert "Your ledger is never uploaded" not in line

    def test_the_typescript_card_says_the_same(self):
        ts = (ROOT / "app" / "lib" / "plans.ts").read_text(encoding="utf-8")
        assert "have a recorded verification dated after the last recorded change." in ts
        assert "none is configured on any deployment today" in ts
        assert "Your ledger is never uploaded" not in ts


class TestTheKitHeadline:
    def test_the_report_and_the_run_say_what_complete_means(self, tmp_path):
        from .test_pilot_kit_provenance import _kit_manifest

        _, run, html = _kit_manifest(tmp_path)
        assert run["verdict"] == "complete"
        limit = next(c for c in run["checks_skipped"] if c.startswith("COMPLETE,"))
        assert "only that every item the collection plan names was found" in limit
        assert "only that every item the collection plan names was found" in html


class TestTheReadme:
    def _readme(self):
        return " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())

    def test_the_every_row_claim_is_followed_by_the_counter_signature_caveat(self):
        text = self._readme()
        assert "no deployment has one configured today" in text
        assert "no_attestation_key_configured" in text

    def test_no_account_no_key_is_stated_as_true_of_the_kit_only(self):
        text = self._readme()
        assert "For the kit: no account, no API key, no upload" in text
        assert "not true of the hosted service" in text
