"""Tests for the demo fleet and the evidence report.

The report is the only surface anyone who is not an engineer at a terminal will
ever see, so the tests here are about what it must never do: lose the chain
status, bury the limitations, reach the network, or claim a machine is covered
when its evidence has lapsed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.registry import Fleet
from assurance.report.demo import DEMO_NOTICE, build_demo
from assurance.report.render import ReportInput, render_report


@pytest.fixture(scope="module")
def demo(tmp_path_factory) -> tuple[Path, object]:
    work = tmp_path_factory.mktemp("demo")
    fleet = build_demo(work)
    return work, fleet


@pytest.fixture(scope="module")
def page(demo) -> str:
    work, fleet = demo
    return render_report(ReportInput(
        ledger=EvidenceLedger(fleet.ledger_path),
        organisation="Grimaldi Engineering",
        prepared_by="tests",
        advisory=fleet.advisory,
        declarations=fleet.declarations,
        notice=DEMO_NOTICE,
    ))


# =====================================================================
# the demo is real, not a fixture
# =====================================================================

class TestDemo:
    def test_it_builds_a_chain_that_verifies(self, demo):
        _, fleet = demo
        ok, problems = EvidenceLedger(fleet.ledger_path).verify_chain()
        assert ok, problems

    def test_it_enrols_four_machines(self, demo):
        _, fleet = demo
        assert len(Fleet.from_ledger(EvidenceLedger(fleet.ledger_path))) == 4

    def test_the_manifests_were_really_collected_from_files(self, demo):
        """Not hand-written: the exports exist and were hashed through the rules."""
        work, fleet = demo
        assert (fleet.exports_root / "0412" / "scanner-zones.cfg").is_file()
        assert (fleet.exports_root / "0412" / "plc-project.zip").is_file()

    def test_the_export_headers_differ_and_two_clean_machines_still_agree(self, demo):
        """0412 and 0501 differ only in the zone radius, not in the stamps."""
        _, fleet = demo
        f = Fleet.from_ledger(EvidenceLedger(fleet.ledger_path))
        a = f.record("Grimaldi/AR-7#0412").manifest
        b = f.record("Grimaldi/AR-7#0620").manifest
        assert a.item("ITM-PLC").content_hash == b.item("ITM-PLC").content_hash
        assert a.item("ITM-ZONES").content_hash == b.item("ITM-ZONES").content_hash

    def test_every_manifest_reaches_tier_validated(self, demo):
        _, fleet = demo
        f = Fleet.from_ledger(EvidenceLedger(fleet.ledger_path))
        assert all(r.manifest.tier_ceiling.value == "validated" for r in f.records)

    def test_one_machine_is_stale_from_a_real_intervention(self, demo):
        _, fleet = demo
        f = Fleet.from_ledger(EvidenceLedger(fleet.ledger_path))
        r = f.record("Grimaldi/AR-7#0501")
        assert r.stale_count == 1
        assert r.coverage.stale[0].invalidated_by == "INT-0501-0007"

    def test_the_advisory_lands_confirmed_contradictory_and_clear(self, demo):
        from assurance.fleet.impact import assess_impact
        _, fleet = demo
        f = Fleet.from_ledger(EvidenceLedger(fleet.ledger_path))
        impact = assess_impact(fleet.advisory, f)
        assert len(impact.confirmed) == 2          # 0412 and 0501
        assert len(impact.contradictory) == 1      # 0418, relabelled artefact
        assert "Grimaldi/AR-7#0620" not in impact.machines_affected  # remedied

    def test_the_ledger_says_it_is_demonstration_data(self):
        assert "do not exist" in DEMO_NOTICE


# =====================================================================
# the report
# =====================================================================

class TestReport:
    def test_it_is_self_contained(self, page):
        """No network, no scripts: it opens in a plant with no internet."""
        assert "<script" not in page
        assert "cdnjs" not in page and "fonts.googleapis" not in page

    def test_the_only_url_is_the_advisory_reference(self, page):
        urls = re.findall(r"https?://[^\s\"'<]+", page)
        assert urls == ["https://controlco.example/advisories/CTRL-2026-11"]

    def test_the_chain_status_comes_before_any_finding(self, page):
        assert page.index("Ledger chain verifies") < page.index("Component advisory")

    def test_a_broken_chain_is_shouted_at_the_top(self, demo, tmp_path):
        import sqlite3
        _, fleet = demo
        # A plain file copy of a WAL database leaves the write-ahead log behind
        # and can arrive without its records, or without the schema at all.
        broken = EvidenceLedger(fleet.ledger_path).snapshot_to(tmp_path / "broken.db")
        db = sqlite3.connect(broken)
        try:
            db.execute("UPDATE chain SET subject = 'tampered' WHERE seq = 2")
            db.commit()
        finally:
            db.close()
        html = render_report(ReportInput(ledger=EvidenceLedger(broken)))
        assert "THE LEDGER CHAIN DOES NOT VERIFY" in html
        assert html.index("DOES NOT VERIFY") < html.index("Fleet")

    def test_the_limitations_are_a_numbered_section_not_a_footnote(self, page):
        assert "What this report does not establish" in page
        assert "<ol class='limits'>" in page

    def test_every_engine_limitation_survives_into_the_page(self, demo):
        _, fleet = demo
        f = Fleet.from_ledger(EvidenceLedger(fleet.ledger_path))
        html = render_report(ReportInput(ledger=EvidenceLedger(fleet.ledger_path)))
        for caveat in f.records[0].coverage.checks_skipped:
            assert caveat[:60] in html

    def test_a_stale_function_is_named_with_the_change_that_caused_it(self, page):
        assert "INT-0501-0007" in page
        assert "Stale" in page

    def test_it_says_how_many_days_a_function_has_been_uncovered(self, page):
        assert re.search(r"Running \d+ day\(s\) without valid evidence", page)

    def test_a_not_demonstrable_function_is_never_shown_as_covered(self, page):
        assert "Not demonstrable" in page
        assert "SF-03" in page

    def test_the_contradictory_machine_is_called_out_as_neither(self, page):
        assert "Counted in neither column" in page
        assert "contradictory" in page

    def test_the_declaration_verdict_appears_per_machine(self, page):
        assert "DOC-AR7-0412" in page
        assert "DOC-AR7-0501" in page

    def test_it_refuses_to_give_legal_advice_in_the_footer(self, page):
        assert "Nothing in this report is legal advice" in page

    def test_it_tells_the_reader_how_to_check_it_without_trusting_us(self, page):
        assert "without trusting whoever sent it" in page

    def test_html_from_the_data_is_escaped(self, tmp_path):
        """A machine or site name is attacker-controlled in a hosted deployment."""
        from datetime import UTC, datetime

        from assurance.core.evidence import Actor
        from assurance.machinery.manifest import (
            HashSource,
            ItemKind,
            MachineIdentity,
            ManifestSource,
            SafetyItem,
            SafetyManifest,
        )
        from assurance.machinery.record import record_manifest

        ledger = EvidenceLedger(tmp_path / "x.db")
        record_manifest(ledger, SafetyManifest(
            manifest_id="M", source=ManifestSource.AS_FOUND,
            machine=MachineIdentity("G", "M", "1",
                                    site="<script>alert(1)</script>"),
            taken_at=datetime(2026, 9, 1, tzinfo=UTC),
            taken_by=Actor("a", "b"),
            items=(SafetyItem("I", ItemKind.FIRMWARE, "fw", "1", "a" * 64,
                              HashSource.READ_FROM_MACHINE),)))
        html = render_report(ReportInput(ledger=ledger))
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;" in html

    def test_the_notice_is_carried_when_given(self, page):
        assert "DEMONSTRATION DATA" in page

    def test_an_empty_ledger_renders_without_falling_over(self, tmp_path):
        html = render_report(ReportInput(ledger=EvidenceLedger(tmp_path / "e.db")))
        assert "Machine safety evidence report" in html


# =====================================================================
# HTTP
# =====================================================================

@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from assurance.api import deps

    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "l.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "a.db"))
    monkeypatch.delenv("ASSURANCE_API_KEYS", raising=False)
    monkeypatch.delenv("ASSURANCE_ALLOW_UNAUTHENTICATED", raising=False)
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    from assurance.api.service import create_app

    with TestClient(create_app()) as c:
        yield c
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


class TestHttp:
    def test_the_report_needs_the_cell_plan(self, client):
        from assurance.api import deps
        store = deps.get_accounts()
        account = store.upsert_account(email="r@example.de", tier="register")
        key = store.issue_key(account.id)
        assert client.get("/v1/fleet/report",
                          headers={"X-API-Key": key}).status_code == 402

    def test_the_cell_plan_gets_html(self, client):
        from assurance.api import deps
        store = deps.get_accounts()
        account = store.upsert_account(email="c@example.de", tier="cell")
        key = store.issue_key(account.id)
        r = client.get("/v1/fleet/report", headers={"X-API-Key": key})
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "Machine safety evidence report" in r.text
