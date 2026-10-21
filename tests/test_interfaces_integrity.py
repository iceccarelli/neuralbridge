"""Reports, exports and case reads are made from validated records.

A ledger whose chain does not verify is an incident. Every surface that would
present its contents as fact refuses, or says so first and loudly; none of them
quietly shows the last state that still hashes. And a report that is produced
carries every limit the engines stated, verbatim, and claims no more than the
records support.
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
from pathlib import Path

import pytest

from assurance.change import CaseStore
from assurance.evidence.ledger import EvidenceLedger
from assurance.report.render import ReportInput, render_report

from . import test_assurance_change as _change
from .interfaces_scenario import Plant, run_cli

client = _change.client
account_store = _change.account_store
keyed = _change.keyed

BANNER = "THE LEDGER CHAIN DOES NOT VERIFY"


def tamper(path: Path, subject: str) -> None:
    """Edit the newest record of ``subject`` in place, as an insider with a text editor would."""
    db = sqlite3.connect(path)
    try:
        cur = db.execute(
            "UPDATE chain SET payload = replace(payload, 'safety_relevant', 'safe__relevant') "
            "WHERE seq = (SELECT MAX(seq) FROM chain WHERE subject = ?)", (subject,))
        assert cur.rowcount == 1
        db.commit()
    finally:
        db.close()


@pytest.fixture
def plant(tmp_path):
    p = Plant(tmp_path / "plant")
    p.enrol_and_change("cli")
    cid = p.expected_drift_case_id()
    r = run_cli("change", "claim", cid, "--ledger", p.ledger_path, "--owner", "v.grimaldi",
                "--actor", "v.grimaldi")
    assert r.returncode == 0, r.stderr
    return p


class TestTheCommandLineRefusesATamperedLedger:
    @pytest.fixture
    def tampered(self, plant):
        cid = plant.expected_drift_case_id()
        tamper(plant.ledger_path, cid)
        ok, _ = EvidenceLedger(plant.ledger_path).verify_chain()
        assert not ok
        return plant, cid

    @pytest.mark.parametrize("verb", ["show", "list"])
    def test_reads_say_so_first_and_show_no_case(self, tampered, verb):
        plant, cid = tampered
        argv = ["change", verb, *([cid] if verb == "show" else []),
                "--ledger", plant.ledger_path]
        r = run_cli(*argv)
        assert r.returncode == 2
        assert r.stderr.splitlines()[0].startswith(BANNER)
        assert cid not in r.stdout and r.stdout.strip() == ""

    def test_json_reads_refuse_the_same_way(self, tampered):
        plant, cid = tampered
        for argv in (["list", "--json"], ["show", cid, "--json"]):
            r = run_cli("change", *argv, "--ledger", plant.ledger_path)
            assert r.returncode == 2 and r.stdout.strip() == ""
            assert r.stderr.startswith(BANNER)

    def test_a_write_is_refused_and_extends_nothing(self, tampered):
        plant, cid = tampered
        before = len(EvidenceLedger(plant.ledger_path))
        r = run_cli("change", "advance", cid, "--ledger", plant.ledger_path,
                    "--actor", "v.grimaldi")
        assert r.returncode == 2 and BANNER in r.stderr
        assert len(EvidenceLedger(plant.ledger_path)) == before

    def test_the_untampered_ledger_is_not_affected(self, plant):
        cid = plant.expected_drift_case_id()
        assert run_cli("change", "show", cid, "--ledger", plant.ledger_path).returncode == 1
        assert run_cli("change", "advance", cid, "--ledger", plant.ledger_path,
                       "--actor", "v.grimaldi").returncode == 0

    def test_fleet_list_leads_with_the_failure_and_does_not_exit_clean(self, tampered):
        plant, _ = tampered
        r = run_cli("fleet", "list", "--ledger", plant.ledger_path)
        assert r.returncode == 2
        assert r.stdout.splitlines()[0].startswith(BANNER)


class TestTheHostedApiRefusesATamperedLedger:
    def _case(self, client, account_store):
        headers = keyed(account_store, "cell")
        r = client.post("/v1/change/assess/drift",
                        json={"baseline": _change.manifest(manifest_id="BASE").to_dict(),
                              "observed": _change.manifest(
                                  _change.item(content_hash="d" * 64),
                                  manifest_id="NOW").to_dict()}, headers=headers)
        return headers, r.json()["case"]["case_id"]

    def test_reads_and_writes_are_500_ledger_integrity_and_write_nothing(
            self, client, account_store):
        from assurance.api import deps

        headers, cid = self._case(client, account_store)
        (account_id,) = _ids(account_store)
        path = deps.tenant_ledger_path(account_id)
        assert client.get(f"/v1/change/cases/{cid}", headers=headers).status_code == 200
        tamper(path, cid)
        before = len(EvidenceLedger(path))
        for method, url, body in (
            ("GET", "/v1/change/cases", None),
            ("GET", f"/v1/change/cases/{cid}", None),
            ("POST", f"/v1/change/cases/{cid}/claim",
             {"owner": "v.grimaldi", "actor": "v.grimaldi"}),
            ("POST", f"/v1/change/cases/{cid}/decision",
             {"disposition": "rejected", "reason": "r", "actor": "v.grimaldi"}),
        ):
            r = client.request(method, url, json=body, headers=headers)
            assert r.status_code == 500, (url, r.status_code, r.text)
            assert r.json()["detail"]["error"] == "ledger_integrity"
            assert "does not verify" in r.json()["detail"]["detail"]
        assert len(EvidenceLedger(path)) == before

    def test_the_fleet_json_and_report_say_so_too(self, client, account_store):
        from assurance.api import deps

        headers, cid = self._case(client, account_store)
        (account_id,) = _ids(account_store)
        tamper(deps.tenant_ledger_path(account_id), cid)
        fleet = client.get("/v1/fleet/machines", headers=headers).json()
        assert fleet["chain_verified"] is False and fleet["chain_problems"]
        page = client.get("/v1/fleet/report", headers=headers)
        assert page.status_code == 200
        assert_banner_first(page.text)


def _ids(store) -> list[str]:
    db = sqlite3.connect(store.path)
    try:
        return [r[0] for r in db.execute("SELECT id FROM accounts")]
    finally:
        db.close()


def assert_banner_first(page: str) -> None:
    upper = page.upper()
    assert "DOES NOT VERIFY" in upper
    first = upper.index("THE LEDGER CHAIN DOES NOT VERIFY")
    # before the tiles, every section and every finding
    for later in ("<DIV CLASS='TILES'>", "<SECTION>", "MACHINE BY MACHINE"):
        assert first < upper.index(later), later
    assert "banner bad" in page[:page.index("<div class='tiles'>")]


class TestTheReport:
    def test_a_tampered_ledger_puts_the_failure_before_everything_else(self, plant, tmp_path):
        tamper(plant.ledger_path, plant.expected_drift_case_id())
        out = tmp_path / "r.html"
        r = run_cli("report", "build", "--ledger", plant.ledger_path, "--out", out)
        assert r.returncode == 0                       # it is a report: it says so, loudly
        assert_banner_first(out.read_text(encoding="utf-8"))

    def test_an_intact_ledger_says_it_verifies_and_has_no_failure_banner(self, plant, tmp_path):
        out = tmp_path / "r.html"
        run_cli("report", "build", "--ledger", plant.ledger_path, "--out", out)
        page = out.read_text(encoding="utf-8")
        assert "Ledger chain verifies." in page and "DOES NOT VERIFY" not in page.upper()

    def test_every_limit_the_engines_stated_is_in_the_report_verbatim(self, plant):
        from assurance.fleet.registry import Fleet

        ledger = EvidenceLedger(plant.ledger_path)
        extra = ("a limit from the caller, with <angle> & ampersand \"quotes\"",)
        page = render_report(ReportInput(ledger=ledger, extra_limits=extra))
        stated = [c for rec in Fleet.from_ledger(ledger).records
                  for c in rec.coverage.checks_skipped] + list(extra)
        assert len(set(stated)) >= 2
        listed = page[page.index("<ol class='limits'>"):page.index("</ol>")]
        for limit in dict.fromkeys(stated):
            assert html.escape(limit, quote=True) in listed, limit

    def test_the_kit_report_carries_every_kit_limit(self, tmp_path):
        from assurance.kit.enrol import KitConfig, run_kit

        plant = Plant(tmp_path / "kit")
        run = run_kit(KitConfig.from_json(plant.root / "kit.json"), plant.root / "out")
        page = Path(run.report_path).read_text(encoding="utf-8")
        assert run.checks_skipped
        for limit in run.checks_skipped:
            assert html.escape(limit, quote=True) in page, limit


FORBIDDEN = [
    r"\bcompliant\b", r"\bcertified\b", r"proof of safety", r"\bguarantee",
    r"\b(is|are|be|now) safe\b", r"fully (covered|verified|compliant)", r"safe to (run|operate|use)",
    r"passes? (the )?compliance", r"\bapproved\b",
]


def strip_disclaimer(text: str) -> str:
    return re.sub(r"<p class='disclaimer'>.*?</p>", "", text, flags=re.S)


class TestTheReportClaimsNoMoreThanItKnows:
    def test_the_renderer_and_its_templates_contain_no_overclaim(self):
        root = Path(__file__).resolve().parents[1] / "src" / "assurance"
        files = [*sorted((root / "report").glob("*.py")), *sorted((root / "kit").glob("*.py"))]
        assert files
        negation = re.compile(r"\b(not|never|no|nor|cannot|n't|neither|without)\b", re.I)
        offenders = []
        for f in files:
            for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if any(re.search(p, line, re.I) for p in FORBIDDEN) and not negation.search(line):
                    offenders.append(f"{f.name}:{n}: {line.strip()}")
        assert offenders == []

    def test_a_generated_report_over_every_coverage_state_contains_none(self, tmp_path):
        from assurance.report.demo import DEMO_NOTICE, build_demo

        fleet = build_demo(tmp_path / "demo")
        page = render_report(ReportInput(
            ledger=EvidenceLedger(fleet.ledger_path), advisory=fleet.advisory,
            declarations=fleet.declarations, notice=DEMO_NOTICE))
        body = strip_disclaimer(page)
        for pattern in FORBIDDEN:
            assert not re.search(pattern, body, re.I), pattern
        # the states the demo reaches are the ones a reader could over-read
        for word in ("Current", "Stale"):
            assert word in page

    def test_the_footer_says_what_a_report_is_not(self, plant, tmp_path):
        out = tmp_path / "r.html"
        run_cli("report", "build", "--ledger", plant.ledger_path, "--out", out)
        page = out.read_text(encoding="utf-8")
        m = re.search(r"<p class='disclaimer'>(.*?)</p>", page, re.S)
        assert m, "the report must carry a disclaimer paragraph"
        text = m.group(1).lower()
        for must in ("not a declaration of conformity", "not a certification",
                     "does not say that any machine is safe"):
            assert must in text

    def test_the_page_declares_its_encoding(self, plant, tmp_path):
        """It contains typographic quotes and goes into an email: a reader that
        guesses the encoding shows mojibake."""
        out = tmp_path / "r.html"
        run_cli("report", "build", "--ledger", plant.ledger_path, "--out", out)
        page = out.read_text(encoding="utf-8")
        assert page.lstrip().lower().startswith("<!doctype html>")
        assert '<meta charset="utf-8">' in page.lower()
        assert "<html" in page.lower() and "<head>" in page.lower()
        json.dumps(page)                                  # it is text, not bytes


class TestAnEmptyBundleVerifiesNothing:
    """`GET /v1/cases/{unknown}/export` and `art14 export <unknown>` emit a
    well-formed bundle with no entries; `evidence verify` used to call it VERIFIED."""

    def test_a_subject_bundle_with_no_entries_does_not_verify(self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "l.db")
        _change.drive(ledger, CaseStore(ledger), _change.CaseStatus.OPEN)
        bundle = ledger.export(subject="case-doesnotexist")
        assert bundle["entries"] == []
        path = tmp_path / "empty.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        r = run_cli("evidence", "verify", path)
        assert r.returncode == 1
        assert "DOES NOT VERIFY" in r.stdout and "no entries" in r.stdout

    def test_a_real_subject_bundle_still_verifies(self, tmp_path):
        ledger = EvidenceLedger(tmp_path / "l.db")
        case, _ = _change.drive(ledger, CaseStore(ledger), _change.CaseStatus.OPEN)
        path = tmp_path / "ok.json"
        path.write_text(json.dumps(ledger.export(subject=case.case_id)), encoding="utf-8")
        assert run_cli("evidence", "verify", path).returncode == 0


def test_case_store_requires_an_intact_chain(tmp_path):
    from assurance.core.errors import LedgerIntegrityError

    ledger = EvidenceLedger(tmp_path / "l.db")
    case, _ = _change.drive(ledger, CaseStore(ledger), _change.CaseStatus.OPEN)
    tamper(ledger.path, case.case_id)
    with pytest.raises(LedgerIntegrityError, match="does not verify"):
        CaseStore(ledger).require_intact()
