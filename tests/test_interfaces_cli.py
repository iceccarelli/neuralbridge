"""The ``assurance change`` command line answers the way the HTTP API does.

The domain functions are the same; these tests pin the places where an
interface could still say something different: an unknown case, the queue
document, the export.
"""

from __future__ import annotations

import json

import pytest

from assurance.change import CaseStatus, CaseStore
from assurance.change.cli import main as change_main
from assurance.change.model import queue_summary
from assurance.evidence.ledger import EvidenceLedger

from .test_assurance_change import drive, manifest


def run(*argv) -> int:
    return change_main([str(a) for a in argv])


@pytest.fixture
def ledger_path(tmp_path):
    return tmp_path / "l.db"


class TestAnUnknownCaseIsExitTwoOnEveryVerb:
    """``show`` exited 2 and every other verb exited 1 for the same id (the HTTP
    twin: GET 404, POST 409). Unknown is 'could not run' everywhere: exit 2."""

    VERBS = [
        ("show",),
        ("claim", "--owner", "v.grimaldi", "--actor", "v.grimaldi"),
        ("advance", "--actor", "v.grimaldi"),
        ("decide", "--disposition", "rejected", "--reason", "r", "--actor", "v.grimaldi"),
        ("resume", "--reason", "r", "--actor", "v.grimaldi"),
        ("resolve-decision", "--number", "1", "--resolution", "r", "--actor", "v.grimaldi"),
        ("waive-reverification", "--entry", "SF-01", "--reason", "r",
         "--actor", "v.grimaldi"),
        ("replay",),
        ("export",),
    ]

    @pytest.mark.parametrize("verb", VERBS, ids=[v[0] for v in VERBS])
    def test_exit_two_and_no_case_on_stderr(self, ledger_path, tmp_path, capsys, verb):
        EvidenceLedger(ledger_path)
        extra = ["--out", tmp_path / "x.json"] if verb[0] == "export" else []
        capsys.readouterr()
        rc = run(verb[0], "--ledger", ledger_path, "case-doesnotexist", *verb[1:], *extra)
        err = capsys.readouterr().err
        assert rc == 2, (verb, err)
        assert "no case 'case-doesnotexist'" in err

    def test_reverify_too(self, ledger_path, tmp_path, capsys):
        EvidenceLedger(ledger_path)
        m = tmp_path / "m.json"
        m.write_text(json.dumps(manifest().to_dict()))
        rc = run("reverify", "--ledger", ledger_path, "case-doesnotexist",
                 "--manifest", m, "--verification-hash", "a" * 64, "--actor", "v.grimaldi")
        assert rc == 2
        assert "no case" in capsys.readouterr().err

    def test_a_reserved_name_does_not_hide_an_unknown_case(self, ledger_path, capsys):
        EvidenceLedger(ledger_path)
        assert run("resume", "--ledger", ledger_path, "case-nope", "--reason", "r",
                   "--actor", "automation") == 2

    def test_a_refused_transition_is_still_exit_one(self, ledger_path, capsys):
        ledger = EvidenceLedger(ledger_path)
        case, _ = drive(ledger, CaseStore(ledger), CaseStatus.OPEN)
        assert run("decide", "--ledger", ledger_path, case.case_id, "--disposition",
                   "closed", "--reason", "early", "--actor", "v.grimaldi") == 1
        assert "finding" in capsys.readouterr().err


class TestTheQueueDocumentIsTheAPIs:
    def test_list_json_has_cases_rows_and_the_shared_summary(self, ledger_path, capsys):
        ledger = EvidenceLedger(ledger_path)
        store = CaseStore(ledger)
        drive(ledger, store, CaseStatus.OPEN)
        capsys.readouterr()
        rc = run("list", "--ledger", ledger_path, "--json")
        doc = json.loads(capsys.readouterr().out)
        cases = store.list()
        assert rc == 1                                    # one is open
        assert doc == {"cases": [c.row() for c in cases], "summary": queue_summary(cases)}
        assert doc["summary"]["open"] == 1

    def test_a_deferred_case_is_counted_and_exit_is_zero_with_nothing_open(
            self, ledger_path, capsys):
        ledger = EvidenceLedger(ledger_path)
        store = CaseStore(ledger)
        drive(ledger, store, CaseStatus.DEFERRED)
        capsys.readouterr()
        assert run("list", "--ledger", ledger_path, "--json") == 0
        doc = json.loads(capsys.readouterr().out)
        assert doc["summary"]["open"] == 0 and doc["summary"]["deferred"] == 1
        assert doc["cases"][0]["status"] == "deferred"
        assert run("list", "--ledger", ledger_path) == 0
        assert "1 deferred" in capsys.readouterr().out

    def test_status_filter_matches_the_api_filter(self, ledger_path, capsys):
        ledger = EvidenceLedger(ledger_path)
        store = CaseStore(ledger)
        drive(ledger, store, CaseStatus.REJECTED)
        capsys.readouterr()
        run("list", "--ledger", ledger_path, "--status", "rejected", "--json")
        assert len(json.loads(capsys.readouterr().out)["cases"]) == 1
        run("list", "--ledger", ledger_path, "--status", "open", "--json")
        assert json.loads(capsys.readouterr().out)["cases"] == []

    def test_a_bad_status_is_exit_two_not_a_traceback(self, ledger_path, capsys):
        EvidenceLedger(ledger_path)
        assert run("list", "--ledger", ledger_path, "--status", "finished") == 2


class TestExport:
    def test_a_case_exported_by_the_cli_verifies_offline(self, ledger_path, tmp_path, capsys):
        from assurance.evidence.cli import main as evidence_main

        ledger = EvidenceLedger(ledger_path)
        store = CaseStore(ledger)
        case, _ = drive(ledger, store, CaseStatus.CLOSED)
        out = tmp_path / "case.json"
        assert run("export", "--ledger", ledger_path, case.case_id, "--out", out) == 0
        bundle = json.loads(out.read_text())
        assert bundle["subject"] == case.case_id
        assert {e["kind"] for e in bundle["entries"]} >= {
            "assurance.change.opened", "assurance.change.decision"}
        capsys.readouterr()
        assert evidence_main(["verify", str(out)]) == 0
        assert "VERIFIED" in capsys.readouterr().out

    def test_export_refuses_a_ledger_that_does_not_verify(self, ledger_path, tmp_path, capsys):
        import sqlite3

        ledger = EvidenceLedger(ledger_path)
        case, _ = drive(ledger, CaseStore(ledger), CaseStatus.OPEN)
        db = sqlite3.connect(ledger_path)
        try:
            db.execute("UPDATE chain SET payload = replace(payload, 'drift', 'dxift') "
                       "WHERE seq = (SELECT MAX(seq) FROM chain)")
            db.commit()
        finally:
            db.close()
        out = tmp_path / "case.json"
        capsys.readouterr()
        assert run("export", "--ledger", ledger_path, case.case_id, "--out", out) == 2
        assert "does not verify" in capsys.readouterr().err
        assert not out.exists()

    def test_a_subject_that_is_not_a_case_is_not_exported_as_one(self, ledger_path, tmp_path,
                                                                 capsys):
        from .test_assurance_change import MACHINE

        ledger = EvidenceLedger(ledger_path)
        drive(ledger, CaseStore(ledger), CaseStatus.OPEN)         # seals a manifest for MACHINE
        out = tmp_path / "x.json"
        assert run("export", "--ledger", ledger_path, MACHINE.key, "--out", out) == 2
        assert not out.exists()


class TestArt14ExportOfAnUnknownCase:
    """`art14 export <unknown>` wrote a well-formed bundle with no entries."""

    def test_unknown_is_exit_two_and_writes_nothing(self, ledger_path, tmp_path, capsys):
        from assurance.security.art14.cli import main as art14_main

        EvidenceLedger(ledger_path)
        out = tmp_path / "x.json"
        capsys.readouterr()
        rc = art14_main(["--ledger", str(ledger_path), "export", "--case", "C-nope",
                         "-o", str(out)])
        assert rc == 2
        assert "no case 'C-nope'" in capsys.readouterr().err
        assert not out.exists()

    def test_a_known_case_still_exports(self, ledger_path, tmp_path):
        from assurance.security.art14.cli import main as art14_main

        ledger = EvidenceLedger(ledger_path)
        case, _ = drive(ledger, CaseStore(ledger), CaseStatus.OPEN)
        out = tmp_path / "x.json"
        assert art14_main(["--ledger", str(ledger_path), "export", "--case", case.case_id,
                           "-o", str(out)]) == 0
        assert json.loads(out.read_text())["subject"] == case.case_id
