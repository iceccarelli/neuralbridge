"""Round 2: the watch, the exported case, the public copy and the first-run leftovers.

Each class is one finding of the independent review of the first pass:

* ``watch run`` said QUIET for a manifest the same branch refuses as "not a look at the machine",
  while ``watch push`` of the same ledger refused it.
* an exported change case carried ``hash_source: read_from_machine`` without saying that the
  label is only the operator's assertion.
* public copy that still sold the counter-signature unqualified, called the install extra
  something it is not, or kept "valid evidence".
* three small leftovers: a config value that is not JSON ``true`` must not assert; the parity
  harness had no branch for exit 3; the unit-key warning was a third copy of the grammar.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from assurance.billing.plans import PLANS
from assurance.change.cli import main as change_main
from assurance.change.service import assess_drift
from assurance.change.store import CaseStore
from assurance.collect.collector import collect
from assurance.core.evidence import Actor
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.divergence import compare
from assurance.machinery.manifest import HashSource
from assurance.machinery.record import record_manifest
from assurance.watch.cli import main as watch_main
from assurance.watch.config import WatchConfig, WatchTarget

from .support import plan, plan_dict, write_export

ROOT = Path(__file__).resolve().parent.parent
ENG = Actor(identifier="m.keller", role="engineer", kind="person")


def _watch_dir(tmp_path, *, flag):
    (tmp_path / "plan.json").write_text(json.dumps(plan_dict()))
    write_export(tmp_path / "0412", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    target = {"serial": "0412", "plan": "plan.json", "root": "0412", "site": "Plant 2",
              "country": "DE"}
    if flag is not None:
        target["read_from_machine"] = flag
    (tmp_path / "watch.json").write_text(json.dumps(
        {"watch_id": "W", "max_age_hours": 168, "targets": [target]}))
    return tmp_path / "watch.json", tmp_path / "ev.db"


def _run(capsys, cfg, ledger):
    capsys.readouterr()
    rc = watch_main(["run", str(cfg), "--ledger", str(ledger), "--json"])
    return rc, json.loads(capsys.readouterr().out)


class TestWatchDoesNotCallAnExportFolderQuiet:
    def test_an_unchanged_export_folder_is_not_a_quiet_fleet(self, tmp_path, capsys):
        cfg, ledger = _watch_dir(tmp_path, flag=None)
        _run(capsys, cfg, ledger)
        rc, body = _run(capsys, cfg, ledger)
        (outcome,) = body["outcomes"]
        assert outcome["status"] == "observed"                  # the hash did not move
        assert body["verdict"] == "degraded" and rc == 2        # but nobody looked at the machine
        assert "export folder, not a look at the machine" in outcome["detail"]
        assert "supplied by a vendor" in outcome["not_a_look"]

    def test_the_text_does_not_say_every_machine_was_looked_at(self, tmp_path, capsys):
        cfg, ledger = _watch_dir(tmp_path, flag=None)
        watch_main(["run", str(cfg), "--ledger", str(ledger)])
        capsys.readouterr()
        rc = watch_main(["run", str(cfg), "--ledger", str(ledger)])
        out = capsys.readouterr().out
        assert rc == 2
        assert "every machine was looked at" not in out
        assert "export folder, not a look at the machine" in out

    def test_a_changed_hash_over_an_export_folder_is_still_a_finding_not_degraded(
            self, tmp_path, capsys):
        cfg, ledger = _watch_dir(tmp_path, flag=None)
        _run(capsys, cfg, ledger)
        (tmp_path / "0412" / "controller-fw.bin").write_bytes(b"\x7fELF" + b"firmware 3.9.0" * 20)
        rc, body = _run(capsys, cfg, ledger)
        assert body["outcomes"][0]["status"] == "changed"
        assert body["verdict"] == "findings" and rc == 1

    def test_with_the_operators_assertion_it_is_quiet_as_before(self, tmp_path, capsys):
        cfg, ledger = _watch_dir(tmp_path, flag=True)
        _run(capsys, cfg, ledger)
        rc, body = _run(capsys, cfg, ledger)
        assert rc == 0 and body["verdict"] == "quiet"
        assert body["outcomes"][0]["not_a_look"] == ""

    def test_watch_md_documents_the_assertion(self):
        text = " ".join((ROOT / "deploy" / "assurance" / "WATCH.md").read_text().split())
        assert '"read_from_machine": true' in text
        assert "export folder" in text and "degraded" in text.lower()


class TestOnlyJsonTrueAsserts:
    @pytest.mark.parametrize("value", ["false", "true", "yes", 1, "1", 0, None, [], {}])
    def test_a_watch_target_asserts_only_for_the_json_value_true(self, value):
        target = WatchTarget.from_dict({"serial": "1", "plan": "p", "root": "r",
                                        "read_from_machine": value})
        assert target.read_from_machine is False

    def test_json_true_asserts(self):
        target = WatchTarget.from_dict({"serial": "1", "plan": "p", "root": "r",
                                        "read_from_machine": True})
        assert target.read_from_machine is True

    def test_a_string_in_the_file_does_not_label_the_manifest(self, tmp_path):
        cfg, _ = _watch_dir(tmp_path, flag="true")
        assert WatchConfig.from_json(cfg).targets[0].read_from_machine is False


class TestTheExportedCaseSaysTheLabelIsAnAssertion:
    def _export(self, tmp_path, *, asserted):
        source = HashSource.READ_FROM_MACHINE if asserted else HashSource.SUPPLIED_BY_VENDOR
        a = write_export(tmp_path / "a", stamp="2026-09-14T06:00:00Z", operator="o", seq="1")
        b = write_export(tmp_path / "b", stamp="2026-09-15T06:00:00Z", operator="o", seq="2",
                         fw=b"firmware 3.9.0")
        base = collect(plan(), a, serial="0412", taken_by=ENG, manifest_id="BASE",
                       hash_source=source,
                       taken_at=datetime(2026, 9, 14, tzinfo=UTC)).manifest
        seen = collect(plan(), b, serial="0412", taken_by=ENG, manifest_id="SEEN",
                       hash_source=source,
                       taken_at=datetime(2026, 9, 15, tzinfo=UTC)).manifest
        ledger = EvidenceLedger(tmp_path / "l.db")
        record_manifest(ledger, base)
        divergence = compare(base, seen)
        case = assess_drift(CaseStore(ledger), divergence, seen, [], [], actor=ENG)
        return divergence, case, tmp_path / "l.db"

    def test_the_item_summary_carries_the_basis(self, tmp_path):
        divergence, _, _ = self._export(tmp_path, asserted=True)
        changes = [c for c in divergence.changes if c.after]
        assert changes
        assert {c.after["hash_source"] for c in changes} == {"read_from_machine"}
        assert {c.after["hash_source_basis"] for c in changes} == {"operator_assertion"}

    def test_a_case_export_names_it_and_carries_the_limit(self, tmp_path):
        _, case, path = self._export(tmp_path, asserted=True)
        assert case is not None
        out = tmp_path / "export.json"
        assert change_main(["export", "--ledger", str(path), case.case_id, "--out", str(out)]) == 0
        bundle = json.loads(out.read_text())
        text = json.dumps(bundle)
        assert '"hash_source_basis": "operator_assertion"' in text
        limits = [c for e in bundle["entries"]
                  for c in (e.get("evidence", {}) or {}).get("checks_skipped", [])]
        assert any("labelled read_from_machine" in c and "assertion" in c for c in limits), limits

    def test_an_unasserted_export_is_labelled_for_what_it_is_and_adds_no_assertion_limit(
            self, tmp_path):
        divergence, _, _ = self._export(tmp_path, asserted=False)
        changes = [c for c in divergence.changes if c.after]
        assert {c.after["hash_source_basis"] for c in changes} == {"supplied_by_vendor"}
        assert not any("labelled read_from_machine" in c for c in divergence.checks_skipped)


class TestPublicCopyIsConsistent:
    MARKER = "configured on any deployment today"

    @pytest.mark.parametrize("rel", [
        "docs/pricing.md", "public/llms.txt", "app/components/SizingCalculator.tsx",
        "app/lib/plans.ts", "src/assurance/billing/plans.py", "README.md"])
    def test_every_place_that_sells_the_counter_signature_says_no_key_is_configured(self, rel):
        text = (" ".join(PLANS["cell"].included) if rel.endswith("plans.py")
                else " ".join((ROOT / rel).read_text(encoding="utf-8").split()))
        assert self.MARKER in text, rel

    @pytest.mark.parametrize("rel", ["README.md", "docs/getting-started.md",
                                     "src/assurance/attest/keys.py"])
    def test_the_extra_is_not_said_to_add_cryptography(self, rel):
        text = " ".join((ROOT / rel).read_text(encoding="utf-8").split())
        assert "adds only `cryptography`" not in text
        assert "adds nothing" in text and "already one of the 22 core dependencies" in text

    def test_valid_evidence_is_gone_from_the_shipped_surface(self):
        hits = []
        roots = [ROOT / "src", ROOT / "app", ROOT / "public", ROOT / "deploy", ROOT / "docs"]
        files = [p for r in roots for p in r.rglob("*")
                 if p.is_file() and p.suffix in {".py", ".ts", ".tsx", ".md", ".json", ".txt"}]
        files.append(ROOT / "README.md")
        for p in files:
            if "valid evidence" in p.read_text(encoding="utf-8", errors="ignore"):
                hits.append(str(p.relative_to(ROOT)))
        assert not hits, hits

    def test_the_route_summary_is_one_phrase_in_code_site_and_schema(self):
        phrase = "Which safety functions a recorded verification still stands for"
        for rel in ("src/assurance/api/machinery_routes.py", "app/lib/routes.ts",
                    "public/openapi.json"):
            assert phrase in (ROOT / rel).read_text(encoding="utf-8"), rel

    def test_handoff_records_what_this_work_changed(self):
        text = " ".join((ROOT / "HANDOFF.md").read_text(encoding="utf-8").split())
        for needle in ("billing grant", "read_from_machine", "exit 3", "supplied_by_vendor"):
            assert needle in text, needle

    def test_the_pilot_programme_says_the_change_needs_the_assertion(self):
        text = " ".join((ROOT / "docs" / "pmf" / "PILOT-PROGRAMME.md").read_text().split())
        assert "--read-from-machine" in text


class TestTheLeftovers:
    def test_the_parity_harness_reads_exit_three_as_an_accepted_uncleared_reverify(self):
        from .interfaces_scenario import CliDriver

        driver = CliDriver.__new__(CliDriver)
        done = subprocess.CompletedProcess([], 3, stdout="", stderr="")
        assert driver._out(done, "").kind == "ok"

    @pytest.mark.parametrize("subject", [" Acme/M#1", "Acme//M#1", "Acme/ M#1", "/M#1", "Acme/#1",
                                         "Acme/M#", "Acme/M#a#b", "Acme/M#1 ", "Acme/M# 1"])
    def test_the_unit_key_warning_uses_the_canonical_grammar_and_the_key_shape(self, subject):
        from assurance.machine.cli import _unit_key_problem

        assert _unit_key_problem(subject), subject

    @pytest.mark.parametrize("subject", ["Acme/M#1", "Grimaldi/AR-7 collaborative cell#CELL-0412"])
    def test_well_formed_keys_are_not_warned(self, subject):
        from assurance.machine.cli import _unit_key_problem

        assert _unit_key_problem(subject) == ""

    def test_machine_cli_does_not_carry_its_own_copy_of_the_grammar(self):
        src = (ROOT / "src" / "assurance" / "machine" / "cli.py").read_text()
        assert "resolve_machine_serial" in src
        assert 'subject.partition("#")' not in src

    def test_the_broken_pipe_tests_do_not_inherit_an_unbuffered_stdout(self):
        src = (ROOT / "tests" / "test_pilot_first_run.py").read_text()
        assert "PYTHONUNBUFFERED" in src

    def test_a_cleared_run_through_the_harness_is_unaffected(self):
        from .interfaces_scenario import CliDriver

        driver = CliDriver.__new__(CliDriver)
        assert driver._out(subprocess.CompletedProcess([], 0, "x", ""), "").kind == "ok"
