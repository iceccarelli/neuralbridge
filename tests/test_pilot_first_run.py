"""First-run friction found by walking the smallest paid workflow for real.

Each class is one thing a new user hit: a ``check`` that reported one placeholder at a
time, an init that said three steps where the README said another number, a
``machine verify --subject`` spelled so that coverage would never see it, an
unchecked check printed as ``[??]``, and a traceback after the ledger was already
sealed when the output was piped to ``head``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from assurance.evidence.ledger import EvidenceLedger
from assurance.kit.cli import main as kit_main
from assurance.machine.cli import main as machine_main

ROOT = Path(__file__).resolve().parent.parent
ENV = ROOT / "examples" / "machine" / "envelope.json"
TRACE = ROOT / "examples" / "machine" / "trace.json"


def _child_env() -> dict[str, str]:
    """The child's environment WITHOUT PYTHONUNBUFFERED: unbuffered output fails at the print,
    which would make the "fails only when flushed" case vacuous."""
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    env.pop("PYTHONUNBUFFERED", None)
    return env


def _tree(root: Path) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in root.rglob("*"))


# =====================================================================
class TestKitCheckNamesEveryPlaceholder:
    def _init(self, tmp_path):
        assert kit_main(["init", str(tmp_path / "plant")]) == 0
        return tmp_path / "plant"

    def test_json_lists_each_placeholder_with_its_file_and_field(self, tmp_path, capsys):
        plant = self._init(tmp_path)
        before = _tree(plant)
        capsys.readouterr()
        rc = kit_main(["check", str(plant / "kit.json"), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 2                                   # unchanged: the kit cannot run
        assert out["ready"] is False
        found = {(p["file"], p["field"]) for p in out["placeholders"]}
        assert ("kit.json", "organisation") in found
        assert ("kit.json", "prepared_by") in found
        assert ("plans/cell.json", "manufacturer") in found
        assert ("plans/cell.json", "model") in found
        for item in ("ITM-ZONES", "ITM-PARAMS", "ITM-PLC", "ITM-FW"):
            assert ("plans/cell.json", f"items.{item}.supplier") in found
        assert all(p["value"].lower() in {"change me", "your company gmbh",
                                          "your.name@yourcompany.example"}
                   for p in out["placeholders"])
        assert _tree(plant) == before                    # check reads only

    def test_text_says_it_is_the_plan_and_which_fields_and_that_nothing_ran(
            self, tmp_path, capsys):
        plant = self._init(tmp_path)
        capsys.readouterr()
        rc = kit_main(["check", str(plant / "kit.json")])
        text = " ".join(capsys.readouterr().err.split())
        assert rc == 2
        assert "plans/cell.json still has CHANGE ME placeholders" in text
        assert "manufacturer" in text and "model" in text
        assert "supplier of ITM-ZONES" in text
        assert "kit.json still has template values" in text
        assert "check only read" in text

    def test_after_kit_json_is_filled_in_the_plan_placeholders_are_still_named(
            self, tmp_path, capsys):
        plant = self._init(tmp_path)
        kit = json.loads((plant / "kit.json").read_text())
        kit.update(organisation="Acme Robotics S.r.l.", prepared_by="a.rossi@acme.example")
        (plant / "kit.json").write_text(json.dumps(kit))
        capsys.readouterr()
        rc = kit_main(["check", str(plant / "kit.json"), "--json"])
        out = json.loads(capsys.readouterr().out)
        assert rc == 1
        fields = {p["field"] for p in out["placeholders"]}
        assert {"manufacturer", "model", "items.ITM-FW.supplier"} <= fields
        assert not any(p["file"] == "kit.json" for p in out["placeholders"])


class TestInitAndReadmeAgreeOnTheSteps:
    def _steps(self, text: str) -> list[str]:
        return [" ".join(m.group(2).split())
                for m in re.finditer(r"^\s*(\d)\. (.+(?:\n {4,}\S.*)*)", text, re.M)]

    def test_the_numbered_steps_printed_by_init_are_the_readme_steps(self, tmp_path, capsys):
        assert kit_main(["init", str(tmp_path / "plant")]) == 0
        printed = self._steps(capsys.readouterr().out)
        readme = (tmp_path / "plant" / "README.md").read_text()
        before_run = readme.split("## Before you run it")[1].split("## Run it")[0]
        in_readme = self._steps(before_run)
        assert printed == in_readme
        assert len(printed) == 4
        # The two files a person must edit are named in the steps, with what to put in.
        joined = " ".join(printed)
        assert "kit.json" in joined and "plans/cell.json" in joined
        assert "manufacturer" in joined and "supplier" in joined

    def test_init_does_not_say_edit_two_files_while_listing_more(self, tmp_path, capsys):
        kit_main(["init", str(tmp_path / "plant")])
        out = capsys.readouterr().out
        assert "two files" not in out.lower()


# =====================================================================
def _verify(tmp_path, capsys, subject, *extra):
    ledger = tmp_path / "ev.db"
    capsys.readouterr()
    rc = machine_main(["verify", "--envelope", str(ENV), "--trace", str(TRACE),
                       "--actor", "v.grimaldi", "--ledger", str(ledger),
                       "--subject", subject, "--json", *extra])
    cap = capsys.readouterr()
    return rc, cap, ledger


class TestSubjectSpellingWarning:
    @pytest.mark.parametrize("subject", ["AR-7 0412", "AR-7#0412", "Grimaldi/AR-7"])
    def test_a_subject_that_is_not_a_unit_key_warns_that_coverage_will_not_see_it(
            self, tmp_path, capsys, subject):
        rc, cap, ledger = _verify(tmp_path, capsys, subject)
        warning = " ".join(cap.err.split())
        assert "coverage will not see" in warning
        assert repr(subject) in warning or subject in warning
        assert "manufacturer/model#serial" in warning
        # Not refused, and stdout is still the JSON document.
        assert json.loads(cap.out)["evidence"]["content_hash"]
        subjects = {e.subject for e in EvidenceLedger(ledger).entries()}
        assert subject in subjects
        assert rc in (0, 1)

    @pytest.mark.parametrize("subject", ["Grimaldi/AR-7#", "#0412"])
    def test_a_subject_the_engine_already_refuses_is_still_refused(
            self, tmp_path, capsys, subject):
        """What is accepted does not change: these were exit 2 before and still are."""
        rc, cap, _ = _verify(tmp_path, capsys, subject)
        assert rc == 2
        assert "not a unit key" in cap.err

    def test_a_well_formed_key_with_a_manifest_in_the_ledger_does_not_warn(
            self, tmp_path, capsys):
        from assurance.machinery.record import record_manifest

        from .test_assurance_machinery import manifest

        m = manifest()
        ledger_path = tmp_path / "ev.db"
        record_manifest(EvidenceLedger(ledger_path), m)
        capsys.readouterr()
        machine_main(["verify", "--envelope", str(ENV), "--trace", str(TRACE),
                      "--actor", "v.grimaldi", "--ledger", str(ledger_path),
                      "--subject", m.machine.key, "--json"])
        assert "coverage will not see" not in capsys.readouterr().err

    def test_a_well_formed_key_no_manifest_in_the_ledger_carries_that_warning(
            self, tmp_path, capsys):
        from assurance.machinery.record import record_manifest

        from .test_assurance_machinery import manifest

        ledger_path = tmp_path / "ev.db"
        record_manifest(EvidenceLedger(ledger_path), manifest())
        capsys.readouterr()
        machine_main(["verify", "--envelope", str(ENV), "--trace", str(TRACE),
                      "--actor", "v.grimaldi", "--ledger", str(ledger_path),
                      "--subject", "Other/Machine#9", "--json"])
        err = " ".join(capsys.readouterr().err.split())
        assert "coverage will not see" in err
        assert "no manifest" in err

    def test_no_subject_and_no_ledger_is_silent(self, tmp_path, capsys):
        capsys.readouterr()
        machine_main(["verify", "--envelope", str(ENV), "--trace", str(TRACE),
                      "--actor", "v.grimaldi", "--json"])
        assert "coverage" not in capsys.readouterr().err


# =====================================================================
class TestUncheckedIsAWord:
    def _files(self, tmp_path):
        """An SSM recording with no separation measurement: ssm_separation is unchecked."""
        from datetime import UTC, datetime

        from .test_assurance_change import _inputs

        env, _ = _inputs(datetime(2026, 3, 1, tzinfo=UTC))
        (tmp_path / "env.json").write_text(json.dumps(env.to_dict()))
        (tmp_path / "trace.json").write_text(json.dumps({
            "trace_id": "T1", "provenance": "field", "source_system": "AR-7 fw",
            "started_at": "2026-03-01T00:00:00Z", "sample_rate_hz": 50.0,
            "samples": [{"t": i / 50, "tcp": [0, 0, 1000], "tcp_speed": 400,
                         "mode": "ssm", "separation": None} for i in range(10)]}))
        return tmp_path / "env.json", tmp_path / "trace.json"

    def test_an_unchecked_check_prints_the_word_not_question_marks(self, tmp_path, capsys):
        env, trace = self._files(tmp_path)
        capsys.readouterr()
        rc = machine_main(["verify", "--envelope", str(env), "--trace", str(trace),
                           "--actor", "v.grimaldi"])
        out = capsys.readouterr().out
        assert rc == 1                                   # INCOMPLETE is not a pass
        assert "INCOMPLETE" in out
        assert re.search(r"\[unchecked\] ssm_separation \(0 samples\)", out), out
        assert "??" not in out
        # The other marks keep their short form: the homepage and docs pin them.
        assert "[ok  ] speed_limit" in out

    def test_the_json_outcome_is_unchanged(self, tmp_path, capsys):
        env, trace = self._files(tmp_path)
        capsys.readouterr()
        machine_main(["verify", "--envelope", str(env), "--trace", str(trace),
                      "--actor", "v.grimaldi", "--json"])
        checks = {c["name"]: c["outcome"]
                  for c in json.loads(capsys.readouterr().out)["result"]["checks"]}
        assert checks["ssm_separation"] == "unchecked"


# =====================================================================
class TestBrokenPipe:
    def test_machine_verify_piped_to_a_reader_that_left_exits_quietly(self, tmp_path):
        ledger = tmp_path / "ev.db"
        env = _child_env()
        proc = subprocess.Popen(  # noqa: S603
            [sys.executable, "-m", "assurance", "machine", "verify",
             "--envelope", str(ENV), "--trace", str(TRACE), "--actor", "v.grimaldi",
             "--ledger", str(ledger), "--subject", "Grimaldi/AR-7#0412"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=ROOT)
        proc.stdout.close()                  # `| head -0`: the reader is already gone
        _, err = proc.communicate(timeout=120)
        text = err.decode()
        assert "Traceback" not in text and "BrokenPipeError" not in text, text
        assert text.strip() == "" or "coverage" in text    # only the subject warning, if any
        # The seal happened before the first byte was printed; nothing was lost.
        led = EvidenceLedger.open_existing(ledger)
        ok, problems = led.verify_chain()
        assert ok, problems
        assert any(e.subject == "Grimaldi/AR-7#0412" for e in led.entries())
        assert proc.returncode == 141        # 128 + SIGPIPE, as `yes | head` reports

    def test_a_short_output_that_only_fails_when_flushed_is_quiet_too(self):
        """Block-buffered: the error surfaces at the flush, not in the print."""
        env = _child_env()
        for argv in ([], ["machine", "separation", "--envelope", str(ENV), "--speed", "400"]):
            proc = subprocess.Popen(  # noqa: S603
                [sys.executable, "-m", "assurance", *argv],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=ROOT)
            proc.stdout.close()
            _, err = proc.communicate(timeout=60)
            assert err.decode().strip() == "", (argv, err.decode())
            assert proc.returncode == 141, argv

    def test_the_handler_does_not_swallow_other_errors(self):
        from assurance.cli import main

        assert main(["nonsense-domain"]) == 2
