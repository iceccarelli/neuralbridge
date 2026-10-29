"""The shipped example pack (``examples/workflow``) runs end to end and its outputs resist edits.

Uses only the files a customer receives: the runner, the synthetic envelope, manifest,
intervention and traces. The recorder is a throwaway key the runner generates. Nothing here
shows that any real machine is safe; it shows the documented workflow reaches the documented
result on invented data, and that the two things handed to an outsider (the passport and the
verification bundle) are rejected when edited or when judged under a list that does not trust
the recorder.
"""
# ruff: noqa: S603  (the tests run this package's own CLI and the shipped runner)
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "examples" / "workflow" / "run.py"
PACK = ("envelope", "manifest", "intervention", "trace-before", "trace-after")


def assurance(work: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "assurance", *args], cwd=work,
                          capture_output=True, text=True, check=False)


@pytest.fixture(scope="module")
def ran(tmp_path_factory):
    work = tmp_path_factory.mktemp("workflow")
    done = subprocess.run([sys.executable, str(RUN), "--json", "--keep", str(work)],
                          capture_output=True, text=True, check=False)
    return work, done, json.loads(done.stdout)


def test_the_runner_reaches_every_documented_result(ran):
    _, done, report = ran
    assert done.returncode == 0, done.stderr
    assert report["synthetic"] is True and report["ok"] is True
    assert [s["exit"] for s in report["steps"]] == [s["expected_exit"] for s in report["steps"]]
    exits = {s["step"].split(":")[0]: s["exit"] for s in report["steps"]}
    assert exits["coverage after the change"] == 1      # the change leaves the evidence stale
    assert len(report["steps"]) == 12


def test_every_step_says_what_it_does_not_show(ran):
    for s in ran[2]["steps"]:
        assert s["shows"].strip() and s["does_not_show"].strip(), s["step"]


@pytest.mark.parametrize("name", PACK)
def test_the_pack_says_it_is_synthetic_and_names_no_real_party(name):
    text = (ROOT / "examples" / "workflow" / f"{name}.json").read_text("utf-8")
    assert "SYNTHETIC" in text.upper() or name.startswith("trace-")
    assert "Grimaldi" not in text


def test_coverage_is_covered_at_validated_on_the_finished_ledger(ran):
    work, _, _ = ran
    cov = assurance(work, "machinery", "coverage", "--ledger", "ledger.db", "--json",
                    "manifest.json")
    assert cov.returncode == 0, cov.stdout
    assert json.loads(cov.stdout)["verdict"] == "covered"


def test_an_edited_passport_is_rejected_and_says_which_block(ran):
    work, _, _ = ran
    assert assurance(work, "machinery", "check", "--ledger", "ledger.db",
                     "passport.json").returncode == 0
    text = (work / "passport.json").read_text("utf-8")
    assert '"covered"' in text
    (work / "passport-edited.json").write_text(text.replace('"covered"', '"gaps"', 1), "utf-8")
    run = assurance(work, "machinery", "check", "--ledger", "ledger.db", "passport-edited.json")
    assert run.returncode == 1 and "REJECTED" in run.stdout
    assert "coverage block was edited" in run.stdout


def test_an_edited_verification_bundle_is_rejected_as_edited_after_sealing(ran):
    work, _, _ = ran
    text = (work / "bundle-after.json").read_text("utf-8")
    assert '"pass"' in text
    (work / "bundle-edited.json").write_text(text.replace('"pass"', '"fail"', 1), "utf-8")
    run = assurance(work, "machine", "check", "bundle-edited.json", "--envelope",
                    "envelope.json", "--trace", "trace-after.json", "--recorder-trust",
                    "trust.json", "--as-of", "2026-03-16T00:00:00Z")
    assert run.returncode == 1 and "edited after sealing" in run.stdout


def test_a_checker_with_no_trust_list_does_not_believe_validated(ran):
    work, _, _ = ran
    run = assurance(work, "machine", "check", "bundle-after.json", "--envelope", "envelope.json",
                    "--trace", "trace-after.json", "--as-of", "2026-03-16T00:00:00Z")
    assert "tier believed by this check: community" in run.stdout
    assert "tier believed by this check: validated" not in run.stdout


def test_a_different_trace_does_not_reproduce_the_sealed_verification(ran):
    work, _, _ = ran
    trace = json.loads((work / "trace-after.json").read_text("utf-8"))
    trace["samples"][10]["tcp_speed"] = 700.0
    (work / "trace-swapped.json").write_text(json.dumps(trace), "utf-8")
    run = assurance(work, "machine", "check", "bundle-after.json", "--envelope", "envelope.json",
                    "--trace", "trace-swapped.json", "--recorder-trust", "trust.json",
                    "--as-of", "2026-03-16T00:00:00Z")
    assert run.returncode == 1 and "REJECTED" in run.stdout, run.stdout


@pytest.mark.parametrize("artefact,verb", [("bundle-after.json", "assurance machine check"),
                                           ("passport.json", "assurance machinery check")])
def test_evidence_verify_on_another_kind_of_artefact_names_the_verb_that_checks_it(
        ran, artefact, verb):
    """``evidence verify`` checks ledger exports only. Handed a verification bundle or a
    passport it must still refuse (exit 2, nothing verified) but say which command to use,
    not leave an outsider with "no `entries` list"."""
    work, _, _ = ran
    run = assurance(work, "evidence", "verify", artefact)
    assert run.returncode == 2 and "DOES NOT VERIFY" in run.stdout
    assert verb in run.stdout
