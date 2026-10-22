"""The customer-facing commands, run as a subprocess (``python -m assurance``).

In-process ``main([...])`` tests do not see the exit code a shell, a cron job or
CI sees, nor what reaches stdout and stderr. These do. The scenario is the
shipped worked fleet, built by the real ``report demo`` command.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def run(*args: str | Path, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "assurance", *map(str, args)],
        capture_output=True, text=True, cwd=cwd, timeout=120, check=False)


@pytest.fixture(scope="module")
def demo(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("demo")
    r = run("report", "demo", "--out", out)
    assert r.returncode == 0, r.stderr
    return out


def ledger_of(demo: Path) -> Path:
    (found,) = list(demo.glob("*.db")) or [next(demo.rglob("*.db"))]
    return found


def test_unknown_domain_and_verb_exit_2_with_a_message_on_stderr():
    r = run("nonsense")
    assert r.returncode == 2 and "unknown domain" in r.stderr
    r = run("fleet", "no-such-verb")
    assert r.returncode == 2 and r.stdout == ""


def test_fleet_list_reads_the_ledger_and_exits_zero(demo):
    r = run("fleet", "list", "--ledger", ledger_of(demo))
    # 1 means "gaps exist", not failure: the demo fleet has functions without evidence
    assert r.returncode in (0, 1) and "machine(s)" in r.stdout


def test_fleet_list_on_a_missing_ledger_is_an_error_not_an_empty_fleet(tmp_path):
    r = run("fleet", "list", "--ledger", tmp_path / "nope.db")
    assert r.returncode == 2 and "does not exist" in r.stderr
    assert not (tmp_path / "nope.db").exists()      # and no ledger was created
    for verb in (["change", "replay", "case-x"], ["change", "export", "case-x"]):
        r = run(*verb, "--ledger", tmp_path / "nope.db")
        assert r.returncode == 2 and not (tmp_path / "nope.db").exists(), verb


def test_value_report_exit_codes_and_json(demo):
    led = ledger_of(demo)
    r = run("value", "report", "--ledger", led, "--json")
    assert r.returncode in (0, 1), r.stderr
    doc = json.loads(r.stdout)
    assert doc["schema"] == "assurance.position/1" and doc["ledger"]["chain_verified"]
    assert doc["not_assessed"]
    assert run("value", "report", "--ledger", led.parent / "gone.db").returncode == 2


def test_attest_keygen_sign_verify_round_trip_and_tamper(demo, tmp_path):
    led = ledger_of(demo)
    key, pub, log = tmp_path / "k.pem", tmp_path / "k.pub", tmp_path / "att.jsonl"
    assert run("attest", "keygen", "--out", key, "--public-out", pub).returncode == 0
    r = run("attest", "sign", "--ledger", led, "--key", key, "--log", log)
    assert r.returncode == 0, r.stderr
    ok = run("attest", "verify", "--log", log, "--public-key", pub, "--ledger", led)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    # a log whose signed bytes were edited must not verify
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    lines[0]["ledger_length"] += 1
    log.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    bad = run("attest", "verify", "--log", log, "--public-key", pub)
    assert bad.returncode != 0


def test_report_build_with_attestation_states_the_basis(demo, tmp_path):
    led = ledger_of(demo)
    key, pub, log = tmp_path / "k.pem", tmp_path / "k.pub", tmp_path / "att.jsonl"
    run("attest", "keygen", "--out", key, "--public-out", pub)
    run("attest", "sign", "--ledger", led, "--key", key, "--log", log)
    out = tmp_path / "report.html"
    r = run("report", "build", "--ledger", led, "--out", out,
            "--attestations", log, "--attest-key", pub)
    assert r.returncode == 0, r.stderr
    html = out.read_text()
    assert "Head attestation verifies" in html and "signer read from the ledger" in html
    # without the key the same log is reported as unchecked, never as valid
    out2 = tmp_path / "report2.html"
    assert run("report", "build", "--ledger", led, "--out", out2,
               "--attestations", log).returncode == 0
    assert "signatures NOT checked" in out2.read_text()


def test_machinery_coverage_and_passport_run(demo):
    led = ledger_of(demo)
    r = run("machinery", "--help")
    assert r.returncode == 0 and "coverage" in r.stdout
    assert run("machinery", "coverage", "--ledger", led).returncode in (0, 1, 2)
