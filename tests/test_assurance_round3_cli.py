"""Round-3 L4: a file the verifier cannot even parse is 'unreadable' (exit 2), not a crash.

``python -m assurance.evidence.cli verify`` on a deeply nested JSON file used to die with
a ``RecursionError`` traceback and exit 1, the code that means 'the evidence does not
verify'. A file nobody could parse says nothing about the evidence either way.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

from assurance.evidence.cli import main as evidence_cli
from assurance.evidence.verify_export import verify_export_file

from .test_assurance_attest import _ledger

DEEP = "[" * 200_000


def _run(args, cwd):
    import os
    from pathlib import Path

    import assurance

    src = str(Path(assurance.__file__).resolve().parent.parent)   # the code under test
    env = {**os.environ, "PYTHONPATH": src}
    return subprocess.run(  # noqa: S603 - our own interpreter
        [sys.executable, "-m", "assurance.evidence.cli", *args],
        capture_output=True, text=True, cwd=cwd, env=env)


def test_the_parser_level_failure_is_a_clean_unreadable_finding(tmp_path):
    f = tmp_path / "deep.json"
    f.write_text(DEEP)
    result = verify_export_file(f)
    assert result.scope == "unknown" and not result.ok
    assert any("too deeply nested" in p for p in result.problems)


def test_the_cli_exits_2_with_no_traceback(tmp_path):
    f = tmp_path / "deep.json"
    f.write_text(DEEP)
    proc = _run(["verify", str(f)], tmp_path)
    assert proc.returncode == 2, proc.stderr[-300:]
    assert "Traceback" not in proc.stderr and "RecursionError" not in proc.stderr
    assert "too deeply nested" in proc.stdout


def test_json_output_carries_the_same_finding(tmp_path, capsys):
    f = tmp_path / "deep.json"
    f.write_text(DEEP)
    assert evidence_cli(["verify", str(f), "--json"]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False
    assert any("too deeply nested" in p for p in out["problems"])


def test_a_bundle_that_parses_but_blows_the_stack_in_analysis_is_unreadable_too(
        tmp_path, monkeypatch):
    """The analysis walks the bundle recursively as well; it must not crash either."""
    from assurance.evidence import verify_export as ve

    led = _ledger(tmp_path / "l.db", 2)
    bundle = led.export(subject="machine-0")
    f = tmp_path / "b.json"
    f.write_text(json.dumps(bundle))

    def boom(*_a, **_k):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(ve, "verify_export", boom)
    result = ve.verify_export_file(f)
    assert result.scope == "unknown" and not result.ok
    assert any("too deeply nested" in p for p in result.problems)


@pytest.mark.parametrize("text", ["{" * 5000, '{"a":' * 5000])
def test_other_deep_shapes(tmp_path, text):
    f = tmp_path / "d.json"
    f.write_text(text)
    assert evidence_cli(["verify", str(f)]) == 2
