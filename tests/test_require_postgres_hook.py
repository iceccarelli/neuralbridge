"""``NEURALBRIDGE_REQUIRE_POSTGRES``: a Postgres skip is a failure, only when asked for.

The Postgres-backed tests skip honestly when no server is reachable. In CI that skip is
a gate that did not run, so the workflow sets ``NEURALBRIDGE_REQUIRE_POSTGRES=1`` and the
hook in ``tests/require_postgres_plugin.py`` (loaded by ``tests/conftest.py``) turns any
skip whose reason names PostgreSQL into a failure carrying the same reason. Unset, or any
other value, skip semantics are untouched. Each case below runs pytest in a subprocess on
a throwaway test file.
"""

from __future__ import annotations

import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

THROWAWAY = '''
import pytest

@pytest.mark.skipif(True, reason="No reachable PostgreSQL at u@127.0.0.1:5432/db")
def test_marked_postgres_skip():
    raise AssertionError("never runs")

def test_call_time_postgres_skip():
    pytest.skip("no postgres server here")

def test_unrelated_skip():
    pytest.skip("needs a GPU")

def test_passes():
    assert True
'''


def run_pytest(tmp_path: Path, **env: str) -> dict[str, dict[str, str]]:
    """Run the throwaway file with the hook plugin loaded; outcome per test."""
    (tmp_path / "test_throwaway.py").write_text(THROWAWAY, encoding="utf-8")
    junit = tmp_path / "junit.xml"
    clean = {k: v for k, v in os.environ.items() if k != "NEURALBRIDGE_REQUIRE_POSTGRES"}
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p",
         "tests.require_postgres_plugin", f"--junitxml={junit}", "test_throwaway.py"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
        env={**clean, "PYTHONPATH": f"{REPO}{os.pathsep}{REPO / 'src'}", **env})
    assert junit.exists(), proc.stdout + proc.stderr
    out: dict[str, dict[str, str]] = {}
    for case in ET.parse(junit).getroot().iter("testcase"):  # noqa: S314  (our own junit file)
        kids = {child.tag: (child.get("message") or "") for child in case}
        kind = next((k for k in ("failure", "error", "skipped") if k in kids), "passed")
        out[case.get("name")] = {"outcome": kind, "message": kids.get(kind, "")}
    return out


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", " Yes "])
def test_when_required_a_postgres_skip_is_a_failure_with_the_same_reason(tmp_path, value):
    got = run_pytest(tmp_path, NEURALBRIDGE_REQUIRE_POSTGRES=value)
    assert got["test_marked_postgres_skip"]["outcome"] in ("failure", "error")
    assert "No reachable PostgreSQL at u@127.0.0.1:5432/db" in \
        got["test_marked_postgres_skip"]["message"]
    assert got["test_call_time_postgres_skip"]["outcome"] in ("failure", "error")
    assert "no postgres server here" in got["test_call_time_postgres_skip"]["message"]
    # a skip about anything else, and a pass, are left alone
    assert got["test_unrelated_skip"]["outcome"] == "skipped"
    assert got["test_passes"]["outcome"] == "passed"


@pytest.mark.parametrize("value", [None, "", "0", "no", "false", "2"])
def test_unset_or_any_other_value_leaves_skips_as_skips(tmp_path, value):
    got = run_pytest(tmp_path, **({} if value is None else {"NEURALBRIDGE_REQUIRE_POSTGRES": value}))
    assert {n: r["outcome"] for n, r in got.items()} == {
        "test_marked_postgres_skip": "skipped", "test_call_time_postgres_skip": "skipped",
        "test_unrelated_skip": "skipped", "test_passes": "passed"}


def test_the_suite_conftest_loads_the_hook():
    """The throwaway runs load the plugin by name; the real suite gets it from conftest."""
    import tests.conftest as suite_conftest
    from tests import require_postgres_plugin as plugin

    assert suite_conftest.pytest_runtest_makereport is plugin.pytest_runtest_makereport
