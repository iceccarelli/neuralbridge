"""The PyPI publish workflow, the build-only dry run, the action pins, the CI skip gate and the local stack.

HONEST SCOPE: nothing here publishes anything or contacts PyPI, GitHub or a registry. It reads the workflow
files and runs the local scripts with throwaway inputs. It proves the workflows' SHAPE (trusted publishing,
separate build and publish jobs, a protected environment, no long-lived token, pinned actions) and the
scripts' fail-closed behaviour. It does NOT prove a publish works: that workflow has never run on GitHub.
"""

# ruff: noqa: S603, S607  (these tests run this repository's own scripts with fixed argv, no shell, no input from outside)

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PYPI = WORKFLOWS / "publish-pypi.yml"
CI = WORKFLOWS / "ci.yml"
bash = shutil.which("bash")


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _on(wf: dict) -> dict:
    return wf.get("on") or wf[True]  # PyYAML parses a bare `on` key as boolean True


# ── publish-pypi.yml ─────────────────────────────────────────────────────────────────────────

def test_pypi_triggers_are_release_and_manual_dispatch_only() -> None:
    on = _on(_load(PYPI))
    assert set(on) == {"release", "workflow_dispatch"}
    assert on["release"] == {"types": ["published"]}
    # A manual run is a dry run unless it is asked to publish.
    assert on["workflow_dispatch"]["inputs"]["publish"]["default"] is False


def test_pypi_uses_trusted_publishing_and_no_long_lived_token() -> None:
    text = PYPI.read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "secrets." not in code
    assert not re.search(r"\b(password|api[-_]?token|PYPI_TOKEN|TWINE_PASSWORD)\b", code, re.IGNORECASE)
    wf = _load(PYPI)
    publish = wf["jobs"]["publish"]
    step = next(s for s in publish["steps"] if s.get("uses", "").startswith("pypa/gh-action-pypi-publish@"))
    assert "password" not in step.get("with", {})
    assert publish["permissions"] == {"id-token": "write"}


def test_pypi_build_and_publish_are_separate_jobs_with_a_protected_environment() -> None:
    wf = _load(PYPI)
    jobs = wf["jobs"]
    assert set(jobs) == {"guard", "build", "publish"}
    assert jobs["publish"]["environment"]["name"] == "pypi"
    assert "environment" not in jobs["build"] and "environment" not in jobs["guard"]
    assert jobs["publish"]["needs"] == ["guard", "build"]
    assert jobs["publish"]["if"] == "needs.guard.outputs.publish == 'true'"
    # The job that holds the upload-capable identity checks out nothing and runs no repository code.
    assert not any("run" in s or s.get("uses", "").startswith("actions/checkout@") for s in jobs["publish"]["steps"])
    # Only the build job can attest provenance; the publish job cannot write attestations itself.
    assert jobs["build"]["permissions"]["attestations"] == "write"
    assert "attestations" not in jobs["publish"]["permissions"]
    build_uses = [s.get("uses", "") for s in jobs["build"]["steps"]]
    assert any(u.startswith("actions/attest-build-provenance@") for u in build_uses)
    assert any(u.startswith("actions/upload-artifact@") for u in build_uses)
    assert any(u.startswith("actions/download-artifact@") for u in (s.get("uses", "") for s in jobs["publish"]["steps"]))


def test_pypi_build_runs_the_same_script_a_person_runs_for_a_dry_run() -> None:
    wf = _load(PYPI)
    runs = " ".join(s.get("run", "") for s in wf["jobs"]["build"]["steps"])
    assert "scripts/build-dist.sh" in runs
    assert "--expect-tag" in runs  # a publish run must have tag == package version
    guard_runs = " ".join(s.get("run", "") for s in wf["jobs"]["guard"]["steps"])
    assert "merge-base --is-ancestor" in guard_runs  # the commit must be on main


def test_pypi_project_url_names_the_real_package() -> None:
    wf = _load(PYPI)
    url = wf["jobs"]["publish"]["environment"]["url"]
    assert url == "https://pypi.org/project/neuralbridge-middleware/"
    assert 'name = "neuralbridge-middleware"' in (ROOT / "pyproject.toml").read_text()


# ── every action in every workflow is pinned to a full commit SHA ─────────────────────────────

def _uses_lines() -> list[tuple[str, str]]:
    out = []
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        for line in wf.read_text().splitlines():
            m = re.match(r"\s*(?:-\s+)?uses:\s*(\S+)(.*)$", line)
            if m:
                out.append((wf.name, line.strip()))
    return out


def test_every_action_is_pinned_to_a_full_sha_with_its_tag_in_a_comment() -> None:
    lines = _uses_lines()
    assert len(lines) >= 40
    bad = [(f, line) for f, line in lines
           if not re.search(r"uses:\s*[\w.-]+/[\w./-]+@[0-9a-f]{40}\s+#\s*v\d+\.\d+\.\d+\s*$", line)]
    assert bad == [], bad


def test_the_same_action_has_one_sha_everywhere() -> None:
    seen: dict[str, set[str]] = {}
    for _, line in _uses_lines():
        m = re.search(r"uses:\s*([\w.-]+/[\w./-]+)@([0-9a-f]{40})", line)
        assert m
        seen.setdefault(m.group(1), set()).add(m.group(2))
    assert {k: v for k, v in seen.items() if len(v) > 1} == {}


# ── ci.yml ───────────────────────────────────────────────────────────────────────────────────

def test_python_test_matrix_does_not_fail_fast_and_keeps_its_gates() -> None:
    job = _load(CI)["jobs"]["test"]
    assert job["strategy"]["fail-fast"] is False
    assert job["strategy"]["matrix"]["python-version"] == ["3.11", "3.12", "3.13"]
    env = job["env"]
    assert env["NEURALBRIDGE_REQUIRE_POSTGRES"] == "1" and env["NEURALBRIDGE_REQUIRE_NETNS"] == "1"
    runs = " ".join(s.get("run", "") for s in job["steps"])
    assert "python -m pytest tests/" in runs and "--junitxml" in runs
    assert "scripts/check_test_skips.py" in runs


def test_site_job_still_requires_node_so_the_skipped_tests_run_somewhere() -> None:
    text = CI.read_text()
    assert 'NEURALBRIDGE_REQUIRE_NODE: "1"' in text


def test_workflow_lint_covers_the_new_scripts() -> None:
    runs = " ".join(s.get("run", "") for s in _load(CI)["jobs"]["workflow-lint"]["steps"])
    for script in ("build-dist.sh", "local-stack.sh", "verify-buyer-path.sh", "verify-release.sh"):
        assert script in runs


# ── scripts/check_test_skips.py ──────────────────────────────────────────────────────────────

def _junit(tmp_path: Path, skips: list[str]) -> Path:
    cases = "".join(f'<testcase classname="t" name="n{i}"><skipped message="{m}"/></testcase>'
                    for i, m in enumerate(skips))
    p = tmp_path / "junit.xml"
    p.write_text(f'<testsuites><testsuite tests="{len(skips) + 1}">'
                 f'<testcase classname="t" name="ok"/>{cases}</testsuite></testsuites>')
    return p


def _run_skips(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "check_test_skips.py"), *args],
                          capture_output=True, text=True, timeout=60)


def test_skip_gate_accepts_only_the_node_skips(tmp_path: Path) -> None:
    ok = _junit(tmp_path, ["node_modules is not installed (npm ci); the CI Site job runs this", "node is not installed"])
    r = _run_skips(str(ok))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "2 allowed skips" in r.stdout


def test_skip_gate_fails_on_an_unexplained_skip(tmp_path: Path) -> None:
    bad = _junit(tmp_path, ["node is not installed", "needs a thing nobody installed"])
    r = _run_skips(str(bad))
    assert r.returncode == 1
    assert "UNEXPLAINED" in r.stdout and "needs a thing nobody installed" in r.stdout


def test_skip_gate_can_bound_the_allowance_and_reports_unreadable_input(tmp_path: Path) -> None:
    many = _junit(tmp_path, ["node is not installed"] * 3)
    assert _run_skips(str(many), "--max-allowed", "2").returncode == 1
    assert _run_skips(str(tmp_path / "missing.xml")).returncode == 2


# ── scripts/build-dist.sh (the dry run; it never uploads) ─────────────────────────────────────

@pytest.mark.skipif(bash is None, reason="bash is required")
def test_build_dist_refuses_a_tag_that_is_not_the_package_version(tmp_path: Path) -> None:
    pytest.importorskip("build")
    pytest.importorskip("twine")
    r = subprocess.run(["bash", str(ROOT / "scripts" / "build-dist.sh"), "--out", str(tmp_path / "d"),
                        "--expect-tag", "v9.9.9"],
                       capture_output=True, text=True, timeout=120, env={"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHON": sys.executable})
    assert r.returncode == 1, r.stderr
    assert "does not match" in r.stderr
    assert not (tmp_path / "d").exists()  # refused before building anything


@pytest.mark.skipif(bash is None, reason="bash is required")
def test_build_dist_refuses_a_non_empty_output_directory(tmp_path: Path) -> None:
    pytest.importorskip("build")
    pytest.importorskip("twine")
    out = tmp_path / "d"
    out.mkdir()
    (out / "stale.whl").write_text("x")
    r = subprocess.run(["bash", str(ROOT / "scripts" / "build-dist.sh"), "--out", str(out)],
                       capture_output=True, text=True, timeout=120, env={"PATH": "/usr/bin:/bin:/usr/local/bin", "PYTHON": sys.executable})
    assert r.returncode == 2 and "not empty" in r.stderr


# ── scripts/local-stack.sh and scripts/local_stack_db.py ───────────────────────────────────────

@pytest.mark.skipif(bash is None, reason="bash is required")
def test_local_stack_without_a_command_prints_usage_and_exits_2() -> None:
    r = subprocess.run(["bash", str(ROOT / "scripts" / "local-stack.sh")], capture_output=True, text=True, timeout=30)
    assert r.returncode == 2 and "verify" in r.stderr and "down" in r.stderr


@pytest.mark.skipif(bash is None, reason="bash is required")
def test_local_stack_down_with_nothing_recorded_is_a_no_op(tmp_path: Path) -> None:
    r = subprocess.run(["bash", str(ROOT / "scripts" / "local-stack.sh"), "down"], capture_output=True, text=True,
                       timeout=30, env={"PATH": "/usr/bin:/bin:/usr/local/bin", "LOCAL_STACK_DIR": str(tmp_path / "none")})
    assert r.returncode == 0 and "already down" in r.stderr


@pytest.mark.parametrize("name", ["postgres", "neuralbridge_ai", "nb_local_", "nb_local_X", 'nb_local_a"; DROP', "nb_local_a-b"])
def test_local_stack_db_refuses_any_name_it_did_not_make(name: str) -> None:
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "local_stack_db.py"), "drop", name],
                       capture_output=True, text=True, timeout=30,
                       env={"PATH": "/usr/bin:/bin", "NEURALBRIDGE_AI_PG_HOST": "127.0.0.1", "NEURALBRIDGE_AI_PG_USER": "u",
                            "NEURALBRIDGE_AI_PG_PASSWORD": "p"})
    assert r.returncode == 2 and "nb_local_" in r.stderr


# ── scripts/verify-buyer-path.sh does not report a pass without making requests ───────────────

@pytest.mark.skipif(bash is None or shutil.which("curl") is None, reason="bash and curl are required")
def test_verify_buyer_path_fails_loudly_when_nothing_is_listening(tmp_path: Path) -> None:
    r = subprocess.run(["bash", str(ROOT / "scripts" / "verify-buyer-path.sh")], capture_output=True, text=True,
                       timeout=60, env={"PATH": "/usr/bin:/bin:/usr/local/bin", "ASSURANCE_API_URL": "http://127.0.0.1:9",
                                        "NEURALBRIDGE_API_URL": "http://127.0.0.1:9/api/v1",
                                        "ASSURANCE_ACCOUNTS": str(tmp_path / "a.db")})
    assert r.returncode == 1
    assert "FAILED" in r.stderr and "not reachable" in r.stderr
    assert "ALL CHECKS PASSED" not in r.stderr


def test_go_live_runbook_has_no_short_operator_key_and_names_the_one_command() -> None:
    text = (ROOT / "docs" / "GO-LIVE.md").read_text()
    assert "local-operator-key" not in text
    assert "scripts/local-stack.sh verify" in text
    # every ASSURANCE_API_KEYS example in the runbook generates a >= 32 character key
    for m in re.finditer(r"ASSURANCE_API_KEYS=(\S+)", text):
        assert "secrets.token_urlsafe" in m.group(1) or m.group(1).lstrip('"').startswith("$"), m.group(0)
    assert textwrap.dedent("python -m pytest") in text


def test_no_workflow_grants_security_events_write_without_uploading_sarif() -> None:
    # Least privilege (red-team finding C): `security-events: write` once sat at workflow level for every job
    # although nothing uploads SARIF. It is allowed only on a job that uses the SARIF upload action.
    for wf_path in sorted(WORKFLOWS.glob("*.yml")):
        wf = _load(wf_path)
        top = wf.get("permissions")
        assert isinstance(top, dict), f"{wf_path.name}: the workflow needs an explicit top-level permissions block"
        assert top.get("security-events") != "write", f"{wf_path.name}: workflow-level security-events: write"
        for name, job in wf["jobs"].items():
            perms = job.get("permissions", top)
            if isinstance(perms, dict) and perms.get("security-events") == "write":
                uploads = any("upload-sarif" in str(s.get("uses", "")) for s in job.get("steps", []))
                assert uploads, f"{wf_path.name}:{name} has security-events: write but uploads no SARIF"


def test_ci_default_permissions_are_read_only_and_each_job_write_is_listed() -> None:
    wf = _load(CI)
    assert wf["permissions"] == {"contents": "read"}
    writes = {name: sorted(k for k, v in job["permissions"].items() if v == "write")
              for name, job in wf["jobs"].items() if "permissions" in job}
    assert writes == {"sbom": ["attestations", "id-token"], "deploy-docs": ["id-token", "pages"]}
