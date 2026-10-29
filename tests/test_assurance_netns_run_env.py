"""``netns-run.sh`` must hand the caller's Python environment through ``sudo``.

On GitHub-hosted Ubuntu the script cannot use ``unshare -rn`` and takes its sudo branch.
``sudo -E`` still strips ``PYTHONPATH`` and ``LD_LIBRARY_PATH``, so a kit run launched with the
README's ``PYTHONPATH=src`` found no ``assurance`` module inside the namespace and the CI job
failed on every Python. This test fakes that situation without privileges: stub ``unshare``
(refuses the unprivileged form, accepts the root form), ``setpriv`` and a ``sudo`` that drops
exactly the variables the real one drops, then runs the real script.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "netns-run.sh"

BASH = shutil.which("bash") or "bash"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")


def _stub(directory: Path, name: str, body: str) -> None:
    path = directory / name
    path.write_text("#!/usr/bin/env bash\n" + body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


@pytest.fixture()
def fake_root_only_sandbox(tmp_path):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    # `unshare -rn true` (unprivileged) fails; `unshare -n ...` (root form) runs the command.
    _stub(stubs, "unshare",
          'if [ "$1" = "-rn" ]; then exit 1; fi\n'
          '[ "$1" = "-n" ] && shift\n'
          '[ "$1" = "true" ] && exit 0\n'
          'exec "$@"\n')
    _stub(stubs, "setpriv", 'while [[ "$1" == --* ]]; do shift; done\nexec "$@"\n')
    # The real sudo -E removes these two even though -E asks to keep the environment.
    _stub(stubs, "sudo",
          'while [[ "$1" == -* ]]; do shift; done\n'
          'exec env -u PYTHONPATH -u LD_LIBRARY_PATH "$@"\n')
    return stubs


def test_a_relative_pythonpath_survives_the_sudo_branch(tmp_path, fake_root_only_sandbox):
    package_root = tmp_path / "src"
    package_root.mkdir()
    (package_root / "netns_probe_mod.py").write_text("FOUND = True\n")
    env = {**os.environ, "PATH": f"{fake_root_only_sandbox}{os.pathsep}{os.environ['PATH']}",
           "PYTHONPATH": "src"}                       # relative, as the workflow sets it
    done = subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), sys.executable, "-c",
         "import netns_probe_mod; print(netns_probe_mod.FOUND)"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip() == "True"


def test_it_still_fails_closed_when_no_namespace_can_be_made(tmp_path):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    _stub(stubs, "unshare", "exit 1\n")
    _stub(stubs, "sudo", "exit 1\n")
    env = {**os.environ, "PATH": f"{stubs}{os.pathsep}{os.environ['PATH']}"}
    done = subprocess.run(  # noqa: S603
        [BASH, str(SCRIPT), sys.executable, "-c", "print('ran')"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60, check=False)
    assert done.returncode == 97
    assert "ran" not in done.stdout
