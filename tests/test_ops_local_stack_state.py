"""scripts/local-stack.sh treats its state file as DATA, never as code (red-team finding B).

HONEST SCOPE: no stack is started, no database is touched. The tests plant hostile state files and
directories and prove that `down` runs nothing from them and removes nothing it did not create, and
that `up` refuses a directory that was planted. They do not prove `up` brings a working stack up (the
buyer-path verification does that).
"""

# ruff: noqa: S603, S607  (these tests run this repository's own script with fixed argv, no shell)

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "local-stack.sh"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash is required")


def run(cmd: str, stack: Path) -> subprocess.CompletedProcess[str]:
    env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "LOCAL_STACK_DIR": str(stack),
           "PYTHON": "/nonexistent-python"}   # a drop of a real database must be impossible here
    return subprocess.run(["bash", str(SCRIPT), cmd], capture_output=True, text=True, timeout=30, env=env)


def planted(tmp_path: Path, state: str, *, marker: bool = True, mode: int = 0o700) -> Path:
    stack = tmp_path / "stack"
    stack.mkdir()
    (stack / "state.env").write_text(state)
    if marker:
        (stack / ".nb-local-stack").write_text("")
    stack.chmod(mode)
    return stack


HOSTILE = [
    "touch {s}\n",
    "DB_NAME=nb_local_ab12\ntouch {s}\n",
    "API_PID=$(touch {s})\n",
    "DB_NAME=nb_local_$(touch {s})\n",
    "DB_NAME=`touch {s}`\n",
    "DB_NAME=nb_local_ab12; touch {s}\n",
    "PATH=/tmp\nDB_NAME=nb_local_ab12\n",              # an unlisted key
    "API_PID=12 34\n", "API_PID=-1\n", "API_PID=\n",
    "DB_NAME=postgres\n", "DB_NAME=nb_local_AB\n", "DB_NAME=nb_local_\n", "DB_NAME=nb_local_a-b\n",
    "API_PORT=80;touch {s}\n",
]


@pytest.mark.parametrize("state", HOSTILE)
def test_a_hostile_state_file_is_never_executed_and_is_refused(tmp_path: Path, state: str) -> None:
    sentinel = tmp_path / "pwned"
    stack = planted(tmp_path, state.format(s=sentinel))
    r = run("down", stack)
    assert not sentinel.exists(), "the state file was executed"
    assert r.returncode == 2 and "refusing" in r.stderr, r.stderr
    assert stack.is_dir() and (stack / "state.env").exists(), "a refused down must remove nothing"


def test_a_directory_without_the_marker_is_never_removed(tmp_path: Path) -> None:
    stack = planted(tmp_path, "DB_NAME=nb_local_ab12\n", marker=False)
    r = run("down", stack)
    assert r.returncode == 2 and "not a directory this script created" in r.stderr
    assert stack.is_dir()


@pytest.mark.parametrize("mode", [0o770, 0o707, 0o777, 0o722])
def test_a_group_or_world_writable_directory_is_refused(tmp_path: Path, mode: int) -> None:
    stack = planted(tmp_path, "API_PORT=8001\n", mode=mode)
    r = run("down", stack)
    assert r.returncode == 2 and "refusing" in r.stderr and stack.is_dir()


def test_a_symlinked_state_file_is_refused(tmp_path: Path) -> None:
    stack = planted(tmp_path, "")
    (stack / "state.env").unlink()
    elsewhere = tmp_path / "elsewhere.env"
    elsewhere.write_text("API_PORT=8001\n")
    os.symlink(elsewhere, stack / "state.env")
    r = run("down", stack)
    assert r.returncode == 2 and "not a regular file" in r.stderr and stack.is_dir()


def test_a_well_formed_state_file_is_accepted_and_only_then_the_directory_removed(tmp_path: Path) -> None:
    stack = planted(tmp_path, "API_PORT=8001\nPLATFORM_PORT=8000\n")
    custody = Path(str(stack) + ".custody")
    custody.mkdir()
    r = run("down", stack)       # no DB_NAME recorded, so nothing to drop
    assert r.returncode == 0, r.stderr
    assert not stack.exists() and not custody.exists()


@pytest.mark.parametrize("kind", ["world_writable", "symlink"])
def test_up_refuses_a_planted_directory(tmp_path: Path, kind: str) -> None:
    stack = tmp_path / "stack"
    if kind == "world_writable":
        stack.mkdir()
        stack.chmod(0o777)
    else:
        target = tmp_path / "target"
        target.mkdir()
        os.symlink(target, stack)
    r = run("up", stack)
    assert r.returncode == 2 and "not a private directory" in r.stderr, r.stderr
    assert not (stack / ".nb-local-stack").exists() and not (stack / "state.env").exists()


def test_the_script_never_sources_or_evals_anything() -> None:
    code = "\n".join(line for line in SCRIPT.read_text().splitlines() if not line.lstrip().startswith("#"))
    for banned in ('. "$STATE"', "source ", "eval "):
        assert banned not in code, banned
    assert "rm -rf" in code and ".nb-local-stack" in code
