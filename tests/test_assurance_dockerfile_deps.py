"""The deploy image installs everything the service imports, from a hash-checked lock.

``deploy/assurance/Dockerfile`` installs ``requirements/assurance-service.lock`` with
``pip install --require-hashes --no-deps``. It once omitted ``cryptography``, which
``assurance.attest.keys`` imports at module level, and ``assurance.api.service`` imports that:
an image built from it could not start. Nothing caught it because every test runs in an
environment that has the full requirements.

Checks, none of which builds an image (no daemon is assumed) or touches a network:

1. only the ``RUN pip install`` commands are read, with comment lines removed, so a package or
   flag named in a comment cannot mask its removal from the real command;
2. every ``pip install`` of the service's dependencies is ``--require-hashes`` and ``--no-deps``
   from a lock file that exists, is COPYed into the build stage, and pins every package with
   a hash (no ranges, no bare ``pip install fastapi``);
3. every third-party import anywhere under ``src/assurance`` (the whole tree is copied into
   the image), including ``importlib.import_module("x")`` and ``__import__("x")`` with a
   literal name, must be provided by a package pinned in that lock, unless it is listed here
   as deliberately not shipped;
4. ``import assurance.api.service`` is run in a fresh interpreter whose import system
   refuses every top-level package outside the standard library and the locked packages,
   which is what the image's interpreter would see. This catches an implicit runtime
   requirement of a dependency (it raises ``ModuleNotFoundError`` exactly as the image would).
"""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import pytest
from packaging.utils import canonicalize_name

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "deploy" / "assurance" / "Dockerfile"
SRC = REPO / "src" / "assurance"

#: third-party imports under src/assurance that the image intentionally does not install.
NOT_SHIPPED = {
    "mcp": "the optional MCP gateway (assurance/mcp/server.py); the image's CMD is the HTTP "
           "service and never imports it",
}


def pip_install_commands(text: str) -> list[str]:
    """Each logical ``pip install`` command (continuations joined), comments removed."""
    logical: list[str] = []
    pending = ""
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        pending += " " + line.rstrip()
        if pending.endswith("\\"):
            pending = pending[:-1]
            continue
        logical.append(" ".join(pending.split()))
        pending = ""
    return [ln for ln in logical if "pip install" in ln]


def locked_requirements_files(text: str) -> list[str]:
    """Paths given to ``-r`` on pip install commands that install the service's dependencies."""
    paths: list[str] = []
    for cmd in pip_install_commands(text):
        paths += re.findall(r"(?:^|\s)-r\s+(\S+)", cmd)
    return paths


def locked_names(lock_text: str) -> set[str]:
    """Canonical names pinned (``name==version``) in a uv-generated lock."""
    names: set[str] = set()
    for line in lock_text.splitlines():
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==", line)
        if m:
            names.add(canonicalize_name(m.group(1)))
    return names


def image_lock() -> Path:
    paths = locked_requirements_files(DOCKERFILE.read_text(encoding="utf-8"))
    assert len(paths) == 1, f"expected one locked install in the Dockerfile, found {paths}"
    return REPO / "requirements" / Path(paths[0]).name


def top_levels(dists: set[str]) -> set[str]:
    """Importable top-level names those distributions provide."""
    names: set[str] = set()
    for top, owners in metadata.packages_distributions().items():
        if any(canonicalize_name(o) in dists for o in owners):
            names.add(top)
    return names


def imports_of(path: Path) -> set[str]:
    """Top-level names imported by a module, including literal importlib/__import__ calls."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            found.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and node.args \
                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            func = ast.unparse(node.func)
            if func in {"importlib.import_module", "import_module", "__import__"}:
                found.add(node.args[0].value.split(".")[0])
    return {n for n in found if n not in sys.stdlib_module_names and n not in {
        "assurance", "__future__"}}


def shipped() -> set[str]:
    return top_levels(locked_names(image_lock().read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------

def assert_hash_checked_install(text: str) -> None:
    commands = pip_install_commands(text)
    assert commands, "no pip install in the Dockerfile"
    for cmd in commands:
        assert "--upgrade pip" not in cmd, f"an unpinned pip self-upgrade defeats the lock: {cmd}"
        assert "--require-hashes" in cmd and "--no-deps" in cmd and re.search(
            r"\s-r\s+\S+\.lock\b", cmd), f"not a hash-checked install from a lock: {cmd}"
        assert not re.search(r"[A-Za-z][\w.-]*(\[[^\]]*\])?\s*[<>=!~]=", cmd), (
            f"a ranged requirement on the command line: {cmd}")
    # the file the RUN reads must be copied into the stage first
    assert re.search(r"^COPY\s+requirements/assurance-service\.lock\s", text, re.M), (
        "requirements/assurance-service.lock is not COPYed into the build stage")


def test_the_dockerfile_installs_the_service_lock_with_hashes_and_no_resolution():
    assert_hash_checked_install(DOCKERFILE.read_text(encoding="utf-8"))
    lock = image_lock()
    assert lock.name == "assurance-service.lock" and lock.is_file()


def test_the_locked_install_names_the_packages_the_service_needs():
    names = locked_names(image_lock().read_text(encoding="utf-8"))
    assert {"fastapi", "uvicorn", "pydantic", "httpx", "cryptography", "starlette"} <= names, names


def test_a_package_or_flag_named_only_in_a_comment_is_not_counted():
    text = (
        "# 'cryptography>=42.0.0' is needed, says this comment\n"
        "# RUN pip install --require-hashes --no-deps -r requirements/assurance-service.lock\n"
        "RUN pip install --no-cache-dir -r /tmp/x.lock \\\n"
        "      # --require-hashes\n"
        "      --no-deps\n"
        "RUN echo 'cryptography' && pip --version\n")
    cmds = pip_install_commands(text)
    assert len(cmds) == 1 and "--require-hashes" not in cmds[0], cmds


def test_every_third_party_import_in_the_shipped_tree_is_provided_by_the_image():
    provided = shipped()
    assert {"fastapi", "starlette", "pydantic", "httpx", "uvicorn", "cryptography"} <= provided
    missing: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        for name in imports_of(path) - provided - set(NOT_SHIPPED):
            missing.setdefault(name, []).append(str(path.relative_to(SRC)))
    assert not missing, f"imported under src/assurance but not installed by the image: {missing}"
    for name in NOT_SHIPPED:
        assert any(name in imports_of(p) for p in SRC.rglob("*.py")), (
            f"{name} is listed as not shipped but nothing imports it: remove it from NOT_SHIPPED")


def test_the_import_scan_sees_literal_dynamic_imports(tmp_path):
    module = tmp_path / "m.py"
    module.write_text(
        "import importlib\nx = importlib.import_module('alpha.beta')\n"
        "y = __import__('gamma')\nz = importlib.import_module(name)\nimport os, delta\n")
    assert imports_of(module) == {"alpha", "gamma", "delta"}


BLOCKER = """
import importlib.abc, json, sys
blocked = set(json.loads(sys.argv[2]))
class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        top = name.partition(".")[0]
        if top in blocked:
            raise ModuleNotFoundError(f"No module named {top!r} (not in the image)", name=top)
        return None
sys.meta_path.insert(0, Block())
sys.path.insert(0, sys.argv[1])
import assurance.api.service
print("imported")
"""


def not_in_the_image() -> list[str]:
    """Every installed third-party top-level name the image would not have."""
    installed = set(metadata.packages_distributions())
    return sorted(installed - shipped() - set(sys.stdlib_module_names) - {"assurance"})


def test_the_service_imports_in_an_interpreter_that_has_only_what_the_image_installs():
    blocked = not_in_the_image()
    assert "mcp" in blocked or "yaml" in blocked or blocked, "nothing is blocked: the check is empty"
    out = subprocess.run(  # noqa: S603  (our own interpreter, fixed code)
        [sys.executable, "-c", BLOCKER, str(REPO / "src"), json.dumps(blocked)],
        capture_output=True, text=True, timeout=180, cwd=REPO)
    assert out.returncode == 0 and "imported" in out.stdout, out.stderr[-3000:]


def test_the_blocker_really_blocks(tmp_path):
    """A package outside the allowed set cannot be imported: the check above is not vacuous."""
    code = BLOCKER.replace("import assurance.api.service", "import cryptography")
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-c", code, str(REPO / "src"), json.dumps(["cryptography"])],
        capture_output=True, text=True, timeout=60, cwd=tmp_path)
    assert out.returncode != 0 and "not in the image" in out.stderr


@pytest.mark.parametrize("dropped", ["cryptography", "httpx"])
def test_removing_a_package_from_the_lock_is_noticed(dropped):
    lock = image_lock().read_text(encoding="utf-8")
    assert dropped in locked_names(lock)
    stripped = "\n".join(ln for ln in lock.splitlines()
                         if not ln.lower().startswith(f"{dropped}=="))
    assert dropped not in locked_names(f"# {dropped}==1\n" + stripped)


@pytest.mark.parametrize("weakened", [
    "RUN pip install --no-cache-dir -r /tmp/assurance-service.lock",
    "RUN pip install --require-hashes -r /tmp/assurance-service.lock",
    "RUN pip install --require-hashes --no-deps 'fastapi>=0.110.0'",
    "RUN pip install --upgrade pip --require-hashes --no-deps -r /tmp/a.lock",
])
def test_a_weakened_install_command_is_rejected(weakened):
    copy = "COPY requirements/assurance-service.lock /tmp/\n"
    with pytest.raises(AssertionError):
        assert_hash_checked_install(copy + weakened + "\n")
    good = "RUN pip install --require-hashes --no-deps --prefix=/install -r /tmp/assurance-service.lock"
    assert_hash_checked_install(copy + good + "\n")
