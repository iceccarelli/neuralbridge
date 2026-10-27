"""The deploy image installs everything the service imports.

``deploy/assurance/Dockerfile`` installs a short list of packages on purpose. It once
omitted ``cryptography``, which ``assurance.attest.keys`` imports at module level, and
``assurance.api.service`` imports that: an image built from it could not start. Nothing
caught it because every test runs in an environment that has the full requirements.

Three checks, none of which builds an image (no daemon is assumed) or touches a network:

1. only the ``RUN pip install`` lines are read, with comment lines removed, so a package
   named in a comment cannot mask its removal from the real command;
2. every third-party import anywhere under ``src/assurance`` (the whole tree is copied into
   the image), including ``importlib.import_module("x")`` and ``__import__("x")`` with a
   literal name, must be provided by those packages or their *transitive* requirements,
   read from the installed metadata, unless it is listed here as deliberately not shipped;
3. ``import assurance.api.service`` is run in a fresh interpreter whose import system
   refuses every top-level package outside the standard library and that same closure,
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
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

REPO = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO / "deploy" / "assurance" / "Dockerfile"
SRC = REPO / "src" / "assurance"

#: third-party imports under src/assurance that the image intentionally does not install.
NOT_SHIPPED = {
    "mcp": "the optional MCP gateway (assurance/mcp/server.py); the image's CMD is the HTTP "
           "service and never imports it",
}


def pip_install_requirements(text: str) -> list[Requirement]:
    """The quoted requirement specs on ``pip install`` lines, comments removed."""
    logical: list[str] = []
    pending = ""
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        pending += " " + line.rstrip()
        if pending.endswith("\\"):
            pending = pending[:-1]
            continue
        logical.append(pending)
        pending = ""
    found: list[Requirement] = []
    for line in logical:
        if "pip install" not in line:
            continue
        for spec in re.findall(r"'([^']+)'", line):
            try:
                found.append(Requirement(spec))
            except InvalidRequirement:
                continue
    return found


def closure(roots: list[Requirement]) -> set[str]:
    """Canonical names of ``roots`` and everything they require that is installed here."""
    seen: set[str] = set()
    stack = [(r.name, set(r.extras)) for r in roots]
    done: set[tuple[str, frozenset[str]]] = set()
    while stack:
        name, extras = stack.pop()
        key = (canonicalize_name(name), frozenset(extras))
        if key in done:
            continue
        done.add(key)
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        seen.add(canonicalize_name(name))
        for raw in dist.requires or []:
            req = Requirement(raw)
            if req.marker is not None and not any(
                    req.marker.evaluate({"extra": e}) for e in (extras | {""})):
                continue
            stack.append((req.name, set(req.extras)))
    return seen


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
    return top_levels(closure(pip_install_requirements(DOCKERFILE.read_text(encoding="utf-8"))))


# ---------------------------------------------------------------------------

def test_the_dockerfile_names_the_packages_the_service_needs():
    names = {canonicalize_name(r.name)
             for r in pip_install_requirements(DOCKERFILE.read_text(encoding="utf-8"))}
    assert {"fastapi", "uvicorn", "pydantic", "httpx", "cryptography"} <= names, names


def test_a_package_named_only_in_a_comment_is_not_counted_as_installed():
    text = (
        "# 'cryptography>=42.0.0' is needed, says this comment\n"
        "RUN pip install --no-cache-dir 'fastapi>=0.110.0' \\\n"
        "      # 'also-in-a-comment>=1'\n"
        "      'httpx>=0.27.0'\n"
        "RUN echo 'cryptography' && pip --version\n")
    names = {canonicalize_name(r.name) for r in pip_install_requirements(text)}
    assert names == {"fastapi", "httpx"}, names


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
def test_removing_a_package_from_the_real_pip_line_is_noticed(dropped):
    text = DOCKERFILE.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    stripped = "\n".join(ln.replace(f"'{dropped}>=42.0.0'", "").replace(
        f"'{dropped}>=0.27.0'", "") for ln in lines)
    # commented mentions are kept, as a reviewer's masking attempt would
    text = f"# '{dropped}>=1'\n" + stripped
    remaining = {canonicalize_name(r.name) for r in pip_install_requirements(text)}
    assert dropped not in remaining
