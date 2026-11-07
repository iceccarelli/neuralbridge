"""One dev setup, three declarations that must not drift apart.

The development environment is declared in three places:

* ``pyproject.toml`` ``[project.optional-dependencies] dev``  -> ``pip install -e '.[dev]'``
  (what a developer, ``README.md`` and ``docs/`` use);
* ``requirements/dev.txt`` (+ ``base.txt``)                   -> CI's *Lint & Type Check* job
  (``ruff check`` and ``mypy``);
* ``requirements/test.txt`` (+ ``base.txt``)                  -> CI's *test* matrix.

Before this file existed they disagreed silently: the ``dev`` extra lacked the ``types-*`` stubs
that CI's mypy run has, and did not bound ruff the way ``dev.txt`` does, so "green locally" and
"green in CI" could be two different checks. These tests make the disagreement a failure.

They also make the other classic failure loud. ``mypy`` run in an environment that is missing a
dependency does not fail with "package X is not installed": it reports hundreds of unrelated
``import-not-found`` / ``attr-defined`` / ``no-any-return`` errors. The last two tests fail first,
and say which package to install, so that a developer reads the cause before the symptom.
"""

from __future__ import annotations

import importlib.util
import re
import tomllib
from importlib import metadata
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parent.parent
REQ = ROOT / "requirements"
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
EXTRAS = PROJECT["optional-dependencies"]
SELF = canonicalize_name(PROJECT["name"])

#: In requirements/dev.txt for interactive notebook work only; no CI job and no test uses them.
NOTEBOOK_ONLY = {"ipython", "jupyter", "nbformat"}
#: In requirements/test.txt but imported by no test (checked below), so not part of ``.[dev]``.
UNUSED_TEST_FIXTURE_LIBS = {"factory-boy", "faker"}
#: In ``.[dev]`` but not in a requirements file: ``packaging`` is a direct test import that pytest
#: already brings in, so CI always has it; ``.[dev]`` names it because the tests import it.
PYPROJECT_ONLY = {"packaging"}

INSTALL = "python -m pip install -e '.[dev]'"


def _read_txt(name: str, seen: frozenset[str] = frozenset()) -> dict[str, Requirement]:
    """Requirements of ``requirements/<name>`` including ``-r`` includes, keyed by canonical name."""
    out: dict[str, Requirement] = {}
    for raw in (REQ / name).read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r "):
            inc = line[3:].strip()
            assert inc not in seen, f"include cycle at {inc}"
            out.update(_read_txt(inc, seen | {name}))
            continue
        req = Requirement(line)
        out[canonicalize_name(req.name)] = req
    return out


def _direct(extra: str) -> dict[str, Requirement]:
    return {canonicalize_name(Requirement(r).name): Requirement(r) for r in EXTRAS[extra]
            if canonicalize_name(Requirement(r).name) != SELF}


def _closure(extra: str, seen: frozenset[str] = frozenset()) -> dict[str, Requirement]:
    """Every requirement an extra installs, following ``neuralbridge-middleware[other]``."""
    out: dict[str, Requirement] = {}
    for raw in EXTRAS[extra]:
        req = Requirement(raw)
        if canonicalize_name(req.name) == SELF:
            for sub in req.extras:
                if sub not in seen:
                    out.update(_closure(sub, seen | {extra, sub}))
        else:
            out[canonicalize_name(req.name)] = req
    return out


def _spec(req: Requirement) -> str:
    return str(sorted(str(s) for s in req.specifier))


def _runtime_in_dev() -> dict[str, Requirement]:
    """What ``.[dev]`` installs through the product extras it references (not the tool list)."""
    out: dict[str, Requirement] = {}
    for raw in EXTRAS["dev"]:
        req = Requirement(raw)
        if canonicalize_name(req.name) == SELF:
            for extra in req.extras:
                out.update(_closure(extra, frozenset({"dev", extra})))
    return out


def test_the_dev_extra_and_the_ci_requirements_pin_the_same_tools() -> None:
    dev_extra = _direct("dev")
    ci = {**_read_txt("test.txt"), **_read_txt("dev.txt")}
    base = _read_txt("base.txt")
    ci_tools = {n: r for n, r in ci.items() if n not in base}

    missing_from_extra = set(ci_tools) - set(dev_extra) - NOTEBOOK_ONLY - UNUSED_TEST_FIXTURE_LIBS
    assert not missing_from_extra, (
        f"CI installs {sorted(missing_from_extra)} (requirements/dev.txt or test.txt) but "
        f"pyproject.toml's `dev` extra does not: `{INSTALL}` would not reproduce CI. Add them to "
        "the extra, or list them in NOTEBOOK_ONLY / UNUSED_TEST_FIXTURE_LIBS with a reason."
    )
    missing_from_ci = set(dev_extra) - set(ci_tools) - PYPROJECT_ONLY - {"httpx"}
    assert not missing_from_ci, (
        f"pyproject.toml's `dev` extra installs {sorted(missing_from_ci)} that no CI requirements "
        "file does: a local run would use a tool CI never runs."
    )
    for name in sorted(set(dev_extra) & set(ci_tools)):
        assert _spec(dev_extra[name]) == _spec(ci_tools[name]), (
            f"{name}: `dev` extra says {dev_extra[name]}, CI requirements say {ci_tools[name]}. "
            "The bound must be identical or local and CI can run different versions."
        )


def test_the_dev_extra_installs_the_same_runtime_bounds_as_base_txt() -> None:
    runtime = _runtime_in_dev()
    base = _read_txt("base.txt")
    for name in sorted(set(runtime) & set(base)):
        assert _spec(runtime[name]) == _spec(base[name]), (
            f"{name}: pyproject says {runtime[name]}, requirements/base.txt says {base[name]}"
        )
    # Everything CI's runtime install has must come out of `.[dev]` too, or a test that passes
    # locally can import a package CI has and the local venv does not (or the reverse).
    only_ci = set(base) - set(runtime)
    assert not only_ci, f"`.[dev]` does not install {sorted(only_ci)}, which requirements/base.txt does"


def test_no_test_imports_the_fixture_libraries_left_out_of_the_dev_extra() -> None:
    pattern = re.compile(r"^\s*(?:import|from)\s+(factory|faker)\b", re.M)
    users = [p.name for p in (ROOT / "tests").rglob("*.py")
             if pattern.search(p.read_text(encoding="utf-8"))]
    assert not users, (
        f"{users} import factory/faker, which `.[dev]` omits because no test used them; move "
        "factory-boy/faker out of UNUSED_TEST_FIXTURE_LIBS and into the extra"
    )


def test_the_interpreter_has_every_runtime_dependency_the_dev_extra_declares() -> None:
    """The cause, stated before mypy's hundreds of misleading symptoms."""
    problems: list[str] = []
    for name, req in sorted({**_runtime_in_dev(), **_direct("dev")}.items()):
        if name in PYPROJECT_ONLY | NOTEBOOK_ONLY:
            continue
        try:
            installed = metadata.version(name)
        except metadata.PackageNotFoundError:
            if name == "mypy" or name == "ruff" or name == "pre-commit":
                continue  # tools are judged by the next test, only where they are used
            problems.append(f"{name} is not installed")
            continue
        if installed not in req.specifier and not req.specifier.contains(installed, prereleases=True):
            problems.append(f"{name} {installed} does not satisfy {req.specifier}")
    assert not problems, (
        "this interpreter is not a complete development environment: "
        + "; ".join(problems)
        + f". Run `{INSTALL}` in a clean virtualenv. Do NOT run mypy or ruff first: with a "
        "dependency missing mypy prints hundreds of unrelated errors."
    )


def test_where_mypy_is_installed_its_stub_packages_are_too() -> None:
    if importlib.util.find_spec("mypy") is None:
        # Not a lint environment (CI's test legs install requirements/test.txt only), so there is
        # no type check here to be wrong. Asserting nothing is the honest outcome, not a skip.
        return
    stubs = {n: r for n, r in _direct("dev").items() if n.startswith("types-")}
    assert stubs, "the dev extra must carry the stubs CI's mypy run has (types-PyYAML, types-PyMySQL)"
    absent = []
    for name, req in stubs.items():
        try:
            metadata.version(name)
        except metadata.PackageNotFoundError:
            absent.append(str(req))
    assert not absent, (
        f"mypy is installed but its stubs are not: {absent}. CI's mypy has them, so this run "
        f"would disagree with CI. Run `{INSTALL}`."
    )
