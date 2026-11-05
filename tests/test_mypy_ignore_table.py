"""The mypy debt table in pyproject.toml stays explicit, honest and shrinking.

``src/assurance/`` is type-checked in CI. Modules that had errors when that began are listed by
name under ``[[tool.mypy.overrides]]`` with ``ignore_errors``. This test keeps that list from
turning into a blanket ignore: no wildcard, no ``src/neuralbridge`` modules (that package is clean
and strict), and every name is a real module, so a deleted or renamed one cannot linger.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def overrides() -> list[dict]:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return data["tool"]["mypy"]["overrides"]


def ignored_modules() -> list[str]:
    names: list[str] = []
    for block in overrides():
        if block.get("ignore_errors"):
            mods = block["module"]
            names += [mods] if isinstance(mods, str) else list(mods)
    return names


def test_strict_mode_is_on_for_everything_not_listed():
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert data["tool"]["mypy"]["strict"] is True


def test_there_is_no_wildcard_and_nothing_outside_assurance_is_ignored():
    names = ignored_modules()
    assert names, "the table is empty: delete the override and this test together"
    for name in names:
        assert "*" not in name, f"wildcard in the mypy ignore table: {name}"
        assert name.startswith("assurance."), f"only src/assurance/ modules may be listed: {name}"
    assert len(names) == len(set(names)), "duplicate entry in the mypy ignore table"
    assert names == sorted(names), "keep the table sorted so a diff shows what was added"


def test_every_listed_module_exists():
    for name in ignored_modules():
        base = REPO / "src" / Path(*name.split("."))
        assert base.with_suffix(".py").is_file() or (base / "__init__.py").is_file(), (
            f"{name} is in the mypy ignore table but does not exist: delete the entry")


def test_no_other_override_ignores_errors_or_missing_imports_wholesale():
    for block in overrides():
        if block.get("ignore_errors"):
            continue
        assert not block.get("ignore_missing_imports") or "*" not in str(block["module"])
