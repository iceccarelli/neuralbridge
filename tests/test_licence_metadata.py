"""The licence is declared the way current packaging standards want, and is still proprietary.

``license = {text = "..."}`` and the ``License :: ...`` trove classifiers are deprecated by
PEP 639; setuptools warns on every build ("SetuptoolsDeprecationWarning: `project.license` as a
TOML table is deprecated"). The replacement is an SPDX license *expression* plus
``license-files``. This product has no SPDX identifier (it is proprietary, all rights reserved),
so the expression is a ``LicenseRef-`` and the terms travel in the ``LICENSE`` file, which is
published as ``License-File``. Switching to an open-source identifier would change the terms and
is not something packaging metadata may do, so that is pinned here too.

Needs no network and imports nothing the ``.[dev]`` extra does not install (setuptools is only
the build backend; tests/test_packaging_contract.py forbids a test importing it). The real
check, ``python -m build`` plus ``twine check`` with no setuptools deprecation warning, is run
per Python version outside the suite.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
PROJECT = PYPROJECT["project"]


def test_the_licence_is_an_spdx_licenseref_expression_and_not_the_deprecated_table() -> None:
    lic = PROJECT["license"]
    assert isinstance(lic, str), (
        "project.license must be an SPDX expression string; the {text = ...} table is deprecated"
    )
    assert re.fullmatch(r"LicenseRef-[A-Za-z0-9.\-]+", lic), (
        f"{lic!r}: a proprietary licence has no SPDX id, so it must be a LicenseRef-... expression"
    )


def test_the_licence_file_is_shipped_and_the_deprecated_classifier_is_gone() -> None:
    files = PROJECT["license-files"]
    assert files == ["LICENSE"]
    assert (ROOT / "LICENSE").is_file()
    assert not [c for c in PROJECT["classifiers"] if c.startswith("License ::")], (
        "License :: classifiers are deprecated by PEP 639 and conflict with License-Expression"
    )


def test_the_licence_stays_proprietary() -> None:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert "NO LICENCE IS GRANTED" in text and "All rights reserved" in text
    assert "proprietary" in PROJECT["license"].lower(), "do not relabel the terms as open source"


def test_the_build_requires_a_setuptools_that_understands_pep_639() -> None:
    requires = [Requirement(r) for r in PYPROJECT["build-system"]["requires"]]
    setuptools = next(r for r in requires if r.name == "setuptools")
    # 77.0.0 is the first release that accepts a license expression and license-files.
    floor = min(Version(str(s.version)) for s in setuptools.specifier if s.operator == ">=")
    assert floor >= Version("77.0.0"), f"setuptools {setuptools.specifier} predates PEP 639"

