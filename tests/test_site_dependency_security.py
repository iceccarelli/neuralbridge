"""The website's framework dependencies stay on patched releases.

The Next.js site (``app/``) runs the Image Optimization API, Server Actions and the App Router on
whatever ``next`` the lockfile resolves. ``next@14.2.15`` carried dozens of advisories (npm's own
registry flags it as deprecated for a security vulnerability), among them unauthenticated remote
code execution in the Image Optimization API (SVG: GHSA-2464-fhr4-w9xw; AVIF: GHSA-2xp9-vwfh-vxw4),
an authorization bypass in middleware (GHSA-f82v-jwr5-mffw) and several denial-of-service and SSRF
issues. The SVG fix also needs ``sharp`` 0.35.5 or later.

CI runs pytest, not Node, so a downgrade, a caret range that resolves lower in a fresh lockfile, or a
hand-edited ``package.json`` that leaves the lockfile behind would otherwise merge unnoticed. These
tests read what is actually pinned and locked. They do not call the network; they cannot prove the
absence of a vulnerability that has not been published, only that the known-bad versions are not
what we ship. ``npm audit --omit=dev`` is the live check and is recorded in the pull request.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
LOCK = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
NEXT_CONFIG = (ROOT / "next.config.js").read_text(encoding="utf-8")

#: The lowest release on each supported line that contains the 14 October 2026 fixes
#: (registry: 15.5.28 is the last 15.x, 16.4.1 the first 16.x with them).
MIN_NEXT = {15: (15, 5, 28), 16: (16, 4, 1)}
MIN_SHARP = (0, 35, 5)


def _version(text: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", text)
    assert match, f"{text!r} is not an exact x.y.z version"
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _locked(name: str) -> dict:
    entry = LOCK["packages"].get(f"node_modules/{name}")
    assert entry, f"{name} is not in package-lock.json"
    return entry


def test_next_is_pinned_exactly():
    declared = PACKAGE["dependencies"]["next"]
    assert re.fullmatch(r"\d+\.\d+\.\d+", declared), (
        f"next is declared as {declared!r}; pin an exact patched release so a fresh install "
        "cannot resolve a different one")


def test_the_locked_next_is_a_patched_release():
    locked = _version(_locked("next")["version"])
    floor = MIN_NEXT.get(locked[0])
    assert floor is not None, (
        f"next {locked} is on an unsupported major line; supported lines: {sorted(MIN_NEXT)}")
    assert locked >= floor, f"next {locked} is below the patched release {floor}"


def test_the_lockfile_and_package_json_agree_on_next():
    assert _locked("next")["version"] == PACKAGE["dependencies"]["next"]


def test_the_lockfile_does_not_mark_next_as_vulnerable():
    """npm's registry sets ``deprecated`` on releases with a known security vulnerability."""
    assert "deprecated" not in _locked("next"), _locked("next").get("deprecated")


def test_sharp_is_at_least_the_librsvg_fix():
    assert _version(_locked("sharp")["version"]) >= MIN_SHARP
    declared = PACKAGE["dependencies"]["sharp"]
    assert _version(declared.lstrip("^~")) >= MIN_SHARP, declared


def test_no_nested_sharp_below_the_fix():
    for path, entry in LOCK["packages"].items():
        if path.endswith("/sharp") and entry.get("version"):
            assert _version(entry["version"]) >= MIN_SHARP, f"{path}: {entry['version']}"


def test_next_never_resolves_a_bundled_postcss_with_known_source_map_reads():
    """Next bundles its own postcss; 8.5.23+ carries the sourceMappingURL fixes."""
    nested = LOCK["packages"].get("node_modules/next/node_modules/postcss")
    if nested is not None:
        assert _version(nested["version"]) >= (8, 5, 23), nested["version"]


def test_the_declared_node_floor_matches_what_next_requires():
    engines = LOCK["packages"]["node_modules/next"].get("engines", {}).get("node", "")
    floor = re.search(r">=\s*(\d+)\.(\d+)", engines)
    if floor:
        needed = (int(floor.group(1)), int(floor.group(2)))
        declared = re.search(r">=\s*(\d+)\.(\d+)", PACKAGE.get("engines", {}).get("node", ""))
        assert declared, "package.json must declare the Node floor Next requires"
        assert (int(declared.group(1)), int(declared.group(2))) >= needed


@pytest.mark.parametrize("flag", ["dangerouslyAllowSVG", "unoptimized: true"])
def test_image_optimization_is_not_widened(flag):
    """SVG through the optimizer was the route to the critical RCE; do not opt back in."""
    assert flag not in NEXT_CONFIG


def test_there_is_no_dead_lint_script():
    """``next lint`` was removed in Next 16; a script that cannot run hides that nothing lints."""
    assert PACKAGE["scripts"].get("lint") != "next lint"
    assert PACKAGE["scripts"].get("typecheck") == "tsc --noEmit"
