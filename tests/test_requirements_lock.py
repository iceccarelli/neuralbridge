"""The committed Python locks are hash-pinned and cover what the inputs declare.

No network and no resolver: this only reads text. It cannot prove the lock is the *current*
resolution of its input (that needs ``uv`` and an index; the "Lock drift" CI job runs
``scripts/lock.sh --check`` for that). It does catch the common mistakes: a requirement
added to ``requirements/*.txt`` or ``pyproject.toml`` without regenerating, a hand-edited
unpinned line, or a package with no hash.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

REPO = Path(__file__).resolve().parents[1]
REQ = REPO / "requirements"

#: lock file -> input it is generated from (see scripts/lock.sh)
LOCKS = {
    "prod.lock": "prod.txt",
    "assurance-service.lock": "assurance-service.txt",
    "test.lock": "test.txt",
}
HOWTO = "run scripts/lock.sh and commit the regenerated requirements/*.lock"

PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\]+)")


def parse_lock(path: Path) -> dict[str, dict]:
    """name -> {version, hashes, line} for each pinned entry in a uv --generate-hashes file."""
    entries: dict[str, dict] = {}
    current = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            m = PIN.match(line)
            assert m, f"{path.name}: not an exact '==' pin: {line!r}. {HOWTO}"
            current = canonicalize_name(m.group(1))
            entries[current] = {"version": m.group(2), "hashes": [], "line": line}
            continue
        m = re.match(r"\s*--hash=sha256:([0-9a-f]{64})\b", line)
        if m:
            assert current is not None
            entries[current]["hashes"].append(m.group(1))
    return entries


def declared(path: Path, seen: set[Path] | None = None) -> set[str]:
    """Canonical package names declared in a requirements .txt, following ``-r`` includes."""
    seen = seen if seen is not None else set()
    if path in seen:
        return set()
    seen.add(path)
    names: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-r "):
            names |= declared(path.parent / line[3:].strip(), seen)
        elif not line.startswith("-"):
            names.add(canonicalize_name(Requirement(line).name))
    return names


@pytest.fixture(scope="module")
def pyproject_deps() -> set[str]:
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return {canonicalize_name(Requirement(d).name) for d in data["project"]["dependencies"]}


@pytest.mark.parametrize("lock", sorted(LOCKS))
def test_every_package_is_exactly_pinned_with_at_least_one_hash(lock):
    entries = parse_lock(REQ / lock)
    assert entries, f"{lock} is empty. {HOWTO}"
    unhashed = sorted(n for n, e in entries.items() if not e["hashes"])
    assert not unhashed, f"{lock}: no --hash for {unhashed}. {HOWTO}"


@pytest.mark.parametrize("lock", sorted(LOCKS))
def test_no_line_in_a_lock_uses_a_range(lock):
    for raw in (REQ / lock).read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#") or raw.startswith((" ", "\t")):
            continue
        spec = raw.split(";", 1)[0]
        assert not re.search(r"[<>~!]=?|===", spec.replace("==", "")), (
            f"{lock}: unpinned or ranged requirement {raw!r}. {HOWTO}")


@pytest.mark.parametrize("lock", sorted(LOCKS))
def test_the_lock_is_self_consistent_and_has_no_index_override(lock):
    text = (REQ / lock).read_text(encoding="utf-8")
    assert not re.search(r"^\s*(--(extra-)?index-url|--find-links|-e |git\+|https?://)", text,
                         re.MULTILINE), f"{lock} names an index, URL or VCS source"
    for name, e in parse_lock(REQ / lock).items():
        assert len(set(e["hashes"])) == len(e["hashes"]), f"{lock}: duplicate hash for {name}"


@pytest.mark.parametrize("lock", sorted(LOCKS))
def test_every_top_level_requirement_in_the_input_is_in_the_lock(lock):
    inputs = declared(REQ / LOCKS[lock])
    assert inputs, f"{LOCKS[lock]} declares nothing"
    locked = set(parse_lock(REQ / lock))
    missing = sorted(inputs - locked)
    assert not missing, (
        f"requirements/{LOCKS[lock]} declares {missing} but requirements/{lock} does not pin "
        f"them: the lock is older than the input. {HOWTO}")


def test_every_runtime_dependency_in_pyproject_is_in_the_prod_lock(pyproject_deps):
    locked = set(parse_lock(REQ / "prod.lock"))
    missing = sorted(pyproject_deps - locked)
    assert not missing, (
        f"pyproject.toml [project].dependencies has {missing} that requirements/prod.lock "
        f"does not pin. {HOWTO}")


def test_the_assurance_service_lock_covers_the_assurance_api_extra():
    data = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    extra = {canonicalize_name(Requirement(d).name)
             for d in data["project"]["optional-dependencies"]["assurance-api"]}
    locked = set(parse_lock(REQ / "assurance-service.lock"))
    assert extra <= locked, f"[assurance-api] needs {sorted(extra - locked)}. {HOWTO}"
    # and the image's own pip line (deploy/assurance/Dockerfile) is the input's contents
    assert declared(REQ / "assurance-service.txt") >= extra


def test_a_ranged_or_unhashed_lock_would_be_caught(tmp_path):
    bad = tmp_path / "bad.lock"
    bad.write_text("fastapi==0.1 \\\n    --hash=sha256:" + "a" * 64 + "\nhttpx\n")
    with pytest.raises(AssertionError):
        parse_lock(bad)
    unhashed = tmp_path / "unhashed.lock"
    unhashed.write_text("fastapi==0.1\n")
    assert parse_lock(unhashed)["fastapi"]["hashes"] == []
