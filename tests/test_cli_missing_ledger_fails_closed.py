"""A mistyped ``--ledger`` must be an error, never a new empty ledger.

Before this, ``machinery passport`` / ``machinery check`` / every ``change`` case verb created
the file named on the command line and then answered against it: ``change list`` reported an
empty queue (exit 0) and ``machinery check`` printed ``OK`` for a passport "verified" against
a ledger that had just been born. A new empty ledger reads as "no machines", "nothing open"
or "nothing contradicts this", which is exactly the wrong thing to say about a typo.

Each command is run as a subprocess (``python -m assurance``), because the exit code and the
files left behind are what a shell, a cron job or CI sees.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

MISSING = "does not exist"


def run(*args: str | Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "assurance", *map(str, args)],
        capture_output=True, text=True, cwd=cwd, timeout=120, check=False)


def _verbs(led: Path, f: Path) -> list[tuple[str, ...]]:
    ledger = ("--ledger", str(led))
    # Deliberately absent: `machine verify --ledger` SEALS the verification into the ledger, so it is
    # a write path that creates one on first use (the independent lab's attack suite relies on it).
    return [
        ("machinery", "passport", str(f), *ledger, "--actor", "bob"),
        ("machinery", "check", str(f), *ledger),
        ("change", "list", *ledger),
        ("change", "show", "c1", *ledger),
        ("change", "claim", "c1", "--owner", "bob", "--actor", "bob", *ledger),
        ("change", "advance", "c1", *ledger),
        ("change", "reverify", "c1", "--manifest", str(f), "--verification-hash", "0" * 64, *ledger),
        ("change", "decide", "c1", "--disposition", "closed", "--reason", "x", "--actor", "bob", *ledger),
        ("change", "resolve-decision", "c1", "--number", "1", "--resolution", "x", "--actor", "bob", *ledger),
        ("change", "waive-reverification", "c1", "--entry", "e", "--reason", "x", "--actor", "bob", *ledger),
        ("change", "resume", "c1", "--reason", "x", "--actor", "bob", *ledger),
        ("change", "assess-intervention", "--manifest", str(f), "--intervention-id", "i1", *ledger),
        ("change", "replay", "c1", *ledger),
        ("change", "export", "c1", *ledger),
        ("change", "assess-drift", "--baseline", str(f), "--observed", str(f), *ledger),
        ("change", "assess-advisory", "--advisory", str(f), *ledger),
        ("report", "build", "--out", str(f.parent / "r.html"), *ledger),
        ("attest", "verify", "--log", str(f), "--public-key", str(f), *ledger),
        ("bridge", "art14", str(f), "--received-by", "bob", *ledger),
        ("fleet", "list", *ledger),
        ("value", "report", *ledger),
    ]


def _names() -> list[str]:
    return [" ".join(v[:2]) for v in _verbs(Path("x"), Path("f"))]


@pytest.mark.parametrize("index", range(len(_names())), ids=_names())
def test_a_missing_ledger_is_exit_2_and_creates_nothing(tmp_path, index):
    led = tmp_path / "typo-ledger.db"
    f = tmp_path / "input.json"
    f.write_text("{}", encoding="utf-8")
    verb = _verbs(led, f)[index]
    r = run(*verb, cwd=tmp_path)
    assert not led.exists(), f"{verb[:2]} created {led.name}: {r.stdout}{r.stderr}"
    assert r.returncode == 2, (verb[:2], r.returncode, r.stdout, r.stderr)
    assert MISSING in r.stderr, (verb[:2], r.stderr)
    assert [p.name for p in tmp_path.iterdir() if p.suffix in {".db", ".sqlite"}] == []


def test_a_passport_is_not_verified_against_a_ledger_that_was_just_invented(tmp_path):
    """The exact reproduction from the ledger audit: passport then check, both typo'd."""
    led = tmp_path / "typo-ledger.db"
    f = tmp_path / "m.json"
    f.write_text("{}", encoding="utf-8")
    check = run("machinery", "check", f, "--ledger", led, cwd=tmp_path)
    assert check.returncode == 2 and "OK" not in check.stdout
    assert not led.exists()
