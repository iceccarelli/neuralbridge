"""A watch run that died after sealing work but before its run record is not a quiet one.

The run record is the last thing a run writes. A process killed after it sealed a divergence,
a manifest and a case (the new manifest is then the baseline) used to leave ``watch status``
reading the PREVIOUS run's ``quiet``, and the next run compared against the new baseline and
read ``quiet`` too: the drift was reported nowhere. Synthetic data, an isolated temp ledger.
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest

from assurance.watch import runner
from assurance.watch.cli import main
from assurance.watch.runner import run_watch

from .test_assurance_watch import T0, config, ledger, reexport, work  # noqa: F401  (fixtures)


class Killed(BaseException):
    """What SIGKILL looks like to the code under test: nothing after this line runs."""


def _z(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _die_before_run_record(led, fn):
    real = led.append

    def append(evidence, **kw):
        if evidence.kind == runner.RUN_KIND:
            raise Killed
        return real(evidence, **kw)

    led.append = append
    try:
        with pytest.raises(Killed):
            fn()
    finally:
        led.append = real


def _status(work, now, capsys):  # noqa: F811
    code = main(["status", str(work / "watch.json"), "--ledger", str(work / "register.db"),
                 "--json", "--now", _z(now)])
    return code, json.loads(capsys.readouterr().out)


def _crashed_history(work, config, ledger):  # noqa: F811
    run_watch(config, ledger, now=T0)
    assert run_watch(config, ledger, now=T0 + timedelta(hours=1)).verdict == "quiet"
    reexport(work, "0412", radius=1200)
    _die_before_run_record(
        ledger, lambda: run_watch(config, ledger, now=T0 + timedelta(hours=2)))


def test_status_after_a_killed_run_is_not_the_previous_quiet(work, config, ledger, capsys):  # noqa: F811
    _crashed_history(work, config, ledger)
    code, doc = _status(work, T0 + timedelta(hours=3), capsys)
    assert code == 2 and doc["verdict"] == "degraded" and doc["stored_verdict"] == "quiet"
    assert doc["freshness"]["interrupted"]
    assert any("did not finish" in r for r in doc["freshness"]["reasons"])


def test_the_next_run_reports_what_the_dead_run_sealed(work, config, ledger):  # noqa: F811
    _crashed_history(work, config, ledger)
    run = run_watch(config, ledger, now=T0 + timedelta(hours=4))
    assert run.verdict == "degraded"
    assert run.interrupted_prior_run                # names what was sealed and never reported
    assert any("divergence" in s for s in run.interrupted_prior_run)
    again = run_watch(config, ledger, now=T0 + timedelta(hours=5))
    assert again.verdict == "quiet" and not again.interrupted_prior_run   # said once, then settled


def test_a_run_that_finished_leaves_no_interruption_behind(work, config, ledger, capsys):  # noqa: F811
    run_watch(config, ledger, now=T0)
    reexport(work, "0412", radius=1200)
    assert run_watch(config, ledger, now=T0 + timedelta(hours=1)).verdict == "findings"
    code, doc = _status(work, T0 + timedelta(hours=2), capsys)
    assert not doc["freshness"]["interrupted"] and code == 1
    assert run_watch(config, ledger, now=T0 + timedelta(hours=3)).interrupted_prior_run == ()


def test_a_dry_run_seals_nothing_so_it_interrupts_nothing(work, config, ledger):  # noqa: F811
    run_watch(config, ledger, now=T0)
    run_watch(config, ledger, now=T0 + timedelta(hours=1))
    reexport(work, "0412", radius=1200)
    run_watch(config, ledger, now=T0 + timedelta(hours=2), seal=False)
    assert run_watch(config, ledger, now=T0 + timedelta(hours=3)).interrupted_prior_run == ()


# ---------------------------------------------------------------------------------------
# two runs at once would each see the same drift and each seal it
# ---------------------------------------------------------------------------------------
def test_a_second_run_while_one_is_in_progress_is_refused_and_writes_nothing(
        work, config, ledger):  # noqa: F811
    from assurance.watch.config import WatchError

    run_watch(config, ledger, now=T0)
    reexport(work, "0412", radius=1200)
    before = len(ledger.entries())
    with runner.hold_run_lock(ledger, config):          # the first run, mid-flight
        with pytest.raises(WatchError, match="already in progress"):
            run_watch(config, ledger, now=T0 + timedelta(hours=1))
        # a dry run seals nothing, so it may look while another run is working
        assert run_watch(config, ledger, now=T0 + timedelta(hours=1), seal=False).changed
    assert len(ledger.entries()) == before


def test_the_lock_is_released_when_a_run_ends_or_dies(work, config, ledger):  # noqa: F811
    run_watch(config, ledger, now=T0)
    reexport(work, "0412", radius=1200)
    _die_before_run_record(
        ledger, lambda: run_watch(config, ledger, now=T0 + timedelta(hours=1)))
    run = run_watch(config, ledger, now=T0 + timedelta(hours=2))      # not wedged by the dead one
    assert run.interrupted_prior_run


# ---------------------------------------------------------------------------------------
# --dry-run: "nothing was sealed" must also mean nothing was written
# ---------------------------------------------------------------------------------------
def _fingerprint(root):
    import hashlib
    out = {".": root.stat().st_mtime_ns}
    for p in sorted(root.rglob("*")):
        if p.name.endswith("-shm"):          # SQLite's own read-mark index, touched by any reader
            continue
        st = p.stat()
        out[p.relative_to(root).as_posix()] = (
            st.st_size, st.st_mtime_ns,
            hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else "")
    return out


def test_a_dry_run_leaves_a_live_wal_ledger_byte_and_mtime_identical(work, config, ledger):  # noqa: F811
    import sqlite3
    run_watch(config, ledger, now=T0)
    reexport(work, "0412", radius=1200)
    service = sqlite3.connect(work / "register.db", isolation_level=None)
    service.execute("PRAGMA journal_mode=WAL")
    service.execute("PRAGMA wal_autocheckpoint=0")
    service.execute("SELECT count(*) FROM chain").fetchone()
    try:
        before = _fingerprint(work)
        import os
        import subprocess
        import sys
        from pathlib import Path
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1",
               "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
        done = subprocess.run(                                      # noqa: S603
            [sys.executable, "-m", "assurance", "watch", "run", str(work / "watch.json"),
             "--ledger", str(work / "register.db"), "--dry-run", "--json"],
            cwd=work, env=env, capture_output=True, text=True, timeout=120, check=False)
        assert done.returncode in (1, 2), done.stderr     # it looked, and found the change
        assert _fingerprint(work) == before
    finally:
        service.close()


def test_a_dry_run_against_a_path_that_holds_no_ledger_creates_nothing(work, capsys):  # noqa: F811
    typo = work / "regsiter.db"
    code = main(["run", str(work / "watch.json"), "--ledger", str(typo), "--dry-run", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert not typo.exists() and code == 1 and doc["verdict"] == "findings"
