"""``watch status`` judges the last run against the clock (issue #94).

It used to replay the stored verdict: a watch that stopped running read ``quiet`` for ever.
The clock is injectable (``--now`` on the CLI, ``now=`` on the function).
"""

from __future__ import annotations

import json
from datetime import timedelta

from assurance.watch.cli import main
from assurance.watch.freshness import CLOCK_SKEW_TOLERANCE, assess_status_freshness
from assurance.watch.runner import last_run, run_watch

from .test_assurance_watch import T0, config, ledger, work  # noqa: F401  (fixtures)


def _z(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _status(work, now, capsys):  # noqa: F811
    code = main(["status", str(work / "watch.json"), "--ledger", str(work / "register.db"),
                 "--json", "--now", _z(now)])
    return code, json.loads(capsys.readouterr().out)


def _quiet_history(config, ledger):  # noqa: F811
    run_watch(config, ledger, now=T0)
    run = run_watch(config, ledger, now=T0 + timedelta(hours=1))
    assert run.verdict == "quiet"


def test_a_fresh_quiet_run_stays_quiet(work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    code, doc = _status(work, T0 + timedelta(hours=2), capsys)
    assert code == 0 and doc["verdict"] == "quiet"
    assert doc["freshness"]["state"] == "fresh" and doc["freshness"]["degraded"] is False


def test_a_run_older_than_max_age_hours_is_degraded_with_its_age(
        work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)                      # max_age_hours is 168
    code, doc = _status(work, T0 + timedelta(hours=1 + 169), capsys)
    assert code == 2 and doc["verdict"] == "degraded" and doc["stored_verdict"] == "quiet"
    assert doc["freshness"]["state"] == "stale" and doc["freshness"]["age_hours"] == 169.0
    assert any("169.00 h old" in r for r in doc["freshness"]["reasons"])


def test_the_boundary_is_exact(work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    last = T0 + timedelta(hours=1)
    assert _status(work, last + timedelta(hours=168), capsys)[0] == 0
    assert _status(work, last + timedelta(hours=168, seconds=1), capsys)[0] == 2


def test_a_last_run_in_the_future_is_not_fresh_and_the_skew_is_reported(
        work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    code, doc = _status(work, T0 - timedelta(days=2), capsys)
    assert code == 2 and doc["verdict"] == "degraded"
    assert doc["freshness"]["state"] == "future"
    assert any("from the future" in r for r in doc["freshness"]["reasons"])


def test_small_clock_drift_is_tolerated(work, config, ledger):  # noqa: F811
    _quiet_history(config, ledger)
    body = last_run(ledger, config.watch_id)
    now = T0 + timedelta(hours=1) - CLOCK_SKEW_TOLERANCE + timedelta(seconds=1)
    assert assess_status_freshness(body, config, ledger, now=now).state == "fresh"


def test_a_machine_not_looked_at_within_the_window_is_stale_even_if_the_run_is_fresh(
        work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    # A run record made fresh by a later run that saw only one machine: the other is stale.
    body = last_run(ledger, config.watch_id)
    now = T0 + timedelta(hours=1) + timedelta(hours=100)
    fresh = assess_status_freshness(body, config, ledger, now=now)
    assert fresh.state == "fresh" and fresh.stale_machines == ()
    small = type(config)(**{**config.__dict__, "max_age_hours": 50.0})
    again = assess_status_freshness(body, small, ledger, now=now)
    assert again.state == "stale" and again.degraded
    assert set(again.stale_machines) == {"0412", "0501"}


def test_a_stored_findings_verdict_is_never_improved_by_the_clock(
        work, config, ledger, capsys):  # noqa: F811
    run_watch(config, ledger, now=T0)                   # first look: findings
    code, doc = _status(work, T0 + timedelta(hours=1), capsys)
    assert code == 1 and doc["verdict"] == "findings"
    code, doc = _status(work, T0 + timedelta(days=30), capsys)
    assert code == 2 and doc["verdict"] == "degraded" and doc["stored_verdict"] == "findings"


def test_the_text_output_states_the_age(work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    code = main(["status", str(work / "watch.json"), "--ledger", str(work / "register.db"),
                 "--now", _z(T0 + timedelta(days=30))])
    out = capsys.readouterr().out
    assert code == 2 and "DEGRADED" in out and "h old" in out and "QUIET" in out
