"""A quiet verdict belongs to the configuration that earned it.

``watch status`` replayed the last run's ``quiet`` under a watch file that had since dropped a
machine or swapped in a plan that looks at one item: the run it described never looked at what
the file now says. And a run whose file no longer lists a machine the previous run watched read
``quiet`` too, so narrowing a watch was indistinguishable from a quiet fleet. Synthetic data.
"""

from __future__ import annotations

import json
from datetime import timedelta

from assurance.watch.cli import main
from assurance.watch.runner import run_watch

from .test_assurance_watch import T0, config, ledger, work  # noqa: F401  (fixtures)


def _z(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _narrow(work, name):  # noqa: F811
    body = json.loads((work / "watch.json").read_text())
    body["targets"] = body["targets"][:1]
    (work / name).write_text(json.dumps(body))
    return work / name


def _status(work, file, now, capsys):  # noqa: F811
    code = main(["status", str(file), "--ledger", str(work / "register.db"), "--json",
                 "--now", _z(now)])
    return code, json.loads(capsys.readouterr().out)


def _quiet_history(config, ledger):  # noqa: F811
    run_watch(config, ledger, now=T0)
    assert run_watch(config, ledger, now=T0 + timedelta(hours=1)).verdict == "quiet"


def test_status_under_the_same_file_is_unchanged(work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    code, doc = _status(work, work / "watch.json", T0 + timedelta(hours=2), capsys)
    assert code == 0 and doc["verdict"] == "quiet" and not doc["freshness"]["config_changed"]


def test_status_under_a_narrower_watch_file_is_degraded(work, config, ledger, capsys):  # noqa: F811
    _quiet_history(config, ledger)
    code, doc = _status(work, _narrow(work, "narrow.json"), T0 + timedelta(hours=2), capsys)
    assert code == 2 and doc["verdict"] == "degraded" and doc["stored_verdict"] == "quiet"
    assert doc["freshness"]["config_changed"]
    assert any("different watch configuration" in r for r in doc["freshness"]["reasons"])


def test_a_run_that_stops_watching_a_machine_says_so_once(work, config, ledger):  # noqa: F811
    from assurance.watch.config import WatchConfig

    _quiet_history(config, ledger)
    narrow = WatchConfig.from_json(_narrow(work, "narrow.json"))
    run = run_watch(narrow, ledger, now=T0 + timedelta(hours=2))
    assert run.verdict == "degraded" and run.dropped_targets == ("0501",)
    assert any("0501" in c and "no longer watched" in c for c in run.checks_skipped)
    again = run_watch(narrow, ledger, now=T0 + timedelta(hours=3))
    assert again.verdict == "quiet" and again.dropped_targets == ()
