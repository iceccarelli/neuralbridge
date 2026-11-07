"""Quiet must be safe by default: the age of an advisory SOURCE is always checked.

A signed supplier feed file and a recorded intel store used to be judged on age only when the
subscription opted in with ``max_age_hours``; without it a sync or refresh job that had silently
stopped read as a quiet week, with a caveat. Now every subscription has a limit: its own
``max_age_hours`` (``limit_basis: explicit``) or ``DEFAULT_SOURCE_MAX_AGE_HOURS`` = 72 h
(``limit_basis: default``). There is no switch that turns the check off, and the limit and its
basis are recorded on the run's feed outcome.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta

import pytest

from assurance.supplier import publish
from assurance.watch.advisories import check_feeds, feed_file_age
from assurance.watch.cli import main
from assurance.watch.config import (
    DEFAULT_SOURCE_MAX_AGE_HOURS,
    FeedSubscription,
    IntelSubscription,
    WatchConfig,
    WatchError,
)
from assurance.watch.runner import run_watch

from . import test_assurance_watch_advisories as adv
from .test_assurance_watch_advisories import IDENTITY, _advisory


@pytest.fixture()
def plant(tmp_path):
    """The advisories plant with a signed feed that exists (one advisory that touches it)."""
    build = getattr(adv.plant, "_get_wrapped_function", lambda: adv.plant.__wrapped__)()
    made = build(tmp_path)
    publish(_advisory(), IDENTITY, made["key"], made["feed"])
    return made


def _age_feed(plant, hours: float) -> datetime:
    """Make the feed file look as if it was last written ``hours`` before the pinned clock."""
    when = NOW - timedelta(hours=hours)
    os.utime(plant["dir"] / "feed.jsonl", (when.timestamp(), when.timestamp()))
    return when


NOW = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)


def _set_feed_age(plant, value) -> None:
    path = plant["dir"] / "watch.json"
    body = json.loads(path.read_text())
    if value is None:
        body["feeds"][0].pop("max_age_hours", None)
    else:
        body["feeds"][0]["max_age_hours"] = value
    path.write_text(json.dumps(body))


def _run(plant, **kw):
    return run_watch(WatchConfig.from_json(plant["dir"] / "watch.json"), plant["ledger"],
                     now=NOW, **kw)


class TestFeedAgeDefault:
    def test_the_default_is_72_hours_and_is_not_a_switch(self):
        assert DEFAULT_SOURCE_MAX_AGE_HOURS == 72.0
        sub = FeedSubscription("controlco", "f.jsonl", "k.pub")
        assert sub.effective_max_age_hours == 72.0 and sub.limit_basis == "default"
        assert "max_age_hours" not in sub.to_dict()             # an old watch keeps its hash
        for off in (0, -1, float("inf"), True, 1e9):
            with pytest.raises(WatchError, match="max_age_hours"):
                FeedSubscription("controlco", "f.jsonl", "k.pub", max_age_hours=off)

    def test_an_explicit_limit_round_trips_and_changes_the_hash(self, plant):
        before = WatchConfig.from_json(plant["dir"] / "watch.json")
        _set_feed_age(plant, 200)
        after = WatchConfig.from_json(plant["dir"] / "watch.json")
        assert after.feeds[0].max_age_hours == 200.0 and after.feeds[0].limit_basis == "explicit"
        assert after.content_hash() != before.content_hash()
        assert WatchConfig.from_dict(after.to_dict()).feeds[0].max_age_hours == 200.0

    def test_a_feed_file_older_than_the_default_is_stale_never_quiet(self, plant):
        _age_feed(plant, 100)
        run = _run(plant, seal=False)
        (out,) = run.advisories.feeds
        assert out.status == "stale" and out.is_degraded
        assert run.verdict == "degraded" and run.verdict != "quiet"
        assert out.age["checked"] is True and out.age["limit_hours"] == 72.0
        assert out.age["limit_basis"] == "default" and out.age["state"] == "stale"
        assert "limit is 72 h" in " ".join(out.problems)

    def test_a_fresh_feed_file_is_judged_and_the_age_is_recorded(self, plant):
        _age_feed(plant, 10)
        out = _run(plant, seal=False).advisories.feeds[0]
        assert out.status == "verified"
        assert out.age["state"] == "fresh" and out.age["age_hours"] == 10.0
        assert out.to_dict()["age"]["limit_basis"] == "default"

    def test_the_edge_of_the_limit(self, plant):
        _age_feed(plant, 72)
        assert _run(plant, seal=False).advisories.feeds[0].status == "verified"
        _age_feed(plant, 72.01)
        assert _run(plant, seal=False).advisories.feeds[0].status == "stale"

    def test_an_explicit_longer_limit_is_honoured_and_recorded_as_explicit(self, plant):
        _set_feed_age(plant, 500)
        _age_feed(plant, 400)
        out = _run(plant, seal=False).advisories.feeds[0]
        assert out.status == "verified" and out.age["limit_basis"] == "explicit"
        assert out.age["limit_hours"] == 500.0

    def test_an_explicit_shorter_limit_degrades_inside_the_default(self, plant):
        _set_feed_age(plant, 6)
        _age_feed(plant, 10)
        assert _run(plant, seal=False).advisories.feeds[0].status == "stale"

    def test_a_feed_dated_after_the_clock_cannot_establish_an_age(self, plant):
        _age_feed(plant, -48)                 # modified two days AFTER the clock
        out = _run(plant, seal=False).advisories.feeds[0]
        assert out.status == "stale" and out.age["state"] == "future"

    def test_a_stale_feed_still_reports_what_it_holds_and_never_clears(self, plant):
        _age_feed(plant, 100)
        run = _run(plant, seal=False)
        assert run.verdict == "degraded"
        assert any(f.advisory_id == "CTRL-2026-11" for f in run.advisories.findings)

    def test_check_feeds_alone_applies_the_default_with_an_injected_clock(self, plant):
        from assurance.fleet.registry import Fleet

        _run(plant)
        _age_feed(plant, 100)
        config = WatchConfig.from_json(plant["dir"] / "watch.json")
        result = check_feeds(list(config.feeds), Fleet.from_ledger(plant["ledger"]), now=NOW)
        assert [f.status for f in result.feeds] == ["stale"]

    def test_feed_file_age_unreadable_mtime_is_a_problem(self, tmp_path):
        sub = FeedSubscription("controlco", str(tmp_path / "gone.jsonl"), "k.pub")
        record, problem = feed_file_age(sub, NOW)
        assert record["state"] == "unreadable" and "STALE" in problem

    def test_the_run_says_the_age_is_checked_and_what_it_cannot_see(self, plant):
        text = " ".join(_run(plant, seal=False).checks_skipped)
        assert "always checked" in text and "72 h" in text and "new modification" in text


class TestStatusRejudgesTheFeedAgainstTheClock:
    def _status(self, plant, now, *extra) -> int:
        return main(["status", str(plant["dir"] / "watch.json"),
                     "--ledger", str(plant["ledger"].path), "--now",
                     now.strftime("%Y-%m-%dT%H:%M:%SZ"), *extra])

    def test_a_feed_that_aged_since_the_last_run_degrades_status(self, plant, capsys):
        _age_feed(plant, 1)
        run = _run(plant)                      # sealed with a fresh feed at NOW
        assert run.verdict in ("quiet", "findings")
        later = NOW + timedelta(hours=100)
        # the feed file is untouched since, so at `later` it is 101 h old
        assert self._status(plant, later, "--json") == 2
        doc = json.loads(capsys.readouterr().out)
        assert doc["verdict"] == "degraded"
        feeds = doc["feed_staleness"]
        assert feeds["ok"] is False and feeds["feeds"][0]["limit_basis"] == "default"
        assert feeds["feeds"][0]["state"] == "stale"

    def test_a_fresh_feed_leaves_status_alone(self, plant, capsys):
        _age_feed(plant, 1)
        _run(plant)
        code = self._status(plant, NOW + timedelta(hours=2), "--json")
        doc = json.loads(capsys.readouterr().out)
        assert doc["feed_staleness"]["ok"] is True
        assert code == {"quiet": 0, "findings": 1}.get(doc["verdict"], 2)


class TestIntelDefault:
    def test_intel_without_a_limit_has_the_default_and_a_stable_hash(self):
        sub = IntelSubscription(store="i.db")
        assert sub.effective_max_age_hours == 72.0 and sub.limit_basis == "default"
        assert "max_age_hours" not in sub.to_dict()
        assert IntelSubscription(store="i.db", max_age_hours=24).limit_basis == "explicit"
