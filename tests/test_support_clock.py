"""The test clock (tests/support_clock.py) pins every reader of the time the change tests use."""

from __future__ import annotations

from datetime import UTC, datetime

from assurance.core import identity

from .support_clock import install


def test_the_clock_is_pinned_and_ticks(monkeypatch):
    install(monkeypatch, datetime(2026, 10, 26, 23, 30, tzinfo=UTC))
    a, b = identity.utc_now(), identity.utc_now()
    assert (a.hour, a.minute) == (23, 30) and b > a


def test_the_direct_wall_clock_readers_follow_it(monkeypatch):
    from assurance.machine import recorder_attestation as ra

    from . import support_recorder as sr

    install(monkeypatch, datetime(2026, 10, 27, 0, 10, tzinfo=UTC))
    for module in (ra, sr):
        now = module.datetime.now(UTC)
        assert now.date().isoformat() == "2026-10-27" and now.minute == 10
        assert isinstance(datetime(2026, 1, 1, tzinfo=UTC), module.datetime)   # isinstance still works
        assert module.datetime(2026, 1, 1).year == 2026
