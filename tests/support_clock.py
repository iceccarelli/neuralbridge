"""A ticking test clock for tests that build "an hour later" data from the wall clock.

Such tests behave differently around midnight UTC: a recording an hour in the future cannot be
attested (an attestation may not be dated in the future, nor before the recording began), so the
case closes only when the test happens to run early in the day. :func:`install` pins the world
the test sees:

* ``assurance.core.identity.utc_now`` and every module that imported it by name,
* ``datetime.now`` in the two modules that read the wall clock directly
  (``assurance.machine.recorder_attestation`` and ``tests.support_recorder``),

to one instant that advances one second per call (so ledger order stays meaningful).
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from assurance.core import identity

_WALL_READERS = ("assurance.machine.recorder_attestation", "tests.support_recorder")


class _Meta(type):
    def __instancecheck__(cls, obj: object) -> bool:
        return isinstance(obj, datetime)

    def __getattr__(cls, name: str) -> Any:
        return getattr(datetime, name)


def today_at_noon() -> datetime:
    """Noon UTC of the real date: a start that cannot cross a day boundary within a test."""
    return datetime.now(UTC).replace(hour=12, minute=0, second=0, microsecond=0)


def install(monkeypatch: Any, start: datetime) -> None:
    """Pin ``utc_now`` and the direct wall-clock readers to ``start`` (UTC), ticking 1s a call."""
    state = {"now": start.astimezone(UTC)}

    def tick() -> datetime:
        state["now"] = state["now"] + timedelta(seconds=1)
        return state["now"]

    class FakeDateTime(metaclass=_Meta):
        def __new__(cls, *args: Any, **kwargs: Any) -> datetime:           # type: ignore[misc]
            return datetime(*args, **kwargs)

        @staticmethod
        def now(tz: Any = None) -> datetime:
            return tick().astimezone(tz) if tz is not None else tick().replace(tzinfo=None)

    original = identity.utc_now
    for module in list(sys.modules.values()):
        if module is not None and getattr(module, "utc_now", None) is original:
            monkeypatch.setattr(module, "utc_now", tick, raising=False)
    monkeypatch.setattr(identity, "utc_now", tick)
    for name in _WALL_READERS:
        module = sys.modules.get(name)
        current = getattr(module, "datetime", None)
        if module is not None and (current is datetime or type(current) is _Meta):
            monkeypatch.setattr(module, "datetime", FakeDateTime)
