"""The one place a physical number is allowed into the machine package.

Every distance, speed, time, force and area that reaches a safety calculation
comes through :func:`number`. It refuses, rather than repairs:

* a boolean (``True`` is ``1.0`` to ``float()``, which is how a flag turns into a
  stopping distance),
* a string (``"750"`` is a number only until somebody types ``"750 mm"``; a
  file that quotes its numbers is a file whose units nobody checked),
* NaN and +/- infinity (every comparison with NaN is false, so a NaN
  separation compares as "not short" and passes; an infinite one passes
  trivially),
* a negative where a magnitude is required, and zero where a divisor is,
* a value past a plausibility rail.

The rails are *sanity rails*, not physics and not limits from any standard.
They exist so that ``1e308`` cannot overflow a sum into ``inf`` and so that a
metres-for-millimetres or milliseconds-for-seconds slip of several orders of
magnitude is more likely to be refused than to be believed. They are
deliberately far beyond any machine cell. A value past a rail is rejected, never
clamped: clamping would turn a wrong number into a plausible one.

The package works in one set of units, carried in the field names and never
converted implicitly: distance in millimetres, speed in millimetres per second,
time in seconds, force in newtons, area in square centimetres, pressure in
newtons per square centimetre. There is no conversion anywhere in this package:
a caller holding metres or milliseconds converts before the value arrives, and
a value that is wrong by a factor of 1000 is only caught here if it also falls
outside a rail.
"""

from __future__ import annotations

import math
import numbers
from typing import Any

from assurance.core.errors import AssuranceError

__all__ = [
    "AREA_MAX_CM2",
    "DISTANCE_MAX_MM",
    "DURATION_MAX_S",
    "FORCE_MAX_N",
    "PRESSURE_MAX_N_CM2",
    "QuantityError",
    "RATE_MAX_HZ",
    "SPEED_MAX_MM_S",
    "number",
]

#: Sanity rails. See the module docstring: these bound the plausible, not the safe.
DISTANCE_MAX_MM = 1.0e7        # 10 km
SPEED_MAX_MM_S = 1.0e6         # 1 km/s
DURATION_MAX_S = 1.0e7         # about 115 days
FORCE_MAX_N = 1.0e7
AREA_MAX_CM2 = 1.0e6           # 100 m^2
PRESSURE_MAX_N_CM2 = 1.0e7
RATE_MAX_HZ = 1.0e6


class QuantityError(AssuranceError, ValueError):
    """A physical quantity is not a usable number."""


def number(
    value: Any,
    name: str,
    *,
    maximum: float,
    exc: type[Exception] = QuantityError,
    minimum: float = 0.0,
    positive: bool = False,
    signed: bool = False,
) -> float:
    """Return ``value`` as a float, or raise ``exc`` saying exactly what is wrong.

    ``minimum`` defaults to 0 (magnitudes). ``signed=True`` allows ``-maximum``
    to ``maximum`` (positions and timestamps). ``positive=True`` also refuses
    zero, for divisors and rates.
    """
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        raise exc(
            f"{name} must be a number, got {type(value).__name__} {value!r}. Numbers "
            "are not accepted as strings or booleans: a quoted or flagged value is "
            "one whose unit nobody checked."
        )
    try:
        x = float(value)
    except (OverflowError, ValueError) as err:
        raise exc(f"{name} {value!r} cannot be represented as a finite number.") from err
    if not math.isfinite(x):
        raise exc(f"{name} is {x}; a physical quantity must be a finite number.")
    low = -maximum if signed else minimum
    if x < low:
        if low == 0.0:
            raise exc(f"{name} is negative ({x}).")
        raise exc(f"{name} is {x}, below the minimum {low}.")
    if positive and x <= 0:
        raise exc(f"{name} must be positive, got {x}.")
    if x > maximum:
        raise exc(
            f"{name} is {x}, beyond the plausibility rail of {maximum:g}. A value this "
            "large is more likely a unit slip or a corrupt field than a measurement, "
            "and it is refused rather than clamped."
        )
    return x
