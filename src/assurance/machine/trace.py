"""Machine execution traces, and what a trace is allowed to prove.

A trace is what the machine actually did: a time series of pose, speed,
operating mode, measured separation from a detected person, and — where the
cell claims power and force limiting — contact force.

The reason this module exists rather than a CSV reader is provenance. A trace
recorded in a simulator and a trace recorded from the cell on the shop floor
are the same shape and are worth entirely different things. Conflating them is
how a validation report comes to assert physical behaviour on the strength of
a model. :class:`Provenance` carries the distinction into the type system, and
:attr:`Provenance.tier_ceiling` names the most an *independently attested*
provenance could support.

The provenance is, however, a field the filer writes. A declared provenance is
therefore recorded but does not lift the tier by itself; only a signed recorder
attestation accepted under the verifier's own trust list does
(:mod:`assurance.machine.provenance_trust`,
:mod:`assurance.machine.recorder_attestation`).
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import statistics
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import content_hash_of, format_utc, parse_utc
from assurance.core.tiers import AssuranceTier
from assurance.machine.quantities import (
    AREA_MAX_CM2,
    DISTANCE_MAX_MM,
    DURATION_MAX_S,
    FORCE_MAX_N,
    RATE_MAX_HZ,
    SPEED_MAX_MM_S,
    number,
)

__all__ = [
    "MAX_FILE_BYTES",
    "MAX_SAMPLES",
    "OperatingMode",
    "Provenance",
    "Sample",
    "Trace",
    "TraceError",
]

#: The most samples one trace may carry, and the largest file read for one.
#: Past these a hostile or runaway export would exhaust memory before any check
#: ran; the trace is refused instead. (The hosted API applies a much lower cap.)
MAX_SAMPLES = 2_000_000
MAX_FILE_BYTES = 512 * 1024 * 1024


class TraceError(AssuranceError):
    """A trace is malformed, or is being asked to support a claim it cannot."""


def _num(value: Any, name: str, **kw: Any) -> float:
    return number(value, name, exc=TraceError, **kw)


#: Samples are read by these keys only. Anything else is ignored unless it looks
#: like one of these in other units (see :func:`_refuse_unit_variants`).
_SAMPLE_KEYS = ("t", "tcp", "x", "y", "z", "tcp_speed", "mode", "separation",
                "human_speed", "contact_force", "contact_area", "body_region")
_UNIT_SUFFIX = re.compile(
    r"(?:^|_)(?:mm|cm|km|m|ms|us|min|mps|kmh|mph|in|ft|lbf|kn|n|deg|rad)"
    r"(?:_s|_s2|_per_s)?$"
)


def _refuse_unit_variants(keys: Iterable[str]) -> None:
    """Refuse a column that is probably a known field in another unit.

    A controller log with ``separation_m`` and no ``separation`` used to load
    with every separation ``None`` — "nobody was detected" — which is the one
    reading that cannot be checked and so cannot fail. Unrecognised columns are
    otherwise ignored (logs carry plenty), but one that begins with a field name
    or ends in a unit token is refused: it is a number we are not reading.
    """
    for key in keys:
        if key in _SAMPLE_KEYS:
            continue
        low = str(key).lower()
        if any(low.startswith(f + "_") for f in _SAMPLE_KEYS) or _UNIT_SUFFIX.search(low):
            raise TraceError(
                f"column {key!r} looks like a recorded quantity in units this package "
                f"does not read (it takes {', '.join(_SAMPLE_KEYS)}, in millimetres, "
                "mm/s, seconds, newtons and cm²). Convert it and name it as the field, "
                "or remove it: a column that is silently ignored reads as 'not recorded'."
            )


_EXACT_PREFIX = b"assurance.machine.trace-exact.v1\n"


def _opt_hex(value: float | None) -> str | None:
    return None if value is None else float(value).hex()


def _exact_sample(s: Sample) -> list[Any]:
    """One sample, every numeric field as its exact binary value, in a fixed order."""
    return [float(s.t).hex(), [float(c).hex() for c in s.tcp], float(s.tcp_speed).hex(),
            s.mode.value, _opt_hex(s.separation), _opt_hex(s.human_speed),
            _opt_hex(s.contact_force), _opt_hex(s.contact_area), s.body_region]


def _exact_value(value: Any) -> Any:
    """A type-tagged, order-independent form of a free-form value (the conditions)."""
    if value is None:
        return ["n"]
    if isinstance(value, bool):
        return ["b", value]
    if isinstance(value, str):
        return ["s", value]
    if isinstance(value, int):
        # An integer is the float it is equal to, so 99 and 99.0 (the same condition
        # through a JSON round trip) agree; one beyond float precision keeps its digits.
        return ["f", float(value).hex()] if abs(value) <= 2 ** 53 else ["i", str(value)]
    if isinstance(value, float):
        return ["f", value.hex()]
    if isinstance(value, (list, tuple)):
        return ["l", [_exact_value(v) for v in value]]
    if isinstance(value, dict):
        pairs = [[str(k), _exact_value(v)] for k, v in value.items()]
        return ["d", sorted(pairs, key=lambda kv: (kv[0], json.dumps(kv[1])))]
    return ["r", type(value).__name__, repr(value)]


class Provenance(StrEnum):
    """Where the samples came from. This is the ceiling on every claim made from them."""

    #: Generated by a simulator or a digital twin. Tells you about the model.
    SIMULATION = "simulation"
    #: Recorded from the real machine off-line: a bench, a commissioning run,
    #: a witnessed test. Real hardware, controlled conditions.
    BENCH = "bench"
    #: Recorded from the machine in production, doing the work it is sold to do.
    FIELD = "field"

    @property
    def tier_ceiling(self) -> AssuranceTier:
        """The highest tier this provenance could reach **if it were independently
        attested**. The verification engine does not use it on a declared provenance:
        see :func:`assurance.machine.provenance_trust.assess_provenance`.

        Simulation can never reach VALIDATED: no simulator has ever measured a
        protective stop. CERTIFIED is never reachable from a trace at all — it
        requires an accredited third party, not a file.
        """
        if self is Provenance.SIMULATION:
            return AssuranceTier.COMMUNITY
        return AssuranceTier.VALIDATED

    @property
    def may_claim_physical_behaviour(self) -> bool:
        return self.tier_ceiling.may_claim_physical_behaviour


class OperatingMode(StrEnum):
    """The collaborative operation in force at a sample, per ISO 10218-2 / ISO/TS 15066.

    The mode decides which checks apply. Speed and separation monitoring is
    meaningless while the machine is stopped, and a power-and-force limit is
    meaningless while nothing is in contact.
    """

    #: Full speed, safeguarded space assumed clear by a fixed guard or interlock.
    AUTOMATIC = "automatic"
    #: Reduced-speed control, typically for teaching or setup.
    REDUCED_SPEED = "reduced_speed"
    #: Operator commands motion directly through a hand-guiding device.
    HAND_GUIDING = "hand_guiding"
    #: Speed and separation monitoring: the cell keeps a computed distance.
    SSM = "ssm"
    #: Power and force limiting: contact is permitted within energy limits.
    PFL = "pfl"
    #: Safety-rated stop, or standstill.
    STOPPED = "stopped"

    @property
    def separation_is_the_control(self) -> bool:
        """Whether a computed distance is what makes this mode safe.

        Only speed and separation monitoring. In automatic mode the protective
        measure is the fixed guard or interlock, not a distance, so applying the
        separation formula there would report a violation on every sample of a
        perfectly safe fenced cell. A person detected during automatic operation
        is a finding, but it is the ``mode_consistency`` finding, not a
        separation shortfall.
        """
        return self is OperatingMode.SSM

    @property
    def contact_is_permitted(self) -> bool:
        return self in (OperatingMode.PFL, OperatingMode.HAND_GUIDING)


def _csv_cell(value: Any, name: str) -> float:
    """A CSV cell is text. It must be a plain decimal number, nothing else."""
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise TraceError(f"{name} {value!r} is not a number.")
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError as exc:
            raise TraceError(
                f"{name} {value!r} is not a number. A cell with a unit in it "
                "('750 mm') is refused rather than guessed at."
            ) from exc
    return float(value)


@dataclass(frozen=True)
class Sample:
    """One instant of machine state.

    Distances are millimetres, speeds millimetres per second, forces newtons,
    areas square centimetres, time seconds from the trace epoch. Units are not
    negotiable and are not carried per field: a trace that arrives in metres is
    a conversion the caller performs before it reaches this class, because a
    silent unit error in a separation distance is a person in hospital.
    """

    t: float
    tcp: tuple[float, float, float]
    tcp_speed: float
    mode: OperatingMode
    #: Minimum measured distance to the nearest detected person, mm.
    #: ``None`` means the sensing system detected nobody — which is a claim in
    #: itself, and is only as good as the sensing system's coverage.
    separation: float | None = None
    #: Closing speed of the detected person, mm/s, when the sensing system
    #: reports it. ``None`` falls back to the envelope's declared figure.
    human_speed: float | None = None
    #: Measured contact force, N. Only meaningful in a contact-permitting mode.
    contact_force: float | None = None
    #: Contact area, cm². Needed to turn a force into a pressure.
    contact_area: float | None = None
    #: Which body region the contact is credited to, keyed to the limits table.
    body_region: str = ""

    def __post_init__(self) -> None:
        _num(self.t, "t", maximum=DURATION_MAX_S, signed=True)
        where = f"t={self.t}"
        if not isinstance(self.tcp, (tuple, list)) or len(self.tcp) != 3:
            raise TraceError(f"{where}: tcp needs three coordinates, got {self.tcp!r}.")
        for axis, v in zip("xyz", self.tcp, strict=True):
            _num(v, f"{where}: tcp {axis}", maximum=DISTANCE_MAX_MM, signed=True)
        _num(self.tcp_speed, f"{where}: tcp_speed", maximum=SPEED_MAX_MM_S)
        if self.separation is not None:
            _num(self.separation, f"{where}: separation", maximum=DISTANCE_MAX_MM)
        if self.human_speed is not None:
            _num(self.human_speed, f"{where}: human_speed", maximum=SPEED_MAX_MM_S)
        if self.contact_force is not None:
            _num(self.contact_force, f"{where}: contact_force", maximum=FORCE_MAX_N)
        if self.contact_area is not None:
            _num(self.contact_area, f"{where}: contact_area", maximum=AREA_MAX_CM2,
                 positive=True)
        if not isinstance(self.mode, OperatingMode):
            raise TraceError(f"{where}: mode {self.mode!r} is not an OperatingMode.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "t": self.t,
            "tcp": list(self.tcp),
            "tcp_speed": self.tcp_speed,
            "mode": self.mode.value,
            "separation": self.separation,
            "human_speed": self.human_speed,
            "contact_force": self.contact_force,
            "contact_area": self.contact_area,
            "body_region": self.body_region,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any], *, csv_row: bool = False) -> Sample:
        """Read one sample.

        ``csv_row`` means every value is text, as a CSV cell is, and is parsed to
        a number here; a JSON sample must already carry numbers, and a string or a
        boolean in one is refused.
        """
        if not isinstance(d, dict):
            raise TraceError(f"a sample must be an object, got {type(d).__name__}.")
        _refuse_unit_variants(k for k in d if isinstance(k, str))

        def need(key: str, *, numeric: bool = True) -> Any:
            if key not in d or d[key] is None or d[key] == "":
                raise TraceError(f"sample is missing required field {key!r}.")
            return _csv_cell(d[key], key) if (csv_row and numeric) else d[key]

        def opt(key: str) -> Any:
            v = d.get(key)
            if v is None or v == "":
                return None
            return _csv_cell(v, key) if csv_row else v

        tcp = d.get("tcp")
        if tcp is None:
            # A position that was not recorded is not the origin.
            tcp = [need("x"), need("y"), need("z")]
        elif csv_row or not isinstance(tcp, (list, tuple)) or len(tcp) != 3:
            raise TraceError(f"tcp needs three coordinates, got {tcp!r}.")
        try:
            mode = OperatingMode(str(need("mode", numeric=False)))
        except ValueError as exc:
            raise TraceError(
                f"mode {d.get('mode')!r} is not one of "
                f"{', '.join(m.value for m in OperatingMode)}."
            ) from exc
        return cls(
            t=need("t"),
            tcp=(tcp[0], tcp[1], tcp[2]),
            tcp_speed=need("tcp_speed"),
            mode=mode,
            separation=opt("separation"),
            human_speed=opt("human_speed"),
            contact_force=opt("contact_force"),
            contact_area=opt("contact_area"),
            body_region=str(d.get("body_region", "") or ""),
        )


@dataclass(frozen=True)
class Trace:
    """A run, with the facts needed to decide what it may be used to claim."""

    trace_id: str
    provenance: Provenance
    #: The producing system: controller make and firmware, simulator and version.
    source_system: str
    #: UTC instant of ``t = 0``.
    started_at: datetime
    sample_rate_hz: float
    samples: tuple[Sample, ...]
    #: Free-form conditions: payload, tool, temperature, operator, work order.
    conditions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.samples:
            raise TraceError(f"trace {self.trace_id!r} has no samples.")
        if len(self.samples) > MAX_SAMPLES:
            raise TraceError(
                f"trace {self.trace_id!r} has {len(self.samples)} samples, more than "
                f"the {MAX_SAMPLES} this package will hold. Split the run."
            )
        if self.started_at.tzinfo is None:
            raise TraceError(f"trace {self.trace_id!r} started_at has no timezone.")
        _num(self.sample_rate_hz, f"trace {self.trace_id!r} sample_rate_hz",
             maximum=RATE_MAX_HZ, positive=True)
        times = [s.t for s in self.samples]
        if any(b <= a for a, b in zip(times, times[1:], strict=False)):
            raise TraceError(
                f"trace {self.trace_id!r} samples are not strictly increasing in t. "
                "An out-of-order trace cannot support a claim about a stop time."
            )

    @property
    def duration_s(self) -> float:
        return self.samples[-1].t - self.samples[0].t

    @property
    def observed_period_s(self) -> float | None:
        """The median interval between samples, or ``None`` for a single sample."""
        deltas = [b.t - a.t for a, b in zip(self.samples, self.samples[1:], strict=False)]
        return statistics.median(deltas) if deltas else None

    @property
    def rate_disagrees_with_data(self) -> bool:
        """Whether the declared rate is more than a factor of two from the data's own.

        The declared rate decides what counts as a gap, so a wrong declaration
        moves the goalposts: 1 Hz declared over 1 kHz data hides every dropout
        shorter than two seconds, and 5 kHz declared over 50 Hz data makes every
        interval look like one. Neither is believed silently.
        """
        observed = self.observed_period_s
        if observed is None:
            return False
        nominal = 1.0 / self.sample_rate_hz
        return observed > 2 * nominal or observed < nominal / 2

    def _gap_period(self) -> float:
        """The *shorter* of the declared period and the one the data shows.

        A declared rate that is too low cannot hide a dropout, and one that is
        too high marks every interval as a gap, loudly.
        """
        nominal = 1.0 / self.sample_rate_hz
        observed = self.observed_period_s
        return nominal if observed is None else min(nominal, observed)

    @property
    def gaps(self) -> list[tuple[float, float]]:
        """Intervals longer than twice the sample period.

        A gap is where the evidence is silent. A protective stop that happened
        inside a gap was not recorded, whatever the surrounding samples imply.
        """
        period = self._gap_period()
        return [(a.t, b.t) for a, b in zip(self.samples, self.samples[1:], strict=False)
                if (b.t - a.t) > 2 * period]

    def gap_touches(self, predicate: Any) -> bool:
        """Whether any gap has a recorded sample on either side satisfying ``predicate``."""
        period = self._gap_period()
        return any(
            (b.t - a.t) > 2 * period and (predicate(a) or predicate(b))
            for a, b in zip(self.samples, self.samples[1:], strict=False)
        )

    def modes_present(self) -> list[OperatingMode]:
        seen: list[OperatingMode] = []
        for s in self.samples:
            if s.mode not in seen:
                seen.append(s.mode)
        return seen

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "provenance": self.provenance.value,
            "source_system": self.source_system,
            "started_at": format_utc(self.started_at),
            "sample_rate_hz": self.sample_rate_hz,
            "conditions": self.conditions,
            "samples": [s.to_dict() for s in self.samples],
        }

    def content_hash(self) -> str:
        """Identity of the run. Two traces with the same hash are the same run.

        "The same run" at the precision of :func:`content_hash_of`: every number is
        rounded to six decimals before hashing, so two traces that differ by less than
        that share a hash (and can differ in a verdict). Anything that must bind the
        *exact* bytes, as a recorder attestation does, uses :meth:`exact_digest` too.
        """
        return content_hash_of(self.hashable_payload())

    def exact_digest(self) -> str:
        """SHA-256 over every value of this trace at full precision.

        Each float is written as ``float.hex()``, which is its exact binary value (so a
        difference of one unit in the last place is a different digest and ``-0.0`` is
        not ``0.0``), and every other field that can affect a verdict is included: the
        trace id, provenance, source system, the start time (to the second, as
        everywhere else: the content hash, the attestation window and staleness read
        no finer, and a trace file re-serialised through :meth:`hashable_payload` must
        keep its digest), the sample rate, the conditions (type-tagged, so ``1`` / ``"1"`` / ``[1]`` cannot
        collide) and each sample field in a fixed order. It is deliberately *not*
        :meth:`content_hash`, whose six-decimal rounding is a property other records
        rely on and is left as it is.
        """
        head = json.dumps({
            "trace_id": self.trace_id,
            "provenance": self.provenance.value,
            "source_system": self.source_system,
            "started_at": format_utc(self.started_at),
            "sample_rate_hz": float(self.sample_rate_hz).hex(),
            "conditions": _exact_value(self.conditions),
            "sample_count": len(self.samples),
        }, sort_keys=True, separators=(",", ":"))
        h = hashlib.sha256(_EXACT_PREFIX)
        h.update(head.encode("utf-8") + b"\n")
        for s in self.samples:
            h.update(json.dumps(_exact_sample(s), separators=(",", ":")).encode("utf-8") + b"\n")
        return h.hexdigest()

    def __len__(self) -> int:
        return len(self.samples)

    def __iter__(self) -> Iterator[Sample]:
        return iter(self.samples)

    # -- loading ----------------------------------------------------------
    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Trace:
        if not isinstance(d, dict):
            raise TraceError(f"a trace must be an object, got {type(d).__name__}.")

        def need(key: str) -> Any:
            if key not in d:
                raise TraceError(f"trace is missing required field {key!r}.")
            return d[key]

        raw_samples = need("samples")
        if not isinstance(raw_samples, list):
            raise TraceError("trace samples must be a list.")
        if len(raw_samples) > MAX_SAMPLES:
            raise TraceError(
                f"trace has {len(raw_samples)} samples, more than the {MAX_SAMPLES} "
                "this package will hold. Split the run."
            )
        try:
            provenance = Provenance(str(need("provenance")))
        except ValueError as exc:
            raise TraceError(
                f"provenance {d['provenance']!r} is not one of "
                f"{', '.join(p.value for p in Provenance)}."
            ) from exc
        try:
            started_at = parse_utc(str(need("started_at")))
        except ValueError as exc:
            raise TraceError(f"started_at {d['started_at']!r}: {exc}") from exc
        return cls(
            trace_id=str(need("trace_id")),
            provenance=provenance,
            source_system=str(need("source_system")),
            started_at=started_at,
            sample_rate_hz=_num(need("sample_rate_hz"), "sample_rate_hz",
                                maximum=RATE_MAX_HZ, positive=True),
            samples=tuple(Sample.from_dict(s) for s in raw_samples),
            conditions=dict(d.get("conditions") or {}),
        )

    @classmethod
    def from_json(cls, path: str | Path) -> Trace:
        p = Path(path)
        if p.stat().st_size > MAX_FILE_BYTES:
            raise TraceError(
                f"{p.name} is {p.stat().st_size} bytes, more than the {MAX_FILE_BYTES} "
                "this package will read."
            )
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise TraceError(f"{p.name} is not valid JSON: {exc}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_csv(
        cls,
        path: str | Path,
        *,
        trace_id: str,
        provenance: Provenance,
        source_system: str,
        started_at: datetime,
        sample_rate_hz: float,
        conditions: dict[str, Any] | None = None,
    ) -> Trace:
        """Read samples from a controller log.

        The metadata a controller does not record — what produced the file, when
        it started, whether it is a simulation — must be supplied by the caller.
        There is no default for ``provenance`` on purpose: the one field that
        decides what the run may prove is the one field nobody may omit.
        """
        p = Path(path)
        if p.stat().st_size > MAX_FILE_BYTES:
            raise TraceError(
                f"{p.name} is {p.stat().st_size} bytes, more than the {MAX_FILE_BYTES} "
                "this package will read."
            )
        samples: list[Sample] = []
        try:
            with p.open(newline="", encoding="utf-8") as fh:
                for row in csv.DictReader(fh):
                    if len(samples) >= MAX_SAMPLES:
                        raise TraceError(
                            f"{p.name} has more than {MAX_SAMPLES} rows, more than "
                            "this package will hold. Split the run."
                        )
                    if None in row:
                        raise TraceError(
                            f"{p.name} row {len(samples) + 2} has more cells than the "
                            "header has columns; a shifted row would read one field "
                            "as another."
                        )
                    samples.append(Sample.from_dict(row, csv_row=True))
        except (UnicodeDecodeError, csv.Error) as exc:
            raise TraceError(f"{p.name} is not readable as UTF-8 CSV: {exc}") from exc
        if not samples:
            raise TraceError(f"{path} has no rows.")
        return cls(
            trace_id=trace_id,
            provenance=provenance,
            source_system=source_system,
            started_at=started_at,
            sample_rate_hz=sample_rate_hz,
            samples=tuple(samples),
            conditions=dict(conditions or {}),
        )

    @classmethod
    def of(cls, samples: Iterable[Sample], **kw: Any) -> Trace:
        seq: Sequence[Sample] = tuple(samples)
        return cls(samples=tuple(seq), **kw)
