"""Which of this machine's safety functions are still covered by valid evidence?

This is the join that neither half can make alone, and the reason both halves
exist in one package.

:mod:`assurance.machine` produces a verification: *on this run, the cell met its
declared separation, speed and workspace limits.* :mod:`assurance.machinery`
produces an intervention record: *on 14 March a technician replaced the safety
controller firmware.* Separately, each is a file. Together they produce a
sentence neither record can produce alone:

    SF-02 protective stop — STALE. Last verified 9 February by bundle a41c…;
    invalidated by INT-0007 on 14 March, which changed safety-controller
    firmware and re-ran nothing. The cell has run for seven months on a
    validation that stopped describing it.

The inference is mechanical, not clever. An intervention names the item it
touched; the manifest says which safety functions that item implements; each
function declares the verification checks that exercise it. A verification
recorded before the intervention, whose verified checks intersect that set, no
longer describes the machine.

Every step of that chain is declared by the customer and visible in the output,
so a reviewer who disagrees can point at the link they disagree with. A function
that declares no checks is reported as ``not_demonstrable`` — never as covered.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, NamedTuple

from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc, parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import (
    BUNDLE_KIND,
    MachineSubjectError,
    provenance_lifts_tier,
    reassess_recorded_attestations,
    resolve_machine_serial,
)
from assurance.machine.recorder_attestation import RecorderTrust
from assurance.machine.verify import parse_engine_version
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest

__all__ = [
    "Coverage",
    "CoverageReport",
    "FunctionCoverage",
    "UnitClaims",
    "VerificationRecord",
    "VerificationRecordError",
    "assess_coverage",
]

#: Stands in for "when the machine was in the state this verification describes"
#: when that date cannot be used. It is the earliest instant there is, so every
#: recorded change counts as having come after it: an unknowable date is never
#: allowed to make a verification look newer than a change.
_EARLIEST = datetime(1, 1, 1, tzinfo=UTC)

#: How far past its own filing time a trace may claim to have started before it
#: is not believed. A day absorbs clock skew and time zones; it does not absorb
#: a run that "started" in 2099.
_FUTURE_TOLERANCE = timedelta(days=1)

_TIER_RANK = {"profile": 0, "community": 1, "validated": 2, "certified": 3}

#: The first engine whose sealed ``provenance_basis`` can mean a lifted tier. Engines 4
#: and earlier let a trace's declared provenance reach ``validated`` on the filer's
#: word; engine 5 capped it; engine 6 added the signed recorder attestation.
_FIRST_ENGINE_WITH_A_PROVENANCE_BASIS = 6


def tier_reaches_validated(tier: str) -> bool:
    """Is ``tier`` at least ``validated``? A name not on the ladder is not known to be."""
    return _TIER_RANK.get(tier, -1) >= _TIER_RANK["validated"]


class _UnitBinding(NamedTuple):
    """The unit a ledger subject names: the whole key, its serial, and whether it parses."""

    key: str
    serial: str
    well_formed: bool


def _unit_binding(subject: str | None) -> _UnitBinding | None:
    """The unit a ledger subject names; None for a product line.

    A subject with no ``#`` names a product line and binds nothing. One with a ``#`` is a
    unit key (``maker/model#serial``); a malformed one cannot be tied to any unit. The WHOLE
    key is kept: a recorder attestation signs a serial, never a maker or model, so what
    binds a bundle to a unit is the key the bundle was sealed for (``unit_key`` in its body).
    """
    if not subject or "#" not in subject:
        return None
    try:
        return _UnitBinding(subject, resolve_machine_serial(subject), True)
    except MachineSubjectError:
        return _UnitBinding(subject, "", False)


def _tier_and_why(
    body: dict[str, Any], recorder_trust: RecorderTrust | None = None,
    unit: _UnitBinding | None = None,
) -> tuple[str, str]:
    """:func:`_believed_tier` and, when the unit binding capped it, the named reason."""
    stored = str(body.get("tier", ""))
    if not tier_reaches_validated(stored):
        return stored, ""
    if unit is not None:
        # Filed under one unit's key: the evidence must have been sealed for THAT unit, whole.
        # The serial alone is not enough (an attestation made for serial 0001 on one maker's
        # machine says nothing about another maker's 0001), and a bundle sealed for a product
        # line accepts a recorder attestation made on ANY unit, so under a unit key it would
        # otherwise lend unit B the recorder of unit A.
        sealed_for = body.get("unit_key")
        if not unit.well_formed:
            return "community", (f"it is filed under {unit.key!r}, which is not a unit key "
                                 "(maker/model#serial), so it names no unit")
        if not isinstance(sealed_for, str) or not sealed_for:
            return "community", (
                "it was sealed without a unit key (for a product line, or before bundles "
                "recorded one), so nothing shows which maker and model its recorder was "
                f"attached to; it is not believed validated for {unit.key!r}")
        if sealed_for != unit.key:
            return "community", (f"it was sealed for {sealed_for!r} and is filed under "
                                 f"{unit.key!r}")
        if str(body.get("machine_serial") or "") != unit.serial:
            return "community", (f"it was matched against serial "
                                 f"{str(body.get('machine_serial') or '')!r}, not "
                                 f"{unit.serial!r}")
    engine = parse_engine_version(body.get("engine_version")) or 0
    if (engine >= _FIRST_ENGINE_WITH_A_PROVENANCE_BASIS
            and provenance_lifts_tier(body)
            and (recorder_trust is None
                 or _reproduces(body, recorder_trust, unit.serial if unit else None))):
        # Nothing in this product certifies: a stored 'certified' (only a resealed body can
        # carry one; the bundle checker rejects it) is read as 'validated' at most.
        return "validated", ""
    return "community", ""


def _believed_tier(
    body: dict[str, Any], recorder_trust: RecorderTrust | None = None,
    unit: _UnitBinding | None = None,
) -> str:
    """The tier a sealed verification body is worth *today*, whatever it says.

    The stored ``tier`` is a string the sealing engine wrote. A body sealed by an
    engine that let a declared provenance reach ``validated`` (engine 4 and earlier) or
    one that could not yet verify a recorder attestation (engine 5), or whose basis is
    not ``recorder_attested`` with a coherent accepted attestation recorded beside it,
    is read at ``community`` at most; the public bundle checker refuses the same bodies.
    A lower stored tier is never raised, and nothing is read above ``validated``.

    Filed under a unit key (``unit``), the body must also have been sealed for that exact
    key (``unit_key``, case- and whitespace-sensitive) and for its serial; a body that
    records no unit key is ``community`` there (no grandfathering of bundles sealed before
    the field existed).

    With ``recorder_trust`` (the reader's own list) the recorded attestations are also
    re-assessed under it, so a key the reader has since revoked or removed stops
    supporting a ``validated`` tier. An EMPTY list trusts nobody, so nothing re-assessed
    is ``validated``.

    ``recorder_trust=None`` means the reader has no list: the sealing verifier's own
    assessment, which a coherent record shows was made, is believed. That is only right
    where the ledger is the reader's own and nobody has revoked anything an offline
    command reading it could not know. **Every hosted (API) reader passes a list** --
    the server's, or an empty one when none is configured or the file is unusable
    (``api/recorder_trust.py:reader_recorder_trust``) -- so a missing or broken trust
    file can never make a reader more generous than a valid one.
    """
    return _tier_and_why(body, recorder_trust, unit)[0]


def _reproduces(
    body: dict[str, Any], recorder_trust: RecorderTrust, serial: str | None = None,
) -> bool:
    assessed = reassess_recorded_attestations(
        body, recorder_trust, now=None, machine_serial=serial)
    pa = body.get("provenance_assessment")
    return bool(assessed is not None and assessed.attested and isinstance(pa, dict)
                and assessed.attestation_hash == pa.get("attestation_hash"))


class UnitClaims:
    """Which unit key holds each recording as its validated evidence.

    One recording is the validated evidence of ONE unit key. The map is built from the ledger
    in a single pass over the bundles and answers, per trace hash, which unit key holds it: the
    earliest filing that would itself read ``validated`` (sealed for its own key, a coherent
    attestation that still holds under the reader's trust list) **under a unit key that is
    enrolled in the same ledger** (a manifest for it was sealed there). A filing under a key
    nobody enrolled holds nothing, so a mistyped or hostile first claim cannot burn the
    recording for the real unit; whoever can enrol a manifest for a hostile key still can
    (the ledger is append-only: the remedy is a new recording attested for the unit).

    Build it ONCE per ledger read and share it (``Fleet.from_ledger`` does): the expensive work,
    a seal verification and an attestation assessment, is done for the first valid claim on each
    recording and for nothing else, so a fleet read is linear in its bundles.
    """

    def __init__(self, holders: dict[str, tuple[int, str]]) -> None:
        self._holders = holders

    def holder(self, trace_hash: str) -> tuple[int, str] | None:
        """``(ledger position, unit key)`` of the claim that holds the recording, if any."""
        return self._holders.get(trace_hash)

    @classmethod
    def build(
        cls, ledger: EvidenceLedger, recorder_trust: RecorderTrust | None, *,
        only: set[str] | None = None,
    ) -> UnitClaims:
        """Read the ledger once. ``only`` limits the work to those trace hashes."""
        from assurance.machinery.record import MANIFEST_KIND

        enrolled: dict[str, bool] = {}

        def is_enrolled(subject: str) -> bool:
            if subject not in enrolled:
                enrolled[subject] = any(
                    e.evidence().verify()
                    for e in ledger.entries(kind=MANIFEST_KIND, subject=subject))
            return enrolled[subject]

        holders: dict[str, tuple[int, str]] = {}
        for entry in ledger.entries(kind=BUNDLE_KIND):
            unit = _unit_binding(entry.subject)
            if unit is None or not unit.well_formed:
                continue
            body = entry.payload.get("body")
            if not isinstance(body, dict) or not tier_reaches_validated(
                    str(body.get("tier", ""))):
                continue        # cheap first: only a stored 'validated' can be a claim
            trace_hash = str(body.get("trace_hash") or "")
            if (not trace_hash or trace_hash in holders
                    or (only is not None and trace_hash not in only)):
                continue
            if (is_enrolled(entry.subject) and entry.evidence().verify()
                    and tier_reaches_validated(_tier_and_why(body, recorder_trust, unit)[0])):
                holders[trace_hash] = (entry.seq, entry.subject)
        return cls(holders)


def _apply_unit_binding(
    ledger: EvidenceLedger, subject: str | None, recorder_trust: RecorderTrust | None,
    records: list[VerificationRecord], claims: UnitClaims | None = None,
) -> list[VerificationRecord]:
    """Name why the unit binding capped a record, and cap a recording's later claimant.

    A record that would read ``validated`` but whose recording is held by another unit key
    (:class:`UnitClaims`) is ``community`` with the holder named in ``tier_note``.
    ``reverify`` refuses the same case outright (``_trace_filed_elsewhere``).
    """
    if not records:
        return records
    by_seq = {r.ledger_seq: r for r in records}
    where: dict[int, tuple[str, str]] = {}      # seq -> (subject, trace hash), validated only

    def note(r: VerificationRecord, why: str, tier: str | None = None) -> VerificationRecord:
        return replace(r, tier=tier if tier is not None else r.tier, tier_note=why)

    for entry in ledger.entries(kind=BUNDLE_KIND, subject=subject):
        record = by_seq.get(entry.seq)
        body = entry.payload.get("body")
        if record is None or not isinstance(body, dict):
            continue
        if tier_reaches_validated(record.tier):
            if _unit_binding(entry.subject) is not None:
                where[entry.seq] = (entry.subject, str(body.get("trace_hash") or ""))
            continue
        if not tier_reaches_validated(str(body.get("tier", ""))):
            continue
        # capped by the unit binding: say why (cheap: the subject's own entries)
        _, why = _tier_and_why(body, recorder_trust, _unit_binding(entry.subject))
        if why:
            by_seq[entry.seq] = note(record, why)

    if where:
        if claims is None:
            claims = UnitClaims.build(ledger, recorder_trust,
                                      only={t for _, t in where.values() if t})
        for seq, (unit_key, trace_hash) in where.items():
            held = claims.holder(trace_hash) if trace_hash else None
            if held is not None and held[1] != unit_key:
                by_seq[seq] = note(
                    by_seq[seq],
                    f"the recording it rests on (trace {trace_hash[:12]}) is already the "
                    f"validated evidence of {held[1]!r} (filed first, ledger position "
                    f"{held[0]}); one recording is evidence about one unit",
                    tier="community")
    return [by_seq[r.ledger_seq] for r in records]


class VerificationRecordError(AssuranceError, ValueError):
    """A verification record cannot be dated, so it cannot be joined to changes."""


class Coverage(StrEnum):
    """The state of the evidence for one safety function."""

    #: A passing verification exists and nothing since has disturbed it.
    CURRENT = "current"
    #: It was verified, and a later intervention invalidated that verification.
    STALE = "stale"
    #: A run exercised this function's checks and at least one VIOLATED its limit.
    FAILING = "failing"
    #: The newest run left this function's checks UNCHECKED: it could not be judged (the trace
    #: gave it nothing to evaluate), none of its checks is verified, and none was violated.
    #: Nothing has been shown for the function, for or against; that is not a failure.
    UNCHECKED = "unchecked"
    #: Some of this function's checks are verified by their newest run and at least one other
    #: was left unchecked (and none was violated). Partly shown; cover needs every check.
    INCOMPLETE = "incomplete"
    #: No verification has ever exercised this function.
    NEVER_VERIFIED = "never_verified"
    #: The function declares no checks, so no verification could cover it.
    NOT_DEMONSTRABLE = "not_demonstrable"

    @property
    def is_covered(self) -> bool:
        return self is Coverage.CURRENT

    @property
    def rank(self) -> int:
        """Worst first, for sorting a report a human reads top-down."""
        return {"failing": 0, "stale": 1, "unchecked": 2, "incomplete": 3,
                "never_verified": 4, "not_demonstrable": 5, "current": 6}[self.value]


@dataclass(frozen=True)
class VerificationRecord:
    """A sealed machine verification, reduced to what staleness needs.

    ``effective_at`` is when the machine was in the state the verification
    describes — the start of the recorded run — not when the bundle was filed.
    A run captured in February and filed in June is evidence about February.
    """

    content_hash: str
    effective_at: datetime
    ledger_seq: int
    product: str
    product_version: str
    verdict: str
    #: The tier this record is *believed* at, not necessarily the one stored in the
    #: sealed body: see :func:`_believed_tier`. Records built by hand keep what they say.
    tier: str
    checks_verified: tuple[str, ...]
    checks_not_verified: tuple[str, ...] = ()
    #: The subset of ``checks_not_verified`` whose outcome was ``not_applicable``
    #: (the trace never entered that regime). Those say nothing for or against a
    #: function. A record that does not say which are which — every manually
    #: built one — has every non-verified check treated as failed.
    checks_not_applicable: tuple[str, ...] = ()
    #: The subset of ``checks_not_verified`` whose outcome was ``unchecked`` (the run could
    #: not judge that check). They are not violations. A record that does not say which are
    #: which, every manually built one, has every non-verified check treated as violated.
    checks_unchecked: tuple[str, ...] = ()
    #: Why ``tier`` is below what the sealed body stored, when the UNIT BINDING is what
    #: capped it (sealed for another unit key or none, or the same recording claimed by an
    #: earlier unit). Empty otherwise.
    tier_note: str = ""
    #: True when ``effective_at`` could not be taken from the bundle: its trace
    #: start was unreadable, or later than the moment it was filed. It is then the
    #: earliest possible instant (see ``_EARLIEST``).
    date_suspect: bool = False

    def __post_init__(self) -> None:
        if self.effective_at.tzinfo is None:
            raise VerificationRecordError(
                f"verification {self.content_hash[:12]} effective_at has no timezone; "
                "comparing it with a change record would mean guessing one."
            )

    @property
    def failed_checks(self) -> tuple[str, ...]:
        """Checks that ran here and did not pass: not verified, and not merely n/a."""
        n_a = set(self.checks_not_applicable)
        return tuple(c for c in self.checks_not_verified if c not in n_a)

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "effective_at": format_utc(self.effective_at),
            "ledger_seq": self.ledger_seq,
            "product": self.product,
            "product_version": self.product_version,
            "verdict": self.verdict,
            "tier": self.tier,
            "checks_verified": list(self.checks_verified),
            "checks_not_verified": list(self.checks_not_verified),
            "checks_not_applicable": list(self.checks_not_applicable),
            "checks_unchecked": list(self.checks_unchecked),
            "tier_note": self.tier_note,
            "date_suspect": self.date_suspect,
        }

    @classmethod
    def from_ledger(
        cls, ledger: EvidenceLedger, *, subject: str | None = None,
        recorder_trust: RecorderTrust | None = None, claims: UnitClaims | None = None,
    ) -> list[VerificationRecord]:
        """Read every sealed machine verification out of a ledger.

        ``recorder_trust`` is the reader's own recorder trust list; when given, a
        ``validated`` tier is kept only if the recorded attestation still re-assesses
        under it (revocation takes effect). See :func:`_believed_tier`.

        A bundle whose evidence no longer matches its own hash is skipped rather
        than trusted: a tampered record must not be able to make a stale
        function look current.
        """
        out: list[VerificationRecord] = []
        for entry in ledger.entries(kind=BUNDLE_KIND, subject=subject):
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            body = evidence.body
            checks = [c for c in (body.get("checks") or [])
                      if isinstance(c, dict) and isinstance(c.get("name"), str)]
            verified = tuple(c["name"] for c in checks
                             if c.get("outcome") == "verified")
            others = tuple(c["name"] for c in checks
                           if c.get("outcome") != "verified")
            not_applicable = tuple(c["name"] for c in checks
                                   if c.get("outcome") == "not_applicable")
            unchecked = tuple(c["name"] for c in checks if c.get("outcome") == "unchecked")
            filed = parse_utc(entry.at)
            suspect = False
            try:
                effective = parse_utc(str(body.get("trace_started_at")))
            except (ValueError, TypeError):
                effective, suspect = _EARLIEST, True
            else:
                if effective > filed + _FUTURE_TOLERANCE:
                    effective, suspect = _EARLIEST, True
            out.append(cls(
                content_hash=evidence.content_hash,
                effective_at=effective,
                ledger_seq=entry.seq,
                product=str(body.get("product", "")),
                product_version=str(body.get("product_version", "")),
                verdict=str(body.get("verdict", "")),
                tier=_believed_tier(body, recorder_trust, _unit_binding(entry.subject)),
                checks_verified=verified,
                checks_not_verified=others,
                checks_not_applicable=not_applicable,
                checks_unchecked=unchecked,
                date_suspect=suspect,
            ))
        return _apply_unit_binding(ledger, subject, recorder_trust, out, claims)


@dataclass(frozen=True)
class FunctionCoverage:
    """The evidence position for one declared safety function."""

    function_id: str
    description: str
    required_performance: str
    coverage: Coverage
    checks: tuple[str, ...]
    #: The most recent verification that covered this function, if any.
    last_verified_hash: str = ""
    last_verified_at: str = ""
    #: The intervention that invalidated it, when coverage is STALE.
    invalidated_by: str = ""
    invalidated_at: str = ""
    invalidating_item: str = ""
    #: Whether that intervention re-ran anything with sealed evidence.
    intervention_revalidated: bool = False
    detail: str = ""
    #: For a CURRENT function: the weakest tier among the verifications its cover rests on
    #: (``profile`` | ``community`` | ``validated`` | ``certified``). Empty otherwise.
    evidence_tier: str = ""

    @property
    def days_uncovered(self) -> int | None:
        """Days the machine has run without valid evidence for this function."""
        if self.coverage is not Coverage.STALE or not self.invalidated_at:
            return None
        try:
            from assurance.core.identity import utc_now
            return max(0, (utc_now() - parse_utc(self.invalidated_at)).days)
        except (ValueError, TypeError):
            return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "description": self.description,
            "required_performance": self.required_performance,
            "coverage": self.coverage.value,
            "checks": list(self.checks),
            "last_verified_hash": self.last_verified_hash,
            "last_verified_at": self.last_verified_at,
            "invalidated_by": self.invalidated_by,
            "invalidated_at": self.invalidated_at,
            "invalidating_item": self.invalidating_item,
            "intervention_revalidated": self.intervention_revalidated,
            "days_uncovered": self.days_uncovered,
            "detail": self.detail,
            "evidence_tier": self.evidence_tier,
        }


@dataclass(frozen=True)
class CoverageReport:
    """Every declared safety function, and whether evidence still stands for it."""

    machine_key: str
    manifest_id: str
    configuration_hash: str
    assessed_at: str
    functions: tuple[FunctionCoverage, ...]
    #: Interventions that touched a safety-bearing item and re-ran nothing.
    unrevalidated_interventions: tuple[str, ...]
    checks_skipped: tuple[str, ...]
    #: The weakest tier among the verifications the *current* functions rest on
    #: (``profile`` | ``community`` | ``validated`` | ``certified``), or ``""`` when no
    #: function is current. Coverage says the evidence still stands; this says how
    #: much that evidence is worth, and a cover resting on ``community`` is about a
    #: model or a recorded file, not a demonstration on the machine.
    evidence_tier_floor: str = ""

    @property
    def verdict(self) -> str:
        """``covered`` | ``covered_at_community`` | ``gaps`` | ``no_functions_declared``.

        ``covered`` means every declared function reads current AND the evidence each rests
        on is at ``validated`` or better. Cover that rests on evidence below that (a trace
        whose provenance the filer only declared is capped at ``community``) is
        ``covered_at_community``: the recorded evidence still stands, but it describes a
        model or a recorded file, not a demonstration on the machine, and it must not read
        as ``covered`` in a headline, a count or an exit code.
        """
        if not self.functions:
            return "no_functions_declared"
        if not all(f.coverage.is_covered for f in self.functions):
            return "gaps"
        return ("covered" if tier_reaches_validated(self.evidence_tier_floor)
                else "covered_at_community")

    @property
    def is_demonstrated(self) -> bool:
        """Is every declared function covered by evidence at ``validated`` or better?"""
        return self.verdict == "covered"

    @property
    def stale(self) -> tuple[FunctionCoverage, ...]:
        return tuple(f for f in self.functions if f.coverage is Coverage.STALE)

    @property
    def uncovered(self) -> tuple[FunctionCoverage, ...]:
        return tuple(f for f in self.functions if not f.coverage.is_covered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "manifest_id": self.manifest_id,
            "configuration_hash": self.configuration_hash,
            "assessed_at": self.assessed_at,
            "verdict": self.verdict,
            "functions": [f.to_dict() for f in self.functions],
            "unrevalidated_interventions": list(self.unrevalidated_interventions),
            "checks_skipped": list(self.checks_skipped),
            "evidence_tier_floor": self.evidence_tier_floor,
        }

    def summary(self) -> str:
        mark = {"current": "ok    ", "stale": "STALE ", "failing": "FAIL  ",
                "unchecked": "UNCHK ", "incomplete": "INCOMP",
                "never_verified": "never ", "not_demonstrable": "n/a   "}
        lines = [
            f"{self.machine_key} — {self.verdict.upper()}",
            f"  configuration {self.configuration_hash[:12]}  "
            f"manifest {self.manifest_id}",
        ]
        for f in sorted(self.functions, key=lambda f: (f.coverage.rank, f.function_id)):
            perf = f" [{f.required_performance}]" if f.required_performance else ""
            lines.append(f"  [{mark[f.coverage.value]}] {f.function_id}{perf}  "
                         f"{f.description}")
            lines.append(f"           {f.detail}")
            days = f.days_uncovered
            if days is not None:
                lines.append(f"           running {days} day(s) without valid evidence "
                             "for this function.")
        if self.unrevalidated_interventions:
            lines.append("  Interventions on safety-bearing items with nothing re-run: "
                         + ", ".join(self.unrevalidated_interventions))
        return "\n".join(lines)


def assess_coverage(
    manifest: SafetyManifest,
    verifications: list[VerificationRecord],
    interventions: list[Intervention],
) -> CoverageReport:
    """Work out, function by function, whether the evidence still stands.

    ``verifications`` and ``interventions`` need not be sorted; both are ordered
    here by the time they describe, not the time they were filed.
    """
    from assurance.core.identity import utc_now

    machine_key = manifest.machine.key
    mine = sorted(
        (i for i in interventions if i.machine_key == machine_key),
        key=lambda i: i.occurred_at,
    )
    verifs = sorted(verifications, key=lambda v: (v.effective_at, v.ledger_seq))

    caveats: list[str] = []
    coverages: list[FunctionCoverage] = []
    weak_tiers: dict[str, list[str]] = {}
    current_tiers: list[str] = []

    def latest(check: str) -> tuple[VerificationRecord, bool] | None:
        """The newest verification that ran ``check``, and whether it passed it.

        A run in which the check was not applicable says nothing either way and
        is skipped; a newer failing run ends the cover an older passing one gave.
        """
        for v in reversed(verifs):
            # Failure first: a record that carries the same check as both verified and
            # failed is contradictory, and contradictory evidence is not cover.
            if check in v.failed_checks:
                return v, False
            if check in v.checks_verified:
                return v, True
        return None

    for fn in sorted(manifest.functions, key=lambda f: f.function_id):
        checks = set(fn.verified_by)

        if not checks:
            coverages.append(FunctionCoverage(
                function_id=fn.function_id, description=fn.description,
                required_performance=fn.required_performance,
                coverage=Coverage.NOT_DEMONSTRABLE, checks=(),
                detail="this function declares no verification check, so no "
                       "verification can cover it. Declare the checks that exercise "
                       "it, or accept that its evidence lives outside this system.",
            ))
            continue

        # Interventions that disturb this function, by the functions they name.
        disturbing = [i for i in mine if checks & manifest.checks_for(set(i.affects_functions))]

        # Cover needs EVERY check the function declares, each judged by the newest
        # run that exercised it. One verified check of two is not cover, and a
        # newer failing run is not erased by an older passing one.
        state = {c: latest(c) for c in sorted(checks)}
        failing = {c: e for c, e in state.items() if e is not None and not e[1]}
        missing = sorted(c for c, e in state.items() if e is None)

        if failing:
            last = max((e[0] for e in failing.values()),
                       key=lambda v: (v.effective_at, v.ledger_seq))
            ran_unchecked = sorted(c for c, e in failing.items()
                                   if c in e[0].checks_unchecked)
            violated = sorted(set(failing) - set(ran_unchecked))
            if violated:
                coverages.append(FunctionCoverage(
                    function_id=fn.function_id, description=fn.description,
                    required_performance=fn.required_performance,
                    coverage=Coverage.FAILING, checks=tuple(sorted(checks)),
                    last_verified_hash=last.content_hash,
                    last_verified_at=format_utc(last.effective_at),
                    detail=f"the most recent run of {', '.join(violated)} "
                           f"({last.content_hash[:12]}, {last.verdict}) did not pass "
                           "it. Coverage has never been established, or has ended.",
                ))
                continue
            # No check was violated; the newest run left some UNCHECKED. That is a check
            # that was not run, not one that failed.
            shown = sorted(c for c, e in state.items() if e is not None and e[1])
            what = (f"{', '.join(ran_unchecked)} was left unchecked by its most recent "
                    f"run ({last.content_hash[:12]}, {last.verdict}): the check was not "
                    "run on that trace, so nothing was shown for or against it.")
            if shown:
                coverages.append(FunctionCoverage(
                    function_id=fn.function_id, description=fn.description,
                    required_performance=fn.required_performance,
                    coverage=Coverage.INCOMPLETE, checks=tuple(sorted(checks)),
                    detail=f"{', '.join(shown)} verified, but {what} Cover needs every "
                           "check the function declares: run the rest on a trace that "
                           "exercises it.",
                ))
            else:
                coverages.append(FunctionCoverage(
                    function_id=fn.function_id, description=fn.description,
                    required_performance=fn.required_performance,
                    coverage=Coverage.UNCHECKED, checks=tuple(sorted(checks)),
                    detail=f"{what} Run it on a trace that exercises it.",
                ))
            continue

        if missing:
            have = sorted(c for c, e in state.items() if e is not None)
            coverages.append(FunctionCoverage(
                function_id=fn.function_id, description=fn.description,
                required_performance=fn.required_performance,
                coverage=Coverage.NEVER_VERIFIED, checks=tuple(sorted(checks)),
                detail=("no verification in the ledger has ever run "
                        + ", ".join(missing) + " for this machine"
                        + (f" ({', '.join(have)} has been verified, which is not "
                           "enough: the function needs all of its checks)."
                           if have else ".")),
            ))
            continue

        # Every check has been verified. The function is only as current as the
        # oldest of the runs its checks rest on.
        used = {e[0].content_hash: e[0] for e in state.values() if e is not None}
        last_good = min(used.values(), key=lambda v: (v.effective_at, v.ledger_seq))
        after = [i for i in disturbing if i.occurred_at >= last_good.effective_at]
        tiers = {v.tier for v in used.values()}
        weakest = min(tiers, key=lambda t: _TIER_RANK.get(t, 0))
        if not after:
            current_tiers.append(weakest)
        if _TIER_RANK.get(weakest, 0) < _TIER_RANK["validated"] and not after:
            weak_tiers.setdefault(weakest, []).append(fn.function_id)

        if not after:
            coverages.append(FunctionCoverage(
                function_id=fn.function_id, description=fn.description,
                required_performance=fn.required_performance,
                coverage=Coverage.CURRENT, checks=tuple(sorted(checks)),
                evidence_tier=weakest,
                last_verified_hash=last_good.content_hash,
                last_verified_at=format_utc(last_good.effective_at),
                detail=f"verified by {last_good.content_hash[:12]} on "
                       f"{format_utc(last_good.effective_at)[:10]} at tier "
                       f"{weakest}; no recorded intervention since has "
                       "touched an item implementing it.",
            ))
            continue

        breaker = after[0]
        revalidated = breaker.is_revalidated
        coverages.append(FunctionCoverage(
            function_id=fn.function_id, description=fn.description,
            required_performance=fn.required_performance,
            coverage=Coverage.STALE, checks=tuple(sorted(checks)),
            last_verified_hash=last_good.content_hash,
            last_verified_at=format_utc(last_good.effective_at),
            invalidated_by=breaker.intervention_id,
            invalidated_at=format_utc(breaker.occurred_at),
            invalidating_item=breaker.item_id,
            intervention_revalidated=revalidated,
            detail=(
                f"last verified by {last_good.content_hash[:12]} on "
                f"{format_utc(last_good.effective_at)[:10]}; invalidated by "
                f"{breaker.intervention_id} on {format_utc(breaker.occurred_at)[:10]}, "
                f"which changed {breaker.item_id}"
                + (f" and re-ran {breaker.revalidation.description!r} — but that "
                   f"revalidation is not in this ledger, so it was not counted."
                   if revalidated and breaker.revalidation is not None
                   else " and re-ran nothing with sealed evidence.")
            ),
        ))

    for tier_name, fids in sorted(weak_tiers.items()):
        caveats.append(
            f"{', '.join(sorted(fids))} show as current on verification at tier "
            f"{tier_name!r}, below 'validated'. A trace's declared provenance is "
            "capped at 'community'; 'validated' needs a recorder attestation accepted "
            "under a recorder trust list the verifier holds, so "
            "current here means the recorded evidence still stands, not that the "
            "behaviour was demonstrated on the machine."
        )
    for v in verifs:
        if v.tier_note:
            caveats.append(
                f"verification {v.content_hash[:12]} is read at tier {v.tier!r}, not the "
                f"tier it was sealed at: {v.tier_note}.")
    for v in verifs:
        if v.date_suspect:
            caveats.append(
                f"verification {v.content_hash[:12]} cannot be dated by its trace "
                "start (the start is unreadable, or later than the moment the bundle "
                "was filed). It is treated as the earliest possible time, so every "
                "recorded change counts as having come after it."
            )

    # -- what this assessment could not see -------------------------------
    unrevalidated = tuple(
        i.intervention_id for i in mine
        if i.is_safety_bearing and not i.is_revalidated
    )
    if not mine:
        caveats.append(
            "no interventions were supplied for this machine. A function shown as "
            "current is current only against the change records you have; an "
            "unrecorded change is invisible here by construction."
        )
    unattributed = [i.intervention_id for i in mine if not i.is_safety_bearing]
    if unattributed:
        caveats.append(
            "intervention(s) " + ", ".join(unattributed) + " name no safety function, "
            "so they disturb nothing in this assessment. If any of them touched a "
            "safety-bearing item, the attribution is missing, not the risk."
        )
    if manifest.uncomparable_items:
        caveats.append(
            f"{len(manifest.uncomparable_items)} manifest item(s) carry no hash, so a "
            "change to them would not appear in a divergence report and would only "
            "reach this assessment if somebody wrote an intervention record by hand."
        )
    for item in manifest.field_modifiable_safety_items:
        caveats.append(
            f"{item.item_id} is safety-bearing and modifiable on site; coverage for "
            f"{', '.join(item.implements)} rests on every such change having been "
            "recorded."
        )
    caveats.append(
        "this joins verification bundles to intervention records through the safety "
        "functions the manifest declares. It does not confirm the manifest is "
        "complete, and a safety-relevant item nobody listed is covered by nothing "
        "here and reported by nothing here."
    )

    return CoverageReport(
        machine_key=machine_key,
        manifest_id=manifest.manifest_id,
        configuration_hash=manifest.configuration_hash(),
        assessed_at=format_utc(utc_now()),
        functions=tuple(coverages),
        unrevalidated_interventions=unrevalidated,
        checks_skipped=tuple(dict.fromkeys(caveats)),
        evidence_tier_floor=(min(current_tiers, key=lambda t: _TIER_RANK.get(t, 0))
                             if current_tiers else ""),
    )
