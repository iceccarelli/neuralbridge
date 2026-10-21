"""The deliverable: a sealed, independently checkable safety evidence bundle.

A verification result is an opinion until somebody can check it without
trusting the tool that produced it. That is what this module makes.

A bundle contains the envelope, the trace's identity, every check with its
margins, everything that was not checked, and the tier the whole thing is worth.
It is sealed into the hash-chained ledger, so a bundle produced in March cannot
be quietly improved in September: the chain says where it sat and what came
after it.

:func:`verify_bundle` is the half that matters commercially. A customer's
auditor, an insurer, or a notified body runs it against the exported file and
the original envelope and trace, and gets a yes or a no without installing
anything of ours beyond this package. Evidence nobody else can check is
marketing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    EvidenceRef,
    Origin,
    ValidationState,
)
from assurance.core.identity import content_hash_of, format_utc
from assurance.core.tiers import AssuranceTier
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import LimitsTable
from assurance.machine.trace import (
    MAX_FILE_BYTES,
    OperatingMode,
    Provenance,
    Sample,
    Trace,
)
from assurance.machine.verify import ENGINE_VERSION, Verdict, VerificationResult, verify

__all__ = [
    "BUNDLE_KIND",
    "LEVEL_INTEGRITY_ONLY",
    "LEVEL_REJECTED",
    "LEVEL_REPRODUCED",
    "BundleCheck",
    "BundleError",
    "EvidenceBundle",
    "build_bundle",
    "check_bundle",
    "check_bundle_data",
    "verify_bundle",
    "verify_bundle_data",
]

BUNDLE_KIND = "machine.safety_verification"
BUNDLE_SCHEMA = "assurance.machine.bundle/1"


class BundleError(AssuranceError):
    """A bundle is malformed, or does not match the inputs it claims."""


@dataclass(frozen=True)
class EvidenceBundle:
    """A sealed verification, ready to hand to someone who does not trust you."""

    evidence: Evidence
    result: VerificationResult
    envelope: SafetyEnvelope

    @property
    def content_hash(self) -> str:
        return self.evidence.content_hash

    @property
    def verdict(self) -> Verdict:
        return self.result.verdict

    @property
    def tier(self) -> AssuranceTier:
        return self.result.tier

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": BUNDLE_SCHEMA,
            "evidence": self.evidence.to_dict(),
            "envelope": self.envelope.to_dict(),
            "result": self.result.to_dict(),
        }

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")
        return p

    def summary(self) -> str:
        return (
            f"{self.result.summary()}\n"
            f"  sealed as {self.content_hash[:16]} "
            f"({len(self.result.checks_skipped)} stated limitations)"
        )


def _body(result: VerificationResult, envelope: SafetyEnvelope,
          limits: LimitsTable | None, trace: Trace) -> dict[str, Any]:
    return {
        "schema": BUNDLE_SCHEMA,
        "product": envelope.product,
        "product_version": envelope.product_version,
        "envelope_hash": result.envelope_hash,
        "trace_hash": result.trace_hash,
        "trace_id": result.trace_id,
        # When the machine was in the state this verification describes. A run
        # captured in February and filed in June is evidence about February, and
        # staleness is computed against this, never against the filing time.
        "trace_started_at": format_utc(trace.started_at),
        "provenance": result.provenance,
        "engine_version": result.engine_version,
        "limits_hash": limits.content_hash() if limits else "",
        "verdict": result.verdict.value,
        "tier": result.tier.value,
        "checks": [c.to_dict() for c in result.checks],
    }


def _judgement(res: VerificationResult) -> tuple[ValidationState, Confidence]:
    """The validation state and confidence a result earns. One rule for sealing and replay."""
    state = {
        Verdict.PASS: ValidationState.VERIFIED,
        Verdict.FAIL: ValidationState.REFUTED,
        Verdict.INCOMPLETE: ValidationState.INDETERMINATE,
    }[res.verdict]
    confidence = Confidence.HIGH if (
        res.verdict is Verdict.PASS and res.tier.may_claim_physical_behaviour
    ) else Confidence.MEDIUM if res.verdict is Verdict.PASS else Confidence.LOW
    return state, confidence


def _refuse_foreign_result(
    result: VerificationResult, envelope: SafetyEnvelope, trace: Trace,
) -> None:
    mismatches = []
    if result.envelope_hash != envelope.content_hash():
        mismatches.append("it was computed against a different envelope")
    if result.trace_hash != trace.content_hash():
        mismatches.append("it was computed against a different trace")
    if result.provenance != trace.provenance.value:
        mismatches.append(f"it names provenance {result.provenance!r}, the trace is "
                          f"{trace.provenance.value!r}")
    if (result.product, result.product_version) != (envelope.product,
                                                    envelope.product_version):
        mismatches.append("it names a different product or version")
    ceiling = min(trace.provenance.tier_ceiling, envelope.tier_ceiling)
    if result.tier > ceiling:
        mismatches.append(f"it claims tier {result.tier.value!r}, above the "
                          f"{ceiling.value!r} these inputs can support")
    if mismatches:
        raise BundleError(
            "the supplied result does not belong to this envelope and trace: "
            + "; ".join(mismatches) + ".")


def build_bundle(
    envelope: SafetyEnvelope,
    trace: Trace,
    *,
    actor: Actor,
    limits: LimitsTable | None = None,
    ledger: EvidenceLedger | None = None,
    result: VerificationResult | None = None,
    subject: str = "",
) -> EvidenceBundle:
    """Verify, seal, and optionally append to the ledger.

    ``actor`` is required and unattributed bundles are refused by
    :meth:`Evidence.seal`. A safety verification that nobody signed is a file,
    not evidence.

    ``subject`` sets the ledger subject. It defaults to ``product@version``,
    which is right for a manufacturer verifying a product line. Pass a machine
    key (``MachineIdentity.key``) when the verification is about one specific
    unit, so that :mod:`assurance.machinery.staleness` can find it alongside
    that unit's intervention records.

    ``result`` lets a caller seal a verification it already ran. It must be the
    verification of *these* inputs: a result for another trace or envelope, or one
    claiming a tier its inputs cannot support, is refused rather than sealed under
    a trace it says nothing about.
    """
    res = result if result is not None else verify(envelope, trace, limits=limits)
    if result is not None:
        _refuse_foreign_result(result, envelope, trace)

    state, confidence = _judgement(res)

    evidence = Evidence(
        kind=BUNDLE_KIND,
        body=_body(res, envelope, limits, trace),
        actor=actor,
        origin=Origin(
            system="assurance.machine",
            reference=f"{envelope.product} {envelope.product_version} / {trace.trace_id}",
            method=f"engine {res.engine_version}: recorded trace compared against "
                   f"declared safety envelope",
        ),
        validation_state=state,
        confidence=confidence,
        checks_skipped=res.checks_skipped,
        relations=(
            EvidenceRef(relation="concerns", content_hash=res.envelope_hash,
                        note="the declared safety envelope"),
            EvidenceRef(relation="derived_from", content_hash=res.trace_hash,
                        note=f"the {res.provenance} trace {res.trace_id}"),
        ),
    ).seal()

    if ledger is not None:
        ledger.append(
            evidence,
            subject=subject or f"{envelope.product}@{envelope.product_version}",
        )

    return EvidenceBundle(evidence=evidence, result=res, envelope=envelope)


_OUTCOMES = ("verified", "violated", "not_applicable", "unchecked")
_VERDICTS = ("pass", "fail", "incomplete")
_TIERS = {t.value: t for t in AssuranceTier}
_STATE_FOR_VERDICT = {
    "pass": ValidationState.VERIFIED.value,
    "fail": ValidationState.REFUTED.value,
    "incomplete": ValidationState.INDETERMINATE.value,
}


def _checks_by_name(checks: Any) -> dict[str, Any]:
    return {str(c.get("name")): c for c in checks if isinstance(c, dict)}


@lru_cache(maxsize=1)
def _standard_check_names() -> tuple[str, ...] | None:
    """The names of the checks the engine produces, asked of the engine itself.

    The engine returns every one of its checks on every run (a check that does not
    apply is ``not_applicable``, never absent), so running it once over the
    smallest valid inputs gives the set without a second copy of the names here to
    drift out of step. ``None`` when the probe cannot run: callers then say so
    rather than guess.
    """
    try:
        probe_envelope = SafetyEnvelope(
            envelope_id="probe", product="probe", product_version="0",
            workspace=Workspace(minimum=(-1.0, -1.0, -1.0), maximum=(1.0, 1.0, 1.0)),
            max_tcp_speed_mm_s={},
            stop=StopPerformance(
                reaction_time_s=0.1, stop_time_s=0.1, stop_distance_mm=1.0,
                measured_at_speed_mm_s=1.0,
                basis=FigureBasis(kind="estimated", reference="probe")),
            uncertainty=SensingUncertainty(
                human_position_mm=0.0, robot_position_mm=0.0,
                basis=FigureBasis(kind="estimated", reference="probe")),
            intrusion_distance_mm=1.0,
        )
        probe_trace = Trace(
            trace_id="probe", provenance=Provenance.SIMULATION, source_system="probe",
            started_at=datetime(2026, 1, 1, tzinfo=UTC), sample_rate_hz=50.0,
            samples=tuple(
                Sample(t=i / 50.0, tcp=(0.0, 0.0, 0.0), tcp_speed=0.0,
                       mode=OperatingMode.STOPPED)
                for i in range(2)),
        )
        return tuple(c.name for c in verify(probe_envelope, probe_trace).checks)
    except (AssuranceError, ValueError, TypeError, KeyError):
        return None


def _check_set_problems(
    body: dict[str, Any], checks: list[Any],
) -> tuple[list[str], list[str], list[str]]:
    """``(problems, limitations, verified)`` for the names of the recorded checks.

    A bundle that records one invented check is not a verification: the engine
    always produces its whole set, so the sealed names must be exactly that set.
    """
    engine = body.get("engine_version")
    if engine != ENGINE_VERSION:
        return [], [
            f"NOT CHECKED: the bundle was produced by engine {engine!r}, whose set of "
            f"checks this verifier ({ENGINE_VERSION!r}) does not know, so whether the "
            "recorded checks are the complete set was not checked."], []
    standard = _standard_check_names()
    if standard is None:
        return [], [
            "NOT CHECKED: this verifier could not work out the set of checks the "
            "engine produces, so whether the recorded checks are the complete set was "
            "not checked."], []
    problems: list[str] = []
    seen: list[str] = []
    for c in checks:
        if not isinstance(c, dict):
            continue
        name = c.get("name")
        key = name if isinstance(name, str) else repr(name)
        if key in seen:
            if f"the bundle records check {key!r} twice." not in problems:
                problems.append(f"the bundle records check {key!r} twice.")
        else:
            seen.append(key)
    missing = [n for n in standard if n not in seen]
    extra = [n for n in seen if n not in standard]
    if missing:
        problems.append(
            f"the bundle omits check(s) {', '.join(map(repr, missing))}, which engine "
            f"{ENGINE_VERSION!r} always produces; a verification with a check "
            "removed is not the verification the engine runs.")
    if extra:
        problems.append(
            f"the bundle records check(s) {', '.join(map(repr, extra))}, which engine "
            f"{ENGINE_VERSION!r} does not produce.")
    verified = [] if problems else [
        f"the recorded checks are exactly the {len(standard)} that engine "
        f"{ENGINE_VERSION!r} produces, none missing, none invented"]
    return problems, [], verified


def _coherence_problems(
    evidence: Evidence, raw: dict[str, Any],
) -> tuple[list[str], list[str], list[str]]:
    """Whether the claim hangs together, without the original inputs.

    The seal is a content hash, not a signature: anyone with this package can
    edit a bundle and recompute it. So the checks here ask whether what the
    bundle says about itself is *possible* — a simulated trace cannot be
    validated, a certified tier cannot come from a file, a tier cannot exceed the
    ceiling of the envelope printed beside it, the checks must be exactly the set
    the engine produces, a violated check must list its violations, the printed
    result must repeat the sealed one — and return ``(problems, limitations,
    verified)``. ``verified`` lists only claims a check here actually established;
    it is meaningful only when ``problems`` is empty.
    """
    problems: list[str] = []
    limits: list[str] = []
    verified: list[str] = []
    body = evidence.body

    if evidence.kind != BUNDLE_KIND:
        problems.append(
            f"the sealed evidence is of kind {evidence.kind!r}, not {BUNDLE_KIND!r}; "
            "this is not a machine verification bundle."
        )

    checks = body.get("checks")
    if not isinstance(checks, list) or not checks:
        problems.append(
            "the bundle records no checks. A verdict with nothing behind it is not a "
            "pass."
        )
        checks = []
    violated = unchecked = 0
    for c in checks:
        if not isinstance(c, dict):
            problems.append("a recorded check is not an object.")
            continue
        name, outcome = c.get("name"), c.get("outcome")
        if outcome not in _OUTCOMES:
            problems.append(f"check {name!r} has outcome {outcome!r}, which is not one "
                            f"of {', '.join(_OUTCOMES)}.")
            continue
        listed = c.get("violations")
        count = c.get("violation_count")
        n = len(listed) if isinstance(listed, list) else None
        if count != n:
            problems.append(f"check {name!r} counts {count!r} violation(s) and lists "
                            f"{n!r}.")
        if outcome == "violated":
            violated += 1
            if not n:
                problems.append(f"check {name!r} is recorded as violated but lists no "
                                "violation.")
        elif n:
            problems.append(f"check {name!r} is recorded as {outcome} but lists {n} "
                            "violation(s).")
        if outcome == "unchecked":
            unchecked += 1
    if checks:
        set_problems, set_limits, set_verified = _check_set_problems(body, checks)
        problems.extend(set_problems)
        limits.extend(set_limits)
        verified.extend(set_verified)

    implied = "fail" if violated else "incomplete" if unchecked else "pass"
    verdict = body.get("verdict")
    if verdict not in _VERDICTS:
        problems.append(f"the bundle records verdict {verdict!r}, which is not one of "
                        f"{', '.join(_VERDICTS)}.")
    elif verdict != implied:
        problems.append(
            f"the bundle records verdict {verdict!r} but its own checks imply "
            f"{implied!r} ({violated} violated, {unchecked} unchecked)."
        )
    else:
        verified.append(
            f"the recorded verdict {verdict!r} agrees with the bundle's own "
            f"{len(checks)} checks ({violated} violated, {unchecked} unchecked)")

    tier_name = body.get("tier")
    provenance = body.get("provenance")
    tier = _TIERS.get(str(tier_name))
    tier_problems = len(problems)
    if tier is None:
        problems.append(f"the bundle records tier {tier_name!r}, which is not a tier.")
    elif tier is AssuranceTier.CERTIFIED:
        problems.append(
            "the bundle records tier 'certified'. That tier needs an accredited "
            "third party and is not reachable from a file, so a bundle cannot carry it."
        )
    if provenance not in ("simulation", "bench", "field"):
        problems.append(f"the bundle records provenance {provenance!r}, which is not "
                        "simulation, bench or field.")
    elif (tier is not None and provenance == "simulation"
            and tier.rank > AssuranceTier.COMMUNITY.rank):
        problems.append(
            f"the bundle records a simulation trace and tier {tier.value!r}. A "
            "simulation can never exceed 'community': it says nothing about how the "
            "hardware behaves."
        )
    if len(problems) == tier_problems:
        verified.append(
            f"the recorded tier {tier_name!r} is one the engine can produce from the "
            f"recorded provenance {provenance!r} (not 'certified', not above that "
            "provenance's ceiling)")

    state = evidence.validation_state.value
    if verdict in _STATE_FOR_VERDICT and state != _STATE_FOR_VERDICT[verdict]:
        problems.append(
            f"the sealed validation state is {state!r} but the verdict {verdict!r} "
            f"requires {_STATE_FOR_VERDICT[verdict]!r}."
        )
    physical = (tier is not None and tier.may_claim_physical_behaviour
                and provenance != "simulation")
    if evidence.confidence in (Confidence.HIGH, Confidence.ESTABLISHED) and not (
            verdict == "pass" and physical):
        problems.append(
            f"the sealed confidence is {evidence.confidence.value!r}, which a bundle "
            "earns only with a pass at a tier that may claim physical behaviour."
        )

    relations = {(r.relation, r.content_hash) for r in evidence.relations}
    for relation, key in (("concerns", "envelope_hash"), ("derived_from", "trace_hash")):
        if body.get(key) and (relation, body.get(key)) not in relations:
            problems.append(f"the sealed relations do not name the {key} the body "
                            "records.")

    # -- the half of the file the seal does not cover -------------------------
    result = raw.get("result")
    if result is None:
        limits.append("NOT CHECKED: the file carries no result block beside the seal.")
    elif not isinstance(result, dict):
        problems.append("the result block is not an object.")
    else:
        before = len(problems)
        for key in ("verdict", "tier", "provenance", "envelope_hash", "trace_hash",
                    "trace_id", "product", "product_version", "engine_version"):
            if result.get(key) != body.get(key):
                problems.append(
                    f"the printed result says {key} is {result.get(key)!r}; the sealed "
                    f"evidence says {body.get(key)!r}. The result block was edited."
                )
        if result.get("may_claim_physical_behaviour") != physical:
            problems.append(
                "the printed result says may_claim_physical_behaviour is "
                f"{result.get('may_claim_physical_behaviour')!r}; the sealed tier "
                f"{tier_name!r} and provenance {provenance!r} give {physical!r}."
            )
        if content_hash_of(result.get("checks")) != content_hash_of(body.get("checks")):
            problems.append("the printed result's checks differ from the sealed "
                            "evidence's checks. The result block was edited.")
        if list(result.get("checks_skipped") or []) != list(evidence.checks_skipped):
            problems.append("the printed result's stated limitations differ from the "
                            "sealed evidence's.")
        if len(problems) == before:
            verified.append("the unsealed result block agrees with the sealed verdict, "
                            "tier, provenance, checks and stated limitations")

    printed_env = raw.get("envelope")
    if printed_env is None:
        limits.append("NOT CHECKED: the file carries no envelope beside the seal.")
    else:
        try:
            printed = SafetyEnvelope.from_dict(printed_env)
            printed_hash = printed.content_hash()
        except (AssuranceError, KeyError, TypeError, ValueError, AttributeError) as exc:
            problems.append(f"the envelope printed in the bundle cannot be read: {exc}")
        else:
            if printed_hash != body.get("envelope_hash"):
                problems.append(
                    "the envelope printed in the bundle is not the one the sealed "
                    f"evidence names (printed {printed_hash[:12]}, sealed "
                    f"{str(body.get('envelope_hash'))[:12]}). It was edited."
                )
            else:
                verified.append(
                    "the envelope copy in the bundle hashes to the envelope hash "
                    "sealed inside the evidence")
                ceiling = printed.tier_ceiling
                if tier is not None and tier.rank > ceiling.rank:
                    problems.append(
                        f"the bundle records tier {tier.value!r}, above the ceiling "
                        f"{ceiling.value!r} that its own envelope's figures allow "
                        "(the stop and sensing figures were not measured on this "
                        "machine).")
                elif tier is not None:
                    verified.append(
                        f"the recorded tier is not above the ceiling "
                        f"({ceiling.value!r}) that the envelope copy in the bundle "
                        "allows")
    return problems, limits, verified


LEVEL_REJECTED = "rejected"
LEVEL_INTEGRITY_ONLY = "integrity_only"
LEVEL_REPRODUCED = "reproduced"


@dataclass(frozen=True)
class BundleCheck:
    """What checking a bundle established, and how far it got.

    ``ok`` means *no inconsistency found* and nothing more: a seal is not a
    signature, so a bundle someone built by hand and sealed again can be ``ok``.
    ``level`` says how much that is worth:

    * ``rejected`` — a problem was found (``ok`` is false);
    * ``integrity_only`` — the seal holds and the claim is coherent, but the engine
      was **not** re-run on the original envelope and trace, so nothing shows the
      machine behaved as recorded;
    * ``reproduced`` — the original envelope and trace (and limits table, if the
      bundle used one) were supplied, matched, and re-running the engine
      reproduced every sealed field.
    """

    ok: bool
    level: str
    problems: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    verified: tuple[str, ...] = ()
    #: The sealed evidence hashes to the hash it carries.
    seal_intact: bool = False
    #: The sealed claim hangs together without the originals (and was readable).
    internally_consistent: bool = False
    #: The engine was re-run on the supplied inputs (whether or not it matched).
    replayed: bool = False

    @property
    def reproduced(self) -> bool:
        return self.level == LEVEL_REPRODUCED

    @property
    def notes(self) -> list[str]:
        """Problems first, then stated limitations: what ``verify_bundle`` returns."""
        return [*self.problems, *self.limitations]


def _rejected(*problems: str) -> BundleCheck:
    return BundleCheck(ok=False, level=LEVEL_REJECTED, problems=tuple(problems))


def check_bundle(
    bundle_path: str | Path,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
) -> BundleCheck:
    """:func:`verify_bundle` with the full answer: ``level`` and what ran."""
    path = Path(bundle_path)
    if path.stat().st_size > MAX_FILE_BYTES:
        return _rejected(f"{path.name} is larger than the {MAX_FILE_BYTES} bytes this "
                         "checker will read.")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        return _rejected(f"the file is not readable JSON: {exc}")
    return check_bundle_data(raw, envelope=envelope, trace=trace, limits=limits)


def verify_bundle(
    bundle_path: str | Path,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
) -> tuple[bool, list[str]]:
    """Check a bundle without trusting whoever produced it.

    Returns ``(ok, problems)``. Separate things are checked, and the caller is
    told which failed:

    1. The sealed evidence hashes to the hash it carries. A bundle whose body
       was edited after sealing fails here.
    2. The claim is coherent *without* the originals: the recorded verdict agrees
       with the bundle's own checks, the checks are exactly the set the engine
       produces, a simulation does not hold a validated tier, no file holds a
       certified one, no tier exceeds its envelope's ceiling, and the envelope
       and result printed beside the seal repeat what the seal says. A content
       hash can be recomputed by anyone, so this is what stops a re-sealed edit.
    3. If the original ``envelope`` and ``trace`` (and ``limits``, if the bundle
       used a table) are supplied, their content hashes match the ones the bundle
       names, and re-running the engine reproduces every sealed field: each check,
       the verdict, the tier, the stated limitations, the trace's start time, its
       identity, the product and provenance. This is the check an auditor runs.

    ``ok`` means **no inconsistency found**. It is not "reproduced": a seal is not
    a signature, so a hand-built bundle that is coherent and sealed again is
    ``ok`` at step 2 alone. The notes that follow ``problems`` say what was not
    done (``NOT CHECKED: ...``), and :func:`check_bundle` returns ``level``
    (``integrity_only`` or ``reproduced``) so a caller can tell the two apart; the
    CLI prints ``NOT REPRODUCED`` for the first and keeps exit status 0 for both.

    Supplying neither envelope nor trace is allowed and is reported as a stated
    limitation, not a pass: integrity alone does not make a claim true. A file
    that cannot be read is reported as a problem; this never raises on content.
    """
    result = check_bundle(bundle_path, envelope=envelope, trace=trace, limits=limits)
    return result.ok, result.notes


def verify_bundle_data(
    raw: Any,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
) -> tuple[bool, list[str]]:
    """:func:`verify_bundle` for a bundle already parsed, so nothing is written to disk."""
    result = check_bundle_data(raw, envelope=envelope, trace=trace, limits=limits)
    return result.ok, result.notes


def check_bundle_data(
    raw: Any,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
) -> BundleCheck:
    """The one implementation: library, CLI and HTTP routes all end up here."""
    if not isinstance(raw, dict):
        return _rejected(f"the file holds a JSON {type(raw).__name__}, not a bundle object.")

    if raw.get("schema") != BUNDLE_SCHEMA:
        return _rejected(
            f"bundle schema is {raw.get('schema')!r}, expected {BUNDLE_SCHEMA!r}.")

    try:
        evidence = Evidence.from_dict(raw["evidence"])
    except Exception as exc:  # noqa: BLE001 - report, do not raise, to a verifier
        return _rejected(f"the sealed evidence object could not be read: {exc!r}")

    if not isinstance(evidence.body, dict):
        return _rejected("the sealed evidence body is not an object.")

    problems: list[str] = []
    limitations: list[str] = []
    verified: list[str] = []

    seal_intact = evidence.verify()
    if seal_intact:
        verified.append("the sealed evidence object still hashes to the hash it carries")
    else:
        problems.append(
            f"the evidence does not hash to the value it carries "
            f"({evidence.content_hash[:16]}). The bundle was edited after sealing."
        )

    body = evidence.body
    coherence, coherence_limits, coherence_verified = _coherence_problems(evidence, raw)
    problems.extend(coherence)
    limitations.extend(coherence_limits)
    verified.extend(coherence_verified)

    inputs_match = True
    if envelope is not None and envelope.content_hash() != body.get("envelope_hash"):
        inputs_match = False
        problems.append(
            "the supplied envelope is not the one this bundle was produced "
            f"against (bundle names {str(body.get('envelope_hash'))[:12]}, "
            f"supplied is {envelope.content_hash()[:12]})."
        )
    if trace is not None and trace.content_hash() != body.get("trace_hash"):
        inputs_match = False
        problems.append(
            "the supplied trace is not the one this bundle was produced against "
            f"(bundle names {str(body.get('trace_hash'))[:12]}, supplied is "
            f"{trace.content_hash()[:12]})."
        )

    recorded_limits = body.get("limits_hash") or ""
    if limits is not None and limits.content_hash() != recorded_limits:
        inputs_match = False
        problems.append(
            "the supplied limits table is not the one this bundle was produced "
            f"against (bundle names {recorded_limits[:12] or 'no table'}, supplied is "
            f"{limits.content_hash()[:12]})."
        )

    replayed = False
    replay_problems: list[str] = []
    if envelope is None or trace is None:
        limitations.insert(0, (
            "NOT CHECKED: the original envelope and trace were not supplied, so only "
            "the bundle's internal integrity was confirmed. Nothing here shows the "
            "machine behaved as the bundle says."
        ))
    elif inputs_match:
        if body.get("engine_version") != ENGINE_VERSION:
            problems.append(
                f"the bundle was produced by engine {body.get('engine_version')!r} and "
                f"this is engine {ENGINE_VERSION!r}; a re-run under different rules is "
                "not a reproduction. Check it with the engine that produced it."
            )
        elif recorded_limits and limits is None:
            limitations.insert(0, (
                "NOT CHECKED: the bundle was produced against a body-region limits "
                f"table ({recorded_limits[:12]}) that was not supplied, so the "
                "re-run was not performed. Supply it with --limits."
            ))
        else:
            try:
                replay = verify(envelope, trace, limits=limits)
            except AssuranceError as exc:
                problems.append(f"re-running the engine on the supplied inputs failed: "
                                f"{exc}")
            else:
                replayed = True
                replay_problems = _replay_differences(
                    replay, evidence, envelope, trace, limits)
                problems.extend(replay_problems)

    ok = not problems
    reproduced = ok and replayed
    if reproduced:
        verified.append(
            f"re-running engine {ENGINE_VERSION!r} on the supplied envelope and trace"
            + (" and limits table" if recorded_limits else "")
            + " reproduces every sealed check, the verdict, tier, provenance, trace "
            "identity and start time, the stated limitations and the confidence")
    level = (LEVEL_REJECTED if not ok
             else LEVEL_REPRODUCED if reproduced else LEVEL_INTEGRITY_ONLY)
    return BundleCheck(
        ok=ok, level=level, problems=tuple(problems), limitations=tuple(limitations),
        verified=tuple(verified) if ok else (),
        seal_intact=seal_intact,
        internally_consistent=not coherence,
        replayed=replayed)


def _replay_differences(
    replay: VerificationResult, evidence: Evidence, envelope: SafetyEnvelope,
    trace: Trace, limits: LimitsTable | None,
) -> list[str]:
    """Every way the sealed bundle differs from what the supplied inputs produce.

    The expected body is built by the same function that sealed it, so a field the
    seal carries that the inputs can give — the trace's start time (which staleness
    joins on), its identity, the product and version, the provenance — cannot be
    resealed to say something else without being reported here.
    """
    body = evidence.body
    out: list[str] = []
    expected = _body(replay, envelope, limits, trace)
    for key in sorted(set(expected) | set(body), key=str):
        if key == "checks":
            continue
        if key not in body:
            out.append(f"re-running produces {key} {expected[key]!r}, which the sealed "
                       "body omits.")
        elif key not in expected:
            out.append(f"the sealed body carries a field {key!r} that the engine does "
                       "not produce.")
        elif body[key] != expected[key]:
            out.append(
                f"re-running the engine on the supplied inputs gives {key} "
                f"{expected[key]!r}, not the recorded {body[key]!r}.")
    mine = _checks_by_name([c.to_dict() for c in replay.checks])
    theirs = _checks_by_name(body.get("checks") or [])
    for name in sorted(set(mine) | set(theirs), key=str):
        if name not in theirs:
            out.append(f"re-running produces check {name!r}, which the bundle omits.")
        elif name not in mine:
            out.append(f"the bundle records check {name!r}, which re-running does "
                       "not produce.")
        elif content_hash_of(mine[name]) != content_hash_of(theirs[name]):
            out.append(f"check {name!r} differs on re-running: the recorded result "
                       "is not what these inputs produce.")
    if list(replay.checks_skipped) != list(evidence.checks_skipped):
        out.append("the stated limitations differ from those produced on re-running; "
                   "a limitation was added, dropped or reworded.")
    state, confidence = _judgement(replay)
    if evidence.validation_state is not state:
        out.append(f"re-running gives validation state {state.value!r}, not the sealed "
                   f"{evidence.validation_state.value!r}.")
    if evidence.confidence is not confidence:
        out.append(f"re-running gives confidence {confidence.value!r}, not the sealed "
                   f"{evidence.confidence.value!r}.")
    wanted = {("concerns", replay.envelope_hash), ("derived_from", replay.trace_hash)}
    if {(r.relation, r.content_hash) for r in evidence.relations} != wanted:
        out.append("the sealed relations differ from the ones this verification "
                   "produces; a relation was added, dropped or changed.")
    return out


def bundle_digest(bundle: EvidenceBundle) -> str:
    """A short, stable identifier to print on a report or a label."""
    return content_hash_of({
        "bundle": bundle.content_hash,
        "product": bundle.envelope.product,
        "version": bundle.envelope.product_version,
    })[:16]
