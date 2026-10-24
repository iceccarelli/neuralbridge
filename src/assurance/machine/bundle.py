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
from collections.abc import Sequence
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
from assurance.machine import provenance_trust
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import LimitsTable
from assurance.machine.limits_review import ReviewTrust
from assurance.machine.recorder_attestation import (
    MachineRef,
    RecorderAttestation,
    RecorderAttestationError,
    RecorderTrust,
    RecordingFacts,
    assess_recorder_attestation,
)
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
        # Why that provenance is believed: "declared_by_filer" caps the tier at
        # community; "recorder_attested" means a signed recorder attestation was
        # accepted under the SEALING verifier's trust list. A checker never believes
        # the word: it re-assesses the attestations recorded below under its own list.
        "provenance_basis": result.provenance_basis,
        "provenance_assessment": result.provenance_assessment,
        # How the supplied recorder attestations were assessed, and the attestations as
        # supplied. Never a trust list: that is the verifier's own input.
        "recorder_attestation": result.recorder_attestation,
        # The unit the verification is about (empty: the product line); the
        # attestation's machine reference is matched against it.
        "machine_serial": result.machine_serial,
        "engine_version": result.engine_version,
        "limits_hash": limits.content_hash() if limits else "",
        # How the table's review evidence was assessed, with the reviews themselves,
        # so a verifier can re-assess them under its own trust list.
        "limits_review": result.limits_review,
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
    attestations: Sequence[Any] = (), recorder_trust: RecorderTrust | None = None,
    machine_serial: str = "",
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
    assessed = provenance_trust.assess_provenance(
        trace, attestations, recorder_trust,
        machine_ref=MachineRef(envelope.product, envelope.product_version, machine_serial))
    ceiling = min(assessed.ceiling, envelope.tier_ceiling)
    if result.provenance_basis != assessed.basis.value:
        mismatches.append(f"it names provenance basis {result.provenance_basis!r}, these "
                          f"inputs give {assessed.basis.value!r}")
    if result.tier > ceiling:
        mismatches.append(f"it claims tier {result.tier.value!r}, above the "
                          f"{ceiling.value!r} these inputs can support")
    if mismatches:
        raise BundleError(
            "the supplied result does not belong to this envelope and trace: "
            + "; ".join(mismatches) + ".")


def _serial_of(subject: str) -> str:
    """The unit serial in a machine key (``maker/model#serial``), or ``""``."""
    return subject.rpartition("#")[2].strip() if "#" in subject else ""


def build_bundle(
    envelope: SafetyEnvelope,
    trace: Trace,
    *,
    actor: Actor,
    limits: LimitsTable | None = None,
    limits_reviews: Sequence[Any] = (),
    review_trust: ReviewTrust | None = None,
    recorder_attestations: Sequence[Any] = (),
    recorder_trust: RecorderTrust | None = None,
    machine_serial: str = "",
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

    ``recorder_attestations`` are signed attestations of the trace; ``recorder_trust`` is
    the sealing verifier's own list of recorder keys. Without a trust list nothing can be
    accepted and the provenance stays declared by the filer. ``machine_serial`` names the
    unit; when omitted it is taken from a ``subject`` of the form ``maker/model#serial``
    (a machine key), so the evidence filed under a unit cannot rest on a recorder
    attached to another.

    ``result`` lets a caller seal a verification it already ran. It must be the
    verification of *these* inputs: a result for another trace or envelope, or one
    claiming a tier its inputs cannot support, is refused rather than sealed under
    a trace it says nothing about.
    """
    serial = machine_serial or _serial_of(subject)
    res = result if result is not None else verify(
        envelope, trace, limits=limits, limits_reviews=limits_reviews,
        review_trust=review_trust, recorder_attestations=recorder_attestations,
        recorder_trust=recorder_trust, machine_serial=serial)
    if result is not None:
        _refuse_foreign_result(result, envelope, trace, recorder_attestations,
                               recorder_trust, serial)

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
    validated, no validated tier can rest on a provenance the filer merely declared, a certified tier cannot come from a file, a tier cannot exceed the
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
    if tier is AssuranceTier.VALIDATED and not provenance_lifts_tier(body):
        basis = body.get("provenance_basis")
        problems.append(
            f"the bundle records tier 'validated' on a trace whose provenance "
            f"{provenance!r} is "
            + (f"only {basis!r}" if isinstance(basis, str)
               else "recorded with no provenance_basis (an engine 4 or earlier bundle)")
            + ". A provenance the filer declared cannot lift the tier, and the bundle "
            "records no recorder attestation that a checker could re-assess. (Bundles "
            "from engine 4 or earlier, which let a declared 'bench' or 'field' reach "
            "'validated', are rejected here for the same reason.)")
    if body.get("provenance_basis") == _ATTESTED:
        problems.extend(_attested_claim_problems(body))
    if len(problems) == tier_problems:
        verified.append(
            f"the recorded tier {tier_name!r} is one the engine can produce from the "
            f"recorded provenance {provenance!r} (not 'certified', not above that "
            "provenance's ceiling)")

    review = body.get("limits_review")
    pfl_check = next((c for c in checks if isinstance(c, dict)
                      and c.get("name") == "pfl_contact"), None)
    if (tier is AssuranceTier.VALIDATED and body.get("limits_hash") and pfl_check
            and pfl_check.get("outcome") == "verified"
            and not _review_accepted(body)):
        problems.append(
            "the bundle records tier 'validated' on a contact check against a limits "
            "table, but records no accepted independent review of that table. A "
            "table's own verified_by text does not earn a validated tier. (Bundles "
            "from engine 3 or earlier, which let that text lift the tier, are rejected "
            "here for the same reason.)")
    elif _review_accepted(body):
        accepted = review.get("accepted_review") if isinstance(review, dict) else None
        if not (isinstance(accepted, dict)
                and accepted.get("table_hash") == body.get("limits_hash")):
            problems.append("the bundle records an accepted limits review that does "
                            "not name the limits table it records.")

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
        for key in ("verdict", "tier", "provenance", "provenance_basis", "envelope_hash",
                    "trace_hash", "trace_id", "product", "product_version",
                    "engine_version"):
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
    #: The provenance basis the bundle RECORDS (``declared_by_filer`` or
    #: ``recorder_attested``). A claim, never evidence of itself.
    provenance_basis: str = ""
    #: What THIS check made of that claim: ``not_applicable`` (declared by the filer),
    #: ``reproduced`` (the recorded attestation is accepted under the trust list the
    #: checker supplied), ``unverifiable`` (the bundle claims an attestation and no
    #: trust list was supplied, so it is NOT believed) or ``not_reproduced`` (rejected).
    provenance_reassessed: str = "not_applicable"
    #: The tier this check believes: the recorded tier, capped at ``community`` unless
    #: the recorder attestation was reproduced under the checker's own trust list.
    #: (The limits review is reported separately.)
    believed_tier: str = ""

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
    review_trust: ReviewTrust | None = None,
    recorder_trust: RecorderTrust | None = None,
    machine_serial: str | None = None,
    as_of: datetime | None = None,
) -> BundleCheck:
    """:func:`verify_bundle` with the full answer: ``level`` and what ran.

    ``as_of`` is the moment the *verifier* judges a limits review's or a recorder
    attestation's expiry against (default: now). The date a bundle records for itself is
    never used: a sealed claim about when it was assessed could be set to a day the
    evidence was still valid. ``recorder_trust`` is the checker's OWN list of recorder
    keys; a list found inside a bundle is ignored.
    """
    path = Path(bundle_path)
    if path.stat().st_size > MAX_FILE_BYTES:
        return _rejected(f"{path.name} is larger than the {MAX_FILE_BYTES} bytes this "
                         "checker will read.")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        return _rejected(f"the file is not readable JSON: {exc}")
    return check_bundle_data(raw, envelope=envelope, trace=trace, limits=limits,
                             review_trust=review_trust, recorder_trust=recorder_trust,
                             machine_serial=machine_serial, as_of=as_of)


def verify_bundle(
    bundle_path: str | Path,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
    review_trust: ReviewTrust | None = None,
    recorder_trust: RecorderTrust | None = None,
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
    result = check_bundle(bundle_path, envelope=envelope, trace=trace, limits=limits,
                          review_trust=review_trust, recorder_trust=recorder_trust)
    return result.ok, result.notes


def verify_bundle_data(
    raw: Any,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
    recorder_trust: RecorderTrust | None = None,
) -> tuple[bool, list[str]]:
    """:func:`verify_bundle` for a bundle already parsed, so nothing is written to disk."""
    result = check_bundle_data(raw, envelope=envelope, trace=trace, limits=limits,
                               recorder_trust=recorder_trust)
    return result.ok, result.notes


def check_bundle_data(
    raw: Any,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
    limits: LimitsTable | None = None,
    review_trust: ReviewTrust | None = None,
    recorder_trust: RecorderTrust | None = None,
    machine_serial: str | None = None,
    as_of: datetime | None = None,
) -> BundleCheck:
    """The one implementation: library, CLI and HTTP routes all end up here.

    ``recorder_trust`` is the CHECKER's own recorder trust list. A bundle that records
    ``provenance_basis: recorder_attested`` is believed only if the attestations it
    carries are accepted under that list (``BundleCheck.provenance_reassessed``); with
    none supplied the claim is reported as unverifiable and the tier believed is capped
    at ``community``. ``machine_serial`` is the unit the checker says the bundle is
    about; default: the one the bundle records.
    """
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
    claims_attested = body.get("provenance_basis") == _ATTESTED
    attested_coherent = claims_attested and not _attested_claim_problems(body)
    assessment_rec = body.get("provenance_assessment")
    recorded_attestation_hash = (
        str(assessment_rec.get("attestation_hash", ""))
        if isinstance(assessment_rec, dict) else "")
    recorder_state = "not_applicable"
    if claims_attested:
        recorder_state = "unverifiable" if recorder_trust is None else "not_reproduced"
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
        elif _review_accepted(body) and review_trust is None:
            limitations.insert(0, (
                "NOT CHECKED: the bundle's validated tier rests on a signed review of "
                "the limits table, and no reviewer trust list was supplied, so the "
                "re-run was not performed and the review was not assessed. Supply "
                "--limits-trust with keys you obtained independently of this bundle."
            ))
        elif claims_attested and recorder_trust is None:
            pass        # the recorder limitation below says why nothing was re-run
        elif recorded_limits and limits is None:
            limitations.insert(0, (
                "NOT CHECKED: the bundle was produced against a body-region limits "
                f"table ({recorded_limits[:12]}) that was not supplied, so the "
                "re-run was not performed. Supply it with --limits."
            ))
        else:
            serial = machine_serial if machine_serial is not None else str(
                body.get("machine_serial") or "")
            try:
                replay = verify(
                    envelope, trace, limits=limits,
                    limits_reviews=_recorded_reviews(body), review_trust=review_trust,
                    recorder_attestations=_recorded_attestations(body),
                    recorder_trust=recorder_trust, machine_serial=serial, now=as_of)
            except AssuranceError as exc:
                problems.append(f"re-running the engine on the supplied inputs failed: "
                                f"{exc}")
            else:
                replayed = True
                replay_problems = _replay_differences(
                    replay, evidence, envelope, trace, limits)
                problems.extend(replay_problems)
                replay_assessment = replay.provenance_assessment or {}
                if (claims_attested and replay.provenance_basis == _ATTESTED
                        and replay_assessment.get("attestation_hash")
                        == recorded_attestation_hash):
                    recorder_state = "reproduced"

    if (claims_attested and recorder_trust is not None and not replayed
            and attested_coherent and not problems):
        # No original trace to re-run, but the attestation can still be re-assessed from
        # the bundle's own description of the trace, under the CHECKER's trust list.
        reassessed = reassess_recorded_attestations(body, recorder_trust, now=as_of,
                                        machine_serial=machine_serial)
        if (reassessed is not None and reassessed.attested
                and reassessed.attestation_hash == recorded_attestation_hash):
            recorder_state = "reproduced"
            verified.append(
                "the recorded recorder attestation is accepted under the recorder trust "
                f"list you supplied (key {reassessed.key_fingerprint}); the recording "
                "window was not compared because the original trace was not supplied "
                "(the trace hash it signs was)")
        else:
            problems.append(
                "the bundle records provenance_basis 'recorder_attested', but the "
                "attestation it carries is not accepted under the recorder trust list "
                "you supplied ("
                + (reassessed.status.value if reassessed is not None else "unreadable")
                + "): its provenance is only declared by the filer, and the tier it "
                "records above 'community' is not believed.")
    if recorder_state == "unverifiable":
        limitations.append(
            "NOT CHECKED: the bundle records provenance_basis 'recorder_attested' (a "
            "signed recorder attestation) and no recorder trust list was supplied, so "
            "the attestation was not assessed and the re-run was not performed. It is "
            "NOT believed: for this check the trace's provenance is treated as declared "
            "by the filer and the tier as capped at community. Supply --recorder-trust "
            "with keys you obtained independently of this bundle.")
    if claims_attested and not attested_coherent:
        recorder_state = "not_reproduced"
    elif (claims_attested and recorder_state == "not_reproduced"
          and recorder_trust is not None and not problems):
        problems.append(
            "re-running with the recorder trust list you supplied does not reproduce "
            "provenance_basis 'recorder_attested' for the attestation the bundle records.")

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
    tier_name = str(body.get("tier"))
    recorded_tier = _TIERS.get(tier_name)
    believed = tier_name
    if (recorded_tier is not None and recorded_tier > AssuranceTier.COMMUNITY
            and recorder_state != "reproduced"):
        believed = AssuranceTier.COMMUNITY.value
    return BundleCheck(
        ok=ok, level=level, problems=tuple(problems), limitations=tuple(limitations),
        verified=tuple(verified) if ok else (),
        seal_intact=seal_intact,
        internally_consistent=not coherence,
        replayed=replayed,
        provenance_basis=str(body.get("provenance_basis") or ""),
        provenance_reassessed=recorder_state,
        believed_tier=believed)


def _recorded_reviews(body: dict[str, Any]) -> list[Any]:
    rec = body.get("limits_review")
    reviews = rec.get("reviews") if isinstance(rec, dict) else None
    return list(reviews) if isinstance(reviews, list) else []


def _review_accepted(body: dict[str, Any]) -> bool:
    rec = body.get("limits_review")
    return isinstance(rec, dict) and rec.get("status") == "accepted"


_ATTESTED = "recorder_attested"
#: The first engine whose sealed body can carry a recorder attestation. Earlier engines
#: could not have verified one, so a body that claims it is lying about its engine.
_FIRST_ENGINE_WITH_ATTESTATION = 6


def _engine_number(body: dict[str, Any]) -> int:
    try:
        return int(str(body.get("engine_version", "")).strip())
    except ValueError:
        return 0


def _recorded_attestations(body: dict[str, Any]) -> list[Any]:
    rec = body.get("recorder_attestation")
    items = rec.get("attestations") if isinstance(rec, dict) else None
    return list(items) if isinstance(items, list) else []


def _attested_claim_problems(body: dict[str, Any]) -> list[str]:
    """Does a sealed ``recorder_attested`` claim hang together? No trust is involved.

    This cannot show the claim is *true* (that needs the verifier's trust list); it
    shows the bundle contains what a true claim would: an accepted attestation that is
    among the recorded ones, names this bundle's trace, product and version, and is the
    one the sealed provenance assessment cites.
    """
    out: list[str] = []
    if _engine_number(body) < _FIRST_ENGINE_WITH_ATTESTATION:
        return [f"the bundle records provenance_basis {_ATTESTED!r} but names engine "
                f"{body.get('engine_version')!r}; engines before "
                f"{_FIRST_ENGINE_WITH_ATTESTATION} could not verify a recorder "
                "attestation, so this basis cannot be genuine."]
    if body.get("provenance") not in ("bench", "field"):
        out.append(f"the bundle records {_ATTESTED!r} for provenance "
                   f"{body.get('provenance')!r}; only bench and field recordings can be "
                   "attested.")
    rec = body.get("recorder_attestation")
    if not isinstance(rec, dict) or rec.get("status") != "accepted":
        return [*out, f"the bundle records provenance_basis {_ATTESTED!r} with no accepted "
                "recorder attestation assessment behind it."]
    try:
        accepted = RecorderAttestation.from_dict(rec.get("accepted_attestation"))
    except RecorderAttestationError as exc:
        return [*out, f"the accepted recorder attestation in the bundle cannot be read: {exc}"]
    if accepted.to_dict() not in _recorded_attestations(body):
        out.append("the accepted recorder attestation is not among the attestations the "
                   "bundle records.")
    pa = body.get("provenance_assessment")
    ahash = accepted.content_hash()
    if not (isinstance(pa, dict) and pa.get("basis") == _ATTESTED
            and pa.get("attestation_hash") == ahash
            and pa.get("key_fingerprint") == accepted.key_fingerprint):
        out.append("the sealed provenance assessment does not cite the accepted "
                   "attestation (hash and key fingerprint).")
    if rec.get("attestation_hash") != ahash or rec.get("key_fingerprint") != \
            accepted.key_fingerprint:
        out.append("the recorder attestation assessment does not agree with the "
                   "attestation it accepted.")
    for label, signed, recorded in (
            ("trace hash", accepted.trace_hash, body.get("trace_hash")),
            ("trace id", accepted.trace_id, body.get("trace_id")),
            ("provenance", accepted.provenance, body.get("provenance")),
            ("trace start", accepted.started_at, body.get("trace_started_at")),
            ("product", accepted.product, body.get("product")),
            ("product version", accepted.product_version, body.get("product_version"))):
        if signed != recorded:
            out.append(f"the accepted recorder attestation names {label} {signed!r}; the "
                       f"bundle records {recorded!r}.")
    if rec.get("trace_hash") != body.get("trace_hash"):
        out.append("the recorder attestation assessment is about a different trace than "
                   "the bundle records.")
    return out


def provenance_lifts_tier(body: dict[str, Any]) -> bool:
    """May a sealed ``validated`` tier rest on this body's provenance? (Coherence only.)

    Only a ``recorder_attested`` basis can, and only if the body also contains a
    coherent accepted attestation (:func:`_attested_claim_problems`). This is *not*
    belief: whether the attestation is genuine is decided by the checker re-assessing it
    under its own trust list (:func:`_recorder_state`). A body that merely says
    ``recorder_attested`` lifts nothing.
    """
    basis = body.get("provenance_basis")
    return (isinstance(basis, str) and basis in provenance_trust.LIFTING_BASES
            and not _attested_claim_problems(body))


def reassess_recorded_attestations(
    body: dict[str, Any], trust: RecorderTrust | None, *, now: datetime | None,
    machine_serial: str | None,
) -> Any:
    """Re-assess the attestations a bundle records, from the bundle alone (no trace bytes).

    The recording window cannot be compared without the trace, but the trace hash the
    attestation signs is compared with the bundle's, and that hash covers the window.
    """
    facts = RecordingFacts.from_bundle_body(body)
    if facts is None:
        return None
    serial = machine_serial if machine_serial is not None else str(
        body.get("machine_serial") or "")
    ref = MachineRef(str(body.get("product")), str(body.get("product_version")), serial)
    return assess_recorder_attestation(
        facts, _recorded_attestations(body), trust, machine_ref=ref, now=now)


def _without_assessed_on(body: dict[str, Any]) -> dict[str, Any]:
    """The body minus what is shown but never compared or trusted on replay.

    The day an assessment was made (a sealed claim about it could name a day the
    evidence was still valid), whether a trust list was present, and the per-finding
    prose, none of which is a fact about the evidence.
    """
    out = body
    rec = body.get("limits_review")
    if isinstance(rec, dict):
        out = {**out, "limits_review": {k: v for k, v in rec.items() if k != "assessed_on"}}
    att = body.get("recorder_attestation")
    if isinstance(att, dict):
        trimmed = {k: v for k, v in att.items()
                   if k not in ("assessed_on", "trust_configured")}
        findings = trimmed.get("findings")
        if isinstance(findings, list):
            trimmed["findings"] = [
                {k: v for k, v in f.items() if k != "detail"} if isinstance(f, dict) else f
                for f in findings]
        out = {**out, "recorder_attestation": trimmed}
    return out


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
    expected = _without_assessed_on(expected)
    body = _without_assessed_on(body)
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
