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
from assurance.machine.envelope import SafetyEnvelope
from assurance.machine.limits import LimitsTable
from assurance.machine.trace import MAX_FILE_BYTES, Trace
from assurance.machine.verify import ENGINE_VERSION, Verdict, VerificationResult, verify

__all__ = [
    "BUNDLE_KIND",
    "BundleError",
    "EvidenceBundle",
    "build_bundle",
    "verify_bundle",
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

    state = {
        Verdict.PASS: ValidationState.VERIFIED,
        Verdict.FAIL: ValidationState.REFUTED,
        Verdict.INCOMPLETE: ValidationState.INDETERMINATE,
    }[res.verdict]

    confidence = Confidence.HIGH if (
        res.verdict is Verdict.PASS and res.tier.may_claim_physical_behaviour
    ) else Confidence.MEDIUM if res.verdict is Verdict.PASS else Confidence.LOW

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


def _coherence_problems(
    evidence: Evidence, raw: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Whether the claim hangs together, without the original inputs.

    The seal is a content hash, not a signature: anyone with this package can
    edit a bundle and recompute it. So the checks here ask whether what the
    bundle says about itself is *possible* — a simulated trace cannot be
    validated, a certified tier cannot come from a file, a violated check must
    list its violations, the printed result must repeat the sealed one — and
    return ``(problems, limitations)``.
    """
    problems: list[str] = []
    limits: list[str] = []
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

    tier_name = body.get("tier")
    provenance = body.get("provenance")
    tier = _TIERS.get(str(tier_name))
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

    printed_env = raw.get("envelope")
    if printed_env is None:
        limits.append("NOT CHECKED: the file carries no envelope beside the seal.")
    else:
        try:
            printed_hash = SafetyEnvelope.from_dict(printed_env).content_hash()
        except (AssuranceError, KeyError, TypeError, ValueError, AttributeError) as exc:
            problems.append(f"the envelope printed in the bundle cannot be read: {exc}")
        else:
            if printed_hash != body.get("envelope_hash"):
                problems.append(
                    "the envelope printed in the bundle is not the one the sealed "
                    f"evidence names (printed {printed_hash[:12]}, sealed "
                    f"{str(body.get('envelope_hash'))[:12]}). It was edited."
                )
    return problems, limits


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
       with the bundle's own checks, a simulation does not hold a validated
       tier, no file holds a certified one, and the envelope and result printed
       beside the seal repeat what the seal says. A content hash can be
       recomputed by anyone, so this is what stops a re-sealed edit.
    3. If the original ``envelope`` and ``trace`` (and ``limits``, if the bundle
       used a table) are supplied, their content hashes match the ones the bundle
       names, and re-running the engine reproduces every check, the verdict, the
       tier and the stated limitations. This is the check an auditor runs.

    Supplying neither envelope nor trace is allowed and is reported as a stated
    limitation, not a pass: integrity alone does not make a claim true. A file
    that cannot be read is reported as a problem; this never raises on content.
    """
    problems: list[str] = []
    limitations: list[str] = []
    path = Path(bundle_path)

    if path.stat().st_size > MAX_FILE_BYTES:
        return False, [f"{path.name} is larger than the {MAX_FILE_BYTES} bytes this "
                       "checker will read."]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        return False, [f"the file is not readable JSON: {exc}"]

    if not isinstance(raw, dict):
        return False, [f"the file holds a JSON {type(raw).__name__}, not a bundle object."]

    if raw.get("schema") != BUNDLE_SCHEMA:
        problems.append(
            f"bundle schema is {raw.get('schema')!r}, expected {BUNDLE_SCHEMA!r}."
        )
        return False, problems

    try:
        evidence = Evidence.from_dict(raw["evidence"])
    except Exception as exc:  # noqa: BLE001 - report, do not raise, to a verifier
        problems.append(f"the sealed evidence object could not be read: {exc!r}")
        return False, problems

    if not isinstance(evidence.body, dict):
        return False, ["the sealed evidence body is not an object."]

    if not evidence.verify():
        problems.append(
            f"the evidence does not hash to the value it carries "
            f"({evidence.content_hash[:16]}). The bundle was edited after sealing."
        )

    body = evidence.body
    coherence, coherence_limits = _coherence_problems(evidence, raw)
    problems.extend(coherence)
    limitations.extend(coherence_limits)

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
                problems.extend(_replay_differences(replay, evidence))

    return not problems, problems + limitations


def _replay_differences(replay: VerificationResult, evidence: Evidence) -> list[str]:
    body = evidence.body
    out: list[str] = []
    if replay.verdict.value != body.get("verdict"):
        out.append(
            f"re-running the engine on the supplied inputs gives verdict "
            f"{replay.verdict.value!r}, not the recorded {body.get('verdict')!r}."
        )
    if replay.tier.value != body.get("tier"):
        out.append(
            f"re-running gives tier {replay.tier.value!r}, not the recorded "
            f"{body.get('tier')!r}."
        )
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
    return out


def bundle_digest(bundle: EvidenceBundle) -> str:
    """A short, stable identifier to print on a report or a label."""
    return content_hash_of({
        "bundle": bundle.content_hash,
        "product": bundle.envelope.product,
        "version": bundle.envelope.product_version,
    })[:16]
