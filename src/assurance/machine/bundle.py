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
from assurance.machine.trace import Trace
from assurance.machine.verify import Verdict, VerificationResult, verify

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
    """
    res = result if result is not None else verify(envelope, trace, limits=limits)

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


def verify_bundle(
    bundle_path: str | Path,
    *,
    envelope: SafetyEnvelope | None = None,
    trace: Trace | None = None,
) -> tuple[bool, list[str]]:
    """Check a bundle without trusting whoever produced it.

    Returns ``(ok, problems)``. Three separate things are checked, and the
    caller is told which failed:

    1. The sealed evidence hashes to the hash it carries. A bundle whose body
       was edited after sealing fails here.
    2. The bundle's own recorded verdict agrees with its check outcomes. A
       bundle whose verdict was hand-written to ``pass`` fails here.
    3. If the original ``envelope`` and ``trace`` are supplied, their content
       hashes match the ones the bundle names, and re-running the engine
       reproduces the same verdict and tier. This is the check an auditor runs.

    Supplying neither envelope nor trace is allowed and is reported as a stated
    limitation, not a pass: integrity alone does not make a claim true.
    """
    problems: list[str] = []
    raw = json.loads(Path(bundle_path).read_text(encoding="utf-8"))

    if raw.get("schema") != BUNDLE_SCHEMA:
        problems.append(
            f"bundle schema is {raw.get('schema')!r}, expected {BUNDLE_SCHEMA!r}."
        )
        return False, problems

    try:
        evidence = Evidence.from_dict(raw["evidence"])
    except Exception as exc:  # noqa: BLE001 - report, do not raise, to a verifier
        problems.append(f"the sealed evidence object could not be read: {exc}")
        return False, problems

    if not evidence.verify():
        problems.append(
            f"the evidence does not hash to the value it carries "
            f"({evidence.content_hash[:16]}). The bundle was edited after sealing."
        )

    body = evidence.body
    checks = body.get("checks") or []
    violated = [c for c in checks if c.get("outcome") == "violated"]
    unchecked = [c for c in checks if c.get("outcome") == "unchecked"]
    implied = ("fail" if violated else "incomplete" if unchecked else "pass")
    if body.get("verdict") != implied:
        problems.append(
            f"the bundle records verdict {body.get('verdict')!r} but its own checks "
            f"imply {implied!r} ({len(violated)} violated, {len(unchecked)} unchecked)."
        )

    if envelope is not None:
        if envelope.content_hash() != body.get("envelope_hash"):
            problems.append(
                "the supplied envelope is not the one this bundle was produced "
                f"against (bundle names {str(body.get('envelope_hash'))[:12]}, "
                f"supplied is {envelope.content_hash()[:12]})."
            )
    if trace is not None:
        if trace.content_hash() != body.get("trace_hash"):
            problems.append(
                "the supplied trace is not the one this bundle was produced against "
                f"(bundle names {str(body.get('trace_hash'))[:12]}, supplied is "
                f"{trace.content_hash()[:12]})."
            )

    if envelope is not None and trace is not None and not problems:
        replay = verify(envelope, trace)
        if replay.verdict.value != body.get("verdict"):
            problems.append(
                f"re-running the engine on the supplied inputs gives verdict "
                f"{replay.verdict.value!r}, not the recorded {body.get('verdict')!r}."
            )
        if replay.tier.value != body.get("tier"):
            problems.append(
                f"re-running gives tier {replay.tier.value!r}, not the recorded "
                f"{body.get('tier')!r}."
            )
    elif not problems:
        problems.append(
            "NOT CHECKED: the original envelope and trace were not supplied, so only "
            "the bundle's internal integrity was confirmed. Nothing here shows the "
            "machine behaved as the bundle says."
        )
        return True, problems

    return not problems, problems


def bundle_digest(bundle: EvidenceBundle) -> str:
    """A short, stable identifier to print on a report or a label."""
    return content_hash_of({
        "bundle": bundle.content_hash,
        "product": bundle.envelope.product,
        "version": bundle.envelope.product_version,
    })[:16]
