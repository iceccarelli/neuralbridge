"""Machine safety verification: does the cell do what its manufacturer declared?

The regulatory work in :mod:`assurance.security` answers a question about
paperwork. This package answers the question underneath it: on this run, did
this machine stay inside the envelope its manufacturer sold it on?

    envelope   what the manufacturer declared, with the provenance of every figure
    trace      what the machine actually did, with the provenance of the recording
    verify     the comparison, with margins and with what was not checked
    bundle     the sealed, independently re-checkable result

The output is not a score. It is a bundle a third party can re-run, whose tier
is computed from the weakest input rather than asserted by whoever ran it.
"""

from assurance.machine.bundle import (
    BUNDLE_KIND,
    EvidenceBundle,
    build_bundle,
    verify_bundle,
)
from assurance.machine.envelope import (
    FigureBasis,
    SafetyEnvelope,
    SensingUncertainty,
    StopPerformance,
    Workspace,
)
from assurance.machine.limits import BodyRegionLimit, LimitsTable
from assurance.machine.ssm import SeparationBreakdown, separation_required
from assurance.machine.trace import OperatingMode, Provenance, Sample, Trace
from assurance.machine.verify import (
    CheckOutcome,
    CheckResult,
    Verdict,
    VerificationResult,
    Violation,
    verify,
)

__all__ = [
    "BUNDLE_KIND",
    "BodyRegionLimit",
    "CheckOutcome",
    "CheckResult",
    "EvidenceBundle",
    "FigureBasis",
    "LimitsTable",
    "OperatingMode",
    "Provenance",
    "SafetyEnvelope",
    "Sample",
    "SensingUncertainty",
    "SeparationBreakdown",
    "StopPerformance",
    "Trace",
    "Verdict",
    "VerificationResult",
    "Violation",
    "Workspace",
    "build_bundle",
    "separation_required",
    "verify",
    "verify_bundle",
]
