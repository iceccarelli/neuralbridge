"""Across machines: the fleet, component advisories, and the declaration.

:mod:`assurance.machine` answers for one run. :mod:`assurance.machinery` answers
for one machine. This package answers for everything an integrator is on the
hook for at once.

    registry     every machine in the ledger, worst first
    advisory     a supplier's statement that a component version is affected
    impact       that advisory fanned out to serial numbers and safety functions
    declaration  the Declaration of Conformity, bound to a configuration hash

The advisory fan-out is the part that gets more valuable with every machine
enrolled, and the part nobody else can build: it needs the manifest fleet, the
item→function→check map, and a coverage position, and those only exist together
here.
"""

from assurance.fleet.advisory import (
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    MatchBasis,
    match_item,
)
from assurance.fleet.declaration import (
    DeclarationOfConformity,
    DeclarationStatus,
    DeclarationVerdict,
    check_declaration,
)
from assurance.fleet.impact import (
    Exposure,
    FunctionExposure,
    ImpactReport,
    assess_impact,
)
from assurance.fleet.registry import Fleet, FleetSummary, MachineRecord

__all__ = [
    "AdvisorySeverity",
    "AffectedArtefact",
    "ComponentAdvisory",
    "DeclarationOfConformity",
    "DeclarationStatus",
    "DeclarationVerdict",
    "Exposure",
    "Fleet",
    "FleetSummary",
    "FunctionExposure",
    "ImpactReport",
    "MachineRecord",
    "MatchBasis",
    "assess_impact",
    "check_declaration",
    "match_item",
]
