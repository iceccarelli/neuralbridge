"""Machinery Regulation Annex III 1.1.9: what software is on the machine, who changed it.

Machinery Regulation (EU) 2023/1230 applies from 20 January 2027. Annex III
1.1.9 requires a machine to identify its safety-relevant software and to record
evidence of intervention in it.

    manifest      what is on the machine, with the provenance of every hash
    divergence    whether it still matches the configuration it was signed off with
    intervention  who changed what, who authorised it, what was re-run
    staleness     which safety functions are still covered by valid evidence
    record        sealing all of it into the ledger, and the machine passport

The join in :mod:`~assurance.machinery.staleness` is the part nobody else has:
a firmware change recorded here invalidates, by name and by date, the
:mod:`assurance.machine` verification that preceded it.
"""

from assurance.machinery.divergence import (
    Change,
    ChangeKind,
    Divergence,
    Severity,
    compare,
)
from assurance.machinery.intervention import (
    Authorization,
    Intervention,
    InterventionKind,
    Revalidation,
)
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
)
from assurance.machinery.record import (
    DIVERGENCE_KIND,
    INTERVENTION_KIND,
    MANIFEST_KIND,
    PASSPORT_KIND,
    MachinePassport,
    build_passport,
    interventions_from_ledger,
    manifests_from_ledger,
    record_divergence,
    record_intervention,
    record_manifest,
    verify_passport,
)
from assurance.machinery.staleness import (
    Coverage,
    CoverageReport,
    FunctionCoverage,
    VerificationRecord,
    assess_coverage,
)

__all__ = [
    "DIVERGENCE_KIND",
    "INTERVENTION_KIND",
    "MANIFEST_KIND",
    "PASSPORT_KIND",
    "Authorization",
    "Change",
    "ChangeKind",
    "Coverage",
    "CoverageReport",
    "Divergence",
    "FunctionCoverage",
    "HashSource",
    "Intervention",
    "InterventionKind",
    "ItemKind",
    "MachineIdentity",
    "MachinePassport",
    "ManifestSource",
    "Revalidation",
    "SafetyFunction",
    "SafetyItem",
    "SafetyManifest",
    "Severity",
    "VerificationRecord",
    "assess_coverage",
    "build_passport",
    "compare",
    "interventions_from_ledger",
    "manifests_from_ledger",
    "record_divergence",
    "record_intervention",
    "record_manifest",
    "verify_passport",
]
