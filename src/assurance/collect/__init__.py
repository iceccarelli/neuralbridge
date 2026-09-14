"""Getting a real machine's software into the system.

Everything else in this package assumes a manifest exists. This is how one comes
to exist without anybody typing JSON.

    plan         what to look for, where, and how to hash it — once per machine type
    normalise    hashing a vendor export without the export's own noise
    collector    run the plan against a folder of exports, produce the manifest
    volatility   prove the rules work before trusting the reports they produce

The normalisation rules are the hard part and the defensible one. A vendor
export that stamps itself with the time and the operator is not byte-stable, and
a tool that hashes it as-is reports drift on every machine every week until its
customer stops reading the report.
"""

from assurance.collect.collector import (
    CollectionError,
    CollectionResult,
    ItemOutcome,
    collect,
)
from assurance.collect.normalise import (
    NormalisationResult,
    Normaliser,
    Rule,
    normalise_file,
)
from assurance.collect.plan import CollectionPlan, ItemSpec, PlanError, VersionSource
from assurance.collect.volatility import ItemVolatility, VolatilityReport, probe

__all__ = [
    "CollectionError",
    "CollectionPlan",
    "CollectionResult",
    "ItemOutcome",
    "ItemSpec",
    "ItemVolatility",
    "NormalisationResult",
    "Normaliser",
    "PlanError",
    "Rule",
    "VersionSource",
    "VolatilityReport",
    "collect",
    "normalise_file",
    "probe",
]
