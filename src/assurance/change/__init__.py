"""Continuous Machine Change Assurance.

CHANGE -> IMPACT -> REQUIRED ACTION -> RE-VERIFICATION -> HUMAN DECISION ->
EVIDENCE-BACKED CLOSURE.

This package adds no new fact about a machine. Every fact a
``ChangeAssuranceCase`` carries is produced by an engine that already
existed — :mod:`assurance.machinery.divergence`,
:mod:`assurance.machinery.staleness`, :mod:`assurance.fleet.impact`,
:mod:`assurance.machinery.intervention` — and kept the way everything else in
this product is kept, in the same hash-chained ledger. What this package adds
is the thing none of those engines were ever asked to be: a queue a person can
work from, with a status that never claims more than the evidence does.

    service    assess_drift, assess_advisory, assess_intervention — build a
               case from an engine's output; claim, advance, reverify, decide
               — move an open case through its lifecycle
    store      CaseStore — the ledger-backed persistence
    model      ChangeAssuranceCase, CaseStatus, TriggerType
"""

from assurance.change.model import CaseStatus, ChangeAssuranceCase, TriggerType
from assurance.change.service import (
    CaseTransitionError,
    advance,
    assess_advisory,
    assess_drift,
    assess_intervention,
    claim,
    decide,
    reverify,
)
from assurance.change.store import CaseStore, CaseStoreError

__all__ = [
    "CaseStatus",
    "CaseStore",
    "CaseStoreError",
    "CaseTransitionError",
    "ChangeAssuranceCase",
    "TriggerType",
    "advance",
    "assess_advisory",
    "assess_drift",
    "assess_intervention",
    "claim",
    "decide",
    "reverify",
]
