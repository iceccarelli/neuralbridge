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
               case from an engine's output; claim, advance, reverify,
               resolve_decision, decide, resume — move a case through its
               lifecycle (decide/resume/resolve need a named person)
    replay     reconstruct_case — rebuild a case from the ledger alone and
               check every step was legal
    store      CaseStore — the ledger-backed persistence
    model      ChangeAssuranceCase, CaseStatus, TriggerType
"""

from assurance.change.model import CaseStatus, ChangeAssuranceCase, TriggerType
from assurance.change.replay import CaseReplay, reconstruct_case
from assurance.change.service import (
    CaseNotFoundError,
    CaseTransitionError,
    UnknownInterventionError,
    advance,
    assess_advisory,
    assess_drift,
    assess_intervention,
    assess_recorded_intervention,
    case_id_for,
    claim,
    decide,
    note_advisory_withdrawn,
    resolve_decision,
    resume,
    reverify,
    waive_reverification,
)
from assurance.change.store import CaseConflictError, CaseStore, CaseStoreError

__all__ = [
    "CaseReplay",
    "CaseStatus",
    "CaseStore",
    "CaseConflictError",
    "CaseNotFoundError",
    "CaseStoreError",
    "CaseTransitionError",
    "ChangeAssuranceCase",
    "TriggerType",
    "UnknownInterventionError",
    "advance",
    "assess_advisory",
    "assess_drift",
    "assess_intervention",
    "assess_recorded_intervention",
    "case_id_for",
    "claim",
    "decide",
    "note_advisory_withdrawn",
    "reconstruct_case",
    "resolve_decision",
    "resume",
    "reverify",
    "waive_reverification",
]
