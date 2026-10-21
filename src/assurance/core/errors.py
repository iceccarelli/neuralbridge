"""Failure modes that must never be swallowed.

An assurance system that degrades quietly is worse than no assurance system,
because it produces confident-looking artifacts that are wrong. Every error
here is raised, never logged-and-continued.
"""

from __future__ import annotations


class AssuranceError(Exception):
    """Base class. Catching this catches everything this package refuses to do."""


class SealedObjectError(AssuranceError):
    """An attempt to mutate an evidence object after it was sealed."""


class LedgerIntegrityError(AssuranceError):
    """The evidence chain does not verify.

    Raised on read, not on write, because the useful moment is when somebody
    asks whether the record can be trusted.
    """


class LedgerConflictError(AssuranceError):
    """An append was refused because the ledger moved since the caller read it.

    Deliberately **not** a :class:`LedgerIntegrityError`: the chain is fine. It is
    the compare-and-swap of a read-modify-append that lost its race. Nothing was
    written; the caller re-reads and decides again.
    """


class EvidenceIncompleteError(AssuranceError):
    """A required field is absent and no defensible default exists.

    Deliberately not a validation *warning*. A submission built from a guess is
    the failure mode this whole package exists to prevent.
    """


class ClockError(AssuranceError):
    """A deadline was asked for before the fact it runs from was established."""
