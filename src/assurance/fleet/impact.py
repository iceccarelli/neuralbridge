"""An advisory arrives. Which machines, which functions, which serial numbers?

This is the join the whole system was built to make.

A supplier publishes: *firmware 3.8.2 has a watchdog defect.* Today that lands
in an inbox and the integrator who carries the CE liability for forty cells has
no way to answer the only question that matters. The mailing list does not know
what is installed anywhere. The plant does not know what its cells are made of.
The supplier does not know who bought what.

The manifest fleet does. And because :mod:`assurance.machinery` already maps
item → safety function → verification check → coverage, an advisory does not
stop at *you have eleven affected machines*. It reaches all the way to:

    AR-7#0412  Plant 2, Line 4   confirmed by hash
        SF-01 was CURRENT, verified 9 February — now in question
        SF-02 was CURRENT, verified 9 February — now in question

A machine whose coverage was already stale is reported separately: an advisory
does not make it worse, and mixing the two would hide the machines that were
fine until this morning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from assurance.core.identity import format_utc, utc_now
from assurance.fleet.advisory import (
    AdvisorySeverity,
    ComponentAdvisory,
    MatchBasis,
    fold_text,
    match_item,
)
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import ManifestSource
from assurance.machinery.staleness import Coverage

__all__ = [
    "CLASSIFICATIONS",
    "Exposure",
    "FunctionExposure",
    "ImpactReport",
    "MachineClassification",
    "assess_impact",
]

#: What this advisory means for one machine, by the evidence it rests on. Never
#: flattened: a label match is not an artefact match, and a label that the
#: artefact contradicts is its own finding.
CLASSIFICATIONS = {
    MatchBasis.HASH: "match_by_hash",
    MatchBasis.HASH_MISMATCH: "contradictory_label_vs_hash",
    MatchBasis.VERSION: "match_by_version_only",
    MatchBasis.NAME_ONLY: "possible_match_name_only",
}
_STRENGTH = [MatchBasis.HASH, MatchBasis.HASH_MISMATCH, MatchBasis.VERSION,
             MatchBasis.NAME_ONLY]


@dataclass(frozen=True)
class MachineClassification:
    """One enrolled machine, classified against one advisory."""

    machine_key: str
    site: str
    #: ``match_by_hash`` | ``match_by_version_only`` | ``possible_match_name_only``
    #: | ``contradictory_label_vs_hash`` | ``unknown`` | ``no_match_found``
    classification: str
    basis: str
    uncertainty: str
    item_ids: tuple[str, ...] = ()
    #: Why this machine cannot be cleared (empty when nothing stands in the way).
    unknown_reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key, "site": self.site,
            "classification": self.classification, "basis": self.basis,
            "uncertainty": self.uncertainty, "item_ids": list(self.item_ids),
            "unknown_reasons": list(self.unknown_reasons),
        }


@dataclass(frozen=True)
class FunctionExposure:
    """One safety function on one machine, and what the advisory does to it."""

    function_id: str
    description: str
    coverage_before: Coverage
    #: True when this function had standing evidence that the advisory unsettles.
    newly_in_question: bool
    last_verified_at: str = ""
    last_verified_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "description": self.description,
            "coverage_before": self.coverage_before.value,
            "newly_in_question": self.newly_in_question,
            "last_verified_at": self.last_verified_at,
            "last_verified_hash": self.last_verified_hash,
        }


@dataclass(frozen=True)
class Exposure:
    """One machine, one item, one advisory."""

    machine_key: str
    site: str
    item_id: str
    item_name: str
    item_version: str
    basis: MatchBasis
    detail: str
    functions: tuple[FunctionExposure, ...]

    @property
    def confidence(self) -> str:
        return self.basis.confidence

    @property
    def needs_a_human(self) -> bool:
        return self.basis.needs_a_human

    @property
    def newly_in_question(self) -> tuple[FunctionExposure, ...]:
        return tuple(f for f in self.functions if f.newly_in_question)

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "site": self.site,
            "item_id": self.item_id,
            "item_name": self.item_name,
            "item_version": self.item_version,
            "basis": self.basis.value,
            "confidence": self.confidence,
            "needs_a_human": self.needs_a_human,
            "detail": self.detail,
            "functions": [f.to_dict() for f in self.functions],
            "newly_in_question": [f.function_id for f in self.newly_in_question],
        }


@dataclass(frozen=True)
class ImpactReport:
    """Everything one advisory means for one fleet."""

    advisory_id: str
    advisory_hash: str
    issued_by: str
    severity: AdvisorySeverity
    title: str
    reference: str
    assessed_at: str
    machines_in_fleet: int
    exposures: tuple[Exposure, ...]
    checks_skipped: tuple[str, ...]
    #: Whether the ledger the fleet was read from verified end to end. A fleet
    #: read from a chain that does not verify cannot support "nothing matched".
    chain_verified: bool = True
    #: Every enrolled machine, classified. See :class:`MachineClassification`.
    classifications: tuple[MachineClassification, ...] = ()
    #: Safety functions whose implementing item could be the subject of this
    #: advisory but cannot be excluded: ``{machine, function_id, item_id, reason}``.
    unknown_functions: tuple[dict[str, Any], ...] = ()
    #: Standing evidence that may no longer describe the machine.
    prior_evidence_in_question: tuple[dict[str, Any], ...] = ()
    #: Where the advisory came from and how far it was trusted (see
    #: ``assurance.supplier.trust``). Empty for an advisory handed over as a bare
    #: file, which is itself said in the summary.
    provenance: dict[str, Any] = field(default_factory=dict)

    @property
    def unknown_machines(self) -> tuple[str, ...]:
        return tuple(c.machine_key for c in self.classifications
                     if c.classification == "unknown")

    @property
    def clear_is_complete(self) -> bool:
        """A ``clear`` verdict that no unknown machine or function qualifies."""
        return (self.verdict == "clear" and not self.unknown_machines
                and not self.unknown_functions)

    @property
    def machines_affected(self) -> tuple[str, ...]:
        out: list[str] = []
        for e in self.exposures:
            if e.machine_key not in out:
                out.append(e.machine_key)
        return tuple(out)

    @property
    def confirmed(self) -> tuple[Exposure, ...]:
        return tuple(e for e in self.exposures if e.basis is MatchBasis.HASH)

    @property
    def contradictory(self) -> tuple[Exposure, ...]:
        """Machines whose label and artefact disagree with the supplier's own figures."""
        return tuple(e for e in self.exposures if e.basis is MatchBasis.HASH_MISMATCH)

    @property
    def needing_a_human(self) -> tuple[Exposure, ...]:
        return tuple(e for e in self.exposures if e.needs_a_human)

    @property
    def functions_newly_in_question(self) -> int:
        return sum(len(e.newly_in_question) for e in self.exposures)

    @property
    def verdict(self) -> str:
        """``clear`` | ``exposed`` | ``needs_review``.

        ``clear`` means the fleet was read from a ledger that verifies and no
        enrolled machine matches. If the chain does not verify, an empty list of
        matches is not evidence of anything — records may have been dropped — so
        the answer is ``needs_review``.
        """
        if not self.exposures:
            return "clear" if self.chain_verified else "needs_review"
        if any(e.newly_in_question for e in self.exposures):
            return "exposed"
        return "needs_review"

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "advisory_hash": self.advisory_hash,
            "issued_by": self.issued_by,
            "severity": self.severity.value,
            "title": self.title,
            "reference": self.reference,
            "assessed_at": self.assessed_at,
            "verdict": self.verdict,
            "machines_in_fleet": self.machines_in_fleet,
            "chain_verified": self.chain_verified,
            "machines_affected": list(self.machines_affected),
            "functions_newly_in_question": self.functions_newly_in_question,
            "exposures": [e.to_dict() for e in self.exposures],
            "checks_skipped": list(self.checks_skipped),
            "machine_classification": [c.to_dict() for c in self.classifications],
            "unknown_machines": list(self.unknown_machines),
            "unknown_functions": [dict(f) for f in self.unknown_functions],
            "prior_evidence_in_question": [dict(f) for f in self.prior_evidence_in_question],
            "clear_is_complete": self.clear_is_complete,
            "provenance": dict(self.provenance),
        }

    def summary(self) -> str:
        head = {
            "clear": "CLEAR — no machine in this fleet matches this advisory",
            "exposed": "EXPOSED — standing safety evidence is now in question",
            "needs_review": "NEEDS REVIEW — matches found, none with standing evidence",
        }[self.verdict]
        if self.verdict == "needs_review" and not self.exposures:
            head = ("NEEDS REVIEW — no match was found, but the ledger chain does not "
                    "verify, so the absence of a match is not evidence")
        lines = []
        if self.provenance.get("inspect_only"):
            lines.append(
                f"  !! INSPECT ONLY — trust state {self.provenance.get('trust_state')}: "
                "this advisory did not meet the trust policy, so nothing below may "
                "drive a stop-use or a case as a trusted supplier statement")
        elif self.provenance.get("trust_basis") == "manual_override":
            ov = self.provenance.get("override") or {}
            lines.append(f"  !! MANUAL OVERRIDE by {ov.get('actor', '?')}: "
                         f"{ov.get('reason', '')}")
        lines += [
            f"{self.advisory_id} ({self.issued_by}, {self.severity.value}) — {head}",
            f"  {self.title}",
            f"  {len(self.machines_affected)} of {self.machines_in_fleet} machine(s) "
            f"match; {self.functions_newly_in_question} safety function(s) newly in "
            "question",
        ]
        order = {"hash": 0, "hash_mismatch": 1, "version": 2, "name_only": 3}
        for e in sorted(self.exposures,
                        key=lambda e: (order[e.basis.value], e.machine_key)):
            lines.append("")
            lines.append(f"  {e.machine_key}   {e.site or '—'}   "
                         f"[{e.confidence}] {e.item_id} {e.item_version}")
            lines.append(f"      {e.detail}")
            for f in e.functions:
                if f.newly_in_question:
                    flag = "→ NOW IN QUESTION"
                elif e.basis is MatchBasis.HASH_MISMATCH:
                    # Neither column: we cannot say whether this machine is
                    # affected, so we must not say its evidence is fine either.
                    flag = (f"→ UNRESOLVED (coverage: "
                            f"{f.coverage_before.value.replace('_', ' ')})")
                else:
                    flag = (f"(coverage already "
                            f"{f.coverage_before.value.replace('_', ' ')})")
                when = (f", verified {f.last_verified_at[:10]}"
                        if f.last_verified_at else "")
                lines.append(f"      {f.function_id}  {f.description}{when}  {flag}")
        if self.unknown_machines or self.unknown_functions:
            lines.append("")
            lines.append(
                f"  UNKNOWN — {len(self.unknown_machines)} machine(s) and "
                f"{len(self.unknown_functions)} safety function(s) cannot be "
                "cleared by this assessment: "
                + ", ".join(self.unknown_machines[:8]))
        if self.prior_evidence_in_question:
            lines.append(
                f"  {len(self.prior_evidence_in_question)} piece(s) of prior "
                "verification may no longer describe the machine they were filed under")
        return "\n".join(lines)


def _candidate_unknown_items(
    advisory: ComponentAdvisory, record: Any, matched_ids: set[str],
) -> list[tuple[Any, str]]:
    """Items that could be this advisory's subject and cannot be ruled out.

    Only from the supplier the advisory names, or an item with no recorded
    supplier. An item whose artefact hash was not read from this machine cannot
    be compared to the supplier's published hashes, so a version label that does
    not appear on the list does not exclude it.
    """
    suppliers = {fold_text(a.supplier) for a in advisory.affected}
    out: list[tuple[Any, str]] = []
    for item in record.manifest.items:
        if item.item_id in matched_ids:
            continue
        sup = fold_text(item.supplier)
        if sup and sup not in suppliers:
            continue
        if not advisory.publishes_hashes:
            continue
        if item.content_hash and item.hash_source.describes_this_unit:
            continue
        reason = ("no artefact hash was recorded for it" if not item.content_hash
                  else f"its hash ({item.hash_source.value}) was not read from this machine")
        out.append((item, f"{reason}; the supplier published hashes, so this item "
                          "can be neither matched nor excluded"))
    return out


def assess_impact(
    advisory: ComponentAdvisory, fleet: Fleet, *,
    provenance: dict[str, Any] | None = None,
) -> ImpactReport:
    """Fan one advisory out across a fleet, all the way to safety functions."""
    exposures: list[Exposure] = []
    caveats: list[str] = []

    for record in fleet.records:
        for item in record.manifest.items:
            matched = match_item(advisory, item)
            if matched is None:
                continue
            basis, detail = matched

            functions: list[FunctionExposure] = []
            for fn in record.manifest.functions_of(item):
                cov = next((c for c in record.coverage.functions
                            if c.function_id == fn.function_id), None)
                before = cov.coverage if cov else Coverage.NEVER_VERIFIED
                functions.append(FunctionExposure(
                    function_id=fn.function_id,
                    description=fn.description,
                    coverage_before=before,
                    # An advisory only unsettles evidence that was standing.
                    # Something already stale is not made worse by it.
                    newly_in_question=(
                        before is Coverage.CURRENT
                        and advisory.severity.puts_functions_in_question
                        and basis is not MatchBasis.HASH_MISMATCH
                    ),
                    last_verified_at=cov.last_verified_at if cov else "",
                    last_verified_hash=cov.last_verified_hash if cov else "",
                ))

            exposures.append(Exposure(
                machine_key=record.machine_key,
                site=record.manifest.machine.site,
                item_id=item.item_id,
                item_name=item.name,
                item_version=item.version,
                basis=basis, detail=detail,
                functions=tuple(functions),
            ))

            if basis is MatchBasis.HASH_MISMATCH:
                caveats.append(
                    f"{record.machine_key} / {item.item_id}: the version label and "
                    "the artefact hash disagree against the supplier's own published "
                    "figures. This machine is neither confirmed affected nor "
                    "confirmed clear, and it is counted in neither column."
                )
            if basis is not MatchBasis.HASH and not item.content_hash:
                caveats.append(
                    f"{record.machine_key} / {item.item_id} carries no artefact hash, "
                    "so this match rests entirely on labels."
                )

    if not advisory.publishes_hashes:
        caveats.append(
            f"{advisory.issued_by} published no artefact hashes with "
            f"{advisory.advisory_id}, so every match above rests on a version label. "
            "A label is not an artefact: this system has already shown firmware can "
            "be replaced without the label moving."
        )

    unhashed_machines = [
        r.machine_key for r in fleet.records
        if any(not i.is_comparable for i in r.manifest.items)
    ]
    if unhashed_machines:
        caveats.append(
            f"{len(unhashed_machines)} machine(s) carry at least one item with no "
            "hash. An affected component hiding in an unhashed item would not be "
            "found by this assessment."
        )
    if not fleet.chain_verified:
        caveats.insert(0, "THE LEDGER CHAIN DOES NOT VERIFY. Every statement here is "
                          "drawn from a store whose integrity is in question.")
    declared_only = [r.machine_key for r in fleet.records
                     if r.manifest.source is not ManifestSource.AS_FOUND]
    if declared_only:
        caveats.append(
            f"{len(declared_only)} machine(s) are known only from a declared baseline "
            "(" + ", ".join(declared_only[:5]) + ("…" if len(declared_only) > 5 else "")
            + "): what is installed on them was never observed, so a match or a clear "
            "here is about the paperwork."
        )
    if len(fleet) == 0:
        caveats.insert(0, (
            "no machine is enrolled in this ledger, so no machine was assessed. A "
            "clear result here is about an empty fleet, not about any machine."))
    caveats.append(
        "this matches the advisory against the latest sealed manifest for each "
        "machine. A machine changed since its last manifest, or never enrolled, is "
        "absent from this report — and absence here is not evidence of safety."
    )

    classifications: list[MachineClassification] = []
    unknown_functions: list[dict[str, Any]] = []
    prior: list[dict[str, Any]] = []
    for record in fleet.records:
        mine = [e for e in exposures if e.machine_key == record.machine_key]
        matched_ids = {e.item_id for e in mine}
        reasons: list[str] = []
        if record.manifest.source is not ManifestSource.AS_FOUND:
            reasons.append("known only from a declared baseline; what is installed was "
                           "never observed")
        if not fleet.chain_verified:
            reasons.append("the ledger chain does not verify, so records may be missing")
        for item, why in _candidate_unknown_items(advisory, record, matched_ids):
            reasons.append(f"{item.item_id}: {why}")
            for fn in record.manifest.functions_of(item):
                unknown_functions.append({
                    "machine": record.machine_key, "function_id": fn.function_id,
                    "item_id": item.item_id, "reason": why,
                })
        if mine:
            basis = min((e.basis for e in mine), key=_STRENGTH.index)
            detail = next(e.detail for e in mine if e.basis is basis)
            classification, basis_value, uncertainty = (
                CLASSIFICATIONS[basis], basis.value, detail)
        elif reasons:
            classification, basis_value = "unknown", ""
            uncertainty = "; ".join(reasons)
        else:
            classification, basis_value = "no_match_found", ""
            uncertainty = ("no item matched by supplier and component name; this "
                           "rests on the manifest being complete")
        classifications.append(MachineClassification(
            machine_key=record.machine_key, site=record.manifest.machine.site,
            classification=classification, basis=basis_value, uncertainty=uncertainty,
            item_ids=tuple(sorted(matched_ids)), unknown_reasons=tuple(reasons)))

    for e in exposures:
        for f in e.functions:
            if f.coverage_before is Coverage.NEVER_VERIFIED and not f.last_verified_at:
                continue
            prior.append({
                "machine": e.machine_key, "function_id": f.function_id,
                "item_id": e.item_id, "basis": e.basis.value,
                "coverage_before": f.coverage_before.value,
                "last_verified_at": f.last_verified_at,
                "last_verified_hash": f.last_verified_hash,
                "resolved": e.basis is not MatchBasis.HASH_MISMATCH,
                "reason": ("the advisory matches the item this was verified against; "
                           "that evidence may no longer describe the machine"
                           if e.basis is not MatchBasis.HASH_MISMATCH else
                           "label and artefact disagree; whether this evidence still "
                           "describes the machine is unresolved"),
            })

    if unknown_functions or any(c.classification == "unknown" for c in classifications):
        caveats.append(
            "some machines or safety functions are UNKNOWN: the manifest does not let "
            "this assessment include or exclude them (see unknown_machines / "
            "unknown_functions). A clear result does not cover them.")

    return ImpactReport(
        advisory_id=advisory.advisory_id,
        advisory_hash=advisory.content_hash(),
        issued_by=advisory.issued_by,
        severity=advisory.severity,
        title=advisory.title,
        reference=advisory.reference,
        assessed_at=format_utc(utc_now()),
        machines_in_fleet=len(fleet),
        exposures=tuple(exposures),
        checks_skipped=tuple(dict.fromkeys(caveats)),
        chain_verified=fleet.chain_verified,
        classifications=tuple(classifications),
        unknown_functions=tuple(unknown_functions),
        prior_evidence_in_question=tuple(prior),
        provenance=dict(provenance or {}),
    )
