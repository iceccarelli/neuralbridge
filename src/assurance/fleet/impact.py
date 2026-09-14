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

from dataclasses import dataclass
from typing import Any

from assurance.core.identity import format_utc, utc_now
from assurance.fleet.advisory import AdvisorySeverity, ComponentAdvisory, MatchBasis, match_item
from assurance.fleet.registry import Fleet
from assurance.machinery.staleness import Coverage

__all__ = ["Exposure", "FunctionExposure", "ImpactReport", "assess_impact"]


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
        """``clear`` | ``exposed`` | ``needs_review``."""
        if not self.exposures:
            return "clear"
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
            "machines_affected": list(self.machines_affected),
            "functions_newly_in_question": self.functions_newly_in_question,
            "exposures": [e.to_dict() for e in self.exposures],
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        head = {
            "clear": "CLEAR — no machine in this fleet matches this advisory",
            "exposed": "EXPOSED — standing safety evidence is now in question",
            "needs_review": "NEEDS REVIEW — matches found, none with standing evidence",
        }[self.verdict]
        lines = [
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
        return "\n".join(lines)


def assess_impact(advisory: ComponentAdvisory, fleet: Fleet) -> ImpactReport:
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
    caveats.append(
        "this matches the advisory against the latest sealed manifest for each "
        "machine. A machine changed since its last manifest, or never enrolled, is "
        "absent from this report — and absence here is not evidence of safety."
    )

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
    )
