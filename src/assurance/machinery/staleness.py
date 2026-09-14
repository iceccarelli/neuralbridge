"""Which of this machine's safety functions are still covered by valid evidence?

This is the join that neither half can make alone, and the reason both halves
exist in one package.

:mod:`assurance.machine` produces a verification: *on this run, the cell met its
declared separation, speed and workspace limits.* :mod:`assurance.machinery`
produces an intervention record: *on 14 March a technician replaced the safety
controller firmware.* Separately, each is a file. Together they produce the
sentence a plant manager has never been shown:

    SF-02 protective stop — STALE. Last verified 9 February by bundle a41c…;
    invalidated by INT-0007 on 14 March, which changed safety-controller
    firmware and re-ran nothing. The cell has run for seven months on a
    validation that stopped describing it.

The inference is mechanical, not clever. An intervention names the item it
touched; the manifest says which safety functions that item implements; each
function declares the verification checks that exercise it. A verification
recorded before the intervention, whose verified checks intersect that set, no
longer describes the machine.

Every step of that chain is declared by the customer and visible in the output,
so a reviewer who disagrees can point at the link they disagree with. A function
that declares no checks is reported as ``not_demonstrable`` — never as covered.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from assurance.core.identity import format_utc, parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.bundle import BUNDLE_KIND
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest

__all__ = [
    "Coverage",
    "CoverageReport",
    "FunctionCoverage",
    "VerificationRecord",
    "assess_coverage",
]


class Coverage(StrEnum):
    """The state of the evidence for one safety function."""

    #: A passing verification exists and nothing since has disturbed it.
    CURRENT = "current"
    #: It was verified, and a later intervention invalidated that verification.
    STALE = "stale"
    #: A verification exists but the checks for this function did not pass.
    FAILING = "failing"
    #: No verification has ever exercised this function.
    NEVER_VERIFIED = "never_verified"
    #: The function declares no checks, so no verification could cover it.
    NOT_DEMONSTRABLE = "not_demonstrable"

    @property
    def is_covered(self) -> bool:
        return self is Coverage.CURRENT

    @property
    def rank(self) -> int:
        """Worst first, for sorting a report a human reads top-down."""
        return {"failing": 0, "stale": 1, "never_verified": 2,
                "not_demonstrable": 3, "current": 4}[self.value]


@dataclass(frozen=True)
class VerificationRecord:
    """A sealed machine verification, reduced to what staleness needs.

    ``effective_at`` is when the machine was in the state the verification
    describes — the start of the recorded run — not when the bundle was filed.
    A run captured in February and filed in June is evidence about February.
    """

    content_hash: str
    effective_at: datetime
    ledger_seq: int
    product: str
    product_version: str
    verdict: str
    tier: str
    checks_verified: tuple[str, ...]
    checks_not_verified: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "content_hash": self.content_hash,
            "effective_at": format_utc(self.effective_at),
            "ledger_seq": self.ledger_seq,
            "product": self.product,
            "product_version": self.product_version,
            "verdict": self.verdict,
            "tier": self.tier,
            "checks_verified": list(self.checks_verified),
            "checks_not_verified": list(self.checks_not_verified),
        }

    @classmethod
    def from_ledger(
        cls, ledger: EvidenceLedger, *, subject: str | None = None,
    ) -> list[VerificationRecord]:
        """Read every sealed machine verification out of a ledger.

        A bundle whose evidence no longer matches its own hash is skipped rather
        than trusted: a tampered record must not be able to make a stale
        function look current.
        """
        out: list[VerificationRecord] = []
        for entry in ledger.entries(kind=BUNDLE_KIND, subject=subject):
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            body = evidence.body
            checks = body.get("checks") or []
            verified = tuple(c["name"] for c in checks
                             if c.get("outcome") == "verified")
            others = tuple(c["name"] for c in checks
                           if c.get("outcome") != "verified")
            raw = body.get("trace_started_at") or entry.at
            try:
                effective = parse_utc(str(raw))
            except (ValueError, TypeError):
                effective = parse_utc(entry.at)
            out.append(cls(
                content_hash=evidence.content_hash,
                effective_at=effective,
                ledger_seq=entry.seq,
                product=str(body.get("product", "")),
                product_version=str(body.get("product_version", "")),
                verdict=str(body.get("verdict", "")),
                tier=str(body.get("tier", "")),
                checks_verified=verified,
                checks_not_verified=others,
            ))
        return out


@dataclass(frozen=True)
class FunctionCoverage:
    """The evidence position for one declared safety function."""

    function_id: str
    description: str
    required_performance: str
    coverage: Coverage
    checks: tuple[str, ...]
    #: The most recent verification that covered this function, if any.
    last_verified_hash: str = ""
    last_verified_at: str = ""
    #: The intervention that invalidated it, when coverage is STALE.
    invalidated_by: str = ""
    invalidated_at: str = ""
    invalidating_item: str = ""
    #: Whether that intervention re-ran anything with sealed evidence.
    intervention_revalidated: bool = False
    detail: str = ""

    @property
    def days_uncovered(self) -> int | None:
        """Days the machine has run without valid evidence for this function."""
        if self.coverage is not Coverage.STALE or not self.invalidated_at:
            return None
        try:
            from assurance.core.identity import utc_now
            return max(0, (utc_now() - parse_utc(self.invalidated_at)).days)
        except (ValueError, TypeError):
            return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_id": self.function_id,
            "description": self.description,
            "required_performance": self.required_performance,
            "coverage": self.coverage.value,
            "checks": list(self.checks),
            "last_verified_hash": self.last_verified_hash,
            "last_verified_at": self.last_verified_at,
            "invalidated_by": self.invalidated_by,
            "invalidated_at": self.invalidated_at,
            "invalidating_item": self.invalidating_item,
            "intervention_revalidated": self.intervention_revalidated,
            "days_uncovered": self.days_uncovered,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class CoverageReport:
    """Every declared safety function, and whether evidence still stands for it."""

    machine_key: str
    manifest_id: str
    configuration_hash: str
    assessed_at: str
    functions: tuple[FunctionCoverage, ...]
    #: Interventions that touched a safety-bearing item and re-ran nothing.
    unrevalidated_interventions: tuple[str, ...]
    checks_skipped: tuple[str, ...]

    @property
    def verdict(self) -> str:
        """``covered`` | ``gaps`` | ``no_functions_declared``."""
        if not self.functions:
            return "no_functions_declared"
        return "covered" if all(f.coverage.is_covered for f in self.functions) else "gaps"

    @property
    def stale(self) -> tuple[FunctionCoverage, ...]:
        return tuple(f for f in self.functions if f.coverage is Coverage.STALE)

    @property
    def uncovered(self) -> tuple[FunctionCoverage, ...]:
        return tuple(f for f in self.functions if not f.coverage.is_covered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "manifest_id": self.manifest_id,
            "configuration_hash": self.configuration_hash,
            "assessed_at": self.assessed_at,
            "verdict": self.verdict,
            "functions": [f.to_dict() for f in self.functions],
            "unrevalidated_interventions": list(self.unrevalidated_interventions),
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        mark = {"current": "ok    ", "stale": "STALE ", "failing": "FAIL  ",
                "never_verified": "never ", "not_demonstrable": "n/a   "}
        lines = [
            f"{self.machine_key} — {self.verdict.upper()}",
            f"  configuration {self.configuration_hash[:12]}  "
            f"manifest {self.manifest_id}",
        ]
        for f in sorted(self.functions, key=lambda f: (f.coverage.rank, f.function_id)):
            perf = f" [{f.required_performance}]" if f.required_performance else ""
            lines.append(f"  [{mark[f.coverage.value]}] {f.function_id}{perf}  "
                         f"{f.description}")
            lines.append(f"           {f.detail}")
            days = f.days_uncovered
            if days is not None:
                lines.append(f"           running {days} day(s) without valid evidence "
                             "for this function.")
        if self.unrevalidated_interventions:
            lines.append("  Interventions on safety-bearing items with nothing re-run: "
                         + ", ".join(self.unrevalidated_interventions))
        return "\n".join(lines)


def assess_coverage(
    manifest: SafetyManifest,
    verifications: list[VerificationRecord],
    interventions: list[Intervention],
) -> CoverageReport:
    """Work out, function by function, whether the evidence still stands.

    ``verifications`` and ``interventions`` need not be sorted; both are ordered
    here by the time they describe, not the time they were filed.
    """
    from assurance.core.identity import utc_now

    machine_key = manifest.machine.key
    mine = sorted(
        (i for i in interventions if i.machine_key == machine_key),
        key=lambda i: i.occurred_at,
    )
    verifs = sorted(verifications, key=lambda v: v.effective_at)

    caveats: list[str] = []
    coverages: list[FunctionCoverage] = []

    for fn in sorted(manifest.functions, key=lambda f: f.function_id):
        checks = set(fn.verified_by)

        if not checks:
            coverages.append(FunctionCoverage(
                function_id=fn.function_id, description=fn.description,
                required_performance=fn.required_performance,
                coverage=Coverage.NOT_DEMONSTRABLE, checks=(),
                detail="this function declares no verification check, so no "
                       "verification can cover it. Declare the checks that exercise "
                       "it, or accept that its evidence lives outside this system.",
            ))
            continue

        # Interventions that disturb this function, by the functions they name.
        disturbing = [i for i in mine if checks & manifest.checks_for(set(i.affects_functions))]

        # The most recent verification whose verified checks cover this function.
        covering = [v for v in verifs if checks & set(v.checks_verified)]
        attempted = [v for v in verifs
                     if checks & (set(v.checks_verified) | set(v.checks_not_verified))]

        if not covering:
            if attempted:
                last = attempted[-1]
                coverages.append(FunctionCoverage(
                    function_id=fn.function_id, description=fn.description,
                    required_performance=fn.required_performance,
                    coverage=Coverage.FAILING, checks=tuple(sorted(checks)),
                    last_verified_hash=last.content_hash,
                    last_verified_at=format_utc(last.effective_at),
                    detail=f"the most recent verification ({last.content_hash[:12]}, "
                           f"{last.verdict}) ran the checks for this function and did "
                           "not pass them. Coverage has never been established.",
                ))
            else:
                coverages.append(FunctionCoverage(
                    function_id=fn.function_id, description=fn.description,
                    required_performance=fn.required_performance,
                    coverage=Coverage.NEVER_VERIFIED, checks=tuple(sorted(checks)),
                    detail="no verification in the ledger has ever run "
                           + ", ".join(sorted(checks)) + " for this machine.",
                ))
            continue

        last_good = covering[-1]
        after = [i for i in disturbing if i.occurred_at > last_good.effective_at]

        if not after:
            coverages.append(FunctionCoverage(
                function_id=fn.function_id, description=fn.description,
                required_performance=fn.required_performance,
                coverage=Coverage.CURRENT, checks=tuple(sorted(checks)),
                last_verified_hash=last_good.content_hash,
                last_verified_at=format_utc(last_good.effective_at),
                detail=f"verified by {last_good.content_hash[:12]} on "
                       f"{format_utc(last_good.effective_at)[:10]} at tier "
                       f"{last_good.tier}; no recorded intervention since has "
                       "touched an item implementing it.",
            ))
            continue

        breaker = after[0]
        revalidated = breaker.is_revalidated
        coverages.append(FunctionCoverage(
            function_id=fn.function_id, description=fn.description,
            required_performance=fn.required_performance,
            coverage=Coverage.STALE, checks=tuple(sorted(checks)),
            last_verified_hash=last_good.content_hash,
            last_verified_at=format_utc(last_good.effective_at),
            invalidated_by=breaker.intervention_id,
            invalidated_at=format_utc(breaker.occurred_at),
            invalidating_item=breaker.item_id,
            intervention_revalidated=revalidated,
            detail=(
                f"last verified by {last_good.content_hash[:12]} on "
                f"{format_utc(last_good.effective_at)[:10]}; invalidated by "
                f"{breaker.intervention_id} on {format_utc(breaker.occurred_at)[:10]}, "
                f"which changed {breaker.item_id}"
                + (f" and re-ran {breaker.revalidation.description!r} — but that "
                   f"revalidation is not in this ledger, so it was not counted."
                   if revalidated else " and re-ran nothing with sealed evidence.")
            ),
        ))

    # -- what this assessment could not see -------------------------------
    unrevalidated = tuple(
        i.intervention_id for i in mine
        if i.is_safety_bearing and not i.is_revalidated
    )
    if not mine:
        caveats.append(
            "no interventions were supplied for this machine. A function shown as "
            "current is current only against the change records you have; an "
            "unrecorded change is invisible here by construction."
        )
    unattributed = [i.intervention_id for i in mine if not i.is_safety_bearing]
    if unattributed:
        caveats.append(
            "intervention(s) " + ", ".join(unattributed) + " name no safety function, "
            "so they disturb nothing in this assessment. If any of them touched a "
            "safety-bearing item, the attribution is missing, not the risk."
        )
    if manifest.uncomparable_items:
        caveats.append(
            f"{len(manifest.uncomparable_items)} manifest item(s) carry no hash, so a "
            "change to them would not appear in a divergence report and would only "
            "reach this assessment if somebody wrote an intervention record by hand."
        )
    for item in manifest.field_modifiable_safety_items:
        caveats.append(
            f"{item.item_id} is safety-bearing and modifiable on site; coverage for "
            f"{', '.join(item.implements)} rests on every such change having been "
            "recorded."
        )
    caveats.append(
        "this joins verification bundles to intervention records through the safety "
        "functions the manifest declares. It does not confirm the manifest is "
        "complete, and a safety-relevant item nobody listed is covered by nothing "
        "here and reported by nothing here."
    )

    return CoverageReport(
        machine_key=machine_key,
        manifest_id=manifest.manifest_id,
        configuration_hash=manifest.configuration_hash(),
        assessed_at=format_utc(utc_now()),
        functions=tuple(coverages),
        unrevalidated_interventions=unrevalidated,
        checks_skipped=tuple(dict.fromkeys(caveats)),
    )
