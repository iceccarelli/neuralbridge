"""Every machine in the ledger, and where each one stands.

``assurance machinery coverage`` answers one machine. An integrator has forty,
in eleven plants, and the question they ask on a Monday morning is not *is cell
0412 covered* but *which of my forty are not*.

This is aggregation, not new inference — every row is produced by the same
:func:`assurance.machinery.staleness.assess_coverage` that answers one machine —
and that is the point. One store, one join, one answer per machine, and the
fleet view is a sort.

What makes it worth more than forty CLI runs is the next module: an advisory
arrives naming one component version, and a fleet is the only thing that can
turn that into a list of serial numbers.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import MANIFEST_KIND
from assurance.machinery.staleness import (
    Coverage,
    CoverageReport,
    VerificationRecord,
    assess_coverage,
)

__all__ = ["Fleet", "FleetSummary", "MachineRecord"]


@dataclass(frozen=True)
class MachineRecord:
    """One machine's current position."""

    machine_key: str
    manifest: SafetyManifest
    coverage: CoverageReport
    interventions: tuple[Intervention, ...]
    verifications: tuple[VerificationRecord, ...]

    @property
    def worst(self) -> Coverage | None:
        """The weakest coverage state among declared functions."""
        return min((f.coverage for f in self.coverage.functions),
                   key=lambda c: c.rank, default=None)

    @property
    def uncovered_count(self) -> int:
        return len(self.coverage.uncovered)

    @property
    def stale_count(self) -> int:
        return len(self.coverage.stale)

    @property
    def site(self) -> str:
        return self.manifest.machine.site

    def to_row(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "site": self.site,
            "manifest_id": self.manifest.manifest_id,
            "configuration_hash": self.manifest.configuration_hash(),
            "taken_at": self.manifest.taken_at.isoformat().replace("+00:00", "Z"),
            "verdict": self.coverage.verdict,
            "worst": self.worst.value if self.worst else None,
            "functions": len(self.coverage.functions),
            "stale": self.stale_count,
            "uncovered": self.uncovered_count,
            "interventions": len(self.interventions),
            "verifications": len(self.verifications),
            "tier_ceiling": self.manifest.tier_ceiling.value,
        }


@dataclass(frozen=True)
class FleetSummary:
    machines: int
    covered: int
    with_gaps: int
    by_worst: dict[str, int]
    sites: dict[str, int]
    chain_verified: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "machines": self.machines, "covered": self.covered,
            "with_gaps": self.with_gaps, "by_worst": self.by_worst,
            "sites": self.sites, "chain_verified": self.chain_verified,
        }


@dataclass(frozen=True)
class Fleet:
    """Every machine the ledger knows about, with its coverage position."""

    records: tuple[MachineRecord, ...]
    chain_verified: bool
    chain_problems: tuple[str, ...] = ()

    @classmethod
    def from_ledger(cls, ledger: EvidenceLedger) -> Fleet:
        """Build the fleet from whatever has been sealed.

        A machine appears once its latest manifest is sealed. Manifests with a
        broken seal are skipped rather than trusted — a tampered manifest must
        not be able to put a machine in the covered column.
        """
        chain_ok, problems = ledger.verify_chain()

        latest: dict[str, SafetyManifest] = {}
        for entry in ledger.entries(kind=MANIFEST_KIND):
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            manifest = SafetyManifest.from_dict(evidence.body["manifest"])
            # Later entries win: the ledger is append-only and ordered by seq,
            # so the last sealed manifest for a machine is the current one.
            latest[manifest.machine.key] = manifest

        records: list[MachineRecord] = []
        for key, manifest in sorted(latest.items()):
            from assurance.machinery.record import interventions_from_ledger

            ivs = interventions_from_ledger(ledger, key)
            vfs = VerificationRecord.from_ledger(ledger, subject=key)
            records.append(MachineRecord(
                machine_key=key, manifest=manifest,
                coverage=assess_coverage(manifest, vfs, ivs),
                interventions=tuple(ivs), verifications=tuple(vfs),
            ))

        return cls(records=tuple(records), chain_verified=chain_ok,
                   chain_problems=tuple(problems))

    def __len__(self) -> int:
        return len(self.records)

    def record(self, machine_key: str) -> MachineRecord | None:
        return next((r for r in self.records if r.machine_key == machine_key), None)

    def with_gaps(self) -> tuple[MachineRecord, ...]:
        """Machines where at least one declared function is not currently covered."""
        return tuple(r for r in self.records if r.coverage.verdict != "covered")

    def summary(self) -> FleetSummary:
        worst = Counter(r.worst.value for r in self.records if r.worst)
        sites = Counter(r.site or "(no site recorded)" for r in self.records)
        covered = sum(1 for r in self.records if r.coverage.verdict == "covered")
        return FleetSummary(
            machines=len(self.records),
            covered=covered,
            with_gaps=len(self.records) - covered,
            by_worst=dict(sorted(worst.items())),
            sites=dict(sorted(sites.items())),
            chain_verified=self.chain_verified,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary().to_dict(),
            "machines": [r.to_row() for r in self.records],
            "chain_verified": self.chain_verified,
            "chain_problems": list(self.chain_problems),
        }

    def table(self) -> str:
        """Worst first, because that is the order somebody reads it in."""
        if not self.records:
            return "no machines in this ledger."
        rows = sorted(
            self.records,
            key=lambda r: (r.worst.rank if r.worst else 99, -r.stale_count,
                           r.machine_key),
        )
        head = (f"{'machine':<28} {'site':<22} {'worst':<17} "
                f"{'stale':>5} {'fns':>4}  config")
        out = [head, "-" * len(head)]
        for r in rows:
            out.append(
                f"{r.machine_key:<28} {(r.site or '—')[:22]:<22} "
                f"{(r.worst.value if r.worst else '—'):<17} "
                f"{r.stale_count:>5} {len(r.coverage.functions):>4}  "
                f"{r.manifest.configuration_hash()[:12]}"
            )
        s = self.summary()
        out.append("")
        out.append(f"{s.machines} machine(s): {s.covered} covered, "
                   f"{s.with_gaps} with gaps")
        if not self.chain_verified:
            out.append("THE LEDGER CHAIN DOES NOT VERIFY — every row above is drawn "
                       "from a store whose integrity is in question.")
        return "\n".join(out)
