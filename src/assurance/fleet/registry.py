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
from datetime import timedelta
from typing import Any

from assurance.core.identity import parse_utc
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.recorder_attestation import RecorderTrust
from assurance.machinery.intervention import Intervention
from assurance.machinery.manifest import ManifestSource, SafetyManifest
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
    def from_ledger(cls, ledger: EvidenceLedger, *,
                    recorder_trust: RecorderTrust | None = None) -> Fleet:
        """Build the fleet from whatever has been sealed.

        ``recorder_trust`` is the reader's own recorder trust list, applied to every
        verification read (see :meth:`VerificationRecord.from_ledger`). A hosted reader
        always passes one; an offline command reading its owner's ledger may not.

        A machine appears once its latest manifest is sealed. Manifests with a
        broken seal are skipped rather than trusted — a tampered manifest must
        not be able to put a machine in the covered column.
        """
        chain_ok, problems = ledger.verify_chain()

        # Which manifest is "the machine"? What was found on it, most recently.
        #
        # * an ``as_intended`` manifest is a plan, not a fact, and never current;
        # * an observation (``as_found``) outranks a declaration, so a baseline
        #   filed after an observation does not make the machine look like its
        #   paperwork;
        # * within a kind, the later ``taken_at`` wins, then the later ledger
        #   entry — and a ``taken_at`` later than the moment the manifest was
        #   filed (plus a day for clocks) is not believed: it is dated by its
        #   filing, so a future date cannot pin a manifest as current for ever.
        best: dict[str, tuple[tuple[int, Any, int], SafetyManifest]] = {}
        for entry in ledger.entries(kind=MANIFEST_KIND):
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            manifest = SafetyManifest.from_dict(evidence.body["manifest"])
            if manifest.source is ManifestSource.AS_INTENDED:
                continue
            filed = parse_utc(entry.at)
            when = manifest.taken_at
            if when > filed + timedelta(days=1):
                when = filed
            rank = (1 if manifest.source is ManifestSource.AS_FOUND else 0,
                    when, entry.seq)
            key = manifest.machine.key
            if key not in best or rank > best[key][0]:
                best[key] = (rank, manifest)
        latest = {k: v[1] for k, v in best.items()}

        records: list[MachineRecord] = []
        for key, manifest in sorted(latest.items()):
            from assurance.machinery.record import interventions_from_ledger

            ivs = interventions_from_ledger(ledger, key)
            vfs = VerificationRecord.from_ledger(
                ledger, subject=key, recorder_trust=recorder_trust)
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
        """Worst first, because that is the order somebody reads it in.

        A chain that does not verify is said first: a warning under the rows
        would be read after the rows had already been believed.
        """
        warning = ("THE LEDGER CHAIN DOES NOT VERIFY — every row below is drawn from a "
                   "store whose integrity is in question.\n\n"
                   if not self.chain_verified else "")
        if not self.records:
            return warning + "no machines in this ledger."
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
        return warning + "\n".join(out)
