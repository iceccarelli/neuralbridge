"""Has this machine drifted from the configuration it was signed off with?

Two manifests go in. What comes out is the sentence an inspector, an insurer or
a plant manager actually wants: *this cell no longer matches the configuration
it was CE-marked with, here is which item changed, and here is which safety
function that item implements.*

The grading is deliberate and narrow. A version string changing while the hash
stays identical is not a change to the machine — it is a change to a label, and
reporting it as a safety divergence trains people to ignore the report. A hash
changing on an item that implements a safety function is the finding. Everything
else sits between, named.

What this cannot do is also stated, every time: an item carrying no hash is
invisible to comparison. A clean divergence report over a manifest full of
declared items means nothing was seen, not that nothing changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from assurance.core.tiers import AssuranceTier
from assurance.machinery.manifest import SafetyItem, SafetyManifest

__all__ = ["Change", "ChangeKind", "Divergence", "Severity", "compare"]


class ChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    #: The artefact itself differs. The only kind that means the machine changed.
    CONTENT_CHANGED = "content_changed"
    #: Hash identical, version string differs. A relabelling.
    VERSION_RELABELLED = "version_relabelled"
    #: The safety functions this item is credited with were re-declared.
    ATTRIBUTION_CHANGED = "attribution_changed"


class Severity(StrEnum):
    #: A safety-bearing item's artefact changed. Prior verification is in doubt.
    SAFETY_RELEVANT = "safety_relevant"
    #: Something changed, but not on an item credited to a safety function.
    NOTABLE = "notable"
    #: Bookkeeping. Worth recording, not worth stopping a line for.
    ADMINISTRATIVE = "administrative"

    @property
    def rank(self) -> int:
        return {"administrative": 0, "notable": 1, "safety_relevant": 2}[self.value]


@dataclass(frozen=True)
class Change:
    """One item that differs between the two manifests."""

    item_id: str
    kind: ChangeKind
    severity: Severity
    name: str
    detail: str
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    #: Safety function ids this item is credited with, in either manifest.
    functions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "kind": self.kind.value,
            "severity": self.severity.value,
            "name": self.name,
            "detail": self.detail,
            "functions": list(self.functions),
            "before": self.before,
            "after": self.after,
        }


def _summary(item: SafetyItem) -> dict[str, Any]:
    return {
        "kind": item.kind.value, "name": item.name, "version": item.version,
        "content_hash": item.content_hash, "hash_source": item.hash_source.value,
        "implements": list(item.implements),
    }


@dataclass(frozen=True)
class Divergence:
    """The comparison, its verdict, and everything it could not see."""

    machine_key: str
    baseline_id: str
    baseline_hash: str
    observed_id: str
    observed_hash: str
    baseline_configuration: str
    observed_configuration: str
    changes: tuple[Change, ...]
    checks_skipped: tuple[str, ...]
    tier: AssuranceTier

    @property
    def identical(self) -> bool:
        """True only when the configuration hashes match exactly."""
        return self.baseline_configuration == self.observed_configuration

    @property
    def safety_relevant(self) -> tuple[Change, ...]:
        return tuple(c for c in self.changes if c.severity is Severity.SAFETY_RELEVANT)

    @property
    def worst(self) -> Severity | None:
        return max((c.severity for c in self.changes),
                   key=lambda s: s.rank, default=None)

    @property
    def affected_functions(self) -> tuple[str, ...]:
        out: list[str] = []
        for c in self.safety_relevant:
            for f in c.functions:
                if f not in out:
                    out.append(f)
        return tuple(sorted(out))

    @property
    def verdict(self) -> str:
        """``matches`` | ``drifted`` | ``safety_relevant_drift``."""
        if self.identical and not self.changes:
            return "matches"
        if self.safety_relevant:
            return "safety_relevant_drift"
        return "drifted"

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "verdict": self.verdict,
            "identical": self.identical,
            "baseline": {"manifest_id": self.baseline_id, "hash": self.baseline_hash,
                         "configuration": self.baseline_configuration},
            "observed": {"manifest_id": self.observed_id, "hash": self.observed_hash,
                         "configuration": self.observed_configuration},
            "changes": [c.to_dict() for c in self.changes],
            "affected_functions": list(self.affected_functions),
            "tier": self.tier.value,
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        head = {
            "matches": "MATCHES — the configuration is the one that was signed off",
            "drifted": "DRIFTED — changes found, none on a safety-bearing item",
            "safety_relevant_drift":
                "SAFETY-RELEVANT DRIFT — a safety-bearing item has changed",
        }[self.verdict]
        lines = [f"{self.machine_key}: {head}",
                 f"  baseline {self.baseline_configuration[:12]} "
                 f"→ observed {self.observed_configuration[:12]}  (tier {self.tier.value})"]
        for c in sorted(self.changes, key=lambda c: (-c.severity.rank, c.item_id)):
            mark = {"safety_relevant": "!!", "notable": " *", "administrative": "  "}
            lines.append(f"  {mark[c.severity.value]} {c.item_id}: {c.detail}")
            if c.functions:
                lines.append(f"       affects {', '.join(c.functions)}")
        if self.affected_functions:
            lines.append("  Verification evidence for the affected functions is in "
                         "doubt until it is re-run.")
        return "\n".join(lines)


def compare(baseline: SafetyManifest, observed: SafetyManifest) -> Divergence:
    """Compare an as-declared baseline against what was found on the machine.

    Refuses to compare two different machines: a divergence report that silently
    compared serial 0412 against serial 0413 would be worse than none.
    """
    if baseline.machine.key != observed.machine.key:
        raise ValueError(
            f"these manifests are about different machines: "
            f"{baseline.machine.key} and {observed.machine.key}."
        )

    changes: list[Change] = []
    caveats: list[str] = []

    b_ids = {i.item_id for i in baseline.items}
    o_ids = {i.item_id for i in observed.items}

    for item_id in sorted(o_ids - b_ids):
        item = observed.item(item_id)
        assert item is not None
        changes.append(Change(
            item_id=item_id, kind=ChangeKind.ADDED,
            severity=Severity.SAFETY_RELEVANT if item.is_safety_bearing
            else Severity.NOTABLE,
            name=item.name,
            detail=f"present on the machine and absent from the baseline "
                   f"({item.kind.value} {item.name} {item.version}).",
            after=_summary(item), functions=item.implements,
        ))

    for item_id in sorted(b_ids - o_ids):
        item = baseline.item(item_id)
        assert item is not None
        changes.append(Change(
            item_id=item_id, kind=ChangeKind.REMOVED,
            severity=Severity.SAFETY_RELEVANT if item.is_safety_bearing
            else Severity.NOTABLE,
            name=item.name,
            detail=f"in the baseline and not found on the machine "
                   f"({item.kind.value} {item.name} {item.version}).",
            before=_summary(item), functions=item.implements,
        ))

    for item_id in sorted(b_ids & o_ids):
        b = baseline.item(item_id)
        o = observed.item(item_id)
        assert b is not None and o is not None
        safety = b.is_safety_bearing or o.is_safety_bearing
        functions = tuple(sorted(set(b.implements) | set(o.implements)))

        if not (b.is_comparable and o.is_comparable):
            caveats.append(
                f"{item_id} carries no hash in one or both manifests "
                f"({b.hash_source.value} / {o.hash_source.value}), so a change to it "
                "would not have been seen. It is NOT reported as unchanged."
            )
            if b.version != o.version:
                changes.append(Change(
                    item_id=item_id, kind=ChangeKind.VERSION_RELABELLED,
                    severity=Severity.NOTABLE, name=o.name,
                    detail=f"version went {b.version!r} → {o.version!r} and neither "
                           "side is hashed, so whether the artefact changed is unknown.",
                    before=_summary(b), after=_summary(o), functions=functions,
                ))
            continue

        if b.content_hash != o.content_hash:
            changes.append(Change(
                item_id=item_id, kind=ChangeKind.CONTENT_CHANGED,
                severity=Severity.SAFETY_RELEVANT if safety else Severity.NOTABLE,
                name=o.name,
                detail=f"the artefact changed: {b.content_hash[:12]} → "
                       f"{o.content_hash[:12]}"
                       + (f" (version {b.version!r} → {o.version!r})"
                          if b.version != o.version
                          else f", with the version still reported as {o.version!r}"),
                before=_summary(b), after=_summary(o), functions=functions,
            ))
        elif b.version != o.version:
            changes.append(Change(
                item_id=item_id, kind=ChangeKind.VERSION_RELABELLED,
                severity=Severity.ADMINISTRATIVE, name=o.name,
                detail=f"version relabelled {b.version!r} → {o.version!r}; the "
                       "artefact is byte-identical, so the machine did not change.",
                before=_summary(b), after=_summary(o), functions=functions,
            ))

        if set(b.implements) != set(o.implements):
            changes.append(Change(
                item_id=item_id, kind=ChangeKind.ATTRIBUTION_CHANGED,
                severity=Severity.NOTABLE, name=o.name,
                detail="the safety functions this item is credited with were "
                       f"re-declared: {sorted(b.implements)} → {sorted(o.implements)}. "
                       "Nothing on the machine need have changed; what changed is "
                       "what we claim about it.",
                before=_summary(b), after=_summary(o), functions=functions,
            ))

    if observed.uncomparable_items:
        caveats.append(
            f"{len(observed.uncomparable_items)} of {len(observed.items)} observed "
            "items carry no hash at all. Those items were not compared."
        )
    if not observed.source.value == "as_found":
        caveats.append(
            f"the observed manifest is recorded as {observed.source.value!r}, not "
            "'as_found'. This compares two declarations, and says nothing about what "
            "is actually on the machine."
        )
    for item in observed.field_modifiable_safety_items:
        caveats.append(
            f"{item.item_id} is a safety-bearing item that can be changed on site. "
            "A divergence report is a snapshot; only an intervention record covers "
            "what happened between snapshots."
        )
    undem = observed.undemonstrable_functions
    if undem:
        caveats.append(
            "safety function(s) " + ", ".join(f.function_id for f in undem)
            + " declare no verification check, so a change affecting them cannot be "
            "traced to any evidence that would need re-running."
        )

    tier = min(baseline.tier_ceiling, observed.tier_ceiling)

    return Divergence(
        machine_key=observed.machine.key,
        baseline_id=baseline.manifest_id,
        baseline_hash=baseline.content_hash(),
        observed_id=observed.manifest_id,
        observed_hash=observed.content_hash(),
        baseline_configuration=baseline.configuration_hash(),
        observed_configuration=observed.configuration_hash(),
        changes=tuple(changes),
        checks_skipped=tuple(dict.fromkeys(caveats)),
        tier=tier,
    )
