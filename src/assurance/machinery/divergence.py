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

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from assurance.core.tiers import AssuranceTier
from assurance.machinery.manifest import (
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
    normalised_digest,
)

__all__ = ["FUNCTION_CHANGE_PREFIX", "Change", "ChangeKind", "Divergence", "Severity", "compare"]


class ChangeKind(StrEnum):
    ADDED = "added"
    REMOVED = "removed"
    #: The artefact itself differs. The only kind that means the machine changed.
    CONTENT_CHANGED = "content_changed"
    #: Hash identical, version string differs. A relabelling.
    VERSION_RELABELLED = "version_relabelled"
    #: The safety functions this item is credited with were re-declared.
    ATTRIBUTION_CHANGED = "attribution_changed"
    #: A safety function's declaration (required performance, the checks that verify it, its
    #: description) differs. ``item_id`` is ``function:<id>``: the change is to a claim, not
    #: to an artefact on the machine.
    FUNCTION_DECLARATION_CHANGED = "function_declaration_changed"
    #: A safety function declared in the baseline is no longer declared.
    FUNCTION_REMOVED = "function_removed"
    #: A safety function is declared that the baseline did not declare.
    FUNCTION_ADDED = "function_added"

    @property
    def concerns_function(self) -> bool:
        return self in (ChangeKind.FUNCTION_DECLARATION_CHANGED,
                        ChangeKind.FUNCTION_REMOVED, ChangeKind.FUNCTION_ADDED)


#: Prefix of the ``item_id`` of a change to a function declaration rather than to an item.
FUNCTION_CHANGE_PREFIX = "function:"


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


#: What stands behind each ``hash_source``. This software never sees where a hash was read:
#: ``read_from_machine`` is a statement by whoever filed the manifest (``collect`` and ``kit``
#: record it as the operator's assertion), so an exported case says so beside the label.
_BASIS = {
    "read_from_machine": "operator_assertion",
    "supplied_by_vendor": "supplied_by_vendor",
    "declared": "declared",
}


def _summary(item: SafetyItem) -> dict[str, Any]:
    return {
        "kind": item.kind.value, "name": item.name, "version": item.version,
        "content_hash": item.content_hash, "hash_source": item.hash_source.value,
        "hash_source_basis": _BASIS[item.hash_source.value],
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
    #: Items whose equality could not be established: no hash on one side, or an
    #: observed hash that was not read off the machine. Nothing was compared, so
    #: nothing is reported unchanged.
    uncompared: tuple[str, ...] = ()
    #: Whether the observed manifest is a record of looking at a machine.
    observed_as_found: bool = True
    #: Same configuration once digests are compared in normal form (case, ``sha256:``
    #: prefix). ``identical`` stays the exact sealed-hash match, which a sealed record
    #: re-verifies, so it cannot be loosened; this is what keeps a relabelled digest from
    #: reading as drift.
    equivalent: bool = False
    #: ``SafetyManifest.safety_declaration_hash`` of each side: what the manifest says its
    #: safety functions are and what verifies them. ``configuration_hash`` does not cover
    #: this and cannot change (it is in stored ledgers), so it is compared separately. Empty
    #: for a divergence built by hand; two empty values are equal.
    baseline_declaration: str = ""
    observed_declaration: str = ""

    @property
    def identical(self) -> bool:
        """True only when the configuration hashes match exactly AND the safety-function
        declarations are the same."""
        return (self.baseline_configuration == self.observed_configuration
                and self.baseline_declaration == self.observed_declaration)

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
        """``matches`` | ``unverifiable`` | ``drifted`` | ``safety_relevant_drift``.

        ``matches`` is a claim that every item was compared and none moved. It is
        made only when every item carries a hash on both sides, every observed
        hash was read off the machine, and the observed manifest is an
        ``as_found`` one. Otherwise an unchanged-looking result is
        ``unverifiable``: nothing was seen, which is not the same as nothing
        changed.
        """
        if (self.identical or self.equivalent) and not self.changes \
                and self.baseline_declaration == self.observed_declaration:
            if self.uncompared or not self.observed_as_found:
                return "unverifiable"
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
                         "configuration": self.baseline_configuration,
                         "safety_declaration": self.baseline_declaration},
            "observed": {"manifest_id": self.observed_id, "hash": self.observed_hash,
                         "configuration": self.observed_configuration,
                         "safety_declaration": self.observed_declaration},
            "changes": [c.to_dict() for c in self.changes],
            "affected_functions": list(self.affected_functions),
            "uncompared": list(self.uncompared),
            "tier": self.tier.value,
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        head = {
            "matches": "MATCHES — the configuration is the one that was signed off",
            "unverifiable": "UNVERIFIABLE — nothing moved that could be seen, and "
                            "some of it could not be seen",
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


def _function_changes(baseline: SafetyManifest, observed: SafetyManifest) -> list[Change]:
    """Differences in what the two manifests declare their safety functions to be.

    ``configuration_hash`` covers items, not functions, so without this emptying a
    function's ``verified_by``, swapping it for a trivial check, or lowering its required
    performance level compared as identical. Every one of those weakens what a past
    verification showed, so each is safety-relevant. A function that vanished is
    safety-relevant too: its verification no longer has anything to be current against.
    """
    out: list[Change] = []
    b_fn = {f.function_id: f for f in baseline.functions}
    o_fn = {f.function_id: f for f in observed.functions}

    def _fsummary(f: SafetyFunction) -> dict[str, Any]:
        return {"function_id": f.function_id, "description": f.description,
                "required_performance": f.required_performance,
                "verified_by": sorted(f.verified_by)}

    for fid in sorted(b_fn.keys() - o_fn.keys()):
        out.append(Change(
            item_id=f"{FUNCTION_CHANGE_PREFIX}{fid}", kind=ChangeKind.FUNCTION_REMOVED,
            severity=Severity.SAFETY_RELEVANT, name=b_fn[fid].description,
            detail=f"safety function {fid} is declared in the baseline and not in the "
                   "observed manifest. Its verification has nothing left to be current "
                   "against; dropping a declaration is not evidence the function stopped "
                   "mattering.",
            before=_fsummary(b_fn[fid]), functions=(fid,)))
    for fid in sorted(o_fn.keys() - b_fn.keys()):
        out.append(Change(
            item_id=f"{FUNCTION_CHANGE_PREFIX}{fid}", kind=ChangeKind.FUNCTION_ADDED,
            severity=Severity.NOTABLE, name=o_fn[fid].description,
            detail=f"safety function {fid} is declared in the observed manifest and not in "
                   "the baseline. It has never been verified against this baseline.",
            after=_fsummary(o_fn[fid]), functions=(fid,)))
    for fid in sorted(b_fn.keys() & o_fn.keys()):
        b, o = b_fn[fid], o_fn[fid]
        what: list[str] = []
        weakening = False
        if b.required_performance != o.required_performance:
            what.append(f"required performance {b.required_performance!r} → "
                        f"{o.required_performance!r}")
            weakening = True
        if set(b.verified_by) != set(o.verified_by):
            what.append(f"verified by {sorted(b.verified_by)} → {sorted(o.verified_by)}")
            weakening = True
        if b.description != o.description:
            what.append(f"description {b.description!r} → {o.description!r}")
        if not what:
            continue
        out.append(Change(
            item_id=f"{FUNCTION_CHANGE_PREFIX}{fid}",
            kind=ChangeKind.FUNCTION_DECLARATION_CHANGED,
            severity=Severity.SAFETY_RELEVANT if weakening else Severity.NOTABLE,
            name=o.description,
            detail=f"the declaration of safety function {fid} changed: "
                   + "; ".join(what) + ". A verification run against the earlier "
                   "declaration does not show the new one.",
            before=_fsummary(b), after=_fsummary(o), functions=(fid,)))
    return out


def compare(
    baseline: SafetyManifest, observed: SafetyManifest,
    *, carried_attribution: Mapping[str, Sequence[str]] | None = None,
) -> Divergence:
    """Compare an as-declared baseline against what was found on the machine.

    Refuses to compare two different machines: a divergence report that silently
    compared serial 0412 against serial 0413 would be worse than none.

    ``carried_attribution`` maps an item to the safety functions it was credited with in the
    latest COMPLETE manifest that credited it (see
    :func:`~assurance.machinery.manifest.last_attribution`). A caller holding the ledger's
    history passes it: an item whose attribution was dropped in an earlier step is not
    thereby out of scope, so a change to it (or its removal) is still safety-relevant for
    the functions it used to implement. Without it only the two manifests are read.
    """
    if baseline.machine.key != observed.machine.key:
        raise ValueError(
            f"these manifests are about different machines: "
            f"{baseline.machine.key} and {observed.machine.key}."
        )
    carried = carried_attribution or {}

    changes: list[Change] = []
    caveats: list[str] = []

    b_ids = {i.item_id for i in baseline.items}
    o_ids = {i.item_id for i in observed.items}
    uncompared: list[str] = []

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
        removed_fns = tuple(item.implements) or tuple(carried.get(item_id, ()))
        changes.append(Change(
            item_id=item_id, kind=ChangeKind.REMOVED,
            severity=Severity.SAFETY_RELEVANT if removed_fns else Severity.NOTABLE,
            name=item.name,
            detail=f"in the baseline and not found on the machine "
                   f"({item.kind.value} {item.name} {item.version})."
                   + ("" if item.implements or not removed_fns else
                      f" It was last credited with {', '.join(removed_fns)} before that "
                      "attribution was dropped."),
            before=_summary(item), functions=removed_fns,
        ))

    for item_id in sorted(b_ids & o_ids):
        b = baseline.item(item_id)
        o = observed.item(item_id)
        assert b is not None and o is not None
        safety = b.is_safety_bearing or o.is_safety_bearing
        functions = tuple(sorted(set(b.implements) | set(o.implements)))
        if not safety and carried.get(item_id):
            # Neither manifest credits this item, but an earlier complete one did and the
            # attribution was dropped since. Still the same artefact on the same machine.
            safety = True
            functions = tuple(sorted(carried[item_id]))

        if not (b.is_comparable and o.is_comparable):
            uncompared.append(item_id)
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

        if not o.hash_source.describes_this_unit:
            uncompared.append(item_id)
            caveats.append(
                f"{item_id}: the observed hash is {o.hash_source.value}, not read from "
                "the machine, so an equal hash says what the file is, not what the "
                "machine holds. It is NOT reported as unchanged."
            )

        if normalised_digest(b.content_hash) != normalised_digest(o.content_hash):
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
            dropped = sorted(set(b.implements) - set(o.implements))
            changes.append(Change(
                item_id=item_id, kind=ChangeKind.ATTRIBUTION_CHANGED,
                # Dropping an attribution takes the item out of every later comparison for
                # that function: a changed firmware hash on it would grade only NOTABLE.
                # Nothing on the machine need have changed, but what the verification was
                # shown to cover did, so it is not left at NOTABLE. A new attribution
                # (nothing dropped) widens what is claimed and stays NOTABLE.
                severity=Severity.SAFETY_RELEVANT if dropped else Severity.NOTABLE,
                name=o.name,
                detail="the safety functions this item is credited with were "
                       f"re-declared: {sorted(b.implements)} → {sorted(o.implements)}. "
                       + (f"{', '.join(dropped)} no longer attributed to it: a later change "
                          "to this item would not be read as touching "
                          f"{'it' if len(dropped) == 1 else 'them'}, so the dropping is "
                          "itself treated as safety-relevant. "
                          if dropped else "")
                       + "Nothing on the machine need have changed; what changed is "
                       "what we claim about it.",
                before=_summary(b), after=_summary(o), functions=functions,
            ))

    changes.extend(_function_changes(baseline, observed))

    asserted = [i for i in observed.items if i.hash_source.describes_this_unit]
    if asserted:
        caveats.append(
            f"{len(asserted)} of {len(observed.items)} observed items are labelled "
            "read_from_machine. That label is the operator's assertion (collect/kit "
            "--read-from-machine, or a watch target's read_from_machine): this software "
            "cannot check that the files came off the machine, and a sealed record carrying "
            "the label shows what was claimed, not that it was true.")
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

    def _shape(m: SafetyManifest) -> list[tuple[Any, ...]]:
        return [(i.item_id, i.kind.value, i.name, i.version,
                 normalised_digest(i.content_hash) or i.content_hash, tuple(sorted(i.implements)))
                for i in sorted(m.items, key=lambda i: i.item_id)]

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
        uncompared=tuple(dict.fromkeys(uncompared)),
        observed_as_found=observed.source.value == "as_found",
        equivalent=_shape(baseline) == _shape(observed),
        baseline_declaration=baseline.safety_declaration_hash(),
        observed_declaration=observed.safety_declaration_hash(),
    )
