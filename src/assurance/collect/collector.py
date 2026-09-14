"""Run a plan against a folder of exports and produce a manifest.

This is the on-ramp. Before it, using any of this meant hand-writing a manifest,
which meant nobody used it. After it, an engineer drops the exports in a folder,
runs one command, and a sealed manifest exists for that serial number.

Three rules keep the output honest.

**A required item that is not there is not in the manifest.** It is a loud
warning instead. A manifest that lists an item the collector never found would
assert the machine has software that was never hashed, and every comparison made
from it afterwards would be wrong in the safest-looking direction.

**A multi-file item is the set, not the first match.** A safety PLC project is a
directory. Its identity is the digest of every member's digest, keyed by
relative path, so adding a file to the project changes the item — which is
correct, and which a "hash the first match" collector misses entirely.

**The rule travels with the digest.** Each item records the normalisation
fingerprint that produced its hash, so a digest taken under a changed rule is
visibly a different measurement rather than an invisible change of machine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from assurance.collect.normalise import (
    NormalisationError,
    NormalisationResult,
    normalise_file,
)
from assurance.collect.plan import CollectionPlan, ItemSpec
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import content_hash_of, format_utc, utc_now
from assurance.machinery.manifest import (
    HashSource,
    MachineIdentity,
    ManifestSource,
    SafetyItem,
    SafetyManifest,
)

__all__ = ["CollectionError", "CollectionResult", "ItemOutcome", "collect"]


class CollectionError(AssuranceError):
    """A collection cannot be performed as specified."""


@dataclass(frozen=True)
class ItemOutcome:
    """What happened to one item spec during a collection."""

    item_id: str
    status: str            # collected | missing | unreadable
    files: tuple[str, ...] = ()
    digest: str = ""
    rule_fingerprint: str = ""
    version: str = ""
    bytes_in: int = 0
    bytes_hashed: int = 0
    applied: dict[str, int] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "collected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id, "status": self.status,
            "files": list(self.files), "digest": self.digest,
            "rule_fingerprint": self.rule_fingerprint, "version": self.version,
            "bytes_in": self.bytes_in, "bytes_hashed": self.bytes_hashed,
            "applied": dict(sorted(self.applied.items())),
            "warnings": list(self.warnings), "detail": self.detail,
        }


@dataclass(frozen=True)
class CollectionResult:
    """The manifest, and everything that went wrong getting it."""

    manifest: SafetyManifest
    plan_id: str
    plan_hash: str
    root: str
    outcomes: tuple[ItemOutcome, ...]
    warnings: tuple[str, ...]

    @property
    def missing(self) -> tuple[ItemOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "missing")

    @property
    def unreadable(self) -> tuple[ItemOutcome, ...]:
        return tuple(o for o in self.outcomes if o.status == "unreadable")

    @property
    def complete(self) -> bool:
        """Whether every required item in the plan was actually hashed."""
        return not self.missing and not self.unreadable

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "plan_hash": self.plan_hash,
            "root": self.root,
            "complete": self.complete,
            "manifest": self.manifest.to_dict(),
            "configuration_hash": self.manifest.configuration_hash(),
            "outcomes": [o.to_dict() for o in self.outcomes],
            "warnings": list(self.warnings),
        }

    def summary(self) -> str:
        lines = [
            f"{self.manifest.machine.key} — "
            f"{'COMPLETE' if self.complete else 'INCOMPLETE'}",
            f"  plan {self.plan_id} ({self.plan_hash[:12]})  root {self.root}",
            f"  configuration {self.manifest.configuration_hash()[:16]}",
            f"  tier ceiling  {self.manifest.tier_ceiling.value}",
        ]
        for o in self.outcomes:
            mark = {"collected": "ok  ", "missing": "MISS", "unreadable": "FAIL"}
            extra = f"  {o.digest[:12]}" if o.digest else ""
            ver = f"  v{o.version}" if o.version else "  (version unknown)"
            lines.append(f"  [{mark[o.status]}] {o.item_id}{extra}{ver}"
                         f"  {len(o.files)} file(s)")
            if o.detail:
                lines.append(f"          {o.detail}")
            for w in o.warnings:
                lines.append(f"          ! {w}")
        for w in self.warnings:
            lines.append(f"  ! {w}")
        return "\n".join(lines)


def _matches(root: Path, spec: ItemSpec) -> list[Path]:
    """Every file the spec's glob matches, sorted, directories excluded."""
    return sorted(p for p in root.glob(spec.source) if p.is_file())


def _collect_item(root: Path, spec: ItemSpec) -> ItemOutcome:
    files = _matches(root, spec)
    rel = tuple(str(p.relative_to(root)) for p in files)

    if not files:
        return ItemOutcome(
            item_id=spec.item_id, status="missing",
            detail=(
                f"nothing matched {spec.source!r} under the collection root. "
                + ("This item is required by the plan and has been LEFT OUT of the "
                   "manifest rather than invented — the machine is not asserted to "
                   "have software nobody hashed."
                   if spec.required else
                   "The plan marks this item optional, so its absence is expected.")
            ),
        )

    digests: list[tuple[str, str]] = []
    applied: dict[str, int] = {}
    warnings: list[str] = []
    bytes_in = 0
    bytes_hashed = 0
    version = ""
    fingerprint = spec.rule.fingerprint()

    for path, name in zip(files, rel, strict=True):
        try:
            result: NormalisationResult = normalise_file(path, spec.rule)
        except NormalisationError as exc:
            return ItemOutcome(
                item_id=spec.item_id, status="unreadable", files=rel,
                detail=str(exc),
            )
        digests.append((name, result.digest))
        bytes_in += result.bytes_in
        bytes_hashed += result.bytes_hashed
        for k, v in result.applied.items():
            applied[k] = applied.get(k, 0) + v
        warnings.extend(result.warnings)
        if result.dropped_everything:
            warnings.append(
                f"{name}: normalisation removed every byte, so this digest "
                "distinguishes nothing. Check the rule."
            )
        if not version and spec.version.kind != "unknown":
            version = spec.version.read(path.read_bytes())

    if len(digests) == 1:
        digest = digests[0][1]
    else:
        # The identity of a multi-file item is the set, keyed by relative path,
        # so adding or removing a member changes the item.
        digest = content_hash_of({"members": sorted(digests)})

    if spec.version.kind != "unknown" and not version:
        warnings.append(
            f"the plan expects a {spec.version.kind} version and none was found. The "
            "item is recorded with no version, which is honest and which means a "
            "supplier advisory matching on labels will not match it."
        )

    return ItemOutcome(
        item_id=spec.item_id, status="collected", files=rel, digest=digest,
        rule_fingerprint=fingerprint, version=version, bytes_in=bytes_in,
        bytes_hashed=bytes_hashed, applied=applied, warnings=tuple(warnings),
        detail=(f"{len(files)} files, hashed as a set" if len(files) > 1 else ""),
    )


def collect(
    plan: CollectionPlan,
    root: str | Path,
    *,
    serial: str,
    taken_by: Actor,
    site: str = "",
    year: str = "",
    manifest_id: str = "",
    source: ManifestSource = ManifestSource.AS_FOUND,
    taken_at: datetime | None = None,
    notes: str = "",
) -> CollectionResult:
    """Run a plan against a folder of exports.

    ``source`` defaults to ``as_found`` because that is what a collection is: a
    record of what was in the folder, and the folder came off a machine. A plan
    run against a build output to establish a baseline should say ``as_declared``
    explicitly, so that the manifest does not later claim somebody looked at a
    machine when they looked at a release.
    """
    base = Path(root)
    if not base.is_dir():
        raise CollectionError(f"{base} is not a directory.")

    outcomes = [_collect_item(base, spec) for spec in plan.items]

    items: list[SafetyItem] = []
    warnings: list[str] = []

    for spec, outcome in zip(plan.items, outcomes, strict=True):
        if not outcome.ok:
            if spec.required:
                warnings.append(
                    f"{spec.item_id} is required by plan {plan.plan_id} and was "
                    f"{outcome.status}. It is absent from this manifest, so no "
                    "comparison made from this manifest says anything about it."
                )
            continue
        items.append(SafetyItem(
            item_id=spec.item_id, kind=spec.kind, name=spec.name,
            version=outcome.version, content_hash=outcome.digest,
            hash_source=HashSource.READ_FROM_MACHINE,
            supplier=spec.supplier, implements=spec.implements,
            modifiable_in_field=spec.modifiable_in_field,
            notes=(f"{spec.notes} " if spec.notes else "")
                  + f"[collected by plan {plan.plan_id} "
                    f"{plan.content_hash()[:12]}, rule {outcome.rule_fingerprint}"
                  + (f", {spec.rule.note}" if spec.rule.note else "") + "]",
        ))

    if not items:
        raise CollectionError(
            f"plan {plan.plan_id} matched nothing at all under {base}. Either the "
            "exports are not there or the plan's paths are wrong; a manifest with no "
            "items would assert this machine has no safety-relevant software."
        )

    for spec in plan.unmapped_items:
        warnings.append(
            f"{spec.item_id} is credited to no safety function, so a change to it "
            "will be reported as drift and will invalidate no verification. If it "
            "does implement one, say so in the plan."
        )
    for fn in plan.undemonstrable_functions:
        warnings.append(
            f"safety function {fn.function_id} declares no verification check, so "
            "nothing can ever demonstrate it."
        )
    warnings.append(
        "a collection records what the plan looked for. Safety-relevant software "
        "the plan does not name is absent from this manifest and from everything "
        "derived from it."
    )

    manifest = SafetyManifest(
        manifest_id=manifest_id or f"{plan.plan_id}-{serial}-"
                                   f"{format_utc(taken_at or utc_now())[:10]}",
        machine=MachineIdentity(manufacturer=plan.manufacturer, model=plan.model,
                                serial=serial, year=year, site=site),
        source=source,
        taken_at=taken_at or utc_now(),
        taken_by=taken_by,
        items=tuple(items),
        functions=plan.functions,
        method=f"collected by plan {plan.plan_id} ({plan.content_hash()[:12]}) "
               f"from {base.name}"
               + (f"; {plan.procedure}" if plan.procedure else ""),
        notes=notes,
    )

    return CollectionResult(
        manifest=manifest, plan_id=plan.plan_id, plan_hash=plan.content_hash(),
        root=str(base), outcomes=tuple(outcomes), warnings=tuple(warnings),
    )
