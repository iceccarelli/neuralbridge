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

import time
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

__all__ = [
    "OPERATOR_ASSERTION",
    "DEFAULT_MAX_SECONDS",
    "MAX_FILES_PER_ITEM",
    "MAX_ITEM_BYTES",
    "MAX_VERSION_SCAN_BYTES",
    "CollectionError",
    "CollectionResult",
    "ItemOutcome",
    "collect",
]

#: Resource limits for one collection, as sanity limits (see ``normalise``). A
#: hostile or runaway folder hits one of these and the item is reported
#: unreadable; the run does not hang and does not exhaust memory.
MAX_FILES_PER_ITEM = 10_000
MAX_ITEM_BYTES = 4 * 1024**3
MAX_VERSION_SCAN_BYTES = 8 * 1024**2
DEFAULT_MAX_SECONDS = 1800.0

#: Recorded wherever a collection is labelled ``read_from_machine``. The label is
#: the operator's claim, made with an explicit flag; nothing in a folder of files can
#: show which machine, if any, they came off.
OPERATOR_ASSERTION = (
    "OPERATOR ASSERTION (--read-from-machine): the operator states the collector "
    "ran on the machine itself; this software cannot check that")

#: Indirection so a test can drive the clock.
_now = time.monotonic


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


class _TooManyFilesError(Exception):
    """The glob matched more files than one item may hold."""


def _matches(root: Path, spec: ItemSpec) -> list[Path]:
    """Every file the spec's glob matches, sorted, directories excluded."""
    found: list[Path] = []
    for p in root.glob(spec.source):
        if p.is_file():
            found.append(p)
            if len(found) > MAX_FILES_PER_ITEM:
                raise _TooManyFilesError
    return sorted(found)


def _inside(root: Path, p: Path) -> bool:
    try:
        p.resolve().relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def _read_version(path: Path, spec: ItemSpec, warnings: list[str]) -> str:
    """Read the version label from a file no larger than ``MAX_VERSION_SCAN_BYTES``.

    A larger file is not scanned in part: a pattern run over a prefix can match a
    label cut off mid-token. It reads as unknown, and the item says why.
    """
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_VERSION_SCAN_BYTES + 1)
    except OSError as exc:
        warnings.append(f"{path.name}: the version could not be read ({exc}).")
        return ""
    if len(data) > MAX_VERSION_SCAN_BYTES:
        warnings.append(
            f"{path.name}: larger than the {MAX_VERSION_SCAN_BYTES} bytes scanned for "
            "a version; no version was read rather than one guessed from part of it.")
        return ""
    return spec.version.read(data)


def _unreadable(spec: ItemSpec, rel: tuple[str, ...], detail: str) -> ItemOutcome:
    return ItemOutcome(item_id=spec.item_id, status="unreadable", files=rel,
                       detail=detail)


def _collect_item(root: Path, spec: ItemSpec, deadline: float) -> ItemOutcome:
    try:
        files = _matches(root, spec)
    except _TooManyFilesError:
        return _unreadable(
            spec, (), f"more than {MAX_FILES_PER_ITEM} files match {spec.source!r}; "
                      "an item that large is not a safety export, and the glob is "
                      "refused rather than half-read.")
    except OSError as exc:
        return _unreadable(spec, (), f"the collection root could not be searched: {exc}")
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
        if _now() > deadline:
            return _unreadable(
                spec, rel, "the collection's time budget ran out before this item "
                           "was read; it was not hashed.")
        if not _inside(root, path):
            return _unreadable(
                spec, rel, f"{name} is a link to a file outside the collection root. "
                           "It is not followed: a digest of something that is not in "
                           "this folder is not a digest of this machine's export.")
        try:
            result: NormalisationResult = normalise_file(path, spec.rule)
        except NormalisationError as exc:
            return _unreadable(spec, rel, str(exc))
        if not result.usable:
            why = (" ".join(result.warnings) if result.warnings else
                   "normalisation removed every byte, so the digest distinguishes "
                   "nothing; check the rule, or the export is empty.")
            return _unreadable(
                spec, rel, f"{name} could not be hashed completely: {why}")
        digests.append((name, result.digest))
        bytes_in += result.bytes_in
        bytes_hashed += result.bytes_hashed
        if bytes_in > MAX_ITEM_BYTES:
            return _unreadable(
                spec, rel, f"the files for this item total more than "
                           f"{MAX_ITEM_BYTES} bytes, which this system will not hash.")
        for k, v in result.applied.items():
            applied[k] = applied.get(k, 0) + v
        warnings.extend(result.warnings)
        if not version and spec.version.kind != "unknown":
            version = _read_version(path, spec, warnings)

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
    country: str = "",
    year: str = "",
    manifest_id: str = "",
    source: ManifestSource = ManifestSource.AS_FOUND,
    taken_at: datetime | None = None,
    notes: str = "",
    max_seconds: float = DEFAULT_MAX_SECONDS,
    hash_source: HashSource = HashSource.SUPPLIED_BY_VENDOR,
) -> CollectionResult:
    """Run a plan against a folder of exports.

    ``source`` defaults to ``as_found`` because that is what a collection is: a
    record of what was in the folder, and the folder came off a machine. A plan
    run against a build output to establish a baseline should say ``as_declared``
    explicitly, so that the manifest does not later claim somebody looked at a
    machine when they looked at a release.

    ``hash_source`` defaults to ``SUPPLIED_BY_VENDOR``: a folder of exported files
    was produced by a tool and handed over, and hashing it says what the export
    holds, not that the unit in front of you holds the same. Only the operator can
    know that the collector ran ON the machine, so ``READ_FROM_MACHINE`` is an
    explicit assertion (``collect run --read-from-machine``, ``kit run
    --read-from-machine``); it is recorded in the manifest's ``method`` and in each
    item's notes as the operator's claim, which the software cannot check.
    """
    base = Path(root)
    if not base.is_dir():
        raise CollectionError(f"{base} is not a directory.")
    if hash_source is HashSource.DECLARED:
        raise CollectionError(
            "a collection hashes files, so its source is read_from_machine or "
            "supplied_by_vendor; 'declared' means nothing was hashed.")
    asserted = hash_source is HashSource.READ_FROM_MACHINE

    deadline = _now() + max_seconds
    outcomes = [_collect_item(base, spec, deadline) for spec in plan.items]

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
            hash_source=hash_source,
            supplier=spec.supplier, implements=spec.implements,
            modifiable_in_field=spec.modifiable_in_field,
            notes=(f"{spec.notes} " if spec.notes else "")
                  + f"[collected by plan {plan.plan_id} "
                    f"{plan.content_hash()[:12]}, rule {outcome.rule_fingerprint}"
                  + (f", {spec.rule.note}" if spec.rule.note else "") + "]"
                  + (f" {OPERATOR_ASSERTION}" if asserted else ""),
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
                                serial=serial, year=year, site=site,
                                country=country.upper()),
        source=source,
        taken_at=taken_at or utc_now(),
        taken_by=taken_by,
        items=tuple(items),
        functions=plan.functions,
        method=f"collected by plan {plan.plan_id} ({plan.content_hash()[:12]}) "
               f"from {base.name}"
               + (f"; {plan.procedure}" if plan.procedure else "")
               + (f"; {OPERATOR_ASSERTION}" if asserted
                  else "; read from an exported folder, not asserted to have run on "
                       "the machine (supplied_by_vendor, community ceiling)"),
        notes=notes,
    )

    return CollectionResult(
        manifest=manifest, plan_id=plan.plan_id, plan_hash=plan.content_hash(),
        root=str(base), outcomes=tuple(outcomes), warnings=tuple(warnings),
    )
