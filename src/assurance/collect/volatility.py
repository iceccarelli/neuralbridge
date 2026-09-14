"""Prove the rules work before trusting the reports they produce.

Collect the same unchanged machine twice. Every item whose digest moves has a
normalisation rule that is not doing its job — it is hashing the export's own
noise along with the machine — and every future weekly report will cry wolf
about it until somebody fixes the rule or stops reading the report.

This is the step no configuration-drift tool ships and every one of them needs.
It costs one extra export and it is the difference between a drift report a
safety engineer acts on and one they filter to a folder.

The probe also does the tedious half of the fix: where the item is text, it
shows the lines that actually differed, which is almost always a timestamp, an
operator name or a sequence number, and from which the exclusion pattern writes
itself.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assurance.collect.normalise import NormalisationError, Normaliser, normalise_file
from assurance.collect.plan import CollectionPlan, ItemSpec

__all__ = ["ItemVolatility", "VolatilityReport", "probe"]

#: Lines that differ between two exports of an unchanged machine are nearly
#: always one of these. Offered as a starting point, never applied silently.
_USUAL_SUSPECTS: tuple[tuple[str, str], ...] = (
    (r"\d{4}-\d{2}-\d{2}", "a date"),
    (r"\d{2}:\d{2}:\d{2}", "a time"),
    (r"(?i)\b(timestamp|exported|export[_ ]?date|generated)\b", "an export stamp"),
    (r"(?i)\b(user|operator|engineer|author|login)\b", "who exported it"),
    (r"(?i)\b(checksum|crc|signature|hash)\b", "a checksum of the export itself"),
    (r"(?i)\b(serial|sequence|session|run)[_ ]?(no|number|id)\b", "a sequence number"),
)


@dataclass(frozen=True)
class ItemVolatility:
    """Whether one item's digest survived two exports of an unchanged machine."""

    item_id: str
    stable: bool
    digest_a: str
    digest_b: str
    rule_kind: Normaliser
    #: Lines present in one export and not the other, trimmed to a readable few.
    differing_lines: tuple[str, ...] = ()
    #: Patterns that would have excluded those lines, with what they look like.
    suggested_patterns: tuple[tuple[str, str], ...] = ()
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id, "stable": self.stable,
            "digest_a": self.digest_a, "digest_b": self.digest_b,
            "rule_kind": self.rule_kind.value,
            "differing_lines": list(self.differing_lines),
            "suggested_patterns": [{"pattern": p, "looks_like": w}
                                   for p, w in self.suggested_patterns],
            "detail": self.detail,
        }


@dataclass(frozen=True)
class VolatilityReport:
    """Which of this plan's rules can be trusted to report real change."""

    plan_id: str
    plan_hash: str
    root_a: str
    root_b: str
    items: tuple[ItemVolatility, ...]
    checks_skipped: tuple[str, ...]

    @property
    def volatile(self) -> tuple[ItemVolatility, ...]:
        return tuple(i for i in self.items if not i.stable)

    @property
    def verdict(self) -> str:
        """``stable`` when every rule holds, otherwise ``volatile``."""
        return "stable" if not self.volatile else "volatile"

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id, "plan_hash": self.plan_hash,
            "root_a": self.root_a, "root_b": self.root_b,
            "verdict": self.verdict,
            "volatile_items": [i.item_id for i in self.volatile],
            "items": [i.to_dict() for i in self.items],
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        head = {
            "stable": "STABLE — every rule survived two exports of the same machine",
            "volatile": "VOLATILE — these rules will report drift that did not happen",
        }[self.verdict]
        lines = [f"plan {self.plan_id} — {head}",
                 f"  {self.root_a}  vs  {self.root_b}"]
        for item in self.items:
            mark = "ok  " if item.stable else "MOVE"
            lines.append(f"  [{mark}] {item.item_id}  ({item.rule_kind.value})")
            if item.detail:
                lines.append(f"          {item.detail}")
            for line in item.differing_lines:
                lines.append(f"          ~ {line}")
            for pattern, looks in item.suggested_patterns:
                lines.append(f"          suggest: {pattern}   ({looks})")
        if self.volatile:
            lines.append("")
            lines.append("  Add the suggested patterns to those items' rules and run "
                         "this again. Until it says STABLE, every drift report from "
                         "this plan contains noise.")
        return "\n".join(lines)


def _text_of(path: Path, spec: ItemSpec) -> list[str] | None:
    """The item's lines after its own exclusions, or None if it is not text."""
    try:
        text = path.read_bytes().decode(spec.rule.encoding)
    except (UnicodeDecodeError, LookupError, OSError):
        return None
    if spec.rule.kind is Normaliser.TEXT_EXCLUDING:
        compiled = [re.compile(p) for p in spec.rule.patterns]
        return [ln for ln in text.splitlines()
                if not any(rx.search(ln) for rx in compiled)]
    return text.splitlines()


def _suggest(lines: list[str]) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for pattern, looks in _USUAL_SUSPECTS:
        rx = re.compile(pattern)
        if any(rx.search(ln) for ln in lines):
            out.append((pattern, looks))
    return tuple(out)


def probe(
    plan: CollectionPlan,
    root_a: str | Path,
    root_b: str | Path,
    *,
    max_lines: int = 6,
) -> VolatilityReport:
    """Compare two collections of a machine that did not change in between.

    Both roots must be exports of the *same unchanged machine*. Nothing here can
    check that — if the machine really did change between them, this will report
    a correct digest difference as a volatile rule, which is why the report says
    so in as many words rather than assuming the caller got it right.
    """
    a, b = Path(root_a), Path(root_b)
    if not a.is_dir() or not b.is_dir():
        raise NormalisationError(f"both roots must be directories: {a}, {b}")

    items: list[ItemVolatility] = []
    skipped: list[str] = [
        "this assumes the two exports are of the same machine with nothing changed "
        "between them. If the machine did change, a correct detection is reported "
        "here as a volatile rule. Take both exports back to back.",
    ]

    for spec in plan.items:
        files_a = sorted(p for p in a.glob(spec.source) if p.is_file())
        files_b = sorted(p for p in b.glob(spec.source) if p.is_file())

        if not files_a or not files_b:
            skipped.append(
                f"{spec.item_id}: matched "
                f"{len(files_a)} file(s) in the first export and {len(files_b)} in the "
                "second, so its rule was not exercised."
            )
            continue

        names_a = [p.relative_to(a).as_posix() for p in files_a]
        names_b = [p.relative_to(b).as_posix() for p in files_b]
        if names_a != names_b:
            items.append(ItemVolatility(
                item_id=spec.item_id, stable=False, digest_a="", digest_b="",
                rule_kind=spec.rule.kind,
                detail=(f"the two exports contain different files for this item "
                        f"({len(names_a)} vs {len(names_b)}). Either the machine "
                        "changed or the glob is catching something it should not."),
            ))
            continue

        try:
            da = [normalise_file(p, spec.rule).digest for p in files_a]
            db = [normalise_file(p, spec.rule).digest for p in files_b]
        except NormalisationError as exc:
            skipped.append(f"{spec.item_id}: {exc}")
            continue

        if da == db:
            items.append(ItemVolatility(
                item_id=spec.item_id, stable=True,
                digest_a=da[0], digest_b=db[0], rule_kind=spec.rule.kind,
            ))
            continue

        differing: list[str] = []
        for pa, pb in zip(files_a, files_b, strict=True):
            la, lb = _text_of(pa, spec), _text_of(pb, spec)
            if la is None or lb is None:
                continue
            for line in difflib.unified_diff(la, lb, lineterm="", n=0):
                if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                    differing.append(line[1:].strip()[:110])
                if len(differing) >= max_lines:
                    break
            if len(differing) >= max_lines:
                break

        detail = (
            "the digest moved between two exports of an unchanged machine. This rule "
            "is hashing the export's own noise, and every drift report from it will "
            "be wrong."
        )
        if not differing and spec.rule.kind is Normaliser.RAW:
            detail += (" The file is not text, so the differing bytes cannot be shown; "
                       "a zip_members rule is usually the answer for an archive.")

        items.append(ItemVolatility(
            item_id=spec.item_id, stable=False,
            digest_a=da[0], digest_b=db[0], rule_kind=spec.rule.kind,
            differing_lines=tuple(differing),
            suggested_patterns=_suggest(differing),
            detail=detail,
        ))

    return VolatilityReport(
        plan_id=plan.plan_id, plan_hash=plan.content_hash(),
        root_a=str(a), root_b=str(b), items=tuple(items),
        checks_skipped=tuple(dict.fromkeys(skipped)),
    )
