"""Power-and-force limits per body region, and the provenance of the numbers.

ISO/TS 15066 Annex A tabulates a maximum permissible pressure and force for
each body region. Those values are the property of the standards body, they are
revised, and a notified body may require a specific edition or a project's own
biomechanical study instead. So this module ships no table.

What it ships is the schema, the loader, and the rule that makes the loader
worth having: a limits table carries who transcribed it, from which edition, and
whether anybody competent checked the transcription. A table nobody verified can
still be used — refusing to run is not helpful — but the resulting evidence
bundle cannot reach VALIDATED, and the bundle says why in a sentence an auditor
can read. A number copied out of a standard by an intern is not the same
evidence as a number checked against a licensed copy, and the difference is
recorded rather than assumed.

Transient contact limits are taken as a multiple of the quasi-static values;
the multiplier is declared in the file rather than hardcoded, because it is
exactly the kind of constant that changes between editions. No check currently
uses it: ``verify`` holds every contact sample to the quasi-static limit, which
is the conservative choice, and says so in the bundle.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from assurance.core.errors import AssuranceError
from assurance.core.identity import content_hash_of
from assurance.core.tiers import AssuranceTier
from assurance.machine.quantities import FORCE_MAX_N, PRESSURE_MAX_N_CM2, number

if TYPE_CHECKING:
    from assurance.machine.limits_review import LimitsReviewAssessment

__all__ = ["BodyRegionLimit", "LimitsError", "LimitsTable", "SCHEMA"]


class LimitsError(AssuranceError):
    """A limits table is malformed, or a region was asked for that it lacks."""


def _num(value: Any, name: str, **kw: Any) -> float:
    return number(value, name, exc=LimitsError, **kw)


#: A plausibility rail on the declared multiplier, like those in
#: :mod:`assurance.machine.quantities`: it is not taken from any standard. It only
#: keeps a typo or a unit slip from reading as a limit.
TRANSIENT_MULTIPLIER_MAX = 1000.0


SCHEMA = """\
{
  "schema": "assurance.machine.limits/1",
  "edition": "<the standard and edition these came from>",
  "transcribed_by": "<who typed them in>",
  "verified_by": "<who checked them against a licensed copy; empty if nobody>",
  "verified_on": "<ISO date, empty if unverified>",
  "transient_multiplier": 2.0,
  "regions": {
    "<region key>": {
      "label": "<human-readable region>",
      "max_pressure_n_cm2": <number>,
      "max_force_n": <number>
    }
  }
}
"""


@dataclass(frozen=True)
class BodyRegionLimit:
    """The quasi-static ceiling for one body region."""

    key: str
    label: str
    max_pressure_n_cm2: float
    max_force_n: float

    def __post_init__(self) -> None:
        _num(self.max_pressure_n_cm2, f"region {self.key!r} max_pressure_n_cm2",
             maximum=PRESSURE_MAX_N_CM2, positive=True)
        _num(self.max_force_n, f"region {self.key!r} max_force_n",
             maximum=FORCE_MAX_N, positive=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "max_pressure_n_cm2": self.max_pressure_n_cm2,
            "max_force_n": self.max_force_n,
        }


@dataclass(frozen=True)
class LimitsTable:
    """A body-region limits table, and what it is worth."""

    edition: str
    transcribed_by: str
    verified_by: str
    verified_on: str
    transient_multiplier: float
    regions: dict[str, BodyRegionLimit] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.regions:
            raise LimitsError("a limits table with no regions cannot check anything.")
        if not self.edition:
            raise LimitsError(
                "a limits table must name the edition it came from. 'ISO/TS 15066' "
                "without a year is not an edition."
            )
        _num(self.transient_multiplier, "transient_multiplier",
             maximum=TRANSIENT_MULTIPLIER_MAX, positive=True)
        if self.verified_on:
            try:
                when = date.fromisoformat(self.verified_on)
            except ValueError as exc:
                raise LimitsError(
                    f"verified_on {self.verified_on!r} is not an ISO date (YYYY-MM-DD). "
                    "A verification that cannot be dated cannot be told from none."
                ) from exc
            if when > datetime.now(UTC).date() + timedelta(days=1):
                raise LimitsError(
                    f"verified_on {self.verified_on} is in the future. A transcription "
                    "cannot already have been checked on a day that has not happened."
                )

    @property
    def claims_verification(self) -> bool:
        """Whether the file *says* somebody checked it. Free text, not evidence.

        ``verified_by`` and ``verified_on`` are written by whoever wrote the table.
        Nothing here can check that the person exists, that they held a licensed
        copy, or that they compared anything. It is an unverified claim about a
        verification, and it is recorded as one.
        """
        return bool(self.verified_by and self.verified_on)

    @property
    def tier_ceiling(self) -> AssuranceTier:
        """What the table alone can support: never more than COMMUNITY.

        A free-text claim cannot lift a table to VALIDATED by itself. Use
        :meth:`tier_for` with the hash the envelope pins to see the one
        combination that can.
        """
        return AssuranceTier.COMMUNITY

    def tier_for(
        self, pinned_hash: str, assessment: LimitsReviewAssessment | None = None,
    ) -> tuple[AssuranceTier, str]:
        """The ceiling this table gives a verification, and the sentence explaining it.

        VALIDATED needs two independent facts: the envelope pins exactly this
        table's content hash, and an independent review (a signature by a key in
        the verifier's own trust configuration, over this table's hash) was
        accepted. The table's ``verified_by`` / ``verified_on`` text is the
        author's own claim and never contributes: with a pin and no accepted
        review the tier stays COMMUNITY.
        """
        pinned = bool(pinned_hash) and pinned_hash == self.content_hash()
        if not pinned:
            return AssuranceTier.COMMUNITY, (
                "the envelope does not pin this table's hash, so nothing ties the "
                "table to the declared product and the tier is capped at community."
                + self._claim_note())
        if (assessment is not None and assessment.table_hash == self.content_hash()
                and assessment.validated):
            return AssuranceTier.VALIDATED, assessment.explanation
        why = (assessment.explanation if assessment is not None else
               "no independent review of the limits table was supplied, so it is an "
               "unreviewed transcription and caps the tier at community.")
        return AssuranceTier.COMMUNITY, why + self._claim_note()

    def _claim_note(self) -> str:
        if not self.claims_verification:
            return ""
        return (
            f" The table's own verified_by ({self.verified_by}) / verified_on "
            f"({self.verified_on}) text is the author's claim, written by whoever "
            "wrote the table; it was not used.")

    def provenance_caveat(self, assessment: LimitsReviewAssessment | None = None) -> str:
        """The sentence that goes into the bundle's ``checks_skipped``."""
        unused = (
            " The transient_multiplier in the file is not used by any check: every "
            "contact sample is held to the quasi-static limits."
        )
        if assessment is not None and assessment.validated:
            return (
                f"body-region limits are from {self.edition}, transcribed by "
                f"{self.transcribed_by or 'an unnamed party'}. An independent review "
                "signature over this exact table was accepted (see the tier reason); "
                "that attests to the table's bytes, not to the standard's values or "
                "to the suitability of this edition for this product." + unused
            )
        return (
            f"body-region limits are an UNREVIEWED transcription of {self.edition} by "
            f"{self.transcribed_by or 'an unnamed party'}. No accepted independent "
            "review covers them; the table's verified_by / verified_on text, if any, "
            "is the author's own claim and was not used. Every pass below rests on "
            "numbers that have not been independently confirmed." + unused
        )

    def limit_for(self, region: str) -> BodyRegionLimit:
        try:
            return self.regions[region]
        except KeyError:
            raise LimitsError(
                f"no limit for body region {region!r}. The table covers: "
                f"{', '.join(sorted(self.regions))}. A contact credited to a region "
                "the table does not cover has not been checked, and will not be "
                "reported as a pass."
            ) from None

    def permitted_force_n(self, region: str, *, transient: bool) -> float:
        base = self.limit_for(region).max_force_n
        return base * self.transient_multiplier if transient else base

    def permitted_pressure_n_cm2(self, region: str, *, transient: bool) -> float:
        base = self.limit_for(region).max_pressure_n_cm2
        return base * self.transient_multiplier if transient else base

    def hashable_payload(self) -> dict[str, Any]:
        return {
            "edition": self.edition,
            "transcribed_by": self.transcribed_by,
            "verified_by": self.verified_by,
            "verified_on": self.verified_on,
            "transient_multiplier": self.transient_multiplier,
            "regions": {k: v.to_dict() for k, v in sorted(self.regions.items())},
        }

    def content_hash(self) -> str:
        """Identity of the table. An envelope pins this so a silent edit is visible."""
        return content_hash_of(self.hashable_payload())

    def to_dict(self) -> dict[str, Any]:
        return {"schema": "assurance.machine.limits/1", **self.hashable_payload()}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> LimitsTable:
        raw = d.get("regions")
        if not isinstance(raw, dict):
            raise LimitsError(f"limits file has no 'regions' object. Schema:\n{SCHEMA}")
        regions: dict[str, BodyRegionLimit] = {}
        for k, v in raw.items():
            if not isinstance(v, dict):
                raise LimitsError(
                    f"region {k!r} must be an object with max_pressure_n_cm2 and "
                    f"max_force_n, got {type(v).__name__}."
                )
            for needed in ("max_pressure_n_cm2", "max_force_n"):
                if needed not in v:
                    raise LimitsError(f"region {k!r} is missing {needed}.")
            regions[str(k)] = BodyRegionLimit(
                key=str(k),
                label=str(v.get("label", k)),
                max_pressure_n_cm2=_num(v["max_pressure_n_cm2"],
                                        f"region {k!r} max_pressure_n_cm2",
                                        maximum=PRESSURE_MAX_N_CM2, positive=True),
                max_force_n=_num(v["max_force_n"], f"region {k!r} max_force_n",
                                 maximum=FORCE_MAX_N, positive=True),
            )
        return cls(
            edition=str(d.get("edition", "")),
            transcribed_by=str(d.get("transcribed_by", "")),
            verified_by=str(d.get("verified_by", "")),
            verified_on=str(d.get("verified_on", "")),
            transient_multiplier=_num(d.get("transient_multiplier", 2.0),
                                      "transient_multiplier",
                                      maximum=TRANSIENT_MULTIPLIER_MAX, positive=True),
            regions=regions,
        )

    @classmethod
    def from_json(cls, path: str | Path) -> LimitsTable:
        p = Path(path)
        if not p.exists():
            raise LimitsError(
                f"{p} does not exist. This package ships no body-region limits: the "
                "values belong to the standards body and the edition that applies is "
                f"a project decision. Write one in this schema:\n{SCHEMA}"
            )
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise LimitsError(f"{p} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise LimitsError(f"{p} must contain a JSON object.")
        return cls.from_dict(raw)
