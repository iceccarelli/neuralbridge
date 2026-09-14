"""From a signed advisory to a drafted Article 14 intake, without deciding anything.

The watch now finds a stop-use advisory against a still machine at 09:00. Then
what? Today: nothing. Somebody reads the output, opens a spreadsheet, and starts
working out which Member States the affected serial numbers went to — which is
field 5 of the ENISA form, and the reason a 24-hour deadline is hard rather than
merely short.

This closes that gap and stops exactly where honesty requires it.

**What it does.** Assembles the intake from evidence that already exists: the
signal, the affected product versions, and the Member States, built from the
serial numbers in the fleet. Records the moment the signal was received, because
the interval between receipt and awareness is the number a market surveillance
authority asks about first, and it cannot be reconstructed afterwards.

**What it refuses.** Awareness is a determination and the track is a decision,
and this makes neither. Art. 14(2)(a) runs twenty-four hours from awareness, not
from receipt, and a tool that quietly equated the two would either start a
manufacturer's clock early — a filing obligation invented by software — or start
it late, which is worse. C(2026) 5252 Annex §213 defines awareness as a
reasonable degree of certainty after an initial assessment, and §214 requires
that assessment to be prompt. The word "prompt" is doing the work, and only a
person can be prompt.

**What it therefore watches instead.** A signal received and never assessed. If
a previous run recorded receipt of a safety-relevant advisory and no awareness
record has appeared since, every subsequent run says so and says how long it has
been. Nobody is told they are late — they are told what is outstanding, with the
provision that makes it matter. That is the alarm that is worth paying for: not
"you have a deadline", which everybody knows, but "this one has been sitting for
thirty-nine hours and nobody has made the determination".

**Who this is for.** Only a manufacturer carries the Art. 14 duty. An integrator
who installs somebody else's cells may or may not be one, and this will not
guess: the configuration has to say so explicitly, and until it does, no intake
is drafted at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from ..bridge.art14 import BridgeError, CaseDraft, draft_from_advisory
from ..core.identity import format_utc, parse_utc
from ..fleet.advisory import AdvisorySeverity, ComponentAdvisory
from ..fleet.impact import assess_impact
from ..fleet.registry import Fleet
from .advisories import AdvisoryFinding

__all__ = [
    "ARTICLE_14_WINDOW",
    "FILING_KIND",
    "FilingPrompt",
    "FilingsPass",
    "draft_filings",
]

FILING_KIND = "watch.article14.intake"

#: Reg. (EU) 2024/2847 Art. 14(2)(a). Measured from awareness, never from
#: receipt. Held here so that nothing in this module has to spell "24" twice.
ARTICLE_14_WINDOW = timedelta(hours=24)

#: Severities that imply a product-security matter worth an intake. An
#: informational advisory is not one, and drafting a regulatory intake for every
#: newsletter is how a manufacturer learns to ignore the drafts.
_WORTH_AN_INTAKE = frozenset({
    AdvisorySeverity.STOP_USE, AdvisorySeverity.SAFETY_RELEVANT,
})


@dataclass(frozen=True)
class FilingPrompt:
    """One advisory, the intake it implies, and what is outstanding on it."""

    advisory_id: str
    supplier_id: str
    severity: str
    received_at: str
    draft: CaseDraft | None
    #: Hours since the signal was received. Not since awareness: awareness has
    #: not been established, and that is the point of this record.
    hours_since_receipt: float
    #: ``drafted`` on the run that first saw it, ``unassessed`` on every run
    #: afterwards until somebody records awareness, ``blocked`` when the intake
    #: could not be assembled.
    state: str
    detail: str = ""

    @property
    def is_escalating(self) -> bool:
        """Outstanding for longer than the window the Regulation allows.

        Deliberately not called ``breach``. The window runs from awareness and
        awareness has not been established, so nothing here is late yet. What
        this says is that the assessment §214 calls prompt has now taken longer
        than the whole filing window, which is a fact worth putting in front of
        somebody.
        """
        return (self.state == "unassessed"
                and self.hours_since_receipt
                > ARTICLE_14_WINDOW.total_seconds() / 3600)

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisory_id": self.advisory_id,
            "supplier_id": self.supplier_id,
            "severity": self.severity,
            "received_at": self.received_at,
            "hours_since_receipt": round(self.hours_since_receipt, 2),
            "state": self.state,
            "escalating": self.is_escalating,
            "detail": self.detail,
            "draft": self.draft.to_dict() if self.draft else None,
        }

    def summary(self) -> str:
        head = (f"{self.advisory_id} ({self.supplier_id}) — received "
                f"{self.received_at}, {self.hours_since_receipt:.1f}h ago")
        if self.state == "blocked":
            return f"{head}\n  intake could not be drafted: {self.detail}"
        if self.state == "unassessed":
            return (
                f"{head}\n  NO AWARENESS RECORD. Art. 14(2)(a) runs 24 hours "
                "from awareness, not from receipt — but C(2026) 5252 Annex §214 "
                "requires the initial assessment to be prompt, and this has been "
                f"outstanding for {self.hours_since_receipt:.1f} hours."
            )
        return f"{head}\n  intake drafted; a person must establish awareness."


@dataclass(frozen=True)
class FilingsPass:
    """What one run established about Article 14 intakes."""

    enabled: bool = False
    prompts: tuple[FilingPrompt, ...] = ()
    checks_skipped: tuple[str, ...] = ()

    @property
    def drafted(self) -> tuple[FilingPrompt, ...]:
        return tuple(p for p in self.prompts if p.state == "drafted")

    @property
    def unassessed(self) -> tuple[FilingPrompt, ...]:
        return tuple(p for p in self.prompts if p.state == "unassessed")

    @property
    def escalating(self) -> tuple[FilingPrompt, ...]:
        return tuple(p for p in self.prompts if p.is_escalating)

    @property
    def is_finding(self) -> bool:
        return bool(self.drafted or self.unassessed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "prompts": [p.to_dict() for p in self.prompts],
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        if not self.enabled:
            return "no Article 14 duty declared; no intake drafted"
        parts = []
        if self.escalating:
            parts.append(f"{len(self.escalating)} unassessed beyond 24h")
        elif self.unassessed:
            parts.append(f"{len(self.unassessed)} awaiting assessment")
        if self.drafted:
            parts.append(f"{len(self.drafted)} newly drafted")
        return "; ".join(parts) if parts else "nothing outstanding"


def _hours_between(earlier: str, now: datetime) -> float:
    try:
        return max(0.0, (now - parse_utc(earlier)).total_seconds() / 3600)
    except ValueError:
        return 0.0


def draft_filings(
    findings: tuple[AdvisoryFinding, ...],
    advisories: dict[str, ComponentAdvisory],
    fleet: Fleet,
    *,
    as_manufacturer: bool,
    received_by: str,
    now: datetime,
    previously_received: dict[str, str] | None = None,
    assessed: frozenset[str] = frozenset(),
) -> FilingsPass:
    """Draft an intake for every advisory that implies one, and decide nothing.

    ``previously_received`` carries forward the moment each advisory was first
    seen, so the interval from receipt is measured from the first run that saw
    it rather than resetting every time the watch runs — which would turn the
    one number a market surveillance authority asks about into a number that is
    always small.

    ``assessed`` names advisories for which an awareness record already exists.
    Those stop being reported here, because the determination has been made and
    the register is where the clock lives from that point on.
    """
    if not as_manufacturer:
        return FilingsPass(
            enabled=False,
            checks_skipped=(
                "No Article 14 duty is declared in this watch, so no regulatory "
                "intake was drafted. Only a manufacturer placing the product on "
                "the Union market carries the Art. 14 reporting duty; whether "
                "that is you is a legal question about your role, not something "
                "this can infer from a fleet. Declare it explicitly if it "
                "applies.",
            ),
        )

    seen = dict(previously_received or {})
    prompts: list[FilingPrompt] = []

    for finding in findings:
        if finding.state == "withdrawn":
            continue
        advisory = advisories.get(finding.advisory_id)
        if advisory is None or advisory.severity not in _WORTH_AN_INTAKE:
            continue
        if not finding.machines:
            continue
        if finding.advisory_id in assessed:
            continue

        received_at = seen.get(finding.advisory_id) or format_utc(now)
        hours = _hours_between(received_at, now)
        first_time = finding.advisory_id not in seen

        draft: CaseDraft | None = None
        state = "drafted" if first_time else "unassessed"
        detail = ""
        try:
            draft = draft_from_advisory(
                advisory, assess_impact(advisory, fleet), fleet,
                received_by=received_by,
                case_id=f"CASE-{finding.advisory_id}",
            )
        except BridgeError as exc:
            state = "blocked"
            detail = str(exc)

        prompts.append(FilingPrompt(
            advisory_id=finding.advisory_id,
            supplier_id=finding.supplier_id,
            severity=finding.severity,
            received_at=received_at,
            draft=draft,
            hours_since_receipt=hours,
            state=state,
            detail=detail,
        ))

    caveats = [
        "Awareness was not established and no track was chosen. Art. 14(2)(a) "
        "runs 24 hours from awareness, not from receipt; C(2026) 5252 Annex "
        "§213 defines awareness as a reasonable degree of certainty after an "
        "initial assessment, and §214 requires that assessment to be prompt. "
        "Only a person can make it.",
        "The Member States in a draft are assembled from the countries recorded "
        "against affected serial numbers in this ledger. A machine with no "
        "country recorded contributes nothing to field 5, and the draft says "
        "when that has happened.",
        "An intake is drafted from a supplier's advisory about a component. "
        "Whether the finished product you placed on the market is itself "
        "reportable under Art. 14 is a judgement about your product, not about "
        "the component.",
    ]
    return FilingsPass(
        enabled=True, prompts=tuple(prompts), checks_skipped=tuple(caveats))
