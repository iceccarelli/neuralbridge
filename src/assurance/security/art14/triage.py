"""Is it reportable?

The tests that decide whether Article 14 is engaged, expressed as code so that
the answer is reproducible and the reasoning survives the person who gave it.

Two things this module deliberately does not do. It does not decide for you:
every test returns an explicit *undetermined* until a human answers it, because
"reliable evidence that a malicious actor has exploited it" is a judgement and a
library that guesses it would be manufacturing a regulatory position. And it
never silently concludes "not reportable": a negative outcome produces a
decision record naming the ground, its authority, and — where the ground can
stop being true without anyone acting — a mandatory reopen trigger.

That last point is the one that bites. Commission guidance §217 exempts
active exploitation a manufacturer already knew about before 11 September 2026,
but the same paragraph says the duty *does* apply where the vulnerability was
known and the exploitation was not. Every open vulnerability in a backlog is
therefore a latent obligation, and a decision record closed on that ground
without a trigger converts it into a forgotten one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .model import NonReportGround, Track

__all__ = ["Answer", "Question", "TriageQuestion", "TriageResult", "triage"]

#: 11 September 2026: the date Article 14 began to apply (Art. 71(2)).
ARTICLE_14_APPLICABLE_FROM = "2026-09-11"


class Answer(StrEnum):
    YES = "yes"
    NO = "no"
    UNDETERMINED = "undetermined"


class Question(StrEnum):
    """The decision points, in the order they must be worked through."""

    IN_SCOPE_PRODUCT = "is_our_product_with_digital_elements_on_the_eu_market"
    RELIABLE_EVIDENCE = "reliable_evidence_of_malicious_exploitation"
    EXPLOITED_IN_OUR_PRODUCT = "exploited_in_our_product_not_merely_in_a_component"
    AWARENESS_AFTER_CUTOFF = "awareness_of_active_exploitation_on_or_after_2026_09_11"
    AFFECTS_PRODUCT_SECURITY = "incident_affects_security_of_the_product"
    SEVERE_SENSITIVE_OR_IMPORTANT = "affects_sensitive_or_important_data_or_functions"
    SEVERE_MALICIOUS_CODE = "could_lead_to_malicious_code_in_product_or_user_network"


@dataclass(frozen=True)
class TriageQuestion:
    """One decision point, its authority, and what a "no" means."""

    question: Question
    prompt: str
    authority: str
    ground_if_no: NonReportGround | None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question.value,
            "prompt": self.prompt,
            "authority": self.authority,
            "ground_if_no": self.ground_if_no.value if self.ground_if_no else None,
            "note": self.note,
        }


_VULNERABILITY_PATH: tuple[TriageQuestion, ...] = (
    TriageQuestion(
        Question.IN_SCOPE_PRODUCT,
        "Is the vulnerability in a product with digital elements that we placed on the Union market?",
        "Art. 2; Art. 14(1)",
        NonReportGround.OUT_OF_SCOPE,
        "Products placed on the market before 11 December 2027 are in scope for reporting "
        "(Art. 69(3)), and the duty outlives the support period (guidance §210).",
    ),
    TriageQuestion(
        Question.RELIABLE_EVIDENCE,
        "Is there reliable evidence that a malicious actor has exploited it in a system, "
        "without the system owner's permission?",
        "Art. 3(42); Recital 68; Commission FAQ 5.2",
        NonReportGround.NO_RELIABLE_EVIDENCE,
        "A published exploit, proof-of-concept code or port scanning is not that evidence. "
        "Nor is a finding from good-faith testing, a bug bounty or a test lab acting for us.",
    ),
    TriageQuestion(
        Question.EXPLOITED_IN_OUR_PRODUCT,
        "Was it exploited in our product, as distinct from in a third-party component we ship?",
        "Commission guidance C(2026) 5252 Annex §218",
        NonReportGround.NOT_EXPLOITED_IN_PRODUCT,
        "If the vulnerable code is not reachable in our product, or has not been exploited in "
        "it, this is not our reportable event — but Art. 13(6) upstream reporting and "
        "Annex I Part II vulnerability handling still apply.",
    ),
    TriageQuestion(
        Question.AWARENESS_AFTER_CUTOFF,
        "Did we become aware of the active exploitation on or after 11 September 2026?",
        "Art. 71(2); Commission guidance C(2026) 5252 Annex §217",
        NonReportGround.PRE_CUTOFF_AWARENESS,
        "Knowing about the vulnerability before the cutoff does not exempt it. Only prior "
        "awareness of the active exploitation does, and only until exploitation recurs or "
        "comes to our attention afterwards.",
    ),
)

_INCIDENT_PATH: tuple[TriageQuestion, ...] = (
    TriageQuestion(
        Question.IN_SCOPE_PRODUCT,
        "Does this concern a product with digital elements that we placed on the Union market?",
        "Art. 2; Art. 14(3)",
        NonReportGround.OUT_OF_SCOPE,
    ),
    TriageQuestion(
        Question.AFFECTS_PRODUCT_SECURITY,
        "Does the incident negatively affect, or is it capable of negatively affecting, the "
        "ability of our product to protect the availability, authenticity, integrity or "
        "confidentiality of data or functions?",
        "Art. 3(44)",
        NonReportGround.NO_PRODUCT_SECURITY_IMPACT,
        "An incident in our own corporate IT qualifies only where it can affect the product "
        "— for example where build infrastructure, an update server or a signing key is "
        "implicated. Disruption to us is not, by itself, in scope.",
    ),
    TriageQuestion(
        Question.SEVERE_SENSITIVE_OR_IMPORTANT,
        "Does it affect, or is it capable of affecting, SENSITIVE OR IMPORTANT data or functions?",
        "Art. 14(5)(a)",
        None,  # a "no" here falls through to limb (b) rather than closing the case
        "The Regulation does not define 'sensitive or important', and neither the Commission "
        "FAQ nor the July 2026 guidance elaborates the Art. 14(5) test. Record the reasoning; "
        "there is no official interpretive support to lean on.",
    ),
    TriageQuestion(
        Question.SEVERE_MALICIOUS_CODE,
        "Has it led, or is it capable of leading, to the introduction or execution of malicious "
        "code in the product, or in a user's network and information systems?",
        "Art. 14(5)(b)",
        NonReportGround.NOT_SEVERE,
        "This limb has no severity qualifier. Any such capability engages it.",
    ),
)


def path_for(track: Track) -> tuple[TriageQuestion, ...]:
    return _VULNERABILITY_PATH if track is Track.VULNERABILITY else _INCIDENT_PATH


@dataclass(frozen=True)
class TriageResult:
    """The outcome, and everything needed to defend it."""

    track: Track
    reportable: bool | None       # None = not yet determined
    answered: dict[str, str] = field(default_factory=dict)
    ground: NonReportGround | None = None
    authority: str = ""
    unanswered: tuple[str, ...] = ()
    reasoning: str = ""
    reopen_trigger_required: bool = False
    upstream_duty_remains: bool = False
    notes: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if self.reportable is None:
            return "undetermined"
        return "reportable" if self.reportable else "not_reportable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "track": self.track.value,
            "status": self.status,
            "reportable": self.reportable,
            "answered": dict(self.answered),
            "unanswered": list(self.unanswered),
            "ground": self.ground.value if self.ground else None,
            "authority": self.authority,
            "reasoning": self.reasoning,
            "reopen_trigger_required": self.reopen_trigger_required,
            "upstream_duty_remains": self.upstream_duty_remains,
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        lines = [f"{self.track.label}: {self.status.upper()}"]
        if self.ground:
            lines.append(f"  ground: {self.ground.value}")
            lines.append(f"  authority: {self.authority}")
        if self.reopen_trigger_required:
            lines.append(
                "  a reopen trigger is MANDATORY: this ground can stop being true without "
                "any action by us"
            )
        if self.upstream_duty_remains:
            lines.append("  Art. 13(6) upstream report to the component maintainer is still due")
        lines.extend(f"  unanswered: {q}" for q in self.unanswered)
        lines.extend(f"  note: {n}" for n in self.notes)
        return "\n".join(lines)


def triage(track: Track, answers: dict[Question | str, Answer | str], reasoning: str = "") -> TriageResult:
    """Work the decision path and return the outcome.

    Stops at the first question answered ``no`` that closes the case, and at the
    first question left ``undetermined`` — an undetermined answer is not a
    negative, and treating it as one is how a reportable event gets filed away.
    """
    normalised: dict[str, Answer] = {}
    for key, value in answers.items():
        k = key.value if isinstance(key, Question) else str(key)
        normalised[k] = value if isinstance(value, Answer) else Answer(str(value))

    path = path_for(track)
    answered: dict[str, str] = {}
    notes: list[str] = []

    for index, step in enumerate(path):
        key = step.question.value
        answer = normalised.get(key, Answer.UNDETERMINED)
        answered[key] = answer.value

        if answer is Answer.UNDETERMINED:
            return TriageResult(
                track=track,
                reportable=None,
                answered=answered,
                unanswered=tuple(s.question.value for s in path[index:]),
                reasoning=reasoning,
                notes=(*notes, step.prompt),
            )

        if answer is Answer.NO:
            # Art. 14(5) limb (a) is not fatal on its own: a "no" there falls
            # through to limb (b), and only a "no" to both closes the case.
            if step.ground_if_no is None:
                notes.append(
                    f"{step.question.value}: answered no — falling through to the next "
                    "limb of Art. 14(5)"
                )
                continue
            return TriageResult(
                track=track,
                reportable=False,
                answered=answered,
                ground=step.ground_if_no,
                authority=step.authority,
                reasoning=reasoning,
                reopen_trigger_required=step.ground_if_no.requires_reopen_trigger,
                upstream_duty_remains=step.ground_if_no.leaves_upstream_duty,
                notes=(*notes, step.note) if step.note else tuple(notes),
            )

        # A "yes" to either limb of Art. 14(5) establishes severity; the
        # remaining limb need not be asked.
        if step.question is Question.SEVERE_SENSITIVE_OR_IMPORTANT:
            notes.append("severity established under Art. 14(5)(a); limb (b) not reached")
            break

    return TriageResult(
        track=track,
        reportable=True,
        answered=answered,
        reasoning=reasoning,
        notes=tuple(notes),
    )
