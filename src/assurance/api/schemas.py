"""Request and response bodies.

Field names match the vocabulary of the Regulation and of the reporting
platform, not an internal convention, so an integrator reading the article and
an integrator reading this schema are reading the same words.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ActorIn",
    "SignalIn",
    "AwarenessIn",
    "TriageIn",
    "AvailabilityIn",
    "MeasureIn",
    "FilingIn",
    "UserNotificationIn",
    "ValidateIn",
    "RecordedOut",
    "FilingOut",
    "ValidationOut",
    "CaseOut",
    "ProblemOut",
]


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActorIn(_Base):
    """Who is recording this. An unattributed record is not evidence."""

    identifier: str = Field(min_length=1, max_length=200)
    role: str = Field(default="", max_length=200)
    kind: Literal["person", "service", "automation"] = "person"


class SignalIn(_Base):
    """A report or observation that might turn out to be reportable."""

    received_at: datetime
    channel: str = "other"
    received_by: str = ""
    description: str = Field(min_length=1, max_length=4000)
    product_name: str = ""
    version: str = ""
    reference: str = ""
    actor: ActorIn


class AwarenessIn(_Base):
    """The moment every deadline runs from.

    ``reasoning`` is required. Commission guidance C(2026) 5252 §213 makes this
    a judgement about reasonable certainty after an initial assessment; a
    timestamp with no judgement behind it cannot be defended.
    """

    established_at: datetime
    assessment_started_at: datetime
    assessment_completed_at: datetime
    track: Literal["actively_exploited_vulnerability", "severe_incident"]
    determined_by: str = ""
    reasoning: str = Field(min_length=1, max_length=4000)
    actor: ActorIn


class TriageIn(_Base):
    """Answers to the reportability decision path.

    Unanswered questions default to *undetermined*; an undetermined answer is
    never treated as a negative.
    """

    answers: dict[str, Literal["yes", "no", "undetermined"]]
    reasoning: str = ""
    reopen_trigger: str = ""
    actor: ActorIn


class AvailabilityIn(_Base):
    """Product, versions, and the Member States where it was made available."""

    product_name: str = Field(min_length=1, max_length=255)
    version_range: str = ""
    member_states: list[str] = Field(default_factory=list)
    other_markets: list[str] = Field(default_factory=list)
    placed_on_market_from: str = ""
    placed_on_market_to: str = ""
    end_of_support: bool = False
    units_in_field: int | None = None
    product_type: str = ""
    annex_category: str = ""
    components: list[str] = Field(default_factory=list)
    evidence_source: str = ""
    owner: str = ""
    actor: ActorIn


class MeasureIn(_Base):
    """The moment a corrective **or mitigating** measure became available.

    This starts the 14-day final-report clock for a vulnerability. A documented
    workaround starts it exactly as a patch does.
    """

    available_at: datetime
    description: str = Field(min_length=1, max_length=2000)
    actor: ActorIn


class FilingIn(_Base):
    """A submission to the reporting platform.

    ``payload`` is keyed by platform field *name*. ``GET /v1/spec/fields``
    returns the names, the stage at which each is required, and the length
    limits.
    """

    stage: Literal["early_warning", "notification", "final", "intermediate"]
    submitted_at: datetime
    payload: dict[str, Any]
    platform_reference: str = ""
    actor: ActorIn


class UserNotificationIn(_Base):
    """The Article 14(8) notification to users.

    The trigger is becoming aware, not the availability of a fix. Guidance
    §§219-221: this is not an obligation to publish.
    """

    at: datetime
    scope: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=8000)
    public_disclosure: bool = False
    actor: ActorIn


class ValidateIn(_Base):
    """Check a draft submission without recording anything."""

    track: Literal["actively_exploited_vulnerability", "severe_incident"]
    stage: Literal["early_warning", "notification", "final", "intermediate"]
    payload: dict[str, Any]


class RecordedOut(BaseModel):
    """What was written, and what is now outstanding."""

    case_id: str
    content_hash: str
    kind: str
    ledger_seq: int
    outstanding: list[str]


class ValidationOut(BaseModel):
    submittable: bool
    track: str
    stage: str
    glossary_version: str
    glossary_date: str
    issues: list[dict[str, Any]]
    checks_skipped: list[str]


class FilingOut(RecordedOut):
    validation: ValidationOut


class CaseOut(BaseModel):
    """The full case view, including deadlines and what is still owed."""

    model_config = ConfigDict(extra="allow")

    case_id: str
    state: str


class ProblemOut(BaseModel):
    """An error the caller can act on.

    ``provision`` carries the article or guidance paragraph the refusal rests
    on, so an integrator can look it up rather than guess.
    """

    error: str
    detail: str
    provision: str = ""
