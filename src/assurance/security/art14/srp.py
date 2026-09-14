"""The reporting platform's field specification, as code.

The ENISA CRA Single Reporting Platform asks for 39 fields. Which of them are
required depends on the stage and on the track, some are carried forward from
the previous stage, and several have character limits tight enough to truncate
a sentence a human would otherwise write. There is no API and no downloadable
schema at the initial release, so a submission is typed into a web form under a
24-hour deadline.

Encoding the specification here does three things a checklist cannot:

* a payload can be **validated before** anyone opens the platform, so a missing
  field is found in calm conditions rather than at hour 23;
* every gap is reported with the field number and the stage, so the answer to
  "what is missing" is actionable;
* fields the platform does not yet capture are marked, so the compensating
  record is produced instead of the fact being lost.

Source: ENISA, CRA SRP Glossary v1.3, 10 September 2026. That document is
operational guidance rather than a legal instrument and has already changed
version once; :data:`GLOSSARY_VERSION` is checked by the report so a stale
build announces itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .model import Stage, Track

__all__ = [
    "EEA_NON_EU",
    "EU_MEMBER_STATES",
    "FIELDS",
    "GLOSSARY_VERSION",
    "FieldSpec",
    "PayloadIssue",
    "PayloadValidation",
    "Requirement",
    "fields_for",
    "validate_payload",
]

GLOSSARY_VERSION = "1.3"
GLOSSARY_DATE = "2026-09-10"

#: The 27 EU Member States, ISO 3166-1 alpha-2. Field 5 asks for the territories
#: in which the product has been made available, and it means Member States.
EU_MEMBER_STATES = frozenset(
    ["AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK"]
)

#: EEA states that are not EU Member States. The CRA is EEA-relevant, so these
#: matter commercially, but they are a common source of an invalid field 5.
EEA_NON_EU = frozenset({"IS", "LI", "NO"})


class Requirement(StrEnum):
    """How a field behaves at one stage."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    #: Copied forward from the previous stage by default.
    CARRIED = "carried"
    #: Required when the manufacturer has the information.
    IF_AVAILABLE = "required_if_available"
    #: Populated by the platform from the registration.
    SYSTEM = "system"
    NOT_APPLICABLE = "n/a"

    @property
    def must_be_present(self) -> bool:
        return self is Requirement.REQUIRED


@dataclass(frozen=True)
class FieldSpec:
    """One platform field."""

    number: str
    name: str
    applies_to: str           # "both" | "vulnerability" | "incident"
    early_warning: Requirement
    notification: Requirement
    final: Requirement
    max_length: int | None = None
    note: str = ""
    #: True where the platform does not yet capture the field, or captures a
    #: different fact under this name. The value must still be recorded here.
    platform_gap: str = ""

    def requirement_at(self, stage: Stage) -> Requirement:
        return {
            Stage.EARLY_WARNING: self.early_warning,
            Stage.NOTIFICATION: self.notification,
            Stage.FINAL: self.final,
            Stage.INTERMEDIATE: self.notification,
        }[stage]

    def applies_to_track(self, track: Track) -> bool:
        if self.applies_to == "both":
            return True
        return (track is Track.VULNERABILITY and self.applies_to == "vulnerability") or (
            track is Track.INCIDENT and self.applies_to == "incident"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "number": self.number,
            "name": self.name,
            "applies_to": self.applies_to,
            "early_warning": self.early_warning.value,
            "notification": self.notification.value,
            "final": self.final.value,
            "max_length": self.max_length,
            "note": self.note,
            "platform_gap": self.platform_gap,
        }


# Short aliases keep the table below readable as a table. They are the only
# abbreviations in this package and they exist so the specification can be read
# the way the platform presents it: a grid.
REQ = Requirement.REQUIRED
OPT = Requirement.OPTIONAL
CAR = Requirement.CARRIED
NAP = Requirement.NOT_APPLICABLE
IFA = Requirement.IF_AVAILABLE
SYS = Requirement.SYSTEM

#: The full specification. Ordered as the platform presents it.
FIELDS: tuple[FieldSpec, ...] = (
    # ---- common -------------------------------------------------------
    FieldSpec("1", "notification_type", "both", REQ, CAR, CAR, None,
              "Vulnerability or Incident."),
    FieldSpec("2", "title", "both", REQ, CAR, CAR, 255),
    FieldSpec("3", "summary", "both", REQ, CAR, CAR, 4000),
    FieldSpec("4", "manufacturer_name", "both", SYS, CAR, CAR, None,
              "Read-only; generated from the registration."),
    FieldSpec("5", "member_states_available", "both", REQ, CAR, CAR, None,
              "The coordinating CSIRT's Member State is pre-filled; the rest must be added. "
              "The only substantive content Art. 14(2)(a) requires at 24 hours."),
    FieldSpec("6", "product_name", "both", REQ, CAR, CAR, 255),
    FieldSpec("7", "product_version", "both", REQ, CAR, CAR, 255),
    FieldSpec("8", "product_type", "both", OPT, CAR, CAR, None,
              "Default / Important / Critical, per Annex III and IV."),
    FieldSpec("9", "product_class", "both", OPT, CAR, CAR, None, "Class I or Class II."),
    FieldSpec("10", "product_category", "both", OPT, CAR, CAR, None, "Annex III or IV category."),
    FieldSpec("11", "end_of_support", "both", OPT, CAR, CAR, None,
              "Reporting continues after the support period ends (guidance §210)."),
    FieldSpec("12", "component_name", "both", OPT, CAR, CAR, 255),
    FieldSpec("13", "mitigating_measure_expected_shortly", "both", OPT, CAR, CAR, None),
    FieldSpec("14", "user_action_reducing_impact", "both", OPT, CAR, CAR, 4000),
    FieldSpec("15", "considered_sensitivity", "both", OPT, OPT, CAR, 255,
              "Feeds the CSIRT's Art. 16(2) discretion to delay onward dissemination."),
    FieldSpec("16", "measures_taken", "both", OPT, OPT, REQ, 2000),
    FieldSpec("17", "measures_users_can_take", "both", OPT, OPT, REQ, 4000),
    FieldSpec("18", "attack_vector", "both", NAP, OPT, OPT, 255),
    # ---- actively exploited vulnerability ------------------------------
    FieldSpec("v19", "cve_id", "vulnerability", OPT, CAR, CAR, 255),
    FieldSpec("v20", "euvd_id", "vulnerability", OPT, CAR, CAR, 255),
    FieldSpec("v21", "vulnerability_general_information", "vulnerability", OPT, REQ, CAR, 4000,
              "How exploitation works. Required at 72 hours."),
    FieldSpec("v22", "measure_available_date", "vulnerability", OPT, OPT, REQ, None,
              "Starts the 14-day final-report clock (Art. 14(2)(c))."),
    FieldSpec("v23", "security_update_details", "vulnerability", OPT, OPT, REQ, 2000),
    FieldSpec("v24", "vulnerability_severity", "vulnerability", OPT, OPT, REQ, 4000),
    FieldSpec("v25", "vulnerability_impact", "vulnerability", OPT, OPT, REQ, 4000),
    FieldSpec("v26", "awareness_datetime", "vulnerability", REQ, CAR, CAR, None,
              "The fact every deadline runs from.",
              platform_gap="Documented as arriving in a future release of the platform. "
                           "Until then the manufacturer's own record is the only evidence."),
    FieldSpec("v27", "malicious_actor", "vulnerability", OPT, OPT, IFA, 100,
              "100 characters. Name the actor; the analysis does not fit and is not asked for."),
    FieldSpec("v28", "particular_exceptional_circumstances", "vulnerability", NAP, OPT, NAP, None,
              "Asks the CSIRT to withhold dissemination under Art. 16(2). Filing is still due on time."),
    FieldSpec("v29", "pec_delay_reason", "vulnerability", NAP, OPT, NAP, None,
              "At least one of the three Art. 16(2) grounds."),
    FieldSpec("v30", "further_information", "vulnerability", OPT, OPT, CAR, 800),
    # ---- severe incident ------------------------------------------------
    FieldSpec("i31", "suspected_unlawful_or_malicious", "incident", REQ, CAR, CAR, None,
              "Yes / No / Unknown. Required by Art. 14(4)(a) itself."),
    FieldSpec("i32", "incident_general_information", "incident", OPT, REQ, CAR, 4000),
    FieldSpec("i33", "mitigation_measures", "incident", OPT, OPT, REQ, 4000),
    FieldSpec("i34", "incident_severity", "incident", OPT, OPT, REQ, 4000),
    FieldSpec("i35", "incident_impact", "incident", OPT, OPT, REQ, 4000),
    FieldSpec("i36", "threat_type_or_root_cause", "incident", OPT, OPT, REQ, 255),
    FieldSpec("i37", "awareness_datetime", "incident", REQ, REQ, CAR, None,
              "The fact every deadline runs from.",
              platform_gap="The platform currently labels this field 'Date and time when the "
                           "incident was detected'. Detection is not awareness; enter the "
                           "awareness time and keep the reasoning."),
    FieldSpec("i38", "incident_occurred_datetime", "incident", OPT, REQ, OPT, None),
    FieldSpec("i39", "initial_assessment", "incident", OPT, REQ, CAR, 4000),
)

_BY_NUMBER = {f.number: f for f in FIELDS}
_BY_NAME: dict[tuple[str, str], FieldSpec] = {(f.applies_to, f.name): f for f in FIELDS}


def fields_for(track: Track, stage: Stage) -> list[FieldSpec]:
    """Fields that apply to this track at this stage, in platform order."""
    return [
        f
        for f in FIELDS
        if f.applies_to_track(track) and f.requirement_at(stage) is not Requirement.NOT_APPLICABLE
    ]


@dataclass(frozen=True)
class PayloadIssue:
    """One problem with a draft submission."""

    field_number: str
    field_name: str
    severity: str   # "blocking" | "advisory"
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "field_number": self.field_number,
            "field_name": self.field_name,
            "severity": self.severity,
            "message": self.message,
        }

    def __str__(self) -> str:
        return f"[{self.severity:8s}] field {self.field_number} ({self.field_name}): {self.message}"


@dataclass(frozen=True)
class PayloadValidation:
    """The verdict on a draft submission.

    ``checks_skipped`` carries the same discipline used everywhere else in this
    package: a field the platform cannot currently accept, or a value that
    could not be checked, is named rather than passed over. A validation that
    reports only problems it happened to look for is a validation that flatters
    the caller.
    """

    track: Track
    stage: Stage
    issues: tuple[PayloadIssue, ...]
    checks_skipped: tuple[str, ...]
    glossary_version: str = GLOSSARY_VERSION

    @property
    def blocking(self) -> tuple[PayloadIssue, ...]:
        return tuple(i for i in self.issues if i.severity == "blocking")

    @property
    def advisory(self) -> tuple[PayloadIssue, ...]:
        return tuple(i for i in self.issues if i.severity == "advisory")

    @property
    def submittable(self) -> bool:
        """True when nothing required is missing or over-length."""
        return not self.blocking

    def to_dict(self) -> dict[str, Any]:
        return {
            "track": self.track.value,
            "stage": self.stage.value,
            "submittable": self.submittable,
            "glossary_version": self.glossary_version,
            "glossary_date": GLOSSARY_DATE,
            "issues": [i.to_dict() for i in self.issues],
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        head = (
            f"{self.stage.label} — {self.track.label}: "
            f"{'ready to submit' if self.submittable else 'NOT submittable'} "
            f"({len(self.blocking)} blocking, {len(self.advisory)} advisory)"
        )
        lines = [head]
        lines.extend("  " + str(i) for i in self.issues)
        if self.checks_skipped:
            lines.append("  checks skipped:")
            lines.extend("    - " + c for c in self.checks_skipped)
        return "\n".join(lines)


def validate_payload(
    payload: dict[str, Any], track: Track, stage: Stage
) -> PayloadValidation:
    """Check a draft submission against the specification for this stage.

    ``payload`` is keyed by field *name* (``product_name``), not number, so a
    caller writes readable code and the numbers stay where they belong — in
    the messages a person has to act on.
    """
    issues: list[PayloadIssue] = []
    skipped: list[str] = []

    applicable = fields_for(track, stage)
    known_names = {f.name for f in applicable}

    for spec in applicable:
        requirement = spec.requirement_at(stage)
        value = payload.get(spec.name)
        present = value not in (None, "", [], ())

        if requirement.must_be_present and not present:
            issues.append(
                PayloadIssue(
                    spec.number,
                    spec.name,
                    "blocking",
                    f"required at this stage but absent. {spec.note}".strip(),
                )
            )
            continue

        if requirement is Requirement.IF_AVAILABLE and not present:
            skipped.append(
                f"field {spec.number} ({spec.name}): required if available, and no value was "
                "supplied — record why it is unavailable"
            )
            continue

        if present and spec.max_length is not None and isinstance(value, str):
            if len(value) > spec.max_length:
                issues.append(
                    PayloadIssue(
                        spec.number,
                        spec.name,
                        "blocking",
                        f"{len(value)} characters exceeds the platform limit of "
                        f"{spec.max_length}; it will be truncated or rejected",
                    )
                )
            elif len(value) > spec.max_length * 0.9:
                issues.append(
                    PayloadIssue(
                        spec.number,
                        spec.name,
                        "advisory",
                        f"{len(value)} of {spec.max_length} characters — close to the limit",
                    )
                )

        if present and spec.platform_gap:
            skipped.append(f"field {spec.number} ({spec.name}): {spec.platform_gap}")

    issues.extend(
        PayloadIssue(
            "-",
            key,
            "advisory",
            "not a field the platform accepts for this track and stage; it will not be "
            "transmitted",
        )
        for key in sorted(set(payload) - known_names)
    )

    # Field 5 deserves its own check: it is the one that cannot be assembled
    # under time pressure, and an empty list is the commonest cause of a
    # 24-hour filing that cannot be completed.
    states = payload.get("member_states_available")
    if isinstance(states, (list, tuple)):
        malformed = [s for s in states if not (isinstance(s, str) and len(s) == 2 and s.isalpha())]
        if malformed:
            issues.append(
                PayloadIssue(
                    "5",
                    "member_states_available",
                    "blocking",
                    f"not ISO 3166-1 alpha-2 codes: {malformed}",
                )
            )
        codes = {s.upper() for s in states if isinstance(s, str) and len(s) == 2 and s.isalpha()}
        eea = sorted(codes & EEA_NON_EU)
        if eea:
            issues.append(
                PayloadIssue(
                    "5",
                    "member_states_available",
                    "advisory",
                    f"{eea} are EEA states but not EU Member States. The CRA is EEA-relevant, "
                    "so confirm how the platform expects them to be entered rather than "
                    "assuming; they belong in the Art. 14(8) user-notification scope either way.",
                )
            )
        unknown = sorted(codes - EU_MEMBER_STATES - EEA_NON_EU)
        if unknown:
            issues.append(
                PayloadIssue(
                    "5",
                    "member_states_available",
                    "blocking",
                    f"{unknown} are not EU Member States. Field 5 asks for the Member States "
                    "in whose territory the product was made available. Markets outside the "
                    "EU/EEA are excluded here \u2014 they still matter for informing users "
                    "under Art. 14(8), which is a separate duty.",
                )
            )
        already_flagged = any(
            i.field_number == "5" and i.message.startswith("required at this stage")
            for i in issues
        )
        if not codes and not already_flagged:
            issues.append(
                PayloadIssue(
                    "5",
                    "member_states_available",
                    "blocking",
                    "no Member States listed. This is the only substantive content "
                    "Art. 14(2)(a) requires at 24 hours.",
                )
            )
    skipped.append(
        "the platform's own acceptance rules are not reproduced here: this validates against "
        f"the published field specification (Glossary v{GLOSSARY_VERSION}, {GLOSSARY_DATE}) "
        "and cannot confirm the live form will accept the values"
    )

    return PayloadValidation(
        track=track, stage=stage, issues=tuple(issues), checks_skipped=tuple(skipped)
    )
