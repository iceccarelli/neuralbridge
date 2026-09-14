"""EU Cyber Resilience Act, Article 14 — reporting.

Regulation (EU) 2024/2847. Applicable since 11 September 2026 and, by
Article 69(3), applicable to products placed on the market before
11 December 2027.
"""

from .clock import Deadline, Deadlines, add_one_month, platform_displayed_notification_due
from .engine import Art14Register, Case, CaseError
from .model import (
    Awareness,
    NonReportGround,
    ProductVersion,
    Signal,
    SignalChannel,
    Stage,
    Track,
)
from .srp import FIELDS, GLOSSARY_VERSION, PayloadValidation, fields_for, validate_payload
from .triage import Answer, Question, TriageResult, triage

__all__ = [
    "FIELDS",
    "GLOSSARY_VERSION",
    "Answer",
    "Art14Register",
    "Awareness",
    "Case",
    "CaseError",
    "Deadline",
    "Deadlines",
    "NonReportGround",
    "PayloadValidation",
    "ProductVersion",
    "Question",
    "Signal",
    "SignalChannel",
    "Stage",
    "Track",
    "TriageResult",
    "add_one_month",
    "fields_for",
    "platform_displayed_notification_due",
    "triage",
    "validate_payload",
]
