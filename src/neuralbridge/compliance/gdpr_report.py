"""
NeuralBridge GDPR Article 30 — Records of Processing Activities.

Generates and maintains the records of processing activities required by
GDPR Article 30.  Every adapter that touches personal data must declare
its processing activity, and this module aggregates those declarations
into a single, exportable register.

The register includes:
* Purpose of processing
* Categories of data subjects and personal data
* Recipients of personal data
* Transfers to third countries
* Retention periods
* Technical and organisational security measures
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger(__name__)


class ProcessingActivity(BaseModel):
    """A single GDPR Article 30 processing activity record."""

    activity_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., description="Name of the processing activity.")
    purpose: str = Field(..., description="Purpose of the data processing.")
    legal_basis: str = Field(
        default="Legitimate interest",
        description="Legal basis under GDPR (e.g. consent, contract, legitimate interest).",
    )
    data_subjects: list[str] = Field(
        default_factory=list,
        description="Categories of data subjects (e.g. employees, customers).",
    )
    data_categories: list[str] = Field(
        default_factory=list,
        description="Categories of personal data processed.",
    )
    recipients: list[str] = Field(
        default_factory=list,
        description="Recipients or categories of recipients.",
    )
    third_country_transfers: list[str] = Field(
        default_factory=list,
        description="Transfers to third countries or international organisations.",
    )
    retention_period: str = Field(
        default="As defined by data retention policy",
        description="Envisaged time limits for erasure.",
    )
    security_measures: list[str] = Field(
        default_factory=lambda: [
            "Encryption at rest and in transit",
            "Role-based access control",
            "Immutable audit logging",
        ],
    )
    adapter_type: str = Field(default="", description="NeuralBridge adapter that performs this processing.")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GDPRRegister:
    """
    Maintains the Article 30 register of processing activities.

    Usage::

        register = GDPRRegister(controller_name="Acme Corp")
        register.add_activity(ProcessingActivity(
            name="CRM Sync",
            purpose="Synchronise customer records with Salesforce",
            data_categories=["name", "email", "phone"],
        ))
        report = register.export_register()
    """

    def __init__(
        self,
        controller_name: str = "Your Organisation",
        controller_contact: str = "dpo@example.com",
    ) -> None:
        self._controller_name = controller_name
        self._controller_contact = controller_contact
        self._activities: dict[str, ProcessingActivity] = {}

    def add_activity(self, activity: ProcessingActivity) -> str:
        """Add a processing activity and return its ID."""
        self._activities[activity.activity_id] = activity
        logger.info("gdpr_activity_added", activity_id=activity.activity_id, name=activity.name)
        return activity.activity_id

    def get_activity(self, activity_id: str) -> ProcessingActivity | None:
        return self._activities.get(activity_id)

    def list_activities(self) -> list[ProcessingActivity]:
        return list(self._activities.values())

    def export_register(self) -> dict[str, Any]:
        """Export the full Article 30 register as a structured dict."""
        return {
            "gdpr_article_30_register": {
                "controller": {
                    "name": self._controller_name,
                    "contact": self._controller_contact,
                },
                "generated_at": datetime.now(UTC).isoformat(),
                "activities": [a.model_dump(mode="json") for a in self._activities.values()],
                "total_activities": len(self._activities),
            }
        }

    def export_markdown(self) -> str:
        """Export the register as a human-readable Markdown document."""
        lines = [
            "# GDPR Article 30 — Records of Processing Activities\n",
            f"**Data Controller:** {self._controller_name}  ",
            f"**Contact:** {self._controller_contact}  ",
            f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}\n",
            "---\n",
        ]
        for i, a in enumerate(self._activities.values(), 1):
            lines.append(f"## {i}. {a.name}\n")
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| **Purpose** | {a.purpose} |")
            lines.append(f"| **Legal Basis** | {a.legal_basis} |")
            lines.append(f"| **Data Subjects** | {', '.join(a.data_subjects) or 'N/A'} |")
            lines.append(f"| **Data Categories** | {', '.join(a.data_categories) or 'N/A'} |")
            lines.append(f"| **Recipients** | {', '.join(a.recipients) or 'N/A'} |")
            lines.append(f"| **Third-Country Transfers** | {', '.join(a.third_country_transfers) or 'None'} |")
            lines.append(f"| **Retention Period** | {a.retention_period} |")
            lines.append(f"| **Security Measures** | {', '.join(a.security_measures)} |")
            lines.append(f"| **Adapter** | {a.adapter_type or 'N/A'} |")
            lines.append("")
        return "\n".join(lines)
