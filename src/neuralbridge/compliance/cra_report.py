"""
EU Cyber Resilience Act (CRA) Compliance Report Generator.

This module provides functionalities to generate vulnerability reports and
compliance summaries in accordance with the EU Cyber Resilience Act (CRA),
particularly Article 14. It includes a CRAReportGenerator class to handle
the report generation, a VulnerabilityReport model for structuring
vulnerability data, and helper functions to check for CRA readiness.

The reports are generated in both structured JSON and human-readable
Markdown formats.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from enum import StrEnum

import structlog
from pydantic import BaseModel, Field, field_validator

from neuralbridge.config import get_settings

logger = structlog.get_logger(__name__)

CRA_DEADLINE = datetime(2026, 9, 11)


class VulnerabilityStatus(StrEnum):
    """Enumeration for the status of a vulnerability."""

    IDENTIFIED = "identified"
    UNDER_INVESTIGATION = "under_investigation"
    MITIGATION_IN_PROGRESS = "mitigation_in_progress"
    MITIGATED = "mitigated"
    NOT_APPLICABLE = "not_applicable"


class VulnerabilityReport(BaseModel):
    """Pydantic model for a single vulnerability report.

    Compliant with CRA requirements for vulnerability disclosure.
    """

    report_id: str = Field(
        ..., description="Unique identifier for the vulnerability report.",
    )
    product_name: str = Field(
        "NeuralBridge Enterprise Middleware",
        description="Name of the product.",
    )
    product_version: str = Field(
        ..., description="Version of the product affected.",
    )
    vulnerability_id: str = Field(
        ..., description="Unique identifier (e.g., CVE ID).",
    )
    vulnerability_description: str = Field(
        ..., description="Detailed description of the vulnerability.",
    )
    status: VulnerabilityStatus = Field(
        ..., description="Current status of the vulnerability.",
    )
    severity: str = Field(
        ..., description="Severity (Critical, High, Medium, Low).",
    )
    cvss_score: float | None = Field(
        None, ge=0, le=10, description="CVSS score.",
    )
    mitigation_details: str | None = Field(
        None, description="Details of mitigation measures taken.",
    )
    timeline: list[datetime] = Field(
        ..., description="Timeline of events related to the vulnerability.",
    )
    reported_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp of when the vulnerability was reported.",
    )
    updated_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp of the last update to the report.",
    )

    @field_validator("timeline", mode="before")
    @classmethod
    def _validate_timeline(
        cls, v: list[datetime],
    ) -> list[datetime]:
        if not isinstance(v, list):
            raise ValueError("Timeline must be a list of datetime objects.")
        return v


class CRAReportGenerator:
    """Generates EU Cyber Resilience Act (CRA) compliance reports."""

    def __init__(self) -> None:
        """Initialize the CRAReportGenerator with settings from config."""
        self.settings = get_settings()
        logger.info(
            "CRAReportGenerator initialized",
            org_name=self.settings.cra_organization_name,
        )

    def generate_vulnerability_report(
        self,
        report: VulnerabilityReport,
        output_format: str = "json",
    ) -> str:
        """Generate a single vulnerability report.

        Args:
            report: The VulnerabilityReport object.
            output_format: The desired output format ('json' or 'markdown').

        Returns:
            The generated report as a string.
        """
        logger.info(
            "Generating vulnerability report",
            report_id=report.report_id,
            format=output_format,
        )
        if output_format == "json":
            return report.model_dump_json(indent=2)
        if output_format == "markdown":
            return self._generate_markdown_report(report)
        raise ValueError(
            "Unsupported output format. Choose 'json' or 'markdown'.",
        )

    def _generate_markdown_report(
        self, report: VulnerabilityReport,
    ) -> str:
        """Generate a human-readable Markdown report.

        Args:
            report: The VulnerabilityReport object.

        Returns:
            The generated Markdown report as a string.
        """
        timeline_str = "\n".join(
            f"- {ts.isoformat()}" for ts in report.timeline
        )
        cvss = report.cvss_score if report.cvss_score is not None else "N/A"
        mitigation = report.mitigation_details or "N/A"
        return (
            f"# Vulnerability Report: {report.vulnerability_id}\n\n"
            f"**Report ID:** {report.report_id}\n\n"
            f"**Date:** {datetime.utcnow().isoformat()}\n\n"
            f"## Product Information\n\n"
            f"- **Product Name:** {report.product_name}\n"
            f"- **Product Version:** {report.product_version}\n\n"
            f"## Vulnerability Details\n\n"
            f"- **Vulnerability ID:** {report.vulnerability_id}\n"
            f"- **Description:** {report.vulnerability_description}\n"
            f"- **Severity:** {report.severity}\n"
            f"- **CVSS Score:** {cvss}\n\n"
            f"## Status and Mitigation\n\n"
            f"- **Status:** {report.status.value}\n"
            f"- **Mitigation Details:** {mitigation}\n\n"
            f"## Timeline\n\n{timeline_str}\n\n"
            f"## Contact Information\n\n"
            f"- **Organization:** {self.settings.cra_organization_name}\n"
            f"- **Contact Email:** {self.settings.cra_contact_email}\n"
        )

    def generate_compliance_summary(
        self,
        reports: list[VulnerabilityReport],
        output_format: str = "markdown",
    ) -> str:
        """Generate a compliance summary report.

        Args:
            reports: A list of VulnerabilityReport objects.
            output_format: The desired output format.

        Returns:
            The generated summary report as a string.
        """
        logger.info(
            "Generating compliance summary", num_reports=len(reports),
        )
        if output_format == "json":
            return json.dumps(
                [r.model_dump() for r in reports],
                indent=2,
                default=str,
            )
        if output_format == "markdown":
            return self._generate_markdown_summary(reports)
        raise ValueError(
            "Unsupported output format. Choose 'json' or 'markdown'.",
        )

    def _generate_markdown_summary(
        self, reports: list[VulnerabilityReport],
    ) -> str:
        """Generate a human-readable Markdown summary.

        Args:
            reports: A list of VulnerabilityReport objects.

        Returns:
            The generated Markdown summary as a string.
        """
        rows = []
        for r in reports:
            updated = r.updated_at.strftime("%Y-%m-%d")
            rows.append(
                f"| {r.vulnerability_id} | {r.severity} "
                f"| {r.status.value} | {updated} |"
            )
        table_body = "\n".join(rows)
        return (
            f"# CRA Compliance Summary\n\n"
            f"**Organization:** "
            f"{self.settings.cra_organization_name}\n\n"
            f"**Date:** {datetime.utcnow().isoformat()}\n\n"
            f"This report summarizes the current status of "
            f"vulnerabilities in relation to the EU CRA.\n\n"
            f"## Vulnerability Overview\n\n"
            f"| Vulnerability ID | Severity | Status | Last Updated |\n"
            f"|---|---|---|---|\n"
            f"{table_body}\n\n"
            f"## Contact Information\n\n"
            f"For inquiries, please contact us at "
            f"{self.settings.cra_contact_email}.\n"
        )

    def check_cra_readiness(self) -> dict[str, object]:
        """Perform a readiness check for CRA compliance.

        Returns:
            A dictionary containing the readiness status and details.
        """
        days_to_deadline = (CRA_DEADLINE - datetime.utcnow()).days
        readiness = {
            "cra_deadline": CRA_DEADLINE.isoformat(),
            "days_to_deadline": days_to_deadline,
            "reporting_enabled": self.settings.cra_reporting_enabled,
            "contact_info_set": bool(
                self.settings.cra_organization_name
                and self.settings.cra_contact_email
            ),
        }
        logger.info("CRA readiness check performed", **readiness)
        return readiness


async def main() -> None:
    """Example usage of the CRAReportGenerator."""
    generator = CRAReportGenerator()

    generator.check_cra_readiness()

    vuln_report = VulnerabilityReport(
        report_id="VR-2026-001",
        product_name="NeuralBridge Middleware",
        product_version="1.2.3",
        vulnerability_id="CVE-2026-12345",
        vulnerability_description=(
            "A critical remote code execution vulnerability."
        ),
        status=VulnerabilityStatus.MITIGATION_IN_PROGRESS,
        severity="Critical",
        cvss_score=9.8,
        mitigation_details=(
            "Patch is under development and will be released shortly."
        ),
        timeline=[
            datetime.utcnow() - timedelta(days=5),
            datetime.utcnow() - timedelta(days=2),
        ],
    )

    generator.generate_vulnerability_report(
        vuln_report, "json",
    )
    generator.generate_vulnerability_report(
        vuln_report, "markdown",
    )


    generator.generate_compliance_summary(
        [vuln_report], "markdown",
    )


if __name__ == "__main__":
    import asyncio

    asyncio.run(main())
