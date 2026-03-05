#!/usr/bin/env python
"""
NeuralBridge: Compliance Incident Logger

This module provides a structured incident logging system designed to meet
CRA (Cyber Resilience Act) Article 14 requirements for incident reporting.
It features a versioned, immutable data store for security incidents,
ensuring a complete audit trail.

Classes:
    SeverityLevel: An enumeration for incident severity.
    SecurityIncident: A Pydantic model for a security incident.
    IncidentLogger: A class to manage the logging and reporting of incidents.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

import structlog
from pydantic import BaseModel, Field, model_validator

from neuralbridge.config import get_settings

# Initialize logger
logger = structlog.get_logger(__name__)
settings = get_settings()

class SeverityLevel(StrEnum):
    """Enumeration for the severity level of a security incident."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class SecurityIncident(BaseModel):
    """
    Pydantic model representing a single, versioned security incident.

    This model captures all necessary details for compliance reporting and
    internal tracking. Timestamps are timezone-aware (UTC).
    """
    incident_id: UUID = Field(default_factory=uuid4, description="Unique identifier for the incident thread.")
    version: int = Field(1, description="Version of the incident record, incremented on each update.")
    severity: SeverityLevel = Field(..., description="Severity level of the incident.")
    title: str = Field(..., min_length=5, max_length=100, description="A concise title for the incident.")
    description: str = Field(..., min_length=20, description="A detailed description of the incident.")
    affected_components: list[str] = Field(..., description="List of system components affected by the incident.")
    discovery_timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC), description="Timestamp when the incident was discovered.")
    resolution_timestamp: datetime | None = Field(None, description="Timestamp when the incident was resolved.")
    status: Literal["open", "investigating", "resolved", "mitigated"] = Field("open", description="Current status of the incident.")
    mitigation_steps: list[str] = Field(default_factory=list, description="Steps taken to mitigate the incident.")
    reporter: str = Field(..., description="Name or identifier of the person reporting the incident.")

    @model_validator(mode="after")
    def check_resolution_timestamp(self) -> SecurityIncident:
        """Ensure resolution timestamp is not before discovery timestamp."""
        if (
            self.resolution_timestamp
            and self.discovery_timestamp
            and self.resolution_timestamp < self.discovery_timestamp
        ):
            raise ValueError("Resolution timestamp cannot be before discovery timestamp.")
        return self

class IncidentLogger:
    """
    Manages the lifecycle of security incidents, from logging to reporting.

    This class provides an interface to log new incidents, update existing ones,
    and export incident data for compliance or analysis. It maintains an in-memory,
    versioned history of all incidents.
    """

    def __init__(self) -> None:
        """Initializes the IncidentLogger with an in-memory incident store."""
        self._incidents: dict[UUID, list[SecurityIncident]] = {}
        logger.info("IncidentLogger initialized", cra_reporting_enabled=settings.cra_reporting_enabled)

    async def log_incident(
        self,
        severity: SeverityLevel,
        title: str,
        description: str,
        affected_components: list[str],
        reporter: str,
    ) -> SecurityIncident:
        """
        Logs a new security incident.

        Args:
            severity: The severity of the incident.
            title: A title for the incident.
            description: A detailed description.
            affected_components: A list of affected components.
            reporter: The identifier of the reporter.

        Returns:
            The newly created SecurityIncident object.
        """
        incident = SecurityIncident(
            severity=severity,
            title=title,
            description=description,
            affected_components=affected_components,
            reporter=reporter,
            version=1,
            resolution_timestamp=None,
            status="open",
        )
        self._incidents[incident.incident_id] = [incident]
        logger.info(
            "New security incident logged",
            incident_id=str(incident.incident_id),
            severity=incident.severity.value,
            title=incident.title,
            reporter=incident.reporter,
        )
        return incident

    async def update_incident(
        self, incident_id: UUID, updates: dict[str, Any]
    ) -> SecurityIncident:
        """
        Updates an existing security incident by creating a new version.

        Incidents are immutable. This method creates a new `SecurityIncident`
        record with an incremented version number.

        Args:
            incident_id: The ID of the incident to update.
            updates: A dictionary of fields to update.

        Returns:
            The new, updated SecurityIncident object.

        Raises:
            ValueError: If the incident ID is not found.
        """
        if incident_id not in self._incidents:
            logger.error("Attempted to update non-existent incident", incident_id=str(incident_id))
            raise ValueError("Incident not found.")

        latest_incident = self._incidents[incident_id][-1]
        updated_data = latest_incident.model_dump()
        updated_data.update(updates)
        updated_data["version"] = latest_incident.version + 1

        new_incident = SecurityIncident(**updated_data)
        self._incidents[incident_id].append(new_incident)

        logger.info(
            "Security incident updated",
            incident_id=str(incident_id),
            new_version=new_incident.version,
            updates=updates,
        )
        return new_incident

    async def list_incidents(self, status: str | None = None) -> list[SecurityIncident]:
        """
        Lists the latest version of all incidents, optionally filtering by status.

        Args:
            status: If provided, only incidents with this status are returned.

        Returns:
            A list of the latest versions of security incidents.
        """
        latest_incidents = [versions[-1] for versions in self._incidents.values()]
        if status:
            return [inc for inc in latest_incidents if inc.status == status]
        return latest_incidents

    async def get_incident_history(self, incident_id: UUID) -> list[SecurityIncident]:
        """
        Retrieves the complete version history of a single incident.

        Args:
            incident_id: The ID of the incident to retrieve.

        Returns:
            A list of all versions of the incident, from oldest to newest.

        Raises:
            ValueError: If the incident ID is not found.
        """
        if incident_id not in self._incidents:
            logger.warning("Incident history requested for non-existent incident", incident_id=str(incident_id))
            raise ValueError("Incident not found.")
        return self._incidents[incident_id]

    async def export_incidents_report(self, format: Literal["json", "csv"] = "json") -> str:
        """
        Exports the latest version of all incidents to a specified format.

        Args:
            format: The desired output format ("json" or "csv").

        Returns:
            A string containing the incident report in the specified format.
        """
        incidents_to_export = await self.list_incidents()
        if not incidents_to_export:
            return ""

        report_data = [inc.model_dump(mode='json') for inc in incidents_to_export]

        if format == "json":
            logger.info("Exporting incidents to JSON report")
            return json.dumps(report_data, indent=2)
        elif format == "csv":
            logger.info("Exporting incidents to CSV report")
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=report_data[0].keys())
            writer.writeheader()
            writer.writerows(report_data)
            return output.getvalue()
        else:
            raise ValueError("Unsupported report format")
