"""
Tests for NeuralBridge Compliance Modules.

Covers CRA report generation, SBOM creation, GDPR register,
and incident logging.
"""

from __future__ import annotations

import pytest


class TestCRAReport:
    """Tests for the CRA report generator."""

    def test_import(self):
        from neuralbridge.compliance.cra_report import CRAReportGenerator
        assert CRAReportGenerator is not None

    def test_instantiation(self):
        from neuralbridge.compliance.cra_report import CRAReportGenerator
        gen = CRAReportGenerator()
        assert gen is not None

    def test_check_readiness(self):
        from neuralbridge.compliance.cra_report import CRAReportGenerator
        gen = CRAReportGenerator()
        readiness = gen.check_cra_readiness()
        assert readiness is not None
        assert "overall_status" in readiness or isinstance(readiness, dict)

    def test_readiness_reports_an_application_date_not_a_deadline(self):
        from datetime import UTC, datetime

        from neuralbridge.compliance.cra_report import CRAReportGenerator

        readiness = CRAReportGenerator().check_cra_readiness()
        assert "cra_deadline" not in readiness and "days_to_deadline" not in readiness
        applies = datetime.fromisoformat(str(readiness["art14_applies_from"]))
        assert applies == datetime(2026, 9, 11, tzinfo=UTC)          # Art. 71(2); timezone-aware
        elapsed = (datetime.now(UTC) - applies).days
        assert readiness["days_since_applicable"] in (elapsed, elapsed - 1, elapsed + 1)
        assert readiness["days_since_applicable"] > 0                  # applicable since 2026-09-11


class TestSBOM:
    """Tests for the SBOM generator."""

    def test_import(self):
        from neuralbridge.compliance.sbom import SBOMGenerator
        assert SBOMGenerator is not None

    def test_instantiation(self):
        from pathlib import Path

        from neuralbridge.compliance.sbom import SBOMGenerator
        gen = SBOMGenerator(project_root=Path("."))
        assert gen is not None


class TestIncidentLogger:
    """Tests for the incident logger."""

    def test_import(self):
        from neuralbridge.compliance.incident_log import IncidentLogger
        assert IncidentLogger is not None

    @pytest.mark.asyncio
    async def test_log_incident(self):
        from neuralbridge.compliance.incident_log import IncidentLogger
        logger = IncidentLogger()
        incident = await logger.log_incident(
            severity="medium",
            title="Test Incident for CI",
            description="This is a test incident for CI validation purposes.",
            affected_components=["test_adapter"],
            reporter="test_user",
        )
        assert incident is not None

    @pytest.mark.asyncio
    async def test_list_incidents(self):
        from neuralbridge.compliance.incident_log import IncidentLogger
        logger = IncidentLogger()
        await logger.log_incident(
            severity="low",
            title="Minor Issue Found Here",
            description="A minor test issue for validation.",
            affected_components=["core"],
            reporter="tester",
        )
        incidents = await logger.list_incidents()
        assert len(incidents) >= 1


class TestGDPRRegister:
    """Tests for the GDPR Article 30 register."""

    def test_import(self):
        from neuralbridge.compliance.gdpr_report import GDPRRegister
        assert GDPRRegister is not None

    def test_add_and_export(self):
        from neuralbridge.compliance.gdpr_report import GDPRRegister, ProcessingActivity
        register = GDPRRegister(controller_name="Test Corp")
        register.add_activity(ProcessingActivity(
            name="Test Activity",
            purpose="Testing",
            data_categories=["email"],
        ))
        export = register.export_register()
        assert export["gdpr_article_30_register"]["total_activities"] == 1
