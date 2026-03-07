# Compliance: EU CRA and GDPR Readiness

In today's regulatory landscape, compliance is a critical requirement for any enterprise software. NeuralBridge is designed with a "compliance as code" philosophy, embedding the requirements of major regulations like the EU's Cyber Resilience Act (CRA) and the General Data Protection Regulation (GDPR) directly into its architecture.

## EU Cyber Resilience Act (CRA)

The CRA is a landmark European regulation that imposes strict cybersecurity requirements on all products with digital elements sold in the EU. NeuralBridge provides a suite of tools to help organizations meet their CRA obligations, which come into full effect in 2026.

### Key CRA Features in NeuralBridge

| CRA Article | Requirement | NeuralBridge Solution |
|---|---|---|
| **Article 10** | Vulnerability Handling | The `compliance.cra_report` module provides a `CRAReport` engine that can automatically generate vulnerability disclosure reports in a machine-readable format. |
| **Article 11** | Duty of Care | The immutable, hash-chained audit log (`security.audit`) provides a verifiable record of all agent activities, demonstrating due diligence and care. |
| **Annex I** | Security Requirements | NeuralBridge's core security features, including RBAC, encryption, and sandboxing, directly address the security-by-design principles outlined in Annex I. |
| **Annex I** | Software Bill of Materials (SBOM) | The `compliance.sbom` module includes an `SBOMGenerator` that can produce a CycloneDX-compliant SBOM, providing transparency into all software components and dependencies. |

### Generating a CRA Vulnerability Report

NeuralBridge simplifies the process of reporting a newly discovered vulnerability, as required by the CRA.

```python
from neuralbridge.compliance import CRAReport

report = CRAReport(
    product_name="NeuralBridge Enterprise Edition",
    product_version="v1.2.3",
    vulnerability_id="CVE-2026-12345",
    description="A remote code execution vulnerability exists in the legacy reporting module.",
    severity="Critical",
    cvss_score=9.8,
    affected_components=["reporting-service"],
    remediation="Upgrade to v1.2.4 or apply patch NB-2026-001."
)

# Generate a machine-readable JSON report
report.save_json("cve-2026-12345.json")
```

## General Data Protection Regulation (GDPR)

GDPR governs how personal data of EU citizens is collected, processed, and stored. NeuralBridge's compliance engine helps organizations maintain their GDPR records.

### GDPR Article 30: Records of Processing Activities

Article 30 requires organizations to maintain a detailed record of all data processing activities. The `compliance.gdpr_report` module provides a `GDPRRegister` to automate the creation and maintenance of this record.

Whenever an agent interacts with a system containing personal data, NeuralBridge can automatically log the activity in the GDPR register.

### Example: Logging a Data Access Event

```python
from neuralbridge.compliance import GDPRRegister

register = GDPRRegister(company_name="Example Corp")

register.log_processing_activity(
    activity="Retrieve customer support history",
    purpose="To provide context for an AI-assisted support agent.",
    data_categories=["Contact Information", "Support Ticket History"],
    data_subjects=["Customers"],
    storage_location="Salesforce (EU-WEST-1)",
    retention_period="365 days"
)

# Export the full register to a CSV file for auditors
register.export_csv("gdpr_article_30_register.csv")
```

By integrating these compliance tools directly into the middleware layer, NeuralBridge transforms compliance from a manual, periodic task into an automated, continuous process, reducing risk and ensuring that the deployment of AI agents aligns with regulatory requirements.
