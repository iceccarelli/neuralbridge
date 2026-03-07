# NeuralBridge: The Universal Enterprise Middleware for Agentic AI

<p align="center">
  <a href="https://iceccarelli.github.io/neuralbridge/">
    <img src="https://raw.githubusercontent.com/iceccarelli/neuralbridge/main/docs/assets/neuralbridge_concept.png" alt="NeuralBridge Concept Diagram" width="700">
  </a>
</p>

<p align="center">
  <em>The missing infrastructure layer for agentic AI. Proudly developed by <strong>Grimaldi Engineering</strong>.</em>
</p>

<p align="center">
  <a href="https://github.com/iceccarelli/neuralbridge/actions/workflows/ci.yml"><img src="https://github.com/iceccarelli/neuralbridge/actions/workflows/ci.yml/badge.svg" alt="CI Status"></a>
  <a href="https://pypi.org/project/neuralbridge-middleware/"><img src="https://img.shields.io/pypi/v/neuralbridge-middleware.svg?color=blue" alt="PyPI version"></a>
  <a href="https://github.com/iceccarelli/neuralbridge/pkgs/container/neuralbridge"><img src="https://img.shields.io/badge/Docker-ghcr.io-blue?logo=docker" alt="Docker Image"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
</p>

---

**NeuralBridge** is an open-source, standardized adapter platform that lets ANY AI agent (OpenClaw, AutoGPT, LangChain, Claude, ChatGPT ) securely connect to ANY data source, API, or enterprise system with simple YAML configuration.

## The Enterprise Problem: Agents Can Think, But They Can't Act

The agentic AI ecosystem is exploding. Projects like **OpenClaw** prove that agents can reason, plan, and learn. But a critical gap prevents their adoption in the enterprise: how do they **act** in the real world—safely, securely, and at scale?

Enterprises are eager to deploy AI agents to automate complex workflows, but are blocked by fundamental challenges:

- **Security & Compliance:** How do you grant an LLM access to a production database without risking data exfiltration or violating GDPR?
- **Integration Complexity:** How do you connect an agent to a dozen different systems (Salesforce, SAP, Snowflake, etc.) without writing thousands of lines of brittle, custom code?
- **Lack of Standardization:** How do you manage a fleet of agents from different vendors, all speaking different protocols?

**NeuralBridge is the answer.** It provides the secure, standardized infrastructure layer that enterprises need to deploy agentic AI with confidence.

## Why NeuralBridge? The Value Proposition

| Feature | Description |
|---|---|
| **Universal Adapter Framework** | With 22+ pre-built adapters, NeuralBridge is the "Stripe for AI agents." Connect to any database, API, messaging platform, or enterprise system in minutes using simple YAML. |
| **Built-in EU CRA Compliance** | NeuralBridge is designed for the future of AI regulation. It comes ready for the **EU Cyber Resilience Act** (deadline Sept 2026) with immutable audit logs, SBOM generation, and vulnerability reporting. |
| **Zero-Trust Security Engine** | Every connection is protected by role-based access control (RBAC), credential encryption (via Vault), rate limiting, and a secure sandboxing engine that isolates every agent action. |
| **No-Code Configuration** | Business users can connect agents to systems via a beautiful React dashboard. No coding required to create, secure, and deploy a new connection. |
| **Agent-Agnostic Gateway** | A standardized entry point for any agent using the Model Context Protocol (MCP), with native support for the OpenClaw plugin ecosystem. |

## Quick Start

### 1. Docker Compose (Recommended)

```bash
docker compose up -d
Visit the dashboard at http://localhost:3000 and the API docs at http://localhost:8000/docs.
2. pip
Bash
pip install neuralbridge-middleware
neuralbridge serve
Architecture Overview
<p align="center"> <a href="https://iceccarelli.github.io/neuralbridge/architecture/"> <img src="https://raw.githubusercontent.com/iceccarelli/neuralbridge/main/docs/assets/architecture_overview.png" alt="NeuralBridge Architecture Diagram" width="800"> </a> </p>
See the full Architecture Documentation for a deep dive into the components.
Feature Deep Dive
Universal Adapter Framework
NeuralBridge ships with 22+ production-ready adapters that cover the most common enterprise integration scenarios. Each adapter is configured through a simple YAML file, requires no custom code, and is secured by the zero-trust engine out of the box.
Category
Supported Systems
Databases
PostgreSQL, MySQL, MongoDB, Snowflake, BigQuery
APIs
REST, GraphQL, SOAP, OData
Messaging
Slack, Teams, Discord, Telegram, Email
Productivity
Gmail, Notion
ERP / CRM
Salesforce, SAP
Cloud Storage
AWS S3, Azure Blob, Google Cloud Storage
Every adapter follows the same lifecycle: configure (YAML), authenticate (OAuth2, API key, or Vault), connect (health-checked), and audit (every operation is logged). Building a custom adapter requires implementing a single Python base class and registering it with the framework.
Secure Sandboxing Engine
NeuralBridge implements strict sandboxing for plugin execution, ensuring that untrusted code or third-party OpenClaw plugins cannot compromise the core middleware. The engine provides three isolation levels, selected automatically based on the runtime environment:
Isolation Level
Environment
Security
Description
Docker
Production
Highest
Each plugin runs in a disposable container with no network, read-only filesystem, limited memory/CPU, and a hard timeout.
Subprocess
Staging
Medium
Uses asyncio.create_subprocess_exec with ulimit resource guards and a restricted PATH.
In-Process
Development
Basic
Wraps execution in a restricted globals() scope with timeout enforcement.
The sandbox integrates directly with the EU CRA compliance engine, recording every execution in the immutable audit log — including the code hash, resource consumption, and exit status.
EU CRA Compliance Engine
With the EU Cyber Resilience Act deadline of September 2026 approaching, NeuralBridge provides a built-in compliance engine that ensures your AI agent deployments are audit-ready from day one.
Capability
Description
Immutable Audit Logs
Hash-chain-verified logs of every agent action. Every API call, database query, and plugin execution is recorded with a cryptographic proof of integrity.
SBOM Generation
Automatically generates CycloneDX-compliant Software Bill of Materials on every CI build.
Vulnerability Reporting
Generate CRA Article 14 vulnerability reports on demand, covering all dependencies and runtime components.
GDPR Data Mapping
Track which adapters access personal data and generate data-flow maps for your Data Protection Officer.
MCP Gateway
The Model Context Protocol (MCP) Gateway is the standardized entry point for any AI agent. It translates agent requests into adapter calls, enforces security policies, and returns structured results — all through a single, well-documented API.
NeuralBridge supports native integration with the OpenClaw plugin ecosystem, meaning any OpenClaw-compatible agent can discover and use NeuralBridge adapters as tools without additional configuration.
React Dashboard
<p align="center"> <a href="https://iceccarelli.github.io/neuralbridge/dashboard/"> <img src="https://raw.githubusercontent.com/iceccarelli/neuralbridge/main/docs/assets/dashboard_screenshot.png" alt="NeuralBridge Dashboard Screenshot" width="800"> </a> </p>
The dashboard provides a complete management interface for non-technical users:
Feature
Description
No-Code Connection Wizard
Create, configure, and deploy new adapter connections through an intuitive step-by-step UI.
Real-Time Monitoring
Live metrics on adapter health, request latency, error rates, and throughput.
Compliance Dashboard
At-a-glance CRA and GDPR readiness status with actionable recommendations.
Cost Optimization
Token cost analytics, caching hit rates, and recommendations to reduce API spend.
User Management
Role-based access control with audit trails for every administrative action.
Example: Connecting an Agent to Salesforce
Create a salesforce.yaml file:
YAML
adapters:
  salesforce:
    type: salesforce
    auth:
      type: oauth2
      client_id: ${SALESFORCE_CLIENT_ID}
      client_secret: ${SALESFORCE_CLIENT_SECRET}
      instance_url: https://yourorg.my.salesforce.com
    permissions:
      - query: "SELECT Id, Name FROM Account"
Run the connection:
Bash
neuralbridge connect --config salesforce.yaml
Now, any agent can use the salesforce_query tool through the NeuralBridge MCP gateway.
Documentation
Full documentation is available at iceccarelli.github.io/neuralbridge, including:
Getting Started Guide
Architecture Deep Dive
Adapter Reference
Security & Sandboxing
EU CRA Compliance
API Reference
Dashboard Guide
Contributing
We welcome contributions from the community! Please see our Contributing Guide to get started.
Security
For security vulnerabilities, please see our Security Policy.
Roadmap
See our Roadmap for planned features.
License
NeuralBridge is licensed under the MIT License.
Plain Text
