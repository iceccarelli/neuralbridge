# NeuralBridge: Universal Enterprise Middleware for Agentic AI

**The missing infrastructure layer for agentic AI.** NeuralBridge is an open-source, standardized adapter platform that lets ANY AI agent (OpenClaw, AutoGPT, LangChain, Claude, ChatGPT) securely connect to ANY data source, API, or enterprise system with simple YAML configuration.

[![CI](https://github.com/your-org/neuralbridge/actions/workflows/ci.yml/badge.svg)](https://github.com/your-org/neuralbridge/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/neuralbridge.svg)](https://badge.fury.io/py/neuralbridge)
[![Docker Hub](https://img.shields.io/docker/pulls/your-org/neuralbridge.svg)](https://hub.docker.com/r/your-org/neuralbridge)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Opportunity: Enterprise-Grade Agentic AI Middleware

The agentic AI ecosystem is exploding. Projects like **OpenClaw** prove that agents can think, but a critical gap remains: how do they **act** in the real world—safely, securely, and at enterprise scale?

Enterprises are eager to adopt AI agents but are blocked by compliance, security, and integration challenges. NeuralBridge is the answer.

## Why NeuralBridge?

| Feature | Description |
|---|---|
| **Universal Adapters** | 22+ pre-built adapters for databases, APIs, messaging, ERP/CRM, and cloud. Think "Stripe for AI agents." |
| **Built-in CRA Compliance** | Ready for the **EU Cyber Resilience Act** (deadline Sept 2026) with immutable audit logs, SBOM generation, and vulnerability reporting. |
| **Zero-Trust Security** | Role-based access control (RBAC), credential encryption, and rate limiting for every connection. |
| **No-Code Configuration** | Business users can connect agents to systems via a beautiful React dashboard and simple YAML files. |
| **OpenClaw Integration** | Native support for the OpenClaw plugin ecosystem. |
| **MCP Gateway** | A standardized entry point for any agent using the Model Context Protocol. |

## Quick Start

### 1. Docker Compose (Recommended)

```bash
docker compose up -d
```

Visit the dashboard at `http://localhost:3000` and the API docs at `http://localhost:8000/docs`.

### 2. pip

```bash
pip install neuralbridge
neuralbridge serve
```

### 3. Example: Connecting an Agent to Salesforce

Create a `salesforce.yaml` file:

```yaml
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
```

Run the connection:

```bash
neuralbridge connect --config salesforce.yaml
```

Now, any agent can use the `salesforce_query` tool through the NeuralBridge MCP gateway.

## Architecture

![NeuralBridge Architecture](docs/architecture.png)

See the full [Architecture Documentation](docs/architecture.md).

## Key Features

### Universal Adapter Framework

Connect to anything with our 22+ adapters:

- **Databases**: PostgreSQL, MySQL, MongoDB, Snowflake, BigQuery
- **APIs**: REST, GraphQL, SOAP, OData
- **Messaging**: Slack, Teams, Discord, Telegram, Email
- **Productivity**: Gmail, Notion
- **ERP / CRM**: Salesforce, SAP
- **Cloud**: AWS S3, Azure Blob, Google Cloud Storage

### EU CRA Compliance Engine

NeuralBridge is designed for the future of AI regulation.

- **Immutable Audit Logs**: Hash-chain-verified logs of every agent action.
- **SBOM Generation**: CycloneDX-compliant Software Bill of Materials.
- **Vulnerability Reporting**: Generate CRA Article 14 reports on demand.

### React Dashboard

- **No-Code Connection Wizard**: Intuitive UI for non-technical users.
- **Compliance Monitoring**: Real-time CRA and GDPR readiness status.
- **Cost Optimization**: Token cost analytics and caching recommendations.

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) to get started.

## Security

For security vulnerabilities, please see our [Security Policy](SECURITY.md).

## Roadmap

See our [Roadmap](ROADMAP.md) for planned features.

## License

NeuralBridge is licensed under the [MIT License](LICENSE).

---

*Keywords: OpenClaw integration, AI agent middleware, CRA compliance, agentic AI, MCP gateway, enterprise AI, large language models, secure AI, AI infrastructure.*
