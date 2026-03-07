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
