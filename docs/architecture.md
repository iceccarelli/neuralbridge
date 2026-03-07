# NeuralBridge Architecture

## Guiding Principles

The architecture of NeuralBridge is founded on three core principles:

- **Security by Design**: Every component is built with a zero-trust mindset. Security is not an afterthought but a foundational layer, from credential encryption to sandboxed execution.
- **Compliance as Code**: Regulatory requirements, particularly the EU Cyber Resilience Act (CRA), are embedded directly into the platform, enabling automated reporting and continuous readiness.
- **Universal Interoperability**: The platform is designed to be vendor-agnostic, supporting any AI agent and connecting to any enterprise system through a standardized adapter framework.

## System Overview

NeuralBridge acts as a secure, intelligent middleware layer. It intercepts requests from AI agents, enforces security and compliance policies, and translates them into actions performed by specialized adapters.

![NeuralBridge High-Level Architecture](assets/architecture_overview.png)
*A high-level overview of the NeuralBridge request flow, from AI Agent to Enterprise System.* 

## Core Components

The core of NeuralBridge is a collection of specialized, decoupled modules that work in concert to process requests.

| Component | Module Path | Description |
|---|---|---|
| **MCP Gateway** | `core/gateway.py` | The primary entry point for AI agents using the Model Context Protocol (MCP). It translates MCP tool calls into the internal NeuralBridge request format. |
| **Request Router** | `core/router.py` | The central nervous system. It validates requests, checks permissions against RBAC policies, enforces rate limits, and dispatches the request to the correct adapter. |
| **Sandbox Engine** | `security/sandbox.py` | **(New)** Provides secure, isolated execution for untrusted code, such as OpenClaw plugins. It uses Docker, subprocesses, or in-process controls to contain threats. |
| **Security Layer** | `security/` | A suite of modules for authentication (`auth.py`), credential encryption (`encryption.py`), immutable audit logging (`audit.py`), and role-based access control (`rbac.py`). |
| **Compliance Engine**| `compliance/` | Automates regulatory tasks, including EU CRA vulnerability reporting (`cra_report.py`), SBOM generation (`sbom.py`), and GDPR record-keeping (`gdpr_report.py`). |
| **Optimization Layer**| `optimization/` | Improves performance and reduces cost through response caching (`cache.py`), request batching (`batching.py`), and token cost estimation (`token_estimator.py`). |

## Data and Request Flow

A typical request follows a seven-step process, ensuring that every action is authenticated, authorized, logged, and executed securely.

1.  **Ingestion**: An AI agent sends a tool call to the MCP Gateway or a direct REST API endpoint.
2.  **Translation**: The Gateway translates the incoming request into a standardized `NeuralBridgeRequest` object.
3.  **Routing & Validation**: The Request Router selects the target adapter and validates the request against the configured permissions and rate limits for the agent's role.
4.  **Authentication & Encryption**: The Security Layer retrieves encrypted credentials from the Vault, decrypts them, and prepares the authentication context for the adapter.
5.  **Sandboxed Execution**: The adapter's `execute` method is invoked within the secure context of the Sandbox Engine, which isolates the process and monitors resource usage.
6.  **Audit Logging**: The result of the operation (success or failure), along with its duration and resource consumption, is recorded in the immutable, hash-chained audit log.
7.  **Response**: The normalized response is returned to the agent.

## Deployment Architecture

NeuralBridge is designed for flexible deployment, from local development to large-scale enterprise environments.

-   **Docker Compose**: The recommended method for development and small-scale production. Provides a one-command setup for the entire stack.
-   **Kubernetes & Helm**: For enterprise-grade scalability and resilience, NeuralBridge includes Kubernetes manifests and a Helm chart for easy deployment and management in a container orchestration environment.
-   **Serverless (Planned)**: Future versions will support deployment to serverless platforms like AWS Lambda and Google Cloud Functions for event-driven, pay-per-use workloads.
