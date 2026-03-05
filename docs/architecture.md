# NeuralBridge Architecture

## System Overview

NeuralBridge is a **middleware platform** that sits between AI agents and enterprise systems. It provides a standardized, secure, and compliant interface for agent-to-system communication.

```
┌─────────────────────────────────────────────────────────────┐
│                      AI Agents                              │
│  OpenClaw  │  AutoGPT  │  LangChain  │  Claude  │  Custom  │
└─────┬──────┴─────┬─────┴──────┬──────┴────┬─────┴────┬─────┘
      │            │            │           │          │
      ▼            ▼            ▼           ▼          ▼
┌─────────────────────────────────────────────────────────────┐
│                    NeuralBridge Core                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐ │
│  │   MCP    │  │ Request  │  │ Security │  │ Compliance │ │
│  │ Gateway  │  │  Router  │  │  Layer   │  │   Engine   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘ │
│       │              │             │              │         │
│  ┌────▼──────────────▼─────────────▼──────────────▼──────┐ │
│  │              Universal Adapter Framework               │ │
│  └──┬────┬────┬────┬────┬────┬────┬────┬────┬────┬───────┘ │
└─────┼────┼────┼────┼────┼────┼────┼────┼────┼────┼─────────┘
      │    │    │    │    │    │    │    │    │    │
      ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐┌────┐
│ PG ││ SF ││Slck││ S3 ││REST││ SAP││GQL ││Gmil││Ntn ││ .. │
└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘└────┘
```

## Core Components

### 1. MCP Gateway (`core/gateway.py`)

The MCP (Model Context Protocol) Gateway is the primary entry point for AI agents. It translates MCP tool calls into NeuralBridge adapter operations.

### 2. Request Router (`core/router.py`)

The intelligent request router dispatches incoming requests to the appropriate adapter, handling:
- Adapter selection and validation
- Operation permission checking
- Rate limit enforcement
- Audit logging

### 3. Execution Engine (`core/executor.py`)

Provides sandboxed execution with resource limits, timeout management, and error isolation.

### 4. Security Layer

| Component | Purpose |
|-----------|---------|
| `security/auth.py` | Multi-strategy authentication (OAuth2, JWT, API keys) |
| `security/encryption.py` | Credential vault with Fernet encryption |
| `security/audit.py` | Immutable, hash-chain audit logging |
| `security/rbac.py` | Role-based access control (4 roles) |
| `security/rate_limit.py` | Token bucket rate limiting |

### 5. Compliance Engine

| Component | Purpose |
|-----------|---------|
| `compliance/cra_report.py` | EU CRA Article 14 vulnerability reports |
| `compliance/sbom.py` | CycloneDX SBOM generation |
| `compliance/incident_log.py` | Structured incident logging |
| `compliance/gdpr_report.py` | GDPR Article 30 register |

### 6. Optimization Layer

| Component | Purpose |
|-----------|---------|
| `optimization/cache.py` | Response caching with Redis |
| `optimization/batching.py` | Request batching for efficiency |
| `optimization/token_estimator.py` | Token cost prediction |

## Adapter Architecture

Every adapter extends `BaseAdapter` and implements:

```python
class MyAdapter(BaseAdapter):
    async def _do_connect(self) -> None: ...
    async def _do_disconnect(self) -> None: ...
    async def _do_execute(self, operation: str, params: dict) -> Any: ...
    async def _do_validate_credentials(self) -> dict: ...
    def _get_config_schema(self) -> dict: ...
```

## Data Flow

1. **Agent** sends a tool call via MCP or REST API
2. **Gateway** translates the call into a NeuralBridge request
3. **Router** validates permissions, checks rate limits, selects adapter
4. **Security Layer** authenticates, encrypts, and logs the request
5. **Adapter** executes the operation against the target system
6. **Response** flows back through the same chain with audit logging
7. **Compliance Engine** records the operation for CRA/GDPR reporting

## Deployment Architecture

NeuralBridge supports multiple deployment models:

- **Docker Compose** — Development and small-scale production
- **Kubernetes** — Enterprise-scale with auto-scaling (3–20 replicas)
- **Helm Chart** — Simplified Kubernetes deployment
- **Serverless** — AWS Lambda / Google Cloud Functions (planned)
