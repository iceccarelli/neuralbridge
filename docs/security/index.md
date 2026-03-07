# Security: A Zero-Trust Foundation

In an era where AI agents can act autonomously, security is not a feature; it is the foundation. NeuralBridge is built from the ground up on a **Zero-Trust** security model. This means that no request is trusted by default, whether it originates from an internal agent or an external system. Every action must be explicitly authenticated, authorized, and audited.

This section details the five core pillars of the NeuralBridge security architecture.

## The Five Pillars of NeuralBridge Security

| Pillar | Description | Module |
|---|---|---|
| [**Sandboxed Execution**](sandboxing.md) | All untrusted code, especially from OpenClaw plugins, is executed in a secure, isolated sandbox (using Docker or subprocesses) to contain threats and prevent exploits from affecting the core middleware. | `security.sandbox` |
| **Role-Based Access Control (RBAC)** | Granular permissions are assigned to roles, and agents are assigned to roles. This ensures that an agent can only perform the specific operations on the specific resources it is authorized for. | `security.rbac` |
| **Credential Encryption and Vaulting** | All sensitive credentials (API keys, passwords, tokens) are encrypted at rest using Fernet symmetric encryption and stored in a secure vault. They are only decrypted in memory at the moment of use. | `security.encryption` |
| **Immutable Audit Logging** | Every request, whether successful or not, is recorded in a hash-chained, immutable audit log. This provides a tamper-proof record of all agent activity for forensic analysis and compliance. | `security.audit` |
| [**Compliance as Code**](compliance.md) | Regulatory requirements from the EU Cyber Resilience Act (CRA) and GDPR are built directly into the platform, with automated engines for vulnerability reporting, SBOM generation, and data protection. | `compliance` |

## A Proactive Security Posture

NeuralBridge's security model is designed to be proactive, not reactive. By enforcing strict controls at every stage of the request lifecycle, it moves beyond simple perimeter defense to a model of intrinsic security. This approach not only protects against external threats but also mitigates the risk of insider threats or misconfigured agents.

This comprehensive, defense-in-depth strategy is what makes it possible to deploy powerful AI agents in sensitive enterprise environments with confidence.
