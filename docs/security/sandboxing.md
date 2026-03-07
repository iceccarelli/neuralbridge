# Sandboxed Execution for Plugins

The ability to execute untrusted code, particularly plugins from ecosystems like OpenClaw, is a powerful but risky capability. The NeuralBridge Sandbox Engine is designed to mitigate this risk by providing multiple layers of isolation, ensuring that plugin failures or exploits are contained and cannot compromise the core middleware or the underlying system.

## The Threat Model

When executing third-party code, we must assume the code could be malicious (intentionally designed to steal data or disrupt services), buggy (leading to infinite loops or memory exhaustion), or vulnerable (containing security flaws that could be exploited). The Sandbox Engine is the primary defense against all of these threats.

## Isolation Levels

The Sandbox Engine supports three distinct isolation levels, automatically selecting the most secure option available in the deployment environment.

| Level | Implementation | Security | Performance | Use Case |
|---|---|---|---|---|
| **Docker** | Executes code in a dedicated, single-use Docker container with strict resource limits (`ulimit`). | **Highest** | Lower | Production environments where Docker is available. |
| **Subprocess** | Executes code in a separate child process with `prlimit` to enforce resource constraints. | **Medium** | Medium | Production or development environments on POSIX systems where Docker is not available. |
| **In-Process** | Executes code in a restricted Python environment within the main NeuralBridge process. | **Lowest** | Highest | Local development and testing only. |

## How It Works

When a request to execute a plugin is received, the `SandboxEngine` performs the following steps:

1.  **Policy Selection**: It applies a `SandboxPolicy`, which defines the rules for the execution, including `timeout_seconds`, `max_memory_mb`, and `denied_modules`.
2.  **Isolation Detection**: It detects the highest available isolation level (Docker > Subprocess > In-Process).
3.  **Execution**: It runs the code within the chosen isolated environment.
4.  **Monitoring**: It actively monitors the execution for timeouts, memory overruns, or illegal operations.
5.  **Result and Audit**: It captures the output, exit code, and any errors, records the entire event in the immutable audit log, and returns a structured `SandboxResult` to the caller.

## CRA Audit Integration

Every sandbox execution is automatically recorded in the immutable audit log, providing full traceability for EU CRA compliance. An optional `audit_callback` can be registered to receive real-time notifications of every execution result, enabling integration with external SIEM or compliance monitoring systems.

## Example: Executing an OpenClaw Plugin

```json
{
  "adapter": "system",
  "operation": "execute_plugin",
  "params": {
    "plugin_code": "print(2 + 3)",
    "context": {}
  }
}
```

NeuralBridge will execute this code inside a secure sandbox. Even if the plugin code contained `import os; os.system('rm -rf /')`, the sandbox would prevent the `os` module from being imported, neutralizing the threat. This robust, multi-layered approach to sandboxing is what enables NeuralBridge to safely extend its capabilities with third-party code.
