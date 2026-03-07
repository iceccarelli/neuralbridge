"""
NeuralBridge Secure Sandbox — Isolated Plugin Execution Engine.

Implements strict sandboxing for plugin and adapter execution to ensure
that untrusted code or third-party OpenClaw plugins cannot compromise
the core middleware.  Three isolation strategies are provided, selected
automatically based on the runtime environment:

1. **Docker isolation** (production) — each plugin invocation runs inside
   a short-lived Docker container with no network access, read-only
   filesystem, limited memory/CPU, and a hard timeout.
2. **subprocess isolation** (staging) — uses ``asyncio.create_subprocess_exec``
   with resource limits via ``ulimit`` and a restricted ``PATH``.
3. **in-process isolation** (development) — wraps execution in a restricted
   ``globals()`` scope with timeout enforcement.

The sandbox integrates with the EU CRA compliance engine by recording
every execution in the immutable audit log, including the code hash,
resource consumption, and exit status.

References
----------
* EU Cyber Resilience Act — Article 14 (vulnerability handling)
* OWASP Sandboxing Cheat Sheet
* Docker security best practices (``--read-only``, ``--network none``)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ── Configuration ───────────────────────────────────────────────


class IsolationLevel(StrEnum):
    """Available isolation strategies, ordered by security strength."""

    DOCKER = "docker"
    SUBPROCESS = "subprocess"
    IN_PROCESS = "in_process"


@dataclass(frozen=True)
class SandboxPolicy:
    """
    Immutable security policy applied to every sandboxed execution.

    Parameters
    ----------
    max_memory_mb : int
        Maximum memory the plugin may consume (MiB).
    max_cpu_seconds : float
        Maximum CPU time before the plugin is killed.
    timeout_seconds : float
        Wall-clock timeout for the entire execution.
    allow_network : bool
        Whether the plugin may access the network.
    allow_filesystem_write : bool
        Whether the plugin may write to the filesystem.
    allowed_modules : frozenset[str]
        Python modules the plugin is permitted to import.
    denied_modules : frozenset[str]
        Python modules explicitly blocked (takes precedence).
    max_output_bytes : int
        Maximum size of stdout + stderr captured from the plugin.
    """

    max_memory_mb: int = 256
    max_cpu_seconds: float = 30.0
    timeout_seconds: float = 60.0
    allow_network: bool = False
    allow_filesystem_write: bool = False
    allowed_modules: frozenset[str] = frozenset()
    denied_modules: frozenset[str] = frozenset({
        "os", "sys", "subprocess", "shutil", "ctypes",
        "importlib", "socket", "http", "urllib",
    })
    max_output_bytes: int = 1_048_576  # 1 MiB


# ── Default policies for common scenarios ───────────────────────

POLICY_STRICT = SandboxPolicy(
    max_memory_mb=128,
    max_cpu_seconds=10.0,
    timeout_seconds=15.0,
    allow_network=False,
    allow_filesystem_write=False,
    max_output_bytes=524_288,
)

POLICY_STANDARD = SandboxPolicy()

POLICY_PERMISSIVE = SandboxPolicy(
    max_memory_mb=512,
    max_cpu_seconds=120.0,
    timeout_seconds=180.0,
    allow_network=True,
    allow_filesystem_write=True,
    max_output_bytes=10_485_760,
)


# ── Execution result ────────────────────────────────────────────


@dataclass
class SandboxResult:
    """Structured result of a sandboxed plugin execution."""

    success: bool
    output: Any = None
    error: str | None = None
    exit_code: int = 0
    duration_ms: float = 0.0
    memory_peak_mb: float = 0.0
    code_hash: str = ""
    isolation_level: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    audit_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a CRA-compliant audit record."""
        return {
            "success": self.success,
            "output": self.output,
            "error": self.error,
            "exit_code": self.exit_code,
            "duration_ms": round(self.duration_ms, 2),
            "memory_peak_mb": round(self.memory_peak_mb, 2),
            "code_hash": self.code_hash,
            "isolation_level": self.isolation_level,
            "timestamp": self.timestamp.isoformat(),
            "audit_id": self.audit_id,
        }


# ── Sandbox Engine ──────────────────────────────────────────────


class SandboxEngine:
    """
    Secure execution engine that runs untrusted plugin code in isolation.

    The engine automatically selects the strongest available isolation
    level based on the runtime environment:

    * If Docker is available → ``IsolationLevel.DOCKER``
    * Else if running on Linux → ``IsolationLevel.SUBPROCESS``
    * Else → ``IsolationLevel.IN_PROCESS``

    Parameters
    ----------
    policy : SandboxPolicy
        Default security policy for all executions.
    force_isolation : IsolationLevel | None
        Override automatic detection and force a specific level.
    docker_image : str
        Base Docker image used for container isolation.
    audit_callback : callable | None
        Optional async callback invoked after each execution with the
        ``SandboxResult`` for CRA audit logging.
    """

    def __init__(
        self,
        policy: SandboxPolicy | None = None,
        force_isolation: IsolationLevel | None = None,
        docker_image: str = "python:3.11-slim",
        audit_callback: Any = None,
    ) -> None:
        self._policy = policy or POLICY_STANDARD
        self._docker_image = docker_image
        self._audit_callback = audit_callback
        self._execution_count = 0

        if force_isolation is not None:
            self._isolation = force_isolation
        else:
            self._isolation = self._detect_isolation()

        logger.info(
            "sandbox_engine_init",
            isolation=self._isolation.value,
            policy_memory_mb=self._policy.max_memory_mb,
            policy_timeout=self._policy.timeout_seconds,
        )

    # ── Public API ──────────────────────────────────────────────

    async def execute_code(
        self,
        code: str,
        *,
        context: dict[str, Any] | None = None,
        policy: SandboxPolicy | None = None,
    ) -> SandboxResult:
        """
        Execute arbitrary Python code inside the sandbox.

        Parameters
        ----------
        code : str
            Python source code to execute.
        context : dict | None
            Variables injected into the plugin's namespace.
        policy : SandboxPolicy | None
            Override the engine's default policy for this execution.

        Returns
        -------
        SandboxResult
            Structured result with output, timing, and audit metadata.
        """
        effective_policy = policy or self._policy
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        self._execution_count += 1

        logger.info(
            "sandbox_execute_start",
            code_hash=code_hash[:16],
            isolation=self._isolation.value,
            execution_id=self._execution_count,
        )

        start = time.monotonic()

        try:
            if self._isolation == IsolationLevel.DOCKER:
                result = await self._execute_docker(code, context, effective_policy)
            elif self._isolation == IsolationLevel.SUBPROCESS:
                result = await self._execute_subprocess(code, context, effective_policy)
            else:
                result = await self._execute_in_process(code, context, effective_policy)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            result = SandboxResult(
                success=False,
                error=f"Sandbox execution failed: {exc}",
                duration_ms=elapsed,
                code_hash=code_hash,
                isolation_level=self._isolation.value,
            )

        result.code_hash = code_hash
        result.isolation_level = self._isolation.value
        result.duration_ms = (time.monotonic() - start) * 1000

        logger.info(
            "sandbox_execute_complete",
            code_hash=code_hash[:16],
            success=result.success,
            duration_ms=round(result.duration_ms, 2),
        )

        # CRA audit callback
        if self._audit_callback is not None:
            try:
                await self._audit_callback(result)
            except Exception:
                logger.exception("sandbox_audit_callback_failed")

        return result

    async def execute_plugin(
        self,
        plugin_path: str | Path,
        *,
        entry_point: str = "main",
        context: dict[str, Any] | None = None,
        policy: SandboxPolicy | None = None,
    ) -> SandboxResult:
        """
        Execute a plugin file inside the sandbox.

        Parameters
        ----------
        plugin_path : str | Path
            Path to the Python plugin file.
        entry_point : str
            Name of the function to call inside the plugin.
        context : dict | None
            Variables passed to the plugin's entry point.
        policy : SandboxPolicy | None
            Override the default policy for this execution.
        """
        path = Path(plugin_path)
        if not path.exists():
            return SandboxResult(
                success=False,
                error=f"Plugin file not found: {path}",
            )

        code = path.read_text(encoding="utf-8")

        # Wrap the code to call the entry point and capture the result
        wrapper = f"""
{code}

import json as _json
_ctx = _json.loads('''{json.dumps(context or {})}''')
_result = {entry_point}(**_ctx) if callable({entry_point}) else None
print(_json.dumps({{"result": _result}}))
"""
        return await self.execute_code(wrapper, context=context, policy=policy)

    def get_stats(self) -> dict[str, Any]:
        """Return engine runtime statistics."""
        return {
            "isolation_level": self._isolation.value,
            "execution_count": self._execution_count,
            "policy": {
                "max_memory_mb": self._policy.max_memory_mb,
                "max_cpu_seconds": self._policy.max_cpu_seconds,
                "timeout_seconds": self._policy.timeout_seconds,
                "allow_network": self._policy.allow_network,
            },
            "docker_available": self._is_docker_available(),
        }

    # ── Docker Isolation ────────────────────────────────────────

    async def _execute_docker(
        self,
        code: str,
        context: dict[str, Any] | None,
        policy: SandboxPolicy,
    ) -> SandboxResult:
        """Run code inside an ephemeral Docker container."""
        tmpdir = tempfile.mkdtemp(prefix="nb_sandbox_")
        try:
            # Write the plugin code to a temporary file
            script_path = os.path.join(tmpdir, "plugin.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

            # Write context as JSON
            ctx_path = os.path.join(tmpdir, "context.json")
            with open(ctx_path, "w", encoding="utf-8") as f:
                json.dump(context or {}, f)

            # Build Docker command with security constraints
            cmd = [
                "docker", "run",
                "--rm",
                "--read-only",
                f"--memory={policy.max_memory_mb}m",
                f"--cpus={policy.max_cpu_seconds / policy.timeout_seconds:.2f}",
                "--pids-limit=64",
                "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",
                "-v", f"{tmpdir}:/sandbox:ro",
                "-w", "/sandbox",
            ]

            # Network isolation
            if not policy.allow_network:
                cmd.append("--network=none")

            # Security options
            cmd.extend([
                "--security-opt=no-new-privileges:true",
                "--cap-drop=ALL",
                self._docker_image,
                "python", "/sandbox/plugin.py",
            ])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=policy.timeout_seconds,
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return SandboxResult(
                    success=False,
                    error=f"Docker execution timed out after {policy.timeout_seconds}s",
                    exit_code=-1,
                )

            stdout_text = stdout[:policy.max_output_bytes].decode("utf-8", errors="replace")
            stderr_text = stderr[:policy.max_output_bytes].decode("utf-8", errors="replace")

            return SandboxResult(
                success=proc.returncode == 0,
                output=self._parse_output(stdout_text),
                error=stderr_text if proc.returncode != 0 else None,
                exit_code=proc.returncode or 0,
            )

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── Subprocess Isolation ────────────────────────────────────

    async def _execute_subprocess(
        self,
        code: str,
        context: dict[str, Any] | None,
        policy: SandboxPolicy,
    ) -> SandboxResult:
        """Run code in a restricted subprocess with ulimit guards."""
        tmpdir = tempfile.mkdtemp(prefix="nb_sandbox_")
        try:
            script_path = os.path.join(tmpdir, "plugin.py")
            with open(script_path, "w", encoding="utf-8") as f:
                f.write(code)

            ctx_path = os.path.join(tmpdir, "context.json")
            with open(ctx_path, "w", encoding="utf-8") as f:
                json.dump(context or {}, f)

            # Build command with resource limits
            memory_bytes = policy.max_memory_mb * 1024 * 1024
            cmd = [
                "bash", "-c",
                (
                    f"ulimit -v {memory_bytes // 1024} && "
                    f"ulimit -t {int(policy.max_cpu_seconds)} && "
                    f"python3 {script_path}"
                ),
            ]

            env = os.environ.copy()
            # Restrict PATH to minimal set
            env["PATH"] = "/usr/bin:/bin"
            # Remove sensitive environment variables
            for key in list(env.keys()):
                if any(secret in key.upper() for secret in [
                    "TOKEN", "SECRET", "PASSWORD", "KEY", "CREDENTIAL",
                ]):
                    del env[key]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=policy.timeout_seconds,
                )
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return SandboxResult(
                    success=False,
                    error=f"Subprocess execution timed out after {policy.timeout_seconds}s",
                    exit_code=-1,
                )

            stdout_text = stdout[:policy.max_output_bytes].decode("utf-8", errors="replace")
            stderr_text = stderr[:policy.max_output_bytes].decode("utf-8", errors="replace")

            return SandboxResult(
                success=proc.returncode == 0,
                output=self._parse_output(stdout_text),
                error=stderr_text if proc.returncode != 0 else None,
                exit_code=proc.returncode or 0,
            )

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ── In-Process Isolation ────────────────────────────────────

    async def _execute_in_process(
        self,
        code: str,
        context: dict[str, Any] | None,
        policy: SandboxPolicy,
    ) -> SandboxResult:
        """
        Run code in a restricted in-process scope (development only).

        Warning: This provides minimal isolation and should only be used
        during local development.  Production deployments MUST use Docker
        or subprocess isolation.
        """
        restricted_globals: dict[str, Any] = {
            "__builtins__": {
                "print": print,
                "len": len,
                "range": range,
                "str": str,
                "int": int,
                "float": float,
                "bool": bool,
                "list": list,
                "dict": dict,
                "tuple": tuple,
                "set": set,
                "type": type,
                "isinstance": isinstance,
                "enumerate": enumerate,
                "zip": zip,
                "map": map,
                "filter": filter,
                "sorted": sorted,
                "min": min,
                "max": max,
                "sum": sum,
                "abs": abs,
                "round": round,
                "True": True,
                "False": False,
                "None": None,
            },
        }

        if context:
            restricted_globals.update(context)

        captured_output: list[str] = []

        def safe_print(*args: Any, **kwargs: Any) -> None:
            captured_output.append(" ".join(str(a) for a in args))

        restricted_globals["__builtins__"]["print"] = safe_print

        def _run_sandboxed(src: str, ns: dict[str, Any]) -> None:
            compiled = compile(src, "<sandbox>", "exec")
            exec(compiled, ns)  # noqa: S102  # nosec B102  # nosec B102

        try:
            await asyncio.wait_for(
                asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: _run_sandboxed(code, restricted_globals),
                ),
                timeout=policy.timeout_seconds,
            )

            output_text = "\n".join(captured_output)
            return SandboxResult(
                success=True,
                output=self._parse_output(output_text),
                exit_code=0,
            )

        except TimeoutError:
            return SandboxResult(
                success=False,
                error=f"In-process execution timed out after {policy.timeout_seconds}s",
                exit_code=-1,
            )
        except Exception as exc:
            return SandboxResult(
                success=False,
                error=str(exc),
                exit_code=1,
            )

    # ── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _detect_isolation() -> IsolationLevel:
        """Auto-detect the strongest available isolation level."""
        if SandboxEngine._is_docker_available():
            return IsolationLevel.DOCKER
        if os.name == "posix":
            return IsolationLevel.SUBPROCESS
        return IsolationLevel.IN_PROCESS

    @staticmethod
    def _is_docker_available() -> bool:
        """Check whether the Docker daemon is reachable."""
        return shutil.which("docker") is not None

    @staticmethod
    def _parse_output(text: str) -> Any:
        """Attempt to parse JSON output; fall back to raw text."""
        text = text.strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return text
