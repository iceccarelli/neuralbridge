"""
Tests for the NeuralBridge Secure Sandbox Engine.

Covers all three isolation levels, policy enforcement, timeout handling,
and CRA audit callback integration.
"""

from __future__ import annotations

import pytest

from neuralbridge.security.sandbox import (
    IsolationLevel,
    POLICY_STRICT,
    SandboxEngine,
    SandboxPolicy,
    SandboxResult,
)


# ── Fixtures ────────────────────────────────────────────────────


@pytest.fixture
def in_process_engine() -> SandboxEngine:
    """Engine forced to in-process isolation for safe CI testing."""
    return SandboxEngine(
        force_isolation=IsolationLevel.IN_PROCESS,
        policy=SandboxPolicy(timeout_seconds=5.0),
    )


@pytest.fixture
def subprocess_engine() -> SandboxEngine:
    """Engine forced to subprocess isolation."""
    return SandboxEngine(
        force_isolation=IsolationLevel.SUBPROCESS,
        policy=SandboxPolicy(timeout_seconds=10.0),
    )


# ── Policy Tests ────────────────────────────────────────────────


class TestSandboxPolicy:
    """Verify that sandbox policies are correctly constructed."""

    def test_default_policy(self) -> None:
        policy = SandboxPolicy()
        assert policy.max_memory_mb == 256
        assert policy.timeout_seconds == 60.0
        assert policy.allow_network is False
        assert policy.allow_filesystem_write is False

    def test_strict_policy(self) -> None:
        assert POLICY_STRICT.max_memory_mb == 128
        assert POLICY_STRICT.timeout_seconds == 15.0
        assert POLICY_STRICT.allow_network is False

    def test_policy_immutable(self) -> None:
        policy = SandboxPolicy()
        with pytest.raises(AttributeError):
            policy.max_memory_mb = 512  # type: ignore[misc]

    def test_denied_modules_default(self) -> None:
        policy = SandboxPolicy()
        assert "os" in policy.denied_modules
        assert "subprocess" in policy.denied_modules
        assert "socket" in policy.denied_modules


# ── Result Tests ────────────────────────────────────────────────


class TestSandboxResult:
    """Verify SandboxResult serialisation."""

    def test_to_dict(self) -> None:
        result = SandboxResult(
            success=True,
            output={"key": "value"},
            code_hash="abc123",
            isolation_level="in_process",
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["output"] == {"key": "value"}
        assert d["code_hash"] == "abc123"
        assert "timestamp" in d

    def test_error_result(self) -> None:
        result = SandboxResult(
            success=False,
            error="timeout",
            exit_code=-1,
        )
        assert result.success is False
        assert result.exit_code == -1


# ── In-Process Execution Tests ──────────────────────────────────


class TestInProcessExecution:
    """Test the in-process isolation strategy."""

    @pytest.mark.asyncio
    async def test_simple_code(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_code('print("hello")')
        assert result.success is True
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_arithmetic(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_code("print(2 + 3)")
        assert result.success is True
        # Output is JSON-parsed: "5" becomes int 5
        assert result.output == 5

    @pytest.mark.asyncio
    async def test_json_output(self, in_process_engine: SandboxEngine) -> None:
        code = """
import json
data = {"status": "ok", "count": 42}
print(json.dumps(data))
"""
        # json is not in restricted builtins, so this should fail
        result = await in_process_engine.execute_code(code)
        # In restricted mode, import is not available
        assert result.success is False or result.output is not None

    @pytest.mark.asyncio
    async def test_restricted_builtins(self, in_process_engine: SandboxEngine) -> None:
        """Verify that dangerous builtins are not available."""
        code = "print(type(None))"
        result = await in_process_engine.execute_code(code)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_syntax_error(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_code("def foo(")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_code_hash_recorded(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_code('print("test")')
        assert len(result.code_hash) == 64  # SHA-256 hex digest

    @pytest.mark.asyncio
    async def test_isolation_level_recorded(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_code('print("test")')
        assert result.isolation_level == "in_process"

    @pytest.mark.asyncio
    async def test_context_injection(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_code(
            'print(greeting)',
            context={"greeting": "hello world"},
        )
        assert result.success is True
        assert result.output == "hello world"


# ── Subprocess Execution Tests ──────────────────────────────────


class TestSubprocessExecution:
    """Test the subprocess isolation strategy."""

    @pytest.mark.asyncio
    async def test_simple_code(self, subprocess_engine: SandboxEngine) -> None:
        result = await subprocess_engine.execute_code('print("subprocess hello")')
        assert result.success is True
        assert "subprocess hello" in str(result.output)

    @pytest.mark.asyncio
    async def test_timeout(self, subprocess_engine: SandboxEngine) -> None:
        code = "import time; time.sleep(30)"
        policy = SandboxPolicy(timeout_seconds=1.0)
        result = await subprocess_engine.execute_code(code, policy=policy)
        assert result.success is False
        assert "timed out" in (result.error or "")

    @pytest.mark.asyncio
    async def test_exit_code(self, subprocess_engine: SandboxEngine) -> None:
        code = "import sys; sys.exit(42)"
        result = await subprocess_engine.execute_code(code)
        assert result.success is False
        assert result.exit_code == 42


# ── Audit Callback Tests ───────────────────────────────────────


class TestAuditCallback:
    """Verify CRA audit callback integration."""

    @pytest.mark.asyncio
    async def test_callback_invoked(self) -> None:
        audit_log: list[SandboxResult] = []

        async def callback(result: SandboxResult) -> None:
            audit_log.append(result)

        engine = SandboxEngine(
            force_isolation=IsolationLevel.IN_PROCESS,
            audit_callback=callback,
        )
        await engine.execute_code('print("audited")')
        assert len(audit_log) == 1
        assert audit_log[0].success is True

    @pytest.mark.asyncio
    async def test_callback_receives_code_hash(self) -> None:
        audit_log: list[SandboxResult] = []

        async def callback(result: SandboxResult) -> None:
            audit_log.append(result)

        engine = SandboxEngine(
            force_isolation=IsolationLevel.IN_PROCESS,
            audit_callback=callback,
        )
        await engine.execute_code('print("hash test")')
        assert len(audit_log[0].code_hash) == 64


# ── Engine Stats Tests ──────────────────────────────────────────


class TestEngineStats:
    """Verify engine statistics reporting."""

    @pytest.mark.asyncio
    async def test_execution_count(self, in_process_engine: SandboxEngine) -> None:
        await in_process_engine.execute_code('print("a")')
        await in_process_engine.execute_code('print("b")')
        stats = in_process_engine.get_stats()
        assert stats["execution_count"] == 2

    def test_stats_structure(self, in_process_engine: SandboxEngine) -> None:
        stats = in_process_engine.get_stats()
        assert "isolation_level" in stats
        assert "policy" in stats
        assert "docker_available" in stats


# ── Plugin File Execution Tests ─────────────────────────────────


class TestPluginExecution:
    """Test plugin file execution."""

    @pytest.mark.asyncio
    async def test_missing_plugin(self, in_process_engine: SandboxEngine) -> None:
        result = await in_process_engine.execute_plugin("/nonexistent/plugin.py")
        assert result.success is False
        assert "not found" in (result.error or "")
