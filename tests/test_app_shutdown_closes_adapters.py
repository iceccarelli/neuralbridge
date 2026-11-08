"""Shutting the app down disconnects every registered adapter, and one failure stops nothing.

``main.lifespan`` used to end with a comment ("cleanup would go here in production"), so asyncpg
pools bound for /ai connections were left to the garbage collector: about 90 unclosed connections
and 90 sockets per full test run with ResourceWarning shown (found by the packaging review).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from neuralbridge.adapters.base import AdapterResponse
from neuralbridge.api.dependencies import get_adapter_registry
from neuralbridge.main import create_app


class _Fake:
    """Duck-typed: the registry and the shutdown path only need these two members."""

    def __init__(self, name: str, log: list[str], *, fail: bool = False) -> None:
        self.adapter_type, self._log, self._fail = name, log, fail

    async def disconnect(self) -> AdapterResponse:
        self._log.append(self.adapter_type)
        if self._fail:
            raise RuntimeError("boom")
        return AdapterResponse(success=True)


def test_shutdown_disconnects_every_registered_adapter_even_if_one_fails() -> None:
    log: list[str] = []
    registry = get_adapter_registry()
    keys = ["zz-test-a", "zz-test-b"]
    registry.register(_Fake("zz-test-a", log, fail=True), key=keys[0])
    registry.register(_Fake("zz-test-b", log), key=keys[1])
    try:
        with TestClient(create_app()):
            assert log == []                      # nothing is closed while the app runs
        assert set(keys) <= set(log), f"adapters not disconnected at shutdown: {log}"
    finally:
        for key in keys:
            registry.unregister(key)
