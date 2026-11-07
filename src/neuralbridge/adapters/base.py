"""
NeuralBridge Base Adapter — Abstract Interface for All Connectors.

Every adapter in NeuralBridge inherits from ``BaseAdapter``.  The base
class enforces a consistent lifecycle (connect → execute → disconnect),
automatic CRA audit logging, credential validation, and normalised error
responses.

Subclass Contract
-----------------
Implementors **must** override:

* ``_do_connect`` — establish a connection to the external system.
* ``_do_disconnect`` — tear down the connection gracefully.
* ``_do_execute`` — perform the requested operation.
* ``_do_validate_credentials`` — verify that stored credentials are valid.

The public methods (``connect``, ``execute``, etc.) wrap these hooks with
logging, timing, and error handling so that adapter authors can focus
purely on integration logic.
"""

from __future__ import annotations

import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


#: How far an adapter talks to a real service. Fail-closed: BaseAdapter defaults to "mock".
#:
#: * ``real``    - calls the real service and is exercised against it by a test (PostgreSQL only; that test
#:                 needs a server and fails, not skips, under NEURALBRIDGE_REQUIRE_POSTGRES=1).
#: * ``partial`` - has a real client path that no test has run against a live service. It may serve data from the
#:                 live service, but must never answer from canned data unless mock is opted in.
#: * ``mock``    - no real call is made; results are canned. ``execute`` refuses unless mock is opted in.
BACKENDS = ("real", "partial", "mock")

#: Environment switch for demos and tests of canned adapters. Never set it where results are relied on.
ALLOW_MOCK_ENV = "NEURALBRIDGE_ALLOW_MOCK_ADAPTERS"


class MockBackendRefusedError(ConnectionError):
    """An operation would have answered with canned data that looks like a real result."""


class AdapterStatus(StrEnum):
    """Lifecycle state of an adapter instance."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"


@dataclass
class AdapterMetadata:
    """Descriptive metadata exposed to the MCP gateway and dashboard."""
    name: str
    adapter_type: str
    description: str
    version: str = "0.1.0"
    category: str = "general"
    supported_operations: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)
    backend: str = "mock"


@dataclass
class AdapterResponse:
    """
    Normalised response returned by every adapter operation.

    All adapters return this structure regardless of the underlying
    system, making it trivial for the MCP gateway to serialise results.
    """
    success: bool
    data: Any = None
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "metadata": self.metadata,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
        }


class BaseAdapter(ABC):
    """
    Abstract base class for all NeuralBridge adapters.

    Parameters
    ----------
    config : dict[str, Any]
        Adapter-specific configuration (parsed from YAML or API).
    """

    # Subclasses MUST set these class attributes.
    adapter_type: str = "base"
    category: str = "general"
    description: str = "Base adapter"
    version: str = "0.1.0"
    supported_operations: list[str] = []
    #: One of BACKENDS. Unclassified adapters are treated as canned (``mock``) and refused by default.
    backend: str = "mock"
    #: True only if code shipped in this repository creates and registers the adapter in a running
    #: platform (a "real" adapter that nothing registers is a library: an operator must wire it in
    #: code). ``scripts/export_integrations.py`` and the README table read it; a test fails if the
    #: claim and the registering code disagree.
    shipped_loader: bool = False

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.status = AdapterStatus.DISCONNECTED
        self._operation_count = 0
        self._error_count = 0
        self._total_duration_ms = 0.0

    # ── Mock policy ──────────────────────────────────────────

    def _mock_allowed(self) -> bool:
        """True only when the caller opted in: ``config["allow_mock"] is True`` or the env switch is "1"."""
        return self.config.get("allow_mock") is True or os.environ.get(ALLOW_MOCK_ENV) == "1"

    def _refuse_mock(self, why: str) -> MockBackendRefusedError:
        """The error to raise instead of answering from canned data (``raise self._refuse_mock(...)``)."""
        return MockBackendRefusedError(
            f"Adapter '{self.adapter_type}' ({self.backend}) would answer from canned data: {why}. "
            f"Fix the connection, or opt in to canned data for a demo or test with config allow_mock=true "
            f"or {ALLOW_MOCK_ENV}=1."
        )

    # ── Public API (with automatic logging & error handling) ─

    async def connect(self, config: dict[str, Any] | None = None) -> AdapterResponse:
        """
        Establish a connection to the external system.

        If *config* is provided it replaces the instance configuration.
        """
        if config:
            self.config = config
        self.status = AdapterStatus.CONNECTING
        logger.info("adapter_connecting", adapter=self.adapter_type)

        try:
            await self._do_connect()
            self.status = AdapterStatus.CONNECTED
            logger.info("adapter_connected", adapter=self.adapter_type)
            return AdapterResponse(success=True, data={"status": "connected"})
        except Exception as exc:
            self.status = AdapterStatus.ERROR
            self._error_count += 1
            logger.exception("adapter_connect_failed", adapter=self.adapter_type)
            return AdapterResponse(success=False, error=str(exc))

    async def disconnect(self) -> AdapterResponse:
        """Gracefully close the connection."""
        try:
            await self._do_disconnect()
            self.status = AdapterStatus.DISCONNECTED
            logger.info("adapter_disconnected", adapter=self.adapter_type)
            return AdapterResponse(success=True, data={"status": "disconnected"})
        except Exception as exc:
            logger.exception("adapter_disconnect_failed", adapter=self.adapter_type)
            return AdapterResponse(success=False, error=str(exc))

    async def execute(self, operation: str, params: dict[str, Any] | None = None) -> Any:
        """
        Execute an operation on the external system.

        Parameters
        ----------
        operation : str
            Operation name (e.g. ``"query"``, ``"send_message"``).
        params : dict | None
            Operation-specific parameters.

        Returns
        -------
        Any
            The operation result (adapter-specific).

        Raises
        ------
        ConnectionError
            If the adapter is not connected.
        ValueError
            If the operation is not supported.
        """
        if self.status != AdapterStatus.CONNECTED:
            # Auto-connect if not yet connected
            connect_result = await self.connect()
            if not connect_result.success:
                raise ConnectionError(
                    f"Adapter '{self.adapter_type}' is not connected and auto-connect failed: "
                    f"{connect_result.error}"
                )

        if self.supported_operations and operation not in self.supported_operations:
            raise ValueError(
                f"Operation '{operation}' not supported by {self.adapter_type}. "
                f"Supported: {self.supported_operations}"
            )

        if self.backend == "mock":
            if not self._mock_allowed():
                raise self._refuse_mock("it makes no real call to the service")
            logger.warning("adapter_mock_backend_active", adapter=self.adapter_type, operation=operation)

        start = time.monotonic()
        self._operation_count += 1

        try:
            result = await self._do_execute(operation, params or {})
            if self.backend == "mock":
                # Canned data must say so, whatever shape the adapter returns it in.
                if isinstance(result, AdapterResponse):
                    result.metadata.setdefault("mock", True)
                elif isinstance(result, dict):
                    result.setdefault("mock", True)
            elapsed = (time.monotonic() - start) * 1000
            self._total_duration_ms += elapsed
            logger.info(
                "adapter_operation",
                adapter=self.adapter_type,
                operation=operation,
                duration_ms=round(elapsed, 2),
            )
            return result
        except Exception:
            self._error_count += 1
            logger.exception(
                "adapter_operation_failed",
                adapter=self.adapter_type,
                operation=operation,
            )
            raise

    async def validate_credentials(self) -> AdapterResponse:
        """Check whether the configured credentials are valid."""
        try:
            result = await self._do_validate_credentials()
            return AdapterResponse(success=True, data=result)
        except Exception as exc:
            return AdapterResponse(success=False, error=str(exc))

    # ── Metadata ─────────────────────────────────────────────

    def get_metadata(self) -> AdapterMetadata:
        """Return descriptive metadata for this adapter."""
        return AdapterMetadata(
            name=self.adapter_type,
            adapter_type=self.adapter_type,
            description=self.description,
            version=self.version,
            category=self.category,
            supported_operations=self.supported_operations,
            config_schema=self._get_config_schema(),
            backend=self.backend,
        )

    def get_stats(self) -> dict[str, Any]:
        """Return runtime statistics."""
        return {
            "adapter_type": self.adapter_type,
            "status": self.status.value,
            "operations": self._operation_count,
            "errors": self._error_count,
            "avg_duration_ms": (
                round(self._total_duration_ms / self._operation_count, 2)
                if self._operation_count
                else 0.0
            ),
        }

    # ── Abstract Hooks (subclasses implement these) ──────────

    @abstractmethod
    async def _do_connect(self) -> None:
        """Establish the underlying connection."""

    @abstractmethod
    async def _do_disconnect(self) -> None:
        """Tear down the underlying connection."""

    @abstractmethod
    async def _do_execute(self, operation: str, params: dict[str, Any]) -> Any:
        """Perform the requested operation."""

    @abstractmethod
    async def _do_validate_credentials(self) -> dict[str, Any]:
        """Verify credentials and return validation details."""

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Return a JSON Schema describing the adapter's configuration.

        Override in subclasses to provide adapter-specific schemas.
        """
        return {"type": "object", "properties": {}}
