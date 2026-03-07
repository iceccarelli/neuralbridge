"""
NeuralBridge Adapter for Salesforce CRM.

This adapter provides a mocked interface to the Salesforce REST API,
enabling AI agents to query, create, update, and delete Salesforce
objects (Accounts, Contacts, Opportunities, etc.) through NeuralBridge.

Supported operations:
    - ``query``: Execute a SOQL query.
    - ``get_record``: Retrieve a single record by ID.
    - ``create_record``: Create a new SObject record.
    - ``update_record``: Update an existing SObject record.
    - ``delete_record``: Delete an SObject record.
    - ``describe``: Describe an SObject schema.
    - ``health_check``: Verify connectivity.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from neuralbridge.adapters.base import (
    AdapterResponse,
    BaseAdapter,
)

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Mock data
# ---------------------------------------------------------------------------

_MOCK_ACCOUNTS: list[dict[str, Any]] = [
    {
        "Id": "001Dn00000A1b2cIAA",
        "Name": "Acme Corporation",
        "Industry": "Technology",
        "AnnualRevenue": 5_000_000,
        "CreatedDate": "2024-01-15T10:30:00.000+0000",
    },
    {
        "Id": "001Dn00000B3c4dIBB",
        "Name": "Global Industries",
        "Industry": "Manufacturing",
        "AnnualRevenue": 12_000_000,
        "CreatedDate": "2024-03-22T14:15:00.000+0000",
    },
]

_MOCK_CONTACTS: list[dict[str, Any]] = [
    {
        "Id": "003Dn00000X1y2zICC",
        "FirstName": "Jane",
        "LastName": "Smith",
        "Email": "jane.smith@acme.com",
        "AccountId": "001Dn00000A1b2cIAA",
    },
]


class SalesforceAdapter(BaseAdapter):
    """Adapter for Salesforce CRM via REST API (mocked)."""

    adapter_type: str = "salesforce"
    supported_operations: list[str] = [
        "query",
        "get_record",
        "create_record",
        "update_record",
        "delete_record",
        "describe",
        "health_check",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config=config or {})
        self._instance_url: str = (config or {}).get(
            "instance_url", "https://mock.salesforce.com"
        )
        self._api_version: str = (config or {}).get("api_version", "v59.0")
        self._records: dict[str, list[dict[str, Any]]] = {
            "Account": list(_MOCK_ACCOUNTS),
            "Contact": list(_MOCK_CONTACTS),
        }
        logger.info(
            "SalesforceAdapter created",
            instance_url=self._instance_url,
            api_version=self._api_version,
        )

    async def _do_connect(self) -> None:
        """Simulate OAuth2 authentication to Salesforce."""
        logger.info("Connecting to Salesforce (mock)")

    async def _do_disconnect(self) -> None:
        """Close the Salesforce session."""
        logger.info("Disconnecting from Salesforce (mock)")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """Validate the OAuth2 credentials."""
        return {"status": "valid", "instance_url": self._instance_url}

    async def _do_execute(
        self,
        operation: str,
        params: dict[str, Any],
    ) -> AdapterResponse:
        """Route the operation to the appropriate handler."""
        handlers = {
            "query": self._soql_query,
            "get_record": self._get_record,
            "create_record": self._create_record,
            "update_record": self._update_record,
            "delete_record": self._delete_record,
            "describe": self._describe,
            "health_check": self._health_check,
        }

        handler = handlers.get(operation)
        if handler is None:
            return AdapterResponse(
                success=False,
                data={"error": f"Unsupported operation: {operation}"},
                metadata={"adapter": self.adapter_type},
            )
        return await handler(params)

    # ------------------------------------------------------------------
    # Operation handlers
    # ------------------------------------------------------------------

    async def _soql_query(self, params: dict[str, Any]) -> AdapterResponse:
        """Execute a mock SOQL query."""
        soql: str = params.get("soql", "")
        sobject = "Account"
        for name in self._records:
            if name.upper() in soql.upper():
                sobject = name
                break

        records = self._records.get(sobject, [])
        return AdapterResponse(
            success=True,
            data={
                "totalSize": len(records),
                "done": True,
                "records": records,
            },
            metadata={"soql": soql, "mock": True},
        )

    async def _get_record(self, params: dict[str, Any]) -> AdapterResponse:
        """Retrieve a single record by SObject type and ID."""
        sobject = params.get("sobject", "Account")
        record_id = params.get("id", "")
        for record in self._records.get(sobject, []):
            if record.get("Id") == record_id:
                return AdapterResponse(
                    success=True,
                    data=record,
                    metadata={"sobject": sobject, "mock": True},
                )
        return AdapterResponse(
            success=False,
            data={"error": "Record not found"},
            metadata={"sobject": sobject, "id": record_id},
        )

    async def _create_record(self, params: dict[str, Any]) -> AdapterResponse:
        """Create a new SObject record."""
        sobject = params.get("sobject", "Account")
        data = params.get("data", {})
        new_id = f"00x{uuid.uuid4().hex[:15].upper()}"
        record = {"Id": new_id, **data, "CreatedDate": datetime.now(UTC).isoformat()}
        self._records.setdefault(sobject, []).append(record)
        return AdapterResponse(
            success=True,
            data={"id": new_id, "success": True},
            metadata={"sobject": sobject, "mock": True},
        )

    async def _update_record(self, params: dict[str, Any]) -> AdapterResponse:
        """Update an existing SObject record."""
        sobject = params.get("sobject", "Account")
        record_id = params.get("id", "")
        updates = params.get("data", {})
        for record in self._records.get(sobject, []):
            if record.get("Id") == record_id:
                record.update(updates)
                return AdapterResponse(
                    success=True,
                    data={"id": record_id, "updated": True},
                    metadata={"sobject": sobject, "mock": True},
                )
        return AdapterResponse(
            success=False,
            data={"error": "Record not found"},
            metadata={"sobject": sobject, "id": record_id},
        )

    async def _delete_record(self, params: dict[str, Any]) -> AdapterResponse:
        """Delete an SObject record."""
        sobject = params.get("sobject", "Account")
        record_id = params.get("id", "")
        records = self._records.get(sobject, [])
        for i, record in enumerate(records):
            if record.get("Id") == record_id:
                records.pop(i)
                return AdapterResponse(
                    success=True,
                    data={"id": record_id, "deleted": True},
                    metadata={"sobject": sobject, "mock": True},
                )
        return AdapterResponse(
            success=False,
            data={"error": "Record not found"},
            metadata={"sobject": sobject, "id": record_id},
        )

    async def _describe(self, params: dict[str, Any]) -> AdapterResponse:
        """Return schema information for an SObject."""
        sobject = params.get("sobject", "Account")
        return AdapterResponse(
            success=True,
            data={
                "name": sobject,
                "label": sobject,
                "fields": [
                    {"name": "Id", "type": "id", "length": 18},
                    {"name": "Name", "type": "string", "length": 255},
                    {"name": "CreatedDate", "type": "datetime", "length": 0},
                ],
                "queryable": True,
                "createable": True,
                "updateable": True,
                "deletable": True,
            },
            metadata={"sobject": sobject, "mock": True},
        )

    async def _health_check(self, params: dict[str, Any]) -> AdapterResponse:
        """Verify mock Salesforce connectivity."""
        return AdapterResponse(
            success=True,
            data={
                "status": "ok",
                "instance_url": self._instance_url,
                "api_version": self._api_version,
            },
            metadata={"mock": True},
        )
