"""
NeuralBridge Adapter for SAP ERP

This adapter provides a unified interface to interact with SAP ERP systems,
leveraging the SAP NetWeaver RFC SDK. It allows for reading tables, calling
BAPIs (Business Application Programming Interfaces), and executing RFC
(Remote Function Call) modules.

Configuration (YAML):
---------------------
.. code-block:: yaml

    adapters:
      - name: my-sap-instance
        type: sap_erp
        config:
          host: "sap.example.com"
          system_number: "00"
          client: "100"
          user: "NB_USER"
          password: "secure_password"
          language: "EN"
          router: "/H/1.2.3.4/S/sapdp99/H/" # Optional SAP Router string

Supported Operations:
---------------------
- ``read_table``: Reads data from a specified table with optional filters.
- ``call_bapi``: Executes a BAPI with specified import/export parameters.
- ``list_bapis``: Lists available BAPIs or function modules based on a search pattern.
- ``get_metadata``: Retrieves metadata for a specific BAPI or RFC.
- ``execute_rfc``: Executes a generic RFC-enabled function module.

"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)


class SapErpAdapter(BaseAdapter):
    """
    SAP ERP adapter for NeuralBridge.
    """

    # ---
    # Subclass attributes that MUST be overridden
    # ---
    adapter_type: str = "sap_erp"
    category: str = "erp_crm"
    description: str = "Connects to SAP ERP systems via RFC."
    version: str = "1.0.0"
    supported_operations: list[str] = [
        "read_table",
        "call_bapi",
        "list_bapis",
        "get_metadata",
        "execute_rfc",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the SAP ERP adapter instance.
        """
        super().__init__(config)
        self._rfc_connection: Any = None

    # ---
    # Abstract method implementations
    # ---

    async def _do_connect(self) -> None:
        """
        Establishes a mock connection to the SAP ERP system.

        In a real implementation, this would use a library like `pyrfc` to
        establish an RFC connection using the provided credentials.
        """
        logger.info(
            "sap_adapter_connecting",
            host=self.config.get("host"),
            client=self.config.get("client"),
            user=self.config.get("user"),
        )
        # MOCK: In production, this would use pyrfc.Connection(**config)
        await asyncio.sleep(0.1)  # Simulate network latency
        self._rfc_connection = {"status": "mock_connected"}
        logger.info("sap_adapter_mock_connection_established")

    async def _do_disconnect(self) -> None:
        """
        Closes the mock RFC connection.
        """
        if self._rfc_connection:
            # MOCK: In production, this would be self._rfc_connection.close()
            self._rfc_connection = None
            logger.info("sap_adapter_mock_connection_closed")
        await asyncio.sleep(0.05)

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Executes a supported SAP operation.
        """
        if operation == "read_table":
            return await self._read_table(params)
        elif operation == "call_bapi":
            return await self._call_bapi(params)
        elif operation == "list_bapis":
            return await self._list_bapis(params)
        elif operation == "get_metadata":
            return await self._get_metadata(params)
        elif operation == "execute_rfc":
            return await self._execute_rfc(params)
        else:
            # This should not be reached due to the check in the base class
            return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates credentials by attempting a mock connection.
        """
        try:
            # MOCK: In production, this would attempt a real connection to verify creds
            await self._do_connect()
            await self._do_disconnect()
            return {"status": "ok", "message": "Credentials appear valid."}
        except Exception as e:
            # In a real scenario, catch specific connection exceptions
            logger.error("sap_credential_validation_failed", error=str(e))
            raise ConnectionError(f"Credential validation failed: {e}") from e

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON Schema for the SAP ERP adapter configuration.
        """
        return {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "SAP application server host."},
                "system_number": {
                    "type": "string",
                    "description": "SAP system number (e.g., '00').",
                },
                "client": {"type": "string", "description": "SAP client (e.g., '100')."},
                "user": {"type": "string", "description": "SAP username."},
                "password": {
                    "type": "string",
                    "description": "SAP user password.",
                    "format": "password",
                },
                "language": {
                    "type": "string",
                    "description": "SAP logon language (e.g., 'EN').",
                    "default": "EN",
                },
                "router": {
                    "type": "string",
                    "description": "Optional SAP router string.",
                },
            },
            "required": ["host", "system_number", "client", "user", "password"],
        }

    # ---
    # Operation-specific implementations
    # ---

    async def _read_table(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Reads data from an SAP table."""
        table_name = params.get("table_name")
        if not table_name:
            return AdapterResponse(success=False, error="'table_name' is required.")

        logger.info("sap_read_table_mock", table=table_name, params=params)
        # MOCK: In production, use RFC_READ_TABLE or a similar function
        mock_data = {
            "T001": [
                {"MANDT": "100", "BUKRS": "0001", "BUTXT": "SAP AG"},
                {"MANDT": "100", "BUKRS": "1000", "BUTXT": "IDES AG"},
            ],
            "MARA": [
                {"MATNR": "HALB-1000", "MTART": "HALB", "MBRSH": "M"},
                {"MATNR": "ROH-1000", "MTART": "ROH", "MBRSH": "M"},
            ],
        }
        await asyncio.sleep(0.2)  # Simulate query time
        data = mock_data.get(table_name.upper(), [])
        return AdapterResponse(success=True, data=data, metadata={"row_count": len(data)})

    async def _call_bapi(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Calls an SAP BAPI."""
        bapi_name = params.get("bapi_name")
        if not bapi_name:
            return AdapterResponse(success=False, error="'bapi_name' is required.")

        logger.info("sap_call_bapi_mock", bapi=bapi_name, params=params)
        # MOCK: In production, dynamically call the specified BAPI
        if bapi_name.upper() == "BAPI_COMPANYCODE_GETLIST":
            mock_response = {
                "COMPANYCODE_LIST": [
                    {"COMP_CODE": "0001", "COMP_NAME": "SAP AG"},
                    {"COMP_CODE": "1000", "COMP_NAME": "IDES AG"},
                ],
                "RETURN": {"TYPE": "S", "MESSAGE": "Company codes retrieved"},
            }
            await asyncio.sleep(0.15)
            return AdapterResponse(success=True, data=mock_response)

        return AdapterResponse(success=False, error=f"Mock for BAPI '{bapi_name}' not implemented.")

    async def _list_bapis(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Lists available BAPIs based on a pattern."""
        pattern = params.get("pattern", "BAPI*")
        logger.info("sap_list_bapis_mock", pattern=pattern)
        # MOCK: In production, this would query the SAP system for function modules
        mock_bapis = [
            {"FUNCNAME": "BAPI_COMPANYCODE_GETLIST", "STEXT": "List of Company Codes"},
            {"FUNCNAME": "BAPI_USER_GET_DETAIL", "STEXT": "Get User Details"},
            {"FUNCNAME": "BAPI_MATERIAL_GET_ALL", "STEXT": "Get All Material Data"},
        ]
        await asyncio.sleep(0.2)
        return AdapterResponse(success=True, data=mock_bapis)

    async def _get_metadata(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Retrieves metadata for a BAPI or RFC."""
        func_name = params.get("func_name")
        if not func_name:
            return AdapterResponse(success=False, error="'func_name' is required.")

        logger.info("sap_get_metadata_mock", func_name=func_name)
        # MOCK: In production, use RFC_METADATA_GET
        if func_name.upper() == "BAPI_COMPANYCODE_GETLIST":
            mock_metadata = {
                "import": [],
                "export": [],
                "tables": [
                    {"name": "COMPANYCODE_LIST", "optional": False, "type": "structure"},
                    {"name": "RETURN", "optional": False, "type": "structure"},
                ],
            }
            await asyncio.sleep(0.1)
            return AdapterResponse(success=True, data=mock_metadata)

        return AdapterResponse(success=False, error=f"Mock metadata for '{func_name}' not found.")

    async def _execute_rfc(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Executes a generic RFC function."""
        func_name = params.get("func_name")
        if not func_name:
            return AdapterResponse(success=False, error="'func_name' is required.")

        logger.info("sap_execute_rfc_mock", func_name=func_name, params=params)
        # MOCK: This is a generic wrapper, similar to call_bapi but for any RFC
        if func_name.upper() == "STFC_CONNECTION":
            requtext = params.get("REQUTEXT", "Hello SAP")
            mock_response = {
                "ECHOTEXT": requtext,
                "RESPTEXT": f"SAP System says: {requtext}",
            }
            await asyncio.sleep(0.1)
            return AdapterResponse(success=True, data=mock_response)

        return AdapterResponse(success=False, error=f"Mock for RFC '{func_name}' not implemented.")

