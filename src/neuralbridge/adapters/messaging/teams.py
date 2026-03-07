"""

NeuralBridge Adapter for Microsoft Teams

This adapter provides connectivity to the Microsoft Teams platform via the
Microsoft Graph API. It enables sending messages, listing teams and channels,
and reading channel messages.

Configuration
-------------
To use this adapter, configure it in your `config.yml` file under the `adapters` section:

.. code-block:: yaml

   adapters:
     - name: my-teams-instance
       type: teams
       config:
         tenant_id: "your-azure-ad-tenant-id"
         client_id: "your-app-client-id"
         client_secret: "your-app-client-secret"
         team_id: "your-default-team-id"

Supported Operations
--------------------
- ``send_message``: Sends a message to a specified channel.
- ``list_channels``: Lists all channels in the configured team.
- ``list_teams``: Lists all teams the user is a member of.
- ``read_messages``: Reads recent messages from a specified channel.
- ``create_channel``: Creates a new channel in the configured team.

"""



from __future__ import annotations

import asyncio
from typing import Any

import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)


class TeamsAdapter(BaseAdapter):
    """
    Connects to Microsoft Teams to send and receive messages.
    """

    # Override class attributes
    adapter_type = "teams"
    category = "messaging"
    description = "Adapter for Microsoft Teams integration via MS Graph API."
    version = "1.0.0"
    supported_operations = [
        "send_message",
        "list_channels",
        "list_teams",
        "read_messages",
        "create_channel",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the Teams adapter.

        Parameters
        ----------
        config : dict[str, Any], optional
            Adapter-specific configuration, by default None
        """
        super().__init__(config)
        self._graph_client: Any = None  # Placeholder for a potential MS Graph client

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the adapter's configuration.

        This schema is used for validation and for generating documentation.

        Returns
        -------
        dict[str, Any]
            A JSON schema dictionary.
        """
        return {
            "type": "object",
            "properties": {
                "tenant_id": {
                    "type": "string",
                    "title": "Azure AD Tenant ID",
                    "description": "The ID of the Azure Active Directory tenant.",
                },
                "client_id": {
                    "type": "string",
                    "title": "Application (Client) ID",
                    "description": "The Client ID of the registered application in Azure AD.",
                },
                "client_secret": {
                    "type": "string",
                    "title": "Client Secret",
                    "description": "The client secret for the registered application.",
                    "format": "password",
                },
                "team_id": {
                    "type": "string",
                    "title": "Default Team ID",
                    "description": "The default Microsoft Teams Team ID to operate on.",
                },
            },
            "required": ["tenant_id", "client_id", "client_secret", "team_id"],
        }

    async def _do_connect(self) -> None:
        """
        Establishes a connection to the Microsoft Graph API.

        In a real implementation, this would involve acquiring an OAuth2 token.
        For this mock, we simply simulate a successful connection.
        """
        logger.info(
            "teams_adapter_connecting",
            tenant_id=self.config.get("tenant_id"),
            client_id=self.config.get("client_id"),
        )
        # MOCK: In production, this would use MSAL or similar to get a token.
        await asyncio.sleep(0.1)  # Simulate network latency
        self._graph_client = True  # Simulate a connected client
        logger.info("teams_adapter_connected", detail="Mock connection successful.")

    async def _do_disconnect(self) -> None:
        """
        Tears down the connection.

        For this mock, we just reset the client placeholder.
        """
        self._graph_client = None
        logger.info("teams_adapter_disconnected", detail="Mock disconnection successful.")
        await asyncio.sleep(0.05)

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the configured credentials by attempting a mock token acquisition.

        Returns
        -------
        dict[str, Any]
            A dictionary with validation status.
        """
        tenant_id = self.config.get("tenant_id")
        client_id = self.config.get("client_id")
        client_secret = self.config.get("client_secret")

        if not all([tenant_id, client_id, client_secret]):
            raise ValueError("Missing required credentials in configuration.")

        # MOCK: In production, this would attempt a real token request.
        logger.info("teams_adapter_validating_credentials")
        await asyncio.sleep(0.2)  # Simulate API call

        if client_secret == "invalid-secret":
            raise ConnectionRefusedError("Invalid client secret.")

        return {
            "status": "ok",
            "message": "Credentials appear valid (mock check).",
            "tenant_id": tenant_id,
        }

    async def _do_execute(
        self, operation: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """
        Executes a supported operation on Microsoft Teams.

        Parameters
        ----------
        operation : str
            The operation to perform (e.g., 'send_message').
        params : dict[str, Any]
            Parameters for the operation.

        Returns
        -------
        AdapterResponse
            The result of the operation.

        Raises
        ------
        ValueError
            If the operation is not supported or parameters are invalid.
        """
        team_id = params.get("team_id", self.config.get("team_id"))
        if not team_id:
            raise ValueError("Team ID must be provided in config or parameters.")

        # MOCK: In production, these would be real Microsoft Graph API calls.
        if operation == "send_message":
            return await self._mock_send_message(params)
        elif operation == "list_channels":
            return await self._mock_list_channels(team_id)
        elif operation == "list_teams":
            return await self._mock_list_teams()
        elif operation == "read_messages":
            return await self._mock_read_messages(team_id, params)
        elif operation == "create_channel":
            return await self._mock_create_channel(team_id, params)
        else:
            # This case should ideally not be reached due to the check in BaseAdapter
            raise ValueError(f"Operation '{operation}' is not supported.")

    async def _mock_send_message(self, params: dict[str, Any]) -> AdapterResponse:
        """Mock implementation for sending a message."""
        channel_id = params.get("channel_id")
        content = params.get("content")
        if not channel_id or not content:
            raise ValueError("`channel_id` and `content` are required for send_message.")

        logger.info("teams_adapter_send_message", channel_id=channel_id)
        await asyncio.sleep(0.15)  # Simulate API call

        mock_response = {
            "id": "1615909804192",
            "from": {"user": {"displayName": "NeuralBridge Bot"}},
            "body": {"contentType": "html", "content": content},
        }
        return AdapterResponse(success=True, data=mock_response)

    async def _mock_list_channels(self, team_id: str) -> AdapterResponse:
        """Mock implementation for listing channels."""
        logger.info("teams_adapter_list_channels", team_id=team_id)
        await asyncio.sleep(0.2)

        mock_channels = [
            {"id": "19:general_channel_id@thread.tacv2", "displayName": "General"},
            {"id": "19:dev_channel_id@thread.tacv2", "displayName": "Development"},
            {"id": "19:design_channel_id@thread.tacv2", "displayName": "Design"},
        ]
        return AdapterResponse(success=True, data=mock_channels)

    async def _mock_list_teams(self) -> AdapterResponse:
        """Mock implementation for listing teams."""
        logger.info("teams_adapter_list_teams")
        await asyncio.sleep(0.3)

        mock_teams = [
            {
                "id": "team_id_1",
                "displayName": "Sales and Marketing",
                "description": "Sales and Marketing team.",
            },
            {
                "id": "team_id_2",
                "displayName": "Project Alpha",
                "description": "Team for Project Alpha.",
            },
        ]
        return AdapterResponse(success=True, data=mock_teams)

    async def _mock_read_messages(
        self, team_id: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """Mock implementation for reading messages."""
        channel_id = params.get("channel_id")
        if not channel_id:
            raise ValueError("`channel_id` is required for read_messages.")

        limit = params.get("limit", 10)
        logger.info(
            "teams_adapter_read_messages",
            team_id=team_id,
            channel_id=channel_id,
            limit=limit,
        )
        await asyncio.sleep(0.25)

        mock_messages = [
            {
                "id": f"message_{i}",
                "from": {"user": {"displayName": f"User {i}"}},
                "body": {"content": f"This is mock message number {i}"},
                "createdDateTime": "2023-10-27T10:00:00Z",
            }
            for i in range(limit)
        ]
        return AdapterResponse(success=True, data=mock_messages)

    async def _mock_create_channel(
        self, team_id: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """Mock implementation for creating a channel."""
        display_name = params.get("display_name")
        if not display_name:
            raise ValueError("`display_name` is required for create_channel.")

        description = params.get("description", "")
        logger.info(
            "teams_adapter_create_channel",
            team_id=team_id,
            display_name=display_name,
        )
        await asyncio.sleep(0.3)

        mock_channel = {
            "id": f"19:{display_name.lower()}_channel_id@thread.tacv2",
            "displayName": display_name,
            "description": description,
        }
        return AdapterResponse(success=True, data=mock_channel)


