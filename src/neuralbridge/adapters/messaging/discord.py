'''
NeuralBridge Adapter for Discord

This adapter provides connectivity to the Discord messaging platform, allowing
for sending messages, listing channels, reading message history, and more.

**Configuration (`config.yml`)**

.. code-block:: yaml

    adapters:
      - type: discord
        name: my_discord_bot
        config:
          bot_token: "YOUR_DISCORD_BOT_TOKEN"
          guild_id: "YOUR_SERVER_ID"
          default_channel_id: "YOUR_DEFAULT_CHANNEL_ID"

**Supported Operations**

- ``send_message``: Sends a message to a specified channel.
- ``list_channels``: Retrieves a list of all text channels in the guild.
- ``read_messages``: Reads the last N messages from a channel.
- ``create_channel``: Creates a new text channel.
- ``add_reaction``: Adds a reaction to a specific message.

'''

from __future__ import annotations

import asyncio
import random
from datetime import UTC, datetime
from typing import Any

import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)


class DiscordAdapter(BaseAdapter):
    """
    Connects NeuralBridge to Discord for messaging operations.

    This adapter simulates a connection to the Discord API for sending and
    receiving messages, managing channels, and other related tasks. It uses
    mock data to avoid reliance on a live Discord application during development
    and testing.
    """

    # --- Adapter Metadata ---
    adapter_type: str = "discord"
    category: str = "messaging"
    description: str = "Adapter for Discord messaging and server automation."
    version: str = "0.2.0"
    supported_operations: list[str] = [
        "send_message",
        "list_channels",
        "read_messages",
        "create_channel",
        "add_reaction",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        """
        Initializes the Discord adapter instance.

        Args:
            config: Adapter-specific configuration dictionary.
        """
        super().__init__(config)
        self._client: Any = None  # Mock client placeholder

    # --- Abstract Method Implementations ---

    async def _do_connect(self) -> None:
        """
        Establishes a mock connection to the Discord service.

        In a real-world scenario, this method would initialize the Discord client
        library (e.g., discord.py) and log in using the bot token.
        """
        logger.info(
            "discord_adapter_connecting",
            guild_id=self.config.get("guild_id"),
            adapter_name=self.config.get("name", "default"),
        )
        # MOCK: In production, this would connect to the Discord Gateway.
        await asyncio.sleep(0.1)  # Simulate network latency
        self._client = "MOCK_DISCORD_CLIENT"
        logger.info("discord_adapter_connected", client=self._client)

    async def _do_disconnect(self) -> None:
        """
        Closes the mock connection to the Discord service.

        In a real-world scenario, this would log the client out and close
        any open network connections gracefully.
        """
        logger.info("discord_adapter_disconnecting", client=self._client)
        # MOCK: In production, this would call `client.close()`
        await asyncio.sleep(0.05)
        self._client = None
        logger.info("discord_adapter_disconnected")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates the provided Discord bot token and guild ID.

        This mock implementation performs basic checks and simulates an API
        call to verify the credentials.

        Returns:
            A dictionary with validation status and details.
        """
        bot_token = self.config.get("bot_token")
        guild_id = self.config.get("guild_id")

        if not bot_token or not guild_id:
            raise ValueError("`bot_token` and `guild_id` are required.")

        # MOCK: In production, this would make a lightweight API call to Discord
        # to verify the token and that the bot is in the specified guild.
        await asyncio.sleep(0.2)  # Simulate API call latency

        if "invalid" in bot_token:
            raise ConnectionRefusedError("Invalid Discord bot token.")

        return {
            "status": "ok",
            "message": "Credentials appear valid.",
            "guild_id": guild_id,
            "bot_user": "NeuralBridgeBot#1234",
        }

    async def _do_execute(
        self, operation: str, params: dict[str, Any]
    ) -> AdapterResponse:
        """
        Executes a supported operation on the Discord platform.

        Dispatches the requested operation to the appropriate handler method.

        Args:
            operation: The name of the operation to execute.
            params: A dictionary of parameters for the operation.

        Returns:
            An AdapterResponse containing the result of the operation.
        """
        operation_map = {
            "send_message": self._op_send_message,
            "list_channels": self._op_list_channels,
            "read_messages": self._op_read_messages,
            "create_channel": self._op_create_channel,
            "add_reaction": self._op_add_reaction,
        }

        handler = operation_map.get(operation)
        if not handler:
            raise ValueError(f"Operation '{operation}' is not supported.")

        return await handler(params)

    # --- Configuration Schema ---

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON Schema for the Discord adapter's configuration.

        This schema is used for validation and for generating documentation
        and UI elements in the NeuralBridge dashboard.

        Returns:
            A JSON Schema dictionary.
        """
        return {
            "type": "object",
            "properties": {
                "bot_token": {
                    "type": "string",
                    "description": "The OAuth2 bot token for your Discord application.",
                    "format": "password",
                },
                "guild_id": {
                    "type": "string",
                    "description": "The ID of the Discord server (guild) to operate on.",
                },
                "default_channel_id": {
                    "type": "string",
                    "description": "The default channel ID to use if none is specified.",
                },
            },
            "required": ["bot_token", "guild_id"],
        }

    # --- Operation Implementations ---

    async def _op_send_message(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Sends a message to a Discord channel."""
        channel_id = params.get("channel_id") or self.config.get("default_channel_id")
        content = params.get("content")

        if not channel_id or not content:
            raise ValueError("`channel_id` and `content` are required for send_message.")

        logger.info("discord_sending_message", channel_id=channel_id, content_length=len(content))
        # MOCK: In production, this would call the real Discord API.
        await asyncio.sleep(random.uniform(0.1, 0.3))

        mock_message = {
            "id": str(random.randint(10**18, 10**19 - 1)),
            "channel_id": channel_id,
            "author": {"id": "BOT_ID", "username": "NeuralBridgeBot", "discriminator": "1234"},
            "content": content,
            "timestamp": datetime.now(UTC).isoformat(),
            "edited_timestamp": None,
            "tts": False,
            "mention_everyone": False,
            "mentions": [],
            "mention_roles": [],
            "attachments": [],
            "embeds": [],
            "reactions": [],
            "pinned": False,
            "type": 0,
        }
        return AdapterResponse(success=True, data=mock_message)

    async def _op_list_channels(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Lists all text channels in the guild."""
        guild_id = self.config.get("guild_id")
        logger.info("discord_listing_channels", guild_id=guild_id)
        # MOCK: In production, this would fetch channels from the Discord API.
        await asyncio.sleep(0.15)

        mock_channels = [
            {"id": "100000000000000001", "name": "general", "type": "text"},
            {"id": "100000000000000002", "name": "random", "type": "text"},
            {"id": "100000000000000003", "name": "tech-talk", "type": "text"},
            {"id": "100000000000000004", "name": "project-updates", "type": "text"},
        ]
        return AdapterResponse(success=True, data=mock_channels)

    async def _op_read_messages(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Reads the last N messages from a channel."""
        channel_id = params.get("channel_id") or self.config.get("default_channel_id")
        limit = params.get("limit", 10)

        if not channel_id:
            raise ValueError("`channel_id` is required for read_messages.")

        logger.info("discord_reading_messages", channel_id=channel_id, limit=limit)
        # MOCK: In production, this would fetch message history.
        await asyncio.sleep(0.2)

        mock_messages = [
            {
                "id": str(random.randint(10**18, 10**19 - 1)),
                "channel_id": channel_id,
                "author": {"id": "USER_ID_1", "username": "Alice", "discriminator": "5678"},
                "content": f"This is mock message number {i+1}.",
                "timestamp": datetime.now(UTC).isoformat(),
            }
            for i in range(limit)
        ]
        return AdapterResponse(success=True, data=mock_messages)

    async def _op_create_channel(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Creates a new text channel."""
        name = params.get("name")
        if not name:
            raise ValueError("`name` is required for create_channel.")

        logger.info("discord_creating_channel", name=name)
        # MOCK: In production, this would call the channel creation endpoint.
        await asyncio.sleep(0.4)

        new_channel = {
            "id": str(random.randint(10**18, 10**19 - 1)),
            "name": name.lower().replace(" ", "-"),
            "type": "text",
            "guild_id": self.config.get("guild_id"),
            "position": random.randint(5, 20),
            "permission_overwrites": [],
            "nsfw": False,
        }
        return AdapterResponse(success=True, data=new_channel)

    async def _op_add_reaction(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Adds a reaction to a message."""
        channel_id = params.get("channel_id") or self.config.get("default_channel_id")
        message_id = params.get("message_id")
        emoji = params.get("emoji")

        if not all([channel_id, message_id, emoji]):
            raise ValueError("`channel_id`, `message_id`, and `emoji` are required.")

        logger.info(
            "discord_adding_reaction",
            channel_id=channel_id,
            message_id=message_id,
            emoji=emoji,
        )
        # MOCK: In production, this would call the reaction API endpoint.
        await asyncio.sleep(0.1)

        return AdapterResponse(
            success=True, data={"status": "ok", "message": f"Reaction '{emoji}' added."}
        )

