'''
NeuralBridge Adapter for Telegram.

This adapter provides a mock implementation of the Telegram Bot API, allowing you
to send messages, photos, and manage webhooks within the NeuralBridge
enterprise middleware platform.

**Configuration**

The adapter is configured via a YAML file with the following structure:

.. code-block:: yaml

    adapters:
      - name: my-telegram-bot
        type: telegram
        config:
          bot_token: "YOUR_TELEGRAM_BOT_TOKEN"
          chat_id: "YOUR_TARGET_CHAT_ID"
          parse_mode: "MarkdownV2"  # Optional: MarkdownV2, HTML, or None
          webhook_url: "https://your.webhook/url"  # Optional

**Supported Operations**

- :code:`send_message`: Sends a text message to the configured chat.
- :code:`get_updates`: Retrieves mock incoming updates.
- :code:`send_photo`: Sends a mock photo to the chat.
- :code:`get_chat`: Retrieves mock information about the chat.
- :code:`set_webhook`: Sets a mock webhook for receiving updates.

'''

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from neuralbridge.adapters.base import AdapterResponse, AdapterStatus, BaseAdapter

logger = structlog.get_logger(__name__)


class TelegramAdapter(BaseAdapter):
    '''
    A mock adapter for interacting with the Telegram Bot API.

    This adapter simulates the behavior of the Telegram API for development and
    testing purposes. It allows you to test workflows that involve sending
    messages and handling updates without needing a live Telegram bot.
    '''

    # Override class attributes
    adapter_type = "telegram"
    category = "messaging"
    description = "Mock adapter for the Telegram Bot API."
    version = "0.1.0"
    supported_operations = [
        "send_message",
        "get_updates",
        "send_photo",
        "get_chat",
        "set_webhook",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        '''Initializes the Telegram adapter with the given configuration.'''
        super().__init__(config)
        self.bot_token = self.config.get("bot_token")
        self.chat_id = self.config.get("chat_id")

    async def _do_connect(self) -> None:
        '''
        Simulates connecting to the Telegram API.

        In a real implementation, this would involve setting up an HTTP client
        session or verifying the bot token.
        '''
        logger.info(
            "telegram_adapter_connect",
            adapter=self.adapter_type,
            bot_token_present=bool(self.bot_token),
        )
        # MOCK: In production, this would initialize an HTTPX client.
        if not self.bot_token:
            raise ValueError("bot_token is required for Telegram adapter")
        await asyncio.sleep(0.1)  # Simulate network latency
        self.status = AdapterStatus.CONNECTED

    async def _do_disconnect(self) -> None:
        '''Simulates disconnecting from the Telegram API.'''
        logger.info("telegram_adapter_disconnect", adapter=self.adapter_type)
        # MOCK: In production, this would close the HTTPX client.
        await asyncio.sleep(0.05)
        self.status = AdapterStatus.DISCONNECTED

    async def _do_validate_credentials(self) -> dict[str, Any]:
        '''
        Simulates validating the bot token with Telegram's `getMe` endpoint.
        '''
        logger.info("telegram_adapter_validate_credentials", adapter=self.adapter_type)
        if not self.bot_token or not self.bot_token.startswith("12345:"):
            raise ValueError("Invalid or missing bot_token.")

        # MOCK: In production, this would call the real getMe API.
        await asyncio.sleep(0.2)
        return {
            "ok": True,
            "result": {
                "id": 123456789,
                "is_bot": True,
                "first_name": "NeuralBridge Mock Bot",
                "username": "NeuralBridgeMockBot",
                "can_join_groups": True,
                "can_read_all_group_messages": False,
                "supports_inline_queries": False,
            },
        }

    async def _do_execute(
        self, operation: str, params: dict[str, Any]
    ) -> AdapterResponse:
        '''
        Executes a supported Telegram operation.

        Dispatches the operation to the corresponding mock implementation.
        '''
        if operation == "send_message":
            return await self._mock_send_message(params)
        elif operation == "get_updates":
            return await self._mock_get_updates(params)
        elif operation == "send_photo":
            return await self._mock_send_photo(params)
        elif operation == "get_chat":
            return await self._mock_get_chat(params)
        elif operation == "set_webhook":
            return await self._mock_set_webhook(params)
        else:
            return AdapterResponse(
                success=False, error=f"Unsupported operation: {operation}"
            )

    def _get_config_schema(self) -> dict[str, Any]:
        '''
        Returns the JSON schema for the Telegram adapter's configuration.
        '''
        return {
            "type": "object",
            "properties": {
                "bot_token": {
                    "type": "string",
                    "title": "Bot Token",
                    "description": "The authentication token for your Telegram bot.",
                },
                "chat_id": {
                    "type": "string",
                    "title": "Chat ID",
                    "description": "The unique identifier for the target chat.",
                },
                "parse_mode": {
                    "type": "string",
                    "title": "Parse Mode",
                    "description": "Formatting style for messages (MarkdownV2 or HTML).",
                    "enum": ["MarkdownV2", "HTML"],
                },
                "webhook_url": {
                    "type": "string",
                    "title": "Webhook URL",
                    "description": "The URL to receive updates from Telegram.",
                    "format": "uri",
                },
            },
            "required": ["bot_token", "chat_id"],
        }

    # --- Mock Operation Implementations ---

    async def _mock_send_message(self, params: dict[str, Any]) -> AdapterResponse:
        '''Mocks the `sendMessage` API call.'''
        text = params.get("text")
        if not text:
            return AdapterResponse(success=False, error="Missing required parameter: text")

        # MOCK: In production, this would call the real sendMessage API.
        await asyncio.sleep(0.15)

        return AdapterResponse(
            success=True,
            data={
                "ok": True,
                "result": {
                    "message_id": 123,
                    "from": {"id": 987654321, "is_bot": True, "first_name": "MockBot"},
                    "chat": {"id": self.chat_id, "type": "private"},
                    "date": 1678886400,
                    "text": text,
                },
            },
            metadata={"text_length": len(text)},
        )

    async def _mock_get_updates(self, params: dict[str, Any]) -> AdapterResponse:
        '''Mocks the `getUpdates` API call.'''
        # MOCK: In production, this would call the real getUpdates API.
        await asyncio.sleep(0.1)
        return AdapterResponse(
            success=True,
            data={
                "ok": True,
                "result": [
                    {
                        "update_id": 54321,
                        "message": {
                            "message_id": 456,
                            "from": {"id": 12345, "first_name": "John Doe"},
                            "chat": {"id": self.chat_id, "type": "private"},
                            "date": 1678886400,
                            "text": "Hello from a mock user!",
                        },
                    }
                ],
            },
        )

    async def _mock_send_photo(self, params: dict[str, Any]) -> AdapterResponse:
        '''Mocks the `sendPhoto` API call.'''
        photo_url = params.get("photo_url")
        if not photo_url:
            return AdapterResponse(success=False, error="Missing required parameter: photo_url")

        # MOCK: In production, this would call the real sendPhoto API.
        await asyncio.sleep(0.3)

        return AdapterResponse(
            success=True,
            data={
                "ok": True,
                "result": {
                    "message_id": 124,
                    "photo": [{"file_id": "mock_file_id", "width": 800, "height": 600}],
                },
            },
            metadata={"photo_url": photo_url},
        )

    async def _mock_get_chat(self, params: dict[str, Any]) -> AdapterResponse:
        '''Mocks the `getChat` API call.'''
        # MOCK: In production, this would call the real getChat API.
        await asyncio.sleep(0.1)
        return AdapterResponse(
            success=True,
            data={
                "ok": True,
                "result": {
                    "id": self.chat_id,
                    "type": "private",
                    "first_name": "Mock",
                    "last_name": "User",
                },
            },
        )

    async def _mock_set_webhook(self, params: dict[str, Any]) -> AdapterResponse:
        '''Mocks the `setWebhook` API call.'''
        webhook_url = params.get("webhook_url") or self.config.get("webhook_url")
        if not webhook_url:
            return AdapterResponse(success=False, error="Missing required parameter: webhook_url")

        # MOCK: In production, this would call the real setWebhook API.
        await asyncio.sleep(0.1)

        return AdapterResponse(
            success=True,
            data={
                "ok": True,
                "result": True,
                "description": f"Webhook was set to {webhook_url}",
            },
        )

