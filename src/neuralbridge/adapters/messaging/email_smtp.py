'''
NeuralBridge Adapter for Email (IMAP/SMTP)

This adapter provides a unified interface for sending and receiving emails using
the standard SMTP and IMAP protocols. It allows NeuralBridge to interact with
email servers to automate communication workflows.

Configuration (YAML)
--------------------
.. code-block:: yaml

    adapters:
      - name: my_email_account
        type: email
        config:
          smtp_host: "smtp.example.com"
          smtp_port: 587
          imap_host: "imap.example.com"
          imap_port: 993
          username: "user@example.com"
          password: "your_password"
          use_tls: true

Supported Operations
--------------------
- **send_email**: Sends an email to one or more recipients.
- **read_inbox**: Fetches a list of recent emails from the INBOX.
- **search_emails**: Searches for emails matching specific criteria.
- **get_email**: Retrieves the full content of a single email by its ID.
- **list_folders**: Lists all available email folders (mailboxes).
'''

import asyncio
import imaplib
import random
import smtplib
from datetime import UTC, datetime, timedelta
from typing import Any

from neuralbridge.adapters.base import AdapterResponse, AdapterStatus, BaseAdapter


class EmailAdapter(BaseAdapter):
    """
    Connects to email servers using IMAP for reading and SMTP for sending.
    """

    # --- Adapter Metadata ---
    adapter_type: str = "email"
    category: str = "messaging"
    description: str = "Send and receive emails via IMAP and SMTP."
    version: str = "0.1.0"
    supported_operations: list[str] = [
        "send_email",
        "read_inbox",
        "search_emails",
        "get_email",
        "list_folders",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        super().__init__(config)
        self._imap_client: imaplib.IMAP4_SSL | None = None
        self._smtp_client: smtplib.SMTP | None = None

    def _get_config_schema(self) -> dict[str, Any]:
        """
        Returns the JSON schema for the adapter's configuration.
        """
        return {
            "type": "object",
            "properties": {
                "smtp_host": {"type": "string", "description": "SMTP server hostname."},
                "smtp_port": {"type": "integer", "description": "SMTP server port."},
                "imap_host": {"type": "string", "description": "IMAP server hostname."},
                "imap_port": {"type": "integer", "description": "IMAP server port."},
                "username": {"type": "string", "description": "Login username."},
                "password": {"type": "string", "description": "Login password.", "format": "password"},
                "use_tls": {"type": "boolean", "description": "Whether to use STARTTLS for SMTP.", "default": True},
            },
            "required": ["smtp_host", "smtp_port", "imap_host", "imap_port", "username", "password"],
        }

    async def _do_connect(self) -> None:
        """
        Establishes mock connections to the IMAP and SMTP servers.
        In a real implementation, this would connect to the actual servers.
        """
        # MOCK: In production, this would establish real connections.
        await asyncio.sleep(0.1)  # Simulate network latency
        self.status = AdapterStatus.CONNECTED
        # In a real scenario, we would initialize clients like this:
        # self._imap_client = imaplib.IMAP4_SSL(self.config["imap_host"], self.config["imap_port"])
        # self._smtp_client = smtplib.SMTP(self.config["smtp_host"], self.config["smtp_port"])
        # if self.config.get("use_tls", True):
        #     self._smtp_client.starttls()
        # self._imap_client.login(self.config["username"], self.config["password"])
        # self._smtp_client.login(self.config["username"], self.config["password"])

    async def _do_disconnect(self) -> None:
        """
        Closes the mock connections to the IMAP and SMTP servers.
        """
        # MOCK: In production, this would close real connections.
        await asyncio.sleep(0.05)
        self._imap_client = None
        self._smtp_client = None
        self.status = AdapterStatus.DISCONNECTED

    async def _do_validate_credentials(self) -> dict[str, Any]:
        """
        Validates credentials by attempting a mock login.
        """
        # MOCK: In production, this would attempt a real login.
        await asyncio.sleep(0.2)
        if self.config.get("password") == "invalid_password":
            raise PermissionError("Invalid username or password.")
        return {"status": "ok", "user": self.config.get("username")}

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        """
        Executes the specified email operation.
        """
        if operation == "send_email":
            return await self._op_send_email(params)
        elif operation == "read_inbox":
            return await self._op_read_inbox(params)
        elif operation == "search_emails":
            return await self._op_search_emails(params)
        elif operation == "get_email":
            return await self._op_get_email(params)
        elif operation == "list_folders":
            return await self._op_list_folders()
        else:
            return AdapterResponse(success=False, error=f"Unsupported operation: {operation}")

    # --- Operation Implementations ---

    async def _op_send_email(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Simulates sending an email."""
        required = ["to", "subject", "body"]
        if not all(p in params for p in required):
            return AdapterResponse(success=False, error="Missing required parameters for send_email.")

        # MOCK: In production, this would use self._smtp_client.send_message()
        await asyncio.sleep(0.1)
        message_id = f"<fake-{random.randint(1000, 9999)}@neuralbridge.io>"
        return AdapterResponse(success=True, data={"status": "sent", "message_id": message_id})

    async def _op_read_inbox(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Simulates reading the inbox."""
        limit = params.get("limit", 10)
        # MOCK: In production, this would use self._imap_client to fetch emails.
        await asyncio.sleep(0.2)
        emails = [
            {
                "id": f"msg-{i}",
                "from": f"sender{i}@example.com",
                "subject": f"Test Email Subject {i}",
                "date": (datetime.now(UTC) - timedelta(hours=i)).isoformat(),
                "snippet": "This is a mock email snippet...",
            }
            for i in range(limit)
        ]
        return AdapterResponse(success=True, data=emails)

    async def _op_search_emails(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Simulates searching for emails."""
        query = params.get("query", "FROM \"test@example.com\"")
        # MOCK: In production, this would use IMAP SEARCH command.
        await asyncio.sleep(0.2)
        return AdapterResponse(
            success=True,
            data=[
                {
                    "id": "search-result-1",
                    "from": "test@example.com",
                    "subject": "Search Result Found",
                    "date": (datetime.now(UTC) - timedelta(days=1)).isoformat(),
                    "snippet": f"This email matches your search for: {query}",
                }
            ],
        )

    async def _op_get_email(self, params: dict[str, Any]) -> AdapterResponse:
        """MOCK: Simulates retrieving a single email."""
        email_id = params.get("id")
        if not email_id:
            return AdapterResponse(success=False, error="Email ID is required.")

        # MOCK: In production, this would fetch the full email body.
        await asyncio.sleep(0.1)
        return AdapterResponse(
            success=True,
            data={
                "id": email_id,
                "from": "full.email@example.com",
                "to": [self.config.get("username")],
                "subject": "Full Email Content",
                "date": datetime.now(UTC).isoformat(),
                "body": "This is the full, detailed body of the mock email. It can contain text, HTML, or both.",
                "headers": {
                    "Message-ID": f"<{email_id}@example.com>",
                    "Content-Type": "text/plain; charset=\"utf-8\"",
                },
            },
        )

    async def _op_list_folders(self) -> AdapterResponse:
        """MOCK: Simulates listing email folders."""
        # MOCK: In production, this would use IMAP LIST command.
        await asyncio.sleep(0.1)
        folders = [
            {"name": "INBOX", "path": "INBOX"},
            {"name": "Sent", "path": "Sent"},
            {"name": "Drafts", "path": "Drafts"},
            {"name": "Trash", "path": "Trash"},
            {"name": "Archive", "path": "Archive"},
        ]
        return AdapterResponse(success=True, data=folders)

