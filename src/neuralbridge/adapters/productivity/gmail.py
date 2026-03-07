'''
NeuralBridge Adapter for Gmail API.

This adapter provides a mock interface to the Gmail API, allowing users to perform
common email operations. It is designed for use in the OpenClaw quickstart tutorial
and demonstrates how to build a production-quality adapter for NeuralBridge.

Configuration
-------------
To use this adapter, configure it in your `config.yml` file as follows:

.. code-block:: yaml

    adapters:
      - name: my_gmail_account
        adapter_type: gmail
        config:
          client_id: "YOUR_GOOGLE_CLIENT_ID"
          client_secret: "YOUR_GOOGLE_CLIENT_SECRET"
          refresh_token: "YOUR_GOOGLE_REFRESH_TOKEN"
          user_email: "your.email@gmail.com"

Supported Operations
--------------------
- **send_email**: Sends an email to one or more recipients.
- **read_inbox**: Retrieves a list of recent emails from the inbox.
- **search_emails**: Searches for emails matching a specific query.
- **get_email**: Fetches the full content of a single email by its ID.
- **list_labels**: Retrieves all available labels in the user's account.
- **create_draft**: Creates a new draft email.

'''

from __future__ import annotations

import asyncio
import base64
import random
import string
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from neuralbridge.adapters.base import AdapterResponse, BaseAdapter

logger = structlog.get_logger(__name__)


class GmailAdapter(BaseAdapter):
    '''
    A mock adapter for interacting with the Gmail API.

    This class provides a simulated environment for Gmail operations, returning
    realistic mock data without making any actual API calls. It serves as a
    reference implementation for building new adapters.
    '''

    # --- Adapter Metadata ---
    adapter_type: str = "gmail"
    category: str = "productivity"
    description: str = "Mock adapter for the Google Mail (Gmail) API."
    version: str = "1.0.0"
    supported_operations: list[str] = [
        "send_email",
        "read_inbox",
        "search_emails",
        "get_email",
        "list_labels",
        "create_draft",
    ]

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        '''
        Initializes the Gmail adapter.

        Parameters
        ----------
        config : dict[str, Any] | None
            Adapter-specific configuration.
        '''
        super().__init__(config)
        self._api_client: Any = None  # Placeholder for the real API client

    # --- Abstract Method Implementations ---

    async def _do_connect(self) -> None:
        '''
        Establishes a mock connection to the Gmail API.

        In a real-world scenario, this method would handle OAuth2 authentication
        and initialize the Google API client library.
        '''
        logger.info(
            "gmail_adapter_connecting",
            user=self.config.get("user_email"),
            client_id=self.config.get("client_id"),
        )
        # MOCK: In production, this would initialize and authenticate the client.
        # from google.oauth2.credentials import Credentials
        # from googleapiclient.discovery import build
        # creds = Credentials.from_authorized_user_info(info=self.config)
        # self._api_client = build('gmail', 'v1', credentials=creds)
        await asyncio.sleep(0.1)  # Simulate network latency
        self._api_client = "mock_gmail_client"
        logger.info("gmail_adapter_mock_connection_established")

    async def _do_disconnect(self) -> None:
        '''
        Tears down the mock connection.

        In a real implementation, this would close any open sessions or connections.
        '''
        logger.info("gmail_adapter_disconnecting")
        self._api_client = None
        await asyncio.sleep(0.05)
        logger.info("gmail_adapter_disconnected")

    async def _do_validate_credentials(self) -> dict[str, Any]:
        '''
        Validates the provided mock credentials.

        This method simulates checking the validity of the OAuth tokens.
        '''
        logger.info("gmail_adapter_validating_credentials")
        client_id = self.config.get("client_id")
        client_secret = self.config.get("client_secret")
        refresh_token = self.config.get("refresh_token")

        if not all([client_id, client_secret, refresh_token]):
            raise ValueError("Missing required OAuth2 credentials in config.")

        # MOCK: In production, this would attempt to refresh the token.
        if refresh_token and "invalid" in str(refresh_token):
            raise ConnectionError("Mock refresh token is invalid.")

        return {
            "status": "ok",
            "user_email": self.config.get("user_email", "unknown"),
            "message": "Mock credentials validated successfully.",
        }

    async def _do_execute(self, operation: str, params: dict[str, Any]) -> AdapterResponse:
        '''
        Dispatches and executes the requested Gmail operation.

        Parameters
        ----------
        operation : str
            The name of the operation to execute.
        params : dict[str, Any]
            The parameters for the operation.

        Returns
        -------
        AdapterResponse
            The result of the operation.
        '''
        operation_map = {
            "send_email": self._op_send_email,
            "read_inbox": self._op_read_inbox,
            "search_emails": self._op_search_emails,
            "get_email": self._op_get_email,
            "list_labels": self._op_list_labels,
            "create_draft": self._op_create_draft,
        }

        handler = operation_map.get(operation)
        if not handler:
            raise ValueError(f"Operation '{operation}' is not supported.")

        logger.info("gmail_adapter_executing_operation", operation=operation, params=params)
        result = await handler(params)
        return result

    # --- Configuration Schema ---

    def _get_config_schema(self) -> dict[str, Any]:
        '''
        Returns the JSON schema for the Gmail adapter's configuration.
        '''
        return {
            "type": "object",
            "properties": {
                "client_id": {
                    "type": "string",
                    "title": "Google Client ID",
                    "description": "The client ID from your Google Cloud project.",
                },
                "client_secret": {
                    "type": "string",
                    "title": "Google Client Secret",
                    "description": "The client secret from your Google Cloud project.",
                },
                "refresh_token": {
                    "type": "string",
                    "title": "Google Refresh Token",
                    "description": "The OAuth2 refresh token for offline access.",
                },
                "user_email": {
                    "type": "string",
                    "title": "User Email",
                    "description": "The Gmail address to operate on.",
                    "format": "email",
                },
            },
            "required": ["client_id", "client_secret", "refresh_token", "user_email"],
        }

    # --- Mock Operation Implementations ---

    async def _op_send_email(self, params: dict[str, Any]) -> AdapterResponse:
        '''MOCK: Simulates sending an email.'''
        required = ["to", "subject", "body"]
        if not all(p in params for p in required):
            return AdapterResponse(success=False, error="Missing required parameters: to, subject, body")

        # MOCK: In production, this would call the real API.
        # message = self._create_email_rfc2822(params['to'], params['subject'], params['body'])
        # result = self._api_client.users().messages().send(userId='me', body=message).execute()

        message_id = f'<{"".join(random.choices(string.ascii_letters + string.digits, k=20))}@mail.gmail.com>'
        thread_id = f'{"".join(random.choices(string.hexdigits, k=16))}'

        return AdapterResponse(
            success=True,
            data={
                "id": message_id,
                "threadId": thread_id,
                "labelIds": ["INBOX", "SENT"],
                "snippet": params["body"][:100],
            },
        )

    async def _op_read_inbox(self, params: dict[str, Any]) -> AdapterResponse:
        '''MOCK: Simulates reading the user's inbox.'''
        count = params.get("count", 10)
        # MOCK: In production, this would call self._api_client.users().messages().list(...)
        emails = [self._generate_mock_email() for _ in range(count)]
        return AdapterResponse(success=True, data={"emails": emails, "resultSizeEstimate": len(emails)})

    async def _op_search_emails(self, params: dict[str, Any]) -> AdapterResponse:
        '''MOCK: Simulates searching for emails.'''
        query = params.get("query")
        if not query:
            return AdapterResponse(success=False, error="Missing required parameter: query")

        # MOCK: In production, this would call self._api_client.users().messages().list(q=query)
        num_results = random.randint(1, 5)
        emails = [self._generate_mock_email(query) for _ in range(num_results)]
        return AdapterResponse(success=True, data={"emails": emails, "resultSizeEstimate": len(emails)})

    async def _op_get_email(self, params: dict[str, Any]) -> AdapterResponse:
        '''MOCK: Simulates fetching a single email.'''
        email_id = params.get("id")
        if not email_id:
            return AdapterResponse(success=False, error="Missing required parameter: id")

        # MOCK: In production, this would call self._api_client.users().messages().get(id=email_id)
        email = self._generate_mock_email(email_id=email_id)
        return AdapterResponse(success=True, data=email)

    async def _op_list_labels(self, params: dict[str, Any]) -> AdapterResponse:
        '''MOCK: Simulates listing all available labels.'''
        # MOCK: In production, this would call self._api_client.users().labels().list()
        labels = [
            {"id": "INBOX", "name": "INBOX", "type": "system"},
            {"id": "SPAM", "name": "SPAM", "type": "system"},
            {"id": "TRASH", "name": "TRASH", "type": "system"},
            {"id": "UNREAD", "name": "UNREAD", "type": "system"},
            {"id": "STARRED", "name": "STARRED", "type": "system"},
            {"id": "IMPORTANT", "name": "IMPORTANT", "type": "system"},
            {"id": "SENT", "name": "SENT", "type": "system"},
            {"id": "DRAFT", "name": "DRAFT", "type": "system"},
            {"id": "Label_1", "name": "Family", "type": "user"},
            {"id": "Label_2", "name": "Work", "type": "user"},
        ]
        return AdapterResponse(success=True, data={"labels": labels})

    async def _op_create_draft(self, params: dict[str, Any]) -> AdapterResponse:
        '''MOCK: Simulates creating a draft email.'''
        required = ["to", "subject", "body"]
        if not all(p in params for p in required):
            return AdapterResponse(success=False, error="Missing required parameters: to, subject, body")

        # MOCK: In production, this would create a proper message and call users().drafts().create()
        draft_id = f'r-{"".join(random.choices(string.digits, k=20))}'
        message_id = f'<{"".join(random.choices(string.ascii_letters + string.digits, k=20))}@mail.gmail.com>'

        return AdapterResponse(
            success=True,
            data={
                "id": draft_id,
                "message": {
                    "id": message_id,
                    "threadId": message_id, # Often same as message for new drafts
                    "labelIds": ["DRAFT"],
                },
            },
        )

    # --- Helper Methods ---

    def _generate_mock_email(self, query: str | None = None, email_id: str | None = None) -> dict[str, Any]:
        '''Generates a realistic-looking mock email dictionary.'''
        now = datetime.now(UTC)
        sender_name = random.choice(["Alice", "Bob", "Charlie", "Diana"])
        sender_email = f"{sender_name.lower()}@example.com"
        subject = f"Mock Email: {query}" if query else "Hello from NeuralBridge!"
        body = f"This is a mock email body. Query was: {query}" if query else "This is a mock email generated by the GmailAdapter."
        timestamp = now - timedelta(minutes=random.randint(1, 5000))

        return {
            "id": email_id or f'{"".join(random.choices(string.hexdigits, k=16))}',
            "threadId": f'{"".join(random.choices(string.hexdigits, k=16))}',
            "labelIds": ["INBOX", "UNREAD", "IMPORTANT"],
            "snippet": body[:120],
            "historyId": str(random.randint(100000, 999999)),
            "internalDate": str(int(timestamp.timestamp() * 1000)),
            "payload": {
                "partId": "",
                "mimeType": "multipart/alternative",
                "filename": "",
                "headers": [
                    {"name": "Received", "value": "from mock.server.com (mock.server.com [1.2.3.4]) by ..."},
                    {"name": "From", "value": f'"{sender_name}" <{sender_email}>'},
                    {"name": "To", "value": self.config.get("user_email")},
                    {"name": "Subject", "value": subject},
                    {"name": "Date", "value": timestamp.strftime("%a, %d %b %Y %H:%M:%S %z")},
                ],
                "body": {"size": len(body.encode('utf-8')), "data": base64.urlsafe_b64encode(body.encode('utf-8')).decode('ascii')}
            },
            "sizeEstimate": len(body.encode('utf-8')) + 500, # Approximation
        }

    def _create_email_rfc2822(self, to: str, subject: str, body: str) -> dict[str, str]:
        '''Creates a base64-encoded RFC 2822 email message.'''
        message = (
            f"From: {self.config.get('user_email')}\n"
            f"To: {to}\n"
            f"Subject: {subject}\n\n"
            f"{body}"
        )
        return {
            "raw": base64.urlsafe_b64encode(message.encode('utf-8')).decode('ascii')
        }


