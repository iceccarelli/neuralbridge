"""
NeuralBridge Universal Adapter Framework.

Every external system that NeuralBridge connects to is represented by an
adapter — a self-contained module that implements the ``BaseAdapter``
interface.  Adapters are organised by category:

* **databases/** — PostgreSQL, MySQL, MongoDB, Snowflake, BigQuery
* **apis/** — REST, GraphQL, SOAP, OData
* **messaging/** — Slack, Teams, Discord, Telegram, Email (IMAP/SMTP)
* **productivity/** — Gmail, Outlook, Google Docs, Notion, SharePoint
* **erp_crm/** — Salesforce, SAP, Oracle, Dynamics 365
* **cloud/** — AWS S3, Azure Blob, Google Cloud Storage
* **custom/** — Template for user-built adapters

Each adapter:
1. Inherits from ``BaseAdapter`` and implements ``connect``, ``disconnect``,
   ``execute``, and ``validate_credentials``.
2. Returns normalised JSON responses.
3. Logs every operation to the immutable CRA audit trail.
4. Handles errors gracefully with retry and circuit-breaker logic.
"""

from neuralbridge.adapters.base import BaseAdapter  # noqa: F401

__all__ = ["BaseAdapter"]
