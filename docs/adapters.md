# NeuralBridge Adapter Development Guide

## Overview

NeuralBridge adapters are the bridge between AI agents and external systems. Each adapter translates standardized NeuralBridge operations into system-specific API calls.

## Supported Adapters

### Databases (5)

| Adapter | Module | Key Operations |
|---------|--------|----------------|
| PostgreSQL | `adapters.databases.postgres` | query, execute, list_tables, describe_table |
| MySQL | `adapters.databases.mysql` | query, execute, list_tables, describe_table |
| MongoDB | `adapters.databases.mongodb` | find, insert, update, delete, aggregate |
| Snowflake | `adapters.databases.snowflake` | query, list_schemas, describe_table |
| BigQuery | `adapters.databases.bigquery` | query, list_datasets, list_tables |

### APIs (4)

| Adapter | Module | Key Operations |
|---------|--------|----------------|
| REST | `adapters.apis.rest` | get, post, put, patch, delete |
| GraphQL | `adapters.apis.graphql` | query, mutation, introspect |
| SOAP | `adapters.apis.soap` | call, discover_wsdl |
| OData | `adapters.apis.odata` | query, create, update, delete |

### Messaging (5)

| Adapter | Module | Key Operations |
|---------|--------|----------------|
| Slack | `adapters.messaging.slack` | send_message, list_channels, upload_file |
| Microsoft Teams | `adapters.messaging.teams` | send_message, list_channels |
| Discord | `adapters.messaging.discord` | send_message, list_channels |
| Telegram | `adapters.messaging.telegram` | send_message, get_updates |
| Email (SMTP) | `adapters.messaging.email` | send_email, list_emails |

### Productivity (2)

| Adapter | Module | Key Operations |
|---------|--------|----------------|
| Gmail | `adapters.productivity.gmail` | send_email, search_emails, read_email |
| Notion | `adapters.productivity.notion` | search, get_page, create_page |

### ERP / CRM (2)

| Adapter | Module | Key Operations |
|---------|--------|----------------|
| Salesforce | `adapters.erp_crm.salesforce` | query, create_record, update_record |
| SAP | `adapters.erp_crm.sap` | read_entity, create_entity, call_function |

### Cloud (3)

| Adapter | Module | Key Operations |
|---------|--------|----------------|
| AWS S3 | `adapters.cloud.aws_s3` | list_objects, get_object, put_object |
| Azure Blob | `adapters.cloud.azure_blob` | list_blobs, download_blob, upload_blob |
| Google Cloud Storage | `adapters.cloud.gcs` | list_objects, download_object, upload_object |

## Creating a Custom Adapter

Use the template at `adapters/custom/adapter_template.py`:

```python
from neuralbridge.adapters.base import BaseAdapter

class MyCustomAdapter(BaseAdapter):
    adapter_type = "my_custom"
    category = "custom"
    description = "My custom adapter description."
    supported_operations = ["read", "write"]

    async def _do_connect(self) -> None:
        # Initialize connection to your system
        pass

    async def _do_disconnect(self) -> None:
        # Clean up resources
        pass

    async def _do_execute(self, operation: str, params: dict) -> Any:
        if operation == "read":
            return await self._read(params)
        elif operation == "write":
            return await self._write(params)

    async def _do_validate_credentials(self) -> dict:
        return {"valid": True}

    def _get_config_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "api_key": {"type": "string"},
            }
        }
```

## YAML Configuration

Every adapter is configured via YAML:

```yaml
adapters:
  my_system:
    type: my_custom
    auth:
      api_key: ${MY_API_KEY}
    permissions:
      allowed_operations: [read]
    rate_limit: 100/minute
    cache:
      enabled: true
      ttl: 300
```
