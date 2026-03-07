# Adapters: The Heart of NeuralBridge

Adapters are the core of NeuralBridge. They are the components that translate the standardized, abstract operations of an AI agent (like `query` or `send_message`) into the specific protocol or API calls of a target system.

## How Adapters Work

Every adapter in NeuralBridge inherits from a common `BaseAdapter` class. This ensures that all adapters, regardless of the system they connect to, expose a consistent interface for:

- **Connection Management**: Establishing and tearing down connections gracefully.
- **Execution**: Performing operations with structured input and output.
- **Credential Validation**: Securely checking the validity of stored credentials.
- **Configuration Schema**: Defining the required configuration parameters in a standardized way.

This standardized approach means that once an adapter is written for a system, *any* AI agent can interact with that system through NeuralBridge without needing to understand its specific API or authentication mechanism.

## Available Adapters

NeuralBridge comes with a rich library of over 20 pre-built adapters, categorized for easy discovery.

| Category | Description | Examples |
|---|---|---|
| [**Databases**](databases.md) | Connect to relational and NoSQL databases. | PostgreSQL, MongoDB, Snowflake |
| [**APIs**](apis.md) | Interact with any web-based API. | REST, GraphQL, SOAP |
| [**Messaging**](messaging.md) | Send and receive messages on collaboration platforms. | Slack, Microsoft Teams, Email |
| [**Cloud Services**](cloud.md) | Manage resources in public cloud environments. | AWS S3, Azure Blob Storage, Google Cloud Storage |
| [**Productivity**] | Integrate with common productivity tools. | Gmail, Notion |
| [**ERP/CRM**] | Connect to enterprise resource planning and customer relationship management systems. | Salesforce, SAP |

## The Power of YAML Configuration

All adapters are configured through simple, human-readable YAML files. This allows non-developers to easily set up and manage connections.

```yaml
adapters:
  # Connect to a PostgreSQL database
  main_db:
    type: postgres
    auth:
      username: ${DB_USER}
      password: ${DB_PASS}
      host: db.example.com
      database: production

  # Connect to the Slack API
  slack_alerts:
    type: slack
    auth:
      bot_token: ${SLACK_BOT_TOKEN}
```

This configuration-driven approach separates the *what* from the *how*. The agent simply needs to know *what* it wants to do (e.g., `query main_db`), and NeuralBridge handles *how* to do it securely and efficiently.
