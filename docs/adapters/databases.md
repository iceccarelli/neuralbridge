# Database Adapters

NeuralBridge provides a suite of adapters for connecting to the most popular relational and NoSQL databases. These adapters allow AI agents to perform complex data operations, such as querying for analytics, retrieving customer data, or even performing transactional operations, all through a standardized, secure interface.

## Supported Databases

| Adapter | Module Path | Key Operations | Use Cases |
|---|---|---|---|
| **PostgreSQL** | `adapters.databases.postgres` | `query`, `execute`, `list_tables`, `describe_table` | Running complex analytical queries, performing transactional updates, exploring database schema. |
| **MySQL** | `adapters.databases.mysql` | `query`, `execute`, `list_tables`, `describe_table` | Interacting with legacy systems, powering web backends, data warehousing. |
| **MongoDB** | `adapters.databases.mongodb` | `find`, `insert`, `update`, `delete`, `aggregate` | Working with unstructured data, managing document-based records, real-time analytics. |
| **Snowflake** | `adapters.databases.snowflake` | `query`, `list_schemas`, `describe_table` | Large-scale data warehousing, business intelligence, cloud analytics. |
| **BigQuery** | `adapters.databases.bigquery` | `query`, `list_datasets`, `list_tables` | Serverless data analysis, machine learning with BigQuery ML, querying massive datasets. |

## Common Operations

-   **`query`**: Executes a read-only query (e.g., `SELECT` in SQL, `find` in MongoDB) and returns the results.
-   **`execute`**: Performs a write operation (e.g., `INSERT`, `UPDATE`, `DELETE`). This operation is typically restricted to specific roles for security.
-   **`list_tables` / `list_collections`**: Discovers the available tables or collections in a database, allowing agents to explore the data landscape.
-   **`describe_table`**: Returns the schema of a specific table, including column names and data types, enabling agents to construct valid queries.

## Example: Querying a PostgreSQL Database

This example demonstrates how to configure a connection to a PostgreSQL database and grant a `readonly` role permission to query a specific table.

### YAML Configuration (`postgres.yaml`)

```yaml
adapters:
  analytics_db:
    type: postgres
    description: "Read-only replica of the production analytics database."
    auth:
      host: pg-replica.example.com
      port: 5432
      username: ${ANALYTICS_DB_USER}
      password: ${ANALYTICS_DB_PASS}
      database: analytics
    permissions:
      - role: analyst
        allowed_operations:
          - query
          - list_tables
          - describe_table
        allowed_queries:
          # Allow queries only on the sales_projections table
          - "SELECT * FROM sales_projections WHERE region = ?"
    connection_pool:
      min_size: 5
      max_size: 20
```

### Agent Tool Call

An agent with the `analyst` role can then execute a query like this:

```json
{
  "adapter": "analytics_db",
  "operation": "query",
  "params": {
    "sql": "SELECT month, projected_revenue FROM sales_projections WHERE region = 'EMEA'"
  }
}
```

NeuralBridge ensures the agent can only perform the allowed `query` operation and that the SQL statement matches the permitted pattern, preventing unauthorized data access or modification.
