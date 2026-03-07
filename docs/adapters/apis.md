# API Adapters

In the modern enterprise, data and functionality are exposed through a wide variety of APIs. NeuralBridge provides a set of powerful and flexible adapters to connect AI agents to these APIs, whether they are modern REST and GraphQL services or legacy SOAP and OData endpoints.

## Supported API Types

| Adapter | Module Path | Key Operations | Use Cases |
|---|---|---|---|
| **REST** | `adapters.apis.rest` | `get`, `post`, `put`, `patch`, `delete` | Interacting with virtually any modern web service, from internal microservices to public SaaS platforms. |
| **GraphQL** | `adapters.apis.graphql` | `query`, `mutation`, `introspect` | Efficiently querying complex data graphs, reducing over-fetching, and interacting with modern application backends. |
| **SOAP** | `adapters.apis.soap` | `call`, `discover_wsdl` | Integrating with legacy enterprise systems, financial services, and government platforms that have not yet migrated to REST. |
| **OData** | `adapters.apis.odata` | `query`, `create`, `update`, `delete` | Connecting to Microsoft ecosystem products like Dynamics 365 and SharePoint, as well as other OData-compliant services. |

## Key Features

- **Dynamic Operation Discovery**: Adapters like SOAP and GraphQL can often discover the available operations and data types automatically, enabling agents to learn how to use an API on the fly.
- **Authentication Handling**: The adapters seamlessly handle various authentication mechanisms, including API keys, OAuth 2.0, and basic authentication, managed securely through the NeuralBridge Vault.
- **Payload Templating**: For complex `POST` or `PUT` requests, you can define payload templates in the YAML configuration, allowing agents to simply fill in the required variables.

## Example: Calling a REST API

This example shows how to configure a connection to a weather API and allow an agent to fetch the current weather for a given city.

### YAML Configuration (`weather.yaml`)

```yaml
adapters:
  weather_api:
    type: rest
    description: "Public API for fetching current weather data."
    base_url: "https://api.weather.com/v1"
    auth:
      type: api_key
      header: "X-Api-Key"
      key: ${WEATHER_API_KEY}
    permissions:
      - role: public_user
        allowed_operations:
          - get
        allowed_endpoints:
          # Use a wildcard to allow any city
          - "/current?city=*"
    rate_limit: 60/minute
```

### Agent Tool Call

An agent with the `public_user` role can then make a `get` request:

```json
{
  "adapter": "weather_api",
  "operation": "get",
  "params": {
    "endpoint": "/current?city=London"
  }
}
```

NeuralBridge constructs the full URL (`https://api.weather.com/v1/current?city=London`), injects the `X-Api-Key` header, executes the request, and returns the JSON response to the agent. The `allowed_endpoints` configuration ensures the agent cannot access other, potentially sensitive, API endpoints.
