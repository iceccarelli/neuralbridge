
# Getting Started

This guide will get you up and running with NeuralBridge in minutes. We offer two primary methods for installation: Docker Compose (recommended for a full-stack experience) and pip for a lightweight, server-only setup.

## Prerequisites

- Docker and Docker Compose (for Docker installation)
- Python 3.11+ (for pip installation)

## 1. Docker Compose (Recommended)

This is the easiest way to get started. It spins up the NeuralBridge API server, the React dashboard, and all necessary services like Postgres and Redis.

```bash
# Clone the repository
git clone https://github.com/iceccarelli/neuralbridge.git
cd neuralbridge

# Start all services in the background
docker compose up -d
```

That's it! You can now access:

- **The React Dashboard** at `http://localhost:3000`
- **The FastAPI Backend & API Docs** at `http://localhost:8000/docs`

## 2. pip Installation

If you only need the core NeuralBridge server and do not require the dashboard or other services, you can install it directly from PyPI.

```bash
pip install neuralbridge
```

Once installed, you can start the server:

```bash
neuralbridge serve
```

This will start the FastAPI server on `http://127.0.0.1:8000`.

## Example: Connecting an Agent to Salesforce

Let's walk through a simple example of using NeuralBridge to connect an AI agent to Salesforce.

### Step 1: Create a YAML Configuration

Create a file named `salesforce.yaml`. This file tells NeuralBridge how to connect to Salesforce and what permissions to grant.

```yaml
adapters:
  salesforce-prod:
    type: salesforce
    description: "Production Salesforce instance for the sales team."
    auth:
      type: oauth2
      client_id: ${SALESFORCE_CLIENT_ID}      # Loaded from environment variables
      client_secret: ${SALESFORCE_CLIENT_SECRET} # Loaded from environment variables
      instance_url: https://your-org.my.salesforce.com
    permissions:
      - role: sales_agent
        allowed_operations:
          - query
        allowed_queries:
          - "SELECT Id, Name, Amount FROM Opportunity WHERE IsWon = true"
          - "SELECT Id, Name FROM Account WHERE Industry = 'Technology'"
    rate_limit: 1000/hour
    cache:
      enabled: true
      ttl: 600 # 10 minutes
```

### Step 2: Set Environment Variables

NeuralBridge securely loads credentials from environment variables. Set your Salesforce credentials:

```bash
export SALESFORCE_CLIENT_ID="your_client_id"
export SALESFORCE_CLIENT_SECRET="your_client_secret"
```

### Step 3: Run the Connection

Use the `neuralbridge` CLI to load and manage your adapter configurations.

```bash
neuralbridge connect --config salesforce.yaml
```

### Step 4: Use the Tool in Your Agent

Now, any AI agent that can make a REST API call can use the `salesforce-prod_query` tool through the NeuralBridge MCP gateway. The agent simply needs to make a POST request:

```json
{
  "adapter": "salesforce-prod",
  "operation": "query",
  "params": {
    "soql": "SELECT Id, Name FROM Account WHERE Industry = 'Technology'"
  }
}
```

NeuralBridge handles the authentication, authorization, execution, and audit logging, providing a secure and compliant bridge between your agent and your enterprise data.
