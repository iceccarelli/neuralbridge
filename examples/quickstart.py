#!/usr/bin/env python3
"""
NeuralBridge Quick Start Example.

Demonstrates how to:
1. Create an adapter registry
2. Register adapters
3. Execute operations through the router
4. View audit logs

Run:
    python examples/quickstart.py
"""

import asyncio

from neuralbridge.adapters.databases.postgres import PostgresAdapter
from neuralbridge.adapters.messaging.slack import SlackAdapter
from neuralbridge.adapters.erp_crm.salesforce import SalesforceAdapter
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger


async def main() -> None:
    print("=" * 60)
    print("  NeuralBridge Quick Start")
    print("  Universal Enterprise Middleware for Agentic AI")
    print("=" * 60)

    # ── Step 1: Create the adapter registry ──────────────────
    print("\n[1/5] Creating adapter registry...")
    registry = AdapterRegistry()

    # ── Step 2: Register adapters ────────────────────────────
    print("[2/5] Registering adapters...")
    registry.register("postgres", PostgresAdapter(config={"host": "localhost"}))
    registry.register("slack", SlackAdapter(config={"bot_token": "xoxb-demo"}))
    registry.register("salesforce", SalesforceAdapter(config={}))
    print(f"       Registered: {', '.join(registry.list_all())}")

    # ── Step 3: Create the request router ────────────────────
    print("[3/5] Initializing request router with audit logging...")
    audit = AuditLogger()
    router = RequestRouter(registry=registry, audit_logger=audit)

    # ── Step 4: Execute operations ───────────────────────────
    print("[4/5] Executing operations...\n")

    # Query PostgreSQL
    print("  → PostgreSQL: Running query...")
    pg_result = await router.route(
        adapter_type="postgres",
        operation="query",
        params={"sql": "SELECT id, name, email FROM users LIMIT 5"},
    )
    print(f"    Result: {pg_result}\n")

    # Query Salesforce
    print("  → Salesforce: Running SOQL query...")
    sf_result = await router.route(
        adapter_type="salesforce",
        operation="query",
        params={"soql": "SELECT Id, Name FROM Account LIMIT 3"},
    )
    print(f"    Result: {sf_result}\n")

    # Send Slack message
    print("  → Slack: Sending notification...")
    slack_result = await router.route(
        adapter_type="slack",
        operation="send_message",
        params={"channel": "#ai-alerts", "text": "NeuralBridge is running!"},
    )
    print(f"    Result: {slack_result}\n")

    # ── Step 5: Review audit trail ───────────────────────────
    print("[5/5] Reviewing audit trail...")
    events = await audit.query_events(filters={})
    print(f"       Total audit events: {len(events)}")
    for event in events[-3:]:
        print(f"       - {event}")

    print("\n" + "=" * 60)
    print("  Quick start complete! NeuralBridge is ready.")
    print("  Visit http://localhost:8000/docs for the API.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
