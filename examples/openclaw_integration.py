#!/usr/bin/env python3
"""
NeuralBridge + OpenClaw Integration Example.

Demonstrates how to use NeuralBridge as a tool provider for OpenClaw
agents, enabling them to securely access enterprise systems.

This example shows:
1. Registering NeuralBridge adapters as OpenClaw tools
2. Executing agent workflows through NeuralBridge
3. CRA-compliant audit logging of all agent actions

Run:
    python examples/openclaw_integration.py
"""

import asyncio

from neuralbridge.adapters.databases.postgres import PostgresAdapter
from neuralbridge.adapters.erp_crm.salesforce import SalesforceAdapter
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger
from neuralbridge.utils.openclaw_plugin import OpenClawPluginAdapter


async def main() -> None:
    print("=" * 60)
    print("  NeuralBridge + OpenClaw Integration")
    print("=" * 60)

    # ── Set up NeuralBridge ──────────────────────────────────
    registry = AdapterRegistry()
    registry.register("postgres", PostgresAdapter(config={"host": "localhost"}))
    registry.register("salesforce", SalesforceAdapter(config={}))

    audit = AuditLogger()
    router = RequestRouter(registry=registry, audit_logger=audit)

    # ── Create OpenClaw-compatible tool definitions ──────────
    plugin = OpenClawPluginAdapter(router=router)
    tools = plugin.get_tool_definitions()

    print(f"\n  Registered {len(tools)} tools for OpenClaw:\n")
    for tool in tools:
        print(f"  - {tool['name']}: {tool['description']}")

    # ── Simulate an OpenClaw agent calling NeuralBridge ──────
    print("\n  Simulating OpenClaw agent workflow...\n")

    # Agent wants to query the database
    print("  Agent: 'I need to find all customers in California.'")
    result = await plugin.execute_tool(
        tool_name="postgres_query",
        arguments={
            "sql": "SELECT name, email FROM customers WHERE state = 'CA' LIMIT 5"
        },
        agent_id="openclaw-agent-001",
    )
    print(f"  NeuralBridge → Agent: {result}\n")

    # Agent wants to create a Salesforce record
    print("  Agent: 'Create a new lead in Salesforce for this prospect.'")
    result = await plugin.execute_tool(
        tool_name="salesforce_create_record",
        arguments={
            "sobject": "Lead",
            "fields": {
                "FirstName": "Jane",
                "LastName": "Doe",
                "Company": "TechCorp",
                "Email": "jane@techcorp.com",
            },
        },
        agent_id="openclaw-agent-001",
    )
    print(f"  NeuralBridge → Agent: {result}\n")

    # ── Show audit trail ─────────────────────────────────────
    events = await audit.query_events(filters={})
    print(f"  Audit trail: {len(events)} events logged (CRA-compliant)")

    print("\n" + "=" * 60)
    print("  Integration complete!")
    print("  Every agent action was logged, encrypted, and audited.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
