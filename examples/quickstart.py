#!/usr/bin/env python3
"""
NeuralBridge adapter platform: a quick tour of the router, the audit log and the fail-closed policy.

This is the experimental adapter platform behind Industrial Autonomous Assurance, not the assurance product
(for that: ``python -m assurance report demo --out demo/``).

Slack and Salesforce here are CANNED adapters: they make no call to Slack or Salesforce and return invented
results. They refuse to run unless you opt in with ``allow_mock`` (as below) or ``NEURALBRIDGE_ALLOW_MOCK_ADAPTERS=1``,
and every canned result is flagged ``mock``. See docs/integrations.md for what each adapter really does.

Run (from the repository root):
    PYTHONPATH=src python examples/quickstart.py
"""

import asyncio

from neuralbridge.adapters.base import MockBackendRefusedError
from neuralbridge.adapters.erp_crm.salesforce import SalesforceAdapter
from neuralbridge.adapters.messaging.slack import SlackAdapter
from neuralbridge.core.router import AdapterRegistry, RequestRouter
from neuralbridge.security.audit import AuditLogger, InMemoryAuditStorage


async def main() -> None:
    print("=" * 64)
    print("  NeuralBridge adapter platform: quick tour")
    print("  Experimental. The adapters below return CANNED data.")
    print("=" * 64)

    # 1-2. Registry and adapters. allow_mock is the explicit, per-adapter opt-in to canned data.
    registry = AdapterRegistry()
    registry.register(SlackAdapter(config={"bot_token": "xoxb-demo", "allow_mock": True}))
    registry.register(SalesforceAdapter(config={"allow_mock": True}))
    print(f"\n[1/4] Registered: {', '.join(registry.list_all())}")

    # 3. Router with an audit log.
    audit = AuditLogger(storage=InMemoryAuditStorage())
    router = RequestRouter(registry=registry, audit_logger=audit)

    print("[2/4] Running operations (canned: nothing is sent to Slack or Salesforce)...\n")
    sf = await router.route(
        adapter_type="salesforce", operation="query", params={"soql": "SELECT Id, Name FROM Account LIMIT 3"}
    )
    print(f"  Salesforce query -> {sf}\n")
    slack = await router.route(
        adapter_type="slack", operation="send_message", params={"channel": "#ai-alerts", "text": "hello"}
    )
    print(f"  Slack send_message -> {slack}\n")

    # 4. The default: no opt-in, no canned data.
    print("[3/4] The same adapter without the opt-in:")
    strict = SlackAdapter(config={"bot_token": "xoxb-demo"})
    try:
        await strict.execute("send_message", {"channel": "#ai-alerts", "text": "hello"})
    except MockBackendRefusedError as exc:
        print(f"  refused: {exc}\n")

    print("[4/4] Audit trail:")
    events = [event async for event in audit.query_events()]
    print(f"  {len(events)} audit events recorded")
    for event in events[-3:]:
        print(f"  - {event}")


if __name__ == "__main__":
    asyncio.run(main())
