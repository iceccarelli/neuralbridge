"""The write-gate shared by every path that can reach an adapter's
``execute()`` — ``/ai``'s own orchestrator, the raw adapters REST route
(``api/routes/adapters.py``), and the MCP gateway (``core/gateway.py``).

Phase 1 left those last two enforcing nothing: a free, even anonymous,
caller could skip `/ai` entirely and mutate a Postgres database directly
through either path. Phase 2 closed that specifically for **postgres**,
the one adapter `/ai` itself supports (see the capability matrix — the
other ~20 adapters are Experimental/evolving and were never gated by
anything, including `/ai`), by importing the same
``neuralbridge.ai.policy.evaluate`` and
``neuralbridge.ai.entitlements.require_ai_control_plane`` that gate `/ai`
itself. Phase 2's own docstring here said explicitly that every other
adapter type was a no-op — "extending real entitlement/policy coverage
to every adapter is future work, not this PR's scope."

Phase 3 does that future work, without inventing a second policy engine
for the ~20 non-postgres adapters (which have no `/ai` SQL-shaped policy
to reuse — they are heterogeneous REST/RPC/messaging/storage APIs, not
one query language). Instead: for every adapter type other than
``postgres``, a free/anonymous caller may only call an operation on a
real, per-adapter allow-list of **discovery** operations — built by
reading each adapter's actual ``supported_operations`` in
``src/neuralbridge/adapters/`` (not guessed from a naming convention).
Every other operation — anything WRITE/DELETE/RPC-shaped, or a name this
module does not recognise — now requires the same
``ai_control_plane`` entitlement postgres WRITE requires (402 for an
under-entitled caller). Clearing the gate proves the caller is paid; it
says nothing about whether the adapter itself has a real backend behind
it — several of these adapters are documented mock/stub implementations
(see each adapter's own docstring and the capability matrix), and this
gate does not and cannot change that. It only closes the free-execute
hole; it does not retroactively make a mock adapter honest about being a
mock, which is a larger, adapter-by-adapter effort out of this phase's
scope.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import HTTPException

from neuralbridge.ai.entitlements import Principal, require_ai_control_plane
from neuralbridge.ai.policy import PolicyError, evaluate

#: Per-adapter allow-list of operations a free/anonymous caller may still
#: invoke without the ai_control_plane entitlement — real discovery/read
#: operations only, taken from each adapter's own ``supported_operations``
#: in ``src/neuralbridge/adapters/``. Anything not listed here for a given
#: adapter type (including an operation name the adapter doesn't even
#: support) requires the entitlement — "unrecognized" is refused the paid
#: way, never assumed safe.
_SAFE_DISCOVERY_OPS: dict[str, frozenset[str]] = {
    # messaging — read/list only; send_message, upload_file, add_reaction,
    # create_channel, set_webhook, send_photo, send_email etc. are gated.
    "slack": frozenset({"list_channels", "read_messages"}),
    "discord": frozenset({"list_channels", "read_messages"}),
    "teams": frozenset({"list_channels", "list_teams", "read_messages"}),
    "telegram": frozenset({"get_updates", "get_chat"}),
    "email": frozenset({"read_inbox", "search_emails", "get_email", "list_folders"}),
    # productivity
    "gmail": frozenset({"read_inbox", "search_emails", "get_email", "list_labels"}),
    "notion": frozenset({"query_database", "search", "get_page", "list_databases"}),
    # cloud storage — listing/reading objects only; put/upload/delete gated.
    "aws_s3": frozenset({"list_buckets", "list_objects", "get_object", "generate_presigned_url"}),
    "gcs": frozenset({"list_buckets", "list_objects", "get_object", "get_metadata"}),
    "azure_blob": frozenset({"list_containers", "list_blobs", "download_blob", "get_blob_properties"}),
    # databases (non-postgres) — execute_sql/insert/update/delete/create_* gated.
    "mysql": frozenset({"query", "list_tables", "describe_table", "health_check"}),
    "snowflake": frozenset({"query", "list_schemas", "list_tables", "describe_table"}),
    "mongodb": frozenset({"find", "list_collections"}),
    "bigquery": frozenset({"query", "list_datasets", "list_tables", "get_table_schema"}),
    # ERP/CRM — RFCs and BAPI calls can mutate the underlying system, so
    # only metadata/discovery operations are free; call_bapi/execute_rfc/
    # create_record/update_record/delete_record all require entitlement.
    "salesforce": frozenset({"query", "get_record", "describe", "health_check"}),
    "sap_erp": frozenset({"read_table", "list_bapis", "get_metadata"}),
    # generic API adapters
    "soap": frozenset({"discover_operations", "get_wsdl"}),
    "odata": frozenset({"query", "get_metadata"}),
    "rest": frozenset({"get", "head"}),
    "graphql": frozenset({"query", "introspect"}),
    "custom_adapter_template": frozenset({"example_read", "example_list"}),
}

#: For adapters whose free "query"-shaped operation accepts a raw
#: query-language payload the adapter itself does not restrict to reads
#: (found during the Phase 3 sanity pass: ``mysql``/``bigquery`` execute
#: whatever SQL string is in ``params["sql"]`` verbatim once a real
#: backend is connected, and the ``graphql`` adapter dispatches
#: ``operation="query"`` and ``operation="mutation"`` to the exact same
#: handler, trusting the document text over the operation name) — the
#: operation name alone is not a trustworthy safety boundary. This maps
#: each such adapter type to the payload key holding that text and a
#: regex that must match for the call to stay free; anything that does
#: not match (including an empty/missing payload) requires the
#: ``ai_control_plane`` entitlement, same as an unrecognised operation.
_FREE_QUERY_PAYLOAD_GUARDS: dict[str, tuple[str, re.Pattern[str]]] = {
    "mysql": ("sql", re.compile(r"^\s*(select|show|explain|describe)\b", re.IGNORECASE)),
    "snowflake": ("sql", re.compile(r"^\s*(select|show|explain|describe)\b", re.IGNORECASE)),
    "bigquery": ("sql", re.compile(r"^\s*(select|with|explain)\b", re.IGNORECASE)),
    "graphql": ("query", re.compile(r"^\s*(query|\{|#)", re.IGNORECASE)),
}

#: Operations within the map above that actually carry the risky payload —
#: e.g. bigquery's free ``list_tables``/``list_datasets`` don't take
#: ``sql`` at all and must not be swept into this check.
_FREE_QUERY_PAYLOAD_OPS: dict[str, frozenset[str]] = {
    "mysql": frozenset({"query"}),
    "snowflake": frozenset({"query"}),
    "bigquery": frozenset({"query"}),
    "graphql": frozenset({"query"}),
}


def _payload_looks_safe(adapter_type: str, operation: str, params: dict[str, Any]) -> bool:
    """True if ``operation`` on ``adapter_type`` has no extra payload guard,
    or the guard's regex matches the relevant param. False means the
    payload looks like it could mutate despite the read-shaped op name.
    """
    guarded_ops = _FREE_QUERY_PAYLOAD_OPS.get(adapter_type)
    if not guarded_ops or operation not in guarded_ops:
        return True
    key, pattern = _FREE_QUERY_PAYLOAD_GUARDS[adapter_type]
    payload = str(params.get(key, ""))
    return bool(pattern.match(payload))


async def enforce_write_gate(adapter_type: str, operation: str, params: dict[str, Any], principal: Principal) -> None:
    """Raise ``HTTPException`` (403 for a disallowed payload, 402 for an
    under-entitled paid caller) to refuse; return normally to proceed.

    ``postgres`` keeps the detailed SQL-aware policy gate (READ always
    free, WRITE/DESTRUCTIVE gated, exfiltration-shaped SQL refused
    outright). Every other adapter type is checked against
    ``_SAFE_DISCOVERY_OPS``: an operation on that adapter's allow-list
    proceeds free; anything else — a real write/RPC operation, or a name
    this module does not recognise for that adapter — requires the same
    ``ai_control_plane`` entitlement.
    """
    if adapter_type == "postgres":
        try:
            decision = evaluate(adapter_type, operation, params)
        except PolicyError as exc:
            raise HTTPException(status_code=403, detail=exc.reason) from exc

        if decision.requires_approval:
            await require_ai_control_plane(principal)
        return

    safe_ops = _SAFE_DISCOVERY_OPS.get(adapter_type, frozenset())
    if operation in safe_ops and _payload_looks_safe(adapter_type, operation, params):
        return

    await require_ai_control_plane(principal)
