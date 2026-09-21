"""The write-gate shared by every path that can reach an adapter's
``execute()`` — ``/ai``'s own orchestrator, the raw adapters REST route
(``api/routes/adapters.py``), and the MCP gateway (``core/gateway.py``).

Phase 1 left those last two enforcing nothing: a free, even anonymous,
caller could skip `/ai` entirely and mutate a Postgres database directly
through either path. Phase 2 closes that specifically — not by inventing
a second policy engine, but by importing the same
``neuralbridge.ai.policy.evaluate`` and
``neuralbridge.ai.entitlements.require_ai_control_plane`` that gate `/ai`
itself.

Scope, deliberately: this only classifies **postgres** operations, the
one adapter `/ai` itself supports (see the capability matrix — the other
~20 adapters are Experimental/evolving and were never gated by anything,
including `/ai`). Extending real entitlement/policy coverage to every
adapter is future work, not this PR's "ship the paid wedge" scope; this
module says so explicitly rather than silently narrowing what it claims
to cover.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException

from neuralbridge.ai.entitlements import Principal, require_ai_control_plane
from neuralbridge.ai.policy import PolicyError, evaluate


async def enforce_write_gate(adapter_type: str, operation: str, params: dict[str, Any], principal: Principal) -> None:
    """Raise ``HTTPException`` (403 for a disallowed payload, 402 for an
    under-entitled paid caller) to refuse; return normally to proceed.

    No-ops for every adapter type other than ``postgres`` — see module
    docstring. For ``postgres``, a READ always proceeds; a WRITE/DESTRUCTIVE
    operation (or one matching an exfiltration/injection shape) is refused
    the same way it would be if it had come through `/ai`.
    """
    if adapter_type != "postgres":
        return

    try:
        decision = evaluate(adapter_type, operation, params)
    except PolicyError as exc:
        raise HTTPException(status_code=403, detail=exc.reason) from exc

    if decision.requires_approval:
        await require_ai_control_plane(principal)
