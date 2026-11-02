"""The Machine Assurance Check service catalogue: what can be executed for a machine right now.

One function, :func:`service_catalogue`, is the body of ``GET /v1/check/services``, the MCP tool
``services`` and ``assurance check services``. It is generated from the same request models and
the same ``PLANS`` table every route enforces; nothing in it is a price or a capability this
deployment cannot execute.
"""

from __future__ import annotations

from typing import Any

from assurance.check.pipeline import AssuranceVerdict
from assurance.core.errors import AssuranceError

__all__ = ["CHECK_OUTPUT_SCHEMA", "service_catalogue"]

# Kept in sync with assurance.check.pipeline.MachineAssuranceCheck.to_dict()
# by hand, not generated: it is a dataclass, not a Pydantic model, so there is
# nothing to introspect automatically without inventing a second schema
# layer. The input schemas below *are* introspected, straight from the
# Pydantic models the routes already validate against — no drift possible.
CHECK_OUTPUT_SCHEMA: dict[str, Any] = {
    "machine": "string", "verdict": "string (see AssuranceVerdict)",
    "enrolled": "boolean", "advisory_evaluated": "boolean", "affected": "boolean",
    "configuration": {"status": "matched | changed | unknown", "changes": "array"},
    "matches": "array", "functions": "array",
    "evidence": {"valid": "integer", "stale": "integer",
                 "insufficient": "integer", "cannot_determine": "integer"},
    "required_actions": "array of function_id",
    "human_review_required": "boolean",
    "interventions": "array", "latest_intervention": "object | null",
    "fleet": {"machines_analyzed": "integer | null",
              "machines_affected": "integer | null"},
    "commercial_next_action": {"action": "string", "endpoint": "string | null"},
    "assessed_at": "string (UTC timestamp)", "checks_skipped": "array of string",
}


def service_catalogue() -> dict[str, Any]:
    """A machine-readable catalogue an agent can discover before calling anything.

    Needs pydantic (the request models are introspected); an installation without it raises
    :class:`AssuranceError` saying so, which a command line reports as "could not run".
    """
    try:
        from assurance.check.schemas import FleetMachineCheckIn, MachineCheckIn
    except ImportError as exc:
        raise AssuranceError(
            "the service catalogue is generated from the request models, which need pydantic "
            "(pip install pydantic). Nothing was invented in its place.") from exc
    from assurance.billing.plans import PLANS

    cell = PLANS["cell"]
    return {
        "verdicts": [v.value for v in AssuranceVerdict],
        "services": [
            {
                "service_id": "machine_assurance_check",
                "human_name": "Machine Assurance Check",
                "description": (
                    "Does this change or advisory match this machine? Free, "
                    "no account, no ledger read — cannot assess whether "
                    "standing safety evidence is still valid."
                ),
                "endpoint": "POST /v1/check/machine",
                "input_schema": MachineCheckIn.model_json_schema(),
                "output_schema": CHECK_OUTPUT_SCHEMA,
                "free_or_paid": "free",
                "required_plan": None,
                "price": "free",
                "human_review_may_be_required": True,
                "estimated_execution_class": "synchronous, sub-second",
                "evidence_output": "none — no ledger entry is made",
                "commercial_action": None,
            },
            {
                "service_id": "fleet_machine_assurance",
                "human_name": "Fleet Machine Assurance Check",
                "description": (
                    "The same check against a machine already enrolled in "
                    "the ledger: its own intervention history and "
                    "verification bundles, plus the fleet-wide fan-out when "
                    "a change is given."
                ),
                "endpoint": "POST /v1/check/fleet-machine",
                "input_schema": FleetMachineCheckIn.model_json_schema(),
                "output_schema": CHECK_OUTPUT_SCHEMA,
                "free_or_paid": "paid",
                "required_plan": "cell",
                "price": cell.price_label or "unpublished",
                "human_review_may_be_required": True,
                "estimated_execution_class": "synchronous, sub-second",
                "evidence_output": (
                    "the machine's manifest, interventions and verification "
                    "bundles already sealed in the hash-chained ledger — "
                    "this call reads them, it does not seal anything new"
                ),
                "commercial_action": {
                    "status_if_not_entitled": "payment_required",
                    "how_to_check_entitlement": "GET /v1/plans with X-API-Key",
                    "how_to_purchase": "POST /v1/checkout",
                },
            },
        ],
    }
