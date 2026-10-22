"""``GET /v1/value`` — the account's own assurance position (read-only).

The same :func:`assurance.value.assess_position` the CLI runs, over the caller's
own per-account ledger. No scoring and no estimate: see the module for the rule.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from starlette.concurrency import run_in_threadpool

from assurance.api.deps import Machine, get_register
from assurance.billing.accounts import Principal
from assurance.value.position import assess_position

__all__ = ["value_router"]

value_router = APIRouter(prefix="/v1/value", tags=["value"])


@value_router.get("", summary="Your assurance position, derived from your own ledger")
async def position(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    del principal
    return await run_in_threadpool(assess_position, register.ledger)
