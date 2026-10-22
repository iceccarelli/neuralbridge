"""Individual operators of an account: who may make a human decision on a case.

An account key proves the account. A case decision, however, is a human act, and
"the account said Dr. Keller did it" is a string anybody holding the key can type.
This adds the smallest binding that fits the architecture: a named operator, a
role, and a key issued to that operator. A decision made with that key is
attributed to that operator by the server, and a revoked or disabled operator's
keys stop authenticating.

What this establishes: *a credential issued to the operator named N in account A
was presented*. What it does not: that N is a particular real-world person (there
is no identity proofing here), or that the holder of the key is N and not someone
N gave it to.

Bootstrapping: an account with no operators lets an account-level key create the
first one, which must be a ``decider``. After that, creating or disabling
operators needs a ``decider`` operator's key, so an automation holding only an
account key cannot mint itself a decision-making identity. The account holder
should create the first operator before handing any key to an agent.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Machine, get_accounts
from assurance.billing.accounts import (
    MAX_ACTIVE_KEYS,
    AccountStore,
    KeyLimitError,
    OperatorsExistError,
    Principal,
)

__all__ = ["operator_router"]

operator_router = APIRouter(prefix="/v1/operators", tags=["operators"])


class OperatorIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200, pattern=r"\S")
    role: str = Field(default="contributor", pattern="^(contributor|decider)$")


def _account_id(principal: Principal) -> str:
    if principal.account is None or principal.key_prefix in ("open-mode", "operator") \
            or principal.account.id == "operator":
        raise HTTPException(status_code=403, detail={
            "error": "account_required",
            "detail": "operators belong to a customer account; this credential has none "
                      "(the platform operator key and open mode cannot make or disable "
                      "operators, and cannot make hosted case decisions)."})
    return principal.account.id


def _require_decider(principal: Principal) -> None:
    if principal.operator_role != "decider":
        raise HTTPException(status_code=403, detail={
            "error": "decider_role_required",
            "detail": "managing operators needs a key issued to a 'decider' operator."})


@operator_router.get("", summary="The account's operators")
async def list_operators(
    principal: Annotated[Principal, Machine],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    return {"operators": accounts.operators_for(_account_id(principal)),
            "you": {"operator_id": principal.operator_id,
                    "role": principal.operator_role or "account-level key"}}


@operator_router.post("", status_code=201,
                      summary="Create an operator and issue its key (shown once)")
async def create_operator(
    body: OperatorIn,
    principal: Annotated[Principal, Machine],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    account_id = _account_id(principal)
    created_by = principal.operator_id or f"account-key:{principal.key_prefix}"
    bootstrap = not principal.operator_id and principal.operator_role == ""
    if principal.operator_id:
        _require_decider(principal)
    elif body.role != "decider":
        raise HTTPException(status_code=422, detail={
            "error": "first_operator_must_decide",
            "detail": "the first operator of an account must be a 'decider'; "
                      "otherwise nobody could ever close a case."})
    try:
        op_id, key = accounts.create_operator(
            account_id, body.name, body.role, created_by=created_by,
            only_if_none=bootstrap, max_active_keys=MAX_ACTIVE_KEYS)
    except OperatorsExistError as exc:
        # An account-level key may only create the very first operator, atomically.
        raise HTTPException(status_code=403, detail={
            "error": "decider_role_required", "detail": str(exc)}) from exc
    except KeyLimitError as exc:
        raise HTTPException(status_code=409, detail={
            "error": "key_limit", "detail": str(exc)}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"operator_id": op_id, "name": body.name.strip(), "role": body.role,
            "api_key": key,
            "note": "This key is shown once and attributes every action made with it to "
                    "this operator. It binds a credential to a name; it does not prove "
                    "who holds it."}


@operator_router.post("/{operator_id}/disable",
                      summary="Disable an operator and revoke its keys")
async def disable_operator(
    operator_id: str,
    principal: Annotated[Principal, Machine],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    account_id = _account_id(principal)
    _require_decider(principal)
    outcome = accounts.disable_operator(account_id, operator_id)
    if outcome == "not_found":
        raise HTTPException(status_code=404, detail={"error": "operator_not_found"})
    return {"operator_id": operator_id, "outcome": outcome}
