"""Counter-signature: a second party who cannot rewrite your ledger.

The module :mod:`assurance.attest` says the signing key must live where the
ledger's operator is not. A hosted service that held both the ledger and the
key would satisfy nothing — whoever can rewrite the records could re-sign them,
which is precisely the decoration that module refuses to be.

So the hosted product does the opposite of what is convenient. **The ledger
never leaves the customer's premises.** They compute their own head, which
requires no trust in anybody, and send three numbers: how many records, which
sequence, which link hash. The service signs *that*, records it in an
append-only log belonging to that account, and refuses the same three cases the
local signer refuses — a shorter ledger, a head that has moved backwards, a
previously signed position that now resolves differently.

What this buys, precisely:

* The customer's own administrator cannot rewind, because the removed records
  were counted in a statement signed by a key nobody at the customer holds.
* The service cannot fabricate the customer's evidence, because the service
  never had it. All it ever saw was a hash.
* Neither party can quietly change the story, because each holds a copy of a
  log that chains to itself.

The basis of every attestation made here is ``declared_by_holder`` and that
value is inside the signed bytes. The service did not see the chain verify. It
is not going to imply otherwise later.

Verification is free and unmetered, for the same reason the bundle re-checker
is: an attestation only a paying customer can check is worth nothing to the
regulator, the insurer or the buyer who is the actual audience for it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Anyone, Attesting, get_accounts
from assurance.attest.attestation import (
    AttestationBasis,
    AttestationError,
    AttestationLog,
    HeadAttestation,
    LedgerHead,
    attest,
    verify_log,
)
from assurance.attest.keys import SigningKey, SigningKeyError, VerifyingKey
from assurance.billing.accounts import AccountStore, Principal

__all__ = ["attest_router"]

attest_router = APIRouter(prefix="/v1/ledger/attest", tags=["attestation"])

_KEY_PEM_ENV = "ASSURANCE_ATTEST_KEY_PEM"
_KEY_ENV = "ASSURANCE_ATTEST_KEY"
_LOGS_ENV = "ASSURANCE_ATTEST_LOGS"
_PASSPHRASE_ENV = "ASSURANCE_ATTEST_PASSPHRASE"

#: A caller submitting more than this many attestations to verify in one call
#: has a file, not a request. Refusing early beats timing out.
MAX_VERIFY_RECORDS = 5_000


def _service_key() -> SigningKey:
    # PEM-in-environment first, because that is what a secrets manager hands a
    # container. A path is for the deployment that mounts a volume or a token.
    pem = os.environ.get(_KEY_PEM_ENV, "").strip()
    if pem:
        try:
            return SigningKey.from_pem(
                pem, passphrase=os.environ.get(_PASSPHRASE_ENV, ""))
        except SigningKeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "attestation_key_unusable", "detail": str(exc)},
            ) from exc

    path = os.environ.get(_KEY_ENV, "")
    if not path:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "error": "no_attestation_key_configured",
                "remedy": (
                    f"Set {_KEY_PEM_ENV} to the key itself, or {_KEY_ENV} to a "
                    "path. Generate one with `assurance attest keygen`. "
                    "This service will not invent a key "
                    "on demand: a key that appears when first needed and lives "
                    "beside the process that uses it is not a second party."
                ),
            },
        )
    try:
        return SigningKey.load(path, passphrase=os.environ.get(_PASSPHRASE_ENV, ""))
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "attestation_key_unusable", "detail": str(exc)},
        ) from exc


def _log_for(principal: Principal) -> AttestationLog:
    root = Path(os.environ.get(_LOGS_ENV, "attestations"))
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in principal.subject)
    return AttestationLog(root / f"{safe}.jsonl")


class AttestIn(BaseModel):
    """Three numbers the customer reads out of their own ledger.

    Nothing else is accepted, and nothing else is wanted. The point of this
    endpoint is that the records stay where they are.
    """

    model_config = ConfigDict(extra="forbid")

    ledger_length: int = Field(ge=0, description="how many records the chain holds")
    head_seq: int = Field(ge=0, description="sequence number of the last record")
    head_link_hash: str = Field(
        min_length=64, max_length=64,
        description="link hash of the last record, hex SHA-256")
    note: str = Field(default="", max_length=500)
    rotating: bool = Field(
        default=False,
        description="acknowledge that this service is signing with a different key "
                    "than it did last time. Only set this if you were told to.")


class AttestationIn(BaseModel):
    model_config = ConfigDict(extra="allow")


class VerifyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attestations: list[dict[str, Any]] = Field(min_length=1)
    public_key_pem: str = Field(
        default="",
        description="the key to check against. Omit to use this service's key — "
                    "but obtaining it from GET /v1/ledger/attest/key over the same "
                    "connection proves less than obtaining it elsewhere.")


@attest_router.get(
    "/key",
    summary="The public key this service counter-signs with. Free, forever.",
)
async def service_key() -> dict[str, Any]:
    """Fetch the verifying key and its fingerprint.

    Read the fingerprint against one published somewhere this service does not
    control. A signature checked against a key that arrived over the same
    connection as the signature proves only that one party was consistent.
    """
    key = _service_key().verifying
    return {
        "fingerprint": key.fingerprint,
        "public_key_pem": key.pem(),
        "algorithm": "Ed25519",
        "checks_skipped": [
            "This response does not establish that the key belongs to this "
            "service rather than to whatever is answering this address. Confirm "
            f"fingerprint {key.fingerprint} by a second route."
        ],
    }


@attest_router.post(
    "",
    summary="Counter-sign the head of your ledger, without sending us the ledger",
)
async def counter_sign(
    body: AttestIn,
    principal: Annotated[Principal, Attesting],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """Sign three numbers, refuse the three cases that would be a lie.

    The refusals return 409, not 422: a shorter ledger is not a malformed
    request, it is the finding. The body of the refusal is the sentence to put
    in front of whoever runs the database.
    """
    try:
        head = LedgerHead(
            length=body.ledger_length,
            head_seq=body.head_seq,
            head_link_hash=body.head_link_hash.lower().strip(),
            basis=AttestationBasis.DECLARED_BY_HOLDER,
        )
    except AttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "not_a_ledger_head", "detail": str(exc)},
        ) from exc

    log = _log_for(principal)
    try:
        record = attest(
            head, _service_key(), log, note=body.note, rotating=body.rotating)
    except AttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "attestation_refused", "finding": str(exc)},
        ) from exc

    return {
        "attestation": record.to_dict(),
        "count": len(log),
        "checks_skipped": [
            "This service did not see your ledger and did not verify your chain. "
            "It signed the values you supplied, at the time you supplied them. "
            "Run `assurance attest verify --ledger` locally to join the two.",
            "Records you appended after this call are covered by no signature.",
        ],
        "keep": (
            "Store this attestation somewhere your ledger's administrator cannot "
            "reach. It is the only artefact in this system that a rewind cannot "
            "touch."
        ),
    }


@attest_router.get(
    "/log",
    summary="Every attestation this service has made for your account",
)
async def account_log(
    principal: Annotated[Principal, Attesting],
) -> dict[str, Any]:
    log = _log_for(principal)
    try:
        records = log.read()
    except AttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "attestation_log_damaged", "finding": str(exc)},
        ) from exc
    return {
        "count": len(records),
        "attestations": [r.to_dict() for r in records],
        "verify_with": "POST /v1/ledger/attest/verify — free, no key needed",
    }


@attest_router.post(
    "/verify",
    summary="Check an attestation log. Free and unmetered, for anyone.",
)
async def verify(
    body: VerifyIn,
    principal: Annotated[Principal, Anyone],
) -> dict[str, Any]:
    """Verify signatures and internal consistency. No account, no quota.

    Deliberately free: the audience for an attestation is a regulator, an
    insurer, or a customer's customer — none of whom will ever hold an API key
    here, and all of whom must be able to check the thing without asking us.

    This endpoint cannot see the caller's ledger, so it cannot answer the
    question that matters most — whether the ledger still holds what was signed
    for. That join happens locally, with ``assurance attest verify --ledger``,
    and its absence here is named rather than glossed.
    """
    if len(body.attestations) > MAX_VERIFY_RECORDS:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail={
                "error": "too_many_attestations",
                "limit": MAX_VERIFY_RECORDS,
                "remedy": "Verify locally: `assurance attest verify --log ...`.",
            },
        )
    try:
        records = [HeadAttestation.from_dict(r) for r in body.attestations]
    except (AttestationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"error": "unreadable_attestation", "detail": str(exc)},
        ) from exc

    if body.public_key_pem.strip():
        try:
            key = VerifyingKey.from_pem(body.public_key_pem)
        except SigningKeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"error": "unreadable_public_key", "detail": str(exc)},
            ) from exc
        supplied = True
    else:
        key = _service_key().verifying
        supplied = False

    verdict = verify_log(records, key)
    skipped = list(verdict.checks_skipped)
    if not supplied:
        skipped.append(
            "No key was supplied, so this service checked the signatures against "
            "its own key. That is a party checking its own work. Fetch the key "
            "and re-run this locally to make the check mean something."
        )
    return {
        "ok": verdict.ok,
        "checked": verdict.checked,
        "summary": verdict.summary(),
        "key_fingerprint": verdict.key_fingerprint,
        "problems": verdict.problems,
        "checks_skipped": skipped,
        "latest": verdict.latest.to_dict() if verdict.latest else None,
    }
