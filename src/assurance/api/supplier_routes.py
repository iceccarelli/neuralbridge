"""Hosted supplier advisory feeds over HTTP.

See `deploy/assurance/ADR-0001-supplier-api.md` for why this exists and why
it looks the way it does. The short version: `assurance supplier publish` is
CLI-only today, so a component supplier — the second class of payer
HANDOFF.md's P1 names — has no way to pay us even if they want to. This adds
the smallest real surface that makes a supplier a payer without inventing
either a price (there is no Stripe price for this tier — it is sales-assigned
until one exists) or a signing service that would hold a supplier's private
key.

A supplier signs an advisory **locally**, the same way the CLI does (their
private key never leaves their machine, same as ``assurance supplier
publish``), and POSTs the resulting signed record here to be hosted. This
service only validates structure and feed invariants — the same invariants
``assurance.supplier.publish.publish()`` enforces — and appends it to a feed
file that is public and unmetered to read, forever, because the value of a
supplier's advisory is in how many integrators can find it, not in how few.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict

from assurance.api.deps import Supplying, supplier_feeds_dir
from assurance.billing.accounts import Principal
from assurance.supplier.publish import (
    AdvisoryFeed,
    PublishError,
    SignedAdvisory,
)

__all__ = ["supplier_router"]

supplier_router = APIRouter(prefix="/v1/supplier", tags=["supplier"])


class AdvisoryIn(BaseModel):
    """A pre-signed advisory record, exactly as `SignedAdvisory.to_dict()` emits it.

    This service never sees a private key: the caller signs locally (the same
    machinery `assurance supplier publish` uses) and hands over the already-
    signed, already-chained record. Structural validation happens on load via
    `SignedAdvisory.from_dict`; this model only proves the body is a JSON
    object before it gets there.
    """

    model_config = ConfigDict(extra="allow")


@supplier_router.post(
    "/advisory",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Publish a signed advisory to your hosted feed (Supplier tier)",
)
def post_advisory(body: AdvisoryIn, principal: Annotated[Principal, Supplying]) -> dict[str, Any]:
    assert principal.account is not None  # Supplying guarantees this
    feed_path = supplier_feeds_dir() / f"{principal.account.id}.jsonl"
    feed = AdvisoryFeed(feed_path)

    try:
        record = SignedAdvisory.from_dict(body.model_dump())
    except PublishError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "malformed_advisory", "detail": str(exc)},
        ) from exc
    if not record.signature:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "unsigned_advisory",
                "detail": "This record carries no signature. Sign it locally with "
                "`assurance supplier publish` (or the same library call) before "
                "sending it here — this service never holds a supplier's private key.",
            },
        )

    history = feed.read()
    if history:
        previous = history[-1]
        if previous.supplier.supplier_id != record.supplier.supplier_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "supplier_identity_mismatch",
                    "detail": f"this account's feed already belongs to "
                    f"{previous.supplier.supplier_id!r}; this record is signed as "
                    f"{record.supplier.supplier_id!r}. One feed, one supplier.",
                },
            )
        if record.sequence != previous.sequence + 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "sequence_mismatch",
                    "detail": f"expected sequence {previous.sequence + 1}, got "
                    f"{record.sequence}. Read GET /v1/supplier/feed/{principal.account.id} "
                    "and publish on top of its last record.",
                },
            )
        if record.previous != previous.content_hash():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "chain_mismatch",
                    "detail": "this record's `previous` does not match the current "
                    "feed head — it was built against a stale copy of the feed.",
                },
            )
        if any(h.advisory_id == record.advisory_id and not h.is_withdrawal
               for h in history):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "duplicate_advisory_id",
                    "detail": f"{record.advisory_id} was already published at "
                    f"sequence {next(h.sequence for h in history if h.advisory_id == record.advisory_id)}.",
                },
            )
    elif record.sequence != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "sequence_mismatch",
                "detail": f"this is a new feed; the first record must be sequence 1, got {record.sequence}.",
            },
        )

    feed.append(record)
    return {
        "sequence": record.sequence,
        "advisory_id": record.advisory_id,
        "feed_url": f"/v1/supplier/feed/{principal.account.id}",
    }


@supplier_router.get(
    "/feed/{supplier_account_id}",
    summary="Read a hosted supplier feed (free, no account, forever)",
)
def get_feed(supplier_account_id: str) -> Response:
    feed_path = supplier_feeds_dir() / f"{supplier_account_id}.jsonl"
    if not feed_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No feed has been published under this id.",
        )
    return Response(content=feed_path.read_text("utf-8"), media_type="application/x-ndjson")
