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
service only checks structure and the feed's chain invariants — the same
invariants ``assurance.supplier.publish.publish()`` enforces — and appends it to
a feed file that anyone can read without an account, because the value of a
supplier's advisory is in how many integrators can find it, not in how few.

Publishing does **not** verify the signature: it holds no supplier's public key and
must not be asked to vouch for one. (A withdrawal does: it is accepted only under a
key the account pinned for that supplier, see ``post_withdrawal``.) A reader verifies the feed against a key
whose fingerprint they obtained by a route that is not this feed
(``assurance supplier verify``). Nothing in this module meters or charges for
reading a feed.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Machine, Supplying, get_register, supplier_feeds_dir
from assurance.attest.keys import SigningKeyError, VerifyingKey
from assurance.billing.accounts import Principal
from assurance.core.errors import AssuranceError
from assurance.core.identity import format_utc, parse_utc, utc_now
from assurance.fleet.advisory import ComponentAdvisory
from assurance.supplier.baseline import accept_feed_baseline
from assurance.supplier.publish import (
    FEED_FORMAT,
    AdvisoryFeed,
    PublishError,
    SignedAdvisory,
    _parse_feed_text,
    locate_withdrawal,
)
from assurance.supplier.trust import (
    TRUST_STATEMENT,
    SupplierTrustError,
    SupplierTrustStore,
    evaluate_feed,
)

__all__ = ["supplier_router"]

supplier_router = APIRouter(prefix="/v1/supplier", tags=["supplier"])

# A real advisory is a few KB. These are bounds, not product limits: the global
# request cap (1 MiB) is far above what one record needs, and a feed is served
# whole from memory, so the file it grows into has to be bounded too.
MAX_RECORD_BYTES = 256 * 1024
MAX_FEED_BYTES = 16 * 1024 * 1024
#: An Ed25519 signature is 64 bytes. A shape check, not a verification.
_SIGNATURE_BYTES = 64
#: How far ahead of the server's clock a signer's `published_at` may run (clock skew).
PUBLISHED_AT_SKEW = timedelta(minutes=5)
_PARSE_ERRORS = (AssuranceError, KeyError, TypeError, ValueError, AttributeError)


class AdvisoryIn(BaseModel):
    """A pre-signed advisory record, exactly as `SignedAdvisory.to_dict()` emits it.

    This service never sees a private key: the caller signs locally (the same
    machinery `assurance supplier publish` uses) and hands over the already-
    signed, already-chained record. Structural validation happens on load via
    `SignedAdvisory.from_dict`; this model only proves the body is a JSON
    object before it gets there.
    """

    model_config = ConfigDict(extra="allow")


def server_now() -> datetime:
    """The server's receipt clock. Key validity is judged at THIS time, never at the
    signer-typed ``published_at``. Tests replace it; nothing in a request can."""
    return utc_now()


def _unprocessable(error: str, detail: str) -> HTTPException:
    return HTTPException(
        status_code=422,
        detail={"error": error, "detail": detail},
    )


def _check_shape(record: SignedAdvisory) -> None:
    """Refuse a record no reader could parse. This is not a signature check."""
    if record.format != FEED_FORMAT:
        raise _unprocessable(
            "malformed_advisory",
            f"format is {record.format!r}; this service hosts {FEED_FORMAT!r}.")
    if not record.key_fingerprint.strip():
        raise _unprocessable("malformed_advisory", "key_fingerprint is empty.")
    try:
        parse_utc(record.published_at)
    except ValueError as exc:
        raise _unprocessable(
            "malformed_advisory",
            f"published_at {record.published_at!r} is not an ISO-8601 timestamp "
            f"with a timezone ({exc}).") from exc
    try:
        parsed = ComponentAdvisory.from_dict(record.advisory)
    except _PARSE_ERRORS as exc:
        raise _unprocessable(
            "malformed_advisory",
            f"the advisory does not parse as a component advisory ({exc!r}).") from exc
    if not parsed.advisory_id.strip():
        raise _unprocessable("malformed_advisory", "advisory_id is empty.")


def _check_signature_shape(signature: str) -> None:
    try:
        raw = base64.b64decode(signature.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise _unprocessable(
            "malformed_signature", f"the signature is not base64 ({exc}).") from exc
    if len(raw) != _SIGNATURE_BYTES:
        raise _unprocessable(
            "malformed_signature",
            f"an Ed25519 signature decodes to {_SIGNATURE_BYTES} bytes; this one "
            f"decodes to {len(raw)}.")


def _require_chain(history: list[SignedAdvisory], record: SignedAdvisory,
                   account_id: str, now: datetime | None = None) -> None:
    """The feed's chain rules, shared by publish and withdraw (one supplier, the next
    sequence, the current head as predecessor, `published_at` not before the previous
    record's and not ahead of the server). Call it under ``feed.locked()``."""
    received = now if now is not None else server_now()
    if parse_utc(record.published_at) > received + PUBLISHED_AT_SKEW:
        raise _unprocessable(
            "published_at_in_future",
            f"published_at {record.published_at!r} is ahead of the server clock "
            f"(allowed skew {int(PUBLISHED_AT_SKEW.total_seconds() // 60)} minutes).")
    if not history:
        if record.sequence != 1:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "sequence_mismatch",
                    "detail": f"this is a new feed; the first record must be sequence 1, got {record.sequence}.",
                },
            )
        return
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
                f"{record.sequence}. Read GET /v1/supplier/feed/{account_id} "
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
    if parse_utc(record.published_at) < parse_utc(previous.published_at):
        raise _unprocessable(
            "published_at_not_monotonic",
            f"published_at {record.published_at!r} is earlier than the previous record's "
            f"{previous.published_at!r}. A feed's record times never go backwards.")


def _read_signed_record(body: AdvisoryIn) -> SignedAdvisory:
    """Body to a structurally valid, signature-shaped record, or the 413/422 that refuses it."""
    payload = body.model_dump()
    size = len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    if size > MAX_RECORD_BYTES:
        raise HTTPException(
            status_code=413,
            detail={"error": "advisory_too_large",
                    "detail": f"this record is {size} bytes; the limit is {MAX_RECORD_BYTES}."},
        )
    try:
        record = SignedAdvisory.from_dict(payload)
    except _PARSE_ERRORS as exc:
        raise _unprocessable("malformed_advisory", str(exc) or repr(exc)) from exc
    if not record.signature:
        raise _unprocessable(
            "unsigned_advisory",
            "This record carries no signature. Sign it locally with "
            "`assurance supplier publish` (or the same library call) before "
            "sending it here — this service never holds a supplier's private key.",
        )
    _check_signature_shape(record.signature)
    _check_shape(record)
    return record


@supplier_router.post(
    "/advisory",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Publish a signed advisory to your hosted feed (Supplier tier); readers verify the signature",
)
def post_advisory(body: AdvisoryIn, principal: Annotated[Principal, Supplying]) -> dict[str, Any]:
    """Host an advisory you signed locally.

    This checks structure and the feed's chain (sequence, predecessor hash, one
    supplier per feed, no repeated advisory id) and refuses what it cannot parse.
    It does not verify the signature: it holds no supplier key. Readers verify
    the feed against a key fingerprint they obtained from you by another route.
    """
    assert principal.account is not None  # Supplying guarantees this
    feed_path = supplier_feeds_dir() / f"{principal.account.id}.jsonl"
    feed = AdvisoryFeed(feed_path)

    record = _read_signed_record(body)
    received_at = server_now()

    # Read, check and append are one step. Two POSTs for the same sequence must
    # not both pass the check: an append-only chain cannot be un-forked.
    with feed.locked():
        history = feed.read()
        _require_chain(history, record, principal.account.id, received_at)
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
        if feed_path.exists() and feed_path.stat().st_size >= MAX_FEED_BYTES:
            raise HTTPException(
                status_code=413,
                detail={"error": "feed_full",
                        "detail": f"this feed has reached {MAX_FEED_BYTES} bytes."},
            )
        feed.append(record)
    return {
        "sequence": record.sequence,
        "advisory_id": record.advisory_id,
        "feed_url": f"/v1/supplier/feed/{principal.account.id}",
    }


def _refused(error: str, detail: str, code: int = status.HTTP_403_FORBIDDEN) -> HTTPException:
    return HTTPException(status_code=code, detail={"error": error, "detail": detail})


def _verify_under_pinned_key(record: SignedAdvisory, store: SupplierTrustStore,
                             received_at: datetime) -> None:
    """The record must verify under a key THIS account pinned for THIS supplier.

    The fingerprint a record names selects which pin to try; it never grants trust.
    A key that is unpinned, revoked, retired or not yet in force at the server's RECEIPT time
    (``received_at``; the signer-typed ``published_at`` is never used for this),
    or a signature that does not verify, is a 403 and nothing is written.
    """
    problems = store.integrity_problems()
    if problems:
        raise _refused("supplier_trust_store_unhealthy",
                       "the account's trust store does not verify, so no key in it can be "
                       "relied on: " + "; ".join(problems[:2]))
    pin = next((p for p in store.pins(record.supplier.supplier_id)
                if p.fingerprint == record.key_fingerprint), None)
    if pin is None:
        raise _refused(
            "supplier_key_not_pinned",
            f"no key with fingerprint {record.key_fingerprint!r} is pinned for supplier "
            f"{record.supplier.supplier_id!r} in this account "
            "(POST /v1/supplier/trust/pin). A withdrawal is accepted only under a "
            "key that was pinned by a route other than the record itself.")
    in_force = pin.in_force_at(received_at)
    if in_force != "trusted":
        raise _refused("supplier_key_not_in_force",
                       f"the pinned key {pin.fingerprint} is {in_force} at {format_utc(received_at)} "
                       "(judged when the server received the record, not at its published_at).")
    try:
        valid = record.verified_by(VerifyingKey.from_pem(pin.public_key_pem))
    except (PublishError, SigningKeyError, ValueError) as exc:
        raise _unprocessable("malformed_signature", str(exc)) from exc
    if not valid:
        raise _refused("signature_invalid",
                       "the signature does not verify under the pinned key for this record: "
                       "it was altered after signing, or signed by a different key.")


@supplier_router.post(
    "/advisory/withdraw",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Withdraw an advisory of your hosted feed with a signed withdrawal (Supplier tier)",
)
def post_withdrawal(
    body: AdvisoryIn, response: Response, principal: Annotated[Principal, Supplying],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Host a withdrawal you signed locally (`assurance supplier withdraw` on a copy of the feed).

    Unlike publish, this verifies the signature, under the key your account pinned for
    the supplier: a withdrawal changes what readers believe stands. The original
    advisory is never edited or removed; the withdrawal is appended as the next record.
    A repeat for an advisory already withdrawn is a 200 that writes nothing.
    """
    assert principal.account is not None  # Supplying guarantees this
    record = _read_signed_record(body)
    if not record.is_withdrawal:
        raise _unprocessable(
            "not_a_withdrawal",
            "this record does not withdraw anything (`withdraws` is empty); "
            "POST /v1/supplier/advisory publishes an advisory.")
    if not record.withdrawal_reason.strip():
        raise _unprocessable("withdrawal_needs_reason",
                             "a withdrawal needs a reason: customers acted on the original.")
    store = account_trust_store(principal, register)
    received_at = server_now()
    _verify_under_pinned_key(record, store, received_at)

    feed_path = supplier_feeds_dir() / f"{principal.account.id}.jsonl"
    not_in_feed = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail={
        "error": "advisory_not_in_feed",
        "detail": f"{record.withdraws!r} is not carried by this account's hosted feed."})
    if not feed_path.exists():
        raise not_in_feed
    feed = AdvisoryFeed(feed_path)
    with feed.locked():
        history = feed.read()
        target, earlier = locate_withdrawal(history, record.withdraws)
        if target is None:
            raise not_in_feed
        if earlier is not None:
            response.status_code = status.HTTP_200_OK
            return {"state": "already_withdrawn", "advisory_id": record.withdraws,
                    "sequence": earlier.sequence, "written": False,
                    "feed_url": f"/v1/supplier/feed/{principal.account.id}"}
        if record.advisory != target.advisory:
            raise _unprocessable(
                "withdrawal_content_mismatch",
                "the withdrawal must carry the advisory it withdraws unchanged "
                "(`assurance supplier withdraw` does this).")
        _require_chain(history, record, principal.account.id, received_at)
        if feed_path.stat().st_size >= MAX_FEED_BYTES:
            raise HTTPException(
                status_code=413,
                detail={"error": "feed_full",
                        "detail": f"this feed has reached {MAX_FEED_BYTES} bytes."})
        feed.append(record)
    return {"state": "withdrawn", "advisory_id": record.withdraws,
            "sequence": record.sequence, "written": True,
            "feed_url": f"/v1/supplier/feed/{principal.account.id}"}


SELF_PIN_STATEMENT = (
    "Pinned as declared by this account. This records that the account holder says "
    "this is the key it publishes with; it is not evidence of the supplier's "
    "real-world identity. It affects only what this account's own feed verification "
    "accepts (for example a withdrawal under POST /v1/supplier/advisory/withdraw), "
    "never another account's trust, and it does not trust any other supplier's feed."
)


class SelfPinIn(BaseModel):
    """Extra fields are collected, then refused by name: a supplier id here is a 422,
    and the value of an unexpected field is never echoed (it could be a private key)."""

    model_config = ConfigDict(extra="allow")

    #: PUBLIC key, PEM. Deliberately unconstrained here so a validation error can
    #: never echo what was sent; size and shape are checked in the route.
    public_key_pem: str = ""
    #: From when the key covers records. Omitted: from the beginning (as `trust/pin`).
    effective_from: str = ""
    #: Only for a rotation (a different key is already active): when the old one retires.
    effective_at: str = ""
    actor: str = Field(default="", max_length=200)
    reason: str = Field(default="", max_length=1000)


def _own_supplier_id(account_id: str) -> str:
    """The supplier id this account publishes as: the one its hosted feed already carries.

    Taken from the feed (one feed, one supplier, see ``_require_chain``), never from
    the request. An account that has not published yet has no identity to pin to.
    """
    path = supplier_feeds_dir() / f"{account_id}.jsonl"
    history = AdvisoryFeed(path).read() if path.exists() else []
    if not history:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={
            "error": "no_supplier_identity",
            "detail": "this account has not published, so it has no supplier id yet. "
                      "Publish a first record (POST /v1/supplier/advisory), then pin "
                      "the key that signed it."})
    return history[0].supplier.supplier_id


@supplier_router.post(
    "/advisory/key",
    response_model=dict,
    status_code=status.HTTP_201_CREATED,
    summary="Pin your own publishing public key in your own account (Supplier tier; as declared by you)",
)
def post_self_pin(
    body: SelfPinIn, response: Response, principal: Annotated[Principal, Supplying],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Pin the public key this account publishes with, for the supplier id it publishes as.

    Same Supplier-tier gate as publish. It calls the same trust store as
    ``/trust/pin`` and ``/trust/rotate`` and can only name this account's own
    supplier id. It is the account holder's declaration, not proof of identity,
    and never trusts another supplier. A repeat of the active key is a 200 that
    writes nothing; a different key while one is active is a rotation and needs
    ``effective_at``; the old key is retired, never deleted. Revocation stays on
    ``/trust/revoke`` (Machine tier).
    """
    assert principal.account is not None  # Supplying guarantees this
    pem = body.public_key_pem
    extras = dict(body.model_extra or {})
    if "PRIVATE" in pem.upper() or any(
            "PRIVATE" in json.dumps(v, default=str).upper() for v in extras.values()):
        raise _unprocessable(
            "private_key_refused",
            "That looks like a private key. It was not read or kept. Only the PUBLIC "
            "key goes here; if this was a real key, treat it as exposed and replace it.")
    if extras:
        raise _unprocessable(
            "unexpected_fields",
            "unexpected field(s): " + ", ".join(sorted(map(str, extras))) + ". The supplier id "
            "is the one this account publishes as and cannot be named in the request.")
    if not pem.strip() or len(pem) > 4096:
        raise _unprocessable("invalid_public_key",
                             "public_key_pem must be one Ed25519 public key in PEM (at most 4096 characters).")
    store = account_trust_store(principal, register)
    who = _actor(body.actor, principal)
    try:
        fingerprint = VerifyingKey.from_pem(pem).fingerprint
    except (SigningKeyError, ValueError):
        raise _unprocessable("invalid_public_key",
                             "not a usable Ed25519 public key in PEM form.") from None
    supplier_id = _own_supplier_id(principal.account.id)
    try:
        start = parse_utc(body.effective_from) if body.effective_from.strip() else None
        retire_at = parse_utc(body.effective_at) if body.effective_at.strip() else None
    except ValueError as exc:
        raise _unprocessable("invalid_effective_time", str(exc)) from exc

    active = [p for p in store.pins(supplier_id) if p.status == "active"]
    same = next((p for p in active if p.fingerprint == fingerprint), None)
    if same is not None:
        response.status_code = status.HTTP_200_OK
        return {"state": "already_pinned", "written": False, "pin": same.to_dict(),
                "supplier_id": supplier_id, "statement": SELF_PIN_STATEMENT}
    via = (f"declared by account {principal.account.id} through "
           "POST /v1/supplier/advisory/key (self-pin)")
    try:
        if active:
            if retire_at is None:
                raise _unprocessable(
                    "rotation_needs_effective_at",
                    f"key {active[0].fingerprint} is already pinned for {supplier_id}; a "
                    "different key is a rotation. Send `effective_at` (when the old key "
                    "retires); it stays on record as retired.")
            pin = store.rotate(supplier_id, pem, retire_fingerprint=active[0].fingerprint,
                               effective_at=retire_at, actor=who, obtained_via=via,
                               reason=body.reason)
            state = "rotated"
        else:
            pin = store.pin(supplier_id, pem, actor=who, obtained_via=via,
                            effective_from=start, reason=body.reason)
            state = "pinned"
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
    return {"state": state, "written": True, "pin": pin.to_dict(),
            "supplier_id": supplier_id, "statement": SELF_PIN_STATEMENT}


@supplier_router.get(
    "/feed/{supplier_account_id}",
    summary="Read a hosted supplier feed (no account needed)",
)
def get_feed(supplier_account_id: str) -> Response:
    # Validate before the id is ever turned into a filename: an overlong or odd id must be
    # a 4xx, not an OSError from the filesystem (and never a path component).
    if not _ID.match(supplier_account_id) or supplier_account_id in (".", ".."):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "invalid_feed_id",
                    "detail": "No feed can exist under this id."},
        )
    feed_path = supplier_feeds_dir() / f"{supplier_account_id}.jsonl"
    try:
        text = feed_path.read_text("utf-8")
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No feed has been published under this id.",
        ) from None
    return Response(
        content=text,
        media_type="application/x-ndjson",
        headers={"X-Content-Type-Options": "nosniff"},
    )


# ---------------------------------------------------------------------------
# Trust: which supplier keys THIS account has pinned, and what a feed is under
# them. Per account, in the account's own ledger. These routes never touch the
# shared operator ledger: an operator key is refused (403), because a pin the
# operator made would be a pin on behalf of every tenant.
#
# The states are reported separately and there is no `verified` field:
#   structurally_readable | signature_state | key_trust_state | chain_valid
# and `trust_state` / `policy_satisfied` summarise them. See supplier/trust.py.
# ---------------------------------------------------------------------------
_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
MAX_FEED_TEXT = 4 * 1024 * 1024


class PinIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supplier_id: str = Field(min_length=1, max_length=200)
    public_key_pem: str = Field(min_length=1, max_length=4096)
    #: What the person was told, by a route that is not the feed. The key must match it.
    expected_fingerprint: str = Field(default="", max_length=64)
    #: Required: how the fingerprint was learned.
    obtained_via: str = Field(min_length=1, max_length=500)
    actor: str = Field(default="", max_length=200)
    reason: str = Field(default="", max_length=1000)


class RotateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supplier_id: str = Field(min_length=1, max_length=200)
    new_public_key_pem: str = Field(min_length=1, max_length=4096)
    retire_fingerprint: str = Field(min_length=1, max_length=64)
    effective_at: str = Field(min_length=1, max_length=40)
    expected_fingerprint: str = Field(default="", max_length=64)
    obtained_via: str = Field(min_length=1, max_length=500)
    actor: str = Field(default="", max_length=200)
    reason: str = Field(default="", max_length=1000)


class RevokeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    supplier_id: str = Field(min_length=1, max_length=200)
    fingerprint: str = Field(min_length=1, max_length=64)
    actor: str = Field(default="", max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class EvaluateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    #: The feed as served: one JSON record per line.
    feed: str = Field(default="", max_length=MAX_FEED_TEXT)
    #: Or the id of a feed hosted here (GET /v1/supplier/feed/{id}).
    hosted_feed_id: str = Field(default="", max_length=128)
    expect_supplier: str = Field(default="", max_length=200)
    #: A key the caller holds and has NOT pinned. It can show that signatures are
    #: valid under it; it can never make the feed trusted.
    candidate_public_key_pem: str = Field(default="", max_length=4096)


class OverrideIn(EvaluateIn):
    advisory_id: str = Field(min_length=1, max_length=200)
    actor: str = Field(default="", max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


class FeedBaselineIn(EvaluateIn):
    actor: str = Field(default="", max_length=200)
    reason: str = Field(min_length=1, max_length=1000)


def account_trust_store(principal: Principal, register: Any) -> SupplierTrustStore:
    """The trust store in this caller's OWN ledger, or a 403.

    The operator (and open mode) is served from the shared ledger; a pin made
    there would apply to every tenant, so it is refused here rather than allowed.
    """
    account = principal.account
    if account is None or account.id == "operator":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "supplier_trust_is_per_account",
                    "detail": "Supplier keys are pinned in a customer account's own "
                              "ledger. The operator's shared ledger holds no pins."})
    return SupplierTrustStore(register.ledger)


def _actor(body_actor: str, principal: Principal) -> str:
    """Who made a trust decision: an operator with the ``decider`` role, by credential.

    Pinning, rotating, revoking a supplier key and overriding an advisory are human
    decisions with automated consequences (stop-use, cases), so they are held to the
    same rule as closing a case: an account-level key, a contributor, or a name typed
    into the body is not enough. The identifier comes from the operator, never the body.
    """
    assert principal.account is not None
    if not principal.operator_id or principal.operator_role != "decider":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={
            "error": "operator_required",
            "detail": "supplier trust decisions need a key issued to an individual "
                      "operator with the 'decider' role (POST /v1/operators); an "
                      "account-level key cannot pin, rotate, revoke or override."})
    if body_actor.strip() and body_actor.strip() != principal.operator_name:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail={
            "error": "actor_mismatch",
            "detail": f"this key belongs to operator {principal.operator_name!r}."})
    return (f"{principal.operator_name} (operator {principal.operator_id}, "
            f"account {principal.account.id})")


def _trust_refusal(exc: SupplierTrustError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"error": "trust_decision_refused", "detail": str(exc)})


def load_feed_records(body: EvaluateIn) -> tuple[list[SignedAdvisory], str]:
    """Records from the body (or a hosted feed), and a parse error if any."""
    text = body.feed
    if body.hosted_feed_id:
        if not _ID.match(body.hosted_feed_id):
            raise _unprocessable("invalid_feed_id", "not a feed id.")
        path = supplier_feeds_dir() / f"{body.hosted_feed_id}.jsonl"
        if not path.exists():
            raise HTTPException(status_code=404, detail="No feed has been published "
                                                        "under this id.")
        text = path.read_text("utf-8")
    try:
        return _parse_feed_text(text, source="the submitted feed"), ""
    except (PublishError, *_PARSE_ERRORS) as exc:
        return [], str(exc) or repr(exc)


def unreadable_payload(error: str) -> dict[str, Any]:
    """The shape of a trust evaluation for a feed that does not even parse."""
    return {
        "trust_state": "untrusted_unreadable", "policy_satisfied": False,
        "inspect_only": True, "structurally_readable": False, "record_count": 0,
        "signature_state": "none", "key_trust_state": "none", "chain_valid": False,
        "chain_problems": [], "duplicate_advisories": [], "conflicting_advisories": [],
        "supplier_id": "", "key_fingerprints": [], "records": [], "advisories": [],
        "withdrawn": [], "unauthenticated_withdrawals": [], "problems": [error],
        "trust_statement": TRUST_STATEMENT,
    }


def _candidate(pem: str) -> Any:
    if not pem.strip():
        return None
    from assurance.attest.keys import SigningKeyError, VerifyingKey

    try:
        return VerifyingKey.from_pem(pem)
    except SigningKeyError as exc:
        raise _unprocessable("invalid_public_key", str(exc)) from exc


@supplier_router.get("/trust", summary="Pinned supplier keys and every trust decision (your account)")
def get_trust(
    principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = account_trust_store(principal, register)
    return {
        "pins": [p.to_dict() for p in store.pins()],
        "history": store.history(),
        "overrides": store.overrides(),
        "integrity_problems": store.integrity_problems(),
        "trust_statement": TRUST_STATEMENT,
    }


@supplier_router.post("/trust/pin", status_code=201,
                      summary="Pin a supplier's public key (fingerprint obtained outside the feed)")
def post_pin(
    body: PinIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = account_trust_store(principal, register)
    try:
        pin = store.pin(body.supplier_id, body.public_key_pem,
                        actor=_actor(body.actor, principal),
                        obtained_via=body.obtained_via,
                        expected_fingerprint=body.expected_fingerprint, reason=body.reason)
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
    return {"pin": pin.to_dict()}


@supplier_router.post("/trust/rotate", status_code=201,
                      summary="Pin a new key and retire the old one from an effective date")
def post_rotate(
    body: RotateIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = account_trust_store(principal, register)
    # Authorise before looking at the input: an account-level key is told 403 whatever it sent,
    # and learns nothing about how its body parses.
    who = _actor(body.actor, principal)
    try:
        when = parse_utc(body.effective_at)
    except ValueError as exc:
        raise _unprocessable("invalid_effective_at", str(exc)) from exc
    try:
        pin = store.rotate(body.supplier_id, body.new_public_key_pem,
                           retire_fingerprint=body.retire_fingerprint, effective_at=when,
                           actor=who,
                           obtained_via=body.obtained_via,
                           expected_fingerprint=body.expected_fingerprint,
                           reason=body.reason)
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
    return {"pin": pin.to_dict()}


@supplier_router.post("/trust/revoke", summary="Revoke a pinned key: everything it signed becomes untrusted")
def post_revoke(
    body: RevokeIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = account_trust_store(principal, register)
    try:
        pin = store.revoke(body.supplier_id, body.fingerprint,
                           actor=_actor(body.actor, principal), reason=body.reason)
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
    return {"pin": pin.to_dict()}


@supplier_router.post(
    "/trust/evaluate",
    summary="What is this feed, state by state, under your pinned keys?",
)
def post_evaluate(
    body: EvaluateIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    """Readable / signature valid / key pinned for this supplier / chain intact,
    each on its own. Always 200: an untrusted feed is a result, not an error."""
    store = account_trust_store(principal, register)
    records, error = load_feed_records(body)
    if error:
        return {"trust": unreadable_payload(error)}
    trust = evaluate_feed(records, store, expect_supplier=body.expect_supplier,
                          candidate_key=_candidate(body.candidate_public_key_pem))
    return {"trust": trust.to_dict()}


@supplier_router.post(
    "/trust/override",
    summary="Explicitly accept ONE untrusted advisory; attributed and written to the ledger",
)
def post_override(
    body: OverrideIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    store = account_trust_store(principal, register)
    records, error = load_feed_records(body)
    if error:
        raise _unprocessable("unreadable_feed", error)
    trust = evaluate_feed(records, store, expect_supplier=body.expect_supplier,
                          candidate_key=_candidate(body.candidate_public_key_pem))
    try:
        done = store.override(trust, body.advisory_id,
                              actor=_actor(body.actor, principal), reason=body.reason)
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
    return {"override": done, "note": "Bound to this advisory's content hash. It does "
            "not pin the key, and a changed advisory is not covered."}


# A supplier that legitimately re-issued its feed no longer extends the history this
# account remembered, so it stays untrusted. A decider operator can accept the feed
# in the request as the new baseline, but only if it is one that would be trusted
# (valid signatures under a pinned key, intact chain): the head is read from that
# feed, never typed, so an unsigned or foreign history cannot become the baseline.
@supplier_router.post(
    "/trust/feed-baseline",
    summary="Accept a re-issued, trusted feed as the new baseline for rollback detection",
)
def post_feed_baseline(
    body: FeedBaselineIn, principal: Annotated[Principal, Machine],
    register: Annotated[Any, Depends(get_register)] = None,
) -> dict[str, Any]:
    who = _actor(body.actor, principal)
    store = account_trust_store(principal, register)
    records, error = load_feed_records(body)
    if error:
        raise _unprocessable("unreadable_feed", error)
    try:
        return accept_feed_baseline(
            store, records, expect_supplier=body.expect_supplier,
            candidate_key=_candidate(body.candidate_public_key_pem),
            actor=who, reason=body.reason)
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
