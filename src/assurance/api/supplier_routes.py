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

It does **not** verify the signature: it holds no supplier's public key and
must not be asked to vouch for one. A reader verifies the feed against a key
whose fingerprint they obtained by a route that is not this feed
(``assurance supplier verify``). Nothing in this module meters or charges for
reading a feed.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from assurance.api.deps import Machine, Supplying, get_register, supplier_feeds_dir
from assurance.billing.accounts import Principal
from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc
from assurance.fleet.advisory import ComponentAdvisory
from assurance.supplier.publish import (
    FEED_FORMAT,
    AdvisoryFeed,
    PublishError,
    SignedAdvisory,
    _parse_feed_text,
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

    # Read, check and append are one step. Two POSTs for the same sequence must
    # not both pass the check: an append-only chain cannot be un-forked.
    with feed.locked():
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


@supplier_router.get(
    "/feed/{supplier_account_id}",
    summary="Read a hosted supplier feed (no account needed)",
)
def get_feed(supplier_account_id: str) -> Response:
    feed_path = supplier_feeds_dir() / f"{supplier_account_id}.jsonl"
    if not feed_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No feed has been published under this id.",
        )
    return Response(
        content=feed_path.read_text("utf-8"),
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
    try:
        when = parse_utc(body.effective_at)
    except ValueError as exc:
        raise _unprocessable("invalid_effective_at", str(exc)) from exc
    try:
        pin = store.rotate(body.supplier_id, body.new_public_key_pem,
                           retire_fingerprint=body.retire_fingerprint, effective_at=when,
                           actor=_actor(body.actor, principal),
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
    trust = evaluate_feed(records, store, expect_supplier=body.expect_supplier,
                          candidate_key=_candidate(body.candidate_public_key_pem))
    if not trust.policy_satisfied or not records:
        raise _trust_refusal(SupplierTrustError(
            "this feed would not be trusted (" + trust.trust_state + "), so it cannot "
            "become the baseline. Pin the supplier's key and supply a feed that verifies."))
    head = records[-1]
    try:
        store.reset_feed_head(trust.supplier_id, head.sequence, head.content_hash(),
                              actor=who, reason=body.reason)
    except SupplierTrustError as exc:
        raise _trust_refusal(exc) from exc
    return {"baseline": {"supplier_id": trust.supplier_id, "sequence": head.sequence,
                         "head_hash": head.content_hash()},
            "note": "Later passes are compared with this head. It does not make an "
                    "untrusted feed trusted, and it moves no key."}
