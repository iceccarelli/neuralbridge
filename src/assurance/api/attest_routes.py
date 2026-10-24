"""Counter-signature: a second party who cannot rewrite your ledger.

The module :mod:`assurance.attest` says the signing key must live where the
ledger's operator is not. A hosted service that held both the ledger and the
key would satisfy nothing — whoever can rewrite the records could re-sign them,
which is precisely the decoration that module refuses to be.

So the counter-signature is built for a ledger **the customer holds**, and does
the opposite of what is convenient. They compute their own head, which requires
no trust in anybody, and send three numbers: how many records, which sequence,
which link hash. The service signs *that*, records it in an append-only log
belonging to that account, and refuses the same three cases the local signer
refuses — a shorter ledger, a head that has moved backwards, a previously signed
position that now resolves differently.

What this buys for a customer-held ledger, precisely:

* The customer's own administrator cannot rewind, because the removed records
  were counted in a statement signed by a key nobody at the customer holds.
* The service cannot fabricate the customer's evidence, because the service
  never had it. All it ever saw was a hash.
* Neither party can quietly change the story, because each holds a copy of a
  log that chains to itself.

**A hosted per-account ledger is different, and weaker.** A ledger this service
holds for an account (the register, the change cases) sits beside the signing key
and the attestation log. Whoever controls that deployment could rewind the ledger
and sign the shorter head, so the ``anchor`` an export embeds from this log
protects only a customer who **keeps their own copy** of a signed attestation
(this endpoint's response, or ``GET /v1/ledger/attest/log``) and checks later
exports against it (``assurance evidence verify --public-key ... --attestations``).
An export embeds only an attestation the service *read from the ledger* it holds
(``read_from_ledger``); the ``declared_by_holder`` records this endpoint writes are
about the customer's own ledger and are never embedded in a hosted export.
Records appended after the latest attestation are covered by no signature.

**No customer route writes a ``read_from_ledger`` record.** The only producer is the
operator's ``assurance attest sign`` run against a hosted per-account ledger, so a
hosted export carries an ``anchor`` only after the operator has done that for the
account (``deploy/assurance/ATTEST.md``). Until then it carries none and says so.

One account's log may therefore hold both bases. Length, head and fork checks are
made only between records of the *same* basis (a customer-held ledger and the hosted
one are different ledgers); the hash chain and the key check span the whole file.

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
    AttestationBusyError,
    AttestationError,
    AttestationLog,
    AttestationLogDamagedError,
    HeadAttestation,
    LedgerHead,
    attest,
    verify_log,
)
from assurance.attest.keys import SigningKey, SigningKeyError, VerifyingKey
from assurance.billing.accounts import AccountStore, Principal

__all__ = [
    "EXPORT_RESPONSES",
    "MAX_DECLARED_LEDGER",
    "anchor_contradiction",
    "attest_router",
    "latest_anchor",
]

attest_router = APIRouter(prefix="/v1/ledger/attest", tags=["attestation"])

_KEY_PEM_ENV = "ASSURANCE_ATTEST_KEY_PEM"
_KEY_ENV = "ASSURANCE_ATTEST_KEY"
_LOGS_ENV = "ASSURANCE_ATTEST_LOGS"
_PASSPHRASE_ENV = "ASSURANCE_ATTEST_PASSPHRASE"

#: A caller submitting more than this many attestations to verify in one call
#: has a file, not a request. Refusing early beats timing out.
MAX_VERIFY_RECORDS = 5_000

#: The largest ledger length or head sequence a customer may declare. Ten million
#: records is two hundred times the 50,000 entries the free evidence verifier will
#: walk and far past any register this product has held; it is a sanity bound, not a
#: plan limit. An unbounded integer is a lever: one request with ``10**9`` would sit
#: in the account's append-only log for ever as the length every later head is
#: compared with.
MAX_DECLARED_LEDGER = 10_000_000

_KEY_FILE_LABEL = "the configured attestation key file"
_LOG_LABEL = "this account's attestation log"

_R401 = {"description": "No API key, or one that is not valid (`WWW-Authenticate: ApiKey`)."}
_R402 = {"description": "Authenticated, but the plan does not include this "
                        "(`plan_does_not_include_*`; the body names the plan that does)."}

#: What a hosted export can answer besides the bundle, for the OpenAPI contract.
#: 409 is a finding, not a fault: the account's anchor does not match this ledger.
EXPORT_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: _R401,
    402: _R402,
    404: {"description": "`case_not_found`: the ledger holds no entry of a case kind under "
                         "this id, so an export is never an empty bundle that reads clean."},
    409: {"description": "`anchor_contradicts_ledger`: the newest server-read signed "
                         "attestation in this account's log does not match this ledger "
                         "(shorter, or different history at a signed position). A rewind "
                         "signal; nothing is exported. `?anchor=false` exports without the "
                         "anchor but does not make the finding go away."},
    500: {"description": "`ledger_integrity` (the account's chain does not verify) or "
                         "`attestation_log_damaged` (the account's attestation log cannot be "
                         "read, so the anchor cannot be chosen; never a silently unanchored "
                         "export)."},
}


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
        return SigningKey.load(
            path, passphrase=os.environ.get(_PASSPHRASE_ENV, ""), label=_KEY_FILE_LABEL)
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": "attestation_key_unusable", "detail": str(exc)},
        ) from exc


def _log_for(principal: Principal) -> AttestationLog:
    root = Path(os.environ.get(_LOGS_ENV, "attestations"))
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in principal.subject)
    return AttestationLog(root / f"{safe}.jsonl", label=_LOG_LABEL)


def _damaged(exc: Exception) -> HTTPException:
    """A log that cannot be read is a fault to repair, not a finding about a ledger."""
    return HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail={"error": "attestation_log_damaged", "finding": str(exc)},
    )


def _busy(exc: AttestationBusyError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={"error": "attestation_busy", "detail": str(exc),
                "remedy": "Retry shortly. Nothing was signed or recorded."},
        headers={"Retry-After": str(exc.retry_after_seconds)},
    )


def latest_anchor(principal: Principal) -> dict[str, Any] | None:
    """The newest **server-read** attestation in this account's own log, or ``None``.

    What a hosted export embeds as its ``anchor``. Only ever this account's log
    (:func:`_log_for` is keyed by the principal), so one tenant's attestation can
    never ride in another's bundle. A damaged log is a 500 finding, not a silently
    unanchored export.

    Only attestations whose basis is ``read_from_ledger`` qualify: the service read
    the hosted chain and signed what it saw. A ``declared_by_holder`` record (what
    ``POST /v1/ledger/attest`` writes) is three numbers the customer typed about a
    ledger *they* hold; it says nothing about the hosted one, and embedding it would
    make every case export fail with ``anchor_contradicts_ledger`` for good (the log
    is append-only). So those are never embedded, whatever their sequence.

    The choice is :func:`assurance.attest.select_anchor`, the same rule the CLI exports
    use; this function adds only the account's log and the HTTP error. The read takes
    no lock, so an export never waits for a signer; an unterminated final line (a
    write in flight or a crash) is ignored, anything else damaged is a 500.
    """
    try:
        record = _log_for(principal).anchor()
    except AttestationError as exc:
        raise _damaged(exc) from exc
    return record.to_dict() if record is not None else None


def anchor_contradiction(exc: Exception) -> HTTPException:
    """The 409 for an export whose account anchor does not match the ledger.

    A finding, not a fault. The anchor is only ever an attestation the service read
    from this very ledger (``read_from_ledger``), so a mismatch means the ledger is
    now shorter than, or differs from, what was signed: a real rewind signal.
    """
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "anchor_contradicts_ledger",
            "finding": str(exc),
            "remedy": "Preserve the ledger and the attestation log as they are: the "
                      "service signed what this ledger held, and it no longer matches. "
                      "?anchor=false exports without the anchor, but that does not "
                      "make the finding go away.",
        },
    )


class AttestIn(BaseModel):
    """Three numbers the customer reads out of their own ledger.

    Nothing else is accepted, and nothing else is wanted. The point of this
    endpoint is that the records stay where they are.
    """

    model_config = ConfigDict(extra="forbid")

    ledger_length: int = Field(
        ge=0, le=MAX_DECLARED_LEDGER, description="how many records the chain holds")
    head_seq: int = Field(
        ge=0, le=MAX_DECLARED_LEDGER, description="sequence number of the last record")
    head_link_hash: str = Field(
        min_length=64, max_length=64,
        description="link hash of the last record, hex SHA-256")
    note: str = Field(
        default="", max_length=500,
        description="free text, signed along with the head. It is YOUR text: verification "
                    "reports it as `note_is_tenant_supplied`, not as a statement by the "
                    "key holder about your ledger.")
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
    summary="The public key this service counter-signs with. No account needed.",
    responses={503: {"description": "`no_attestation_key_configured` or "
                                    "`attestation_key_unusable`: the service has no usable "
                                    "signing key. The message never names a server path."}},
)
def service_key() -> dict[str, Any]:
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
    responses={
        401: _R401,
        402: _R402,
        409: {"description": "`attestation_refused`: a finding, not a malformed request. "
                             "The head is shorter than, behind, or a different history "
                             "from one already signed *for the same kind of head* (your "
                             "own declared heads), or a different key is signing without "
                             "`rotating`. The `finding` is the sentence to show whoever "
                             "runs the database."},
        422: {"description": "Not a ledger head (`not_a_ledger_head`), or a length or "
                             "sequence beyond the declared-head bound."},
        500: {"description": "`attestation_log_damaged`: this account's attestation log "
                             "cannot be read or ends in an unfinished write. A fault to "
                             "repair, not a finding about your ledger; nothing was signed."},
        503: {"description": "`attestation_busy` (retry after `Retry-After`; the log's lock "
                             "was not free in time, nothing was signed) or a missing or "
                             "unusable service key."},
    },
)
def counter_sign(
    body: AttestIn,
    principal: Annotated[Principal, Attesting],
    accounts: Annotated[AccountStore, Depends(get_accounts)],
) -> dict[str, Any]:
    """Sign three numbers, refuse the three cases that would be a lie.

    The refusals return 409, not 422: a shorter ledger is not a malformed
    request, it is the finding. The body of the refusal is the sentence to put
    in front of whoever runs the database.

    Heads you declare are compared only with heads you declared earlier: they
    describe your ledger, not any ledger this service holds. ``note`` is signed
    but is your text; the response and every later verification say so.

    This is a plain ``def`` so FastAPI runs it in its thread pool: waiting for the
    log's lock (bounded, then 503) must never hold up the event loop.
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
    key = _service_key()
    try:
        record = attest(head, key, log, note=body.note, rotating=body.rotating)
    except AttestationBusyError as exc:
        raise _busy(exc) from exc
    except AttestationLogDamagedError as exc:
        raise _damaged(exc) from exc
    except AttestationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "attestation_refused", "finding": str(exc)},
        ) from exc

    checks_skipped = [
        "This service did not see your ledger and did not verify your chain. "
        "It signed the values you supplied, at the time you supplied them. "
        "Run `assurance attest verify --ledger` locally to join the two.",
        "Records you appended after this call are covered by no signature.",
    ]
    if record.note_is_tenant_supplied:
        checks_skipped.append(
            "The note is the requester's free text: it is signed because the signature "
            "covers every field, and it is not a statement by the key holder about "
            "your ledger."
        )
    return {
        "attestation": record.to_dict(),
        "count": len(log),
        "note_is_tenant_supplied": record.note_is_tenant_supplied,
        "checks_skipped": checks_skipped,
        "keep": (
            "Store this attestation somewhere your ledger's administrator cannot "
            "reach. It is the only artefact in this system that a rewind cannot "
            "touch."
        ),
    }


@attest_router.get(
    "/log",
    summary="Every attestation this service has made for your account",
    responses={
        401: _R401,
        402: _R402,
        500: {"description": "`attestation_log_damaged`: a line other than the last cannot "
                             "be read. The message never names a server path."},
    },
)
def account_log(
    principal: Annotated[Principal, Attesting],
) -> dict[str, Any]:
    """The account's attestation log. Reads without the writer's lock, so it never
    waits; an unfinished last line is reported in ``warnings`` and left out."""
    log = _log_for(principal)
    try:
        records, torn = log.scan()
    except AttestationError as exc:
        raise _damaged(exc) from exc
    warnings = []
    if torn:
        warnings.append(
            "The log ends in an unterminated line (a write that did not finish, or one "
            "in flight). It was ignored. Until the operator repairs the file, new "
            "attestations are refused (500 attestation_log_damaged).")
    return {
        "count": len(records),
        "attestations": [r.to_dict() for r in records],
        "warnings": warnings,
        "verify_with": "POST /v1/ledger/attest/verify — free, no key needed",
    }


@attest_router.post(
    "/verify",
    summary="Check an attestation log. Free and unmetered, for anyone.",
    responses={
        413: {"description": "`too_many_attestations`: verify larger logs locally."},
        422: {"description": "`unreadable_attestation` or `unreadable_public_key`."},
        503: {"description": "No public key was supplied and the service has no usable key."},
    },
)
def verify(
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

    ``notes`` lists every note with ``note_is_tenant_supplied``: on a counter-signature
    the note is the requester's free text, covered by the signature but not a statement
    by the key holder about the ledger.
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
        "notes": verdict.notes,
        "latest": verdict.latest.to_dict() if verdict.latest else None,
    }
