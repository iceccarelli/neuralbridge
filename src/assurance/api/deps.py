"""Dependencies: the register, the account store, and who is calling.

Three things are settled here.

**Authentication is not optional.** An Article 14 register holds the record
that decides whether a manufacturer filed on time. An unauthenticated one is
worse than none, because it produces confident artifacts anyone could have
written.

**Entitlement is read on every request.** A tier that is stored and never
consulted is a pricing page that lies. :func:`require_register` is the only
door into the register, and it asks the plan every time.

**Quota is spent in the same transaction that authorises the call.** Counting
elsewhere and reconciling later is how a metered product leaks.

Configuration, all by environment variable:

``ASSURANCE_LEDGER``    evidence ledger path (default ``art14-register.db``). This is
                        the OPERATOR ledger; see "Tenancy" below.
``ASSURANCE_TENANT_LEDGERS``  directory holding one ledger file per customer
                        account (default: ``tenants/`` beside the operator ledger,
                        so ``/data/tenants`` on the Fly volume)
``ASSURANCE_ACCOUNTS``  account and key store path (default ``accounts.db``)
``ASSURANCE_API_KEYS``  comma-separated operator keys; full access, no quota
``ASSURANCE_ALLOW_UNAUTHENTICATED``  ``1`` to run open for local evaluation
``ASSURANCE_PUBLIC_URL`` base URL used in checkout redirects
``ASSURANCE_ATTEST_KEY_PEM``  the Ed25519 key the service counter-signs with
``ASSURANCE_ATTEST_KEY``   a path to that key instead
``ASSURANCE_ATTEST_PASSPHRASE``  passphrase for it, if encrypted
``ASSURANCE_ATTEST_LOGS``  directory holding one attestation log per account
``ASSURANCE_TRUST_FLY_PROXY``  ``1`` to key the free-tier quota on the
                        ``Fly-Client-IP`` header instead of the socket peer
                        (set it ONLY when every request arrives through Fly's
                        proxy, which overwrites that header)
``ASSURANCE_MAX_BODY_BYTES``  request body cap for ``/v1`` POSTs (default 1 MiB)
``ASSURANCE_MAX_TRACE_BODY_BYTES``  the cap for ``POST /v1/machine/verify``,
                        whose recorded traces are legitimately large
                        (default 32 MiB)
``STRIPE_SECRET_KEY`` / ``STRIPE_WEBHOOK_SECRET`` / ``ASSURANCE_PRICE_*``

**Tenancy.** Every ``/v1`` route reaches the ledger through
:func:`get_register`, so tenant isolation is decided in exactly one place. A
customer account gets its own SQLite ledger file under
:func:`tenant_ledgers_dir`; the operator (``ASSURANCE_API_KEYS``, or open
mode) keeps the shared ledger at :func:`ledger_path`; an anonymous caller gets
no ledger at all. Isolation is by file, not by a column, so there is no query
that can forget a ``WHERE account_id = ?``.
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import uuid
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, Request, Response, status

from ..billing.accounts import (
    Account,
    AccountStore,
    IdempotencyConflictError,
    Principal,
    QuotaExceededError,
    SpendLimitError,
)
from ..billing.metering import allowance_for, payg_available, valid_idempotency_key
from ..billing.plans import METERED_SCOPES
from ..core.identity import format_utc, utc_now
from ..evidence.ledger import EvidenceLedger
from ..security.art14.engine import Art14Register

__all__ = [
    "get_register",
    "shared_register",
    "tenant_ledger_path",
    "tenant_ledgers_dir",
    "BodySizeLimitMiddleware",
    "max_body_bytes",
    "get_accounts",
    "current_principal",
    "ENTITLEMENT_GATES",
    "EvidenceReadout",
    "MeterTicket",
    "Metered",
    "quota_refusal",
    "require_attestation",
    "require_evidence_readout",
    "require_machine",
    "require_register",
    "require_supplier",
    "seconds_until_reset",
    "spend",
    "auth_mode",
    "ledger_path",
    "accounts_path",
    "public_url",
    "marketing_url",
    "allowed_origins",
    "supplier_feeds_dir",
]

_LEDGER_ENV = "ASSURANCE_LEDGER"
_ACCOUNTS_ENV = "ASSURANCE_ACCOUNTS"
_KEYS_ENV = "ASSURANCE_API_KEYS"
_OPEN_ENV = "ASSURANCE_ALLOW_UNAUTHENTICATED"
_FLY_ENV = "ASSURANCE_TRUST_FLY_PROXY"


def ledger_path() -> str:
    return os.environ.get(_LEDGER_ENV, "art14-register.db")


def accounts_path() -> str:
    return os.environ.get(_ACCOUNTS_ENV, "accounts.db")


def supplier_feeds_dir() -> Path:
    """Where hosted supplier feeds live: one append-only JSONL file per account.

    Keyed by account id, not the supplier_id inside the advisory body — the
    account id is already a safe, server-issued token, so this sidesteps
    trusting a customer-chosen string as a filename.
    """
    return Path(os.environ.get("ASSURANCE_SUPPLIER_FEEDS", "supplier-feeds"))


def public_url() -> str:
    return os.environ.get("ASSURANCE_PUBLIC_URL", "http://127.0.0.1:8000").rstrip("/")


def marketing_url() -> str:
    """Where a paying customer's browser should land after Stripe checkout.

    Defaults to the real marketing site rather than this API's own host: a
    customer who just paid should see a page that explains what happened, not
    raw JSON. Falls back to this API's own /v1/checkout/complete (still
    functional, just unstyled) only if explicitly pointed there.
    """
    return os.environ.get("ASSURANCE_MARKETING_URL", "https://neuralbridge.io").rstrip("/")


_ORIGINS_ENV = "ASSURANCE_ALLOWED_ORIGINS"
# The marketing site's own known origins, plus local dev. A browser enforces
# CORS on the *caller's* side — curl and server-to-server calls never see
# this — so its absence is invisible to every test that does not run in an
# actual browser, which is exactly how it went unnoticed until now.
_DEFAULT_ORIGINS: tuple[str, ...] = (
    "https://neuralbridge.io",
    "https://www.neuralbridge.io",
    "http://localhost:3000",
)


def allowed_origins() -> tuple[str, ...]:
    raw = os.environ.get(_ORIGINS_ENV, "")
    if raw:
        return tuple(o.strip() for o in raw.split(",") if o.strip())
    return _DEFAULT_ORIGINS


def _operator_keys() -> tuple[str, ...]:
    raw = os.environ.get(_KEYS_ENV, "")
    return tuple(k.strip() for k in raw.split(",") if k.strip())


def auth_mode() -> str:
    """``api_key``, ``open`` or ``unconfigured``."""
    if _operator_keys():
        return "api_key"
    if os.environ.get(_OPEN_ENV) == "1":
        return "open"
    return "unconfigured"


@lru_cache(maxsize=8)
def _register_for(path: str) -> Art14Register:
    return Art14Register(EvidenceLedger(path))


_TENANT_ENV = "ASSURANCE_TENANT_LEDGERS"
# Account ids are minted by the server (``acc_`` + 16 hex digits), never taken
# from a request. The shape is still checked before it becomes part of a file
# name, so a corrupted or hostile value cannot become a path.
_ACCOUNT_ID_RE = re.compile(r"acc_[0-9a-f]{16}")


def tenant_ledgers_dir() -> Path:
    """Where each customer account's ledger lives.

    Defaults to ``tenants/`` beside the operator ledger, which on the Fly
    deployment (``ASSURANCE_LEDGER=/data/art14-register.db``) is the persistent
    volume.
    """
    raw = os.environ.get(_TENANT_ENV, "")
    if raw:
        return Path(raw)
    return Path(ledger_path()).parent / "tenants"


def tenant_ledger_path(account_id: str) -> Path:
    """The ledger file for one account. ``ValueError`` for anything not an account id."""
    if not isinstance(account_id, str) or not _ACCOUNT_ID_RE.fullmatch(account_id):
        raise ValueError("not a valid account id")
    base = tenant_ledgers_dir()
    path = base / f"{account_id}.db"
    # Belt and braces: the pattern already excludes every path separator.
    if path.resolve().parent != base.resolve():
        raise ValueError("not a valid account id")
    return path


# A ledger object holds no open connection (each operation connects and
# closes), so a cache entry costs a path and a lock. The bound exists only to
# stop an unbounded number of accounts pinning memory; it is generous so that
# a busy deployment does not thrash, which would also replace the per-ledger
# write lock while a request is using it.
@lru_cache(maxsize=512)
def _tenant_register_for(path: str) -> Art14Register:
    return Art14Register(EvidenceLedger(path))


def shared_register() -> Art14Register:
    """The operator's ledger. Only the operator and in-process code get this."""
    return _register_for(ledger_path())


class _NoRegister:
    """What an anonymous caller is handed instead of a ledger.

    A route that accepts anonymous callers and also asks for the register may
    only touch it for a caller who has an account. Anonymous callers share one
    address-keyed quota bucket and have no tenant; letting them near the
    operator's ledger would be a shared write path for the whole internet.
    Touching this raises a 401 rather than quietly using some other ledger.
    """

    def __getattr__(self, name: str) -> Any:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )


_NO_REGISTER = _NoRegister()


@lru_cache(maxsize=8)
def _accounts_for(path: str) -> AccountStore:
    return AccountStore(path)


def get_accounts() -> AccountStore:
    return _accounts_for(accounts_path())


_OPERATOR = Account(
    id="operator",
    email="",
    company="operator",
    tier="cell",
    status="active",
)


def _client_address(request: Request, fly_client_ip: str | None) -> str:
    """The address the free-tier quota is keyed on.

    Behind Fly's proxy every socket peer is the proxy, so every anonymous
    caller would share one bucket. ``Fly-Client-IP`` is set (overwritten) by
    that proxy, but it is an ordinary header to anyone who can reach the
    process directly, so it is honoured only when the operator says every
    request arrives through the proxy.
    """
    if os.environ.get(_FLY_ENV) == "1" and fly_client_ip:
        candidate = fly_client_ip.strip()
        if 0 < len(candidate) <= 64 and re.fullmatch(r"[0-9A-Fa-f:.]+", candidate):
            return _bucket(candidate)
    return _bucket(request.client.host) if request.client else "unknown"


def _bucket(address: str) -> str:
    """One quota bucket per caller: an IPv6 /64, an IPv4 address.

    A single IPv6 subscriber is routinely handed a whole /64, so keying on the
    full address would give one person 2**64 daily allowances.
    """
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            # ::ffff:a.b.c.d is an IPv4 client seen through a dual-stack socket;
            # as an IPv6 /64 they would all share the single bucket "::/64".
            return str(ip.ipv4_mapped)
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


async def current_principal(
    request: Request,
    x_api_key: str | None = Header(default=None),
    fly_client_ip: str | None = Header(default=None),
    accounts: AccountStore = Depends(get_accounts),
) -> Principal:
    """Resolve the caller. Never raises for an absent key.

    No key means the free, address-limited path — which is the point: the
    validator has to be usable by a prospect who has not signed up for
    anything. A key that is presented and wrong is a 401, because that is a
    mistake the caller needs told about.
    """
    presented = (x_api_key or "").strip()
    if not presented:
        client = _client_address(request, fly_client_ip)
        return Principal(account=None, key_prefix="", anonymous_subject=f"ip:{client}")

    for key in _operator_keys():
        # Compare bytes: str comparison raises TypeError on non-ASCII input, and
        # an unhandled 500 from a header anyone can send is not a failure mode.
        if hmac.compare_digest(presented.encode(), key.encode()):
            return Principal(account=_OPERATOR, key_prefix="operator")

    principal = accounts.resolve_key(presented)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return principal


def get_register(
    principal: Annotated[Principal | None, Depends(current_principal)] = None,
) -> Art14Register:
    """The ledger this caller may touch. The single choke point for tenancy.

    * A customer account: its own ledger file.
    * The operator (an ``ASSURANCE_API_KEYS`` key, or open mode): the shared
      ledger.
    * Anonymous, outside open mode: nothing (see :class:`_NoRegister`).
    * ``None``: only in-process callers that invoke this function directly
      with no request (tests, tooling); it is never what FastAPI passes.
    """
    if principal is None:
        return shared_register()
    account = principal.account
    if account is None:
        if auth_mode() == "open":
            # require_* maps an anonymous caller to the operator in open mode;
            # this must agree with it or open mode would split across ledgers.
            return shared_register()
        return _NO_REGISTER  # type: ignore[return-value]
    if account.id == _OPERATOR.id:
        return shared_register()
    try:
        path = tenant_ledger_path(account.id)
    except ValueError as exc:
        # Account ids are server-issued, so this is a corrupted store, not a
        # client mistake. Refuse rather than fall back to a shared ledger.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "invalid_account_id"},
        ) from exc
    return _tenant_register_for(str(path))


def seconds_until_reset() -> tuple[int, str]:
    """Seconds until the UTC day rolls over, and that instant as an ISO time.

    The daily allowance resets at UTC midnight for everyone (see
    ``AccountStore.consume``), so a refused caller can be told exactly when to
    come back instead of guessing.
    """
    now = utc_now()
    midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return max(1, int((midnight - now).total_seconds())), format_utc(midnight)


def quota_refusal(
    *, error: str, scope: str, limit: int, used: int, tier: str, remedy: str,
    extra: dict[str, Any] | None = None,
) -> HTTPException:
    """A 429 that says what ran out, when it opens again and what to do about it."""
    retry, resets_at = seconds_until_reset()
    detail: dict[str, Any] = {
        "error": error, "scope": scope, "limit": limit, "used": used, "tier": tier,
        "remedy": remedy, "resets_at": resets_at, "retry_after_seconds": retry,
    }
    detail.update(extra or {})
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail,
        headers={"Retry-After": str(retry)},
    )


def _quota_remedy(limit: int) -> str:
    text = (
        f"The free allowance is {limit} calls per day, per caller. A paid plan removes "
        "the cap: see GET /v1/plans, then POST /v1/checkout."
    )
    if payg_available():
        text += (
            " Pay-as-you-go (GET /v1/plans, tier payg) bills operations beyond the "
            "allowance, up to a spend limit you set."
        )
    return text


def spend(principal: Principal, scope: str, limit: int | None, accounts: AccountStore) -> None:
    """Consume one unit of allowance, or refuse with a 429 that says what to do.

    For ``/ai`` reads, which are a daily guard and never billed: the unit is
    taken before the read, so a read that then fails still counts. The billable
    scopes use :func:`Metered`/``MeterTicket.commit``, which count only work
    that succeeded.
    """
    try:
        accounts.consume(principal.subject, scope, limit, principal.tier)
    except QuotaExceededError as exc:
        raise quota_refusal(
            error="quota_exceeded", scope=exc.scope, limit=exc.limit, used=exc.used,
            tier=exc.tier, remedy=_quota_remedy(exc.limit),
        ) from exc


# ---------------------------------------------------------------------------
# metered work: counted once, after it succeeded
# ---------------------------------------------------------------------------
def _metering_refusal(exc: Exception, principal: Principal) -> HTTPException:
    """Map a store refusal onto the HTTP answer. Nothing was recorded."""
    if isinstance(exc, SpendLimitError):
        account = principal.account
        zero = exc.limit_units == 0
        return quota_refusal(
            error="spend_limit_reached", scope=exc.scope, limit=exc.limit_units,
            used=exc.used_units, tier=principal.tier,
            remedy=(
                "Pay-as-you-go is on for your account, but your monthly spend limit is 0, "
                "so nothing past the free daily allowance is billed. "
                if zero else
                f"Your monthly spend limit of {exc.limit_units} billable units is reached "
                f"({exc.used_units} used this UTC month), so this call was not run for "
                "billing. "
            ) + (
                'Set a limit with POST /v1/usage/limits {"spend_limit_units": N}; see '
                "GET /v1/usage. The free daily allowance renews at resets_at."
            ),
            extra={"spend_limit_units": exc.limit_units, "billable_units": exc.used_units,
                   "account_id": account.id if account else ""},
        )
    if isinstance(exc, QuotaExceededError):
        return quota_refusal(
            error="quota_exceeded", scope=exc.scope, limit=exc.limit, used=exc.used,
            tier=exc.tier, remedy=_quota_remedy(exc.limit),
        )
    assert isinstance(exc, IdempotencyConflictError)
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={
            "error": "idempotency_key_reused",
            "detail": str(exc),
            "remedy": "Use a new Idempotency-Key for different work; reuse one only to "
                      "retry the identical call.",
        },
    )


@dataclass
class MeterTicket:
    """A promise to count one unit of ``scope`` if, and only if, the work succeeds.

    ``begin`` (the :func:`Metered` dependency) refuses an obviously over-limit
    caller before any work is done. The route then computes its whole answer.
    :meth:`commit`, called immediately before the route returns, counts the
    unit in the same transaction as the authoritative quota check. A route that
    raises (a 422 from the domain, a bug) never reaches ``commit``, so a failed
    operation records and costs nothing. See ``billing/metering.py``.
    """

    principal: Principal
    scope: str
    accounts: AccountStore
    key: str
    #: True when the client supplied the key (so a retry can be deduplicated).
    client_key: bool

    @property
    def limit(self) -> int | None:
        return allowance_for(self.principal.plan, self.scope)

    def _account(self) -> Account | None:
        account = self.principal.account
        return account if account is not None and account.id != _OPERATOR.id else None

    def precheck(self) -> None:
        limit = self.limit
        if limit is None:
            return
        try:
            account = self._account()
            if account is not None:
                self.accounts.check_usage(
                    account.id, self.scope, 1, self.key if self.client_key else None)
            else:
                self.accounts.check_quota(
                    self.principal.subject, self.scope, limit, self.principal.tier)
        except (QuotaExceededError, SpendLimitError) as exc:
            raise _metering_refusal(exc, self.principal) from exc

    def commit(self, response: Response | None = None) -> None:
        """Count the unit. Raises the 429/409 if the authoritative check refuses."""
        limit = self.limit
        event_id = ""
        billable = 0
        try:
            account = self._account()
            if limit is None:
                pass
            elif account is not None:
                record = self.accounts.record_usage(account.id, self.scope, 1, self.key)
                event_id, billable = record.event_id, record.billable_quantity
            else:
                self.accounts.consume(
                    self.principal.subject, self.scope, limit, self.principal.tier)
        except (QuotaExceededError, SpendLimitError, IdempotencyConflictError) as exc:
            raise _metering_refusal(exc, self.principal) from exc
        if response is None:
            return
        response.headers["X-Assurance-Tier"] = self.principal.tier
        if limit is not None:
            used = self.accounts.usage_today(self.principal.subject).get(self.scope, 0)
            response.headers["X-Assurance-Quota-Limit"] = str(limit)
            response.headers["X-Assurance-Quota-Remaining"] = str(max(0, limit - used))
        if event_id:
            response.headers["X-Assurance-Usage-Event"] = event_id
        if billable:
            response.headers["X-Assurance-Billable-Units"] = str(billable)


def Metered(scope: str) -> Any:  # noqa: N802 - used like ``Depends``/``Anyone``
    """Dependency for a route that does metered work: ``Annotated[MeterTicket, Metered("x")]``.

    Resolves the caller, validates the optional ``Idempotency-Key`` header
    (a malformed one is a 400 that costs nothing), refuses a caller who is
    certainly over their limit, and hands the route a :class:`MeterTicket`.
    The route must call ``ticket.commit(response)`` once its answer is complete.
    """
    if scope not in METERED_SCOPES:
        raise ValueError(f"{scope!r} is not a metered scope")

    async def dependency(
        principal: Annotated[Principal, Depends(current_principal)],
        accounts: Annotated[AccountStore, Depends(get_accounts)],
        idempotency_key: Annotated[str | None, Header()] = None,
    ) -> MeterTicket:
        if idempotency_key is not None and not valid_idempotency_key(idempotency_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "invalid_idempotency_key",
                    "detail": "Idempotency-Key must be 1-255 characters of "
                              "A-Z a-z 0-9 . _ : - (a UUID is ideal).",
                },
            )
        ticket = MeterTicket(
            principal=principal, scope=scope, accounts=accounts,
            key=idempotency_key if idempotency_key is not None else f"auto:{uuid.uuid4().hex}",
            client_key=idempotency_key is not None,
        )
        ticket.precheck()
        return ticket

    return Depends(dependency)


_LAPSED_NOTE = (
    " Your subscription has ended: new records and operational views are closed, "
    "but your evidence is still yours - read, verify and export it with "
    "GET /v1/cases, GET /v1/cases/{case_id}/export and GET /v1/ledger/verify."
)


def _payment_required(principal: Principal, error: str, remedy: str) -> HTTPException:
    """The 402 for an authenticated caller whose plan lacks an entitlement.

    A customer whose subscription ended is told what they can still do, so the
    refusal never reads as "your records are gone".
    """
    account = principal.account
    assert account is not None
    note = _LAPSED_NOTE if account.ever_paid else ""
    return HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail={
            "error": error,
            "tier": principal.tier,
            "account_status": account.status,
            "remedy": remedy + note,
        },
    )


async def require_register(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The only door into the register.

    Returns 402 rather than 403 when the caller is authenticated but not
    entitled: the obstacle is payment, and the status code should say so.
    """
    mode = auth_mode()
    if mode == "unconfigured" and principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"No operator keys configured and no account presented. Set {_KEYS_ENV}, "
                f"or sell a plan, or set {_OPEN_ENV}=1 for local evaluation. This service "
                "refuses unauthenticated writes to a regulatory register by default."
            ),
        )
    if mode == "open" and principal.account is None:
        return Principal(account=_OPERATOR, key_prefix="open-mode")

    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not principal.plan.register:
        raise _payment_required(
            principal, "plan_does_not_include_register",
            "The register is included from the Register plan upward. "
            "GET /v1/plans, then POST /v1/checkout.",
        )
    return principal


async def require_evidence_readout(
    response: Response,
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The door for reading, verifying and exporting your own evidence.

    Open to everyone :func:`require_register` admits, **and** to a customer whose
    subscription has ended: records a manufacturer produced while paying are
    theirs, and a payment lapse must not stand between them and an auditor.
    A lapsed customer gets exactly the routes in
    ``plans.EVIDENCE_READOUT_AFTER_LAPSE``, from their own ledger only
    (:func:`get_register` still decides which file), and the response says so
    in ``X-Assurance-Access``. Anyone who never paid still gets the 402.
    """
    try:
        return await require_register(principal)
    except HTTPException as exc:
        account = principal.account
        if exc.status_code != status.HTTP_402_PAYMENT_REQUIRED or account is None \
                or not account.ever_paid:
            raise
        response.headers["X-Assurance-Access"] = "evidence-readout-only"
        return principal


async def require_machine(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The door into machine safety verification.

    Same 402-not-403 rule as the register: an authenticated caller without the
    entitlement is looking at a price, not a prohibition.
    """
    if auth_mode() == "open" and principal.account is None:
        return Principal(account=_OPERATOR, key_prefix="open-mode")
    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not principal.plan.machine_verification:
        raise _payment_required(
            principal, "plan_does_not_include_machine_verification",
            "Machine safety verification is included from the Cell plan "
            "upward. The separation calculator "
            "(POST /v1/machine/separation) and the bundle re-checker "
            "(POST /v1/machine/bundle/check) stay free. "
            "GET /v1/plans, then POST /v1/checkout.",
        )
    return principal


async def require_attestation(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The door to the counter-signature.

    This gate exists because the Cell plan already said "signed head
    attestation for the evidence ledger" while nothing in the codebase signed
    anything. An entitlement that is advertised and not enforced is the same
    defect as a compliance field that is fabricated: the pricing page makes a
    claim the software does not back.
    """
    if auth_mode() == "open" and principal.account is None:
        return Principal(account=_OPERATOR, key_prefix="open-mode")
    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not principal.plan.signed_attestation:
        raise _payment_required(
            principal, "plan_does_not_include_signed_attestation",
            "Counter-signed head attestation is included from the Cell "
            "plan upward. Verifying an attestation "
            "(POST /v1/ledger/attest/verify) and fetching the public key "
            "(GET /v1/ledger/attest/key) are free and always will be: an "
            "attestation only a paying customer can check is worth "
            "nothing. GET /v1/plans, then POST /v1/checkout.",
        )
    return principal


async def require_supplier(
    principal: Principal = Depends(current_principal),
) -> Principal:
    """The door to publishing a signed advisory.

    The second payer HANDOFF.md's P1 names: a component supplier, not a
    manufacturer. There is no self-serve Stripe price for this tier yet — see
    ADR-0001 — so today the only way in is a sales-assigned account tier.
    Reading a feed (GET /v1/supplier/feed/{id}) is deliberately outside this
    gate and needs no account, same reasoning as every other free-forever
    verification route: the audience for a supplier's advisory is every
    integrator who might be affected, not a paying subscriber.
    """
    if auth_mode() == "open" and principal.account is None:
        return Principal(
            account=Account(id="operator", email="", company="operator",
                             tier="supplier", status="active"),
            key_prefix="open-mode",
        )
    if principal.account is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This endpoint needs an API key. See GET /v1/plans.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    if not principal.plan.supplier_publish:
        raise _payment_required(
            principal, "plan_does_not_include_supplier_publish",
            "Publishing a signed advisory needs the Supplier tier, "
            "which is sales-assigned today (no self-serve price yet). "
            "Reading any supplier's feed stays free at "
            "GET /v1/supplier/feed/{supplier_id}. Contact sales.",
        )
    return principal


Registered = Depends(require_register)
Machine = Depends(require_machine)
Attesting = Depends(require_attestation)
Supplying = Depends(require_supplier)
Anyone = Depends(current_principal)
EvidenceReadout = Depends(require_evidence_readout)

#: Every entitlement gate, and what it consults. ``tests/test_assurance_entitlements.py``
#: reads the live app and fails if a ``/v1`` route that touches tenant data
#: carries none of these, or if a gating Plan flag (``plans.GATE_FLAGS``) is
#: carried by no route.
ENTITLEMENT_GATES: dict[Callable[..., Any], str] = {
    require_register: "register",
    require_machine: "machine_verification",
    require_attestation: "signed_attestation",
    require_supplier: "supplier_publish",
    require_evidence_readout: "evidence_readout",
}


# ---------------------------------------------------------------------------
# request body cap
# ---------------------------------------------------------------------------
_BODY_ENV = "ASSURANCE_MAX_BODY_BYTES"
_TRACE_BODY_ENV = "ASSURANCE_MAX_TRACE_BODY_BYTES"
_DEFAULT_BODY = 1024 * 1024
_DEFAULT_TRACE_BODY = 32 * 1024 * 1024
_TRACE_PATHS = frozenset({"/v1/machine/verify"})
# Stripe events are a few KB. The webhook is read in full before its signature
# is checked, so it gets a fixed small cap of its own: not the configurable one
# (a mis-set value must never be why a payment event is lost) and not none (an
# unsigned 256 MiB POST would otherwise be buffered before being refused).
_WEBHOOK_PATH = "/v1/billing/webhook"
_WEBHOOK_BODY = 1024 * 1024
_WRITE_METHODS = frozenset({"POST", "PUT", "PATCH"})


def _env_bytes(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, ""))
    except ValueError:
        return default
    return value if value > 0 else default


def max_body_bytes(path: str, *, authenticated: bool = False) -> int | None:
    """The largest request body accepted at ``path``; ``None`` = not capped here.

    The large allowance for recorded traces is only for a caller whose key
    resolves: the body is parsed before the route's own auth runs, so granting
    32 MiB to anyone would let an anonymous POST make the server hold it.
    """
    if not path.startswith("/v1/"):
        return None
    if path == _WEBHOOK_PATH:
        return _WEBHOOK_BODY
    if path in _TRACE_PATHS and authenticated:
        return _env_bytes(_TRACE_BODY_ENV, _DEFAULT_TRACE_BODY)
    return _env_bytes(_BODY_ENV, _DEFAULT_BODY)


def _key_resolves(presented: str) -> bool:
    """Whether ``presented`` may send a large recorded trace. Never raises.

    True for an operator key, or a live account key whose plan includes machine
    verification (the only route with the large allowance). Read-only: this runs
    before authentication, so it must not take the write lock.
    """
    if not presented:
        return False
    try:
        raw = presented.encode()
        if any(hmac.compare_digest(raw, k.encode()) for k in _operator_keys()):
            return True
        principal = get_accounts().peek_key(presented)
        return principal is not None and principal.plan.machine_verification
    except Exception:  # noqa: BLE001 - an unresolvable key just gets the small cap
        return False


async def _send_413(
    send: Callable[[MutableMapping[str, Any]], Awaitable[None]], detail: dict[str, Any]
) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({
        "type": "http.response.start",
        "status": 413,
        "headers": [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ],
    })
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """Refuse an oversized ``/v1`` request body with a 413.

    Checks ``Content-Length`` up front, and counts bytes as they arrive for a
    chunked body that declares nothing, so neither a lying nor a silent client
    makes the server buffer an arbitrary amount of JSON.
    """

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http" or scope.get("method") not in _WRITE_METHODS:
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers") or [])
        limit = max_body_bytes(
            scope.get("path", ""),
            authenticated=_key_resolves(headers.get(b"x-api-key", b"").decode("latin-1").strip()),
        )
        if limit is None:
            await self.app(scope, receive, send)
            return

        detail = {
            "error": "request_too_large",
            "limit_bytes": limit,
            "detail": f"Request bodies on this endpoint are limited to {limit} bytes.",
        }
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                too_big = False
            if too_big:
                await _send_413(send, detail)
                return

        seen = 0

        async def limited_receive() -> MutableMapping[str, Any]:
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # An HTTPException raised from the body read is turned into
                    # a response by the application's own exception handling.
                    raise HTTPException(status_code=413, detail=detail)
            return message

        await self.app(scope, limited_receive, send)
