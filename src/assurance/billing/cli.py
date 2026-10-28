"""``assurance billing`` — operator tooling for accounts provisioned without Stripe.

    grant       create an account for a pilot and print its API key, once
    issue-key   print another key for an existing manual grant, once
    revoke-key  stop one key of a manual grant, at once
    extend      move (or remove) a manual grant's last day
    list        every account in the store: where it came from, until when, no secrets

This is for **operator-run manual pilots invoiced OUTSIDE Stripe**. It exists because the
only other way to give a pilot customer a key was to call the account store from Python, and
the account that produced was indistinguishable from a paid one. **The founder decides who
gets a grant;** nothing in this tool, the docs or the tests decides that, and a grant is a
commercial commitment this software cannot take back by itself.

What it does, and does not:

* It works on the local account store file (``--store``, the file the service reads as
  ``ASSURANCE_ACCOUNTS``). It opens no socket, imports no Stripe code, creates no Stripe
  customer, subscription, price, invoice or charge, and sends no email.
* An account it makes records ``source: manual_grant``, the note you gave, when it was granted
  and who granted it, and shows that in ``GET /v1/me`` and in ``list``. It never gets a Stripe
  customer id, so it is not a Stripe-paid account anywhere (``ever_paid`` stays false). What a
  *lapsed* manual grant may still read is therefore the same open decision as for an account
  that never paid (``plans.EVIDENCE_READOUT_AFTER_LAPSE``); this tool does not change it. As
  built, a lapsed grant is refused with 402 on everything a paid plan gates, including the
  evidence read-out.
* The key is printed once, here, and only its hash is stored. It is never written to a log or
  a file by this command and no other command shows it again. Treat it as a secret: put it
  straight into the customer's hands, not into a chat or a ticket.
* ``--expires-on YYYY-MM-DD`` is the last UTC day the grant is in force, inclusive. The
  entitlement is computed from the date on every request, so it ends at 00:00 UTC the day
  after, with no job involved, and ``extend`` takes effect on the next request. With no
  ``--expires-on`` the grant has no expiry, and the output says so.
* A second ``grant`` for an email that already has a manual grant is refused, naming the
  existing account; ``issue-key`` is the explicit way to a second key.
* It refuses to run while a live-looking Stripe credential is in the environment (a
  ``sk_live_``/``rk_live_``/``pk_live_``/``ek_live_``/``whsec_live`` value, a ``STRIPE*LIVE*``
  variable, or ``ASSURANCE_PAYG_ALLOW_LIVE``), and says which variable by name and never its
  value. Zero revenue and no live Stripe are the standing facts; run this from a shell that
  does not hold the variable.

Exit codes: 0 done, 2 refused or could not run (the message says what to do).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from assurance.billing.accounts import (
    GRANTABLE_TIERS,
    KEY_PREFIX,
    Account,
    AccountStore,
    ManualGrantError,
)
from assurance.core.identity import utc_now

__all__ = ["build_parser", "live_stripe_variables", "main"]

_KEY_NOTE = (
    "This key is shown once. Only its hash is stored here and no command shows it again; "
    "if it is lost, issue another and revoke this one. Treat it as a secret.")
_LIVE_VALUES = ("sk_live_", "rk_live_", "pk_live_", "ek_live_", "whsec_live")


class _RefusedError(Exception):
    """The command did not run, and why."""


def live_stripe_variables(environ: Mapping[str, str]) -> list[str]:
    """Names (never values) of environment variables that look like live Stripe access."""
    found = []
    for name, value in environ.items():
        upper = name.upper()
        if upper == "ASSURANCE_PAYG_ALLOW_LIVE":
            if value.strip():
                found.append(name)
        elif (upper.startswith("STRIPE") and "LIVE" in upper) \
                or any(marker in value for marker in _LIVE_VALUES):
            found.append(name)
    return sorted(found)


def _expiry(text: str) -> str:
    if not text:
        return ""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        raise _RefusedError(f"--expires-on {text!r} is not a date; write it YYYY-MM-DD.")
    try:
        day = date.fromisoformat(text)
    except ValueError:
        raise _RefusedError(f"--expires-on {text!r} is not a calendar date.") from None
    if day < utc_now().date():
        raise _RefusedError(
            f"--expires-on {text} is already in the past (UTC today is "
            f"{utc_now().date().isoformat()}); a grant that has already ended is not a grant.")
    return text


def _open(path: Path, *, create: bool) -> AccountStore:
    if not path.exists() and not create:
        raise _RefusedError(
            f"{path} does not exist. This is the account store the service reads as "
            "ASSURANCE_ACCOUNTS (on the hosted volume, /data/accounts.db). A mistyped path "
            "would otherwise create a new, empty store and mint a key that works nowhere; if "
            "you really are starting a new store, pass --create.")
    if path.exists() and not path.is_file():
        raise _RefusedError(f"{path} is not a file.")
    return AccountStore(path)


def _manual(store: AccountStore, account_id: str) -> Account:
    account = store.account(account_id)
    if account is None:
        raise _RefusedError(f"no account {account_id!r} in this store.")
    if not account.is_manual_grant:
        raise _RefusedError(
            f"{account_id} is not a manual grant. Its access follows Stripe, and this tool "
            "does not touch it.")
    return account


def _describe(account: Account, store: AccountStore) -> dict[str, Any]:
    return {
        "id": account.id,
        "email": account.email,
        "company": account.company,
        "tier": account.tier,
        "status": account.status,
        "source": ("manual_grant" if account.is_manual_grant
                   else "stripe" if account.stripe_customer_id else "unbilled"),
        "note": account.grant_note,
        "granted_at": account.granted_at,
        "granted_by": account.granted_by,
        "expires_on": account.grant_expires_on,
        "lapsed": account.grant_lapsed,
        "entitled_now": account.tier != "free" and account.plan.tier == account.tier,
        "active_keys": store.active_key_count(account.id),
        "stripe_bound": bool(account.stripe_customer_id),
    }


def _emit(args: argparse.Namespace, payload: dict[str, Any], lines: list[str]) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("\n".join(lines))


def _cmd_grant(args: argparse.Namespace) -> int:
    expires = _expiry(args.expires_on)
    store = _open(args.store, create=args.create)
    try:
        account, key = store.grant_manual(
            email=args.email, tier=args.tier, company=args.company, note=args.note,
            expires_on=expires, granted_by=args.granted_by)
    except ManualGrantError as exc:
        raise _RefusedError(str(exc)) from None
    prefix = key[: len(KEY_PREFIX) + 6]
    payload = {
        "account_id": account.id, "email": account.email, "tier": account.tier,
        "source": "manual_grant", "note": account.grant_note,
        "granted_at": account.granted_at, "granted_by": account.granted_by,
        "expires_on": account.grant_expires_on, "api_key": key, "key_prefix": prefix,
        "key_note": _KEY_NOTE,
        "not_a_stripe_account": (
            "No Stripe customer, subscription, price, invoice or charge exists for this "
            "account. Invoice it outside Stripe."),
    }
    _emit(args, payload, [
        f"granted {account.tier} to {account.email}  (account {account.id})",
        "  source     manual_grant  (not a Stripe customer; invoice it outside Stripe)",
        f"  note       {account.grant_note or '—'}",
        "  expires    " + (f"last day in force {account.grant_expires_on} (UTC, inclusive)"
                           if account.grant_expires_on else
                           "no expiry: this grant does not lapse until you extend or revoke"),
        "",
        f"  API KEY    {key}",
        f"  {_KEY_NOTE}",
        "  Use:  curl -H 'X-API-Key: <key>' <service>/v1/me",
    ])
    return 0


def _cmd_issue_key(args: argparse.Namespace) -> int:
    store = _open(args.store, create=False)
    account = _manual(store, args.account)
    key = store.issue_key(account.id, label=args.label)
    payload = {"account_id": account.id, "api_key": key,
               "key_prefix": key[: len(KEY_PREFIX) + 6], "key_note": _KEY_NOTE}
    _emit(args, payload, [f"another key for {account.email}  (account {account.id})",
                          f"  API KEY    {key}", f"  {_KEY_NOTE}"])
    return 0


def _cmd_revoke_key(args: argparse.Namespace) -> int:
    store = _open(args.store, create=False)
    account = _manual(store, args.account)
    result = store.revoke_account_key(account.id, key_prefix=args.prefix)
    if args.json:
        print(json.dumps({"account_id": account.id, "prefix": args.prefix, "result": result}))
    else:
        print(f"{account.id} key {args.prefix}: {result}")
    if result == "revoked":
        return 0
    if result == "ambiguous":
        print("error: more than one live key shares that prefix; revoke is by prefix only "
              "and will not guess which.", file=sys.stderr)
    elif result == "not_found":
        print("error: this account has no key with that prefix (see `billing list` for the "
              "count; the prefix is the first 10 characters of the key).", file=sys.stderr)
    return 0 if result == "already_revoked" else 2


def _cmd_extend(args: argparse.Namespace) -> int:
    expires = _expiry(args.expires_on)
    store = _open(args.store, create=False)
    _manual(store, args.account)
    account = store.extend_grant(args.account, expires)
    _emit(args, {"account_id": account.id, "expires_on": account.grant_expires_on,
                 "lapsed": account.grant_lapsed},
          [f"{account.id}: " + (f"last day in force {expires} (UTC, inclusive)"
                                 if expires else "no expiry")])
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    store = _open(args.store, create=False)
    rows = [_describe(a, store) for a in store.list_accounts()]
    if args.json:
        print(json.dumps({"accounts": rows}, indent=2, sort_keys=True))
        return 0
    if not rows:
        print("no accounts in this store.")
        return 0
    print(f"{'ACCOUNT':<22} {'TIER':<9} {'SOURCE':<13} {'STATUS':<10} {'LAST DAY':<11} "
          f"{'NOW':<5} {'KEYS':<4} EMAIL")
    for r in rows:
        print(f"{r['id']:<22} {r['tier']:<9} {r['source']:<13} {r['status']:<10} "
              f"{r['expires_on'] or '—':<11} {'yes' if r['entitled_now'] else 'no':<5} "
              f"{r['active_keys']:<4} {r['email']}"
              + (f"   [{r['note']}]" if r["note"] else ""))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance billing", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    verbs = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--store", required=True, type=Path,
                        help="the account store file (the service's ASSURANCE_ACCOUNTS)")
        sp.add_argument("--json", action="store_true")

    g = verbs.add_parser(
        "grant", help="create a manual-pilot account and print its key, once",
        description=(
            "Create an account for an operator-run manual pilot invoiced OUTSIDE Stripe, and "
            "print its API key once. The founder decides who gets a grant. Works on the local "
            "account store only: no network, no Stripe, no email. The account is marked "
            "source=manual_grant and has no Stripe customer id. Run `assurance billing "
            "--help` for what it does and does not do."))
    common(g)
    g.add_argument("--email", required=True, help="who the grant is for (not proof of identity)")
    g.add_argument("--tier", required=True, choices=GRANTABLE_TIERS)
    g.add_argument("--company", default="")
    g.add_argument("--note", default="",
                   help="why, and the arrangement (e.g. 'pilot, invoiced by bank transfer'); "
                        "shown in /v1/me and `billing list`")
    g.add_argument("--expires-on", default="", metavar="YYYY-MM-DD",
                   help="the last UTC day the grant is in force, inclusive; without it the "
                        "grant never lapses by itself")
    g.add_argument("--granted-by", default="", help="who is granting it (recorded)")
    g.add_argument("--create", action="store_true",
                   help="allow creating the store file if it does not exist (otherwise a "
                        "mistyped path is refused)")

    ik = verbs.add_parser("issue-key", help="print another key for a manual grant, once")
    common(ik)
    ik.add_argument("--account", required=True)
    ik.add_argument("--label", default="manual-grant")

    rk = verbs.add_parser("revoke-key", help="stop one key of a manual grant")
    common(rk)
    rk.add_argument("--account", required=True)
    rk.add_argument("--prefix", required=True,
                    help="the key's first 10 characters, as `grant` printed them")

    ex = verbs.add_parser("extend", help="move a manual grant's last day")
    common(ex)
    ex.add_argument("--account", required=True)
    ex.add_argument("--expires-on", required=True, metavar="YYYY-MM-DD")

    ls = verbs.add_parser("list", help="every account: source, tier, last day, key count")
    common(ls)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"grant": _cmd_grant, "issue-key": _cmd_issue_key,
                "revoke-key": _cmd_revoke_key, "extend": _cmd_extend, "list": _cmd_list}
    try:
        if args.command != "list":
            live = live_stripe_variables(os.environ)
            if live:
                raise _RefusedError(
                    "a live-looking Stripe credential is in this environment ("
                    + ", ".join(live) + "). This tool provisions pilots outside Stripe and "
                    "refuses to run beside live Stripe access: zero revenue and no live "
                    "Stripe are the standing facts until the founder says otherwise. Run it "
                    "from a shell that does not hold the variable (its value is not shown).")
        return handlers[args.command](args)
    except _RefusedError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (LookupError, ValueError, RuntimeError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
