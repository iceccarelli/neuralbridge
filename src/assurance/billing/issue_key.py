"""Operator command: issue a new API key to a paying Stripe account.

``python -m assurance.billing.issue_key (--customer cus_... | --account acc_...)
[--discard-staged cs_...] [--json]``

For the one case the product has no other answer to: a checkout key that was never collected
when a backup was taken. ``pending_keys`` is deliberately not in a backup (it holds a working
credential in plaintext), and the checkout's session marker is, so after a restore the
customer's ``/v1/checkout/complete`` answers 410 (``already_collected_or_expired``) and
Stripe's redelivery is a duplicate. This mints a fresh key for that account through the same
``AccountStore.issue_key`` the API uses (same active-key limit), once, to stdout.

It is also the recovery when someone other than the buyer collected the key (they held the
session id and the claim token), or the buyer lost the claim token while the key is still
staged (``/v1/checkout/complete`` answers 403): ``--discard-staged cs_...`` first deletes
the staged key and revokes it, so the staged copy can never be used.

It issues only to an account that is paying now (``active`` or ``past_due`` on a paid tier)
and has a Stripe customer; it never touches the operator account, status, tier or any
subscription. The key is written to stdout and nowhere else: it is not logged, not put in an
error, and only its SHA-256 is stored. Pass it to the customer over a channel you trust.

Exit 0 issued, 1 refused (nothing was changed), 2 could not run.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .accounts import ENTITLED_STATUSES, MAX_ACTIVE_KEYS, AccountStore, KeyLimitError

LABEL = "operator re-issue (key not collected before a restore)"


def _refuse(message: str) -> int:
    sys.stderr.write(f"issue_key: refused: {message}\n")
    sys.stderr.flush()
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m assurance.billing.issue_key",
        description="Issue a new API key to a paying Stripe account. The key is printed once, "
                    "to stdout, and cannot be recovered afterwards.",
    )
    who = parser.add_mutually_exclusive_group(required=True)
    who.add_argument("--customer", metavar="cus_...", help="the account's Stripe customer id")
    who.add_argument("--account", metavar="acc_...", help="the account id")
    parser.add_argument("--discard-staged", metavar="cs_...", default="",
                        help="first delete the key staged for this checkout session and revoke "
                             "it: for a buyer who lost the claim token, or a key that may have "
                             "been collected by someone else. It must belong to the same account")
    parser.add_argument("--json", action="store_true",
                        help='print {"account_id", "prefix", "api_key"} instead of the bare key')
    args = parser.parse_args(argv)

    path = os.environ.get("ASSURANCE_ACCOUNTS", "accounts.db")
    if not Path(path).is_file():
        # AccountStore would create an empty database; a typo must not.
        sys.stderr.write("issue_key: could not run: ASSURANCE_ACCOUNTS does not point at an "
                         "existing account store.\n")
        return 2
    try:
        store = AccountStore(path)
        acct = (store.account_by_customer(args.customer) if args.customer
                else store.account(args.account))
        if acct is None:
            return _refuse("no such account.")
        if acct.id == "operator":
            return _refuse("the operator account is not a customer.")
        if not acct.stripe_customer_id:
            return _refuse("the account has no Stripe customer; this command is only for "
                           "accounts that pay through Stripe.")
        if acct.status not in ENTITLED_STATUSES or acct.tier == "free":
            return _refuse(f"the account is not entitled (status {acct.status!r}, tier "
                           f"{acct.tier!r}); a key would open nothing.")
        if args.discard_staged:
            staged_for = store.discard_pending_key(args.discard_staged)
            if staged_for is None:
                sys.stderr.write("issue_key: no key was staged for that session; continuing.\n")
            elif staged_for != acct.id:
                return _refuse("the staged key for that session belongs to a different "
                               "account; it was discarded and revoked, nothing was issued.")
            else:
                sys.stderr.write("issue_key: discarded and revoked the staged key.\n")
        try:
            key = store.issue_key(acct.id, label=LABEL, max_active=MAX_ACTIVE_KEYS)
        except KeyLimitError:
            return _refuse(f"the account already holds {MAX_ACTIVE_KEYS} active keys; revoke "
                           "one first.")
    except Exception as exc:  # noqa: BLE001 - report the class, never a value
        sys.stderr.write(f"issue_key: could not run: {type(exc).__name__}\n")
        return 2

    if args.json:
        sys.stdout.write(json.dumps(
            {"account_id": acct.id, "prefix": key[:10], "api_key": key}) + "\n")
    else:
        sys.stdout.write(key + "\n")
    sys.stdout.flush()
    sys.stderr.write(f"issue_key: issued a key for {acct.id}. It is shown once and only its "
                     "hash is stored.\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
