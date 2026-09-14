"""``assurance supplier`` — publish an advisory your customers can verify.

    keygen     an Ed25519 publishing key, and the fingerprint to give customers
    publish    sign an advisory and append it to your feed
    withdraw   sign a withdrawal of an earlier advisory. It is never deleted
    verify     check a feed before anything acts on it
    list       what stands in a feed, and what was withdrawn

Exit codes: 0 fine, 1 a finding — a bad signature, a gap, a feed that must not
be acted on — and 2 the command could not run.

The fingerprint printed by ``keygen`` is the whole security model. Put it where
your customers will find it without following a link from an advisory: the
contract, the machine's documentation folder, the back of the quotation. Read
it aloud on the phone. A key that can only be checked against the thing it
signs establishes that one party was consistent and nothing more.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.attest.keys import SigningKey, VerifyingKey
from assurance.core.errors import AssuranceError
from assurance.fleet.advisory import ComponentAdvisory
from assurance.supplier.publish import (
    AdvisoryFeed,
    PublishError,
    SupplierIdentity,
    publish,
    verify_feed,
    withdraw,
)

__all__ = ["build_parser", "main"]


def _identity(args: argparse.Namespace) -> SupplierIdentity:
    if getattr(args, "identity", None):
        return SupplierIdentity.from_dict(
            json.loads(Path(args.identity).read_text(encoding="utf-8")))
    return SupplierIdentity(
        supplier_id=args.supplier_id,
        legal_name=args.legal_name,
        key_contact=args.key_contact,
    )


def _add_identity_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--identity", type=Path, default=None,
                   help="JSON file with supplier_id, legal_name, key_contact")
    p.add_argument("--supplier-id", default="")
    p.add_argument("--legal-name", default="")
    p.add_argument("--key-contact", default="",
                   help="where a customer confirms this key's fingerprint by a "
                        "route that is not this feed")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance supplier",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    k = verbs.add_parser("keygen", help="an Ed25519 publishing key")
    k.add_argument("--out", required=True, type=Path)
    k.add_argument("--public-out", type=Path, default=None)
    k.add_argument("--passphrase-env", default=None)

    pb = verbs.add_parser("publish", help="sign an advisory into your feed")
    pb.add_argument("advisory", type=Path, help="the advisory as JSON")
    pb.add_argument("--feed", required=True, type=Path)
    pb.add_argument("--key", required=True, type=Path)
    pb.add_argument("--rotating", action="store_true")
    pb.add_argument("--passphrase-env", default=None)
    _add_identity_args(pb)

    wd = verbs.add_parser("withdraw", help="sign a withdrawal of an advisory")
    wd.add_argument("advisory_id")
    wd.add_argument("--reason", required=True)
    wd.add_argument("--feed", required=True, type=Path)
    wd.add_argument("--key", required=True, type=Path)
    wd.add_argument("--rotating", action="store_true")
    wd.add_argument("--passphrase-env", default=None)
    _add_identity_args(wd)

    v = verbs.add_parser("verify", help="check a feed before acting on it")
    v.add_argument("--feed", required=True, type=Path)
    v.add_argument("--public-key", required=True, type=Path)
    v.add_argument("--expect-supplier", default="")
    v.add_argument("--json", action="store_true")

    ls = verbs.add_parser("list", help="what stands in a feed")
    ls.add_argument("--feed", required=True, type=Path)
    ls.add_argument("--json", action="store_true")

    return p


def _passphrase(args: argparse.Namespace) -> str:
    import os

    name = getattr(args, "passphrase_env", None)
    if not name:
        return ""
    value = os.environ.get(name)
    if value is None:
        raise PublishError(
            f"${name} is not set. The passphrase is read from the environment "
            "on purpose: on the command line it lands in shell history and in "
            "the process table."
        )
    return value


def _cmd_keygen(args: argparse.Namespace) -> int:
    key = SigningKey.generate()
    private = key.save(args.out, passphrase=_passphrase(args))
    public = Path(args.public_out) if args.public_out else Path(str(private) + ".pub")
    public.parent.mkdir(parents=True, exist_ok=True)
    public.write_text(key.verifying.pem(), encoding="utf-8")

    print(f"publishing key {key.fingerprint}")
    print(f"  private  {private}  (mode 600)")
    print(f"  public   {public}")
    print("\n  Give your customers this fingerprint:")
    print(f"\n      {key.fingerprint}\n")
    print("  Put it in the contract, in the machine's documentation folder, on "
          "the quotation —")
    print("  anywhere they will find it WITHOUT following a link from an "
          "advisory. That is the")
    print("  whole security model. An advisory that carries its own key proves "
          "nothing, and")
    print("  the forged advisory telling somebody to reflash a safety "
          "controller will carry one.")
    return 0


def _cmd_publish(args: argparse.Namespace) -> int:
    advisory = ComponentAdvisory.from_json(args.advisory)
    record = publish(
        advisory, _identity(args),
        SigningKey.load(args.key, passphrase=_passphrase(args)),
        AdvisoryFeed(args.feed), rotating=args.rotating)
    print(f"published {record.advisory_id} as record {record.sequence}")
    print(f"  signed by {record.key_fingerprint} at {record.published_at}")
    print(f"  feed      {args.feed}")
    if not advisory.publishes_hashes:
        print("\n  This advisory names versions but no content hashes. Your "
              "customers will match")
        print("  it by label, and every finding they derive will say so. "
              "Publishing the hashes")
        print("  turns 'probably affected' into 'affected', and it is the "
              "single most useful")
        print("  thing a component supplier can do for the people who install "
              "their parts.")
    return 0


def _cmd_withdraw(args: argparse.Namespace) -> int:
    record = withdraw(
        args.advisory_id, args.reason, _identity(args),
        SigningKey.load(args.key, passphrase=_passphrase(args)),
        AdvisoryFeed(args.feed), rotating=args.rotating)
    print(f"withdrew {args.advisory_id} as record {record.sequence}")
    print(f"  reason: {args.reason}")
    print("\n  The original stays in the feed. Your customers changed machines "
          "because of it;")
    print("  deleting it would leave them holding a change nobody can explain.")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    feed = AdvisoryFeed(args.feed)
    key = VerifyingKey.from_file(args.public_key)
    verdict = verify_feed(feed.read(), key, expect_supplier=args.expect_supplier)

    if args.json:
        print(json.dumps({
            "ok": verdict.ok, "checked": verdict.checked,
            "supplier_id": verdict.supplier_id,
            "key_fingerprint": verdict.key_fingerprint,
            "problems": verdict.problems,
            "checks_skipped": verdict.checks_skipped,
            "live": [r.advisory_id for r in verdict.live],
            "withdrawn": list(verdict.withdrawn),
        }, indent=2))
    else:
        print(verdict.summary())
        for problem in verdict.problems:
            print(f"  ! {problem}")
        print("\n  not checked:")
        for skipped in verdict.checks_skipped:
            print(f"    - {skipped}")
        if not verdict.ok:
            print("\n  Do not act on this feed. A change to a safety system "
                  "driven by an advisory")
            print("  that does not verify is the attack this mechanism exists "
                  "to prevent.")
    return 0 if verdict.ok else 1


def _cmd_list(args: argparse.Namespace) -> int:
    records = AdvisoryFeed(args.feed).read()
    if args.json:
        print(json.dumps([r.to_dict() for r in records], indent=2, sort_keys=True))
        return 0
    if not records:
        print(f"{args.feed}: empty")
        return 0
    for r in records:
        mark = "WITHDRAWN" if r.is_withdrawal else "published"
        print(f"{r.sequence:>4}  {r.published_at}  {mark:<10} "
              f"{r.advisory_id:<20} {r.advisory.get('title', '')[:50]}")
        if r.is_withdrawal:
            print(f"        withdraws {r.withdraws}: {r.withdrawal_reason}")
    print("\n  Nothing here was verified. `assurance supplier verify` does that.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"keygen": _cmd_keygen, "publish": _cmd_publish,
                "withdraw": _cmd_withdraw, "verify": _cmd_verify, "list": _cmd_list}
    try:
        return handlers[args.command](args)
    except PublishError as exc:
        print(f"finding: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
