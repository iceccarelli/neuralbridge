"""``assurance supplier`` — publish an advisory your customers can verify.

    keygen     an Ed25519 publishing key, and the fingerprint to give customers
    publish    sign an advisory and append it to your feed
    withdraw   sign a withdrawal of an earlier advisory. It is never deleted
    verify     check a feed before anything acts on it
    list       what stands in a feed, and what was withdrawn
    fetch      download a hosted feed (GET /v1/supplier/feed/{id}) to a local
               file — the path a ``watch`` config's ``feed:`` field names
    trust      the account's pinned supplier keys, kept in its own ledger:
               pin | rotate | revoke | list | check | override. ``check`` says,
               state by state, what a feed is: readable, signature valid, key
               pinned for THIS supplier, chain intact. It never says "verified"

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
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory
from assurance.supplier.publish import (
    AdvisoryFeed,
    PublishError,
    SupplierIdentity,
    _parse_feed_text,
    fetch_feed,
    publish,
    verify_feed,
    withdraw,
)
from assurance.supplier.trust import (
    TRUST_STATEMENT,
    SupplierTrustError,
    SupplierTrustStore,
    evaluate_feed,
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

    ft = verbs.add_parser(
        "fetch", help="download a hosted feed (GET /v1/supplier/feed/{id}) to disk")
    ft.add_argument("url", help="e.g. https://host/v1/supplier/feed/<account_id>")
    ft.add_argument("--out", required=True, type=Path,
                     help="local file the watch config's feed: path should name")
    ft.add_argument("--public-key", type=Path, default=None,
                     help="refuse to write the feed unless it verifies against "
                          "this key")
    ft.add_argument("--expect-supplier", default="")
    ft.add_argument("--timeout", type=float, default=10.0)

    tr = verbs.add_parser(
        "trust", help="pin, rotate, revoke and check supplier keys (per account)")
    tv = tr.add_subparsers(dest="trust_command", required=True)

    def _ledger(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--ledger", required=True, type=Path,
                        help="the ACCOUNT's evidence ledger, never a shared one")

    tp = tv.add_parser("pin", help="trust this key for this supplier")
    _ledger(tp)
    tp.add_argument("--supplier-id", required=True)
    tp.add_argument("--public-key", required=True, type=Path)
    tp.add_argument("--fingerprint", default="",
                    help="the fingerprint you were given by another route; the "
                         "key must match it")
    tp.add_argument("--obtained-via", required=True,
                    help="how you learned the fingerprint (not: from the feed)")
    tp.add_argument("--actor", required=True)
    tp.add_argument("--reason", default="")

    tro = tv.add_parser("rotate", help="pin a new key, retire the old from a date")
    _ledger(tro)
    tro.add_argument("--supplier-id", required=True)
    tro.add_argument("--new-public-key", required=True, type=Path)
    tro.add_argument("--retire-fingerprint", required=True)
    tro.add_argument("--effective-at", required=True, help="ISO-8601 with timezone")
    tro.add_argument("--fingerprint", default="")
    tro.add_argument("--obtained-via", required=True)
    tro.add_argument("--actor", required=True)
    tro.add_argument("--reason", default="")

    trv = tv.add_parser("revoke", help="stop trusting a key")
    _ledger(trv)
    trv.add_argument("--supplier-id", required=True)
    trv.add_argument("--fingerprint", required=True)
    trv.add_argument("--actor", required=True)
    trv.add_argument("--reason", required=True)

    tl = tv.add_parser("list", help="pinned keys and the decision history")
    _ledger(tl)
    tl.add_argument("--json", action="store_true")

    tc = tv.add_parser("check", help="what is this feed, state by state")
    _ledger(tc)
    tc.add_argument("--feed", required=True, type=Path)
    tc.add_argument("--expect-supplier", default="")
    tc.add_argument("--public-key", type=Path, default=None,
                    help="an UNPINNED key to test signatures against; it can show "
                         "that signatures are valid, never that they are trusted")
    tc.add_argument("--json", action="store_true")

    to = tv.add_parser("override", help="accept ONE advisory despite the policy")
    _ledger(to)
    to.add_argument("--feed", required=True, type=Path)
    to.add_argument("--expect-supplier", default="")
    to.add_argument("--advisory-id", required=True)
    to.add_argument("--actor", required=True)
    to.add_argument("--reason", required=True)

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


def _cmd_fetch(args: argparse.Namespace) -> int:
    text = fetch_feed(args.url, timeout=args.timeout)
    records = _parse_feed_text(text, source=args.url)

    if args.public_key:
        key = VerifyingKey.from_file(args.public_key)
        verdict = verify_feed(records, key, expect_supplier=args.expect_supplier)
        if not verdict.ok:
            print(f"finding: {verdict.summary()}", file=sys.stderr)
            for problem in verdict.problems:
                print(f"  ! {problem}", file=sys.stderr)
            print(f"\n  Refusing to write {args.out}: a feed that does not "
                  "verify must not overwrite one that does, and must not "
                  "start driving a watch either.", file=sys.stderr)
            return 1
        print(f"fetched and verified {verdict.summary()}")
    else:
        print(f"fetched {len(records)} record(s) from {args.url} — UNVERIFIED "
              "(pass --public-key to check the signature before this feed "
              "drives anything)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(args.out.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(args.out)
    print(f"  wrote {args.out}")
    return 0


def _cmd_trust(args: argparse.Namespace) -> int:
    from assurance.core.identity import parse_utc

    store = SupplierTrustStore(EvidenceLedger(args.ledger))
    cmd = args.trust_command
    if cmd == "pin":
        pin = store.pin(
            args.supplier_id, Path(args.public_key).read_text(encoding="utf-8"),
            actor=args.actor, obtained_via=args.obtained_via,
            expected_fingerprint=args.fingerprint, reason=args.reason)
        print(f"pinned {pin.fingerprint} for {pin.supplier_id} (by {pin.pinned_by})")
        print(f"  learned via: {pin.obtained_via}")
        return 0
    if cmd == "rotate":
        pin = store.rotate(
            args.supplier_id, Path(args.new_public_key).read_text(encoding="utf-8"),
            retire_fingerprint=args.retire_fingerprint,
            effective_at=parse_utc(args.effective_at), actor=args.actor,
            obtained_via=args.obtained_via, expected_fingerprint=args.fingerprint,
            reason=args.reason)
        print(f"pinned {pin.fingerprint} for {pin.supplier_id} from {pin.effective_from}; "
              f"{args.retire_fingerprint} retired from the same moment")
        return 0
    if cmd == "revoke":
        pin = store.revoke(args.supplier_id, args.fingerprint, actor=args.actor,
                           reason=args.reason)
        print(f"revoked {pin.fingerprint} for {pin.supplier_id}: every record it "
              "signed is now untrusted")
        return 0
    if cmd == "list":
        pins = [p.to_dict() for p in store.pins()]
        if args.json:
            print(json.dumps({"pins": pins, "history": store.history(),
                              "overrides": store.overrides(),
                              "integrity_problems": store.integrity_problems()},
                             indent=2, sort_keys=True))
            return 0
        if not pins:
            print("no supplier key is pinned in this ledger")
        for p in pins:
            print(f"{p['supplier_id']:<16} {p['fingerprint']}  {p['status']:<8} "
                  f"from {p['effective_from']}  pinned by {p['pinned_by']} via "
                  f"{p['obtained_via']}")
        return 0

    records = AdvisoryFeed(args.feed).read()
    candidate = (VerifyingKey.from_file(args.public_key)
                 if getattr(args, "public_key", None) else None)
    trust = evaluate_feed(records, store, expect_supplier=args.expect_supplier,
                          candidate_key=candidate)
    if cmd == "override":
        done = store.override(trust, args.advisory_id, actor=args.actor,
                              reason=args.reason)
        print(f"override recorded for {done['advisory_id']} by {done['actor']}")
        print("  This accepts ONE advisory as it is now (bound to its content hash). "
              "It does not pin the key, and it is in the ledger for audit.")
        return 0
    if args.json:
        print(json.dumps(trust.to_dict(), indent=2, sort_keys=True))
    else:
        print(trust.summary())
        print(f"  1 readable          {trust.structurally_readable} "
              f"({trust.record_count} record(s))")
        print(f"  2 signatures        {trust.signature_state}")
        print(f"  3 key trusted for   {trust.key_trust_state} "
              f"{', '.join(trust.key_fingerprints)}")
        print(f"  4 chain             {'intact' if trust.chain_valid else 'BROKEN'}")
        for problem in trust.problems:
            print(f"  ! {problem}")
        print(f"\n  {TRUST_STATEMENT}")
    return 0 if trust.policy_satisfied else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"keygen": _cmd_keygen, "publish": _cmd_publish,
                "withdraw": _cmd_withdraw, "verify": _cmd_verify, "list": _cmd_list,
                "fetch": _cmd_fetch, "trust": _cmd_trust}
    try:
        return handlers[args.command](args)
    except (PublishError, SupplierTrustError) as exc:
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
