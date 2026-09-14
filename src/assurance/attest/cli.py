"""``assurance attest`` — sign the head of a ledger, and check the signatures.

    keygen   make an Ed25519 key pair, refusing to put the private half next
             to the ledger it will sign
    sign     attest the current head, refusing every case that would lie
    verify   check an attestation log, and a ledger against it
    log      print the attestations without checking anything

``sign`` and ``verify`` exit 0 when everything holds, 1 when there is a
finding — a rewind, a fork, a bad signature — and 2 when the command could not
run at all. A finding is not an error: it is the output this exists to produce,
and it must not share an exit code with a missing file.

The intended shape of a deployment is that ``sign`` runs somewhere the ledger's
operator does not control, on a timer, with the private key held there:

    0 3 * * *  assurance attest sign --ledger /data/register.db \\
                   --key /secrets/attest.pem --log /vault/attest.jsonl || alert
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from assurance.attest.attestation import (
    AttestationError,
    AttestationLog,
    attest,
    verify_log,
)
from assurance.attest.keys import SigningKey, VerifyingKey
from assurance.core.errors import AssuranceError
from assurance.evidence.ledger import EvidenceLedger

__all__ = ["build_parser", "main"]


def _passphrase(args: argparse.Namespace) -> str:
    name = getattr(args, "passphrase_env", None)
    if not name:
        return ""
    value = os.environ.get(name)
    if value is None:
        raise AttestationError(
            f"${name} is not set. The passphrase is read from the environment on "
            "purpose: on the command line it lands in shell history and in the "
            "process table, where every other user on the machine can read it."
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance attest",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    k = verbs.add_parser("keygen", help="make an Ed25519 key pair")
    k.add_argument("--out", required=True, type=Path, help="where the private key goes")
    k.add_argument("--public-out", type=Path, default=None,
                   help="where the public key goes (default: <out>.pub)")
    k.add_argument("--ledger", type=Path, default=None,
                   help="the ledger this key will sign; naming it makes the tool "
                        "refuse to store the key beside it")
    k.add_argument("--passphrase-env", default=None,
                   help="environment variable holding the passphrase")

    s = verbs.add_parser("sign", help="attest the current head of a ledger")
    s.add_argument("--ledger", required=True, type=Path)
    s.add_argument("--key", required=True, type=Path)
    s.add_argument("--log", required=True, type=Path)
    s.add_argument("--note", default="")
    s.add_argument("--rotating", action="store_true",
                   help="acknowledge that this is a different key from the last one")
    s.add_argument("--passphrase-env", default=None)
    s.add_argument("--json", action="store_true")

    v = verbs.add_parser("verify", help="check an attestation log")
    v.add_argument("--log", required=True, type=Path)
    v.add_argument("--public-key", required=True, type=Path)
    v.add_argument("--ledger", type=Path, default=None,
                   help="check the ledger against the attestations too; without it "
                        "only the log itself is checked")
    v.add_argument("--json", action="store_true")

    ll = verbs.add_parser("log", help="print the attestations, checking nothing")
    ll.add_argument("--log", required=True, type=Path)
    ll.add_argument("--json", action="store_true")

    return p


def _cmd_keygen(args: argparse.Namespace) -> int:
    key = SigningKey.generate()
    private = key.save(args.out, passphrase=_passphrase(args), ledger=args.ledger)
    public = Path(args.public_out) if args.public_out else Path(str(private) + ".pub")
    public.parent.mkdir(parents=True, exist_ok=True)
    public.write_text(key.verifying.pem(), encoding="utf-8")

    print(f"key {key.fingerprint}")
    print(f"  private  {private}  (mode 600)")
    print(f"  public   {public}")
    if not args.passphrase_env:
        print("\n  The private key is not encrypted. That is a defensible choice for "
              "an unattended signer inside a secrets store, and a bad one for a "
              "laptop.")
    print("\n  Give the public key to whoever will check the attestations, by some "
          "route other than the one the attestations travel on. Read the "
          f"fingerprint {key.fingerprint} aloud to them if you can: a signature "
          "checked against a key that arrived with it proves nothing.")
    return 0


def _cmd_sign(args: argparse.Namespace) -> int:
    ledger = EvidenceLedger(args.ledger)
    key = SigningKey.load(args.key, passphrase=_passphrase(args))
    log = AttestationLog(args.log)
    record = attest(ledger, key, log, note=args.note, rotating=args.rotating)

    if args.json:
        print(json.dumps(record.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"attestation {record.sequence} — {record.ledger_length} record(s), "
              f"head seq {record.head_seq} {record.head_link_hash[:12]}")
        print(f"  signed by {record.key_fingerprint} at {record.attested_at}")
        print(f"  appended to {log.path}")
        if record.ledger_length == 0:
            print("\n  The ledger is empty. This is still worth signing: it fixes "
                  "the starting point, so a record back-dated before today cannot "
                  "be passed off as having always been there.")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    log = AttestationLog(args.log)
    key = VerifyingKey.from_file(args.public_key)
    ledger = EvidenceLedger(args.ledger) if args.ledger else None
    verdict = verify_log(log.read(), key, ledger=ledger)

    if args.json:
        print(json.dumps(
            {
                "ok": verdict.ok,
                "checked": verdict.checked,
                "key_fingerprint": verdict.key_fingerprint,
                "problems": verdict.problems,
                "checks_skipped": verdict.checks_skipped,
                "latest": verdict.latest.to_dict() if verdict.latest else None,
            },
            indent=2, sort_keys=True))
    else:
        print(verdict.summary())
        if verdict.latest is not None:
            print(f"  latest: attestation {verdict.latest.sequence}, "
                  f"{verdict.latest.ledger_length} record(s), "
                  f"{verdict.latest.attested_at}")
        for problem in verdict.problems:
            print(f"  ! {problem}")
        print("\n  not checked:")
        for skipped in verdict.checks_skipped:
            print(f"    - {skipped}")
    return 0 if verdict.ok else 1


def _cmd_log(args: argparse.Namespace) -> int:
    records = AttestationLog(args.log).read()
    if args.json:
        print(json.dumps([r.to_dict() for r in records], indent=2, sort_keys=True))
        return 0
    if not records:
        print(f"{args.log}: no attestations")
        return 0
    for r in records:
        print(f"{r.sequence:>4}  {r.attested_at}  len={r.ledger_length:<6} "
              f"head={r.head_seq:<6} {r.head_link_hash[:12]}  key={r.key_fingerprint}"
              f"  {r.basis.value}" + (f"  {r.note}" if r.note else ""))
    print("\n  Nothing here was verified. `assurance attest verify` does that.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "keygen": _cmd_keygen,
        "sign": _cmd_sign,
        "verify": _cmd_verify,
        "log": _cmd_log,
    }
    try:
        return handlers[args.command](args)
    except AttestationError as exc:
        print(f"finding: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
