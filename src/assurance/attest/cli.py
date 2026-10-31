"""``assurance attest`` — sign the head of a ledger, and check the signatures.

    keygen      make an Ed25519 key pair, refusing to put the private half next
                to the ledger it will sign, or to overwrite anything
    sign        attest the current head, refusing every case that would lie
    verify      check an attestation log, and a ledger against it (repeat
                --public-key to verify a log that spans a rotation)
    log         print the attestations without checking anything
    preflight   would counter-signing and validated verification work in this
                environment? Reads the service's own variables; prints no key
    anchor-all  counter-sign the head of every hosted tenant ledger (a timer job; see
                deploy/assurance/KEY-CEREMONY.md section 11)
    trust-list  create / add / revoke / list / verify-file for the recorder trust
                file the hosted service loads (ASSURANCE_RECORDER_TRUST)

``sign`` and ``verify`` exit 0 when everything holds, 1 when there is a
finding — a rewind, a fork, a bad signature — and 2 when the command could not
run at all. A finding is not an error: it is the output this exists to produce,
and it must not share an exit code with a missing file.

Exit 3 (``TORN_TAIL_EXIT``) is a log that ends in an unterminated line: a write that
did not finish, or one still in flight. For ``verify`` it means the newest attestation
may be missing, so nothing is established and ``ok`` is false (text and ``--json``,
where ``torn_tail`` is true); it is never reported as a pass. For ``sign`` it means
nothing was appended. A real finding wins: a log that is torn *and* has a problem
exits 1. Preserve the file, then have the operator repair it.

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
from typing import Any

from assurance.attest.attestation import (
    AttestationBasis,
    AttestationError,
    AttestationLog,
    AttestationTornTailError,
    attest,
    verify_log,
)
from assurance.attest.custody import require_private_key_file, verify_log_across_rotation
from assurance.attest.keys import SigningKey, SigningKeyError, VerifyingKey
from assurance.attest.preflight import run_preflight
from assurance.attest.trustlist import (
    add_recorder,
    create_trust_file,
    entries_as_json,
    load_trust,
    revoke_recorder,
    summarise,
    trust_file_problems,
)
from assurance.core.errors import AssuranceError
from assurance.evidence.ledger import EvidenceLedger

__all__ = ["TORN_TAIL_EXIT", "build_parser", "main"]

#: A log whose last line was not finished. Distinct from a finding (1) and a command
#: that could not run (2): the log needs a person, and what it says is not established.
TORN_TAIL_EXIT = 3

_TORN_MESSAGE = ("the log ends in an unterminated line (a write that did not finish, or "
                 "one in flight); the newest attestation may be missing, so this is not "
                 "a pass")


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
    k.add_argument("--json", action="store_true",
                   help="print the public fingerprint and the two paths as JSON")

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
    v.add_argument("--public-key", required=True, type=Path, action="append",
                   help="the verifier's own copy of the public key. Repeat it, once per "
                        "key, to verify a log that spans a rotation: each attestation must "
                        "verify under the key it names, and a key is never read from the log")
    v.add_argument("--ledger", type=Path, default=None,
                   help="check the ledger against the attestations too; without it "
                        "only the log itself is checked")
    v.add_argument("--basis", choices=[b.value for b in AttestationBasis], default=None,
                   help="with --ledger and a log that mixes bases: which records "
                        "describe that ledger. Default: the log's only basis, else "
                        "read_from_ledger (a declared head describes the holder's own "
                        "ledger, not the one the signer read)")
    v.add_argument("--json", action="store_true")

    _preflight_parser(verbs)
    _anchor_all_parser(verbs)
    _trust_parser(verbs)

    ll = verbs.add_parser("log", help="print the attestations, checking nothing")
    ll.add_argument("--log", required=True, type=Path)
    ll.add_argument("--json", action="store_true")

    return p


def _preflight_parser(verbs: Any) -> None:
    f = verbs.add_parser(
        "preflight",
        help="would counter-signing and validated verification work in this environment?")
    f.add_argument("--key", type=Path, default=None,
                   help="a private key FILE to check in place of ASSURANCE_ATTEST_KEY")
    f.add_argument("--trust", type=Path, default=None,
                   help="a trust file to check in place of ASSURANCE_RECORDER_TRUST")
    f.add_argument("--expect-fingerprint", default="",
                   help="the service-key fingerprint you wrote down elsewhere; a mismatch "
                        "fails the check")
    f.add_argument("--must-be-revoked", action="append", default=[], metavar="FINGERPRINT",
                   help="a recorder fingerprint that must not be trusted; fails if the list "
                        "still trusts it. Repeatable")
    f.add_argument("--require", choices=["both", "counter-signing", "validated", "none"],
                   default="both",
                   help="which capabilities must be available for exit 0 (default: both)")
    f.add_argument("--anchors", type=Path, default=None, metavar="DIR",
                   help="also check that every tenant ledger under this deployment data "
                        "directory has a verified, young anchor (read-only)")
    f.add_argument("--max-age", type=float, default=None, metavar="HOURS",
                   help="with --anchors: how old the newest anchor may be (default 24)")
    f.add_argument("--tenants-dir", type=Path, default=None,
                   help="with --anchors: tenant ledgers directory if not DIR/tenants")
    f.add_argument("--logs-dir", type=Path, default=None,
                   help="with --anchors: attestation logs directory if not DIR/attestations")
    f.add_argument("--json", action="store_true")


def _anchor_all_parser(verbs: Any) -> None:
    a = verbs.add_parser(
        "anchor-all",
        help="counter-sign the head of every tenant ledger (operator job; run on a timer)")
    a.add_argument("--data-dir", required=True, type=Path,
                   help="deployment data directory: tenants/ holds the ledgers, "
                        "attestations/ the per-account logs")
    a.add_argument("--key", required=True, type=Path)
    a.add_argument("--passphrase-env", default=None)
    a.add_argument("--max-age", type=float, default=24.0, metavar="HOURS",
                   help="a ledger whose newest verified anchor is younger than this and "
                        "already covers its head is left alone (default 24)")
    a.add_argument("--tenants-dir", type=Path, default=None)
    a.add_argument("--logs-dir", type=Path, default=None)
    a.add_argument("--dry-run", action="store_true",
                   help="verify and report what would be anchored; write nothing")
    a.add_argument("--json", action="store_true")


def _trust_parser(verbs: Any) -> None:
    t = verbs.add_parser(
        "trust-list", help="manage the recorder trust file the hosted service loads")
    tv = t.add_subparsers(dest="trust_command", required=True)

    c = tv.add_parser("create", help="start an empty trust file (refuses to replace one)")
    c.add_argument("--trust", required=True, type=Path)

    a = tv.add_parser("add", help="trust one recorder PUBLIC key")
    a.add_argument("--trust", required=True, type=Path)
    a.add_argument("--public-key", required=True, type=Path)
    a.add_argument("--label", required=True, help="whose recorder this is")
    a.add_argument("--provenance", required=True,
                   help="comma list of what the key may vouch for: bench, field. "
                        "Grant the narrowest set")
    a.add_argument("--fingerprint", required=True,
                   help="the fingerprint the recorder operator gave you by ANOTHER route; "
                        "a key that does not hash to it is refused")

    r = tv.add_parser("revoke", help="revoke a recorder key (total and immediate)")
    r.add_argument("--trust", required=True, type=Path)
    r.add_argument("--fingerprint", required=True)
    r.add_argument("--effective", required=True, metavar="YYYY-MM-DD",
                   help="the date to record. Required, never defaulted. Every attestation of "
                        "a revoked key is rejected, whatever date it states")

    ls = tv.add_parser("list", help="print the trusted recorders (public information)")
    ls.add_argument("--trust", required=True, type=Path)
    ls.add_argument("--json", action="store_true")

    vf = tv.add_parser("verify-file",
                       help="check the file loads exactly as the service loads it")
    vf.add_argument("--trust", required=True, type=Path)
    vf.add_argument("--json", action="store_true")


def _cmd_keygen(args: argparse.Namespace) -> int:
    private_path = Path(args.out)
    public = Path(args.public_out) if args.public_out else Path(str(private_path) + ".pub")
    # Refuse before generating anything: the public half is not secret, but overwriting
    # it would silently replace the key customers were told to check against.
    if public.exists() or public.is_symlink():
        raise SigningKeyError(
            f"{public} already exists; refusing to overwrite a public key that may be the "
            "one customers hold.")
    if public.resolve() == private_path.resolve():
        raise SigningKeyError("--public-out must not be the private key's path.")
    key = SigningKey.generate()
    private = key.save(args.out, passphrase=_passphrase(args), ledger=args.ledger)
    public.parent.mkdir(parents=True, exist_ok=True)
    with public.open("x", encoding="utf-8") as handle:
        handle.write(key.verifying.pem())

    if args.json:
        print(json.dumps({"fingerprint": key.fingerprint, "private_key_file": str(private),
                          "public_key_file": str(public),
                          "private_key_encrypted": bool(args.passphrase_env)},
                         indent=2, sort_keys=True))
        return 0
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
    ledger = EvidenceLedger.open_existing(args.ledger)
    require_private_key_file(args.key)
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
    ledger = EvidenceLedger.open_existing(args.ledger) if args.ledger else None
    log = AttestationLog(args.log)
    keys = [VerifyingKey.from_file(p) for p in args.public_key]
    records, torn = log.scan()
    basis = AttestationBasis(args.basis) if args.basis else None
    if len(keys) == 1:
        verdict = verify_log(records, keys[0], ledger=ledger, basis=basis)
    else:
        verdict = verify_log_across_rotation(records, keys, ledger=ledger, basis=basis)
    ok = verdict.ok and not torn
    problems = [*verdict.problems, *([_TORN_MESSAGE] if torn else [])]

    if args.json:
        print(json.dumps(
            {
                "ok": ok,
                "checked": verdict.checked,
                "key_fingerprint": verdict.key_fingerprint,
                "problems": problems,
                "checks_skipped": verdict.checks_skipped,
                "notes": verdict.notes,
                "torn_tail": torn,
                "latest": verdict.latest.to_dict() if verdict.latest else None,
            },
            indent=2, sort_keys=True))
    else:
        print(verdict.summary() if not torn or verdict.problems
              else f"{verdict.checked} attestation(s) read, 1 problem: the log is incomplete "
                   "(not a pass)")
        if verdict.latest is not None:
            print(f"  latest: attestation {verdict.latest.sequence}, "
                  f"{verdict.latest.ledger_length} record(s), "
                  f"{verdict.latest.attested_at}")
        for problem in verdict.problems:
            print(f"  ! {problem}")
        if torn:
            print(f"  ! {_TORN_MESSAGE}")
        print("\n  not checked:")
        for skipped in verdict.checks_skipped:
            print(f"    - {skipped}")
    if not verdict.ok:
        return 1
    return TORN_TAIL_EXIT if torn else 0


def _cmd_preflight(args: argparse.Namespace) -> int:
    report = run_preflight(
        key_file=args.key, trust_file=args.trust, expect_fingerprint=args.expect_fingerprint,
        must_be_revoked=tuple(args.must_be_revoked), anchors=args.anchors,
        anchor_max_age_hours=args.max_age, anchor_tenants_dir=args.tenants_dir,
        anchor_logs_dir=args.logs_dir)
    code = report.exit_code(args.require)
    if args.json:
        print(json.dumps({**report.to_dict(), "ok": code == 0, "required": args.require},
                         indent=2, sort_keys=True))
        return code
    yes = {True: "AVAILABLE", False: "NOT AVAILABLE"}
    print(f"counter-signed attestation   {yes[report.counter_signing]}"
          + (f"   key {report.service_fingerprint}" if report.service_fingerprint else ""))
    print(f"validated-tier verification  {yes[report.validated_verification]}"
          f"   trust list: {report.trust_status}")
    print()
    for c in report.checks:
        print(f"  [{c.status:<4}] {c.name}: {c.detail}")
    print("\n  NOT checked:")
    for item in report.to_dict()["not_checked"]:
        print(f"    - {item}")
    print("\n  This inspected configuration only. Nothing was signed, verified or changed.")
    return code


def _cmd_anchor_all(args: argparse.Namespace) -> int:
    from assurance.attest.anchor_all import anchor_all, render

    if args.max_age < 0:
        raise ValueError("--max-age cannot be negative.")
    require_private_key_file(args.key)
    try:
        key = SigningKey.load(args.key, passphrase=_passphrase(args), label="the key file")
    except SigningKeyError as exc:
        # The parser's own text can sit next to key bytes; say only what class of fault.
        text = str(exc).lower()
        why = ("is encrypted and no passphrase was given" if "no passphrase" in text
               else "does not exist" if "does not exist" in text
               else "is not an Ed25519 private key" if "not an ed25519" in text
               else "could not be read (malformed, or the passphrase is wrong)")
        raise ValueError(f"the key file {why}. Nothing was signed.") from None
    if _inside(args.key.parent, args.data_dir):
        raise ValueError("the key file sits inside the data directory it would sign for; "
                         "whoever can rewrite the ledger could re-sign it. Nothing was signed.")
    report = anchor_all(args.data_dir, key, tenants_dir=args.tenants_dir,
                        logs_dir=args.logs_dir, max_age_hours=args.max_age,
                        dry_run=args.dry_run)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(render(report))
    return report.exit_code


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


def _cmd_trust_list(args: argparse.Namespace) -> int:
    which = args.trust_command
    if which == "create":
        path = create_trust_file(args.trust)
        print(f"{path}: empty recorder trust list created (nobody is trusted yet)")
        return 0
    if which == "add":
        classes = frozenset(c.strip() for c in args.provenance.split(",") if c.strip())
        entry = add_recorder(args.trust, args.public_key, label=args.label,
                             provenance=classes, expected_fingerprint=args.fingerprint)
        print(f"{args.trust}: trusted {entry.fingerprint} ({entry.label}) for "
              f"{', '.join(entry.provenance)}")
        print("  This is you vouching for its holder, for every account on the server. "
              "The list is server-wide.")
        return 0
    if which == "revoke":
        entry = revoke_recorder(args.trust, args.fingerprint, effective=args.effective)
        print(f"{args.trust}: revoked {entry.fingerprint} ({entry.label}), recorded as "
              f"{entry.revoked_on}")
        print("  Revocation is total and immediate: every attestation by this key is "
              "rejected, including those dated before the revocation. Evidence sealed "
              "under it reads as community until re-attested under a trusted key.")
        return 0
    trust = load_trust(args.trust)         # raises on anything the server could not load
    entries = summarise(trust)
    problems = trust_file_problems(args.trust)
    if which == "list":
        if args.json:
            print(json.dumps(entries_as_json(entries), indent=2, sort_keys=True))
            return 0
        if not entries:
            print(f"{args.trust}: no recorders; nobody is trusted")
        for e in entries:
            state = f"REVOKED {e.revoked_on or '(no date)'}" if e.revoked else "trusted"
            print(f"  {e.fingerprint}  {state:<22} {','.join(e.provenance):<11} {e.label}")
        return 0
    live = sum(1 for e in entries if not e.revoked)           # verify-file
    ok = not problems
    if args.json:
        print(json.dumps({"ok": ok, "recorders": len(entries), "not_revoked": live,
                          "problems": problems}, indent=2, sort_keys=True))
    else:
        print(f"{args.trust}: loads as the service loads it; {len(entries)} recorder key(s), "
              f"{live} not revoked")
        for problem in problems:
            print(f"  ! {problem}")
    return 0 if ok else 1


def _cmd_log(args: argparse.Namespace) -> int:
    records, torn = AttestationLog(args.log).scan()
    if torn:
        print("note: the log ends in an unterminated line (a write that did not "
              "finish); it was ignored", file=sys.stderr)
    if args.json:
        print(json.dumps([r.to_dict() for r in records], indent=2, sort_keys=True))
        return 0
    if not records:
        print(f"{args.log}: no attestations")
        return 0
    for r in records:
        print(f"{r.sequence:>4}  {r.attested_at}  len={r.ledger_length:<6} "
              f"head={r.head_seq:<6} {r.head_link_hash[:12]}  key={r.key_fingerprint}"
              f"  {r.basis.value}"
              + ((f"  note (requester's text, not the signer's): {r.note}"
                  if r.note_is_tenant_supplied else f"  {r.note}") if r.note else ""))
    print("\n  Nothing here was verified. `assurance attest verify` does that.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "keygen": _cmd_keygen,
        "sign": _cmd_sign,
        "verify": _cmd_verify,
        "log": _cmd_log,
        "preflight": _cmd_preflight,
        "anchor-all": _cmd_anchor_all,
        "trust-list": _cmd_trust_list,
    }
    try:
        return handlers[args.command](args)
    except AttestationTornTailError as exc:
        print(f"finding: {exc}", file=sys.stderr)
        return TORN_TAIL_EXIT
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
