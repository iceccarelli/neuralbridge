"""``assurance tenant``: export one customer account's data, verify the export, offboard it.

    export         write a verified export of one account into a new empty 0700 directory
    verify-export  re-hash every file against MANIFEST.json and re-verify the copied chain
    delete         a PLAN by default; --execute removes exactly the planned files

Operator tooling on the data volume: not an HTTP route, not an MCP tool, and it deletes
nothing unless --execute is given with every guard satisfied (see ``tenant delete --help``).

Exit codes. 0 done / verified; 1 refused, or the export does not match or is damaged; 2 could
not run (usage, I/O, a busy lock); 3 (verify-export only) unchecked: there is no manifest.
No command creates a ledger, an account or a directory it was not told to write.
"""

# ruff: noqa: T201 - a command line writes to stdout
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.text import neutralise
from assurance.tenant.delete import execute_deletion, plan_deletion
from assurance.tenant.export import export_account, verify_export_dir
from assurance.tenant.layout import TenantError

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance tenant", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                allow_abbrev=False)
    verbs = p.add_subparsers(dest="command", required=True)

    e = verbs.add_parser("export", help="export one account into a new empty directory")
    e.add_argument("--data-dir", required=True, type=Path,
                   help="the service data directory (holds tenants/ and attestations/)")
    e.add_argument("--account", required=True, help="acc_ followed by 16 lowercase hex digits")
    e.add_argument("--out", required=True, type=Path, help="a new (or empty) directory")
    e.add_argument("--actor", required=True, help="who is taking the export")
    e.add_argument("--accept-damaged", action="store_true",
                   help="export even though the chain does not verify; the manifest says so "
                        "and no evidence bundle is written")
    e.add_argument("--json", action="store_true")

    v = verbs.add_parser("verify-export", help="check an export directory")
    v.add_argument("directory", type=Path)
    v.add_argument("--json", action="store_true")

    d = verbs.add_parser(
        "delete", help="plan an account's removal; --execute removes it",
        description="Without --execute this only prints what would be removed and what would "
                    "not. --execute also needs --confirm-account, --export (a directory "
                    "`tenant verify-export` passes, for this account, at the ledger's current "
                    "head) and an --actor that is a named person.")
    d.add_argument("--data-dir", required=True, type=Path)
    d.add_argument("--account", required=True)
    d.add_argument("--actor", default="", help="required with --execute: a named person")
    d.add_argument("--backup-dir", type=Path, default=None,
                   help="list this backup directory's copies of the account (names only)")
    d.add_argument("--execute", action="store_true")
    d.add_argument("--confirm-account", default=None, help="repeat the account id")
    d.add_argument("--export", dest="export_dir", type=Path, default=None)
    d.add_argument("--operator-ledger", type=Path, default=None,
                   help="the operator ledger that receives the tombstone "
                        "(default <data-dir>/art14-register.db; never created)")
    d.add_argument("--accept-damaged", action="store_true",
                   help="allow an export that was taken with --accept-damaged")
    d.add_argument("--lock-timeout", type=float, default=10.0, help=argparse.SUPPRESS)
    d.add_argument("--json", action="store_true")
    return p


def _lines(title: str, items: list[str] | tuple[str, ...]) -> None:
    print(f"\n  {title}")
    for item in items:
        print(f"    - {neutralise(item)}")


def _print_export(m: dict[str, Any], out: Path) -> None:
    print(f"exported {m['account_id']} to {out}")
    print(f"  records {m['record_count']}, head {m['head_hash']}, "
          f"chain {m['verify']['status']}")
    for f in m["files"]:
        print(f"  {f['name']:<22} {f['size']:>9} bytes  sha256 {f['sha256']}")
    if m["accept_damaged"] and m["verify"]["status"] != "verified":
        print("\n  WARNING: this export was taken with --accept-damaged and the chain does NOT "
              "verify.")
    _lines("NOT included:", m["not_included"])
    _lines("Does NOT establish:", m["does_not_establish"])


def _print_verify(r: dict[str, Any]) -> None:
    print(f"verify-export {r['directory']}: {r['status'].upper()}")
    if r["account_id"]:
        print(f"  account {r['account_id']}, records {r['record_count']}, head {r['head_hash']}")
    for name in r["checked"]:
        print(f"  ok  {name}")
    for problem in r["problems"]:
        print(f"  !!  {neutralise(problem)}")
    if r["status"] == "ok":
        _lines("Does NOT establish:", r["not_established"])


def _print_plan(plan: dict[str, Any]) -> None:
    print(f"PLAN (nothing was removed) for {plan['account_id']}")
    if plan["already_removed"]:
        print("  already removed: none of the account's files exist")
    for f in plan["would_remove"]:
        print(f"  would remove  {f['path']}  ({f['size']} bytes)")
    _lines("Deliberately NOT removed:", plan["not_removed"])
    if plan["backup_dir_checked"]:
        copies = plan["backup_copies_still_holding_data"]
        print(f"\n  WARNING: backups still hold this data. In {plan['backup_dir_checked']}:")
        for c in copies or [{"path": "(no file named for this account found)", "size": 0}]:
            print(f"    - {neutralise(c['path'])}")
        print("    A backup of the whole volume also holds accounts.db and the operator ledger.")
    else:
        print("\n  Backups were not checked (give --backup-dir). Any backup taken before now "
              "still holds this data.")
    _lines("Would NOT be established:", plan["not_established"])
    print("\n  To remove: tenant export, tenant verify-export, then re-run with --execute "
          "--confirm-account <id> --export <dir> --actor <named person>.")


def _print_done(r: dict[str, Any]) -> None:
    print(f"REMOVED the files of {r['account_id']}:")
    for f in r["removed"]:
        print(f"  removed  {f['path']}  ({f['size']} bytes)")
    t = r["tombstone"]
    print(f"  tombstone: operator ledger entry {t['seq']} ({t['content_hash'][:16]})")
    print(f"  accounts.db: {r['accounts_db']}")
    _lines("Deliberately NOT removed:", r["not_removed"])
    _lines("NOT established:", r["not_established"])


def _run(args: argparse.Namespace) -> int:
    if args.command == "export":
        manifest = export_account(args.data_dir, args.account, args.out, actor=args.actor,
                                  accept_damaged=args.accept_damaged)
        if args.json:
            print(json.dumps(manifest, indent=2))
        else:
            _print_export(manifest, args.out)
        return 0
    if args.command == "verify-export":
        result = verify_export_dir(args.directory)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            _print_verify(result)
        return int(result["exit_code"])
    if args.execute:
        done = execute_deletion(
            args.data_dir, args.account, actor=args.actor, confirm_account=args.confirm_account,
            export_dir=args.export_dir, operator_ledger=args.operator_ledger,
            accept_damaged=args.accept_damaged, lock_timeout=args.lock_timeout)
        if args.json:
            print(json.dumps(done, indent=2))
        else:
            _print_done(done)
        return 0
    plan = plan_deletion(args.data_dir, args.account, backup_dir=args.backup_dir)
    if args.json:
        print(json.dumps(plan, indent=2))
    else:
        _print_plan(plan)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _run(args)
    except TenantError as exc:
        print(f"refused: {exc}" if exc.exit_code == 1 else f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except (AssuranceError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"error: could not complete ({type(exc).__name__}: {exc}). "
              "Check what was and was not changed before retrying.", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
