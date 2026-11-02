"""Offboard one account: a plan by default, and a guarded removal of exactly the planned files.

``plan`` reads only names and sizes of the files it would remove. It writes nothing.

``execute`` removes the account's ledger (and its ``-wal``/``-shm``/``-journal``), its
attestation log and that log's lock file, and nothing else, and only when ALL of these hold:

* ``--confirm-account`` repeats the account id;
* the actor is a named person (the rule the enrolment and change workflows apply);
* ``--export`` is a directory that ``verify_export_dir`` passes, for this same account, and
  whose head hash and record count are the ledger's NOW. A ledger that grew since the export
  is refused: the newer records would be deleted unexported;
* the operator ledger exists and its chain verifies (the tombstone is appended to it);
* the account's attestation-log lock can be taken, so a running anchor job is not raced.

Files are removed one by one by their exact names. There is no recursive delete and no glob.
Afterwards a ``tenant.deletion`` entry is appended to the OPERATOR ledger. It carries the
account id, time, actor, the export manifest's sha256, the head hash and the names and sizes of
the removed files, and no customer record contents.

``accounts.db`` is NOT touched. ``AccountStore`` can end a manual grant, but an account that
came from Stripe is closed by a billing event, and closing one here would diverge from Stripe.
The operator closes the account in the billing system first; see ``deploy/assurance/TENANT.md``.
"""

from __future__ import annotations

import os
from contextlib import nullcontext
from pathlib import Path
from typing import Any

from assurance.attest.attestation import AttestationLog
from assurance.core import Actor, Evidence, Origin
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import EnrolmentError, require_person
from assurance.tenant.export import live_head, load_manifest, verify_export_dir
from assurance.tenant.layout import (
    OPERATOR_LEDGER_NAME,
    AccountFiles,
    TenantError,
    account_files,
    check_account_id,
    plain_file,
)

__all__ = ["TOMBSTONE_KIND", "NOT_REMOVED", "NOT_ESTABLISHED", "plan_deletion",
           "execute_deletion"]

TOMBSTONE_KIND = "tenant.deletion"

NOT_REMOVED = (
    "the account's row in accounts.db (this tool never opens it; close the account in the "
    "billing system, not here)",
    "billing and Stripe records, invoices and usage counters",
    "backups already taken: they still hold this account's ledger until the operator disposes "
    "of them",
    "exports already taken, including the one used for this deletion",
    "the operator ledger: it gains a tombstone and loses nothing",
)

NOT_ESTABLISHED = (
    "that no copy of the data exists elsewhere: backups, replicas, exports, logs and anything "
    "the customer or a processor holds are outside this tool",
    "storage-level remanence: unlinking a file does not overwrite its blocks, and SQLite free "
    "pages leave with the file, not with a wipe",
    "that deletion satisfies any legal or contractual obligation: this is the procedure the "
    "tooling supports, not a conclusion about what is required",
    "that the person named as actor was authorised: the name is recorded as given",
)


def _backups(backup_dir: Path | None, account_id: str) -> list[dict[str, Any]]:
    """Names (never contents) of files in *backup_dir* that are this account's. Read-only."""
    if backup_dir is None:
        return []
    if backup_dir.is_symlink() or not backup_dir.is_dir():
        raise TenantError(f"{backup_dir} is not a directory (or is a symbolic link).",
                          exit_code=2)
    found: list[dict[str, Any]] = []
    for root, dirs, names in os.walk(backup_dir, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            if name.startswith(account_id):
                path = Path(root) / name
                found.append({"path": str(path), "size": os.lstat(path).st_size})
    return found


def plan_deletion(data_dir: str | Path, account_id: str, *,
                  backup_dir: str | Path | None = None) -> dict[str, Any]:
    files = account_files(data_dir, account_id)
    would = [{"path": str(p), "size": os.lstat(p).st_size} for p in files.planned()]
    return {
        "account_id": account_id,
        "mode": "plan",
        "would_remove": would,
        "already_removed": not would,
        "not_removed": list(NOT_REMOVED),
        "backup_copies_still_holding_data": _backups(
            Path(backup_dir) if backup_dir else None, account_id),
        "backup_dir_checked": str(backup_dir) if backup_dir else None,
        "not_established": list(NOT_ESTABLISHED),
    }


def _person(actor: str) -> Actor:
    try:
        return require_person(Actor(identifier=(actor or "").strip(), kind="person"),
                              "tenant deletion")
    except EnrolmentError as exc:
        raise TenantError(str(exc)) from exc


def _remove(path: Path) -> None:
    """Unlink exactly *path*, which must still be a plain file (re-checked just now)."""
    if plain_file(path):
        os.unlink(path)


def execute_deletion(
    data_dir: str | Path, account_id: str, *, actor: str, confirm_account: str | None,
    export_dir: str | Path | None, operator_ledger: str | Path | None = None,
    accept_damaged: bool = False, lock_timeout: float = 10.0,
) -> dict[str, Any]:
    check_account_id(account_id)
    if confirm_account != account_id:
        raise TenantError("--execute needs --confirm-account repeating the account id exactly. "
                          "Nothing was removed.")
    who = _person(actor)
    if export_dir is None:
        raise TenantError("--execute needs --export DIR: an export that `tenant verify-export` "
                          "passes. Nothing was removed.")
    files = account_files(data_dir, account_id)
    planned = files.planned()
    if not planned:
        raise TenantError(f"{account_id} is already removed: none of its files exist. "
                          "Nothing was changed.")
    if not files.ledger_exists:
        raise TenantError(
            f"{account_id} has no ledger but leftover files exist ("
            + ", ".join(p.name for p in planned)
            + "). A deletion needs an export to match against; remove the leftovers by hand "
              "after deciding what they are. Nothing was changed.")

    verdict = verify_export_dir(export_dir)
    allowed = {"ok"} | ({"damaged_accepted"} if accept_damaged else set())
    if verdict["status"] not in allowed:
        raise TenantError(
            f"the export {export_dir} does not pass `tenant verify-export` "
            f"(status {verdict['status']}): " + "; ".join(verdict["problems"][:3])
            + ". Nothing was removed.")
    manifest, manifest_sha = load_manifest(Path(export_dir))
    if manifest.get("account_id") != account_id:
        raise TenantError(f"the export is for {manifest.get('account_id')!r}, not "
                          f"{account_id}. Nothing was removed.")

    op_path = Path(operator_ledger) if operator_ledger \
        else Path(data_dir) / OPERATOR_LEDGER_NAME
    if not plain_file(op_path):
        raise TenantError(f"the operator ledger {op_path} does not exist, so the tombstone "
                          "could not be recorded and none is created here. Nothing was removed.",
                          exit_code=2)
    operator = EvidenceLedger(op_path, mint_id=False)
    op_ok, op_problems = operator.verify_chain()
    if not op_ok:
        raise TenantError("the operator ledger's chain does not verify, so a tombstone cannot "
                          "be appended to it: " + "; ".join(op_problems[:2])
                          + ". Nothing was removed.")

    removed: list[dict[str, Any]] = []
    guard = AttestationLog(files.log).locked(timeout=lock_timeout) if files.log_exists \
        else nullcontext()
    with guard:
        _check_head_and_remove(files, manifest, removed)
    # The lock file goes last, after the lock on it is released.
    _stat_and_remove(files.log_lock, removed)

    body = {
        "schema": "neuralbridge-tenant-deletion/1",
        "account_id": account_id,
        "deleted_at": format_utc(utc_now()),
        "actor": who.identifier,
        "export": {
            "manifest_sha256": manifest_sha,
            "exported_at": manifest.get("exported_at"),
            "export_actor": manifest.get("actor"),
            "head_hash": manifest.get("head_hash"),
            "record_count": manifest.get("record_count"),
            "ledger_id": manifest.get("ledger_id"),
            "export_status": verdict["status"],
        },
        "removed_files": [{"name": Path(r["path"]).name, "size": r["size"]} for r in removed],
        "not_removed": list(NOT_REMOVED),
        "not_established": list(NOT_ESTABLISHED),
    }
    evidence = Evidence(
        kind=TOMBSTONE_KIND, body=body, actor=who,
        origin=Origin(system="assurance.tenant", reference=account_id,
                      method="operator deletion after a verified export; the files named "
                             "were unlinked"),
        checks_skipped=NOT_ESTABLISHED,
    ).seal()
    result = {"account_id": account_id, "mode": "executed", "removed": removed,
              "export_manifest_sha256": manifest_sha, "head_hash": manifest.get("head_hash"),
              "tombstone": None, "not_removed": list(NOT_REMOVED),
              "not_established": list(NOT_ESTABLISHED),
              "accounts_db": "not touched: close the account in the billing system"}
    try:
        entry = operator.append(evidence, subject=f"tenant/{account_id}")
    except Exception as exc:
        raise TenantError(
            "THE FILES WERE REMOVED but the tombstone could not be appended to the operator "
            f"ledger ({type(exc).__name__}). Record this by hand: account {account_id}, "
            f"actor {who.identifier}, export manifest sha256 {manifest_sha}, removed "
            + ", ".join(Path(r["path"]).name for r in removed), exit_code=2) from exc
    result["tombstone"] = {"ledger": str(op_path), "seq": entry.seq,
                           "content_hash": evidence.content_hash}
    return result


def _stat_and_remove(path: Path, removed: list[dict[str, Any]]) -> None:
    if not plain_file(path):
        return
    size = os.lstat(path).st_size
    _remove(path)
    removed.append({"path": str(path), "size": size})


def _check_head_and_remove(files: AccountFiles, manifest: dict[str, Any],
                           removed: list[dict[str, Any]]) -> None:
    count, head = live_head(files.ledger)
    if count != manifest.get("record_count") or head != manifest.get("head_hash"):
        raise TenantError(
            f"the ledger now holds {count} record(s) with a head that is not the export's "
            f"({manifest.get('record_count')} record(s)). It changed since the export, so "
            "deleting would remove records that were never exported. Run `tenant export` "
            "again and use that export. Nothing was removed.")
    # Reading the ledger may have created or dropped SQLite companions: list the files again,
    # by the same fixed names, and leave the lock file for the caller.
    for path in account_files(files.data_dir, files.account_id).planned():
        if path != files.log_lock:
            _stat_and_remove(path, removed)
