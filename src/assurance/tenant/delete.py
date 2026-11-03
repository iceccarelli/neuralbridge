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

The head is compared, the deletion marker (``tenants/<acc>.deleted``) is written and the files
are unlinked while the ledger's writer lock (``BEGIN IMMEDIATE``) is held, so no append can land
between the comparison and the removal.

Files are removed one by one by their exact names. There is no recursive delete and no glob.
Afterwards a ``tenant.deletion`` entry is appended to the OPERATOR ledger. It carries the
account id, time, actor, the export manifest's sha256, the head hash and the names and sizes of
the removed files, and no customer record contents.

``accounts.db`` is NOT touched. ``AccountStore`` can end a manual grant, but an account that
came from Stripe is closed by a billing event, and closing one here would diverge from Stripe.
The operator closes the account in the billing system first; see ``deploy/assurance/TENANT.md``.
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager, nullcontext
from pathlib import Path
from typing import Any

from assurance.attest.attestation import AttestationLog
from assurance.core import Actor, Evidence, Origin
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import EnrolmentError, require_person
from assurance.tenant.export import live_head, load_manifest, verify_export_dir
from assurance.tenant.layout import (
    MARKER_SCHEMA,
    OPERATOR_LEDGER_NAME,
    AccountFiles,
    TenantError,
    account_files,
    check_account_id,
    plain_file,
    read_marker,
)

__all__ = ["TOMBSTONE_KIND", "NOT_REMOVED", "NOT_ESTABLISHED", "plan_deletion",
           "execute_deletion"]

TOMBSTONE_KIND = "tenant.deletion"

#: Test seam: called, with the ledger's writer lock held, between the head comparison and the
#: first unlink. Production never sets it.
_BETWEEN_CHECK_AND_REMOVE: Callable[[], None] | None = None

_POISON_APPENDS = (
    "CREATE TRIGGER IF NOT EXISTS nb_ledger_removed BEFORE INSERT ON chain "
    "BEGIN SELECT RAISE(ABORT, 'this ledger was removed by an operator'); END")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_PRINTABLE = re.compile(r"[ -~]{1,120}")

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
    marker = read_marker(files.marker) if files.marker_exists else None
    if would:
        state = "files_present"
    elif marker is not None:
        state = "already_removed"
    else:
        state = "no_such_account_data"
    return {
        "account_id": account_id,
        "mode": "plan",
        "state": state,
        "would_remove": would,
        "already_removed": state == "already_removed",
        "removed_at": (marker or {}).get("deleted_at") if state == "already_removed" else None,
        "removed_by": (marker or {}).get("actor") if state == "already_removed" else None,
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
    if files.marker_exists:
        raise TenantError(f"{account_id} is already removed: its deletion marker "
                          f"{files.marker.name} exists. Nothing was changed.")
    if not planned:
        raise TenantError(f"no such account data on this host for {account_id}: none of its "
                          "files exist and it has no deletion marker (it never existed here, "
                          "or the id is wrong). Nothing was changed.")
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

    bound = _bound_manifest_fields(manifest)

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
    transient: list[dict[str, Any]] = []
    deleted_at = format_utc(utc_now())
    guard = AttestationLog(files.log).locked(timeout=lock_timeout) if files.log_exists \
        else nullcontext()
    with guard:
        _check_head_and_remove(
            files, bound, removed, lock_timeout=lock_timeout, transient=transient,
            marker_doc={"schema": MARKER_SCHEMA, "account_id": account_id,
                        "deleted_at": deleted_at, "actor": who.identifier,
                        "export_manifest_sha256": manifest_sha})
    # The lock file goes last, after the lock on it is released.
    _stat_and_remove(files.log_lock, removed)

    body = {
        "schema": "neuralbridge-tenant-deletion/1",
        "account_id": account_id,
        "deleted_at": deleted_at,
        "actor": who.identifier,
        # Only values `verify-export` bound to something: the head, the count and the ledger
        # id were compared with the copied ledger, the manifest by its own hash. The
        # manifest's time and actor are unbound text and are deliberately not copied.
        "export": {
            "manifest_sha256": manifest_sha,
            "head_hash": bound["head_hash"],
            "record_count": bound["record_count"],
            "ledger_id": bound["ledger_id"],
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
              "removed_transient_sqlite_files": [Path(t["path"]).name for t in transient],
              "export_manifest_sha256": manifest_sha, "head_hash": bound["head_hash"],
              "marker": str(files.marker),
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


def _bound_manifest_fields(manifest: dict[str, Any]) -> dict[str, Any]:
    """The manifest values this module keeps, each checked for type and shape.

    ``verify_export_dir`` compares the head hash, record count and ledger id with the copied
    ledger; here they must also be plain, bounded values before they go into an append-only
    ledger.
    """
    head, count, ledger_id = (manifest.get("head_hash"), manifest.get("record_count"),
                              manifest.get("ledger_id"))
    if not (isinstance(head, str) and _HEX64.fullmatch(head)):
        raise TenantError("the export manifest's head_hash is not a sha256 hex string. "
                          "Nothing was removed.")
    if not (isinstance(count, int) and not isinstance(count, bool) and 0 <= count < 10**12):
        raise TenantError("the export manifest's record_count is not a count. Nothing was "
                          "removed.")
    if not (isinstance(ledger_id, str) and _PRINTABLE.fullmatch(ledger_id)):
        raise TenantError("the export manifest's ledger_id is not a short printable string. "
                          "Nothing was removed.")
    return {"head_hash": head, "record_count": count, "ledger_id": ledger_id}


@contextmanager
def _writer_lock(ledger: Path, timeout: float) -> Iterator[sqlite3.Connection]:
    """Hold the ledger's writer lock (``BEGIN IMMEDIATE``), the one every append takes.

    While it is held no append can commit, so what is read under it is the final state. It is
    released (rolled back: nothing is written through this connection) when the block ends.
    SQLite on POSIX allows the file to be unlinked while it is open; a writer that was waiting
    then finds its database gone and fails instead of being acknowledged.
    """
    try:
        db = sqlite3.connect(ledger, timeout=timeout, isolation_level=None)
    except sqlite3.Error as exc:
        raise TenantError(f"the ledger could not be opened ({type(exc).__name__}). Nothing "
                          "was removed.", exit_code=2) from exc
    try:
        try:
            db.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            raise TenantError("the ledger's writer lock could not be taken (a writer is busy "
                              f"or the file is unreadable: {exc}). Nothing was removed; retry.",
                              exit_code=2) from exc
        try:
            yield db
        finally:
            try:
                if db.in_transaction:
                    db.execute("ROLLBACK")
            except sqlite3.Error:
                pass
    finally:
        db.close()


def _write_marker(path: Path, doc: dict[str, Any]) -> None:
    """Create the deletion marker, 0600, exclusively; an existing one is never overwritten."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise TenantError(f"{path.name} already exists: the account is already removed. "
                          "Nothing was removed.") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write((json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, 0o600)


def _check_head_and_remove(files: AccountFiles, bound: dict[str, Any],
                           removed: list[dict[str, Any]], *, marker_doc: dict[str, Any],
                           transient: list[dict[str, Any]], lock_timeout: float = 10.0) -> None:
    """Under the ledger's writer lock: compare the head, write the marker, unlink the files.

    The lock is taken BEFORE the head is read and kept until every file is unlinked, so an
    append cannot land between the comparison and the removal. If the head is not the
    export's, nothing is removed and no marker is written.
    """
    with _writer_lock(files.ledger, lock_timeout) as db:
        count, head = live_head(files.ledger)
        if count != bound["record_count"] or head != bound["head_hash"]:
            raise TenantError(
                f"the ledger now holds {count} record(s) with a head that is not the export's "
                f"({bound['record_count']} record(s)). It changed since the export, so "
                "deleting would remove records that were never exported. Run `tenant export` "
                "again and use that export. Nothing was removed.")
        if _BETWEEN_CHECK_AND_REMOVE is not None:
            _BETWEEN_CHECK_AND_REMOVE()
        # The marker goes first, still under the lock: from here the API refuses the account
        # and nothing it does can recreate the ledger, whatever happens to the unlinks.
        _write_marker(files.marker, marker_doc)
        # Reading the ledger may have created or dropped SQLite companions: list the files
        # again, by the same fixed names, and leave the lock file for the caller.
        initial = set(files.planned())
        try:
            # A writer that was already waiting for the lock holds the file open. Unlinking
            # does not stop it from committing to the orphaned inode and being told "stored".
            # So the last thing done through the lock is to make every further INSERT fail.
            db.execute(_POISON_APPENDS)
            db.execute("COMMIT")
            for path in account_files(files.data_dir, files.account_id).planned():
                if path != files.log_lock:
                    # -wal/-shm that only exist because this connection holds the lock are
                    # unlinked too, but are not part of the account's files as planned
                    _stat_and_remove(path, removed if path in initial else transient)
        except (OSError, TenantError, sqlite3.Error) as exc:
            raise TenantError(
                f"THE DELETION IS INCOMPLETE ({type(exc).__name__}: {exc}). The marker "
                f"{files.marker.name} is in place, so the API refuses the account; some of "
                "its files may remain. Removed so far: "
                + (", ".join(Path(r["path"]).name for r in removed) or "none")
                + ". Finish by hand and record it.", exit_code=2) from exc
