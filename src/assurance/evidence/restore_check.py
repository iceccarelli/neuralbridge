"""Back up the service's data directory consistently, and prove a restore.

The hosted service keeps three kinds of state, all SQLite, all on one volume:

* ``accounts.db`` — accounts, key hashes, usage, processed billing events;
* the operator ledger (``art14-register.db``) — the shared, operator-only chain;
* ``tenants/<account id>.db`` — one hash-chained ledger per customer account;
* ``attestations/`` and ``supplier-feeds/`` — append-only JSONL logs, copied as
  files (they are written by single appends and are not SQLite).

A plain file copy of a WAL-mode database can lose its newest records, and
``sqlite3 .dump`` of only the operator ledger — what the deploy README used to
suggest — silently skips every customer's evidence. ``backup`` takes a
transactionally consistent snapshot of **all** of it; ``verify`` opens a backup
(or a restored volume) and checks what can be checked from the files alone.

``backup`` also writes ``backup-manifest.json``: every file with its size and SHA-256, each
ledger's length and head link hash, the attestation logs' record counts and the list of
accounts. Without it ``verify`` could only look at the files that happen to be present, and a
restore that had lost a ledger — or all of them — read "ok". The backup directory is created
``0700`` and its files ``0600``, and the ``pending_keys`` rows (API keys minted by a checkout
and not yet collected, held in plaintext for up to 24 hours) are **not copied**: a customer
whose key was still unclaimed at backup time must be issued a new one after a restore.

What ``verify`` establishes: each database passes SQLite's integrity check, each ledger's
hash chain verifies, every tenant ledger belongs to a known account, every file the manifest
lists is present with the recorded hash (or, with ``--live``, a ledger only ever grew past the
recorded head), nothing unlisted appeared, and every attestation log still fits the ledger it
was signed over (a ledger shorter than its own attestation log has lost evidence).
What it cannot: that nothing was *removed* by someone who also rewrote the manifest and the
attestation log (the manifest is not signed; keep ``manifest_sha256`` from the ``backup``
output somewhere else), or that a log's records are genuine (the signing key is not in a
backup: ``attest verify`` with the public key does that). It says so in its output.

    python -m assurance.evidence.restore_check backup  <data dir> <backup dir> [--ai-store <file>]
    python -m assurance.evidence.restore_check verify  [--live] [--against-live <live data dir>] <dir>
    python -m assurance.evidence.restore_check restore <backup dir> <new data dir>

``backup --ai-store FILE`` also snapshots the ``/ai`` control plane's SQLite store
(``NEURALBRIDGE_AI_STORE``: connection records and plans, never credentials) as
``ai-store.db``. ``restore`` is the only supported way to put a backup back: it verifies the
backup strictly first and refuses anything that does not verify; it refuses a target that
exists and is not an empty directory (it never overwrites a live volume or a live ledger);
it stages a copy beside the target, re-verifies the copy and only then renames it into place.
Plans in the restored ``ai-store.db`` that were still ``pending_approval`` or ``approved`` are
set to ``denied`` / ``failed``: the write they describe may have run after the backup was taken,
and a restored "pending" plan must not be approvable a second time.

``verify`` is read-only, including on a volume a service has opened: it creates, changes,
renames and deletes nothing under the directory it checks (nor under ``--against-live``).
Databases are inspected through private temporary copies, so SQLite never writes ``-wal`` /
``-shm`` beside them. A ``-wal`` / ``-journal`` beside a database the manifest lists is not an
"unlisted file"; if it holds content it is read, reported under ``sidecars`` and
``not_established``, and is a finding in strict mode (the manifest hash covers the main file only).

``backup`` exits 1 and writes ``degraded: true`` when the source already fails a check (a
broken chain, or an attestation log that claims more than its ledger holds); the snapshot is
kept, and ``verify`` fails it. Every ledger carries a random ``ledger_id`` (its lineage, kept
by a file copy); ``--against-live`` fails a restored ledger that shares an id with one on the
live volume but disagrees with it, i.e. a fork. A hash chain alone does not detect removal
of the newest records: without an attestation log ``verify`` says so under ``not_established``.

Exit codes: 0 verified, 1 a finding, 2 could not run, 3 **unchecked** — there is no manifest
(a backup taken by an older build, or a live data directory without ``--live`` context), so
the files are consistent as far as they can be read and nothing says nothing is missing.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from assurance.attest import AttestationBasis, AttestationLog, check_log_against_ledger
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger

__all__ = ["MANIFEST_NAME", "RestoreRefused", "backup", "restore", "verify", "main"]

MANIFEST_NAME = "backup-manifest.json"
MANIFEST_FORMAT = "neuralbridge-backup-manifest/1"

_OPERATOR_LEDGER = "art14-register.db"
_ACCOUNTS = "accounts.db"
_AI_STORE = "ai-store.db"
_TENANT = re.compile(r"^acc_[0-9a-f]{16}\.db$")
_LOG_DIRS = ("attestations", "supplier-feeds")


#: Longest a snapshot waits for a source that stays locked, in seconds. sqlite3's
#: ``backup()`` retries a busy source for ever on its own.
BACKUP_DEADLINE = 30.0


def _ro_uri(path: Path) -> str:
    """A read-only SQLite URI for ``path``, percent-encoded.

    ``f"file:{path}?mode=ro"`` ends the URI at a ``#`` or ``?`` in the path: the
    "source" became a different, nonexistent file that SQLite then created empty,
    and the backup reported success with an empty snapshot.
    """
    return f"{Path(path).resolve().as_uri()}?mode=ro"


def _private_dir(path: Path) -> None:
    """Create ``path`` (and parents) and make it 0700 NOW.

    The umask is only the first line of defence: a default ACL on the parent, or a filesystem
    that ignores the umask, hands a new directory group/world access anyway (observed: a
    Codespace's /tmp gives 0756 under umask 077). An explicit chmod is not subject to either, and
    a 0700 directory shuts everyone else out of whatever is created inside it.
    """
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _snapshot(src: Path, dest: Path) -> None:
    _private_dir(dest.parent)
    # Create the file 0600 before SQLite does: SQLite asks for 0644 and leaves the rest to the
    # umask, which an ACL can override. An existing file is left to _tighten.
    try:
        os.close(os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError:
        pass
    # A short busy timeout on the source: each backup step then returns BUSY after about
    # a second instead of waiting out 30 s inside SQLite, so ``bounded`` below gets to
    # enforce BACKUP_DEADLINE at that granularity.
    source = sqlite3.connect(_ro_uri(src), uri=True, timeout=min(1.0, BACKUP_DEADLINE))
    started = time.monotonic()

    def bounded(status: int, remaining: int, total: int) -> None:
        # Called after every step, including the ones that found the source busy.
        if status in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) \
                and time.monotonic() - started >= BACKUP_DEADLINE:
            raise sqlite3.OperationalError(
                f"database is locked: gave up after {BACKUP_DEADLINE:g}s waiting to "
                f"snapshot {src.name}")

    try:
        target = sqlite3.connect(dest)
        try:
            source.backup(target, progress=bounded)
        finally:
            target.close()
    finally:
        source.close()


def _strip_pending_keys(path: Path) -> int:
    """Delete the unclaimed plaintext checkout keys from a backup copy. Returns how many.

    ``secure_delete`` and a ``VACUUM`` afterwards, so the key bytes are not left in a free
    page of the file (they would also be in any page the live database had freed earlier).
    """
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA secure_delete=ON")
        try:
            count = int(db.execute("SELECT COUNT(*) FROM pending_keys").fetchone()[0])
            db.execute("DELETE FROM pending_keys")
            db.commit()
        except sqlite3.OperationalError as exc:
            if "no such table" not in str(exc):
                raise
            count = 0
        db.execute("VACUUM")
        return count
    finally:
        db.close()


def _sha256(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    remaining = limit
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1 << 20 if remaining is None else min(1 << 20, remaining))
            if not chunk:
                break
            digest.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
                if remaining <= 0:
                    break
    return digest.hexdigest()


def _tighten(root: Path) -> None:
    """0700 directories, 0600 files, whatever the source or the umask said."""
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            continue
        os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _ledger_facts(path: Path) -> dict[str, Any]:
    ledger = EvidenceLedger(path, mint_id=False)
    entries = ledger.entries()
    last = entries[-1] if entries else None
    return {"entries": len(entries), "head_seq": last.seq if last else 0,
            "head_link_hash": last.link_hash if last else "",
            "ledger_id": ledger.ledger_id()}


def _read_attestations(path: Path) -> tuple[list[Any], bool]:
    """``(records, torn_tail)`` of an attestation log; raises on a log that cannot be read."""
    return AttestationLog(path).scan()


def _is_ledger(rel: str) -> bool:
    return rel == _OPERATOR_LEDGER or (rel.startswith("tenants/") and rel.endswith(".db"))


def _write_manifest(
    out_dir: Path, pending_not_copied: int, findings: list[str] | None = None
) -> dict[str, Any]:
    files: dict[str, Any] = {}
    for path in sorted(p for p in out_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(out_dir).as_posix()
        if rel == MANIFEST_NAME:
            continue
        entry: dict[str, Any] = {"size": path.stat().st_size, "sha256": _sha256(path)}
        if _is_ledger(rel):
            entry.update(_ledger_facts(path))
        elif rel.startswith("attestations/") and rel.endswith(".jsonl"):
            try:
                entry["records"] = len(_read_attestations(path)[0])
            except Exception:  # noqa: BLE001 - a damaged log is recorded as unreadable
                entry["records"] = None
        files[rel] = entry
    accounts = sorted(_account_ids(out_dir / _ACCOUNTS)) if (out_dir / _ACCOUNTS).exists() else []
    manifest = {
        "format": MANIFEST_FORMAT,
        "taken_at": format_utc(utc_now()),
        "files": files,
        "accounts": accounts,
        "pending_keys_not_copied": pending_not_copied,
        # A snapshot of a source that already failed its own checks is still a snapshot
        # (it is evidence), but it must not read as a good backup.
        "degraded": bool(findings),
        "source_findings": list(findings or []),
        "note": ("Checksums, not signatures: anyone who can rewrite this file can rewrite the "
                 "backup. Keep its SHA-256 (printed by `backup`) somewhere the volume is not."),
    }
    path = out_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
    return manifest


def _source_findings(root: Path) -> list[str]:
    """Findings in a fresh snapshot: a ledger whose chain breaks, or an attestation log that
    claims more than its ledger holds (the only way a truncated tail shows)."""
    found: list[str] = []
    ledgers = [p for p in (root / _OPERATOR_LEDGER,) if p.is_file()]
    if (root / "tenants").is_dir():
        ledgers += sorted((root / "tenants").glob("*.db"))
    for path in ledgers:
        label = path.relative_to(root).as_posix()
        try:
            ok, problems = EvidenceLedger(path, mint_id=False).verify_chain()
        except Exception as exc:  # noqa: BLE001 - unreadable is a finding
            found.append(f"{label}: unreadable ({type(exc).__name__})")
            continue
        if not ok:
            found.extend(f"{label}: {p}" for p in problems)
    _check_attestation_logs(root, found, {})
    return found


def backup(data_dir: Path, out_dir: Path, *, ai_store: Path | None = None) -> list[str]:
    """Snapshot every database under ``data_dir`` into ``out_dir``. Returns names.

    Also writes the manifest (``MANIFEST_NAME``), which is not in the returned names. Each
    ledger is chain-verified and every attestation log is compared with its ledger after the
    snapshot; any finding is kept (``degraded: true``, ``source_findings``) rather than
    refusing, because a damaged source is still worth keeping. ``verify`` then fails it. The
    result is private to its owner and carries no unclaimed plaintext API keys. ``out_dir``
    must not exist or be empty (``FileExistsError``). ``ai_store`` names the ``/ai`` control-plane
    SQLite file to snapshot too (stored as ``ai-store.db``); a path that does not exist is an
    error, not a silent omission.
    """
    if ai_store is not None and not ai_store.is_file():
        raise FileNotFoundError(f"{ai_store} is not a file")
    if not data_dir.is_dir():
        raise FileNotFoundError(f"{data_dir} is not a directory")
    if out_dir.is_dir() and any(out_dir.iterdir()):
        # A snapshot written over an earlier one would list, and vouch for, files it did not
        # write. Take it into a directory of its own.
        raise FileExistsError(f"{out_dir} already holds files; back up into an empty directory")
    previous = os.umask(0o077)
    try:
        _private_dir(out_dir)
        taken: list[str] = []
        pending = 0
        # Attestation and supplier-feed logs FIRST, the ledgers after them. A log entry attests
        # to a record the ledger already holds, so a ledger snapshotted after the log copy always
        # contains everything the copied log refers to. The other way round, an anchor or a
        # counter-signature that lands between the two steps is in the log but not in the
        # snapshot, and the backup reads "N record(s) were removed after being attested": a
        # false alarm that also makes `restore` refuse a good backup.
        logs: list[str] = []
        for name in _LOG_DIRS:
            if (data_dir / name).is_dir():
                shutil.copytree(data_dir / name, out_dir / name, dirs_exist_ok=True)
                logs.append(f"{name}/")
        # Tenant ledgers first, the account list after them: a customer who signs up while the
        # backup runs then has an account row without a ledger (harmless), never a ledger in
        # the backup whose account is not (a spurious `belongs to no account`).
        tenants = data_dir / "tenants"
        if tenants.is_dir():
            for path in sorted(tenants.glob("*.db")):
                EvidenceLedger(path)    # gives a pre-id ledger its lineage id before the copy
                _snapshot(path, out_dir / "tenants" / path.name)
                taken.append(f"tenants/{path.name}")
        for name in (_ACCOUNTS, _OPERATOR_LEDGER):
            if (data_dir / name).exists():
                if name == _OPERATOR_LEDGER:
                    EvidenceLedger(data_dir / name)
                _snapshot(data_dir / name, out_dir / name)
                taken.append(name)
        if ai_store is not None:
            _snapshot(ai_store, out_dir / _AI_STORE)
            taken.append(_AI_STORE)
        if (out_dir / _ACCOUNTS).exists():
            pending = _strip_pending_keys(out_dir / _ACCOUNTS)
        taken.extend(logs)
        _tighten(out_dir)
        _write_manifest(out_dir, pending, _source_findings(out_dir))
        return taken
    finally:
        os.umask(previous)


#: SQLite's companion files. ``verify`` never opens a database *in place*: even ``mode=ro`` on
#: a WAL-mode file creates ``-wal`` and ``-shm`` beside it, and ``EvidenceLedger`` switches the
#: journal mode. Both are writes to the directory under test.
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")


class _Views:
    """Private, throwaway copies of the databases ``verify`` has to open.

    ``verify`` is read-only: it may not create, modify, rename or delete anything under the
    directory it checks (nor under ``--against-live``'s live volume). SQLite cannot open a
    WAL-mode file without writing beside it, so each database is copied, with its ``-wal`` and
    ``-journal`` sidecars when present, into a temporary directory outside the target, and
    opened there. SQLite recovers the sidecar's committed frames in the copy, so what is checked
    is what the next opener of the real file would see, including content that has not been
    checkpointed into the main file. ``-shm`` is a rebuildable index and is not copied.

    The copy is a point-in-time read of files that may still be written by a running service
    (``--live``); a database changing underneath the copy can read as damaged, which is a
    finding to re-run, not a pass.
    """

    def __init__(self, avoid: tuple[Path, ...]) -> None:
        self._dir = Path(tempfile.mkdtemp(prefix="nb-verify-"))
        resolved = self._dir.resolve()
        for root in avoid:
            if resolved == root.resolve() or root.resolve() in resolved.parents:
                shutil.rmtree(self._dir, ignore_errors=True)
                raise OSError(f"the temporary directory {resolved} is inside {root}; "
                              "set TMPDIR elsewhere so verify can stay read-only")
        self._made: dict[Path, Path] = {}

    def of(self, path: Path) -> Path:
        key = Path(path).resolve()
        if key not in self._made:
            slot = self._dir / str(len(self._made))
            slot.mkdir()
            dest = slot / key.name
            shutil.copyfile(key, dest)
            for suffix in ("-wal", "-journal"):
                side = key.with_name(key.name + suffix)
                if side.is_file():
                    shutil.copyfile(side, slot / (key.name + suffix))
            self._made[key] = dest
        return self._made[key]

    def close(self) -> None:
        shutil.rmtree(self._dir, ignore_errors=True)


def _use(views: _Views | None, path: Path) -> Path:
    return path if views is None else views.of(path)


def _sidecar_bytes(path: Path) -> dict[str, int]:
    """Non-empty ``-wal`` / ``-journal`` files beside ``path`` (name suffix -> size)."""
    out: dict[str, int] = {}
    for suffix in ("-wal", "-journal"):
        side = path.with_name(path.name + suffix)
        if side.is_file() and not side.is_symlink() and (size := side.stat().st_size) > 0:
            out[suffix] = size
    return out


def _integrity(path: Path, views: _Views | None = None) -> str:
    db = sqlite3.connect(_ro_uri(_use(views, path)), uri=True, timeout=30)
    try:
        return str(db.execute("PRAGMA integrity_check").fetchone()[0])
    finally:
        db.close()


def _account_ids(accounts: Path, views: _Views | None = None) -> set[str]:
    db = sqlite3.connect(_ro_uri(_use(views, accounts)), uri=True, timeout=30)
    try:
        return {r[0] for r in db.execute("SELECT id FROM accounts")}
    finally:
        db.close()


def _symlinks(root: Path) -> list[str]:
    """Every symbolic link under ``root`` (not followed), relative to it."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in (*dirnames, *filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                found.append(path.relative_to(root).as_posix())
    return sorted(found)


def _safe_rel(rel: object) -> bool:
    return (isinstance(rel, str) and bool(rel) and not rel.startswith("/")
            and ".." not in Path(rel).parts)


def _check_manifest(
    root: Path, manifest: dict[str, Any], known: set[str], allow_growth: bool,
    problems: list[str], views: _Views | None = None,
) -> None:
    """Compare what is on disk with what the backup recorded."""
    files = manifest.get("files")
    if not isinstance(files, dict):
        problems.append(f"{MANIFEST_NAME}: has no file list")
        return
    for rel, entry in sorted(files.items()):
        if not _safe_rel(rel) or not isinstance(entry, dict):
            problems.append(f"{MANIFEST_NAME}: refusing the entry {str(rel)[:60]!r}")
            continue
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel}: missing — the manifest lists it ({entry.get('size')} bytes)"
                            + (", a ledger" if _is_ledger(rel) else ""))
            continue
        size, digest = entry.get("size"), entry.get("sha256")
        if allow_growth and _is_ledger(rel):
            _ledger_only_grew(path, rel, entry, problems, views)
        elif allow_growth and rel.startswith(("attestations/", "supplier-feeds/")):
            # append-only logs: the recorded bytes must still be the start of the file
            if not isinstance(size, int) or path.stat().st_size < size \
                    or _sha256(path, size) != digest:
                problems.append(f"{rel}: is not an extension of the backed-up log (sha256 of "
                                "its first bytes differs, or it is shorter)")
        elif allow_growth:
            continue    # accounts.db and the like move on a live service; nothing to compare
        elif path.stat().st_size != size or _sha256(path) != digest:
            problems.append(f"{rel}: size or sha256 differs from the manifest — modified, "
                            "truncated or replaced since the backup was taken")
    listed = set(files)
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        if rel == MANIFEST_NAME or rel in listed:
            continue
        if any(rel.endswith(sfx) and rel[:-len(sfx)] in listed and rel[:-len(sfx)].endswith(".db")
               for sfx in _SIDECAR_SUFFIXES):
            # SQLite's own companion of a database the manifest lists (the service left it
            # when it opened the volume). Not an added file; its content is accounted for in
            # `verify` (a non-empty -wal / -journal is reported, and strict mode fails on it).
            continue
        if allow_growth and (rel.startswith(("tenants/", "attestations/", "supplier-feeds/"))
                             or rel == _OPERATOR_LEDGER):
            continue
        problems.append(f"{rel}: not in the manifest — added since the backup was taken")
    recorded = manifest.get("accounts")
    if isinstance(recorded, list) and known:
        gone = sorted(set(map(str, recorded)) - known)
        if gone:
            problems.append("accounts.db no longer lists account(s) the backup recorded: "
                            + ", ".join(gone[:5]))
        extra = sorted(known - set(map(str, recorded)))
        if extra and not allow_growth:
            problems.append("accounts.db lists account(s) the backup did not record: "
                            + ", ".join(extra[:5]))


def _ledger_only_grew(path: Path, rel: str, entry: dict[str, Any], problems: list[str],
                      views: _Views | None = None) -> None:
    try:
        ledger = EvidenceLedger(_use(views, path), mint_id=False)
        entries = ledger.entries()
    except Exception as exc:  # noqa: BLE001
        problems.append(f"{rel}: unreadable ({type(exc).__name__})")
        return
    recorded_id, now_id = entry.get("ledger_id"), ledger.ledger_id()
    if recorded_id and now_id and recorded_id != now_id:
        problems.append(f"{rel}: is a different ledger from the one backed up (ledger_id "
                        f"{now_id[:8]} where {recorded_id[:8]} was recorded) — replaced, "
                        "not grown")
    want = entry.get("entries")
    if not isinstance(want, int):
        return
    if len(entries) < want:
        problems.append(f"{rel}: holds {len(entries)} record(s); the backup held {want}. "
                        f"{want - len(entries)} record(s) were removed since.")
        return
    if want:
        at = {e.seq: e.link_hash for e in entries}.get(entry.get("head_seq"))
        if at != entry.get("head_link_hash"):
            problems.append(f"{rel}: the record at seq {entry.get('head_seq')} is not the one "
                            "the backup held — the history was rewritten")


def _safe_records(path: Path) -> list[Any]:
    try:
        return _read_attestations(path)[0] if path.is_file() else []
    except Exception:  # noqa: BLE001 - an unreadable log is reported by _check_attestation_logs
        return []


def _check_attestation_logs(
    root: Path, problems: list[str], records_seen: dict[str, int],
    views: _Views | None = None,
) -> None:
    """Every attestation log must still fit the ledger it was signed over.

    This compares what each record states (length, head, link hash) with the ledger beside
    it; the signing key is not in a backup, so it does not prove the log is genuine.
    """
    logs = root / "attestations"
    if not logs.is_dir():
        return
    for log_path in sorted(logs.glob("*.jsonl")):
        label = f"attestations/{log_path.name}"
        try:
            records, _torn = _read_attestations(log_path)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{label}: cannot be read as an attestation log "
                            f"({type(exc).__name__}) — the cross-check against its ledger "
                            "could not be made")
            continue
        records_seen[label] = len(records)
        mine = [r for r in records if r.basis is AttestationBasis.READ_FROM_LEDGER]
        if not mine:
            continue
        ledger_path = root / "tenants" / f"{log_path.stem}.db"
        if not ledger_path.is_file():
            problems.append(f"{label}: attests {mine[-1].ledger_length} record(s) of "
                            f"tenants/{log_path.stem}.db, which is missing — that evidence "
                            "was lost")
            continue
        try:
            found, _ = check_log_against_ledger(
                mine, EvidenceLedger(_use(views, ledger_path), mint_id=False), basis=AttestationBasis.READ_FROM_LEDGER,
                chain=False)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{label}: cross-check against its ledger failed "
                            f"({type(exc).__name__})")
            continue
        problems.extend(f"{label} vs tenants/{log_path.name[:-6]}.db: {p}" for p in found)


def _ledger_files(root: Path) -> dict[str, Path]:
    out = {_OPERATOR_LEDGER: root / _OPERATOR_LEDGER} if (root / _OPERATOR_LEDGER).is_file() else {}
    if (root / "tenants").is_dir():
        out.update({f"tenants/{p.name}": p for p in sorted((root / "tenants").glob("*.db"))})
    return out


def _check_lineage(root: Path, live: Path, problems: list[str],
                   views: _Views | None = None) -> None:
    """A restored ledger must not be a second writable copy of one the live volume holds.

    Same ``ledger_id`` and the same records up to the shorter of the two is one lineage
    (the restore is behind, or equal): fine to inspect, and say nothing. Same id and a
    different link hash at a shared position is a fork: both verify on their own, and
    neither can tell it lost.
    """
    held: dict[str, tuple[str, dict[int, str]]] = {}
    for rel, path in _ledger_files(live).items():
        try:
            lg = EvidenceLedger(_use(views, path), mint_id=False)
            if (lid := lg.ledger_id()):
                held[lid] = (rel, {e.seq: e.link_hash for e in lg.entries()})
        except Exception:  # noqa: BLE001, S112 - the live volume's own problem
            continue
    for rel, path in _ledger_files(root).items():
        try:
            lg = EvidenceLedger(_use(views, path), mint_id=False)
            lid = lg.ledger_id()
            mine = {e.seq: e.link_hash for e in lg.entries()}
        except Exception:  # noqa: BLE001, S112 - reported by check_ledger
            continue
        if lid and lid in held:
            where, theirs = held[lid]
            forked = sorted(q for q in mine.keys() & theirs.keys() if mine[q] != theirs[q])
            if forked:
                problems.append(
                    f"{rel}: carries ledger_id {lid[:8]}, which the live volume already holds "
                    f"as {where}, but the two disagree from seq {forked[0]} — one ledger forked "
                    "into two lineages. Only one may stay writable; the other's records after "
                    "the fork point are not in the first.")


def verify(
    root: Path, *, allow_growth: bool = False, live_dir: Path | None = None,
) -> dict[str, object]:
    """Check a data directory or backup. Never raises on a corrupt database.

    **Read-only.** Nothing under ``root`` (or ``live_dir``) is created, modified, renamed or
    deleted: databases are inspected through private copies (see :class:`_Views`). A restored
    volume the service has opened carries ``<db>-wal`` / ``<db>-shm`` files; for a database the
    manifest lists they are not "added files". A non-empty ``-wal`` or ``-journal`` is content
    the main file does not hold (and the manifest's hash does not cover): it is read, reported
    under ``sidecars``, a finding in strict mode and a note under ``--live``.

    ``status`` is ``ok`` (checked against the backup's manifest), ``failed`` (a finding) or
    ``unchecked`` (no manifest: nothing says nothing is missing). ``allow_growth`` is for a
    volume that has been running since the backup: ledgers and logs may be longer, never
    shorter or different.
    """
    views = _Views((root,) if live_dir is None else (root, live_dir))
    try:
        return _verify(root, allow_growth, live_dir, views)
    finally:
        views.close()


def _verify(root: Path, allow_growth: bool, live_dir: Path | None,
            views: _Views) -> dict[str, object]:
    problems: list[str] = []
    checked: dict[str, int] = {}

    def check_ledger(path: Path, label: str) -> None:
        try:
            if (res := _integrity(path, views)) != "ok":
                problems.append(f"{label}: SQLite integrity_check says {res}")
                return
            ledger = EvidenceLedger(views.of(path), mint_id=False)
            ok, found = ledger.verify_chain()
            checked[label] = len(ledger.entries())
            if not ok:
                problems.extend(f"{label}: {p}" for p in found)
        except Exception as exc:  # noqa: BLE001 - a corrupt file is a finding
            problems.append(f"{label}: unreadable ({type(exc).__name__})")

    for link in _symlinks(root):
        # `is_file()` and every open follow a link, so a file (or a whole directory) that lives
        # elsewhere would pass its hash and its database checks. A backup is regular files.
        problems.append(f"{link}: is a symbolic link; a backup holds regular files, and what "
                        "this points at is not part of the backup")

    accounts = root / _ACCOUNTS
    known: set[str] = set()
    if not accounts.exists():
        problems.append(f"{_ACCOUNTS} is missing — keys and entitlements cannot be restored")
    else:
        try:
            if (res := _integrity(accounts, views)) != "ok":
                problems.append(f"{_ACCOUNTS}: SQLite integrity_check says {res}")
            else:
                known = _account_ids(accounts, views)
                checked[_ACCOUNTS] = len(known)
        except Exception as exc:  # noqa: BLE001
            problems.append(f"{_ACCOUNTS}: unreadable ({type(exc).__name__})")

    if (root / _OPERATOR_LEDGER).exists():
        check_ledger(root / _OPERATOR_LEDGER, _OPERATOR_LEDGER)

    tenants = root / "tenants"
    if tenants.is_dir():
        for path in sorted(tenants.glob("*.db")):
            label = f"tenants/{path.name}"
            if not _TENANT.match(path.name):
                problems.append(f"{label}: not a tenant ledger name")
                continue
            if known and path.stem not in known:
                problems.append(f"{label}: belongs to no account in {_ACCOUNTS}")
            check_ledger(path, label)

    if (root / _AI_STORE).is_file():
        try:
            if (res := _integrity(root / _AI_STORE, views)) != "ok":
                problems.append(f"{_AI_STORE}: SQLite integrity_check says {res}")
            else:
                # closing(): `with connection` only ends a transaction, it never closes.
                ai_uri = _ro_uri(views.of(root / _AI_STORE))
                with contextlib.closing(sqlite3.connect(ai_uri, uri=True)) as ai_db:
                    checked[_AI_STORE] = int(
                        ai_db.execute("SELECT COUNT(*) FROM plans").fetchone()[0])
        except Exception as exc:  # noqa: BLE001 - a damaged store is a finding
            problems.append(f"{_AI_STORE}: unreadable ({type(exc).__name__})")

    for name in _LOG_DIRS:
        if (root / name).is_dir():
            checked[f"{name}/"] = sum(1 for _ in (root / name).glob("*"))

    attestation_records: dict[str, int] = {}
    _check_attestation_logs(root, problems, attestation_records, views)

    unchecked: list[str] = []
    manifest_path = root / MANIFEST_NAME
    manifest: dict[str, Any] | None = None
    if manifest_path.is_file():
        try:
            loaded = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(loaded, dict) or loaded.get("format") != MANIFEST_FORMAT:
                raise ValueError("unknown format")
            manifest = loaded
        except (OSError, ValueError) as exc:
            problems.append(f"{MANIFEST_NAME}: unreadable ({type(exc).__name__}: {exc})")
    else:
        unchecked.append(
            "no manifest (backup-manifest.json): this backup was taken by a build that did "
            "not write one, or is not a backup. Whatever is here is consistent as far as it "
            "can be read, but nothing says that no ledger or file is missing.")
    if manifest is not None:
        _check_manifest(root, manifest, known, allow_growth, problems, views)

    if manifest is not None and manifest.get("degraded"):
        found = manifest.get("source_findings")
        problems.extend(f"taken from a damaged source: {p}" for p in
                        (found if isinstance(found, list) and found else ["(no detail recorded)"]))
    if live_dir is not None:
        _check_lineage(root, live_dir, problems, views)

    sidecars: dict[str, dict[str, int]] = {}
    for db_path in [root / _ACCOUNTS, root / _AI_STORE, *_ledger_files(root).values()]:
        if db_path.is_file() and (found_side := _sidecar_bytes(db_path)):
            sidecars[db_path.relative_to(root).as_posix()] = found_side
    for rel_db, side in sorted(sidecars.items()):
        desc = ", ".join(f"{rel_db}{sfx} ({n} bytes)" for sfx, n in sorted(side.items()))
        if not allow_growth and manifest is not None:
            problems.append(
                f"{desc}: committed content beside a database the manifest lists. The manifest's "
                "sha256 covers the main file only, so this is a change since the backup that the "
                "hash cannot show (a service wrote to the volume, or it was not shut down "
                "cleanly). It was read, not ignored: the checks above include it.")

    not_established = [
        "That nothing was removed by someone who also rewrote the manifest and the "
        "attestation log: the manifest holds checksums, not signatures. Keep the "
        "manifest_sha256 that `backup` printed somewhere else.",
        "That an attestation log's records are genuine: the signing key is not in a "
        "backup. `assurance attest verify --ledger` with the public key does that.",
        "That this backup is recent: the files carry no proof of when they were taken.",
    ]
    bare = sorted(
        rel for rel in _ledger_files(root) if rel.startswith("tenants/")
        and not any(r.basis is AttestationBasis.READ_FROM_LEDGER
                    for r in _safe_records(root / "attestations" / f"{Path(rel).stem}.jsonl")))
    if bare:
        not_established.append(
            "A ledger with no attestation log cannot be shown complete: a hash chain "
            "verifies after records are removed from its end. No attestation log covers "
            + ", ".join(bare[:5]) + (" and others" if len(bare) > 5 else "") + ".")

    if sidecars:
        not_established.append(
            "Write-ahead-log / journal content beside "
            + ", ".join(sorted(sidecars)) + ": read through a private copy so that nothing "
            "under the target changed, and included in the checks above, but not covered by "
            "the manifest's sha256 (it hashes the main file). Stop the service and let it "
            "checkpoint, or re-take the backup, to establish the main files alone.")
    if allow_growth:
        not_established.append(
            "A consistent view of a volume a service is still writing: each database is read "
            "from a point-in-time copy. A copy taken mid-write that reads as damaged is a "
            "reason to run again, not a conclusion.")

    status = "failed" if problems else ("ok" if manifest is not None else "unchecked")
    return {
        "ok": status == "ok",
        "status": status,
        "checked": checked,
        "sidecars": sidecars,
        "attestation_records": attestation_records,
        "problems": problems,
        "unchecked": unchecked,
        "not_established": not_established,
    }


class RestoreRefused(Exception):  # noqa: N818 - a refusal, not an error
    """A restore was not performed. Nothing was written to the target."""

    def __init__(self, reason: str, problems: list[str] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.problems = list(problems or [])


_VOID_REASON = ("voided by restore: the backup is older than this plan's last known state, so "
                "the write it describes may already have run. Propose it again if it is still "
                "wanted.")


def _void_unresolved_plans(store: Path) -> dict[str, int]:
    """``pending_approval`` -> ``denied`` and ``approved`` (in flight) -> ``failed``, in place."""
    db = sqlite3.connect(store, isolation_level=None)
    try:
        db.execute("BEGIN IMMEDIATE")
        now = format_utc(utc_now())
        denied = db.execute(
            "UPDATE plans SET status='denied', decided_by='restore_check', decided_at=?, "
            "deny_reason=? WHERE status='pending_approval'", (now, _VOID_REASON)).rowcount
        failed = db.execute(
            "UPDATE plans SET status='failed', decided_at=? WHERE status='approved'",
            (now,)).rowcount
        db.execute("COMMIT")
        res = db.execute("PRAGMA integrity_check").fetchone()[0]
        if res != "ok":
            raise RestoreRefused(f"{_AI_STORE} failed its integrity check after the restore: {res}")
        return {"pending_to_denied": int(denied), "approved_to_failed": int(failed)}
    finally:
        db.close()


def restore(backup_dir: Path, target: Path) -> dict[str, Any]:
    """Put a verified backup back as a NEW data directory. Raises :class:`RestoreRefused`.

    Refuses, writing nothing: a backup that does not verify strictly (``failed`` or
    ``unchecked``); a target that exists and is not an empty directory (so a live volume, a live
    ledger or an earlier restore is never overwritten, merged into or deleted); a target that is a
    symlink or overlaps the backup. The copy is staged in a private directory beside the target,
    checked against the manifest again, and renamed into place only if it verifies, so a crash
    leaves either the empty target or the finished one.
    """
    backup_dir = Path(backup_dir)
    target = Path(target)
    if not backup_dir.is_dir():
        raise RestoreRefused(f"{backup_dir} is not a directory")
    if target.is_symlink():
        raise RestoreRefused(f"{target} is a symbolic link; restore into a real, new directory")
    src, dst = backup_dir.resolve(), target.resolve()
    if src == dst or src in dst.parents or dst in src.parents:
        raise RestoreRefused("the backup and the target overlap; restore into a separate directory")
    if target.exists():
        if not target.is_dir():
            raise RestoreRefused(f"{target} exists and is not a directory")
        if any(target.iterdir()):
            raise RestoreRefused(
                f"{target} is not empty: refusing to restore over (or into) existing data. "
                "A restore never overwrites a live ledger; restore to a new directory, verify "
                "it, then switch the service over.")
    first = verify(backup_dir)
    if first["status"] != "ok":
        detail = first["problems"] or first["unchecked"]
        raise RestoreRefused(
            f"the backup does not verify (status {first['status']}); nothing was restored",
            [str(p) for p in detail])  # type: ignore[attr-defined]

    target.parent.mkdir(parents=True, exist_ok=True)
    previous = os.umask(0o077)
    stage = Path(tempfile.mkdtemp(prefix=".restore-", dir=target.parent))
    try:
        os.chmod(stage, 0o700)
        shutil.copytree(backup_dir, stage, dirs_exist_ok=True, copy_function=shutil.copy2,
                        symlinks=True)
        _tighten(stage)
        second = verify(stage)
        if second["status"] != "ok":
            raise RestoreRefused("the staged copy does not verify; nothing was restored",
                                 [str(p) for p in second["problems"]])  # type: ignore[attr-defined]
        voided: dict[str, int] = {}
        if (stage / _AI_STORE).is_file():
            voided = _void_unresolved_plans(stage / _AI_STORE)
        if target.exists():
            target.rmdir()  # empty, checked above
        os.rename(stage, target)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        os.umask(previous)
    return {
        "restored_to": str(target),
        "checked": second["checked"],
        "manifest_sha256": _sha256(target / MANIFEST_NAME),
        "ai_plans_voided": voided,
        "note": ("Verified against the backup's manifest before the move. ai-store.db, if "
                 "present, was changed afterwards (unresolved plans voided), so a later strict "
                 "`verify` reports it. Unclaimed checkout keys are not in a backup: re-issue "
                 "them. Run `verify --against-live` against any surviving volume before "
                 "starting the service."),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if argv[:1] == ["restore"] and len(argv) == 3:
            try:
                print(json.dumps(restore(Path(argv[1]), Path(argv[2])), indent=2))
            except RestoreRefused as refused:
                print(json.dumps({"restored": False, "reason": refused.reason,
                                  "problems": refused.problems}, indent=2))
                return 1
            return 0
        ai_store: Path | None = None
        if argv[:1] == ["backup"] and "--ai-store" in argv:
            k = argv.index("--ai-store")
            if k + 1 >= len(argv):
                print(__doc__, file=sys.stderr)
                return 2
            ai_store = Path(argv[k + 1])
            del argv[k:k + 2]
        if len(argv) == 3 and argv[0] == "backup":
            out = Path(argv[2])
            names = backup(Path(argv[1]), out, ai_store=ai_store)
            digest = _sha256(out / MANIFEST_NAME)
            degraded = bool(json.loads((out / MANIFEST_NAME).read_text()).get("degraded"))
            if sys.stdout is None:
                # `>&-`: the digest is printed once and nowhere else; say so rather than lose it.
                print(f"backup taken at {out} but stdout is closed, so its manifest digest was "
                      f"not printed. manifest_sha256: {digest}", file=sys.stderr)
                return 2
            print(json.dumps({"backed_up": names, "manifest": MANIFEST_NAME,
                              "degraded": degraded,
                              "manifest_sha256": digest,
                              "note": "unclaimed checkout keys are not copied: re-issue after a "
                                      "restore"}, indent=2))
            return 1 if degraded else 0
        live = "--live" in argv
        rest = [a for a in argv if a != "--live"]
        live_dir: Path | None = None
        if "--against-live" in rest:
            k = rest.index("--against-live")
            if k + 1 >= len(rest):
                print(__doc__, file=sys.stderr)
                return 2
            live_dir = Path(rest[k + 1])
            del rest[k:k + 2]
        if len(rest) == 2 and rest[0] == "verify":
            if not Path(rest[1]).is_dir():
                # Nothing was looked at: "could not run", not a failed check (1).
                print(f"could not run: {rest[1]} is not a directory", file=sys.stderr)
                return 2
            result = verify(Path(rest[1]), allow_growth=live, live_dir=live_dir)
            print(json.dumps(result, indent=2))
            return {"ok": 0, "failed": 1}.get(str(result["status"]), 3)
    except (OSError, sqlite3.Error) as exc:
        print(f"could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
