"""Custody of bound-connection credentials: shared across workers, encrypted, revocable, rollback-proof.

A bound ``/ai`` connection (``POST /ai/connections``) used to keep its password only in the
``PostgresAdapter`` of the worker process that bound it. Under ``uvicorn --workers N`` the other
workers could not use it, a rotation reached one worker only, and a restore of an older backup
could bring back a revoked connection. This module is the answer, and where a guarantee cannot be
established it **refuses** (fails closed) instead of pretending.

Custody modes (``CustodyConfig.mode``)
--------------------------------------
``shared_encrypted``
    The credential is sealed with AES-256-GCM and stored as ciphertext in the ``credentials`` table
    of the ``/ai`` store. Every worker reads the shared record on use, decrypts in memory and builds
    its own adapter. Needs BOTH a key source and an anti-rollback journal (below).
``process_local``
    The previous behaviour, kept only as an explicit single-worker opt-in
    (``NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS=single-worker``, refused if ``WEB_CONCURRENCY`` > 1).
    Nothing is stored; the connection is live only in the process that bound it.
``unavailable``
    Nothing configured (or something configured wrongly). Binding and rotating a connection answer
    **503** ``credential_custody_unconfigured`` with the reason. Revoking and deleting always work.

What protects the credential
----------------------------
* **Authenticated encryption.** AES-256-GCM (``cryptography``), a fresh random 96-bit nonce per
  record, and associated data binding the ciphertext to the tenant, the connection id, the
  credential version, the key id and a digest of the target (host, port, database, ssl mode). A
  ciphertext moved to another tenant or connection, replayed as another version, or pointed at a
  different host fails authentication and is never used.
* **The key is never in the database.** It comes from ``NEURALBRIDGE_CREDENTIAL_KEYS`` (inline,
  e.g. a KMS-issued data key injected as a secret) or ``NEURALBRIDGE_CREDENTIAL_KEY_FILE`` (mode
  0600, outside the ``/ai`` store's directory, which is what gets backed up). Keys are versioned by
  id (``id:base64(32 bytes)``); ``NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY`` names the one new records are
  sealed with. Rotation: add the new key, make it active, restart, run
  ``python -m neuralbridge.ai.credentials reencrypt``, then remove the old key once ``status``
  shows nothing sealed under it.
* **Propagation.** The connection row (status, ``cred_version``) is read from the shared store on
  every use. A revoked connection is refused and its local adapter dropped; a worker whose adapter
  was built from an older ``cred_version`` rebuilds it from the current ciphertext.
* **Anti-rollback.** ``NEURALBRIDGE_CREDENTIAL_JOURNAL`` names an append-only, hash-chained file
  kept OUTSIDE the ``/ai`` store's directory (so ``restore_check`` and any file-level restore of the
  store cannot rewind it). Every create/rotate/revoke/delete is written to it BEFORE the store
  changes. On every use the store's record is checked against it: revoked or deleted in the journal
  means refused, and a ``cred_version`` below the journal's high-water mark means refused. The
  journal's identity is also recorded in the store, so a lost or replaced journal fails closed
  rather than silently disarming the check.
* **Retention.** Only the current ciphertext of a connection is kept. Revoke and delete remove it
  in the same transaction as the status change, and the store runs with ``secure_delete`` so the
  freed pages are zeroed. Backups taken earlier still hold earlier ciphertext, sealed under keys you
  control: retiring those keys makes them unreadable.

What this does not establish (documented in ``docs/platform.md``)
-----------------------------------------------------------------
* The journal protects against restoring the STORE. If the journal lives on the same volume as the
  store and that whole volume is rolled back (a provider snapshot restore), both rewind together.
  ``status`` reports ``journal.same_device``; put the journal on separate storage to close that.
* It is a hash chain, not a signature: someone who can rewrite the journal can recompute it. It is
  a guard against operational rollback, not against a hostile operator of the control plane.
* All workers must share one filesystem for the store and one for the journal (as the store
  already requires). A network filesystem without working locks is not supported.
* The decrypted password exists in the memory of every worker that uses the connection.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from neuralbridge.ai.store import REVOKED, AiStore, ConnectionRecord, CredentialRow

if TYPE_CHECKING:
    from neuralbridge.core.router import AdapterRegistry

logger = structlog.get_logger(__name__)

KEYS_ENV = "NEURALBRIDGE_CREDENTIAL_KEYS"
KEY_FILE_ENV = "NEURALBRIDGE_CREDENTIAL_KEY_FILE"
ACTIVE_KEY_ENV = "NEURALBRIDGE_CREDENTIAL_ACTIVE_KEY"
JOURNAL_ENV = "NEURALBRIDGE_CREDENTIAL_JOURNAL"
PROCESS_LOCAL_ENV = "NEURALBRIDGE_AI_PROCESS_LOCAL_CREDENTIALS"
PROCESS_LOCAL_VALUE = "single-worker"

SHARED = "shared_encrypted"
PROCESS_LOCAL = "process_local"
UNAVAILABLE = "unavailable"

#: ``ConnectionRecord.custody`` values.
CUSTODY_VAULT = "vault"
CUSTODY_PROCESS_LOCAL = "process_local"

#: A long-lived worker re-reads and re-verifies the whole journal at least this often (seconds), so an
#: in-place edit of a line it already parsed is noticed even if the file also grew.
RECHECK_INTERVAL_S = 30.0

_KEY_ID = re.compile(r"^[A-Za-z0-9._-]{1,32}$")
_META_JOURNAL_ID = "credential_journal_id"
_GENESIS = "0" * 64


class CustodyError(Exception):
    """A custody refusal. ``status_code`` maps to HTTP (409 wrong state, 503 not configured or not
    safe to serve, 404 gone). ``detail`` never carries a key, a password, a path or driver text."""

    def __init__(self, status_code: int, code: str, detail: str) -> None:
        self.status_code = status_code
        self.code = code
        self.detail = detail
        super().__init__(detail)


# --------------------------------------------------------------------------------------------
# key ring
# --------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class KeyRing:
    """Versioned 256-bit keys. ``repr`` shows ids only."""

    keys: Mapping[str, bytes] = field(repr=False)
    active_id: str

    def __repr__(self) -> str:
        return f"KeyRing(ids={sorted(self.keys)}, active={self.active_id!r})"

    def seal(self, plaintext: bytes, aad: bytes) -> tuple[str, bytes, bytes]:
        nonce = os.urandom(12)
        return self.active_id, nonce, AESGCM(self.keys[self.active_id]).encrypt(nonce, plaintext, aad)

    def open(self, key_id: str, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        key = self.keys.get(key_id)
        if key is None:
            raise CustodyError(
                503, "credential_unreadable",
                f"The credential is sealed under key '{key_id}', which is not in the configured key ring.")
        try:
            return bytes(AESGCM(key).decrypt(nonce, ciphertext, aad))
        except InvalidTag as exc:
            raise CustodyError(
                503, "credential_unreadable",
                "The stored credential failed authentication (wrong key, or the record was altered or "
                "moved); it was not used.") from exc


def _decode_key(raw: str) -> bytes:
    text = raw.strip()
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            key = decoder(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError):
            continue
        if len(key) == 32:
            return key
    raise ValueError("a credential key must be exactly 32 random bytes, base64-encoded")


def _parse_entries(blob: str, source: str) -> dict[str, bytes]:
    keys: dict[str, bytes] = {}
    for entry in re.split(r"[,\n]", blob):
        entry = entry.strip()
        if not entry or entry.startswith("#"):
            continue
        key_id, sep, material = entry.partition(":")
        if not sep or not _KEY_ID.match(key_id.strip()):
            raise ValueError(f"{source}: entries are 'id:base64key' with an id of 1-32 [A-Za-z0-9._-]")
        try:
            keys[key_id.strip()] = _decode_key(material)
        except ValueError as exc:
            raise ValueError(f"{source}: key '{key_id.strip()}': {exc}") from exc
    return keys


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def load_keyring(env: Mapping[str, str], store_dir: Path | None) -> KeyRing | None:
    """The configured key ring, ``None`` if no key source is configured at all.

    Raises ``ValueError`` (message safe to show) for a source that is configured but unusable: bad
    base64, wrong length, a key file readable by group/other or kept inside the store's directory,
    or an active id that names no key."""
    keys: dict[str, bytes] = {}
    configured = False
    inline = env.get(KEYS_ENV, "").strip()
    if inline:
        configured = True
        keys.update(_parse_entries(inline, KEYS_ENV))
    key_file = env.get(KEY_FILE_ENV, "").strip()
    if key_file:
        configured = True
        path = Path(key_file)
        if store_dir is not None and _inside(path, store_dir):
            raise ValueError(
                f"{KEY_FILE_ENV} is inside the /ai store's directory; a key kept beside the ciphertext "
                "is backed up and restored with it. Keep it elsewhere.")
        try:
            mode = path.stat().st_mode
            blob = path.read_text()
        except OSError as exc:
            raise ValueError(f"{KEY_FILE_ENV} cannot be read ({type(exc).__name__})") from exc
        if mode & 0o077:
            raise ValueError(f"{KEY_FILE_ENV} must not be readable by group or others (chmod 600)")
        keys.update(_parse_entries(blob, KEY_FILE_ENV))
    if not configured:
        return None
    if not keys:
        raise ValueError("a credential key source is configured but holds no key")
    active = env.get(ACTIVE_KEY_ENV, "").strip()
    if not active:
        if len(keys) != 1:
            raise ValueError(f"{ACTIVE_KEY_ENV} must name the active key when more than one key is configured")
        active = next(iter(keys))
    if active not in keys:
        raise ValueError(f"{ACTIVE_KEY_ENV} names a key that is not configured")
    return KeyRing(keys=keys, active_id=active)


# --------------------------------------------------------------------------------------------
# the anti-rollback journal
# --------------------------------------------------------------------------------------------
@dataclass
class JournalState:
    """What the journal knows about one connection."""

    min_version: int = 0
    revoked: bool = False
    deleted: bool = False
    owner: str = ""


def _line_hash(body: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class RollbackJournal:
    """Append-only, hash-chained record of credential lifecycle events, outside the restored data set.

    One writer at a time (``flock``), many readers; a line is one ``os.write`` on an ``O_APPEND``
    descriptor followed by ``fsync``. Readers cache the parsed state and extend it incrementally."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._offset = 0
        self._inode: int | None = None
        self._last_hash = _GENESIS
        self._seq = 0
        self._journal_id = ""
        self._state: dict[str, JournalState] = {}
        self._mtime = 0
        self._verified_at = 0.0

    # -- reading ------------------------------------------------------
    def _reset(self) -> None:
        self._offset, self._last_hash, self._seq, self._journal_id, self._state = 0, _GENESIS, 0, "", {}
        self._mtime = 0

    @staticmethod
    def _apply(state: dict[str, JournalState], entry: dict[str, Any]) -> None:
        st = state.setdefault(entry["connection_id"], JournalState(owner=entry.get("owner", "")))
        op, version = entry["op"], int(entry.get("version", 0))
        if op in ("create", "rotate"):
            st.min_version = max(st.min_version, version)
        elif op == "revoke":
            st.revoked = True
        elif op == "delete":
            st.deleted = True

    def _refresh(self) -> None:
        """Bring the cached state up to the file. Raises ``CustodyError`` if the chain is broken."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._reset()
            self._inode = None
            return
        except OSError as exc:
            raise CustodyError(503, "credential_journal_unavailable",
                               f"The anti-rollback journal cannot be read ({type(exc).__name__}).") from exc
        now = time.monotonic()
        # Re-verify from the start when the file was replaced, shrank, was modified without growing
        # (an in-place edit of already-parsed lines) or has not been fully checked for a while;
        # otherwise only the bytes appended since the last look are parsed.
        if (self._inode != st.st_ino or st.st_size < self._offset
                or (st.st_size == self._offset and st.st_mtime_ns != self._mtime)
                or now - self._verified_at > RECHECK_INTERVAL_S):
            self._reset()
            self._inode = st.st_ino
            self._verified_at = now
        self._mtime = st.st_mtime_ns
        if st.st_size == self._offset:
            return
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                data = fh.read()
        except OSError as exc:
            raise CustodyError(503, "credential_journal_unavailable",
                               f"The anti-rollback journal cannot be read ({type(exc).__name__}).") from exc
        consumed = 0
        while True:
            end = data.find(b"\n", consumed)
            if end < 0:
                break  # a line still being written: not part of the state yet
            raw = data[consumed:end]
            consumed = end + 1
            try:
                entry = json.loads(raw)
                claimed = entry.pop("hash")
                if entry["prev"] != self._last_hash or entry["seq"] != self._seq + 1 \
                        or _line_hash(entry) != claimed:
                    raise ValueError("chain")
            except (ValueError, KeyError, TypeError) as exc:
                raise CustodyError(
                    503, "credential_journal_corrupt",
                    "The anti-rollback journal failed its integrity check; no stored credential is served "
                    "until an operator has examined it.") from exc
            if self._seq == 0:
                self._journal_id = claimed
            self._seq += 1
            self._last_hash = claimed
            self._apply(self._state, entry)
        self._offset += consumed

    def snapshot(self) -> tuple[str, dict[str, JournalState], int]:
        """``(journal_id, state_by_connection, entries)``; ``journal_id`` is ``''`` for an empty/missing journal."""
        with self._lock:
            self._refresh()
            return self._journal_id, {k: JournalState(**vars(v)) for k, v in self._state.items()}, self._seq

    def state_of(self, connection_id: str) -> JournalState:
        _, state, _ = self.snapshot()
        return state.get(connection_id, JournalState())

    # -- writing ------------------------------------------------------
    def append(self, op: str, *, connection_id: str, owner: str, version: int = 0) -> str:
        """Durably record an event; returns the journal id. Raises ``CustodyError`` if it cannot."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
        except OSError as exc:
            raise CustodyError(503, "credential_journal_unavailable",
                               f"The anti-rollback journal cannot be written ({type(exc).__name__}).") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            with self._lock:
                self._refresh()  # under the file lock nobody else appends: the tail is final
                body = {
                    "seq": self._seq + 1, "at": datetime.now(UTC).isoformat(), "op": op,
                    "connection_id": connection_id, "owner": owner, "version": version,
                    "prev": self._last_hash,
                }
                digest = _line_hash(body)
                line = json.dumps({**body, "hash": digest}, sort_keys=True, separators=(",", ":")) + "\n"
                os.write(fd, line.encode())
                os.fsync(fd)
                self._refresh()
                return self._journal_id
        except OSError as exc:
            raise CustodyError(503, "credential_journal_unavailable",
                               f"The anti-rollback journal cannot be written ({type(exc).__name__}).") from exc
        finally:
            os.close(fd)  # also releases the flock


_JOURNALS: dict[str, RollbackJournal] = {}
_JOURNALS_LOCK = threading.Lock()


def journal_for(path: Path) -> RollbackJournal:
    """One cached reader/writer per journal path in this process."""
    key = str(path)
    with _JOURNALS_LOCK:
        if key not in _JOURNALS:
            _JOURNALS[key] = RollbackJournal(path)
        return _JOURNALS[key]


# --------------------------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------------------------
def declared_workers(env: Mapping[str, str] | None = None) -> int:
    """The worker count the deployment DECLARES (``WEB_CONCURRENCY``); ``1`` when absent. uvicorn's
    ``--workers`` flag is not visible to the process, which is why the single-worker mode is an
    explicit opt-in and not an inference."""
    raw = (os.environ if env is None else env).get("WEB_CONCURRENCY", "").strip()
    try:
        return max(1, int(raw)) if raw else 1
    except ValueError:
        return 1


@dataclass(frozen=True)
class CustodyConfig:
    mode: str
    reason: str = ""
    keyring: KeyRing | None = None
    journal: RollbackJournal | None = None

    @classmethod
    def from_env(cls, store_path: Path, env: Mapping[str, str] | None = None) -> CustodyConfig:
        env = os.environ if env is None else env
        store_dir = store_path.parent if str(store_path) != ":memory:" else None
        try:
            ring = load_keyring(env, store_dir)
        except ValueError as exc:
            return cls(UNAVAILABLE, f"credential key source is unusable: {exc}")
        journal_raw = env.get(JOURNAL_ENV, "").strip()
        if ring is None:
            if env.get(PROCESS_LOCAL_ENV, "").strip() == PROCESS_LOCAL_VALUE:
                if declared_workers(env) > 1:
                    return cls(UNAVAILABLE, f"{PROCESS_LOCAL_ENV}={PROCESS_LOCAL_VALUE} is refused because "
                                            f"WEB_CONCURRENCY={declared_workers(env)}: a process-local credential "
                                            "is invisible to the other workers.")
                return cls(PROCESS_LOCAL, "process-local credentials (single worker only), as explicitly requested")
            return cls(UNAVAILABLE, f"no credential key is configured ({KEYS_ENV} or {KEY_FILE_ENV}), so a "
                                    "bound credential cannot be stored safely for all workers. Configure a key "
                                    f"and {JOURNAL_ENV}, or for ONE worker only set "
                                    f"{PROCESS_LOCAL_ENV}={PROCESS_LOCAL_VALUE}.")
        if not journal_raw:
            return cls(UNAVAILABLE, f"{JOURNAL_ENV} is not set: without an anti-rollback record kept outside "
                                    "the /ai store, a restore of an older backup could bring back a revoked "
                                    "credential, so credentials are not stored.", keyring=ring)
        journal_path = Path(journal_raw)
        if store_dir is not None and _inside(journal_path, store_dir):
            return cls(UNAVAILABLE, f"{JOURNAL_ENV} is inside the /ai store's directory; it would be backed up "
                                    "and restored with the data it guards. Keep it elsewhere.", keyring=ring)
        return cls(SHARED, "credentials are sealed (AES-256-GCM) in the /ai store and shared by all workers",
                   keyring=ring, journal=journal_for(journal_path))


# --------------------------------------------------------------------------------------------
# the vault
# --------------------------------------------------------------------------------------------
def _device_of(path: Path) -> int:
    """The device a path lives (or would live) on: that of its nearest existing ancestor."""
    probe = path.resolve()
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    return probe.stat().st_dev


def target_digest(config: Mapping[str, Any]) -> str:
    """Digest of where the credential may be sent; part of the AEAD associated data."""
    parts = [str(config.get(k, "")) for k in ("host", "port", "database", "ssl_mode")]
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


def _aad(owner: str, connection_id: str, version: int, key_id: str, target: str) -> bytes:
    return "\x1e".join(("neuralbridge/credential/v1", owner, connection_id, str(version), key_id, target)).encode()


class CredentialVault:
    """The one place credentials are sealed, opened, checked against the journal and loaded."""

    def __init__(self, store: AiStore, config: CustodyConfig) -> None:
        self.store = store
        self.config = config

    @property
    def mode(self) -> str:
        return self.config.mode

    # -- availability -------------------------------------------------
    def require_available(self) -> str:
        """The mode to bind/rotate under, or a 503 explaining why none is safe."""
        if self.config.mode == UNAVAILABLE:
            raise CustodyError(503, "credential_custody_unconfigured", self.config.reason)
        return self.config.mode

    @property
    def journal(self) -> RollbackJournal:
        return self._journal()

    def _journal(self) -> RollbackJournal:
        if self.config.journal is None:
            raise CustodyError(503, "credential_custody_unconfigured", self.config.reason)
        return self.config.journal

    def _ring(self) -> KeyRing:
        if self.config.keyring is None:
            raise CustodyError(503, "credential_custody_unconfigured", self.config.reason)
        return self.config.keyring

    # -- seal / open --------------------------------------------------
    def seal(self, *, owner: str, connection_id: str, version: int, target: Mapping[str, Any],
             user: str, password: str) -> CredentialRow:
        ring = self._ring()
        payload = json.dumps({"user": user, "password": password}, separators=(",", ":")).encode()
        key_id, nonce, ct = ring.seal(
            payload, _aad(owner, connection_id, version, ring.active_id, target_digest(target)))
        return CredentialRow(connection_id=connection_id, version=version, owner=owner, key_id=key_id,
                             nonce=nonce, ciphertext=ct)

    def open(self, row: CredentialRow, record: ConnectionRecord) -> dict[str, str]:
        """Decrypt ``row`` for ``record``; the associated data comes from the RECORD, not the row."""
        plain = self._ring().open(
            row.key_id, row.nonce, row.ciphertext,
            _aad(record.owner, record.id, row.version, row.key_id, target_digest(record.config)))
        data = json.loads(plain)
        return {"user": str(data["user"]), "password": str(data["password"])}

    # -- journal-backed guard ----------------------------------------
    def record_journal_id(self, journal_id: str) -> None:
        """Remember in the store which journal guards it (first writer wins)."""
        self.store.set_meta_if_absent(_META_JOURNAL_ID, journal_id)

    def _check_journal_identity(self, journal_id: str) -> None:
        expected = self.store.get_meta(_META_JOURNAL_ID)
        if expected is not None and journal_id != expected:
            raise CustodyError(
                503, "credential_journal_mismatch",
                "The anti-rollback journal is not the one this store was created with (lost, replaced or "
                "emptied); stored credentials are not served until an operator has examined it.")

    def authorize(self, record: ConnectionRecord) -> None:
        """Raise unless ``record`` may be used now. Reads the shared store's record (the caller passes
        a fresh one) and the journal, so it holds in every worker and after a restore."""
        if record.status == REVOKED:
            raise CustodyError(409, "revoked", f"Connection '{record.id}' has been revoked and cannot be used. "
                                               "Revocation is permanent: bind a new connection with POST /ai/connections.")
        if record.custody != CUSTODY_VAULT:
            return
        if self.config.mode != SHARED:
            raise CustodyError(503, "credential_custody_unconfigured", self.config.reason)
        journal_id, state, _ = self._journal().snapshot()
        self._check_journal_identity(journal_id)
        st = state.get(record.id)
        if st is None:
            raise CustodyError(
                409, "credential_unrecorded",
                f"Connection '{record.id}' is not in the anti-rollback journal (restored into a different "
                "installation?); it was not used. Rotate it to re-supply its credentials.")
        if st.revoked or st.deleted:
            # The journal outranks the store: a restore resurrected a connection that was revoked or deleted.
            self.reconcile_one(record, st)
            raise CustodyError(409, "revoked", f"Connection '{record.id}' has been revoked and cannot be used. "
                                               "Revocation is permanent: bind a new connection with POST /ai/connections.")
        if record.cred_version < st.min_version:
            raise CustodyError(
                409, "credential_rolled_back",
                f"Connection '{record.id}' holds credential version {record.cred_version}, but this "
                f"installation has already issued version {st.min_version} (an older backup was restored, or a "
                "rotation is committing). The old credential was not used; rotate the connection to continue.")

    def reconcile_one(self, record: ConnectionRecord, st: JournalState) -> None:
        """Apply a journal tombstone to the store (revoke, or delete); idempotent."""
        if st.deleted:
            self.store.delete_connection(record.id)
        elif record.status != REVOKED:
            self.store.revoke_connection(record.id, by="system:journal-reconcile")
        logger.warning("ai_credential_journal_reconciled", connection_id=record.id,
                       revoked=st.revoked, deleted=st.deleted)

    def reconcile_all(self) -> dict[str, int]:
        """Re-apply every revoke/delete in the journal to the store (after a restore)."""
        _, state, _ = self._journal().snapshot()
        applied = {"revoked": 0, "deleted": 0}
        for rec in self.store.list_connections():
            st = state.get(rec.id)
            if rec.custody != CUSTODY_VAULT or st is None:
                continue
            if st.deleted:
                self.store.delete_connection(rec.id)
                applied["deleted"] += 1
            elif st.revoked and rec.status != REVOKED:
                self.store.revoke_connection(rec.id, by="system:journal-reconcile")
                applied["revoked"] += 1
        return applied

    def next_version(self, record: ConnectionRecord) -> int:
        """The version a rotation installs: above the store's AND the journal's high-water mark."""
        high = self._journal().state_of(record.id).min_version
        return max(record.cred_version, high) + 1

    # -- loading into a worker ---------------------------------------
    def usable(self, record: ConnectionRecord) -> bool:
        """Could a worker use this connection right now? (Does not build an adapter.)"""
        try:
            self.authorize(record)
            if record.custody != CUSTODY_VAULT:
                return False
            row = self.store.get_credential(record.id)
            if row is None or row.version != record.cred_version:
                return False
            self.open(row, record)
            return True
        except CustodyError:
            return False

    def load_adapter_config(self, record: ConnectionRecord) -> dict[str, Any]:
        """Decrypted adapter config for a vault connection, after every check."""
        self.authorize(record)
        row = self.store.get_credential(record.id)
        if row is None:
            raise CustodyError(409, "credential_missing",
                               f"Connection '{record.id}' has no stored credential; rotate it to re-supply one.")
        if row.version != record.cred_version or row.owner != record.owner:
            raise CustodyError(409, "credential_rolled_back",
                               f"Connection '{record.id}' changed while it was being loaded; retry.")
        secret = self.open(row, record)
        cfg = record.config
        return {"host": cfg["host"], "port": cfg["port"], "database": cfg["database"],
                "ssl_mode": cfg.get("ssl_mode", "prefer"), **secret}

    # -- key rotation -------------------------------------------------
    def reencrypt(self) -> dict[str, int]:
        """Re-seal every stored credential under the ACTIVE key (same version, fresh nonce).

        Needs the old keys in the ring. A row that cannot be opened is counted, never skipped
        silently, and left as it is."""
        ring = self._ring()
        counts = {"resealed": 0, "already_current": 0, "failed": 0}
        for row in self.store.list_credentials():
            if row.key_id == ring.active_id:
                counts["already_current"] += 1
                continue
            record = self.store.get_connection(row.connection_id)
            try:
                if record is None:
                    raise CustodyError(409, "orphan", "no connection")
                secret = self.open(row, record)
                new = self.seal(owner=record.owner, connection_id=record.id, version=row.version,
                                target=record.config, user=secret["user"], password=secret["password"])
                if not self.store.reseal_credential(row, new):
                    raise CustodyError(409, "raced", "changed meanwhile")
                counts["resealed"] += 1
            except CustodyError:
                counts["failed"] += 1
        return counts

    # -- reporting ----------------------------------------------------
    def status(self) -> dict[str, Any]:
        """Operational facts for readiness and the CLI. No key material, no path."""
        out: dict[str, Any] = {"mode": self.config.mode, "reason": self.config.reason}
        ring = self.config.keyring
        if ring is not None:
            in_use: dict[str, int] = {}
            for row in self.store.list_credentials():
                in_use[row.key_id] = in_use.get(row.key_id, 0) + 1
            out.update(active_key_id=ring.active_id, key_ids=sorted(ring.keys), sealed_under=in_use)
        if self.config.journal is not None:
            j: dict[str, Any] = {"configured": True}
            try:
                journal_id, _, n = self.config.journal.snapshot()
                j.update(entries=n, intact=True, matches_store=self.store.get_meta(_META_JOURNAL_ID) in (None, journal_id))
            except CustodyError as exc:
                j.update(intact=False, error=exc.code)
            try:
                j["same_device"] = _device_of(self.config.journal.path) == _device_of(self.store.path)
            except OSError:
                j["same_device"] = None
            out["journal"] = j
        if self.config.mode == PROCESS_LOCAL:
            out["warning"] = "process-local credentials: correct for ONE worker only"
        return out

    # -- worker-side adapter management ------------------------------
    async def ensure_live(self, registry: AdapterRegistry, record: ConnectionRecord) -> None:
        """Make THIS process hold an adapter built from the connection's CURRENT credential.

        The record is the caller's fresh read of the shared store. A revoked connection drops the
        local adapter and is refused; a local adapter built from an older version is replaced."""
        from neuralbridge.adapters.databases.postgres import PostgresAdapter

        key = record.registry_key
        try:
            self.authorize(record)
        except CustodyError:
            old = registry.get(key)
            if old is not None:
                registry.unregister(key)
                await _close(old, record.id)
            raise
        if record.custody != CUSTODY_VAULT:
            if key not in registry:
                raise CustodyError(
                    409, "no_live_adapter",
                    f"Connection '{record.id}' was bound with process-local credentials and has no live adapter "
                    "in this worker (after a restart, or on another worker). Rotate it with "
                    "POST /ai/connections/{id}/rotate to store its credentials for all workers.")
            return
        if registry.get(key) is not None and registry.version_of(key) == record.cred_version:
            return
        adapter = PostgresAdapter(config=self.load_adapter_config(record))
        previous = registry.get(key)
        registry.register(adapter, key=key, version=record.cred_version)
        if previous is not None:
            await _close(previous, record.id)


async def _close(adapter: Any, connection_id: str) -> None:
    try:
        await adapter.disconnect()
    except Exception:  # noqa: BLE001 - best effort: the credential has left the registry either way
        logger.warning("ai_connection_disconnect_failed", connection_id=connection_id)


_CONFIG_CACHE: dict[tuple[Any, ...], CustodyConfig] = {}
_CONFIG_ENVS = (KEYS_ENV, KEY_FILE_ENV, ACTIVE_KEY_ENV, JOURNAL_ENV, PROCESS_LOCAL_ENV, "WEB_CONCURRENCY")


def vault_for(store: AiStore) -> CredentialVault:
    """The vault for ``store``, configured from the environment.

    The parsed configuration is cached on (store path, the relevant environment, the key file's
    size, mode and change time), so a changed key file or variable is picked up on the next call and an
    unchanged one costs a ``stat``."""
    key_file = os.environ.get(KEY_FILE_ENV, "").strip()
    stamp: tuple[int, ...] | None = None
    if key_file:
        try:
            st = Path(key_file).stat()
            stamp = (st.st_mtime_ns, st.st_ctime_ns, st.st_size, st.st_mode)
        except OSError:
            stamp = None
    cache_key = (str(store.path), *(os.environ.get(n, "") for n in _CONFIG_ENVS), stamp)
    config = _CONFIG_CACHE.get(cache_key)
    if config is None:
        if len(_CONFIG_CACHE) > 64:
            _CONFIG_CACHE.clear()
        config = _CONFIG_CACHE[cache_key] = CustodyConfig.from_env(store.path)
    return CredentialVault(store, config)


def make_connection_guard(registry: AdapterRegistry, store: AiStore) -> Callable[[str], Awaitable[None]]:
    """A guard for ``RequestRouter``: before a per-connection key is used (raw operator route, MCP),
    re-check the shared record, so a connection revoked or rotated in another worker is not served
    from this worker's stale adapter. Refuses with ``ValueError`` (the router's 'not usable')."""

    async def guard(adapter_type: str) -> None:
        connection_id = adapter_type.split(":", 1)[1]
        record = store.get_connection(connection_id)
        if record is None:
            stale = registry.get(adapter_type)
            if stale is not None:  # deleted in another worker
                registry.unregister(adapter_type)
                await _close(stale, connection_id)
                raise ValueError(f"Adapter '{adapter_type}' is not registered.")
            return
        try:
            await vault_for(store).ensure_live(registry, record)
        except CustodyError as exc:
            raise ValueError(exc.detail) from exc

    return guard


# --------------------------------------------------------------------------------------------
# command line:  python -m neuralbridge.ai.credentials status|reencrypt|reconcile
# --------------------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m neuralbridge.ai.credentials", description=__doc__.split("\n")[0])
    parser.add_argument("command", choices=["status", "reencrypt", "reconcile"])
    parser.add_argument("--store", default=os.environ.get("NEURALBRIDGE_AI_STORE", "neuralbridge-ai.db"))
    args = parser.parse_args(argv)
    store = AiStore(args.store)
    vault = CredentialVault(store, CustodyConfig.from_env(Path(args.store)))
    try:
        if args.command == "status":
            result: dict[str, Any] = vault.status()
        elif args.command == "reencrypt":
            result = vault.reencrypt()
        else:
            result = vault.reconcile_all()
    except CustodyError as exc:
        sys.stdout.write(json.dumps({"error": exc.code, "detail": exc.detail}) + "\n")
        return 2
    sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 1 if result.get("failed") else 0


if __name__ == "__main__":
    sys.exit(main())
