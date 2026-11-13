"""A verifier's own record of which public keys signed, and when each one was in force.

A signature is worth the provenance of the key, and a key outlives the day it was made: after
a rotation the old key still signed every earlier anchor, and a verifier holding only today's
key sees all of them as foreign. The remedy the key ceremony names ("keep the old public key
indefinitely") needs a place to keep it that a tool can read, so this is that place: a
public-key-only file, ``assurance.attest.keyset.v1``.

    {"format": "assurance.attest.keyset.v1",
     "keys": [{"fingerprint": "83b8af727a2ee9ca",
               "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n...\\n-----END PUBLIC KEY-----\\n",
               "status": "retired",
               "effective_from": "2025-01-01T00:00:00Z",
               "effective_until": "2026-06-01T00:00:00Z",
               "label": "service key, first era"}]}

* the key that checks an anchor is chosen **by the fingerprint the anchor names**, from this
  file, never from the anchor or the bundle;
* ``active``: signs from ``effective_from`` and has no end; ``retired``: signed from
  ``effective_from`` to ``effective_until`` (required), and an anchor dated outside that
  window is a problem; ``revoked``: nothing it signed is trusted, whatever date it carries
  (the signer chooses the date it writes, so a window cannot save a leaked key);
* a fingerprint that is not in the file is *unestablished*, not a forgery and not a pass:
  the anchor may be genuine and from a key the verifier holds no record of.

The loader fails closed. It refuses a file that holds private key material (this is a place
for public keys only; if a private key ever lands in one, treat that key as burned), a repeated
JSON name, a field it does not know, a wrong type, a fingerprint that is not the key's, a
repeated key, an unreadable or non-Ed25519 key, a date that is not ``YYYY-MM-DDTHH:MM:SSZ``,
an empty window, and any format version it does not implement. Nothing is guessed.

Dates are the signer's own claim about when it signed. A window makes a retired key's
*honest* anchors checkable; it cannot make a leaked key's forged ones detectable.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from assurance.attest.keys import SigningKeyError, VerifyingKey
from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc
from assurance.core.text import neutralise
from assurance.evidence.verify_export import loads_no_duplicate_keys

__all__ = ["KEYSET_FORMAT", "KeyEntry", "Keyset", "KeysetError"]

KEYSET_FORMAT = "assurance.attest.keyset.v1"
STATUSES = ("active", "retired", "revoked")
MAX_KEYSET_BYTES = 256 * 1024
MAX_KEYS = 64
MAX_LABEL = 120
EPOCH = "1970-01-01T00:00:00Z"

_TOP = frozenset({"format", "keys"})
_REQUIRED = frozenset({"fingerprint", "public_key_pem", "status", "effective_from"})
_OPTIONAL = frozenset({"effective_until", "label"})
_FINGERPRINT = re.compile(r"[0-9a-f]{16}")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


class KeysetError(AssuranceError):
    """A keyset that must not be used. The message names the fault, never key bytes."""


def _timestamp(value: object, where: str) -> str:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise KeysetError(f"{where} must be a UTC time written YYYY-MM-DDTHH:MM:SSZ")
    try:
        parse_utc(value)
    except (ValueError, OverflowError):
        raise KeysetError(f"{where} is not a real date") from None
    return value


@dataclass(frozen=True)
class KeyEntry:
    """One public key, as the verifier recorded it."""

    fingerprint: str
    key: VerifyingKey
    status: str
    effective_from: str
    effective_until: str | None = None
    label: str = ""

    def judge(self, attested_at: str) -> str:
        """``""`` if an anchor signed at *attested_at* may be checked under this key, else why not."""
        if self.status == "revoked":
            return (f"signed by key {self.fingerprint}, which your keyset marks REVOKED: "
                    "nothing it signed is trusted, whatever date the anchor carries")
        if not isinstance(attested_at, str) or not _TIME.fullmatch(attested_at):
            return (f"its signing time {neutralise(str(attested_at)[:40])!r} is not a "
                    "YYYY-MM-DDTHH:MM:SSZ time, so it cannot be placed in the window of key "
                    f"{self.fingerprint}")
        try:
            moment = parse_utc(attested_at)
        except (ValueError, OverflowError):
            return f"its signing time {attested_at!r} is not a real date"
        if moment < parse_utc(self.effective_from):
            return (f"dated {attested_at}, before key {self.fingerprint} was in force "
                    f"(from {self.effective_from})")
        if self.effective_until is not None and moment > parse_utc(self.effective_until):
            return (f"dated {attested_at}, after key {self.fingerprint} was "
                    f"{self.status} (until {self.effective_until}): a retired key signing "
                    "later is a leak, a back-dated record, or a wrong date in your keyset")
        return ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "fingerprint": self.fingerprint, "public_key_pem": self.key.pem(),
            "status": self.status, "effective_from": self.effective_from}
        if self.effective_until is not None:
            out["effective_until"] = self.effective_until
        if self.label:
            out["label"] = self.label
        return out

    def describe(self) -> str:
        window = (f"{self.effective_from} .. {self.effective_until}"
                  if self.effective_until else f"from {self.effective_from}")
        return (f"{self.fingerprint}  {self.status:<8} {window}"
                + (f"  {neutralise(self.label)}" if self.label else ""))


@dataclass(frozen=True)
class Keyset:
    """The keys a verifier recognises. Immutable; built by :meth:`load` / :meth:`from_keys`."""

    entries: tuple[KeyEntry, ...]

    # -- lookup ---------------------------------------------------------
    def get(self, fingerprint: str) -> KeyEntry | None:
        for entry in self.entries:
            if entry.fingerprint == fingerprint:
                return entry
        return None

    @property
    def fingerprints(self) -> tuple[str, ...]:
        return tuple(sorted(e.fingerprint for e in self.entries))

    # -- construction ---------------------------------------------------
    @classmethod
    def from_keys(cls, keys: Iterable[VerifyingKey]) -> Keyset:
        """Keys given one by one (``--public-key`` repeated): active throughout, no history."""
        return cls._checked(tuple(
            KeyEntry(k.fingerprint, k, "active", EPOCH, None, "") for k in keys))

    def merged_with(self, other: Keyset) -> Keyset:
        return self._checked((*self.entries, *other.entries))

    @staticmethod
    def _checked(entries: tuple[KeyEntry, ...]) -> Keyset:
        seen: set[str] = set()
        for entry in entries:
            if entry.fingerprint in seen:
                raise KeysetError(
                    f"key {entry.fingerprint} is given twice. A key has one status; remove "
                    "the duplicate (a --public-key that is also in the keyset file is the "
                    "usual cause).")
            seen.add(entry.fingerprint)
        if not entries:
            raise KeysetError("a keyset with no keys verifies nothing")
        return Keyset(entries)

    @classmethod
    def from_dict(cls, doc: object) -> Keyset:
        if not isinstance(doc, dict):
            raise KeysetError("the keyset is not a JSON object")
        fmt = doc.get("format")
        if fmt != KEYSET_FORMAT:
            raise KeysetError(
                f"unsupported keyset format {neutralise(str(fmt)[:60])!r}: this build reads "
                f"{KEYSET_FORMAT} only, and will not guess at another version")
        extra = sorted(str(k)[:40] for k in doc if k not in _TOP)
        if extra:
            raise KeysetError("the keyset carries field(s) it does not define: "
                              + ", ".join(neutralise(k) for k in extra[:5]))
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise KeysetError("`keys` must be a list")
        if not keys:
            raise KeysetError("a keyset with no keys verifies nothing")
        if len(keys) > MAX_KEYS:
            raise KeysetError(f"more than {MAX_KEYS} keys; a key history is not that long")
        return cls._checked(tuple(cls._entry(i, raw) for i, raw in enumerate(keys, start=1)))

    @staticmethod
    def _entry(number: int, raw: object) -> KeyEntry:
        where = f"key {number}"
        if not isinstance(raw, dict):
            raise KeysetError(f"{where} is not an object")
        missing = sorted(_REQUIRED - set(raw))
        if missing:
            raise KeysetError(f"{where} lacks {', '.join(missing)}")
        extra = sorted(str(k)[:40] for k in raw if k not in _REQUIRED | _OPTIONAL)
        if extra:
            raise KeysetError(f"{where} carries field(s) it does not define: "
                              + ", ".join(neutralise(k) for k in extra[:5]))
        for name in ("fingerprint", "public_key_pem", "status"):
            if not isinstance(raw[name], str):
                raise KeysetError(f"{where}: {name} must be text")
        if not _FINGERPRINT.fullmatch(raw["fingerprint"]):
            raise KeysetError(f"{where}: fingerprint must be 16 lower-case hex characters "
                              "(what `attest keygen` prints)")
        if raw["status"] not in STATUSES:
            raise KeysetError(f"{where}: status must be one of {', '.join(STATUSES)}")
        try:
            key = VerifyingKey.from_pem(raw["public_key_pem"])
        except SigningKeyError as exc:
            raise KeysetError(f"{where}: {neutralise(exc)}") from None
        if key.fingerprint != raw["fingerprint"]:
            raise KeysetError(
                f"{where}: the fingerprint {raw['fingerprint']} is not the key's: that key "
                f"is {key.fingerprint}. Either the wrong key was pasted or the wrong "
                "fingerprint was written down; neither is guessed at.")
        start = _timestamp(raw["effective_from"], f"{where}: effective_from")
        until = None
        if "effective_until" in raw:
            until = _timestamp(raw["effective_until"], f"{where}: effective_until")
            if parse_utc(until) <= parse_utc(start):
                raise KeysetError(f"{where}: effective_until is not after effective_from")
        if raw["status"] == "retired" and until is None:
            raise KeysetError(f"{where}: a retired key needs effective_until, the last moment "
                              "it signed (without it the window is open-ended, which is "
                              "what `active` means)")
        if raw["status"] == "active" and until is not None:
            raise KeysetError(f"{where}: an active key has no end; mark it retired, with the "
                              "date, when it is retired")
        label = raw.get("label", "")
        if not isinstance(label, str) or len(label) > MAX_LABEL:
            raise KeysetError(f"{where}: label must be text of at most {MAX_LABEL} characters")
        return KeyEntry(raw["fingerprint"], key, raw["status"], start, until, label)

    @classmethod
    def load(cls, path: str | Path) -> Keyset:
        """Read a keyset file, refusing everything the format does not define."""
        p = Path(path)
        try:
            with p.open("rb") as handle:
                data = handle.read(MAX_KEYSET_BYTES + 1)
        except OSError as exc:
            raise KeysetError(f"the keyset file cannot be read ({type(exc).__name__}). "
                              "Nothing was checked against it.") from None
        if len(data) > MAX_KEYSET_BYTES:
            raise KeysetError("the keyset file is too large to be a list of public keys")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise KeysetError("the keyset file is not UTF-8 text") from None
        if _private_material(text):
            raise KeysetError(
                "the keyset file holds private key material. It is a place for PUBLIC keys "
                "only and is refused whole; if that key was ever real, treat it as burned "
                "and rotate it (KEY-CEREMONY.md section 6).")
        try:
            doc = loads_no_duplicate_keys(text)
        except RecursionError:
            raise KeysetError("the keyset file is nested far deeper than any keyset") from None
        except ValueError as exc:
            raise KeysetError(f"the keyset file is not valid JSON: {neutralise(exc)}") from None
        if _private_material(_strings(doc)):
            raise KeysetError(
                "the keyset file holds private key material. It is a place for PUBLIC keys "
                "only and is refused whole; if that key was ever real, treat it as burned "
                "and rotate it (KEY-CEREMONY.md section 6).")
        return cls.from_dict(doc)

    # -- output ---------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {"format": KEYSET_FORMAT, "keys": [e.to_dict() for e in self.entries]}

    def save(self, path: str | Path) -> Path:
        """Write the keyset atomically (a temp file in the same directory, then a rename)."""
        import json

        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n")
            os.replace(tmp, p)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return p


def _private_material(text: str) -> bool:
    upper = text.upper()
    return "PRIVATE KEY" in upper or "OPENSSH PRIVATE" in upper


def _strings(node: Any) -> str:
    """Every member name and string value in *node*, so an escaped header cannot hide."""
    out: list[str] = []
    stack = [node]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for k, v in item.items():
                out.append(str(k))
                stack.append(v)
        elif isinstance(item, list):
            stack.extend(item)
    return "\n".join(out)
