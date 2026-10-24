"""A signed recorder attestation: the only route above the declared-provenance cap.

A trace says where it came from (``simulation`` / ``bench`` / ``field``) in a field
its filer writes. That word is the filer's claim. What a machine *can* check is much
narrower, and this module does exactly that and no more.

What an accepted attestation PROVES
    The holder of an Ed25519 key that **this verifier's own trust list** names, and
    has not revoked, and permits for this provenance class, signed -- on the stated
    date -- a statement that binds *these exact trace bytes* (the content hash, which
    covers the trace id, the declared provenance, the source system, the start time,
    the sample rate, the conditions and every sample) to a recorder key and to a
    machine reference (product, version, optionally a serial) the recorder says it
    was attached to.

What it does NOT prove
    * that the sample values are true physical measurements;
    * that the recorder or its sensors were calibrated, uncompromised or correctly
      installed;
    * that the machine reference is the physical machine in front of anybody;
    * that the person holding the key is who the recorder label says (the label,
      ``recorder_id``, is signed but **never trusted**: only the key is);
    * that the machine is safe.

    Cryptographic integrity is not recorder authenticity, and recorder authenticity is
    not physical safety. Every report that quotes an accepted attestation says so.

Trust is a verifier input
    A recorder trust list (:class:`RecorderTrust`) is pinned public keys, each with the
    provenance classes the key may attest. It arrives **separately from the trace and
    the bundle**: a trust list embedded in a bundle is ignored, and with no list
    configured no attestation can be accepted (the trace stays ``declared_by_filer``
    and capped at ``community``). A key trusted for ``bench`` cannot lift a trace that
    declares ``field``; ``simulation`` is never liftable.

Rotation and revocation
    Rotate by adding the new key and revoking (or removing) the old one. A revoked key
    rejects **all** of its attestations, including ones dated before the revocation:
    the signer chooses the ``attested_on`` date, so a date before ``revoked_on`` proves
    nothing about when the signature was made. Removing a key has the same effect as
    revoking it. Re-attest the recording under the new key if it must stay validated.

The signed bytes
    ``b"assurance.machine.recorder-attestation.v1\\n"`` + ``canonical_json(body)`` where
    ``body`` carries ``format`` and every other field except ``signature``. The fixed
    prefix is a domain separator: a limits-review or ledger-head signature (a bare
    canonical JSON document) can never verify as a recorder attestation, nor the
    reverse. Numbers in the recording window are carried as strings so no float
    formatting can be reinterpreted. Unknown fields, repeated keys, wrong types and
    unsupported ``format`` versions are refused; nothing unsigned can ride along.

Reuses :mod:`assurance.attest.keys` for the key, fingerprint and signature primitives;
no cryptography is implemented here. Signing happens on the recorder operator's side
(``assurance machine recorder-sign``). A private key is never embedded in a bundle,
never sent to the API and refused unread when it appears in anything a caller supplies.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import secrets
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from assurance.attest.keys import SigningKey, SigningKeyError, VerifyingKey
from assurance.core.errors import AssuranceError
from assurance.core.identity import canonical_json, content_hash_of, format_utc, parse_utc

if TYPE_CHECKING:
    from assurance.machine.trace import Trace

__all__ = [
    "ATTESTATION_FORMAT",
    "MAX_ATTESTATIONS",
    "MAX_LAG_DAYS",
    "SIGNING_PREFIX",
    "TRUST_FORMAT",
    "AttestationFinding",
    "AttestationStatus",
    "MachineRef",
    "RecorderAttestation",
    "RecorderAttestationAssessment",
    "RecorderAttestationError",
    "RecorderTrust",
    "RecordingFacts",
    "TrustedRecorder",
    "UnsupportedAttestationVersionError",
    "assess_recorder_attestation",
    "load_attestation_file",
    "loads_strict",
    "refuse_private_key",
]

ATTESTATION_FORMAT = "assurance.machine.recorder-attestation.v1"
TRUST_FORMAT = "assurance.machine.recorder-trust.v1"
#: The domain-separation prefix of every signed payload.
SIGNING_PREFIX = b"assurance.machine.recorder-attestation.v1\n"

#: Most attestations examined per assessment. A trace needs one; a hostile bundle could
#: carry thousands. The rest are not looked at and the assessment says so.
MAX_ATTESTATIONS = 8
#: Most recorders a trust list may hold.
MAX_TRUSTED_RECORDERS = 64
#: An attestation dated more than this many days after the recording began is not
#: believed to be an attestation *of that recording* (``stale``). A recorder signs when
#: it exports a run; three months is generous and the bound exists only so that a key
#: cannot be used to vouch, years later, for a recording nobody signed at the time.
MAX_LAG_DAYS = 90
#: Largest attestation (as canonical JSON) that is read at all.
MAX_ATTESTATION_BYTES = 8 * 1024
MAX_TRUST_BYTES = 1024 * 1024
_MAX_TEXT = 256
#: Provenance classes a key may be trusted for. ``simulation`` is deliberately absent.
LIFTABLE_PROVENANCE = frozenset({"bench", "field"})

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_FPR = re.compile(r"^[0-9a-f]{16}$")
_COUNT = re.compile(r"^(0|[1-9][0-9]{0,9})$")
_DECIMAL = re.compile(r"^-?[0-9]{1,12}\.[0-9]{6}$")


class RecorderAttestationError(AssuranceError):
    """An attestation or trust file is malformed in a way that cannot be assessed."""


class UnsupportedAttestationVersionError(RecorderAttestationError):
    """The ``format`` names a version these rules do not define."""


class AttestationStatus(StrEnum):
    """What became of the attestation evidence. Only ``accepted`` lifts the tier."""

    NONE = "none"                                  # nothing was supplied
    ACCEPTED = "accepted"
    MALFORMED = "malformed"
    UNSUPPORTED_VERSION = "unsupported_version"
    UNTRUSTED_KEY = "untrusted_key"                # no trust list, or the key is not in it
    REVOKED_KEY = "revoked_key"
    BAD_SIGNATURE = "bad_signature"
    DUPLICATE = "duplicate"                        # the same attestation, supplied again
    TRACE_MISMATCH = "trace_mismatch"              # signed over a different recording
    MACHINE_MISMATCH = "machine_mismatch"          # a different product, version or serial
    PROVENANCE_NOT_PERMITTED = "provenance_not_permitted"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    STALE = "stale"                                # dated outside the recording's window


# ---------------------------------------------------------------------------
# refusals that apply to anything a caller hands over
# ---------------------------------------------------------------------------
PRIVATE_KEY_MESSAGE = (
    "That looks like a private key. It was not read or kept. Only a PUBLIC key (in a "
    "trust list) and signed attestations are ever needed; if this was a real key, "
    "treat it as exposed and replace it.")


def _contains_private_key(value: Any, depth: int = 0) -> bool:
    if depth > 24:
        return True        # nothing legitimate nests this deep; refuse rather than walk
    if isinstance(value, str):
        return "PRIVATE KEY" in value.upper()
    if isinstance(value, dict):
        return any(_contains_private_key(k, depth + 1) or _contains_private_key(v, depth + 1)
                   for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return any(_contains_private_key(v, depth + 1) for v in value)
    return False


def refuse_private_key(value: Any) -> None:
    """Raise if ``value`` (text, or parsed JSON) looks like it holds a private key.

    Applied before anything a caller supplies is read: attestations, trust lists. The
    value is not echoed back.
    """
    if _contains_private_key(value):
        raise RecorderAttestationError(PRIVATE_KEY_MESSAGE)


def loads_strict(text: str, what: str) -> Any:
    """``json.loads`` that refuses repeated keys, NaN/Infinity, and private keys.

    A repeated key is how two readers come to disagree about one document: the second
    wins in Python and the first in other parsers, so a signed value could be shadowed.
    """
    if "PRIVATE KEY" in text.upper():
        raise RecorderAttestationError(PRIVATE_KEY_MESSAGE)

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise RecorderAttestationError(
                    f"{what} repeats the key {k!r}; a document with a repeated key is "
                    "read differently by different parsers and is refused.")
            out[k] = v
        return out

    def constant(name: str) -> Any:
        raise RecorderAttestationError(f"{what} contains {name}, which is not valid JSON.")

    try:
        parsed = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except RecorderAttestationError:
        raise
    except (ValueError, RecursionError) as exc:
        raise RecorderAttestationError(f"{what} is not valid JSON: {exc}") from exc
    refuse_private_key(parsed)
    return parsed


def _read_text(path: Path, what: str, limit: int) -> str:
    try:
        if path.stat().st_size > limit:
            raise RecorderAttestationError(
                f"{what} {path.name} is larger than the {limit} bytes this reader accepts.")
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RecorderAttestationError(f"cannot read {what} {path}: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise RecorderAttestationError(f"{what} {path.name} is not UTF-8 text.") from exc


def load_attestation_file(path: str | Path) -> dict[str, Any]:
    """Read one attestation file as strict JSON (no repeated keys, no private key)."""
    p = Path(path)
    parsed = loads_strict(_read_text(p, "attestation", MAX_ATTESTATION_BYTES), f"{p.name}")
    if not isinstance(parsed, dict):
        raise RecorderAttestationError(f"{p.name} must be a JSON object.")
    return parsed


# ---------------------------------------------------------------------------
# field validation
# ---------------------------------------------------------------------------
def _text(d: dict[str, Any], key: str, where: str, *, empty: bool = False,
          pattern: re.Pattern[str] | None = None) -> str:
    value = d.get(key)
    if type(value) is not str:
        raise RecorderAttestationError(
            f"{where}{key} must be text, not {type(value).__name__}.")
    if not value:
        if empty:
            return value
        raise RecorderAttestationError(f"{where}{key} is empty.")
    if len(value) > _MAX_TEXT:
        raise RecorderAttestationError(f"{where}{key} is longer than {_MAX_TEXT} characters.")
    if any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn")
           for c in value):
        raise RecorderAttestationError(f"{where}{key} contains control characters.")
    if pattern is not None and not pattern.match(value):
        raise RecorderAttestationError(f"{where}{key} {value!r} is not in the expected form.")
    return value


def _iso_date(value: str, name: str) -> date:
    if not _DATE.match(value):
        raise RecorderAttestationError(f"{name} {value!r} is not an ISO date (YYYY-MM-DD).")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise RecorderAttestationError(f"{name} {value!r} is not a calendar date.") from exc


def _exact_keys(d: dict[str, Any], expected: tuple[str, ...], where: str) -> None:
    unknown = sorted(str(k) for k in d if k not in expected)
    if unknown:
        raise RecorderAttestationError(
            f"{where or 'attestation '}has unknown field(s) {', '.join(map(repr, unknown))}; "
            "a field the signature does not cover is refused rather than ignored.")
    missing = [k for k in expected if k not in d]
    if missing:
        raise RecorderAttestationError(
            f"{where or 'attestation '}is missing {', '.join(map(repr, missing))}.")


def decimal_text(value: float) -> str:
    """The fixed rendering of a float carried in a signed body (six decimals)."""
    return f"{float(value):.6f}"


@dataclass(frozen=True)
class MachineRef:
    """The machine a verification is about: from its envelope and, if known, its unit."""

    product: str
    product_version: str
    serial: str = ""

    def describe(self) -> str:
        return (f"{self.product} {self.product_version}"
                + (f" #{self.serial}" if self.serial else ""))


@dataclass(frozen=True)
class RecordingFacts:
    """What an attestation is compared with: a trace, or a sealed bundle's description of one.

    ``sample_count``, ``sample_rate_hz`` and ``duration_s`` are ``None`` when only the
    bundle is available (the trace bytes are not); the recording window is then not
    compared and the assessment says so (``window_checked`` is false). The trace hash
    still binds every one of those values, so a bundle's attestation that names the
    bundle's own trace hash cannot be about another recording.
    """

    trace_hash: str
    trace_id: str
    provenance: str
    started_at: datetime
    sample_count: int | None = None
    sample_rate_hz: float | None = None
    duration_s: float | None = None

    @classmethod
    def from_trace(cls, trace: Trace) -> RecordingFacts:
        return cls(
            trace_hash=trace.content_hash(), trace_id=trace.trace_id,
            provenance=trace.provenance.value, started_at=trace.started_at,
            sample_count=len(trace.samples), sample_rate_hz=trace.sample_rate_hz,
            duration_s=trace.duration_s)

    @classmethod
    def from_bundle_body(cls, body: dict[str, Any]) -> RecordingFacts | None:
        """The same facts as a sealed bundle states them, or ``None`` if unreadable."""
        try:
            started = parse_utc(str(body["trace_started_at"]))
            trace_hash, trace_id = body["trace_hash"], body["trace_id"]
            provenance = body["provenance"]
        except (KeyError, ValueError, TypeError):
            return None
        if not (isinstance(trace_hash, str) and isinstance(trace_id, str)
                and isinstance(provenance, str)):
            return None
        return cls(trace_hash, trace_id, provenance, started)

    @property
    def window_known(self) -> bool:
        return None not in (self.sample_count, self.sample_rate_hz, self.duration_s)


# ---------------------------------------------------------------------------
# the attestation
# ---------------------------------------------------------------------------
_TOP = ("format", "attestation_id", "trace_hash", "trace_id", "provenance", "window",
        "recorder_id", "machine_ref", "attested_on", "expires_on", "key_fingerprint",
        "signature")
_WINDOW = ("started_at", "sample_count", "sample_rate_hz", "duration_s")
_MREF = ("product", "product_version", "machine_serial")


@dataclass(frozen=True)
class RecorderAttestation:
    """A signed statement binding one exact recording to a recorder key and machine reference.

    ``recorder_id`` is the recorder's own label. It is signed, so it cannot be altered,
    but the verifier trusts the *key*, never this string.
    """

    format: str
    attestation_id: str
    trace_hash: str
    trace_id: str
    provenance: str
    started_at: str
    sample_count: str
    sample_rate_hz: str
    duration_s: str
    recorder_id: str
    product: str
    product_version: str
    machine_serial: str
    attested_on: str
    expires_on: str
    key_fingerprint: str
    signature: str = ""

    def _body(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "attestation_id": self.attestation_id,
            "trace_hash": self.trace_hash,
            "trace_id": self.trace_id,
            "provenance": self.provenance,
            "window": {
                "started_at": self.started_at,
                "sample_count": self.sample_count,
                "sample_rate_hz": self.sample_rate_hz,
                "duration_s": self.duration_s,
            },
            "recorder_id": self.recorder_id,
            "machine_ref": {
                "product": self.product,
                "product_version": self.product_version,
                "machine_serial": self.machine_serial,
            },
            "attested_on": self.attested_on,
            "expires_on": self.expires_on,
            "key_fingerprint": self.key_fingerprint,
        }

    def signed_payload(self) -> bytes:
        """Exactly the bytes that are signed: the domain prefix, then the canonical body."""
        return SIGNING_PREFIX + canonical_json(self._body()).encode("utf-8")

    def content_hash(self) -> str:
        """Identity of the signed statement (the body; the signature is over it)."""
        return content_hash_of(self._body())

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "signature": self.signature}

    @property
    def machine_ref(self) -> MachineRef:
        return MachineRef(self.product, self.product_version, self.machine_serial)

    @classmethod
    def sign(
        cls, trace: Trace, key: SigningKey, *, recorder_id: str, product: str,
        product_version: str, attested_on: str, machine_serial: str = "",
        expires_on: str = "", attestation_id: str = "",
    ) -> RecorderAttestation:
        """Attest ``trace`` as it is now. Run by the recorder operator, offline.

        The signer states the dates; the verifier decides whether they are plausible
        (``stale`` / ``expired`` / ``not_yet_valid``), so this does not second-guess
        them beyond their form.
        """
        facts = RecordingFacts.from_trace(trace)
        unsigned = cls(
            format=ATTESTATION_FORMAT,
            attestation_id=attestation_id or secrets.token_hex(16),
            trace_hash=facts.trace_hash, trace_id=facts.trace_id,
            provenance=facts.provenance, started_at=format_utc(facts.started_at),
            sample_count=str(facts.sample_count),
            sample_rate_hz=decimal_text(facts.sample_rate_hz or 0.0),
            duration_s=decimal_text(facts.duration_s or 0.0),
            recorder_id=recorder_id, product=product, product_version=product_version,
            machine_serial=machine_serial, attested_on=attested_on,
            expires_on=expires_on, key_fingerprint=key.fingerprint)
        unsigned._validate()                       # refuse to sign something unreadable
        sig = base64.b64encode(key.sign(unsigned.signed_payload())).decode("ascii")
        return cls(**{**unsigned.__dict__, "signature": sig})

    def _validate(self) -> None:
        """Re-read this attestation through the strict parser (form only)."""
        type(self).from_dict({**self._body(), "signature": self.signature or "AA=="},
                             _form_only=True)

    @classmethod
    def from_dict(cls, data: Any, *, _form_only: bool = False) -> RecorderAttestation:
        """Strict parse: exact fields, text where text is required, nothing else."""
        if not isinstance(data, dict):
            raise RecorderAttestationError("a recorder attestation must be a JSON object.")
        refuse_private_key(data)
        fmt = data.get("format")
        if type(fmt) is not str:
            raise RecorderAttestationError("recorder attestation has no text 'format'.")
        if fmt != ATTESTATION_FORMAT:
            if fmt.startswith("assurance.machine.recorder-attestation."):
                raise UnsupportedAttestationVersionError(
                    f"recorder attestation format {fmt!r} is not {ATTESTATION_FORMAT!r}; "
                    "a version these rules do not define cannot be assessed under them.")
            raise RecorderAttestationError(
                f"recorder attestation format {fmt!r} is not {ATTESTATION_FORMAT!r}.")
        if len(canonical_json(data)) > MAX_ATTESTATION_BYTES:
            raise RecorderAttestationError("recorder attestation is implausibly large.")
        _exact_keys(data, _TOP, "")
        window, mref = data["window"], data["machine_ref"]
        if not isinstance(window, dict):
            raise RecorderAttestationError("attestation window must be an object.")
        if not isinstance(mref, dict):
            raise RecorderAttestationError("attestation machine_ref must be an object.")
        _exact_keys(window, _WINDOW, "window ")
        _exact_keys(mref, _MREF, "machine_ref ")

        started = _text(window, "started_at", "window.")
        try:
            parse_utc(started)
        except ValueError as exc:
            raise RecorderAttestationError(f"window.started_at {started!r}: {exc}") from exc
        if not started.endswith("Z"):
            raise RecorderAttestationError("window.started_at must be a UTC time ending in Z.")
        attested_on = _text(data, "attested_on", "", pattern=_DATE)
        _iso_date(attested_on, "attested_on")
        expires_on = _text(data, "expires_on", "", empty=True)
        if expires_on:
            _iso_date(expires_on, "expires_on")
        signature = _text(data, "signature", "")
        if not _form_only:
            try:
                raw = base64.b64decode(signature.encode("ascii"), validate=True)
            except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
                raise RecorderAttestationError(
                    f"attestation signature is not base64: {exc}") from exc
            if len(raw) != 64:
                raise RecorderAttestationError(
                    "attestation signature is not an Ed25519 signature (64 bytes).")
        provenance = _text(data, "provenance", "")
        if provenance not in ("simulation", "bench", "field"):
            raise RecorderAttestationError(
                f"attestation provenance {provenance!r} is not simulation, bench or field.")
        return cls(
            format=fmt,
            attestation_id=_text(data, "attestation_id", "", pattern=_ID),
            trace_hash=_text(data, "trace_hash", "", pattern=_HASH),
            trace_id=_text(data, "trace_id", ""),
            provenance=provenance,
            started_at=started,
            sample_count=_text(window, "sample_count", "window.", pattern=_COUNT),
            sample_rate_hz=_text(window, "sample_rate_hz", "window.", pattern=_DECIMAL),
            duration_s=_text(window, "duration_s", "window.", pattern=_DECIMAL),
            recorder_id=_text(data, "recorder_id", "", empty=True),
            product=_text(mref, "product", "machine_ref."),
            product_version=_text(mref, "product_version", "machine_ref."),
            machine_serial=_text(mref, "machine_serial", "machine_ref.", empty=True),
            attested_on=attested_on, expires_on=expires_on,
            key_fingerprint=_text(data, "key_fingerprint", "", pattern=_FPR),
            signature=signature)

    def signature_bytes(self) -> bytes:
        try:
            return base64.b64decode(self.signature.encode("ascii"), validate=True)
        except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
            raise RecorderAttestationError(f"attestation signature is not base64: {exc}") from exc


# ---------------------------------------------------------------------------
# trust
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TrustedRecorder:
    """A recorder key the *verifier* chose to trust, with the classes it may attest."""

    label: str
    key: VerifyingKey
    provenance: frozenset[str]
    revoked: bool = False
    revoked_on: str = ""

    @property
    def fingerprint(self) -> str:
        return self.key.fingerprint


_TRUST_TOP = ("format", "recorders")
_TRUST_ENTRY = ("label", "public_key_pem", "fingerprint", "provenance", "revoked",
                "revoked_on")


class RecorderTrust:
    """Which recorder keys are trusted, and for which provenance classes.

    Supplied by the verifier, never by the trace or the bundle. The fingerprint of an
    entry is always computed from its public key; a declared fingerprint that disagrees
    is refused, so a typo cannot silently trust the wrong key.
    """

    def __init__(self, recorders: Iterable[TrustedRecorder] = ()) -> None:
        self._by_fp: dict[str, TrustedRecorder] = {}
        for r in recorders:
            if r.fingerprint in self._by_fp:
                raise RecorderAttestationError(f"recorder key {r.fingerprint} is listed twice.")
            if not r.provenance or not r.provenance <= LIFTABLE_PROVENANCE:
                raise RecorderAttestationError(
                    f"recorder key {r.fingerprint} must name one or more of "
                    f"{', '.join(sorted(LIFTABLE_PROVENANCE))}; 'simulation' is never liftable.")
            self._by_fp[r.fingerprint] = r
        if len(self._by_fp) > MAX_TRUSTED_RECORDERS:
            raise RecorderAttestationError(
                f"a recorder trust list holds at most {MAX_TRUSTED_RECORDERS} keys.")

    def get(self, fingerprint: str) -> TrustedRecorder | None:
        return self._by_fp.get(fingerprint)

    def __len__(self) -> int:
        return len(self._by_fp)

    @property
    def recorders(self) -> tuple[TrustedRecorder, ...]:
        return tuple(self._by_fp.values())

    def to_dict(self) -> dict[str, Any]:
        return {"format": TRUST_FORMAT, "recorders": [
            {"label": r.label, "public_key_pem": r.key.pem(), "fingerprint": r.fingerprint,
             "provenance": sorted(r.provenance), "revoked": r.revoked,
             "revoked_on": r.revoked_on} for r in self._by_fp.values()]}

    @classmethod
    def from_dict(cls, data: Any) -> RecorderTrust:
        if not isinstance(data, dict) or data.get("format") != TRUST_FORMAT:
            raise RecorderAttestationError(
                f"a recorder trust file must be an object with format {TRUST_FORMAT!r}.")
        refuse_private_key(data)
        _exact_keys(data, _TRUST_TOP, "recorder trust file ")
        raw = data["recorders"]
        if not isinstance(raw, list):
            raise RecorderAttestationError("recorder trust file has no 'recorders' list.")
        if len(raw) > MAX_TRUSTED_RECORDERS:
            raise RecorderAttestationError(
                f"a recorder trust list holds at most {MAX_TRUSTED_RECORDERS} keys.")
        out: list[TrustedRecorder] = []
        for i, r in enumerate(raw):
            where = f"recorder #{i} "
            if not isinstance(r, dict):
                raise RecorderAttestationError(f"{where}must be an object.")
            unknown = sorted(str(k) for k in r if k not in _TRUST_ENTRY)
            if unknown:
                raise RecorderAttestationError(
                    f"{where}has unknown field(s) {', '.join(map(repr, unknown))}.")
            pem = r.get("public_key_pem")
            if type(pem) is not str:
                raise RecorderAttestationError(f"{where}needs a public_key_pem.")
            try:
                key = VerifyingKey.from_pem(pem)
            except SigningKeyError as exc:
                raise RecorderAttestationError(f"{where}: {exc}") from exc
            declared = r.get("fingerprint")
            if declared is not None and declared != key.fingerprint:
                raise RecorderAttestationError(
                    f"{where}declares fingerprint {declared!r} but its key is "
                    f"{key.fingerprint}. Refusing to trust a key whose pinned "
                    "fingerprint does not match.")
            classes = r.get("provenance")
            if (not isinstance(classes, list) or not classes
                    or not all(type(c) is str for c in classes)):
                raise RecorderAttestationError(
                    f"{where}needs a 'provenance' list naming what the key may attest "
                    "(bench, field).")
            bad = sorted(set(classes) - LIFTABLE_PROVENANCE)
            if bad:
                raise RecorderAttestationError(
                    f"{where}names provenance {', '.join(map(repr, bad))}; only bench and "
                    "field can be attested. 'simulation' never lifts.")
            revoked = r.get("revoked", False)
            if type(revoked) is not bool:
                raise RecorderAttestationError(f"{where}'revoked' must be true or false.")
            revoked_on = r.get("revoked_on", "")
            if type(revoked_on) is not str:
                raise RecorderAttestationError(f"{where}'revoked_on' must be text.")
            if revoked_on:
                _iso_date(revoked_on, "revoked_on")
            label = r.get("label", "")
            if type(label) is not str or len(label) > _MAX_TEXT:
                raise RecorderAttestationError(f"{where}'label' must be short text.")
            out.append(TrustedRecorder(
                label=label, key=key, provenance=frozenset(classes),
                revoked=revoked or bool(revoked_on), revoked_on=revoked_on))
        return cls(out)

    @classmethod
    def from_json(cls, path: str | Path) -> RecorderTrust:
        p = Path(path)
        return cls.from_dict(loads_strict(_read_text(p, "recorder trust file", MAX_TRUST_BYTES),
                                          f"recorder trust file {p.name}"))


# ---------------------------------------------------------------------------
# assessment
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AttestationFinding:
    """What happened to one supplied attestation."""

    status: AttestationStatus
    detail: str
    key_fingerprint: str = ""
    attestation_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status.value, "detail": self.detail,
                "key_fingerprint": self.key_fingerprint,
                "attestation_hash": self.attestation_hash}


NOT_PROVED = (
    "This establishes that the holder of that key signed such a statement. It does not "
    "establish that the samples are true physical measurements, that the recorder or its "
    "sensors were calibrated or uncompromised, that the machine reference is the physical "
    "machine, who holds the key, or that the machine is safe: cryptographic integrity is "
    "not recorder authenticity, and recorder authenticity is not physical safety.")


@dataclass(frozen=True)
class RecorderAttestationAssessment:
    """The outcome of assessing every supplied attestation against one recording."""

    trace_hash: str
    status: AttestationStatus
    accepted: RecorderAttestation | None
    findings: tuple[AttestationFinding, ...]
    #: Every attestation as supplied (re-serialised if readable, a digest placeholder if
    #: not), so a sealed bundle carries what a later verifier must re-assess under its own
    #: trust list. Never a trust list, never a key.
    submitted: tuple[Any, ...] = ()
    #: The day expiry was judged against. Shown, never compared or trusted on replay.
    assessed_on: str = ""
    #: Whether this assessment had a trust list at all. Shown, not compared on replay.
    trust_configured: bool = False
    #: False when only a bundle's description of the trace was available.
    window_checked: bool = True

    @property
    def attested(self) -> bool:
        return self.status is AttestationStatus.ACCEPTED

    @property
    def attestation_hash(self) -> str:
        return self.accepted.content_hash() if self.accepted else ""

    @property
    def key_fingerprint(self) -> str:
        return self.accepted.key_fingerprint if self.accepted else ""

    @property
    def explanation(self) -> str:
        """The sentence for the report. Identical for every verifier that reaches the
        same outcome: it quotes no verifier-side label or detail."""
        if self.accepted is not None:
            a = self.accepted
            where = a.machine_ref.describe()
            return (
                f"the trace {self.trace_hash[:12]} carries recorder attestation "
                f"{a.attestation_id} signed by key {a.key_fingerprint}, which this "
                "verifier's own trust configuration lists, has not revoked and permits "
                f"for {a.provenance!r} recordings. The signed statement binds exactly "
                f"this trace content ({a.sample_count} samples from {a.started_at}, "
                f"duration {a.duration_s} s) to a recorder that calls itself "
                f"{a.recorder_id!r} (the recorder's own text, not verified) and to the "
                f"machine reference {where!r}, dated {a.attested_on}"
                + (f", valid until {a.expires_on}" if a.expires_on else "")
                + ". " + NOT_PROVED)
        if self.status is AttestationStatus.NONE:
            return ("no recorder attestation was supplied, so the trace's provenance is "
                    "only declared by whoever filed it and the tier is capped at "
                    "community.")
        kinds = ", ".join(dict.fromkeys(f.status.value for f in self.findings)) or \
            self.status.value
        return (
            "recorder attestation evidence was supplied but not accepted "
            f"({kinds}), so the trace's provenance is only declared by whoever filed it "
            "and the tier is capped at community.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_hash": self.trace_hash,
            "status": self.status.value,
            "assessed_on": self.assessed_on,
            "attested": self.attested,
            "trust_configured": self.trust_configured,
            "window_checked": self.window_checked,
            "attestation_hash": self.attestation_hash,
            "key_fingerprint": self.key_fingerprint,
            "accepted_attestation": self.accepted.to_dict() if self.accepted else None,
            "findings": [f.to_dict() for f in self.findings],
            "attestations": list(self.submitted),
            "explanation": self.explanation,
        }


def _placeholder(item: Any, why: str) -> dict[str, Any]:
    """What is sealed in place of an attestation that could not be read: a digest only."""
    try:
        digest = content_hash_of(item)
    except Exception:  # noqa: BLE001 - anything unhashable is simply unreadable
        digest = ""
    return {"unreadable": why, "content_hash": digest}


def assess_recorder_attestation(
    trace: Trace | RecordingFacts,
    attestations: Iterable[Any],
    trust: RecorderTrust | None,
    *,
    machine_ref: MachineRef,
    now: datetime | None = None,
) -> RecorderAttestationAssessment:
    """Decide whether any supplied attestation lifts ``trace`` above the declared cap.

    Fail-closed: every defect leaves the status short of ``accepted`` and the findings
    say which one. ``attestations`` may be attestation objects or raw dicts, so a
    malformed one is reported rather than raised past the caller. Only the first
    :data:`MAX_ATTESTATIONS` are examined.
    """
    facts = trace if isinstance(trace, RecordingFacts) else RecordingFacts.from_trace(trace)
    when = (now or datetime.now(UTC)).astimezone(UTC)
    today = when.date()
    on = today.isoformat()
    trusted = trust is not None and len(trust) > 0
    window_checked = facts.window_known
    supplied = list(attestations)
    if not supplied:
        return RecorderAttestationAssessment(
            facts.trace_hash, AttestationStatus.NONE, None, (), (), on, trusted,
            window_checked)
    findings: list[AttestationFinding] = []
    if len(supplied) > MAX_ATTESTATIONS:
        findings.append(AttestationFinding(
            AttestationStatus.MALFORMED,
            f"more than {MAX_ATTESTATIONS} attestations supplied; only the first "
            f"{MAX_ATTESTATIONS} were examined"))
        supplied = supplied[:MAX_ATTESTATIONS]
    raw: list[Any] = []
    accepted: RecorderAttestation | None = None
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    start_day = facts.started_at.astimezone(UTC).date()

    for item in supplied:
        try:
            att = item if isinstance(item, RecorderAttestation) \
                else RecorderAttestation.from_dict(item)
        except UnsupportedAttestationVersionError as exc:
            raw.append(_placeholder(item, "unsupported_version"))
            findings.append(AttestationFinding(AttestationStatus.UNSUPPORTED_VERSION, str(exc)))
            continue
        except RecorderAttestationError as exc:
            private = "private key" in str(exc).lower()
            raw.append({"unreadable": "refused", "content_hash": ""} if private
                       else _placeholder(item, "malformed"))
            findings.append(AttestationFinding(AttestationStatus.MALFORMED, str(exc)))
            continue
        raw.append(att.to_dict())
        fp, ah = att.key_fingerprint, att.content_hash()

        def bad(status: AttestationStatus, detail: str, fp: str = fp, ah: str = ah) -> None:
            findings.append(AttestationFinding(status, detail, fp, ah))

        entry = trust.get(fp) if trust is not None else None
        if entry is None:
            bad(AttestationStatus.UNTRUSTED_KEY,
                f"key {fp} is not in the recorder trust configuration" if trusted else
                f"key {fp} cannot be trusted: no recorder trust configuration was supplied")
            continue
        if entry.revoked:
            bad(AttestationStatus.REVOKED_KEY,
                f"key {fp} ({entry.label or 'unlabelled'}) is revoked"
                + (f" as of {entry.revoked_on}" if entry.revoked_on else "")
                + "; every attestation it signed is rejected, whatever date it states")
            continue
        try:
            sig = att.signature_bytes()
        except RecorderAttestationError as exc:
            bad(AttestationStatus.MALFORMED, str(exc))
            continue
        if not entry.key.verify(att.signed_payload(), sig):
            bad(AttestationStatus.BAD_SIGNATURE,
                f"the signature does not verify under key {fp} over the stated content")
            continue
        # A genuine signature. Now: is it a repeat, and is it about THIS recording?
        if att.attestation_id in seen_ids or ah in seen_hashes:
            bad(AttestationStatus.DUPLICATE,
                f"attestation {att.attestation_id} was already supplied")
            continue
        seen_ids.add(att.attestation_id)
        seen_hashes.add(ah)
        mismatch = _trace_mismatch(att, facts)
        if mismatch:
            bad(AttestationStatus.TRACE_MISMATCH, mismatch)
            continue
        wanted = machine_ref
        machine = _machine_mismatch(att, wanted)
        if machine:
            bad(AttestationStatus.MACHINE_MISMATCH, machine)
            continue
        if facts.provenance not in entry.provenance:
            bad(AttestationStatus.PROVENANCE_NOT_PERMITTED,
                f"key {fp} is not trusted for {facts.provenance!r} recordings"
                + ("; a simulation never lifts the tier" if facts.provenance == "simulation"
                   else f" (it may attest: {', '.join(sorted(entry.provenance))})"))
            continue
        attested_day = _iso_date(att.attested_on, "attested_on")
        if attested_day > today:
            bad(AttestationStatus.NOT_YET_VALID,
                f"the attestation is dated {att.attested_on}, in the future")
            continue
        if att.expires_on and _iso_date(att.expires_on, "expires_on") < today:
            bad(AttestationStatus.EXPIRED, f"the attestation expired on {att.expires_on}")
            continue
        if attested_day < start_day:
            bad(AttestationStatus.STALE,
                f"the attestation is dated {att.attested_on}, before the recording began "
                f"({start_day.isoformat()}); it cannot be an attestation of this recording")
            continue
        if attested_day > start_day + timedelta(days=MAX_LAG_DAYS):
            bad(AttestationStatus.STALE,
                f"the attestation is dated {att.attested_on}, more than {MAX_LAG_DAYS} days "
                f"after the recording began ({start_day.isoformat()})")
            continue
        if accepted is None:
            accepted = att

    if accepted is not None:
        return RecorderAttestationAssessment(
            facts.trace_hash, AttestationStatus.ACCEPTED, accepted, tuple(findings),
            tuple(raw), on, trusted, window_checked)
    return RecorderAttestationAssessment(
        facts.trace_hash, findings[0].status if findings else AttestationStatus.MALFORMED,
        None, tuple(findings), tuple(raw), on, trusted, window_checked)


def _trace_mismatch(att: RecorderAttestation, facts: RecordingFacts) -> str:
    if att.trace_hash != facts.trace_hash:
        return (f"the attestation covers trace {att.trace_hash[:12]}, not "
                f"{facts.trace_hash[:12]}: the trace was changed after it was attested, or "
                "this is another trace")
    if att.trace_id != facts.trace_id:
        return f"the attestation names trace id {att.trace_id!r}, the trace is {facts.trace_id!r}"
    if att.provenance != facts.provenance:
        return (f"the attestation states provenance {att.provenance!r}, the trace declares "
                f"{facts.provenance!r}")
    if att.started_at != format_utc(facts.started_at):
        return (f"the attestation states the recording began {att.started_at}, the trace "
                f"says {format_utc(facts.started_at)}")
    if facts.window_known:
        assert facts.sample_count is not None  # for the type checker
        assert facts.sample_rate_hz is not None and facts.duration_s is not None
        if att.sample_count != str(facts.sample_count):
            return (f"the attestation states {att.sample_count} samples, the trace has "
                    f"{facts.sample_count}")
        if att.sample_rate_hz != decimal_text(facts.sample_rate_hz):
            return (f"the attestation states a sample rate of {att.sample_rate_hz} Hz, the "
                    f"trace declares {decimal_text(facts.sample_rate_hz)}")
        if att.duration_s != decimal_text(facts.duration_s):
            return (f"the attestation states a duration of {att.duration_s} s, the trace "
                    f"spans {decimal_text(facts.duration_s)}")
    return ""


def _machine_mismatch(att: RecorderAttestation, wanted: MachineRef) -> str:
    if att.product != wanted.product:
        return (f"the recorder says it was attached to product {att.product!r}; this "
                f"verification is of {wanted.product!r}")
    if att.product_version != wanted.product_version:
        return (f"the recorder says version {att.product_version!r}; this verification "
                f"is of {wanted.product_version!r}")
    if wanted.serial and att.machine_serial != wanted.serial:
        return (f"this verification is of machine serial {wanted.serial!r}; the recorder "
                + (f"says {att.machine_serial!r}" if att.machine_serial
                   else "names no serial"))
    return ""
