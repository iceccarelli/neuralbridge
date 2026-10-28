"""Which supplier keys this account trusts, and what a feed is worth under them.

``verify_feed`` answers one question: do these signatures verify under *this*
key. It cannot answer the one that matters, because the key a caller hands it
is whatever the caller happens to hold. Six different facts get called
"verified" in this industry and they are not interchangeable:

1. **readable**  — the feed parses. Anyone can write a readable forgery.
2. **signature valid** — the bytes were signed by the holder of a given key.
3. **key trusted for this supplier** — that key's fingerprint was pinned,
   for *this* supplier id, by a person, from a source that is not the feed. A
   fingerprint printed inside a feed proves nothing: the forger prints their own.
4. **chain intact** — sequence unbroken, each record names its predecessor, no
   id published twice, no id published with different content.
5. **matches enrolled machines** — a fleet question; see ``fleet.impact``.
6. **implications reviewed** — a human decision. This module only carries the
   field; nothing here decides it.

This module keeps 1–4 apart and never folds them into one boolean. The only
combination it calls ``trusted`` is: every record signature valid, under a key
that was pinned for that supplier and was in force on the record's date and has
not been revoked, on an intact chain, with no conflicting duplicates, read
from a trust store whose ledger verifies. Anything less is *untrusted*: the
advisory can still be read and impact-assessed by an operator ("inspect"), but
it carries no automated consequence — no stop-use, no case opened as a trusted
supplier statement — until a person either pins the key or records an explicit,
attributed override.

What a trusted feed still is not: a signed advisory proves who signed these
bytes. It does not prove the advisory is correct, complete or timely.

The store is a set of records in the *account's own* evidence ledger. It is
append-only and attributed: pin, rotation (new key pinned, old retired with an
effective date), revocation and overrides are each a sealed evidence object with
an actor. State is the replay of those records, so the history is the audit
trail. The shared operator ledger must never be passed in.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from ..attest.keys import SigningKeyError, VerifyingKey
from ..core.errors import AssuranceError, LedgerConflictError
from ..core.evidence import Actor, Confidence, Evidence, Origin, ValidationState
from ..core.identity import content_hash_of, format_utc, parse_utc, utc_now
from ..evidence.ledger import EvidenceLedger
from .publish import FEED_FORMAT, PublishError, SignedAdvisory

__all__ = [
    "TRUST_KIND",
    "TRUST_STATEMENT",
    "TRUST_SUBJECT",
    "FeedTrust",
    "KeyPin",
    "RecordTrust",
    "SupplierTrustError",
    "SupplierTrustStore",
    "evaluate_feed",
]

_EPOCH = "1970-01-01T00:00:00Z"
TRUST_KIND = "supplier.trust"
TRUST_SUBJECT = "supplier-trust"

#: Said wherever an output describes trust. It travels with the claim.
TRUST_STATEMENT = (
    "A signed advisory proves who signed these bytes. It does not prove that the "
    "advisory is correct, complete or timely: a supplier who has not noticed a "
    "defect publishes nothing, and no signature can tell you that. Nor can a feed "
    "show that its newest records are present unless the reader supplies the highest "
    "sequence it has already seen."
)


class SupplierTrustError(AssuranceError):
    """A pin, rotation, revocation or override that must not be recorded."""


# ---------------------------------------------------------------------------
# the store
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class KeyPin:
    """One public key pinned to one supplier, as the ledger replays it."""

    supplier_id: str
    fingerprint: str
    public_key_pem: str
    #: ``active`` | ``retired`` | ``revoked``
    status: str
    effective_from: str
    pinned_by: str
    obtained_via: str
    pinned_at: str
    retired_at: str = ""
    revoked_at: str = ""
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "supplier_id": self.supplier_id, "fingerprint": self.fingerprint,
            "status": self.status, "effective_from": self.effective_from,
            "retired_at": self.retired_at, "revoked_at": self.revoked_at,
            "pinned_by": self.pinned_by, "obtained_via": self.obtained_via,
            "pinned_at": self.pinned_at, "reason": self.reason,
        }

    def in_force_at(self, when: datetime) -> str:
        """``trusted`` or the reason this key does not cover ``when``."""
        if self.status == "revoked":
            return "revoked"
        if when < parse_utc(self.effective_from):
            return "not_yet_effective"
        if self.retired_at and when >= parse_utc(self.retired_at):
            return "retired"
        return "trusted"


@dataclass(frozen=True)
class _Override:
    supplier_id: str
    advisory_id: str
    advisory_hash: str
    actor: str
    reason: str
    at: str
    ledger_seq: int

    def to_dict(self) -> dict[str, Any]:
        return {"supplier_id": self.supplier_id, "advisory_id": self.advisory_id,
                "advisory_hash": self.advisory_hash, "actor": self.actor,
                "reason": self.reason, "at": self.at, "ledger_seq": self.ledger_seq}


@dataclass(frozen=True)
class _State:
    pins: dict[str, KeyPin]
    overrides: tuple[_Override, ...]
    events: tuple[dict[str, Any], ...]
    problems: tuple[str, ...]
    head: int
    #: supplier id -> (highest feed sequence a trusted evaluation saw, that record's hash)
    feed_heads: dict[str, tuple[int, str]] = field(default_factory=dict)


def _fp_of(pem: str) -> str:
    try:
        return VerifyingKey.from_pem(pem).fingerprint
    except SigningKeyError as exc:
        raise SupplierTrustError(f"not a usable Ed25519 public key: {exc}") from exc


class SupplierTrustStore:
    """Pins, rotations, revocations and overrides, in one account's ledger.

    Pass the *account's* ledger. The store refuses nothing about which ledger it
    is given (it cannot know), so the callers that serve tenants — the API —
    refuse the shared operator ledger before constructing one.
    """

    def __init__(self, ledger: EvidenceLedger) -> None:
        self.ledger = ledger

    # -- reading --------------------------------------------------------
    def _replay(self) -> _State:
        pins: dict[str, KeyPin] = {}
        overrides: list[_Override] = []
        events: list[dict[str, Any]] = []
        problems: list[str] = []
        heads: dict[str, tuple[int, str]] = {}
        head = 0
        for entry in self.ledger.entries(subject=TRUST_SUBJECT, kind=TRUST_KIND):
            head = entry.seq
            ev = entry.evidence()
            if not ev.verify():
                problems.append(
                    f"trust record at ledger seq {entry.seq} does not match its own "
                    "hash; nothing is trusted from a store that has been edited")
                continue
            body = ev.body
            events.append({"ledger_seq": entry.seq, "at": entry.at,
                           "actor": ev.actor.identifier, **body})
            kind = body.get("event")
            if kind in ("pin", "rotate"):
                fp = str(body["fingerprint"])
                pins[fp] = KeyPin(
                    supplier_id=str(body["supplier_id"]), fingerprint=fp,
                    public_key_pem=str(body["public_key_pem"]), status="active",
                    effective_from=str(body["effective_from"]),
                    pinned_by=ev.actor.identifier,
                    obtained_via=str(body.get("obtained_via", "")),
                    pinned_at=entry.at, reason=str(body.get("reason", "")))
                if kind == "rotate":
                    old = pins.get(str(body["retire_fingerprint"]))
                    if old is not None and old.status == "active":
                        pins[old.fingerprint] = _with(
                            old, status="retired", retired_at=str(body["effective_from"]),
                            reason=str(body.get("reason", "")))
            elif kind == "revoke":
                old = pins.get(str(body["fingerprint"]))
                if old is not None:
                    pins[old.fingerprint] = _with(
                        old, status="revoked", revoked_at=str(body["revoked_at"]),
                        reason=str(body.get("reason", "")))
            elif kind in ("feed_head", "feed_head_reset"):
                sup = str(body["supplier_id"])
                seq = int(body["sequence"])
                # A recorded head only moves forward; only a person's reset moves it back.
                if kind == "feed_head_reset" or seq > heads.get(sup, (0, ""))[0]:
                    heads[sup] = (seq, str(body["head_hash"]))
            elif kind == "override":
                overrides.append(_Override(
                    supplier_id=str(body["supplier_id"]),
                    advisory_id=str(body["advisory_id"]),
                    advisory_hash=str(body["advisory_hash"]),
                    actor=ev.actor.identifier, reason=str(body.get("reason", "")),
                    at=entry.at, ledger_seq=entry.seq))
        return _State(pins, tuple(overrides), tuple(events), tuple(problems), head, heads)

    def feed_head(self, supplier_id: str) -> tuple[int, str] | None:
        """The newest feed record a trusted evaluation has seen for this supplier.

        ``(sequence, content hash)``, or None when none has been recorded. Passed to
        :func:`evaluate_feed` as ``min_sequence`` / ``expect_head`` so a feed that has
        been cut back, or swapped for an older copy, is not trusted.
        """
        return self._replay().feed_heads.get(supplier_id.strip())

    def record_feed_head(self, supplier_id: str, sequence: int, head_hash: str, *,
                         actor: str = "assurance.watch") -> bool:
        """Remember the newest record of a feed that was just trusted.

        Best effort and monotonic: returns False, writing nothing, when the head has not
        advanced or the store changed while this was prepared (the next pass records it).
        Not a trust decision, so it carries the automation that observed it.
        """
        supplier_id = supplier_id.strip()
        state = self._replay()
        if state.problems or sequence <= state.feed_heads.get(supplier_id, (0, ""))[0]:
            return False
        try:
            self._append(state, {
                "event": "feed_head", "supplier_id": supplier_id,
                "sequence": int(sequence), "head_hash": head_hash,
            }, actor, "newest record of a trusted feed")
        except SupplierTrustError:
            return False
        return True

    def reset_feed_head(self, supplier_id: str, sequence: int, head_hash: str, *,
                        actor: str, reason: str) -> None:
        """A named person accepts a different history as the new baseline.

        For the case where a supplier legitimately re-issued its feed. Without this a
        feed that no longer extends the remembered one stays untrusted (inspect only).
        """
        if not reason.strip():
            raise SupplierTrustError("resetting a feed baseline needs a reason.")
        supplier_id = supplier_id.strip()
        self._append(self._replay(), {
            "event": "feed_head_reset", "supplier_id": supplier_id,
            "sequence": int(sequence), "head_hash": head_hash, "reason": reason,
        }, actor, "feed baseline reset by a person")

    def pins(self, supplier_id: str = "") -> list[KeyPin]:
        state = self._replay()
        return [p for p in state.pins.values()
                if not supplier_id or p.supplier_id == supplier_id]

    def history(self) -> list[dict[str, Any]]:
        """Every trust decision, oldest first, with who made it. PEMs omitted."""
        return [{k: v for k, v in e.items() if k != "public_key_pem"}
                for e in self._replay().events]

    def overrides(self) -> list[dict[str, Any]]:
        return [o.to_dict() for o in self._replay().overrides]

    def integrity_problems(self) -> list[str]:
        """Problems that mean nothing may be trusted from this store."""
        problems = list(self._replay().problems)
        ok, chain = self.ledger.verify_chain()
        if not ok:
            problems.append("the ledger holding the trust store does not verify: "
                            + "; ".join(chain[:3]))
        return problems

    # -- writing --------------------------------------------------------
    def _append(self, state: _State, body: dict[str, Any], actor: str,
                note: str) -> dict[str, Any]:
        if not actor.strip():
            raise SupplierTrustError(
                "a trust decision needs an actor. An unattributed decision about "
                "which key may drive a safety change is not an audit trail.")
        ev = Evidence(
            kind=TRUST_KIND, body=body, actor=Actor(actor.strip(), "trust decision"),
            origin=Origin(system="assurance.supplier.trust", reference=body["supplier_id"],
                          method=note),
            validation_state=ValidationState.UNVERIFIED, confidence=Confidence.NONE,
            checks_skipped=(
                "recording a pin records that a person said this fingerprint belongs "
                "to this supplier. It does not check that they were right; the route "
                "by which they learned it is in `obtained_via`.",),
        ).seal()
        try:
            self.ledger.append(ev, subject=TRUST_SUBJECT,
                               expect_subject_head=state.head, expect_kinds=[TRUST_KIND])
        except LedgerConflictError as exc:
            raise SupplierTrustError(
                "the trust store changed while this decision was prepared; read it "
                "again and retry. Nothing was written.") from exc
        return body

    def pin(self, supplier_id: str, public_key_pem: str, *, actor: str,
            obtained_via: str, expected_fingerprint: str = "",
            effective_from: datetime | None = None, reason: str = "") -> KeyPin:
        """Trust this key for this supplier (from ``effective_from`` if given).

        ``obtained_via`` is required: where the fingerprint came from, which must
        not be the feed. ``expected_fingerprint`` is what the person read off the
        contract or heard on the phone; when given, the key must match it.
        """
        supplier_id = supplier_id.strip()
        if not supplier_id:
            raise SupplierTrustError("a pin names a supplier id.")
        if not obtained_via.strip():
            raise SupplierTrustError(
                "obtained_via is empty. Say how you learned this fingerprint (the "
                "contract, a phone call, the documentation folder). A fingerprint "
                "that came from the feed it signs is not a pin.")
        fp = _fp_of(public_key_pem)
        if expected_fingerprint and expected_fingerprint.strip().lower() != fp:
            raise SupplierTrustError(
                f"the key offered has fingerprint {fp}, not the {expected_fingerprint} "
                "you were given independently. Do not pin it.")
        state = self._replay()
        self._refuse_reuse(state, supplier_id, fp)
        active = [p for p in state.pins.values()
                  if p.supplier_id == supplier_id and p.status == "active"]
        if active:
            raise SupplierTrustError(
                f"{supplier_id} already has an active pinned key ({active[0].fingerprint}). "
                "A second key is a rotation: use rotate, with an effective date.")
        # A pin says "this key is the supplier's". It has no start date unless one
        # is given: a customer who pins today must still be able to check last
        # month's advisory. Dates matter for a rotation, where they are explicit.
        when = format_utc(effective_from) if effective_from else _EPOCH
        self._append(state, {
            "event": "pin", "supplier_id": supplier_id, "fingerprint": fp,
            "public_key_pem": public_key_pem, "effective_from": when,
            "obtained_via": obtained_via.strip(), "reason": reason,
        }, actor, "key pinned by a person")
        return self._replay().pins[fp]

    def rotate(self, supplier_id: str, new_public_key_pem: str, *, retire_fingerprint: str,
               effective_at: datetime, actor: str, obtained_via: str,
               expected_fingerprint: str = "", reason: str = "") -> KeyPin:
        """Pin a new key and retire the old one from ``effective_at``."""
        if not obtained_via.strip():
            raise SupplierTrustError(
                "obtained_via is empty: how did you learn the new fingerprint? Not "
                "from the feed that announces the rotation.")
        fp = _fp_of(new_public_key_pem)
        if expected_fingerprint and expected_fingerprint.strip().lower() != fp:
            raise SupplierTrustError(
                f"the new key has fingerprint {fp}, not the {expected_fingerprint} "
                "you were given independently. Do not pin it.")
        state = self._replay()
        old = state.pins.get(retire_fingerprint)
        if old is None or old.supplier_id != supplier_id or old.status != "active":
            raise SupplierTrustError(
                f"{retire_fingerprint} is not an active key pinned for {supplier_id}.")
        self._refuse_reuse(state, supplier_id, fp)
        if effective_at <= parse_utc(old.effective_from):
            raise SupplierTrustError(
                "the rotation must take effect after the old key came into force.")
        self._append(state, {
            "event": "rotate", "supplier_id": supplier_id, "fingerprint": fp,
            "public_key_pem": new_public_key_pem, "retire_fingerprint": retire_fingerprint,
            "effective_from": format_utc(effective_at), "obtained_via": obtained_via.strip(),
            "reason": reason,
        }, actor, "key rotated by a person")
        return self._replay().pins[fp]

    def revoke(self, supplier_id: str, fingerprint: str, *, actor: str, reason: str,
               revoked_at: datetime | None = None) -> KeyPin:
        """Stop trusting a key. Every record it signed becomes untrusted."""
        if not reason.strip():
            raise SupplierTrustError("a revocation needs a reason.")
        state = self._replay()
        pin = state.pins.get(fingerprint)
        if pin is None or pin.supplier_id != supplier_id:
            raise SupplierTrustError(f"{fingerprint} is not pinned for {supplier_id}.")
        if pin.status == "revoked":
            raise SupplierTrustError(f"{fingerprint} is already revoked.")
        self._append(state, {
            "event": "revoke", "supplier_id": supplier_id, "fingerprint": fingerprint,
            "revoked_at": format_utc(revoked_at or utc_now()), "reason": reason.strip(),
        }, actor, "key revoked by a person")
        return self._replay().pins[fingerprint]

    def override(self, trust: FeedTrust, advisory_id: str, *, actor: str,
                 reason: str) -> dict[str, Any]:
        """Explicitly accept ONE advisory from a feed that did not meet policy.

        Bound to the advisory's content hash: if the supplier's bytes change, the
        override stops applying. Refused where the failure is positive evidence
        of tampering (a signature that fails under a known key, a revoked key, a
        content conflict) rather than an inability to check.
        """
        if not reason.strip():
            raise SupplierTrustError("an override needs a reason.")
        row = next((a for a in trust.advisories if a["advisory_id"] == advisory_id), None)
        if row is None:
            raise SupplierTrustError(f"{advisory_id} is not a standing advisory in that feed.")
        if row["override_refused"]:
            raise SupplierTrustError(
                f"{advisory_id} cannot be overridden: {row['override_refused']}")
        state = self._replay()
        self._append(state, {
            "event": "override", "supplier_id": row["supplier_id"],
            "advisory_id": advisory_id, "advisory_hash": row["advisory_hash"],
            "reason": reason.strip(), "feed_trust_state": trust.trust_state,
            "feed_problems": list(trust.problems)[:20],
        }, actor, "manual override of supplier trust policy")
        return {"advisory_id": advisory_id, "advisory_hash": row["advisory_hash"],
                "actor": actor, "reason": reason.strip()}

    @staticmethod
    def _refuse_reuse(state: _State, supplier_id: str, fp: str) -> None:
        existing = state.pins.get(fp)
        if existing is None:
            return
        if existing.supplier_id != supplier_id:
            raise SupplierTrustError(
                f"key {fp} is already pinned for {existing.supplier_id!r}. One key, "
                "one supplier.")
        raise SupplierTrustError(
            f"key {fp} is already pinned for {supplier_id} (status {existing.status}); "
            "a retired or revoked key is never re-pinned.")


def _with(pin: KeyPin, **changes: str) -> KeyPin:
    return replace(pin, **changes)


# ---------------------------------------------------------------------------
# evaluation
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class RecordTrust:
    """One feed record, with signature and key trust kept apart."""

    sequence: int
    advisory_id: str
    is_withdrawal: bool
    key_fingerprint: str
    #: ``valid`` | ``invalid`` | ``malformed`` | ``not_checkable`` (no key to try)
    signature: str
    #: ``trusted`` | ``unknown_key`` | ``wrong_supplier`` | ``revoked`` | ``retired``
    #: | ``not_yet_effective`` | ``store_unhealthy``
    key_trust: str
    #: Signature valid under a key in force: this record is authentic.
    authentic: bool
    #: A signature that verified under an UNPINNED key supplied by the caller.
    signature_valid_under_candidate: bool | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence, "advisory_id": self.advisory_id,
            "is_withdrawal": self.is_withdrawal, "key_fingerprint": self.key_fingerprint,
            "signature": self.signature, "key_trust": self.key_trust,
            "authentic": self.authentic,
            "signature_valid_under_candidate": self.signature_valid_under_candidate,
        }


@dataclass(frozen=True)
class FeedTrust:
    """What a feed is, state by state. There is deliberately no ``verified`` field."""

    #: 1. parses, and has records
    structurally_readable: bool
    record_count: int
    #: 2. ``all_valid`` | ``some_invalid`` | ``not_checkable`` | ``none``
    signature_state: str
    #: 3. ``pinned`` | ``unknown_key`` | ``revoked`` | ``retired`` | ``wrong_supplier``
    #: | ``not_yet_effective`` | ``store_unhealthy`` | ``none``
    key_trust_state: str
    #: 4.
    chain_valid: bool
    chain_problems: tuple[str, ...]
    duplicate_advisories: tuple[str, ...]
    conflicting_advisories: tuple[str, ...]
    supplier_id: str
    key_fingerprints: tuple[str, ...]
    records: tuple[RecordTrust, ...]
    #: Standing advisories, each with its own trust basis. 6 lives here:
    #: ``implications_reviewed`` is False until a person records otherwise.
    advisories: tuple[dict[str, Any], ...]
    withdrawn: tuple[str, ...]
    unauthenticated_withdrawals: tuple[str, ...]
    problems: tuple[str, ...]
    #: ``trusted`` or ``untrusted_<reason>`` — a summary of 1–4, never a substitute.
    trust_state: str
    #: The policy outcome: 1, 2, 3, 4 all satisfied.
    policy_satisfied: bool
    trust_statement: str = TRUST_STATEMENT

    @property
    def inspect_only(self) -> bool:
        """No advisory here carries automated consequences."""
        return not any(a["automated_consequences_permitted"] for a in self.advisories)

    def permitted(self, advisory_id: str) -> bool:
        return any(a["advisory_id"] == advisory_id and a["automated_consequences_permitted"]
                   for a in self.advisories)

    def provenance_for(self, advisory_id: str) -> dict[str, Any]:
        """The small dict ``fleet.impact`` stamps on a report built from this advisory."""
        row = next((a for a in self.advisories if a["advisory_id"] == advisory_id), {})
        return {
            "source": "supplier_feed",
            "trust_state": self.trust_state,
            "trust_basis": row.get("trust_basis", "none"),
            "signature_state": self.signature_state,
            "key_trust_state": self.key_trust_state,
            "chain_valid": self.chain_valid,
            "automated_consequences_permitted": bool(
                row.get("automated_consequences_permitted", False)),
            "inspect_only": not row.get("automated_consequences_permitted", False),
            "override": row.get("override"),
            "implications_reviewed": bool(row.get("implications_reviewed", False)),
            "problems": list(self.problems)[:10],
            "trust_statement": self.trust_statement,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_state": self.trust_state,
            "policy_satisfied": self.policy_satisfied,
            "inspect_only": self.inspect_only,
            "structurally_readable": self.structurally_readable,
            "record_count": self.record_count,
            "signature_state": self.signature_state,
            "key_trust_state": self.key_trust_state,
            "chain_valid": self.chain_valid,
            "chain_problems": list(self.chain_problems),
            "duplicate_advisories": list(self.duplicate_advisories),
            "conflicting_advisories": list(self.conflicting_advisories),
            "supplier_id": self.supplier_id,
            "key_fingerprints": list(self.key_fingerprints),
            "records": [r.to_dict() for r in self.records],
            "advisories": [dict(a) for a in self.advisories],
            "withdrawn": list(self.withdrawn),
            "unauthenticated_withdrawals": list(self.unauthenticated_withdrawals),
            "problems": list(self.problems),
            "trust_statement": self.trust_statement,
        }

    def summary(self) -> str:
        if self.policy_satisfied:
            return (f"TRUSTED — {self.record_count} record(s) from {self.supplier_id} "
                    f"signed by pinned key {', '.join(self.key_fingerprints)}; "
                    f"{len(self.advisories)} advisory(ies) stand, {len(self.withdrawn)} "
                    "withdrawn")
        return (f"UNTRUSTED ({self.trust_state.removeprefix('untrusted_')}) — inspect "
                "only; no automated consequence may follow from this feed")


def _chain_problems(items: list[SignedAdvisory]) -> list[str]:
    problems: list[str] = []
    expected = 1
    previous: SignedAdvisory | None = None
    for record in items:
        where = f"record {record.sequence}"
        if record.format != FEED_FORMAT:
            problems.append(f"{where}: format is {record.format!r}, expected {FEED_FORMAT!r}")
        if record.sequence != expected:
            problems.append(f"{where}: out of order, expected {expected} — a record was "
                            "removed, duplicated or the file was reordered")
            expected = record.sequence
        want = previous.content_hash() if previous else ""
        if record.previous != want:
            problems.append(
                f"{where}: names predecessor {record.previous[:12] or '(none)'} but "
                f"follows {want[:12] or '(none)'} — the chain is broken here")
        previous = record
        expected += 1
    return problems


def _advisory_hash(record: SignedAdvisory) -> str:
    return content_hash_of(record.advisory)


def evaluate_feed(
    records: Iterable[SignedAdvisory],
    store: SupplierTrustStore | None,
    *,
    expect_supplier: str = "",
    candidate_key: VerifyingKey | None = None,
    now: datetime | None = None,
    min_sequence: int | None = None,
    expect_head: str = "",
) -> FeedTrust:
    """Judge a feed under the account's pinned keys. Never raises on a bad feed.

    ``candidate_key`` is a key the caller holds but has NOT pinned. It lets the
    evaluation say "the signatures are valid under this key" (state 2) without
    ever turning that into trust (state 3).
    """
    items = list(records)
    problems: list[str] = []
    state: _State | None = None
    store_problems: list[str] = []
    if store is not None:
        store_problems = store.integrity_problems()
        if not store_problems:
            state = store._replay()
    pins = state.pins if state is not None else {}

    suppliers = sorted({r.supplier.supplier_id for r in items})
    if not items:
        problems.append(
            "the feed is empty. That is a supplier with nothing published or a file "
            "that did not arrive, and nothing in the file can say which.")
    if len(suppliers) > 1:
        problems.append("the feed carries more than one supplier ("
                        + ", ".join(suppliers) + ").")
    if expect_supplier and suppliers and expect_supplier not in suppliers:
        problems.append(f"expected a feed from {expect_supplier!r}; this one is from "
                        + ", ".join(suppliers))
    problems.extend(store_problems)

    per_record: list[RecordTrust] = []
    for r in items:
        sig = "not_checkable"
        candidate_ok: bool | None = None
        pin = pins.get(r.key_fingerprint)
        key_trust: str
        if store_problems:
            key_trust = "store_unhealthy"
        elif pin is None:
            key_trust = "unknown_key"
        elif pin.supplier_id != r.supplier.supplier_id:
            key_trust = "wrong_supplier"
        else:
            try:
                when = parse_utc(r.published_at)
                key_trust = pin.in_force_at(when)
            except ValueError:
                key_trust = "not_yet_effective"
                problems.append(f"record {r.sequence}: published_at {r.published_at!r} "
                                "is not a timestamp")
        try:
            if pin is not None and key_trust != "store_unhealthy":
                vk = VerifyingKey.from_pem(pin.public_key_pem)
                sig = "valid" if r.verified_by(vk) else "invalid"
            elif candidate_key is not None:
                candidate_ok = r.verified_by(candidate_key)
                sig = "valid" if candidate_ok else "invalid"
        except (PublishError, SigningKeyError, ValueError):
            sig = "malformed"
        per_record.append(RecordTrust(
            sequence=r.sequence, advisory_id=r.advisory_id, is_withdrawal=r.is_withdrawal,
            key_fingerprint=r.key_fingerprint, signature=sig, key_trust=key_trust,
            authentic=(sig == "valid" and key_trust == "trusted"),
            signature_valid_under_candidate=candidate_ok if pin is None else None))

    chain_problems = _chain_problems(items)
    # A valid chain cannot show that the newest records were cut off or an older copy
    # was served. A reader that remembers the highest sequence (and that record's
    # hash) can: a shorter or rewritten feed is not an intact chain.
    if min_sequence is None:
        # Not stated by the caller: use what this account remembers for the supplier, so
        # every path that judges a feed (API, CLI, watch) holds it to the same baseline.
        # Pass 0 to judge a feed with no baseline (accepting a re-issued feed).
        min_sequence, expect_head = 0, ""
        if store is not None and len(suppliers) == 1:
            seen = store.feed_head(suppliers[0])
            if seen:
                min_sequence, expect_head = seen
    if min_sequence:
        tip = items[-1].sequence if items else 0
        if tip < min_sequence:
            chain_problems.append(
                f"the feed ends at record {tip} but record {min_sequence} was seen "
                "before: newer records were removed or an older copy was served, and a "
                "withdrawal may be missing")
        elif expect_head:
            seen = [r for r in items if r.sequence == min_sequence]
            if not seen or seen[0].content_hash() != expect_head:
                chain_problems.append(
                    f"record {min_sequence} is not the record seen before: the feed was "
                    "rewritten or replaced")
    problems.extend(chain_problems)

    # duplicates and conflicts: same id, same content vs different content
    seen: dict[str, SignedAdvisory] = {}
    dup: list[str] = []
    conflict: list[str] = []
    for r in items:
        if r.is_withdrawal:
            target = seen.get(r.withdraws)
            if target is None:
                problems.append(f"record {r.sequence}: withdraws {r.withdraws}, which "
                                "this feed does not contain")
            elif _advisory_hash(target) != _advisory_hash(r):
                if r.withdraws not in conflict:
                    conflict.append(r.withdraws)
                problems.append(f"record {r.sequence}: the withdrawal of {r.withdraws} "
                                "carries different content from the advisory it withdraws")
            continue
        prior = seen.get(r.advisory_id)
        if prior is None:
            seen[r.advisory_id] = r
        elif _advisory_hash(prior) == _advisory_hash(r):
            if r.advisory_id not in dup:
                dup.append(r.advisory_id)
            problems.append(f"record {r.sequence}: {r.advisory_id} published again "
                            "with identical content")
        else:
            if r.advisory_id not in conflict:
                conflict.append(r.advisory_id)
            problems.append(f"record {r.sequence}: {r.advisory_id} reappears with "
                            "DIFFERENT content — two statements under one identity")

    # standing advisories; a withdrawal counts only if authentic
    auth_by_seq = {rt.sequence: rt for rt in per_record}
    standing: dict[str, SignedAdvisory] = {}
    withdrawn: list[str] = []
    bad_withdrawals: list[str] = []
    for r in items:
        rt = auth_by_seq[r.sequence]
        if r.is_withdrawal:
            if rt.authentic:
                if r.withdraws in standing:
                    standing.pop(r.withdraws)
                    withdrawn.append(r.withdraws)
            else:
                bad_withdrawals.append(r.withdraws)
        else:
            standing.setdefault(r.advisory_id, r)
    if bad_withdrawals:
        problems.append(
            "withdrawal(s) of " + ", ".join(bad_withdrawals) + " are not authentic and "
            "were NOT applied: an unauthenticated retraction must not cancel an advisory.")

    # feed-level states
    sigs = {rt.signature for rt in per_record}
    if not per_record:
        signature_state = "none"
    elif sigs == {"valid"}:
        signature_state = "all_valid"
    elif sigs & {"invalid", "malformed"}:
        signature_state = "some_invalid"
    else:
        signature_state = "not_checkable"
    kt = [rt.key_trust for rt in per_record]
    key_state = "none"
    for bad in ("store_unhealthy", "revoked", "wrong_supplier", "unknown_key",
                "not_yet_effective", "retired"):
        if bad in kt:
            key_state = bad
            break
    else:
        if kt:
            key_state = "pinned"

    chain_ok = not chain_problems
    for rt in per_record:
        if rt.signature == "invalid":
            problems.append(f"record {rt.sequence} ({rt.advisory_id}): signature does "
                            f"not verify under key {rt.key_fingerprint}")
        elif rt.signature == "malformed":
            problems.append(f"record {rt.sequence} ({rt.advisory_id}): signature is "
                            "malformed; the feed is damaged, not unsigned")
        if rt.key_trust not in ("trusted", "store_unhealthy"):
            problems.append(f"record {rt.sequence} ({rt.advisory_id}): key "
                            f"{rt.key_fingerprint} is {rt.key_trust.replace('_', ' ')}"
                            " for this supplier")

    all_authentic = bool(per_record) and all(rt.authentic for rt in per_record)
    single_supplier = len(suppliers) == 1 and (not expect_supplier or
                                              suppliers[0] == expect_supplier)
    policy = (bool(items) and all_authentic and chain_ok and not dup and not conflict
              and single_supplier and not store_problems and state is not None)

    if policy:
        trust_state = "trusted"
    elif not items:
        trust_state = "untrusted_empty"
    elif store is None or store_problems:
        trust_state = "untrusted_store_unhealthy" if store_problems else "untrusted_no_trust_store"
    elif key_state == "revoked":
        trust_state = "untrusted_revoked_key"
    elif signature_state == "some_invalid":
        trust_state = "untrusted_signature_invalid"
    elif conflict:
        trust_state = "untrusted_conflicting_advisories"
    elif not chain_ok:
        trust_state = "untrusted_chain_broken"
    elif key_state in ("unknown_key", "wrong_supplier"):
        trust_state = "untrusted_unknown_key"
    elif key_state in ("retired", "not_yet_effective"):
        trust_state = "untrusted_key_not_in_force"
    else:
        trust_state = "untrusted_policy_not_met"

    overrides = state.overrides if state is not None else ()
    when_now = format_utc(now or utc_now())
    rows: list[dict[str, Any]] = []
    for aid, r in standing.items():
        rt = auth_by_seq[r.sequence]
        h = _advisory_hash(r)
        ov = next((o for o in overrides if o.supplier_id == r.supplier.supplier_id
                   and o.advisory_id == aid and o.advisory_hash == h), None)
        refused = ""
        if rt.signature in ("invalid", "malformed"):
            refused = ("its signature FAILS under the key it claims; that is evidence "
                       "of tampering, not an inability to check")
        elif rt.key_trust == "revoked":
            refused = "it is signed by a revoked key"
        elif aid in conflict:
            refused = "the feed carries conflicting content under this advisory id"
        permitted = policy or (ov is not None and not refused)
        rows.append({
            "advisory_id": aid, "supplier_id": r.supplier.supplier_id,
            "sequence": r.sequence, "severity": str(r.advisory.get("severity", "")),
            "title": str(r.advisory.get("title", "")), "advisory_hash": h,
            "record_authentic": rt.authentic,
            "trust_basis": ("pinned_key_policy" if policy
                            else "manual_override" if permitted else "none"),
            "automated_consequences_permitted": permitted,
            "override": ov.to_dict() if (ov is not None and not policy) else None,
            "override_refused": refused,
            "implications_reviewed": False,
            "case_opened": "",
            "evaluated_at": when_now,
        })

    return FeedTrust(
        structurally_readable=bool(items), record_count=len(items),
        signature_state=signature_state, key_trust_state=key_state,
        chain_valid=chain_ok, chain_problems=tuple(chain_problems),
        duplicate_advisories=tuple(dup), conflicting_advisories=tuple(conflict),
        supplier_id=suppliers[0] if len(suppliers) == 1 else ", ".join(suppliers),
        key_fingerprints=tuple(dict.fromkeys(r.key_fingerprint for r in items)),
        records=tuple(per_record), advisories=tuple(rows), withdrawn=tuple(withdrawn),
        unauthenticated_withdrawals=tuple(bad_withdrawals),
        problems=tuple(dict.fromkeys(problems)), trust_state=trust_state,
        policy_satisfied=policy,
    )

