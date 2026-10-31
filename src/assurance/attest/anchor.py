"""Choosing a ledger's completeness anchor from an attestation log, safely.

``EvidenceLedger.verify_report(anchor=...)`` compares a ledger with a signed head.
It does not check the signature, so *what is passed in* is the whole security of the
answer. This module is the one place that decides whether a log may supply an anchor:

* the log must be readable and not end in an unfinished line (the unfinished line may
  be the newest head);
* every record must verify against a key the **caller** holds (the service's own key
  or a public key a person pointed at). Never a key read from the log or an export;
* only a head the signer *read from the ledger* qualifies (:func:`select_anchor`): a
  ``declared_by_holder`` head describes the holder's own ledger.

If any prerequisite fails there is **no anchor**, with a plain reason for each. A
signature that does not verify is never promoted to an anchor.

What an anchor proves, and what it does not, is :data:`ANCHOR_MEANING`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from .attestation import HeadAttestation, select_anchor, verify_log
from .keys import VerifyingKey

__all__ = ["ANCHOR_MEANING", "AnchorChoice", "choose_anchor", "describe_choice"]

ANCHOR_MEANING = (
    "An anchor shows this ledger is at least as long as, and agrees with, a head that "
    "the key with the stated fingerprint signed at the stated time. It covers nothing "
    "appended after that head. A signature proves who signed the head, not that the "
    "records behind it are true or were ever correct."
)


@dataclass(frozen=True)
class AnchorChoice:
    """The anchor to compare with, or why there is none."""

    anchor: dict[str, Any] | None
    #: One plain sentence per prerequisite that was missing. Empty when ``anchor`` is set.
    reasons: list[str] = field(default_factory=list)
    key_fingerprint: str = ""


def choose_anchor(
    records: Sequence[HeadAttestation],
    key: VerifyingKey | None,
    *,
    torn: bool = False,
    log_label: str = "the attestation log",
) -> AnchorChoice:
    """The newest head in *records* that *key* verifiably signed, or the reasons not."""
    if key is None:
        return AnchorChoice(None, [
            "no service signing key is configured, so no attestation could be verified "
            "and none is used as an anchor"])
    if torn:
        return AnchorChoice(None, [
            f"{log_label} ends in an unfinished line that may be the newest head; no "
            "earlier record is used in its place"], key.fingerprint)
    if not records:
        return AnchorChoice(None, [
            f"{log_label} holds no attestations (or does not exist)"], key.fingerprint)
    verdict = verify_log(records, key)
    if not verdict.ok:
        return AnchorChoice(None, [
            f"{log_label} does not verify against the service key {key.fingerprint} "
            f"({verdict.problems[0]}); nothing in it is used as an anchor"], key.fingerprint)
    chosen = select_anchor(records)
    if chosen is None:
        return AnchorChoice(None, [
            f"{log_label} holds only heads declared by the account holder (a ledger the "
            "service never read); they describe the holder's own ledger and cannot "
            "anchor this one"], key.fingerprint)
    # verify_log passed for every record, but the anchor is the thing everything rests
    # on, so its own signature is checked once more at the point of use.
    if not chosen.verified_by(key):  # pragma: no cover - verify_log just proved it
        return AnchorChoice(None, [
            f"attestation {chosen.sequence} does not verify against the service key"],
            key.fingerprint)
    return AnchorChoice(chosen.to_dict(), [], key.fingerprint)


def describe_choice(choice: AnchorChoice) -> dict[str, Any] | None:
    """The anchor's identifying facts for a response (no signature bytes)."""
    if choice.anchor is None:
        return None
    a = choice.anchor
    return {
        "sequence": a["sequence"],
        "attested_at": a["attested_at"],
        "ledger_length": a["ledger_length"],
        "head_seq": a["head_seq"],
        "head_link_hash": a["head_link_hash"],
        "key_fingerprint": a["key_fingerprint"],
        "basis": a["basis"],
    }
