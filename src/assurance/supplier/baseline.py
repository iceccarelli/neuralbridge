"""Accept a re-issued, trusted feed as the new rollback baseline.

The body of ``POST /v1/supplier/trust/feed-baseline`` and of ``assurance supplier trust
baseline``: one function, so the two cannot decide differently.

A supplier that legitimately re-issued its feed no longer extends the history this account
remembered, so it stays untrusted. A named person may accept the feed in hand as the new
baseline, but only if it is one that WOULD be trusted (valid signatures under a pinned key, an
intact chain): the head is read from that feed, never typed, so an unsigned or foreign history
cannot become the baseline. This is a write to the account's trust store and a trust decision;
it moves no key and makes no untrusted feed trusted.
"""

from __future__ import annotations

from typing import Any

from assurance.attest.keys import VerifyingKey
from assurance.supplier.publish import SignedAdvisory
from assurance.supplier.trust import SupplierTrustError, SupplierTrustStore, evaluate_feed

__all__ = ["accept_feed_baseline"]


def accept_feed_baseline(
    store: SupplierTrustStore, records: list[SignedAdvisory], *,
    expect_supplier: str = "", candidate_key: VerifyingKey | None = None,
    actor: str, reason: str,
) -> dict[str, Any]:
    """Reset the remembered feed head to the head of ``records``, or raise.

    Raises :class:`SupplierTrustError` when the feed would not be trusted, is empty, or the
    store refuses the reset (no reason given, a store whose own integrity is in question).
    """
    # min_sequence=0: judge the feed on its own merits, not against the baseline being
    # replaced, or a re-issued feed could never be accepted.
    trust = evaluate_feed(records, store, expect_supplier=expect_supplier,
                          candidate_key=candidate_key, min_sequence=0)
    if not trust.policy_satisfied or not records:
        raise SupplierTrustError(
            "this feed would not be trusted (" + trust.trust_state + "), so it cannot "
            "become the baseline. Pin the supplier's key and supply a feed that verifies.")
    head = records[-1]
    previous = store.feed_head(trust.supplier_id)
    store.reset_feed_head(trust.supplier_id, head.sequence, head.content_hash(),
                          actor=actor, reason=reason)
    return {"baseline": {"supplier_id": trust.supplier_id, "sequence": head.sequence,
                         "head_hash": head.content_hash()},
            "previous": ({"sequence": previous[0], "head_hash": previous[1]}
                         if previous else None),
            "note": "Later passes are compared with this head. It does not make an "
                    "untrusted feed trusted, and it moves no key."}
