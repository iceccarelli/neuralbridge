"""The supplier side: signed advisories, and a feed that cannot be edited quietly.

    publish   SupplierIdentity, SignedAdvisory, AdvisoryFeed, verify_feed
    trust     SupplierTrustStore, evaluate_feed: pinned keys, per account

A component advisory today is an unsigned PDF in an email. Acting on a forged
one means modifying the safety system of a machine people stand next to. This is
the half of the market that makes the other half worth having.
"""

from assurance.supplier.publish import (
    FEED_FORMAT,
    AdvisoryFeed,
    FeedVerdict,
    PublishError,
    SignedAdvisory,
    SupplierIdentity,
    fetch_feed,
    publish,
    verify_feed,
    withdraw,
)
from assurance.supplier.trust import (
    TRUST_STATEMENT,
    FeedTrust,
    SupplierTrustError,
    SupplierTrustStore,
    evaluate_feed,
)

__all__ = [
    "TRUST_STATEMENT",
    "FeedTrust",
    "SupplierTrustError",
    "SupplierTrustStore",
    "evaluate_feed",
    "FEED_FORMAT",
    "AdvisoryFeed",
    "FeedVerdict",
    "PublishError",
    "SignedAdvisory",
    "SupplierIdentity",
    "fetch_feed",
    "publish",
    "verify_feed",
    "withdraw",
]
