"""The supplier side: signed advisories, and a feed that cannot be edited quietly.

    publish   SupplierIdentity, SignedAdvisory, AdvisoryFeed, verify_feed

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
    publish,
    verify_feed,
    withdraw,
)

__all__ = [
    "FEED_FORMAT",
    "AdvisoryFeed",
    "FeedVerdict",
    "PublishError",
    "SignedAdvisory",
    "SupplierIdentity",
    "publish",
    "verify_feed",
    "withdraw",
]
