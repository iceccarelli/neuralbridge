"""Industrial autonomous assurance.

Evidence infrastructure for products whose software controls physical things.

The package answers one question in several regulatory dialects: *can you prove
what this system is, what it contains, what it was tested against, what it
actually did, and why this version was allowed to ship or operate?*

Layout
------
``assurance.core``      identity, evidence objects, assurance tiers
``assurance.evidence``  the tamper-evident ledger every record lands in
``assurance.attest``    signed head attestations — the part of the ledger a
                        rewind cannot reach, because the key left the building
``assurance.security``  product-security obligations. ``security.art14`` is the
                        EU CRA reporting duty that has applied since 2026-09-11.

Nothing here imports from ``palletizer_full``. The dependency runs the other
way when it runs at all, so the assurance layer can be packaged, sold and
audited without dragging a palletising engine behind it.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
