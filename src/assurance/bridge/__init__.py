"""Where the two halves of the system meet.

    art14   a supplier advisory becomes a CRA Article 14 intake, with the
            affected product versions and the Member States already assembled
            from the fleet

A manufacturer who becomes aware of an actively exploited vulnerability has 24
hours. Everything on that form can be written under pressure except the list of
Member States the product was made available in — an inventory question whose
answer lives in four spreadsheets. The fleet already knows it.

The bridge does the inventory. It refuses the judgement.
"""

from assurance.bridge.art14 import (
    BridgeError,
    CaseDraft,
    draft_from_advisory,
    open_case,
)

__all__ = ["BridgeError", "CaseDraft", "draft_from_advisory", "open_case"]
