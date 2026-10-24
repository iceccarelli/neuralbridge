"""The recorder keys this deployment trusts: the server's own configuration.

One reader of ``ASSURANCE_RECORDER_TRUST`` for the whole service. Never from a request:
whoever files a trace must not also supply the list of recorders who vouch for it, so no
route passes a caller's value here. A missing, unreadable or malformed file trusts nobody
(fail closed): with no list, no recorder attestation can be accepted and every trace stays
declared by its filer, capped at ``community``.
"""

from __future__ import annotations

import os

from assurance.core.errors import AssuranceError
from assurance.machine.recorder_attestation import RecorderTrust

__all__ = ["server_recorder_trust"]


def server_recorder_trust() -> RecorderTrust | None:
    path = os.environ.get("ASSURANCE_RECORDER_TRUST", "")
    if not path:
        return None
    try:
        return RecorderTrust.from_json(path)
    except AssuranceError:
        return None  # fail closed: a broken trust file trusts nobody
