"""The recorder keys this deployment trusts: the server's own configuration.

One reader of ``ASSURANCE_RECORDER_TRUST`` for the whole service. Never from a request:
whoever files a trace must not also supply the list of recorders who vouch for it, so no
route passes a caller's value here.

Three states, kept apart (they used to be one ``None``):

``unset``
    The variable is not set. Nobody is trusted; no attestation is accepted; every trace
    stays declared by its filer, capped at ``community``. This is the default deployment.
``configured``
    The variable names a readable, valid trust file.
``unreadable``
    The variable is set but its file is missing, unreadable, malformed, or holds a key
    this service cannot use. That is an operator mistake, and the service **fails
    closed**: it trusts nobody (an *empty* list, not "no list"), so sealing yields
    ``community`` and every reader re-assesses ``validated`` evidence against nobody and
    reads it as ``community``. It is reported once in the log and in the verification
    response, never with the file's path.

A reader that is handed no list at all believes whatever tier the sealing verifier
recorded. That is right for an offline command reading its owner's own ledger and wrong
for a hosted route, where the list may have been revoked, removed or broken since the
evidence was sealed, so every API reader takes :func:`reader_recorder_trust`, which is
never ``None``.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from assurance.machine.recorder_attestation import RecorderTrust

__all__ = [
    "ServerTrust",
    "reader_recorder_trust",
    "server_recorder_trust",
    "server_recorder_trust_state",
]

_log = logging.getLogger(__name__)

#: Problems already reported, so a broken file is surfaced once and not on every request.
_REPORTED: set[str] = set()


@dataclass(frozen=True)
class ServerTrust:
    """The server's recorder trust and how it came to be what it is."""

    status: str                          # "unset" | "configured" | "unreadable"
    trust: RecorderTrust | None
    #: One sentence for a response. Never contains the file's path.
    note: str = ""


_NOTES = {
    "unset": "no recorder trust list is configured on this server, so no recorder "
             "attestation can be accepted and every trace stays declared by its filer.",
    "configured": "",
    "unreadable": "ASSURANCE_RECORDER_TRUST is set but its file cannot be used, so this "
                  "server trusts no recorder: no attestation is accepted and validated "
                  "evidence already in the ledger is read as community until the operator "
                  "fixes the file.",
}


def _report_once(kind: str) -> None:
    if kind in _REPORTED:
        return
    _REPORTED.add(kind)
    # The exception's text is not logged: it names the file. The class is enough to act on.
    _log.error("ASSURANCE_RECORDER_TRUST is set but its file cannot be used (%s); no "
               "recorder is trusted until it is fixed.", kind)


def server_recorder_trust_state() -> ServerTrust:
    """Read the server's trust configuration: unset, configured, or set-but-unusable."""
    path = os.environ.get("ASSURANCE_RECORDER_TRUST", "")
    if not path:
        _REPORTED.clear()
        return ServerTrust("unset", None, _NOTES["unset"])
    try:
        trust = RecorderTrust.from_json(path)
    except Exception as exc:  # noqa: BLE001 - whatever is wrong with the file, trust nobody
        _report_once(type(exc).__name__)
        return ServerTrust("unreadable", RecorderTrust(), _NOTES["unreadable"])
    _REPORTED.clear()          # fixed: a later breakage is news again
    return ServerTrust("configured", trust)


def server_recorder_trust() -> RecorderTrust | None:
    """``None`` only when no trust is configured; an EMPTY list when the file is unusable."""
    return server_recorder_trust_state().trust


def reader_recorder_trust() -> RecorderTrust:
    """The list every API reader of the ledger applies: the server's, or an empty one.

    Never ``None``: ``VerificationRecord.from_ledger(..., recorder_trust=None)`` believes
    the sealed tier, which a hosted reader must not do when the operator has removed or
    broken the list. With nobody trusted, nothing re-assessed is ``validated``.
    """
    return server_recorder_trust() or RecorderTrust()
