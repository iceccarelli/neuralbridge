"""Where an advisory handed over as a bare file or request body came from.

A file on disk or a JSON body has no signature to check and no key to pin. It can be
assessed; it is not a trusted supplier statement. Every entry point that accepts one says so
with the same provenance, so the answer does not depend on which door it came through.
"""

from __future__ import annotations

from typing import Any

__all__ = ["bare_provenance"]

_BARE = {
    "file": ("bare_file", "unauthenticated_file"),
    "body": ("request_body", "unauthenticated_input"),
}


def bare_provenance(kind: str) -> dict[str, Any]:
    """``kind`` is ``file`` (a path on a command line) or ``body`` (an HTTP request body)."""
    source, state = _BARE[kind]
    return {
        "source": source, "trust_state": state, "trust_basis": "none",
        "signature_state": "none", "automated_consequences_permitted": False,
        "inspect_only": True, "override": None, "implications_reviewed": False,
    }
