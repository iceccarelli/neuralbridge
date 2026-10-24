"""A caller's declared role, reduced to text that cannot imitate a server token.

Several routes seal an ``Actor`` built from words the caller typed. Where the server
adds its own attribution, the sealed ``Actor.role`` reads
``"<declared> via account A; operator=O (decider); key=K; attribution=B"`` and everything
after the declared part is the server's. A reader (a regulator, an auditor, a script)
scanning a sealed record for ``attribution=authenticated_operator`` or ``operator=op_...``
must be able to believe that token came from the server and not from the request body.

``;`` and ``=`` are that grammar's separators, so they (and their full-width look-alikes,
via NFKC) are removed from the declared part, along with control and line-separator
characters; whitespace is collapsed and the length capped. The sanitiser is applied at
**every** API route that builds an ``Actor`` from caller text (``HANDOFF.md`` lists them),
not only where the server appends its own tokens: a route that seals the declared role
verbatim would otherwise let the caller write ``operator=op_x (decider)`` into the record
where nothing server-built contradicts it.

It lives here, not in a route module, so the routes share one definition.
``assurance.api.machine_routes`` re-exports it for the callers that imported it there.
"""

from __future__ import annotations

import unicodedata

__all__ = ["DEFAULT_ROLE", "MAX_DECLARED_ROLE", "sanitise_declared_role"]

DEFAULT_ROLE = "verification engineer"
MAX_DECLARED_ROLE = 80


def sanitise_declared_role(role: str, *, default: str = DEFAULT_ROLE) -> str:
    """The caller-declared role with the server's grammar taken out of it.

    An empty result falls back to *default* (``DEFAULT_ROLE`` unless the route's own
    schema says an undeclared role is the empty string, as the Article 14 register's
    does). The default is the route's constant and never caller text, so it is not
    sanitised again.
    """
    text = unicodedata.normalize("NFKC", role or "")
    text = "".join(" " if unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn")
                   else c for c in text)
    text = text.replace(";", " ").replace("=", " ")
    text = " ".join(text.split())[:MAX_DECLARED_ROLE].strip()
    return text or default
