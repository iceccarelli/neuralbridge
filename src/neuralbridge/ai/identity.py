"""Actor identity for the /ai surface.

There is no working session/auth layer anywhere in
``src/neuralbridge`` today (``security/rbac.py``'s ``get_current_user()``
is a hardcoded mock; ``security/auth.py``'s real JWT implementation is
unwired to any route — see ``reports/NEURALBRIDGE-AI-SECURITY-MATRIX.md``).
Rather than pretend to full authentication this module does the one thing
Phase 1's brief actually requires: every request that reaches the
orchestrator carries a *real, non-"system"* actor identity, threaded from
here into every audit event and every plan/approval record.

This is intentionally minimal — a client-supplied, session-scoped operator
identity, not OAuth. It answers the audit trail's question ("who did
this?") honestly for a single-operator/demo deployment; it does not
answer "was this person authorized to be an operator at all?" That is the
same scope boundary ``src/assurance/api/deps.py`` draws with its
``open``/``ASSURANCE_ALLOW_UNAUTHENTICATED`` mode for local evaluation —
documented, not disguised as more than it is.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import Header

ACTOR_HEADER = "X-NB-Actor"
SESSION_HEADER = "X-NB-Session"

#: The one value an actor id may never be — that was the bug.
FORBIDDEN_ACTOR_IDS = {"system", "mcp_client", "anonymous", ""}


@dataclass(frozen=True)
class Actor:
    """A real identity for audit/policy purposes — never a placeholder."""

    id: str
    session_id: str
    kind: str = "human_session"  # or "service" for a non-interactive caller

    def as_audit_string(self) -> str:
        """The value threaded into ``RequestRouter.route(actor=...)``."""
        return f"{self.kind}:{self.id}"


def resolve_actor(actor_header: str | None, session_header: str | None) -> Actor:
    """Build an :class:`Actor` from request headers, defaulting safely.

    A missing/blank/forbidden actor header never falls back to
    ``"system"`` — it gets a fresh, clearly-labelled operator id instead,
    so "who did this" is always answerable from the audit trail alone.
    """
    session_id = session_header or str(uuid.uuid4())
    if not actor_header or actor_header.strip().lower() in FORBIDDEN_ACTOR_IDS:
        return Actor(id=f"operator-{session_id[:8]}", session_id=session_id)
    return Actor(id=actor_header.strip(), session_id=session_id)


async def get_current_actor(
    x_nb_actor: str | None = Header(default=None, alias=ACTOR_HEADER),
    x_nb_session: str | None = Header(default=None, alias=SESSION_HEADER),
) -> Actor:
    """FastAPI dependency — the actor for the current ``/ai`` request."""
    return resolve_actor(x_nb_actor, x_nb_session)
