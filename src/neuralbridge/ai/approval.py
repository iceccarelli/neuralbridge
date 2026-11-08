"""Four-eyes approval for /ai write plans — an opt-in policy, OFF by default.

Without it (the default, and what every existing customer has) the account that proposes a plan
may approve it, with the same key: one authenticated principal can propose and execute a write.
With it ON, for a tenant:

* the approver must be **independently authenticated**: a different API key than the proposer's,
  and, when both keys are bound to an individual operator, a different operator. The comparison is
  on server-derived fingerprints (a prefix of SHA-256 of the presented key, never the key), not on
  ``X-NB-Actor`` / ``X-NB-Session``, which are client-chosen labels;
* a caller whose identity cannot be established (open mode, no key) can neither propose-then-approve
  nor approve: independence cannot be shown, so it is refused;
* a proposal lapses (``expired``, terminal) ``NEURALBRIDGE_AI_FOUR_EYES_TTL_S`` seconds after it was
  made (default 24 h) and an expired, denied, failed or executed plan can never run;
* the approver's identity and the time are written once, in the claim that moves the plan from
  ``pending_approval`` to ``approved`` (a compare-and-set), and the store refuses any later change
  to them (``plans_decision_immutable`` trigger).

Where the policy comes from: ``NEURALBRIDGE_AI_FOUR_EYES=1`` turns it on for every tenant of the
deployment (``source: "environment"``); otherwise a tenant can turn it on for itself
(``PUT /ai/policy``, ``source: "tenant"``). A tenant cannot turn it OFF again with the key whose
holder might be the one it protects against; only the operator can (``PUT /ai/policy`` with
``owner``), and not while the environment forces it. The setting in force when a plan is PROPOSED is
stored on the plan and cannot be loosened afterwards.

What it does not do: it cannot tell two keys held by one person apart, and it does not make the
operator key (full access) subject to anything but its own key fingerprint.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from assurance.billing.accounts import Principal, hash_key
from neuralbridge.ai.store import AiStore

FOUR_EYES_ENV = "NEURALBRIDGE_AI_FOUR_EYES"
TTL_ENV = "NEURALBRIDGE_AI_FOUR_EYES_TTL_S"
DEFAULT_TTL_S = 24 * 3600


@dataclass(frozen=True)
class CallerRef:
    """Who authenticated, as server-derived fingerprints. ``key_ref == ""`` = no key was presented."""

    key_ref: str = ""
    operator: str = ""

    @classmethod
    def from_request(cls, api_key: str | None, principal: Principal) -> CallerRef:
        presented = (api_key or "").strip()
        return cls(
            key_ref=hash_key(presented)[:16] if presented else "",
            operator=principal.operator_id or "",
        )


@dataclass(frozen=True)
class FourEyesPolicy:
    four_eyes: bool
    source: str  # "environment" | "tenant" | "default"
    ttl_s: int = DEFAULT_TTL_S

    def as_dict(self) -> dict[str, object]:
        return {"four_eyes": self.four_eyes, "source": self.source,
                "approval_ttl_s": self.ttl_s if self.four_eyes else None}


def _ttl() -> int:
    try:
        return max(60, int(os.environ.get(TTL_ENV, DEFAULT_TTL_S)))
    except ValueError:
        return DEFAULT_TTL_S


def environment_forces() -> bool:
    return os.environ.get(FOUR_EYES_ENV, "") == "1"


def effective_policy(store: AiStore, owner: str) -> FourEyesPolicy:
    if environment_forces():
        return FourEyesPolicy(True, "environment", _ttl())
    if store.get_tenant_policy(owner):
        return FourEyesPolicy(True, "tenant", _ttl())
    return FourEyesPolicy(False, "default", _ttl())


def expiry_for(policy: FourEyesPolicy, now: datetime | None = None) -> str | None:
    if not policy.four_eyes:
        return None
    return ((now or datetime.now(UTC)) + timedelta(seconds=policy.ttl_s)).isoformat()


def is_expired(expires_at: str | None, now: datetime | None = None) -> bool:
    return bool(expires_at) and datetime.fromisoformat(expires_at) <= (now or datetime.now(UTC))  # type: ignore[arg-type]


def independence_problem(
    proposer_key: str, proposer_operator: str, approver: CallerRef,
) -> str | None:
    """Why ``approver`` may not approve a plan proposed by that principal; ``None`` if independent."""
    if not proposer_key or not approver.key_ref:
        return "the proposer or the approver was not identified by an API key, so independence cannot be shown"
    if approver.key_ref == proposer_key:
        return "the approver authenticated with the same API key as the proposer"
    if proposer_operator and approver.operator and approver.operator == proposer_operator:
        return "the approver is the same operator as the proposer"
    return None
