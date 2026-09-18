"""What each tier may do.

Entitlements are declared here and enforced in one place. The rule the
palletizer repository got right and is worth keeping: **if it is not gated in
code, it is not on the pricing page.** A feature list that the software does
not enforce is marketing, and it is the kind of marketing that produces refund
requests.

Prices live in Stripe, not here. This module carries only the price *lookup*
and the entitlements, so changing a number never means shipping code.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Tier", "Plan", "PLANS", "plan_for", "plan_for_price", "public_catalogue"]

Tier = str  # "free" | "register" | "cell"


@dataclass(frozen=True)
class Plan:
    """One tier, and exactly what it permits."""

    tier: Tier
    name: str
    blurb: str
    #: Environment variable holding the Stripe price id. Empty for free.
    price_env: str = ""
    price_label: str = ""
    #: Calls per UTC day to the free validator. None = unlimited.
    validations_per_day: int | None = None
    #: May create and write cases in the register.
    register: bool = False
    #: Product families that may appear in availability records.
    product_families: int | None = None
    #: Cases per UTC day.
    cases_per_day: int | None = None
    #: May export a verifiable evidence bundle.
    export: bool = False
    #: May have the service counter-sign the head of their own ledger. The
    #: verification side is deliberately outside this gate: see attest_routes.
    signed_attestation: bool = False
    #: May verify a machine trace against a declared safety envelope and seal
    #: the resulting evidence bundle. The separation calculator and the bundle
    #: re-checker are deliberately outside this gate: see machine_routes.
    machine_verification: bool = False
    #: Safety envelope separation calculations per UTC day on the free tier.
    separations_per_day: int | None = None
    #: Manifest comparisons per UTC day on the free tier.
    diffs_per_day: int | None = None
    #: May publish signed advisories to a hosted feed under POST
    #: /v1/supplier/advisory. See ADR-0001 (deploy/assurance/ADR-0001-supplier-api.md):
    #: this is the second payer HANDOFF.md's P1 names — a component supplier,
    #: not a manufacturer — and it has no self-serve Stripe price yet.
    supplier_publish: bool = False
    included: tuple[str, ...] = field(default_factory=tuple)

    @property
    def price_id(self) -> str:
        return os.environ.get(self.price_env, "") if self.price_env else ""

    @property
    def purchasable(self) -> bool:
        return bool(self.price_id)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "name": self.name,
            "blurb": self.blurb,
            "price": self.price_label or "free",
            "purchasable": self.purchasable,
            "includes": list(self.included),
            "limits": {
                "validations_per_day": self.validations_per_day,
                "product_families": self.product_families,
                "cases_per_day": self.cases_per_day,
                "register_access": self.register,
                "verifiable_export": self.export,
                "signed_attestation": self.signed_attestation,
                "machine_verification": self.machine_verification,
                "separations_per_day": self.separations_per_day,
                "diffs_per_day": self.diffs_per_day,
                "supplier_publish": self.supplier_publish,
            },
        }


PLANS: dict[Tier, Plan] = {
    "free": Plan(
        tier="free",
        name="Validator",
        blurb=(
            "Check a draft Article 14 filing against the ENISA platform's 39-field "
            "specification before you open the platform. No account, nothing recorded."
        ),
        validations_per_day=20,
        separations_per_day=20,
        diffs_per_day=10,
        included=(
            "POST /v1/spec/validate — what is missing, what exceeds a character limit, "
            "which listed territories are not EU Member States",
            "GET /v1/spec/fields — the full field specification per track and stage",
            "POST /v1/machine/separation — the ISO/TS 15066 protective separation "
            "distance for your cell, term by term, from your own stop figures",
            "POST /v1/machine/bundle/check — re-verify anybody's evidence bundle. "
            "Always free: a bundle only a paying customer can check is worth nothing",
            "POST /v1/machinery/diff — whether a machine still matches the "
            "configuration it was CE-marked with",
            "POST /v1/fleet/advisory/check — whether one supplier advisory affects "
            "one machine",
            "POST /v1/fleet/declaration/check — whether a Declaration of Conformity "
            "still describes the machine you were sold. Always free: the person who "
            "most needs this is the buyer, not the seller",
            "The offline enrolment kit — `assurance kit run` collects your "
            "machines inside your own plant, into your own ledger, with a guard "
            "over the socket layer proving nothing left. No account, no upload, "
            "and free: if it needed a licence it would need a procurement "
            "review, which is the thing it exists to avoid",
            "POST /v1/ledger/attest/verify and GET /v1/ledger/attest/key — check "
            "anybody's signed head attestations. Always free: the audience for an "
            "attestation is a regulator or an insurer, not an account holder",
            "20 validations and 20 separation calculations per day, per address",
        ),
    ),
    "register": Plan(
        tier="register",
        name="Register",
        blurb=(
            "The Article 14 register for one manufacturer: awareness records, both "
            "deadline clocks, triage with the grounds cited, and a hash-chained evidence "
            "ledger you can export."
        ),
        price_env="ASSURANCE_PRICE_REGISTER",
        price_label="€390 / month",
        validations_per_day=None,
        register=True,
        product_families=25,
        cases_per_day=50,
        export=True,
        included=(
            "Everything in Validator, without the daily cap",
            "Unlimited cases; awareness records with the reasoning that defends them",
            "Both final-report clocks computed correctly, and the platform's counter "
            "defect surfaced rather than inherited",
            "Hash-chained evidence ledger; export refuses if the chain does not verify",
            "Up to 25 product families",
        ),
    ),
    "cell": Plan(
        tier="cell",
        name="Cell",
        blurb=(
            "For a manufacturer or integrator shipping machines: everything in "
            "Register, plus machine safety assurance: check a recorded run against "
            "the safety envelope you declared, track what safety software is on each "
            "machine and who changed it, and know which safety functions still have "
            "evidence that describes the machine as it is today."
        ),
        price_env="ASSURANCE_PRICE_CELL",
        price_label="€1,290 / month",
        validations_per_day=None,
        register=True,
        product_families=None,
        cases_per_day=None,
        export=True,
        signed_attestation=True,
        machine_verification=True,
        included=(
            "Everything in Register",
            "Machine safety verification: POST /v1/machine/verify checks a recorded "
            "run against a declared safety envelope and seals the result",
            "Separation, speed, workspace, stop characterisation, power-and-force and "
            "mode-consistency checks, each with its worst margin",
            "Evidence bundles anyone can re-verify without an account",
            "Machinery Regulation Annex III 1.1.9: the safety software manifest, the "
            "intervention record, and the machine passport",
            "Coverage: which declared safety functions still have valid evidence, and "
            "which intervention invalidated the rest",
            "Fleet: every enrolled machine ranked worst-first, and a supplier "
            "advisory fanned out to serial numbers and the safety functions it "
            "puts in question",
            "Declarations of Conformity bound to a configuration hash, so a "
            "declaration can be shown to have stopped describing the machine",
            "Unlimited product families and cases",
            "Counter-signed head attestation: POST /v1/ledger/attest signs the "
            "head of your ledger with a key you do not hold, so a rewind "
            "contradicts a signed statement. Your ledger is never uploaded — "
            "we sign three numbers and never see a record",
            "Priority response",
        ),
    ),
    # Not in public_catalogue(): this is a second, different buyer — a
    # component supplier, not a manufacturer — and there is no Stripe price
    # for it yet. Granting it is a manual, sales-assigned account tier until
    # a real self-serve price exists; see ADR-0001. Keeping it out of the
    # pricing page GET /v1/plans already serves means the existing frontend
    # (which renders exactly three cards) never has to reason about a plan
    # it cannot sell.
    "supplier": Plan(
        tier="supplier",
        name="Supplier",
        blurb=(
            "Publish signed component advisories to a feed every enrolled "
            "integrator can subscribe to. Sales-assigned; contact us."
        ),
        price_label="Contact sales",
        supplier_publish=True,
        included=(
            "POST /v1/supplier/advisory — publish a signed advisory to your "
            "hosted feed",
            "GET /v1/supplier/feed/{supplier_id} — always free to read, for "
            "any integrator",
        ),
    ),
}


def plan_for(tier: Tier) -> Plan:
    """The plan for a tier, falling back to free rather than raising.

    An unknown tier in a stored account must degrade to the least privilege, not
    to an error and not to the most.
    """
    return PLANS.get(tier, PLANS["free"])


def plan_for_price(price_id: str) -> Plan | None:
    """Which plan a Stripe price belongs to."""
    for plan in PLANS.values():
        if plan.price_id and plan.price_id == price_id:
            return plan
    return None


def public_catalogue() -> list[dict[str, Any]]:
    return [PLANS[t].to_public_dict() for t in ("free", "register", "cell")]
