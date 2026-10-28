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

__all__ = [
    "EVIDENCE_READOUT_AFTER_LAPSE",
    "GATE_FLAGS",
    "METERED_SCOPES",
    "PLANS",
    "Plan",
    "Tier",
    "payg_available",
    "plan_for",
    "plan_for_price",
    "public_catalogue",
]

Tier = str  # "free" | "register" | "cell" | "supplier"

#: The one sentence every public surface uses about case volume. Kept identical
#: to CASES_NOT_METERED in app/lib/plans.ts (tests/test_assurance_plans_parity.py).
CASES_NOT_METERED = "Cases are not metered — no per-case cap or charge"


#: The entitlement contract, in one place.
#:
#: A Plan flag may be advertised only if a gate in ``api/deps.py`` consults it
#: on a route, and every ``/v1`` route that reads or writes tenant data carries
#: a gate (``tests/test_assurance_entitlements.py`` reads the live app and
#: fails otherwise). ``GATE_FLAGS`` maps each gating flag to the dependency in
#: ``api/deps.py`` that enforces it; each answers 401 with no key and 402 when
#: the caller is authenticated but the plan lacks the flag.
#:
#: Quotas (``*_per_day``) are spent through ``api/deps.py:Metered`` (or
#: ``spend`` for ``/ai`` reads) and fail with a 429 that carries the remedy and
#: ``Retry-After``; nothing is ever dropped silently.
GATE_FLAGS: dict[str, str] = {
    "register": "require_register",
    "machine_verification": "require_machine",
    "signed_attestation": "require_attestation",
    "supplier_publish": "require_supplier",
}

#: What a customer whose subscription has ended can still do: read, verify and
#: export the evidence in their own ledger. Evidence must not be held hostage to
#: a payment, and a lapsed customer is exactly the person who most needs to hand
#: their records to an auditor. **Nothing else stays open**: every write, and
#: every operational view (readiness report, fleet, change cases, attestation),
#: returns 402 as before. It applies to an account that has paid (it has a
#: Stripe customer); a caller who never paid gets 402 here too. Enforced by
#: ``api/deps.py:require_evidence_readout``.
EVIDENCE_READOUT_AFTER_LAPSE: tuple[tuple[str, str], ...] = (
    ("GET", "/v1/cases"),
    ("GET", "/v1/cases/{case_id}"),
    ("GET", "/v1/cases/{case_id}/export"),
    ("GET", "/v1/ledger/verify"),
)


#: The only work that is metered, and the Plan field holding its free daily
#: allowance. Each successful call is one unit; operations beyond the allowance
#: are billable only on a plan with ``metered_overage`` (pay-as-you-go), and
#: only up to the account's spend limit. **Everything else is unmetered by
#: design**: Article 14 cases, change-assurance cases and every other register
#: write (a meter on filing a regulatory report would discourage reporting),
#: machine verification, attestation, and the free re-verification routes.
#: ``/ai`` reads have their own daily guard and are never billed.
METERED_SCOPES: dict[str, str] = {
    "validate": "validations_per_day",
    "separation": "separations_per_day",
    "machinery_diff": "diffs_per_day",
    "advisory_check": "diffs_per_day",
}

_LIVE_KEY_PREFIXES = ("sk_live_", "rk_live_")


def payg_available() -> bool:
    """Whether this deployment offers pay-as-you-go. **Off unless fully configured.**

    All of: ``ASSURANCE_PRICE_PAYG`` (a metered Stripe price id) and
    ``ASSURANCE_PAYG_METER_EVENT`` (the Billing Meter's event name) are set, and
    the Stripe key is not a live key. Pay-as-you-go has been verified against a
    fake Stripe transport only, so it refuses to run against live mode unless
    ``ASSURANCE_PAYG_ALLOW_LIVE=1`` says someone has tested it in test mode.
    """
    if not (os.environ.get("ASSURANCE_PRICE_PAYG") and
            os.environ.get("ASSURANCE_PAYG_METER_EVENT")):
        return False
    live = os.environ.get("STRIPE_SECRET_KEY", "").startswith(_LIVE_KEY_PREFIXES)
    return not live or os.environ.get("ASSURANCE_PAYG_ALLOW_LIVE") == "1"


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
    #: May export a verifiable evidence bundle (GET /v1/cases/{id}/export).
    #: Enforced there; see routes.get_case_export.
    export: bool = False
    # Register cases are deliberately NOT metered or capped: a cap on
    # regulatory filings would discourage investigating a serious finding.
    # There is no ``cases_per_day`` or ``product_families`` field for that
    # reason, and none should be added unless something enforces it
    # (tests/test_assurance_billing_hardening.py fails an advertised limit
    # that nothing consults).
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
    #: May propose and approve a WRITE through the /ai control plane (and the
    #: same-policy raw adapters/MCP paths — see reports/NEURALBRIDGE-AI-PHASE2.md),
    #: bind additional connections, and fetch the account's own audit log. The
    #: control plane's discovery and READ path stays free — see
    #: ai_reads_per_day — the same "verification stays free" rule the rest
    #: of this table follows: reading is how a prospect evaluates the
    #: product, writing is the entitlement.
    ai_control_plane: bool = False
    #: READ calls (list_tables / describe_table / query / health_check)
    #: per UTC day through /ai on the free tier. None = unlimited (paid).
    ai_reads_per_day: int | None = None
    #: Operations beyond the free daily allowance are accepted and billed
    #: (pay-as-you-go), up to the account's spend limit. Consulted by
    #: ``billing/metering.py:overage_allowed``, which ``AccountStore.record_usage``
    #: calls in the same transaction as the quota check. Without it the daily
    #: allowance is a hard cap.
    metered_overage: bool = False
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
                "register_access": self.register,
                "verifiable_export": self.export,
                "signed_attestation": self.signed_attestation,
                "machine_verification": self.machine_verification,
                "separations_per_day": self.separations_per_day,
                "diffs_per_day": self.diffs_per_day,
                "supplier_publish": self.supplier_publish,
                "ai_control_plane": self.ai_control_plane,
                "ai_reads_per_day": self.ai_reads_per_day,
                "metered_overage": self.metered_overage,
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
        ai_reads_per_day=30,
        included=(
            "/ai control plane: discover the demo connection and run READ "
            "operations (list tables, describe a table, run a SELECT), up "
            "to 30 a day — writes need Register or Cell",
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
        export=True,
        ai_control_plane=True,
        included=(
            "Everything in Validator, without the daily cap",
            CASES_NOT_METERED,
            "Awareness records with the reasoning that defends them",
            "Both final-report clocks computed correctly, and the platform's counter "
            "defect surfaced rather than inherited",
            "Hash-chained evidence ledger; export refuses if the chain does not verify",
            "If the subscription ends you keep read, verify and export of your own "
            "evidence; new records and the operational views stop",
            "/ai control plane: unlimited reads, propose-and-approve WRITEs, "
            "bind additional connections, the adapter-call log for your account (held in memory, cleared on restart) and durable plan decisions",
        ),
    ),
    "cell": Plan(
        tier="cell",
        name="Cell",
        blurb=(
            "For a manufacturer or integrator shipping machines: everything in "
            "Register, plus machine safety assurance: check a recorded run against "
            "the safety envelope you declared, track what safety software is on each "
            "machine and who changed it, and know which safety functions have a "
            "recorded verification dated after the last recorded change."
        ),
        price_env="ASSURANCE_PRICE_CELL",
        price_label="€1,290 / month",
        validations_per_day=None,
        register=True,
        export=True,
        signed_attestation=True,
        machine_verification=True,
        ai_control_plane=True,
        included=(
            "Everything in Register",
            "/ai control plane: unlimited reads, propose-and-approve WRITEs, "
            "bind additional connections, the adapter-call log for your account (held in memory, cleared on restart) and durable plan decisions",
            "Machine safety verification: POST /v1/machine/verify checks a recorded "
            "run against a declared safety envelope and seals the result",
            "Separation, speed, workspace, stop characterisation, power-and-force and "
            "mode-consistency checks, each with its worst margin",
            "Evidence bundles anyone can re-verify without an account",
            "Machinery Regulation Annex III 1.1.9: the safety software manifest, the "
            "intervention record, and the machine passport",
            "Coverage: which declared safety functions have a recorded verification "
            "dated after the last recorded change, and which change came after the rest",
            "Fleet: every enrolled machine ranked worst-first, and a supplier "
            "advisory fanned out to serial numbers and the safety functions it "
            "puts in question",
            "Declarations of Conformity bound to a configuration hash, so a "
            "declaration can be shown to have stopped describing the machine",
            CASES_NOT_METERED,
            "Change-assurance cases over /v1/change/*: open, claim, advance and "
            "submit re-verification evidence. Closure is a named human decision. A "
            "validated verification needs a recorder attestation accepted under a "
            "trust list the operator configures; no such list is configured in a "
            "default deployment, so a required re-verification is closed in practice "
            "by a named person's waiver",
            "Counter-signed head attestation: POST /v1/ledger/attest signs the "
            "head of your ledger with a key you do not hold, so a rewind "
            "contradicts a signed statement. It answers 503 until the operator "
            "configures a service signing key, and none is configured on any "
            "deployment today. Attestation sends three numbers and never a record; "
            "machine verification (POST /v1/machine/verify) does receive the full "
            "trace you submit",
        ),
    ),
    # Listed by public_catalogue() only when payg_available(): a deployment that
    # has not been given a metered price and a meter does not advertise it.
    "payg": Plan(
        tier="payg",
        name="Pay as you go",
        blurb=(
            "Run more verification operations than the free daily allowance and pay "
            "only for the extra ones, up to a monthly spend limit you set. Nothing is "
            "billed until you set a limit."
        ),
        price_env="ASSURANCE_PRICE_PAYG",
        price_label="Pay per use",
        validations_per_day=20,
        separations_per_day=20,
        diffs_per_day=10,
        ai_reads_per_day=30,
        metered_overage=True,
        included=(
            "The same free daily allowance as Validator on each calculator",
            "Operations beyond the allowance are metered one unit per successful "
            "call: validate, separation, manifest diff, advisory check. A call that "
            "fails is never counted or billed",
            "A hard spend limit, in units per UTC calendar month, that you set with "
            "POST /v1/usage/limits. The default is zero, so nothing is billed until "
            "you choose; at the limit the API answers 429 and records nothing",
            "GET /v1/usage lists every metered event with its idempotency key. Send "
            "an Idempotency-Key header and a retry is never counted or billed twice",
            "Not included: the Article 14 register, machine verification and the "
            "other paid gates - those are Register and Cell",
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
    """The plans on sale. Pay-as-you-go appears only when it is fully configured."""
    tiers = ["free", "register", "cell"]
    if payg_available():
        tiers.append("payg")
    return [PLANS[t].to_public_dict() for t in tiers]
