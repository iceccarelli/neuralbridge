"""Copy that states a number or a promise is pinned to the code that makes it true.

Three things drifted before this existed: the site said evidence re-checking is
"not metered at any tier" while ``POST /v1/evidence/verify`` spends a unit of a
daily allowance; "Free, forever" sat on routes and in ``agent.json`` with nothing
behind it; and prices were typed into structured data (schema.org Offers) with no
test tying them to ``billing/plans.py`` or saying they are unvalidated.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from assurance.billing.plans import PLANS

ROOT = Path(__file__).resolve().parents[1]

PUBLIC_COPY = [
    "README.md",
    "docs/pricing.md",
    "docs/index.md",
    "public/llms.txt",
    "public/openapi.json",
    "public/.well-known/agent.json",
    "app/page.tsx",
    "app/layout.tsx",
    "app/solutions/[slug]/page.tsx",
    "src/assurance/api/attest_routes.py",
    "src/assurance/api/supplier_routes.py",
]

#: Promises with no code behind them. Each was found in the copy once.
_UNBACKED = re.compile(
    r"not metered at any tier"
    r"|free at every (?:tier|one)"
    r"|free,? forever"
    r"|\"period\":\s*\"forever\""
    r"|always will be"
    r"|always-free",
    re.I,
)


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class TestNoUnbackedPromises:
    @pytest.mark.parametrize("relative", PUBLIC_COPY)
    def test_the_copy_makes_none(self, relative):
        match = _UNBACKED.search(_text(relative))
        assert match is None, f"{relative} says {match.group(0)!r}"


class TestEvidenceAllowanceIsStatedAsEnforced:
    """What the copy says about evidence re-checking is what ``_meter`` does."""

    def test_the_route_is_metered_against_the_validator_allowance(self):
        source = _text("src/assurance/api/evidence_routes.py")
        assert 'spend(principal, "evidence_verify"' in source
        assert "principal.plan.validations_per_day" in source

    def test_the_allowance_is_the_free_plans_and_the_paid_plans_have_none(self):
        assert PLANS["free"].validations_per_day is not None
        assert PLANS["register"].validations_per_day is None
        assert PLANS["cell"].validations_per_day is None

    @pytest.mark.parametrize("relative", [
        "README.md", "docs/pricing.md", "docs/index.md", "public/llms.txt",
        "app/page.tsx", "app/layout.tsx", "app/solutions/[slug]/page.tsx",
    ])
    def test_the_copy_states_the_number_the_code_enforces(self, relative):
        allowance = PLANS["free"].validations_per_day
        text = _text(relative)
        assert f"{allowance} a day" in text, f"{relative} must say {allowance} a day"
        wrong = {int(n) for n in re.findall(r"(\d+) a day per address", text)} - {allowance}
        assert not wrong, f"{relative} states {wrong}, the code enforces {allowance}"


def _digits(price_label: str) -> str:
    return re.sub(r"[^\d]", "", price_label.split("/")[0])


class TestPricesInStructuredDataMatchPlans:
    """schema.org Offers live in ``app/lib/structured-offers.json`` and are emitted by the home page only.

    The pin is deliberately as strict as the old layout regex was: the number, the currency
    AND (new) the billing period, taken from ``billing/plans.py``. A bare ``price`` with no
    period read as a one-off charge for a subscription.
    """

    OFFERS = "app/lib/structured-offers.json"

    @pytest.mark.parametrize("name", ["Register", "Cell"])
    def test_offers_pin_the_list_price_the_currency_and_the_period(self, name):
        data = json.loads(_text(self.OFFERS))
        label = PLANS[name.lower()].price_label  # e.g. "\u20ac1,290 / month"
        expected = _digits(label)
        period = label.split("/")[1].strip()
        assert expected and period == "month" and label.startswith("\u20ac")
        offers = [o for o in data["softwareApplication"]["offers"] if o["name"] == name]
        products = [p["offers"] for p in data["products"] if p["name"] == name]
        assert len(offers) == 1 and len(products) == 1, name
        for offer in (offers[0], products[0]):
            spec = offer["priceSpecification"]
            assert (spec["price"], spec["priceCurrency"], spec["unitText"]) == (expected, "EUR", period)

    def test_the_validator_offer_is_zero(self):
        data = json.loads(_text(self.OFFERS))
        (free,) = [o for o in data["softwareApplication"]["offers"] if o["name"] == "Validator"]
        assert free["priceSpecification"]["price"] == "0"

    def test_prices_are_labelled_unvalidated_on_every_offer_and_product(self):
        data = json.loads(_text(self.OFFERS))
        note = data["listPriceNote"]
        assert "unvalidated" in note.lower()
        paid = [o for o in data["softwareApplication"]["offers"] if o["name"] != "Validator"]
        paid += [p["offers"] for p in data["products"]]
        assert len(paid) == 4 and all(o["description"] == note for o in paid)

    def test_agent_json_prices_match_and_are_labelled(self):
        data = json.loads(_text("public/.well-known/agent.json"))
        tiers = {t["name"]: t for t in data["pricing"]["tiers"]}
        for name in ("Register", "Cell"):
            assert str(tiers[name]["price"]) == _digits(PLANS[name.lower()].price_label)
            assert tiers[name]["price_status"] == "unvalidated_list_price"
        assert tiers["Validator"]["price"] == 0
        assert tiers["Validator"]["period"] != "forever"
        assert "not validated" in data["pricing"]["price_note"]
