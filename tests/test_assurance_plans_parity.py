"""The pricing page and the API say the same thing, and neither says a stale thing.

``app/lib/plans.ts`` carries a copy of ``GET /v1/plans`` for when the API is
unreachable. The two drifted once (caps that nothing enforced, "priority
response" with no mechanism behind it). This parses ``FALLBACK_PLANS`` out of
the TypeScript and compares it with what the backend actually serves, and it
fails if a retired claim reappears in the plan data or the public copy.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

from assurance.billing.plans import CASES_NOT_METERED, PLANS, public_catalogue

ROOT = Path(__file__).resolve().parents[1]
PLANS_TS = ROOT / "app" / "lib" / "plans.ts"

_STR = r"""'(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*\""""


def _unquote(token: str) -> str:
    body = token[1:-1]
    return re.sub(r"\\(.)", r"\1", body)


def _string_consts(text: str) -> dict[str, str]:
    found = {}
    for m in re.finditer(rf"\bconst\s+(\w+)\s*=\s*({_STR})\s*;", text, re.S):
        found[m.group(1)] = _unquote(m.group(2))
    return found


def _balanced(text: str, start: int, open_: str, close: str) -> str:
    """The text between the bracket at ``start`` and its match, string-aware."""
    depth, i, quote = 0, start, ""
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\":
                i += 1
            elif c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c == open_:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return text[start + 1:i]
        i += 1
    raise AssertionError("unbalanced brackets in plans.ts")


def _fallback_plans() -> list[dict]:
    text = PLANS_TS.read_text(encoding="utf-8")
    consts = _string_consts(text)
    head = re.search(r"FALLBACK_PLANS\s*:\s*Plan\[\]\s*=\s*\[", text)
    assert head, "FALLBACK_PLANS not found in app/lib/plans.ts"
    array = _balanced(text, head.end() - 1, "[", "]")

    plans = []
    pos = 0
    while True:
        brace = array.find("{", pos)
        if brace == -1:
            break
        body = _balanced(array, brace, "{", "}")
        pos = brace + len(body) + 2

        def one(key: str, body: str = body) -> str:
            m = re.search(rf"\b{key}\s*:\s*({_STR})", body, re.S)
            assert m, f"{key} missing"
            return _unquote(m.group(1))

        inc_at = body.index("includes:")
        includes_body = _balanced(body, body.index("[", inc_at), "[", "]")
        includes = []
        for tok in re.finditer(rf"({_STR})|\b([A-Z][A-Z_]+)\b", includes_body, re.S):
            includes.append(_unquote(tok.group(1)) if tok.group(1) else consts[tok.group(2)])

        lim_at = body.index("limits:")
        limits_body = _balanced(body, body.index("{", lim_at), "{", "}")
        limits = {}
        for key, val in re.findall(r"(\w+)\s*:\s*(null|true|false|\d+)", limits_body):
            limits[key] = {"null": None, "true": True, "false": False}.get(
                val, int(val) if val.isdigit() else val)

        plans.append({
            "tier": one("tier"), "name": one("name"), "blurb": one("blurb"),
            "price": one("price"),
            "purchasable": re.search(r"purchasable\s*:\s*(true|false)", body).group(1) == "true",
            "includes": includes, "limits": limits,
        })
    return plans


@pytest.fixture()
def backend(monkeypatch):
    monkeypatch.delenv("ASSURANCE_PRICE_REGISTER", raising=False)
    monkeypatch.delenv("ASSURANCE_PRICE_CELL", raising=False)
    return {p["tier"]: p for p in public_catalogue()}


class TestParity:
    def test_the_parser_reads_three_plans(self):
        assert [p["tier"] for p in _fallback_plans()] == ["free", "register", "cell"]

    @pytest.mark.parametrize("tier", ["free", "register", "cell"])
    def test_every_field_the_page_shows_matches_the_api(self, backend, tier):
        ts = {p["tier"]: p for p in _fallback_plans()}[tier]
        api = backend[tier]
        for field in ("name", "blurb", "price", "purchasable"):
            assert ts[field] == api[field], f"{tier}.{field} differs between plans.ts and plans.py"
        assert ts["includes"] == api["includes"], (
            f"{tier}.includes differs: change plans.py and plans.ts in the same commit"
        )
        assert ts["limits"] == api["limits"], f"{tier}.limits differs"

    def test_the_case_volume_sentence_is_identical(self):
        text = PLANS_TS.read_text(encoding="utf-8")
        assert _string_consts(text)["CASES_NOT_METERED"] == CASES_NOT_METERED


_RETIRED = re.compile(
    r"(?<!reads )unlimited(?! reads)|priority (response|support)|product famil|cases_per_day|"
    r"\b50 cases\b|25 product",
    re.I,
)


def _enforced_section(text: str) -> str:
    # The registry has to quote retired claims (and name the removed fields) to
    # say they are retired; only its table of live claims is held to the rule.
    start = text.index("## Enforced claims")
    return text[start:text.index("## Not enforced", start)]


class TestNoRetiredClaims:
    def test_the_backend_plan_data_makes_none(self, backend):
        for tier, plan in backend.items():
            blob = " | ".join([plan["blurb"], *plan["includes"], *plan["limits"]])
            assert not _RETIRED.search(blob), (tier, _RETIRED.search(blob).group(0))
        for plan in PLANS.values():
            blob = " | ".join([plan.blurb, *plan.included])
            assert not _RETIRED.search(blob), plan.tier

    def test_the_typescript_plan_data_makes_none(self):
        for plan in _fallback_plans():
            blob = " | ".join([plan["blurb"], *plan["includes"], *plan["limits"]])
            assert not _RETIRED.search(blob), (plan["tier"], _RETIRED.search(blob).group(0))

    @pytest.mark.parametrize("relative", [
        "README.md", "docs/pricing.md", "public/llms.txt",
        "docs/claims-registry.md",
    ])
    def test_public_copy_makes_none(self, relative):
        path = ROOT / relative
        if not path.exists():
            pytest.skip(f"{relative} not present")
        text = path.read_text(encoding="utf-8")
        if relative == "docs/claims-registry.md":
            text = _enforced_section(text)
        match = _RETIRED.search(text)
        assert match is None, f"{relative} says {match.group(0)!r}"


# ---------------------------------------------------------------------------
# pay as you go: on sale only when the deployment really has it
# ---------------------------------------------------------------------------
PRICING_TSX = ROOT / "app" / "components" / "PricingPlans.tsx"
SIZING_TSX = ROOT / "app" / "components" / "SizingCalculator.tsx"


class TestPayAsYouGoIsOffUnlessConfigured:
    @pytest.fixture(autouse=True)
    def _clean(self, monkeypatch):
        for name in ("ASSURANCE_PRICE_PAYG", "ASSURANCE_PAYG_METER_EVENT",
                     "STRIPE_SECRET_KEY", "ASSURANCE_PAYG_ALLOW_LIVE",
                     "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL"):
            monkeypatch.delenv(name, raising=False)

    def test_the_default_catalogue_is_the_three_plans_the_page_falls_back_to(self):
        assert [p["tier"] for p in public_catalogue()] == ["free", "register", "cell"]
        assert [p["tier"] for p in _fallback_plans()] == ["free", "register", "cell"]

    @pytest.mark.parametrize("env", [
        {"ASSURANCE_PRICE_PAYG": "price_x"},                   # price, no meter
        {"ASSURANCE_PAYG_METER_EVENT": "ops"},                 # meter, no price
        {"ASSURANCE_PRICE_PAYG": "price_x", "ASSURANCE_PAYG_METER_EVENT": "ops",
         "STRIPE_SECRET_KEY": "sk_live_abc"},                  # live mode, untested
        {"ASSURANCE_PRICE_PAYG": "price_x", "ASSURANCE_PAYG_METER_EVENT": "ops",
         "STRIPE_SECRET_KEY": "rk_live_abc"},
    ])
    def test_half_configured_or_live_is_not_advertised(self, monkeypatch, env):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        assert "payg" not in [p["tier"] for p in public_catalogue()]

    def test_fully_configured_in_test_mode_it_is_listed_and_purchasable(self, monkeypatch):
        monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_x")
        monkeypatch.setenv("ASSURANCE_PAYG_METER_EVENT", "ops")
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_test_abc")
        listed = {p["tier"]: p for p in public_catalogue()}
        assert listed["payg"]["purchasable"] is True
        assert listed["payg"]["limits"]["metered_overage"] is True
        assert set(listed["payg"]["limits"]) == set(listed["free"]["limits"])
        assert [t for t in listed if t != "payg"] == ["free", "register", "cell"]

    def test_the_live_opt_in_exists_and_is_explicit(self, monkeypatch):
        monkeypatch.setenv("ASSURANCE_PRICE_PAYG", "price_x")
        monkeypatch.setenv("ASSURANCE_PAYG_METER_EVENT", "ops")
        monkeypatch.setenv("STRIPE_SECRET_KEY", "sk_live_abc")
        monkeypatch.setenv("ASSURANCE_PAYG_ALLOW_LIVE", "1")
        assert "payg" in [p["tier"] for p in public_catalogue()]

    def test_the_frontend_renders_it_only_from_the_live_catalogue(self):
        text = PRICING_TSX.read_text(encoding="utf-8")
        assert "p.tier === 'payg'" in text and "live ?" in text
        assert "byTier('payg')" not in text
        assert "payg" not in [p["tier"] for p in _fallback_plans()]

    def test_no_price_or_plan_name_is_typed_into_the_pricing_component(self):
        text = PRICING_TSX.read_text(encoding="utf-8")
        body = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
        assert not re.search(r"&euro;|€\s*\d|\b390\b|1,290", body), "a price is hard-coded"
        for name in ("Validator", "Register", "Cell"):
            assert f">{name}<" not in body, f"plan name {name!r} is hard-coded"


class TestSizingCalculatorIsDerivedFromTheGates:
    _NEED = re.compile(r"\{\s*key:\s*'(\w+)',\s*gate:\s*'(\w+)'")

    def _needs(self):
        found = dict(self._NEED.findall(SIZING_TSX.read_text(encoding="utf-8")))
        assert found, "SizingCalculator no longer names the gate of each need"
        return found

    def test_each_need_names_the_flag_that_really_gates_its_routes(self):
        from .test_assurance_entitlements import _gates, _v1

        app = importlib.import_module("assurance.api.service").create_app()
        routes = _v1(app)
        carrier = {
            "machine": ("POST", "/v1/machine/verify"),
            "annex3": ("POST", "/v1/machinery/manifest"),
            "fleet": ("GET", "/v1/fleet/machines"),
            "change": ("GET", "/v1/change/cases"),
            "attest": ("POST", "/v1/ledger/attest"),
        }
        assert set(self._needs()) == set(carrier), "a need was added or removed: map its route"
        for need, gate in self._needs().items():
            assert _gates(routes[carrier[need]]) == {gate}, (need, gate)

    def test_the_gates_are_granted_by_exactly_the_plans_the_calculator_will_name(self):
        by_tier = {p["tier"]: p["limits"] for p in _fallback_plans()}
        for gate in set(self._needs().values()):
            granted = [t for t, limits in by_tier.items() if limits[gate]]
            assert granted == ["cell"], (gate, granted)
        assert [t for t, limits in by_tier.items() if limits["register_access"]] == [
            "register", "cell"]

    def test_no_cap_or_case_sentence_is_typed_into_the_calculator(self):
        text = SIZING_TSX.read_text(encoding="utf-8")
        assert not re.search(r"\b20/day\b|\b50\b|per-case cap", text)
        assert "CASES_NOT_METERED" in text and "FALLBACK_PLANS" in text


# ---------------------------------------------------------------------------
# the change-assurance claim must not outrun what the code can do
# ---------------------------------------------------------------------------
class TestTheChangeAssuranceClaimIsHonest:
    """No verification this package produces reaches ``validated`` (declared trace
    provenance is capped at ``community``), so a case with a required re-verification
    closes only through a named person's waiver. Copy that says a customer can
    "re-verify and close" a case promises a path that does not exist."""

    _OVERCLAIM = re.compile(
        r"re-verify,? (and|&)? ?close|re-verify, close|claim, re-verify", re.I)

    def _change_line(self, includes: list[str]) -> str:
        (line,) = [i for i in includes if i.startswith("Change-assurance cases")]
        return line

    def test_the_cell_plan_does_not_promise_closing_by_re_verification(self, backend):
        line = self._change_line(backend["cell"]["includes"])
        assert not self._OVERCLAIM.search(line), line
        assert "waiver" in line and "validated" in line

    def test_the_page_copy_says_the_same_thing(self):
        ts = {p["tier"]: p for p in _fallback_plans()}["cell"]
        line = self._change_line(ts["includes"])
        assert not self._OVERCLAIM.search(line), line
        assert "waiver" in line and "validated" in line

    @pytest.mark.parametrize("relative", [
        "app/lib/routes.ts", "app/components/SizingCalculator.tsx", "app/page.tsx",
        "docs/pricing.md", "docs/claims-registry.md", "README.md", "public/llms.txt",
    ])
    def test_no_public_copy_still_says_a_case_is_re_verified_and_closed(self, relative):
        path = ROOT / relative
        if not path.exists():
            pytest.skip(f"{relative} not present")
        match = self._OVERCLAIM.search(path.read_text(encoding="utf-8"))
        assert match is None, f"{relative} says {match.group(0)!r}"

    def test_the_registry_row_states_the_waiver_path(self):
        text = (ROOT / "docs" / "claims-registry.md").read_text(encoding="utf-8")
        row = next(r for r in _enforced_section(text).splitlines()
                   if r.startswith("| Change-assurance cases"))
        assert "waive" in row and "validated" in row
