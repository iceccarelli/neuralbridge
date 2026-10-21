"""The pricing page and the API say the same thing, and neither says a stale thing.

``app/lib/plans.ts`` carries a copy of ``GET /v1/plans`` for when the API is
unreachable. The two drifted once (caps that nothing enforced, "priority
response" with no mechanism behind it). This parses ``FALLBACK_PLANS`` out of
the TypeScript and compares it with what the backend actually serves, and it
fails if a retired claim reappears in the plan data or the public copy.
"""

from __future__ import annotations

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
        "README.md", "docs/pricing.md", "docs/index.md", "public/llms.txt",
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
