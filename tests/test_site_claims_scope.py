"""Public claims are no stronger than the code or the claims registry behind them.

An independent audit found the site unusually honest, and found the defects where the existing
guards did not reach: copy about the offline kit that said the guard *proves* nothing left (the
registry says it refuses and records what it can see, and the operating system is the boundary), a
"never version-range arithmetic" claim that is true of ``fleet advisory`` and false of the CSAF
import, engine guides rendered on the public site that carried pilot, price and founder framing,
a concrete deployment host in a curl example while the site says no API is deployed, and internal
deployment notes in ``llms.txt`` and the home page. Each class of defect is held here by a test that
reads the real source file and was seen to fail on the unfixed text.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _flat(relative: str) -> str:
    """The file with every run of whitespace (and a markdown/JSX line break) collapsed, so a phrase wrapped across lines still matches."""
    return re.sub(r"\s+", " ", _text(relative).replace("’", "'"))


def _site_sources() -> list[str]:
    """Every file a visitor can read as page copy, structured data, a static agent file or a rendered guide."""
    found: list[Path] = []
    for pattern in ("app/**/*.ts", "app/**/*.tsx"):
        found += list(ROOT.glob(pattern))
    found += [ROOT / "public" / "llms.txt", ROOT / "public" / ".well-known" / "agent.json", ROOT / "README.md"]
    found += list((ROOT / "scripts" / "site_static").glob("*.tmpl"))
    found += list((ROOT / "docs").glob("*.md")) + list((ROOT / "docs" / "assurance").glob("*.md"))
    found += [ROOT / "deploy" / "assurance" / name for name in _engine_sources()]
    return sorted({p.relative_to(ROOT).as_posix() for p in found if p.is_file()})


def _engine_sources() -> list[str]:
    """The ``deploy/assurance/*.md`` guards rendered under /docs/assurance, read from the page registry."""
    docs = _text("app/lib/docs.ts")
    block = re.search(r"const ENGINE_PAGES[^=]*=\s*\[(.*?)\n\];", docs, re.S)
    assert block, "ENGINE_PAGES not found in app/lib/docs.ts"
    sources = re.findall(r"source: 'deploy/assurance/([^']+)'", block.group(1))
    assert len(sources) >= 15, sources
    return sources


# ---------------------------------------------------------------------------
# the kit: a guard that refuses and records what it can see; the OS is the boundary
# ---------------------------------------------------------------------------
#: Claims stronger than docs/claims-registry.md (the kit row): the in-process guard records intent.
_OVERSTATED_KIT = [
    re.compile(r"(?:proving|proves) (?:that )?nothing left", re.I),
    re.compile(r"proves it stayed there", re.I),
    re.compile(r"nothing left the building", re.I),
    re.compile(r"nothing leaves the room", re.I),
    re.compile(r"enforced by a guard in the process", re.I),
    # "opens no sockets" said of the kit or of the offline path, with nothing about what the guard can see
    re.compile(r"\b(?:kit|offline)\b[^.\n]{0,160}\b(?:opens?|open) no sockets?\b", re.I),
    re.compile(r"\b(?:opens?|open) no sockets?\b[^.\n]{0,160}\b(?:kit|offline)\b", re.I),
    re.compile(r"refuses every outbound (?:socket|connection) during a run", re.I),
]


class TestTheKitClaimIsNoStrongerThanTheRegistry:
    @pytest.mark.parametrize("relative", _site_sources() + ["src/assurance/billing/plans.py"])
    def test_no_overstated_phrase_survives_anywhere_a_visitor_reads(self, relative):
        text = _flat(relative)
        for pattern in _OVERSTATED_KIT:
            hit = pattern.search(text)
            assert hit is None, f"{relative}: {hit.group(0)!r} says more than the kit's guard does"

    def test_the_plan_card_names_the_operating_system_boundary(self):
        for relative in ("src/assurance/billing/plans.py", "app/lib/plans.ts"):
            text = _flat(relative).replace('" "', "")
            assert "refuses and records any network or process attempt it can see" in text, relative
            assert "network namespace" in text, relative

    @pytest.mark.parametrize("relative", ["app/page.tsx", "app/trust/page.tsx", "docs/assurance/index.md",
                                          "deploy/assurance/KIT.md", "README.md", "docs/getting-started.md"])
    def test_each_kit_surface_says_the_guard_watches_from_inside_the_process(self, relative):
        text = _flat(relative).lower()
        assert "network namespace" in text and "can see" in text, relative

    def test_the_registry_row_these_pages_follow_still_says_the_guard_records_intent(self):
        row = _flat("docs/claims-registry.md")
        assert "This **records intent**" in row and "the namespace layer (3) enforces" in row


# ---------------------------------------------------------------------------
# fleet advisory does no range arithmetic; the CSAF import reads dotted-decimal ranges
# ---------------------------------------------------------------------------
_RANGE_SURFACES = ["app/page.tsx", "app/lib/solutions.ts", "app/applications/page.tsx",
                   "app/lib/productPages.ts", "README.md"]
_UNSCOPED_RANGE = re.compile(r"\bnever (?:by )?version-range arithmetic", re.I)


class TestTheRangeClaimIsScopedToFleetAdvisory:
    def test_the_import_really_does_compare_ranges_so_the_unscoped_claim_is_false(self):
        from assurance.ingest import csaf

        assert csaf._in_range((3, 8, 1), "<3.9") is True
        assert csaf._in_range((3, 9, 0), "<3.9") is False
        assert csaf._in_range((3, 8, 1), "All versions < 3.1") is None  # not interpreted: unknown, not a guess

    def test_fleet_advisory_itself_does_none(self):
        advisory = _text("src/assurance/fleet/advisory.py")
        assert "No version-range arithmetic" in advisory
        assert "_in_range" not in advisory

    @pytest.mark.parametrize("relative", _RANGE_SURFACES)
    def test_no_surface_says_never_range_arithmetic_without_scope(self, relative):
        assert _UNSCOPED_RANGE.search(_flat(relative)) is None, relative

    @pytest.mark.parametrize("relative", _RANGE_SURFACES)
    def test_each_surface_scopes_the_claim_and_names_the_exception(self, relative):
        text = _flat(relative)
        assert "does no version-range arithmetic" in text, relative
        assert "dotted-decimal" in text, relative


# ---------------------------------------------------------------------------
# the rendered guides carry no market, pilot, price or founder framing
# ---------------------------------------------------------------------------
_RENDERED_DOCS = ["docs/getting-started.md", "docs/pricing.md", "docs/platform.md", "docs/integrations.md",
                  "docs/assurance/index.md"]
#: Commercial and internal-planning framing that does not belong in a public technical guide.
_PLANNING_FRAMING = [
    re.compile(r"\bpilots?\b", re.I),
    re.compile(r"\bfounders?\b", re.I),
    re.compile(r"nobody else|no one else|nobody has (?:closed|solved)", re.I),
    re.compile(r"eleven weeks", re.I),
    re.compile(r"DEPLOY_NOW|pilot-ledger|docs/pmf|CLAUDE\.md"),
    re.compile(r"subscription rather than a tool licence", re.I),
    re.compile(r"\.fly\.dev\b"),
]
_PRICE = re.compile(r"€|\bEUR\b")


class TestRenderedGuidesCarryNoPlanningFraming:
    @pytest.mark.parametrize("relative", _RENDERED_DOCS + [f"deploy/assurance/{n}" for n in _engine_sources()])
    def test_no_pilot_founder_prospect_or_unsourced_superlative(self, relative):
        text = _flat(relative)
        for pattern in _PLANNING_FRAMING:
            hit = pattern.search(text)
            assert hit is None, f"{relative}: {hit.group(0)!r} is internal planning or an unsourced claim on a public page"

    @pytest.mark.parametrize("relative", [d for d in _RENDERED_DOCS if d != "docs/pricing.md"]
                             + [f"deploy/assurance/{n}" for n in _engine_sources()])
    def test_no_price_outside_the_pricing_page(self, relative):
        hit = _PRICE.search(_flat(relative))
        assert hit is None, f"{relative}: {hit.group(0)!r}; prices live on docs/pricing.md with the unvalidated label"

    def test_every_engine_source_is_covered(self):
        sources = _engine_sources()
        assert {"KIT.md", "WATCH.md", "SUPPLIER.md", "KEY-CEREMONY.md", "INTEL.md", "FLEET.md",
                "TRUST-RUNBOOK.md", "ATTEST.md"} <= set(sources)
        assert all((ROOT / "deploy" / "assurance" / s).exists() for s in sources)

    def test_operator_commands_are_kept(self):
        """The technical content stays: a deployer still gets the command, minus the planning framing."""
        assert "fly secrets set ASSURANCE_ATTEST_KEY_PEM" in _text("deploy/assurance/TRUST-RUNBOOK.md")
        assert "fly secrets set ASSURANCE_ATTEST_KEY_PEM" in _text("deploy/assurance/KEY-CEREMONY.md")


class TestNoConcreteHostInTheCurlExamples:
    def test_attest_examples_use_a_placeholder_host(self):
        attest = _text("deploy/assurance/ATTEST.md")
        hosts = set(re.findall(r"curl -sS (https?://\S+?)/v1/", attest))
        assert hosts == {"https://<your-deployment>"}, hosts


# ---------------------------------------------------------------------------
# internal deployment notes stay off the public surfaces
# ---------------------------------------------------------------------------
_INTERNAL_NOTE = [
    re.compile(r"\bfounders?\b", re.I),
    re.compile(r"Fly\.io", re.I),
    re.compile(r"\bfly deploy\b"),
    re.compile(r"NEXT_PUBLIC_\w+"),
    re.compile(r"live Stripe keys", re.I),
    re.compile(r"environment that built", re.I),
]
_PUBLIC_STATIC = ["public/llms.txt", "public/.well-known/agent.json", "public/neuralbridge.vcf",
                  "public/.well-known/security.txt", "scripts/site_static/llms.txt.tmpl",
                  "scripts/site_static/agent.json.tmpl", "app/page.tsx"]


class TestInternalDeploymentNotesStayOffPublicSurfaces:
    @pytest.mark.parametrize("relative", _PUBLIC_STATIC)
    def test_no_founder_flyio_or_env_var_name(self, relative):
        text = _flat(relative)
        for pattern in _INTERNAL_NOTE:
            hit = pattern.search(text)
            assert hit is None, f"{relative}: {hit.group(0)!r} is an internal deployment note"

    def test_the_static_files_say_no_public_endpoint_is_deployed(self):
        assert "not deployed to a public endpoint" in _flat("public/llms.txt")
        assert "not deployed to a public endpoint" in _flat("app/page.tsx")


class TestAgentDescriptor:
    def _agent(self) -> dict:
        return json.loads(_text("public/.well-known/agent.json"))

    def test_it_states_that_no_hosted_api_is_deployed(self):
        data = self._agent()
        assert data["hosted_api"]["deployed"] is False
        assert "/v1/*" in data["hosted_api"]["note"] and "not an API" in data["hosted_api"]["note"]

    def test_it_does_not_call_itself_always_current(self):
        assert "always-current" not in _text("public/.well-known/agent.json")
        assert "always-current" not in _text("scripts/site_static/agent.json.tmpl")

    def test_the_checkout_503_is_scoped_to_an_operator_run_deployment(self):
        data = self._agent()
        for tier in data["pricing"]["tiers"]:
            if tier.get("purchasable_now") is False:
                assert "no public API instance" in tier["note"] and "503 price_not_configured" in tier["note"]
        assert "503 price_not_configured" in data["honesty_note"]
        assert data["honesty_note"].startswith("Purchase is inactive today.")

    def test_llms_txt_lists_the_verifier_and_the_engine_guides(self):
        llms = _text("public/llms.txt")
        assert "https://neuralbridge.io/verify" in llms and "https://neuralbridge.io/docs/assurance" in llms
        for slug in re.findall(r"slug: '([\w-]+)'", re.search(r"const ENGINE_PAGES.*?\n\];", _text("app/lib/docs.ts"), re.S).group(0)):
            assert slug in llms, slug
        agent = self._agent()["documentation"]
        assert "https://neuralbridge.io/verify" in agent and "https://neuralbridge.io/docs/assurance" in agent


# ---------------------------------------------------------------------------
# prices carry their qualifier wherever they are shown
# ---------------------------------------------------------------------------
_PRICE_TEXT = re.compile(r"(?:€|&euro;)\s?(?:390|1,290)\s?/\s?mo")


class TestPricesAreQualified:
    @pytest.mark.parametrize("relative", ["app/layout.tsx", "app/Header.tsx", "app/lib/search-index.ts"])
    def test_each_price_line_says_it_is_an_unvalidated_list_price(self, relative):
        lines = [ln for ln in _text(relative).splitlines() if _PRICE_TEXT.search(ln)]
        assert lines, relative
        for ln in lines:
            assert "list price" in ln.lower(), f"{relative}: {ln.strip()}"

    def test_the_home_page_product_cards_qualify_their_badge_price(self):
        page = _text("app/page.tsx")
        cards = re.findall(r"badge: '(€[^']+)',.*?body: '([^']+)'", page, re.S)
        assert len(cards) == 2, cards
        for badge, body in cards:
            assert "unvalidated list price" in body.lower(), badge


# ---------------------------------------------------------------------------
# links go where their labels say; titles name the topic
# ---------------------------------------------------------------------------
class TestLinksAndTitles:
    def test_the_footer_regulation_links_go_to_their_own_pages(self):
        layout = _text("app/layout.tsx")
        assert '<a href="/product/cra-article-14">CRA Article 14</a>' in layout
        assert '<a href="/product/machinery-regulation-evidence">Machinery Reg. Annex III 1.1.9</a>' in layout
        pages = _text("app/lib/productPages.ts")
        for slug in ("cra-article-14", "machinery-regulation-evidence"):
            assert f"slug: '{slug}'" in pages

    def test_developers_does_not_send_a_reader_to_a_checkout_that_does_not_exist(self):
        text = _flat("app/developers/page.tsx")
        assert "Get a key from <code>POST /v1/checkout</code>" not in text
        assert "none is public today" in text and 'href="/start#account"' in text

    @pytest.mark.parametrize("relative", ["app/Header.tsx", "app/lib/search-index.ts"])
    def test_nothing_points_at_a_deploying_guide_that_is_not_there(self, relative):
        assert not re.search(r"every engine, deploying", _text(relative))

    def test_titles_name_the_topic(self):
        for relative in ("app/ai/page.tsx", "app/cli/page.tsx"):
            title = re.search(r"title: '([^']+)'", _text(relative)).group(1)
            assert len(title.split()) >= 3, f"{relative}: {title!r}"
        solutions = _text("app/lib/solutions.ts")
        meta = re.findall(r"metaTitle: '([^']+)'", solutions)
        roles = re.findall(r"\n    role: '([^']+)'", solutions)
        assert len(meta) == len(roles) == 6
        for title, role in zip(meta, roles, strict=True):
            assert title != role and len(title) <= 47, title
        assert "title: solution.metaTitle," in _text("app/solutions/[slug]/page.tsx")

    def test_the_continuous_assurance_definition_says_configuration_drift(self):
        pages = _text("app/lib/productPages.ts")
        definition = re.search(r"slug: 'continuous-machine-assurance'.*?definition:\s*'([^']+)'", pages, re.S).group(1)
        assert "configuration drift" in definition
        assert sum(m.start() >= 0 for m in re.finditer(r"configuration drift", "".join(_text(p) for p in
               ("app/lib/productPages.ts", "app/lib/solutions.ts")), re.I)) >= 2


# ---------------------------------------------------------------------------
# the playground: neutral next-step wording, sample data labelled
# ---------------------------------------------------------------------------
class TestAdvisoryPlayground:
    PLAYGROUND = "app/components/AdvisoryCheckPlayground.tsx"

    def test_the_human_review_action_is_not_shown_as_a_sales_call(self):
        text = _flat(self.PLAYGROUND)
        assert "talk to sales" not in text.lower() and "'Contact sales'" not in text
        assert "review this with your safety engineer" in text

    def test_the_sample_payload_is_labelled_synthetic(self):
        assert "Sample data (synthetic)" in _text(self.PLAYGROUND)
