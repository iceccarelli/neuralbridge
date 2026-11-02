"""The /product/<slug> pages say what the code does, and each of their claims is held by a test.

The eleven pages are written once, as data, in ``app/lib/productPages.ts`` and rendered by
``app/product/[slug]/page.tsx``. This module reads that data under Node (type stripping) and checks the
words against the capability contract (``public/capabilities.json``), the OpenAPI schema and the engine
guides under ``deploy/assurance/``; a second layer builds the site and checks what a visitor and a crawler
receive: one ``h1``, the same FAQ in the page and in the FAQPage JSON-LD, the canonical URL, the sitemap.

Every rule has a mutation test: the same checker run on a copy of the data with one thing broken (a
capability id that does not exist, a route that does not exist, ``trusted by``) must report it.
"""

from __future__ import annotations

import copy
import html
import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA_MODULE = "app/lib/productPages.ts"
CONTRACT = json.loads((ROOT / "public" / "capabilities.json").read_text(encoding="utf-8"))
OPENAPI = json.loads((ROOT / "public" / "openapi.json").read_text(encoding="utf-8"))
SITE = "https://neuralbridge.io"

SLUGS = [
    "industrial-autonomous-assurance",
    "machine-evidence-ledger",
    "continuous-machine-assurance",
    "supplier-advisory-fleet-impact",
    "cra-article-14",
    "machinery-regulation-evidence",
    "machine-safety-verification",
    "evidence-attestation",
    "offline-assurance-kit",
    "assurance-api-and-mcp",
    "enterprise-integration",
]
CATEGORY = SLUGS[0]

# test_site_capabilities_contract.py bans these on its pages; here they apply to every product page,
# extended with the wording a claim we cannot back would use.
BANNED = re.compile(
    r"\b(customers?|pilots?|revenue|valuation|market (?:leader|share|position|size)|dominan\w*|"
    r"industry[- ]leading|world[- ]class|best[- ]in[- ]class|certified|certification|"
    r"guarantee[sd]?|trusted by|compliant with)\b"
    r"|certified by|\bguarantee\w*|market-leading|best-in-class|#1\b|trusted by|customers include|\baward\w*",
    re.I,
)

# test_site_capabilities_contract.py: a count typed next to its noun must be a number the contract holds.
NOUN = re.compile(
    r"\b(\d[\d,]*|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
    r"fifteen|sixteen|seventeen|eighteen|nineteen|twenty)\s+(?:(?:HTTP|MCP|CLI|read-only)\s+)*"
    r"(tools|routes|domains|commands|capabilities)\b", re.I)


# ---------------------------------------------------------------------------------------------
# reading the data module
# ---------------------------------------------------------------------------------------------
def _node(script: str) -> object:
    node = shutil.which("node")
    assert node, "node is not installed; this module reads app/lib/productPages.ts with it"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is a constant in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def data() -> dict:
    return _node(
        "const m = await import('./app/lib/productPages.ts');"
        "process.stdout.write(JSON.stringify({pages: m.PRODUCT_PAGES, vocabulary: m.VOCABULARY,"
        " category: m.CATEGORY_SLUG, base: m.PRODUCT_BASE, site: m.SITE_URL}));"
    )


@pytest.fixture(scope="module")
def pages(data) -> list[dict]:
    return data["pages"]


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


def _prose(page: dict) -> str:
    """The words a visitor reads on the page that come from the data (the status table is read from the contract)."""
    parts = [page["definition"], *page["problem"]]
    parts += [f"{s['title']}. {s['body']}" for s in page["workflow"]]
    parts += [*page["youGet"], *page["notEstablished"], *page["whoActs"], page["statusNote"]]
    parts += [f"{f['q']} {f['a']}" for f in page["faq"]]
    return re.sub(r"\s+", " ", " ".join(parts).replace("`", "")).strip()


def _words(text: str) -> int:
    return len(re.findall(r"[\w'’/.-]+", text))


# ---------------------------------------------------------------------------------------------
# the contract: what exists
# ---------------------------------------------------------------------------------------------
CAP_IDS = {c["id"] for c in CONTRACT["capabilities"]}
CAPS = {c["id"]: c for c in CONTRACT["capabilities"]}
MCP_TOOLS = set(CONTRACT["mcp_tools"])
CLI_NAMES = {n for c in CONTRACT["capabilities"] for n in c["surfaces"]["cli"].get("names", [])}
CLI_DOMAINS = CONTRACT["cli_domains"]


def _norm_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


API_ROUTES = {
    f"{name.split(' ', 1)[0]} {_norm_path(name.split(' ', 1)[1])}"
    for c in CONTRACT["capabilities"] for name in c["surfaces"]["api"].get("names", [])
}
API_ROUTES |= {
    f"{m.upper()} {_norm_path(path)}"
    for path, item in OPENAPI["paths"].items() if path.startswith("/v1/") for m in item
    if m in {"get", "post", "put", "patch", "delete"}
}
_VOCAB_CORPUS = "\n".join(
    p.read_text(encoding="utf-8") for p in sorted((ROOT / "deploy" / "assurance").glob("*.md"))
)


# ---------------------------------------------------------------------------------------------
# the checkers (each returns a list of problems, so a mutation test can assert it is non-empty)
# ---------------------------------------------------------------------------------------------
def check_capability_ids(pages: list[dict]) -> list[str]:
    bad = []
    for page in pages:
        ids = [c for step in page["workflow"] for c in step.get("caps", [])] + list(page["statusCaps"])
        bad += [f"{page['slug']}: {i}" for i in ids if i not in CAP_IDS]
    return bad


def _backticked(page: dict) -> list[str]:
    return [span for s in _strings(page) for span in re.findall(r"`([^`]+)`", s)]


def _cli_prefix_exists(tokens: list[str]) -> bool:
    """The leading words of a command (up to the first flag, path, placeholder or file name) are a CLI name or the start of one."""
    prefix: list[str] = []
    for token in tokens:
        if token.startswith("-") or token.isdigit() or re.search(r"[A-Z/.=<>\[\]]", token):
            break
        prefix.append(token)
    if not prefix:
        return False
    joined = " ".join(prefix)
    return joined in CLI_NAMES or any(n.startswith(joined + " ") for n in CLI_NAMES)


def check_named_things(pages: list[dict], vocabulary: list[str]) -> list[str]:
    """Every command, route and MCP tool a page names in code is one the contract (or openapi.json) lists."""
    bad = []
    allowed_words = MCP_TOOLS | set(vocabulary)
    for page in pages:
        for span in _backticked(page):
            if m := re.fullmatch(r"(GET|POST|PUT|PATCH|DELETE) (/v1/\S+)", span):
                if f"{m.group(1)} {_norm_path(m.group(2))}" not in API_ROUTES:
                    bad.append(f"{page['slug']}: route {span}")
            elif re.match(r"(python -m )?assurance\b", span):
                tokens = re.sub(r"^(python -m )?assurance\s*", "", span).split()
                if tokens and not _cli_prefix_exists(tokens):
                    bad.append(f"{page['slug']}: command {span}")
            elif re.fullmatch(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+", span):
                if span not in allowed_words:
                    bad.append(f"{page['slug']}: tool or term {span}")
        # a route written outside backticks is checked too
        plain = " ".join(s.replace("`", "") for s in _strings(page))
        for method, path in re.findall(r"\b(GET|POST|PUT|PATCH|DELETE) (/v1/[^\s,;:)]+)", plain):
            path = path.rstrip(".")
            if f"{method} {_norm_path(path)}" not in API_ROUTES:
                bad.append(f"{page['slug']}: route {method} {path}")
    return bad


def check_banned(pages: list[dict]) -> list[str]:
    out = []
    for page in pages:
        for s in _strings(page):
            if hit := BANNED.search(s.replace("`", "")):
                out.append(f"{page['slug']}: {hit.group(0)!r}")
    return out


# ---------------------------------------------------------------------------------------------
# 1. the data
# ---------------------------------------------------------------------------------------------
class TestTheEveryPageExists:
    def test_the_eleven_pages_are_exactly_these_slugs_in_order(self, pages):
        assert [p["slug"] for p in pages] == SLUGS

    def test_base_path_and_site_url(self, data):
        assert data["base"] == "/product" and data["site"] == SITE and data["category"] == CATEGORY

    def test_every_page_has_every_section_filled(self, pages):
        for p in pages:
            assert p["definition"].strip() and p["definition"].count(". ") == 0 and p["definition"].endswith("."), p["slug"]
            assert len(p["problem"]) >= 2, p["slug"]
            assert len(p["workflow"]) >= 5, p["slug"]
            assert p["youGet"] and p["notEstablished"] and p["whoActs"] and p["statusNote"], p["slug"]
            assert len(p["notEstablished"]) >= 3, p["slug"]
            assert len(p["statusCaps"]) >= 6, p["slug"]
            assert p["docs"], p["slug"]

    def test_related_links_resolve_and_the_category_links_to_all_others(self, pages):
        by_slug = {p["slug"]: p for p in pages}
        for p in pages:
            assert p["slug"] not in p["related"], p["slug"]
            assert set(p["related"]) <= set(by_slug), p["slug"]
            assert len(p["related"]) >= 3, p["slug"]
        assert set(by_slug[CATEGORY]["related"]) == set(SLUGS) - {CATEGORY}

    def test_the_lifecycle_is_the_nine_stages_in_order(self, pages):
        stages = [s["title"] for s in pages[0]["workflow"]]
        assert stages == ["Machine", "Configuration", "Software", "Evidence", "Change",
                          "Verification", "Finding", "Intervention", "Attestation"]


class TestCapabilityIdsAndNamedThings:
    def test_every_capability_id_referenced_exists(self, pages):
        assert check_capability_ids(pages) == []

    def test_every_page_ties_its_workflow_to_the_contract(self, pages):
        for p in pages:
            assert sum(len(s.get("caps", [])) for s in p["workflow"]) >= 2, p["slug"]

    def test_every_command_route_and_tool_named_exists(self, pages, data):
        assert check_named_things(pages, data["vocabulary"]) == []

    def test_the_pages_name_real_things_at_all(self, pages, data):
        spans = [s for p in pages for s in _backticked(p)]
        assert sum(s.startswith("assurance ") for s in spans) > 60
        assert sum(bool(re.match(r"(GET|POST) /v1/", s)) for s in spans) > 12
        assert {s for s in spans if s in MCP_TOOLS} >= {"ledger_verify", "capabilities", "machinery_coverage"}

    def test_every_vocabulary_term_is_in_the_engine_guides_and_used(self, pages, data):
        used = {s for p in pages for s in _backticked(p)}
        for term in data["vocabulary"]:
            assert term in _VOCAB_CORPUS, f"{term} is not in deploy/assurance/*.md"
            assert term in used, f"{term} is in VOCABULARY but no page uses it"

    def test_mcp_tool_count_is_not_typed_wrongly(self, pages):
        counts = CONTRACT["counts"]
        allowed = {"tools": counts["mcp_tools"], "routes": counts["api_routes"], "domains": counts["cli_domains"],
                   "commands": counts["cli_commands"], "capabilities": counts["capabilities"]}
        for p in pages:
            for number, noun in NOUN.findall(_prose(p)):
                assert number.isdigit() and int(number.replace(",", "")) == allowed[noun.lower()], \
                    f"{p['slug']}: {number} {noun}"

    def test_the_status_claims_in_the_notes_match_the_contract(self):
        def cell(cap: str, surface: str) -> str:
            return CAPS[cap]["surfaces"][surface]["status"]

        # "no MCP tool, by design" for a named person's declaration or decision
        for cap in ("machinery.enrol", "machinery.amend_enrolment", "machinery.intervention", "machinery.passport",
                    "change.decide", "art14.awareness", "intel.ingest", "intel.refresh", "attest.keygen",
                    "machine.recorder_sign", "machine.recorder_trust", "ops.cycle", "tenant.export", "tenant.delete"):
            assert cell(cap, "mcp") == "by_design", cap
        # CLI-only operator tooling: no route either
        for cap in ("kit.init", "kit.check", "kit.run", "attest.keygen", "machine.recorder_sign", "ops.cycle",
                    "tenant.export", "tenant.delete", "intel.ingest", "intel.refresh"):
            assert cell(cap, "api") == "by_design", cap
        # the one planned item anywhere is the CLI verb for the signed advisory case route
        planned = [(c["id"], s) for c in CONTRACT["capabilities"] for s, v in c["surfaces"].items() if v["status"] == "planned"]
        assert planned == [("change.assess_advisory_signed", "cli")]
        assert cell("change.assess_advisory_signed", "api") == "available"
        # reads that the pages say MCP offers
        for cap in ("machinery.coverage", "machinery.diff", "machinery.passport_check", "art14.case", "art14.register",
                    "art14.breaches", "art14.export", "evidence.ledger_verify", "attest.verify", "machine.check"):
            assert cell(cap, "mcp") == "available", cap
        # the MCP tools the API page names as bounded case work
        for tool in ("change_claim", "change_advance", "change_reverify", "change_assess_drift", "change_assess_intervention"):
            assert tool in MCP_TOOLS


class TestMetadataInTheData:
    def test_titles_are_unique_and_at_most_60_characters(self, pages):
        titles = [p["title"] for p in pages]
        assert len(set(titles)) == len(titles)
        for t in titles:
            assert 10 <= len(t) <= 60, f"{len(t)}: {t}"

    def test_descriptions_are_unique_and_120_to_160_characters(self, pages):
        descriptions = [p["description"] for p in pages]
        assert len(set(descriptions)) == len(descriptions)
        for d in descriptions:
            assert 120 <= len(d) <= 160, f"{len(d)}: {d}"

    def test_names_h1s_and_definitions_are_unique(self, pages):
        for field in ("name", "h1", "definition", "intent"):
            values = [p[field] for p in pages]
            assert len(set(values)) == len(values), field

    def test_titles_do_not_repeat_the_page_titles_the_site_already_has(self, pages):
        taken = set()
        for relative in ("app/layout.tsx", "app/security/page.tsx", "app/privacy/page.tsx", "app/contact/page.tsx",
                         "app/verify/page.tsx", "app/status/page.tsx", "app/roadmap/page.tsx", "app/cli/page.tsx"):
            taken |= set(re.findall(r"title:\s*'([^']+)'", (ROOT / relative).read_text(encoding="utf-8")))
        assert not taken & {p["title"] for p in pages}


class TestTheWords:
    def test_each_page_has_600_to_1100_words_of_data_prose(self, pages):
        for p in pages:
            n = _words(_prose(p))
            assert 600 <= n <= 1100, f"{p['slug']}: {n} words"

    def test_the_faq_is_three_to_five_unique_plain_questions(self, pages):
        for p in pages:
            assert 3 <= len(p["faq"]) <= 5, p["slug"]
            questions = [f["q"] for f in p["faq"]]
            assert len(set(questions)) == len(questions)
            for f in p["faq"]:
                assert f["q"].endswith("?") and f["a"].strip(), (p["slug"], f)
                assert "`" not in f["q"] + f["a"], f"{p['slug']}: a FAQ string must be plain text, the JSON-LD repeats it"

    def test_no_banned_claim_words(self, pages):
        assert check_banned(pages) == []

    def test_no_link_into_the_repository_and_no_forbidden_structured_data(self):
        for relative in (DATA_MODULE, "app/product/[slug]/page.tsx", "app/product/product.css"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            assert "github.com" not in text and "iceccarelli" not in text, relative
        page = (ROOT / "app/product/[slug]/page.tsx").read_text(encoding="utf-8")
        types = set(re.findall(r"'@type': '(\w+)'", page))
        assert types == {"BreadcrumbList", "ListItem", "FAQPage", "Question", "Answer"}, types

    def test_no_price_or_customer_or_market_figure_in_the_copy(self, pages):
        for p in pages:
            text = " ".join(_strings(p))
            assert not re.search(r"€|\bEUR\b|\$\d|/mo\b|per month", text), p["slug"]

    def test_the_regulation_pages_do_not_say_the_product_files_or_certifies(self, pages):
        for p in pages:
            text = " ".join(_strings(p)).replace("`", "")
            assert not re.search(r"\b(?:NeuralBridge|this product|the product|the software|software)\s+(?:files|certifies|makes you)\b", text, re.I), p["slug"]
        by = {p["slug"]: p for p in pages}
        # the two regulation pages state the separation the brief asks for
        for slug in ("cra-article-14", "machinery-regulation-evidence"):
            who = " ".join(by[slug]["whoActs"]).lower()
            for word in ("obligation", "product feature", "human decision", "conformity assessment"):
                assert word in who, (slug, word)
        assert "filing" in " ".join(by["cra-article-14"]["whoActs"]).lower()

    def test_the_connectors_are_labelled_evolving_and_file_based(self, pages):
        text = " ".join(_strings(next(p for p in pages if p["slug"] == "enterprise-integration"))).lower()
        for needle in ("not a supported adapter", "file importer", "evolving", "synthetic", "fixture", "canned"):
            assert needle in text, needle

    def test_the_kit_page_says_the_guard_records_intent_and_names_the_test(self, pages):
        text = " ".join(_strings(next(p for p in pages if p["slug"] == "offline-assurance-kit"))).lower()
        assert "records intent" in text and "network namespace" in text and "airgap test suite" in text
        assert (ROOT / "tests" / "test_assurance_airgap_enforcement.py").exists()

    def test_the_ledger_page_states_what_a_chain_does_not_detect(self, pages):
        text = " ".join(_strings(next(p for p in pages if p["slug"] == "machine-evidence-ledger"))).lower()
        for needle in ("does not detect removal", "tail", "signed head", "not checked", "backup", "restore"):
            assert needle in text, needle

    def test_the_supplier_page_keeps_the_two_hard_sentences(self, pages):
        text = " ".join(_strings(next(p for p in pages if p["slug"] == "supplier-advisory-fleet-impact"))).lower()
        assert "describes a product" in text and "not what" in text
        assert "empty fleet" in text and "no machine was assessed" in text and "inspect-only" in text


# ---------------------------------------------------------------------------------------------
# 2. mutations: each checker must fail on a broken copy
# ---------------------------------------------------------------------------------------------
class TestMutations:
    def test_a_bogus_capability_id_fails(self, pages):
        broken = copy.deepcopy(pages)
        broken[3]["statusCaps"].append("supplier.does_not_exist")
        assert check_capability_ids(broken) == ["supplier-advisory-fleet-impact: supplier.does_not_exist"]
        broken = copy.deepcopy(pages)
        broken[1]["workflow"][0]["caps"] = ["evidence.not_a_capability"]
        assert check_capability_ids(broken)

    def test_a_bogus_route_command_or_tool_fails(self, pages, data):
        for bogus in ("POST /v1/ledger/rewind", "assurance machinery teleport", "assurance bogusdomain run", "ledger_rewind"):
            broken = copy.deepcopy(pages)
            broken[1]["youGet"].append(f"Use `{bogus}` for this.")
            assert check_named_things(broken, data["vocabulary"]), bogus

    def test_a_route_outside_backticks_is_checked_too(self, pages, data):
        broken = copy.deepcopy(pages)
        broken[2]["problem"].append("Call POST /v1/nothing/here to do it.")
        assert check_named_things(broken, data["vocabulary"])

    def test_the_real_ones_pass_the_same_checker(self, pages, data):
        ok = copy.deepcopy(pages)
        ok[1]["youGet"].append("Use `assurance attest sign --ledger L`, `POST /v1/ledger/attest` and `ledger_verify`.")
        assert check_named_things(ok, data["vocabulary"]) == []

    @pytest.mark.parametrize("phrase", ["trusted by", "Trusted by plants", "certified by TUV", "guarantee", "market-leading",
                                        "best-in-class", "#1 choice", "customers include", "award-winning", "our customers"])
    def test_a_banned_claim_fails(self, pages, phrase):
        broken = copy.deepcopy(pages)
        broken[0]["youGet"].append(f"This is {phrase} today.")
        assert check_banned(broken), phrase

    def test_the_banned_words_in_the_title_description_and_faq_fail_too(self, pages):
        for field in ("title", "description"):
            broken = copy.deepcopy(pages)
            broken[0][field] += " trusted by"
            assert check_banned(broken), field
        broken = copy.deepcopy(pages)
        broken[0]["faq"][0]["a"] = "Customers include several plants."
        assert check_banned(broken)

    def test_the_real_data_is_clean_under_the_same_regex(self, pages):
        assert check_banned(pages) == []


# ---------------------------------------------------------------------------------------------
# 3. the wiring: sitemap, search index, menu, home page, solutions
# ---------------------------------------------------------------------------------------------
def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class TestWiring:
    def test_sitemap_search_header_and_home_are_driven_by_the_data_module(self):
        assert "PRODUCT_PAGES.map" in _text("app/sitemap.ts") and "productHref(p.slug)" in _text("app/sitemap.ts")
        assert "PRODUCT_PAGES" in _text("app/lib/search-index.ts")
        header = _text("app/Header.tsx")
        assert "PRODUCT_PAGES" in header and "label: 'Product'" in header
        assert "PRODUCT_PAGES" in _text("app/page.tsx")

    def test_each_solution_links_to_product_pages(self, pages):
        source = _text("app/lib/solutions.ts")
        slugs = re.findall(r"productHref\('([a-z0-9-]+)'\)", source)
        assert set(slugs) <= set(SLUGS) and len(slugs) >= 9
        for block in re.split(r"\n  \{\n    slug: ", source)[1:]:
            assert "productHref('" in block.split("primaryCta")[0], block[:40]

    def test_search_titles_are_unique(self):
        # SearchOverlay keys its results by title
        source = _text("app/lib/search-index.ts")
        assert "title: `${p.name}: how it works`" in source

    def test_the_product_route_group_has_no_index_page_to_404(self):
        assert not (ROOT / "app" / "product" / "page.tsx").exists()


# ---------------------------------------------------------------------------------------------
# 4. the built site
# ---------------------------------------------------------------------------------------------
class _Page(HTMLParser):
    """Collects what a crawler and a reader get from one built page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.h1 = 0
        self.h2: list[tuple[str, str]] = []
        self.ld: list[str] = []
        self.hrefs: list[str] = []
        self.dt: list[str] = []
        self.dd: list[str] = []
        self.main_text: list[str] = []
        self.meta: dict[str, str] = {}
        self.canonical = ""
        self.title = ""
        self.lis: list[str] = []
        self._stack: list[str] = []
        self._buf: list[str] = []
        self._cur_h2_id = ""
        self._in_main = 0
        self._ld = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self._stack.append(tag)
        if tag == "main":
            self._in_main += 1
        if tag == "h1":
            self.h1 += 1
        if tag == "h2":
            self._cur_h2_id = a.get("id", "")
        if tag == "a" and self._in_main and a.get("href"):
            self.hrefs.append(a["href"])
        if tag == "meta":
            key = a.get("name") or a.get("property")
            if key and "content" in a:
                self.meta[key] = a["content"]
        if tag == "link" and a.get("rel") == "canonical":
            self.canonical = a.get("href", "")
        if tag == "script" and a.get("type") == "application/ld+json":
            self._ld = True
            self._buf = []
        if tag in {"dt", "dd", "h2", "title"}:
            self._buf = []

    def handle_endtag(self, tag):
        if tag == "script" and self._ld:
            self.ld.append("".join(self._buf))
            self._ld = False
        if tag == "dt":
            self.dt.append("".join(self._buf).strip())
        if tag == "dd":
            self.dd.append("".join(self._buf).strip())
        if tag == "h2":
            self.h2.append((self._cur_h2_id, "".join(self._buf).strip()))
        if tag == "title":
            self.title = "".join(self._buf).strip()
        if tag == "main":
            self._in_main -= 1
        if self._stack and self._stack[-1] == tag:
            self._stack.pop()

    def handle_data(self, data):
        self._buf.append(data)
        if self._in_main and "script" not in self._stack and "style" not in self._stack:
            self.main_text.append(data)


def _parse(path: Path) -> _Page:
    page = _Page()
    page.feed(path.read_text(encoding="utf-8"))
    return page


def _build(tmp_name: str) -> Path:
    if not (ROOT / "node_modules" / "next").exists():
        pytest.skip("node_modules is not installed (npm ci); the CI Site job runs this module after npm ci")
    dist = ROOT / tmp_name
    shutil.rmtree(dist, ignore_errors=True)
    env = dict(os.environ)
    env.pop("NEXT_PUBLIC_REPO_PUBLIC", None)
    env["NEXT_DIST_DIR"] = tmp_name
    env["NEXT_TELEMETRY_DISABLED"] = "1"
    tsconfig = ROOT / "tsconfig.json"
    before = tsconfig.read_text(encoding="utf-8")
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv
            [shutil.which("npm") or "npm", "run", "build"],
            cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=900,
        )
    finally:
        tsconfig.write_text(before, encoding="utf-8")  # next build edits it; put it back
    assert done.returncode == 0, done.stdout[-2000:] + done.stderr[-2000:]
    return dist


@pytest.fixture(scope="module")
def built():
    dist = _build(".next-repo-product")
    yield dist
    shutil.rmtree(dist, ignore_errors=True)


def _built_page(dist: Path, slug: str) -> _Page:
    return _parse(dist / "server" / "app" / "product" / f"{slug}.html")


def _json_ld(page: _Page) -> list[dict]:
    return [json.loads(block) for block in page.ld]


def _route_exists(dist: Path, href: str) -> bool:
    path = href.split("#", 1)[0].split("?", 1)[0]
    if path in {"/openapi.json", "/capabilities.json"}:
        return (ROOT / "public" / path.lstrip("/")).exists()
    if path == "/":
        return (dist / "server" / "app" / "index.html").exists()
    return (dist / "server" / "app" / f"{path.strip('/')}.html").exists()


class TestBuiltPages:
    @pytest.mark.parametrize("slug", SLUGS)
    def test_exactly_one_h1_and_the_required_sections(self, built, pages, slug):
        page = _built_page(built, slug)
        assert page.h1 == 1
        ids = [i for i, _ in page.h2]
        assert ids == ["problem-h", "how-h", "get-h", "not-h", "who-h", "status-h", "related-h", "faq-h"]
        headings = [t for _, t in page.h2]
        assert headings == ["The problem", "How it works here", "What you get", "What it does not establish",
                            "Who acts", "Status", "Related", "Questions"]

    @pytest.mark.parametrize("slug", SLUGS)
    def test_title_description_canonical_and_open_graph(self, built, pages, slug):
        data = next(p for p in pages if p["slug"] == slug)
        page = _built_page(built, slug)
        url = f"{SITE}/product/{slug}"
        assert page.title == data["title"] and len(page.title) <= 60
        assert page.meta["description"] == data["description"] and 120 <= len(page.meta["description"]) <= 160
        assert page.canonical == url
        assert page.meta["og:url"] == url and page.meta["og:title"] == data["title"]
        assert page.meta["og:description"] == data["description"]
        assert page.meta["twitter:title"] == data["title"]

    @pytest.mark.parametrize("slug", SLUGS)
    def test_structured_data_is_a_breadcrumb_and_the_visible_faq_and_nothing_else_of_ours(self, built, pages, slug):
        data = next(p for p in pages if p["slug"] == slug)
        page = _built_page(built, slug)
        blocks = _json_ld(page)
        types = [b["@type"] for b in blocks]
        assert {"BreadcrumbList", "FAQPage"} <= set(types)
        assert set(types) <= {"BreadcrumbList", "FAQPage", "Organization"}, types  # Organization is the layout's

        def all_types(node) -> set[str]:
            if isinstance(node, dict):
                return ({node["@type"]} if "@type" in node else set()) | {t for v in node.values() for t in all_types(v)}
            if isinstance(node, list):
                return {t for v in node for t in all_types(v)}
            return set()

        mine = [b for b in blocks if b["@type"] != "Organization"]
        assert all_types(mine) == {"BreadcrumbList", "ListItem", "FAQPage", "Question", "Answer"}
        crumb = next(b for b in blocks if b["@type"] == "BreadcrumbList")
        items = [(i["position"], i["name"], i["item"]) for i in crumb["itemListElement"]]
        expected = [(1, "Home", f"{SITE}/"), (2, "Product", f"{SITE}/product/{CATEGORY}")]
        if slug != CATEGORY:
            expected.append((3, data["name"], f"{SITE}/product/{slug}"))
        assert items == expected
        faq = next(b for b in blocks if b["@type"] == "FAQPage")
        ld_pairs = [(q["name"], q["acceptedAnswer"]["text"]) for q in faq["mainEntity"]]
        visible = list(zip(page.dt, page.dd, strict=True))
        assert ld_pairs == visible == [(f["q"], f["a"]) for f in data["faq"]]
        assert 3 <= len(visible) <= 5

    @pytest.mark.parametrize("slug", SLUGS)
    def test_visible_words_banned_words_and_counts(self, built, slug):
        page = _built_page(built, slug)
        text = re.sub(r"\s+", " ", html.unescape(" ".join(page.main_text))).strip()
        assert _words(text) >= 500, _words(text)
        assert not BANNED.search(text), BANNED.search(text).group(0)
        assert "github.com" not in "".join(page.hrefs) and "iceccarelli" not in text
        for number, noun in NOUN.findall(text):
            counts = CONTRACT["counts"]
            allowed = {"tools": counts["mcp_tools"], "routes": counts["api_routes"], "domains": counts["cli_domains"],
                       "commands": counts["cli_commands"], "capabilities": counts["capabilities"]}
            assert number.isdigit() and int(number) == allowed[noun.lower()], (number, noun)

    @pytest.mark.parametrize("slug", SLUGS)
    def test_every_internal_link_resolves_and_every_capability_anchor_is_real(self, built, slug):
        page = _built_page(built, slug)
        cap_links = [h for h in page.hrefs if h.startswith("/docs/capabilities#")]
        assert len(cap_links) >= 4
        for href in page.hrefs:
            if href.startswith("/"):
                assert _route_exists(built, href), f"{slug}: {href} answers not-found"
            if href.startswith("/docs/capabilities#"):
                frag = href.split("#", 1)[1]
                assert frag.startswith("cap-") and frag[4:] in CAP_IDS, href
            if href.startswith("/product/"):
                assert href.removeprefix("/product/") in SLUGS, href

    @pytest.mark.parametrize("slug", SLUGS)
    def test_status_table_matches_the_contract_cell_for_cell(self, built, pages, slug):
        data = next(p for p in pages if p["slug"] == slug)
        raw = (built / "server" / "app" / "product" / f"{slug}.html").read_text(encoding="utf-8")
        table = raw[raw.index('class="product-status"'):]
        table = table[:table.index("</table>")]
        rows = re.findall(r"<tr><th scope=\"row\"><a href=\"([^\"]+)\">(.*?)</a></th>(.*?)</tr>", table, re.S)
        assert [h for h, _, _ in rows] == [f"/docs/capabilities#cap-{i}" for i in data["statusCaps"]]
        label = {"available": "available", "planned": "planned", "by_design": "by design"}
        for (_, title, cells), cap_id in zip(rows, data["statusCaps"], strict=True):
            cap = CAPS[cap_id]
            assert html.unescape(title) == cap["title"]
            statuses = re.findall(r'<span class="status-(\w+)">([^<]+)</span>', cells)
            assert [(s, t) for s, t in statuses] == [
                (cap["surfaces"][k]["status"], label[cap["surfaces"][k]["status"]]) for k in ("cli", "api", "mcp")
            ], cap_id

    def test_the_category_page_links_to_every_other_page_and_each_links_back(self, built):
        cat = _built_page(built, CATEGORY)
        assert {f"/product/{s}" for s in SLUGS if s != CATEGORY} <= set(cat.hrefs)
        for slug in SLUGS[1:]:
            assert f"/product/{CATEGORY}" in _built_page(built, slug).hrefs

    def test_the_sitemap_lists_every_page_once(self, built):
        body = (built / "server" / "app" / "sitemap.xml.body").read_text(encoding="utf-8")
        locs = re.findall(r"<loc>([^<]+)</loc>", body)
        for slug in SLUGS:
            assert locs.count(f"{SITE}/product/{slug}") == 1, slug
        assert f"{SITE}/product" not in locs
        assert len(locs) == len(set(locs))

    def test_home_and_solutions_link_to_the_product_pages(self, built):
        home = _parse(built / "server" / "app" / "index.html")
        assert {f"/product/{s}" for s in SLUGS} <= set(home.hrefs)
        for solution in ("manufacturer", "plant-operator", "compliance-officer", "insurer-auditor", "ai-ops"):
            page = _parse(built / "server" / "app" / "solutions" / f"{solution}.html")
            assert any(h.startswith("/product/") for h in page.hrefs), solution

    def test_the_built_product_pages_name_no_repository(self, built):
        for slug in SLUGS:
            raw = (built / "server" / "app" / "product" / f"{slug}.html").read_text(encoding="utf-8")
            assert "github.com/iceccarelli" not in raw
