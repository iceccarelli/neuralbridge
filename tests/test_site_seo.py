"""The built site is findable and describes itself accurately: titles, descriptions, canonicals, social tags, structured data.

Every assertion reads the HTML ``next build`` wrote, not the TSX that produced it, because the failures this
guards against are in what a crawler receives: a page-level ``openGraph`` that silently drops the image, a
canonical inherited from the layout onto the 404, two pages sharing a title, a JSON-LD block that claims a
price. ``app/lib/seo.ts`` (``buildMetadata``) is the one place those tags are assembled.

Build cost: one production build into ``.next-repo-seo`` (about 20 s, once per run; the directory is
git-ignored through ``.next-repo-*/``). It reuses ``test_site_repo_links._build`` so the tsconfig restore and the
"no node_modules -> skip with a reason" behaviour are the same. To skip the build, point ``SITE_SEO_DIST`` at an
existing ``next build`` output made from this checkout (for example ``.next`` after ``npm run build``).

What is deliberately not here: the noindex route list is NOT hand-written for the sitemap check; it is whatever
pages carry a robots noindex tag. The four known ones are asserted by name so a page cannot lose its tag unnoticed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import pytest

from .test_site_repo_links import _build

ROOT = Path(__file__).resolve().parents[1]
SITE = "https://neuralbridge.io"
TITLE_MAX = 60
DESC_MIN, DESC_MAX = 120, 160
KNOWN_NOINDEX = {"/assurance", "/status", "/checkout/success", "/investigate"}

#: JSON-LD @type values any page may carry (top-level or nested): the layout graph and the docs breadcrumbs.
SITE_TYPES = {"Organization", "WebSite", "BreadcrumbList", "Person", "ContactPoint", "ListItem"}
#: Carried by the home page only, from app/lib/structured-offers.json, which tests/test_site_honesty.py pins to
#: billing/plans.py (price, currency and period). Nothing else may add to this set.
HOME_ONLY_TYPES = {"SoftwareApplication", "Product", "Brand", "Offer", "UnitPriceSpecification"}
#: Never, on any page: claims this site cannot source (CLAUDE.md: no reviews, ratings, awards, customers).
FORBIDDEN_TYPES = {"Review", "AggregateRating", "Rating", "AggregateOffer", "Award", "FAQPage", "Question", "Answer"}


# ---------------------------------------------------------------------------
# a small parser for the parts of a page the checks need
# ---------------------------------------------------------------------------
class Page(HTMLParser):
    def __init__(self, html: str):
        super().__init__(convert_charrefs=True)
        self.lang: str | None = None
        self.title = ""
        self.meta: dict[str, list[str]] = {}
        self.links: dict[str, list[str]] = {}
        self.h1 = 0
        self.jsonld: list[str] = []
        self.breadcrumb: list[str] = []
        self._in_title = False
        self._in_ld = False
        self._ld = ""
        self._in_crumb = 0
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.lang = a.get("lang")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            key = a.get("name") or a.get("property")
            if key and "content" in a:
                self.meta.setdefault(key, []).append(a["content"] or "")
        elif tag == "link" and a.get("rel") and a.get("href"):
            self.links.setdefault(a["rel"], []).append(a["href"])
        elif tag == "h1":
            self.h1 += 1
        elif tag == "script" and a.get("type") == "application/ld+json":
            self._in_ld, self._ld = True, ""
        elif tag == "nav" and a.get("aria-label") == "Breadcrumb":
            self._in_crumb = 1
        elif tag == "li" and self._in_crumb:
            self._crumb_text = ""

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_ld:
            self._in_ld = False
            self.jsonld.append(self._ld)
        elif tag == "nav" and self._in_crumb:
            self._in_crumb = 0
        elif tag == "li" and self._in_crumb:
            self.breadcrumb.append(getattr(self, "_crumb_text", "").strip())

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._in_ld:
            self._ld += data
        if self._in_crumb and hasattr(self, "_crumb_text"):
            self._crumb_text += data

    def one(self, key: str) -> str | None:
        vals = self.meta.get(key)
        return vals[0] if vals else None

    @property
    def noindex(self) -> bool:
        return any("noindex" in v.lower() for v in self.meta.get("robots", []))


def jsonld_nodes(page: Page) -> list[dict]:
    """Every top-level JSON-LD node, with a ``@graph`` flattened. Raises if any block is not valid JSON."""
    nodes: list[dict] = []
    for block in page.jsonld:
        data = json.loads(block)
        nodes.extend(data["@graph"] if isinstance(data, dict) and "@graph" in data else [data])
    return nodes


def all_types(node) -> set[str]:
    """Every @type at any depth of a JSON-LD value."""
    found: set[str] = set()
    if isinstance(node, dict):
        t = node.get("@type")
        found |= set(t) if isinstance(t, list) else {t} if t else set()
        for v in node.values():
            found |= all_types(v)
    elif isinstance(node, list):
        for v in node:
            found |= all_types(v)
    return found


# ---------------------------------------------------------------------------
# the checks, as functions over {route: html} so the mutation tests can feed them a broken site
# ---------------------------------------------------------------------------
def check_unique(pages: dict[str, Page], what: str, getter) -> list[str]:
    seen: dict[str, str] = {}
    problems = []
    for route, page in sorted(pages.items()):
        value = getter(page)
        if value in seen:
            problems.append(f"{route}: {what} duplicates {seen[value]}: {value!r}")
        seen.setdefault(value, route)
    return problems


def check_lengths(pages: dict[str, Page]) -> list[str]:
    problems = []
    for route, page in sorted(pages.items()):
        title = unescape(page.title).strip()
        desc = (page.one("description") or "").strip()
        if not title or len(title) > TITLE_MAX:
            problems.append(f"{route}: title is {len(title)} characters (max {TITLE_MAX}): {title!r}")
        if not DESC_MIN <= len(desc) <= DESC_MAX:
            problems.append(f"{route}: description is {len(desc)} characters (want {DESC_MIN}-{DESC_MAX})")
    return problems


def expected_canonical(route: str) -> str:
    return SITE if route == "/" else f"{SITE}{route}"


def check_social_and_canonical(pages: dict[str, Page]) -> list[str]:
    problems = []
    for route, page in sorted(pages.items()):
        canonical = (page.links.get("canonical") or [None])[0]
        if canonical != expected_canonical(route):
            problems.append(f"{route}: canonical is {canonical!r}, want {expected_canonical(route)!r}")
        if page.lang != "en":
            problems.append(f"{route}: <html lang> is {page.lang!r}")
        if not (page.one("viewport") or "").startswith("width=device-width"):
            problems.append(f"{route}: no responsive viewport meta")
        if page.h1 != 1:
            problems.append(f"{route}: {page.h1} <h1> elements, want exactly 1")
        og_url = page.one("og:url")
        if (og_url or "").rstrip("/") != expected_canonical(route).rstrip("/"):
            problems.append(f"{route}: og:url is {og_url!r}")
        if page.one("og:title") != unescape(page.title).strip():
            problems.append(f"{route}: og:title differs from <title>")
        if page.one("og:description") != page.one("description"):
            problems.append(f"{route}: og:description differs from the description")
        for key in ("og:image", "og:image:alt", "twitter:image", "twitter:title", "twitter:description"):
            if not page.one(key):
                problems.append(f"{route}: missing {key}")
        if page.one("twitter:card") != "summary_large_image":
            problems.append(f"{route}: twitter:card is {page.one('twitter:card')!r}")
        if not (page.one("og:image") or "").startswith(f"{SITE}/"):
            problems.append(f"{route}: og:image is not an absolute {SITE} URL")
    return problems


def check_structured_data(pages: dict[str, Page]) -> list[str]:
    problems = []
    for route, page in sorted(pages.items()):
        try:
            nodes = jsonld_nodes(page)
        except json.JSONDecodeError as exc:
            problems.append(f"{route}: JSON-LD does not parse: {exc}")
            continue
        top = [n.get("@type") for n in nodes]
        for n in nodes:
            types = all_types(n)
            # FAQ structured data is allowed on /product/* only: those pages show the same
            # questions in the visible text, which tests/test_site_product_pages.py checks equal.
            forbidden = FORBIDDEN_TYPES - ({"FAQPage", "Question", "Answer"} if route.startswith("/product/") else set())
            bad = types & forbidden
            if bad:
                problems.append(f"{route}: forbidden JSON-LD type(s) {sorted(bad)}")
            allowed = set(SITE_TYPES)
            if route.startswith("/product/"):
                allowed |= {"FAQPage", "Question", "Answer"}
            if route == "/" and n.get("@type") in {"SoftwareApplication", "Product"}:
                allowed |= HOME_ONLY_TYPES
            extra = types - allowed - forbidden
            if extra:
                problems.append(f"{route}: JSON-LD type(s) {sorted(extra)} not allowed on this page")
            if "potentialAction" in json.dumps(n) and n.get("@type") == "WebSite":
                problems.append(f"{route}: WebSite claims a potentialAction but the site has no search results page")
        if top.count("Organization") != 1 or top.count("WebSite") != 1:
            problems.append(f"{route}: want exactly one Organization and one WebSite, got {top}")
        crumbs = [n for n in nodes if n.get("@type") == "BreadcrumbList"]
        # Pages that show a breadcrumb trail (and so may carry the matching BreadcrumbList):
        # the docs, and the /product pages. The category page is itself the end of its trail.
        is_docs = route == "/docs" or route.startswith("/docs/")
        is_product = route.startswith("/product/")
        trail_root = "Docs" if is_docs else "Product"
        has_trail = is_docs or is_product
        if has_trail and len(crumbs) != 1:
            problems.append(f"{route}: page with a breadcrumb trail does not have exactly one BreadcrumbList")
        if not has_trail and crumbs:
            problems.append(f"{route}: BreadcrumbList on a page that shows no breadcrumb")
        if has_trail and len(crumbs) == 1:
            names = [i["name"] for i in crumbs[0]["itemListElement"]]
            urls = [i["item"] for i in crumbs[0]["itemListElement"]]
            if names[:2] != ["Home", trail_root] or urls[-1] != expected_canonical(route):
                problems.append(f"{route}: breadcrumb trail {names} / {urls}")
            if page.breadcrumb != names:
                problems.append(f"{route}: JSON-LD breadcrumb {names} is not the visible trail {page.breadcrumb}")
    return problems


def parse_robots(text: str) -> dict:
    out = {"allow": [], "disallow": [], "sitemap": []}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key in out:
            out[key].append(value.strip())
    return out


def check_robots_and_sitemap(pages: dict[str, Page], sitemap_paths: set[str], robots_txt: str) -> list[str]:
    problems = []
    robots = parse_robots(robots_txt)
    if f"{SITE}/sitemap.xml" not in robots["sitemap"]:
        problems.append(f"robots.txt does not declare {SITE}/sitemap.xml: {robots['sitemap']}")
    for route in sorted(sitemap_paths):
        for rule in robots["disallow"]:
            if rule and route.startswith(rule):
                problems.append(f"robots.txt disallows {rule!r} but the sitemap lists {route}")
    for route, page in sorted(pages.items()):
        if page.noindex and route in sitemap_paths:
            problems.append(f"{route}: noindex but listed in the sitemap")
        if not page.noindex and route not in sitemap_paths and route != "/404":
            problems.append(f"{route}: indexable page missing from the sitemap")
    for route in sitemap_paths - set(pages):
        problems.append(f"sitemap lists {route}, which has no built page")
    return problems


# ---------------------------------------------------------------------------
# the build
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def dist():
    env = os.environ.get("SITE_SEO_DIST")
    if env:
        path = (ROOT / env).resolve()
        if not (path / "server" / "app" / "index.html").exists():
            pytest.skip(f"SITE_SEO_DIST={env} holds no next build output")
        yield path
        return
    path = _build(None, ".next-repo-seo")
    yield path
    shutil.rmtree(path, ignore_errors=True)


def _route_of(file: Path, base: Path) -> str:
    rel = file.relative_to(base).with_suffix("").as_posix()
    return "/" if rel == "index" else f"/{rel}"


@pytest.fixture(scope="module")
def site(dist):
    base = dist / "server" / "app"
    pages: dict[str, Page] = {}
    for file in sorted(base.rglob("*.html")):
        route = _route_of(file, base)
        if route in {"/_not-found", "/_global-error"}:
            continue
        pages[route] = Page(file.read_text(encoding="utf-8"))
    sitemap_xml = (base / "sitemap.xml.body").read_text(encoding="utf-8")
    sitemap = {urlparse(u).path or "/" for u in re.findall(r"<loc>([^<]+)</loc>", sitemap_xml)}
    robots = (base / "robots.txt.body").read_text(encoding="utf-8")
    not_found = Page((base / "_not-found.html").read_text(encoding="utf-8"))
    return {"pages": pages, "sitemap": sitemap, "robots": robots, "not_found": not_found, "base": base}


@pytest.fixture(scope="module")
def indexable(site):
    return {r: p for r, p in site["pages"].items() if not p.noindex}


# ---------------------------------------------------------------------------
# 1. what the built pages say
# ---------------------------------------------------------------------------
class TestBuiltPages:
    def test_the_build_has_the_pages_this_test_is_about(self, site, indexable):
        assert len(indexable) >= 30, sorted(indexable)
        assert {"/", "/docs", "/privacy", "/solutions/manufacturer"} <= set(indexable)

    def test_titles_are_present_unique_and_at_most_60_characters(self, indexable):
        problems = [x for x in check_lengths(indexable) if "title" in x]
        problems += check_unique(indexable, "title", lambda p: unescape(p.title).strip())
        assert problems == []

    def test_descriptions_are_unique_and_120_to_160_characters(self, indexable):
        problems = [x for x in check_lengths(indexable) if "description" in x]
        problems += check_unique(indexable, "description", lambda p: p.one("description"))
        assert problems == []

    def test_canonical_language_viewport_one_h1_and_social_tags(self, indexable):
        assert check_social_and_canonical(indexable) == []

    def test_no_canonical_has_a_trailing_slash_or_a_query(self, indexable):
        for route, page in indexable.items():
            canonical = page.links["canonical"][0]
            assert "?" not in canonical and "#" not in canonical, route
            assert route == "/" or not canonical.endswith("/"), route

    def test_noindex_pages_keep_their_tag_and_are_not_in_the_sitemap(self, site):
        pages = site["pages"]
        for route in KNOWN_NOINDEX:
            assert pages[route].noindex, f"{route} lost its noindex robots tag"
            assert route not in site["sitemap"], f"{route} is noindex but in the sitemap"

    def test_noindex_pages_are_still_well_formed(self, site):
        # a noindex page still renders social tags and a lang attribute; only the h1 is exempt (the checkout page
        # renders its heading on the client, after the Stripe return).
        for route in KNOWN_NOINDEX:
            page = site["pages"][route]
            assert page.lang == "en" and page.one("og:image") and page.links.get("canonical"), route


# ---------------------------------------------------------------------------
# 2. structured data
# ---------------------------------------------------------------------------
class TestStructuredData:
    def test_every_page_parses_and_carries_only_allowed_types(self, site):
        assert check_structured_data(site["pages"]) == []

    def test_the_site_graph_is_organization_and_website_with_a_contact_point(self, site):
        nodes = {n["@type"]: n for n in jsonld_nodes(site["pages"]["/privacy"])}
        org, web = nodes["Organization"], nodes["WebSite"]
        assert org["name"] == web["name"] == "Industrial Autonomous Assurance"
        assert org["contactPoint"]["url"] == f"{SITE}/contact"
        assert web["publisher"] == {"@id": org["@id"]}
        assert "potentialAction" not in web  # no search results page exists to point one at
        assert "logo" not in org  # no logo asset exists; the favicon is not a logo

    def test_only_the_home_page_carries_offer_types(self, site):
        for route, page in site["pages"].items():
            types = set().union(*(all_types(n) for n in jsonld_nodes(page)))
            if route != "/":
                assert not types & {"Offer", "Product", "SoftwareApplication", "UnitPriceSpecification"}, route

    def test_repository_urls_stay_out_of_the_graph(self, site):
        # the default build has REPO_PUBLIC off: test_site_repo_links.py owns the on/off pair, this pins the default
        for page in site["pages"].values():
            assert "sameAs" not in json.dumps(jsonld_nodes(page))


# ---------------------------------------------------------------------------
# 3. robots.txt, sitemap, 404, headers
# ---------------------------------------------------------------------------
class TestCrawlerFiles:
    def test_robots_declares_the_sitemap_and_blocks_no_listed_page(self, site):
        assert check_robots_and_sitemap(site["pages"], site["sitemap"], site["robots"]) == []

    def test_robots_blocks_the_account_and_transaction_pages_only(self, site):
        robots = parse_robots(site["robots"])
        assert robots["allow"] == ["/"]
        for path in ("/assurance", "/checkout/", "/status"):
            assert path in robots["disallow"]
        assert not [d for d in robots["disallow"] if d.startswith(("/docs", "/solutions", "/developers", "/privacy"))]

    def test_the_404_page_is_noindex_has_no_canonical_and_links_somewhere(self, site):
        page = site["not_found"]
        assert page.noindex
        assert not page.links.get("canonical")
        assert page.h1 == 1 and page.lang == "en"
        html = (site["base"] / "_not-found.html").read_text(encoding="utf-8")
        for href in ('href="/docs"', 'href="/contact"', 'href="/"'):
            assert href in html


class TestResponseHeaders:
    @staticmethod
    def _headers():
        node = shutil.which("node")
        if not node:
            pytest.skip("node is not installed")
        done = subprocess.run(  # noqa: S603 - fixed argv
            [node, "-e", "require('./next.config.js').headers().then(h => console.log(JSON.stringify(h)))"],
            cwd=ROOT, capture_output=True, text=True, check=True, timeout=60,
        )
        return json.loads(done.stdout)

    def test_security_headers_are_set_on_every_route(self):
        rules = {r["source"]: {h["key"]: h["value"] for h in r["headers"]} for r in self._headers()}
        site_wide = rules["/:path*"]
        assert site_wide["X-Content-Type-Options"] == "nosniff"
        assert site_wide["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert site_wide["X-Frame-Options"] == "DENY"
        assert site_wide["Content-Security-Policy"] == "frame-ancestors 'none'"
        assert "camera=()" in site_wide["Permissions-Policy"]

    def test_no_script_policy_is_claimed(self):
        # A script-src/default-src policy must be verified against Next's inline bootstrap scripts and the inline
        # JSON-LD in a real browser first; until then only frame-ancestors is set.
        for rule in self._headers():
            for h in rule["headers"]:
                if h["key"] == "Content-Security-Policy":
                    assert "script-src" not in h["value"] and "default-src" not in h["value"]

    def test_the_repo_public_define_and_dist_dir_are_untouched(self):
        config = (ROOT / "next.config.js").read_text(encoding="utf-8")
        assert "process.env.NEXT_DIST_DIR || '.next'" in config
        assert "NEXT_PUBLIC_REPO_PUBLIC: process.env.NEXT_PUBLIC_REPO_PUBLIC === 'true' ? 'true' : 'false'" in config


# ---------------------------------------------------------------------------
# 4. the checks can fail: each mutation breaks one rule on a copy and must be caught
# ---------------------------------------------------------------------------
def _copy(page: Page, **changes) -> Page:
    clone = Page("")
    clone.__dict__.update({k: (v.copy() if hasattr(v, "copy") else v) for k, v in page.__dict__.items()})
    clone.__dict__.update(changes)
    return clone


class TestMutations:
    def test_a_duplicated_title_is_caught(self, indexable):
        pages = dict(indexable)
        pages["/cli"] = _copy(pages["/cli"], title=pages["/privacy"].title)
        problems = check_unique(pages, "title", lambda p: unescape(p.title).strip())
        assert any("/privacy" in p and "duplicates" in p for p in problems), problems

    def test_a_too_long_title_and_a_too_short_description_are_caught(self, indexable):
        pages = dict(indexable)
        pages["/cli"] = _copy(pages["/cli"], title="x" * 61)
        broken = _copy(pages["/privacy"])
        broken.meta = {**broken.meta, "description": ["too short"]}
        pages["/privacy"] = broken
        problems = check_lengths(pages)
        assert any(p.startswith("/cli") and "title" in p for p in problems)
        assert any(p.startswith("/privacy") and "description" in p for p in problems)

    def test_an_offer_added_to_the_json_ld_is_caught(self, indexable):
        pages = dict(indexable)
        page = pages["/privacy"]
        offer = {"@context": "https://schema.org", "@type": "Product", "name": "Register",
                 "offers": {"@type": "Offer", "price": "390", "priceCurrency": "EUR"}}
        pages["/privacy"] = _copy(page, jsonld=[*page.jsonld, json.dumps(offer)])
        problems = check_structured_data(pages)
        assert any(p.startswith("/privacy") and "Offer" in p for p in problems), problems

    def test_a_rating_or_a_faq_page_is_caught_even_on_the_home_page(self, indexable):
        pages = dict(indexable)
        rating = {"@type": "SoftwareApplication", "name": "x", "aggregateRating": {"@type": "AggregateRating", "ratingValue": "5"}}
        pages["/"] = _copy(pages["/"], jsonld=[*pages["/"].jsonld, json.dumps(rating)])
        faq = {"@type": "FAQPage", "mainEntity": []}
        pages["/cli"] = _copy(pages["/cli"], jsonld=[*pages["/cli"].jsonld, json.dumps(faq)])
        problems = check_structured_data(pages)
        assert any(p.startswith("/: forbidden") and "AggregateRating" in p for p in problems), problems
        assert any(p.startswith("/cli") and "FAQPage" in p for p in problems), problems

    def test_a_search_action_without_a_search_page_is_caught(self, indexable):
        pages = dict(indexable)
        graph = json.loads(pages["/privacy"].jsonld[0])
        for node in graph["@graph"]:
            if node["@type"] == "WebSite":
                node["potentialAction"] = {"@type": "SearchAction", "target": f"{SITE}/search?q={{q}}"}
        pages["/privacy"] = _copy(pages["/privacy"], jsonld=[json.dumps(graph)])
        assert any("potentialAction" in p for p in check_structured_data(pages))

    def test_invalid_json_ld_is_caught(self, indexable):
        pages = dict(indexable)
        pages["/cli"] = _copy(pages["/cli"], jsonld=["{not json"])
        assert any("does not parse" in p for p in check_structured_data(pages))

    def test_a_missing_og_image_a_second_h1_and_a_wrong_canonical_are_caught(self, indexable):
        pages = dict(indexable)
        no_img = _copy(pages["/cli"])
        no_img.meta = {k: v for k, v in no_img.meta.items() if k != "og:image"}
        pages["/cli"] = no_img
        pages["/privacy"] = _copy(pages["/privacy"], h1=2)
        pages["/contact"] = _copy(pages["/contact"], links={"canonical": [f"{SITE}/contact/"]})
        problems = check_social_and_canonical(pages)
        assert any(p.startswith("/cli") and "og:image" in p for p in problems)
        assert any(p.startswith("/privacy") and "<h1>" in p for p in problems)
        assert any(p.startswith("/contact") and "canonical" in p for p in problems)

    def test_listing_a_noindex_page_in_the_sitemap_or_blocking_a_listed_page_is_caught(self, site):
        pages, sitemap, robots = site["pages"], set(site["sitemap"]), site["robots"]
        assert any("noindex but listed" in p for p in check_robots_and_sitemap(pages, sitemap | {"/assurance"}, robots))
        blocked = robots + "Disallow: /docs\n"
        assert any("disallows '/docs'" in p for p in check_robots_and_sitemap(pages, sitemap, blocked))
        no_map = "\n".join(line for line in robots.splitlines() if not line.lower().startswith("sitemap"))
        assert any("does not declare" in p for p in check_robots_and_sitemap(pages, sitemap, no_map))
        assert any("missing from the sitemap" in p for p in check_robots_and_sitemap(pages, sitemap - {"/cli"}, robots))
