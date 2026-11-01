"""The website's capability pages are generated from the code, and a test fails when they are not.

``src/assurance/capabilities.py`` declares which of the CLI, the HTTP API and the MCP server offers
each capability, and checks the declaration against the real surfaces. ``public/capabilities.json``
is that catalogue exported for the website (``scripts/export_capabilities.py``), and
``/docs/capabilities`` renders it. Same pattern as the OpenAPI snapshot: the committed file must be
exactly what the code produces now, every capability id the site names must exist, and the lists
and counts the site states must be the ones in the file instead of a second hand-typed copy.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest

from assurance import capabilities as catalogue
from assurance.api.service import app

from .test_site_honesty import _node

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "public" / "capabilities.json"
METHODS = {"get", "post", "put", "patch", "delete"}


def _text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _exporter():
    spec = importlib.util.spec_from_file_location("export_capabilities", ROOT / "scripts" / "export_capabilities.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def _norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def _app_sources() -> list[Path]:
    return [p for p in (ROOT / "app").rglob("*") if p.suffix in (".ts", ".tsx")]


# ---------------------------------------------------------------------------
# the committed file is what the code produces
# ---------------------------------------------------------------------------
class TestTheContractIsNotStale:
    def test_the_committed_file_is_what_the_code_exports_now(self):
        fresh = _exporter().render()
        assert CONTRACT.read_text(encoding="utf-8") == fresh, \
            "public/capabilities.json is stale: run `python scripts/export_capabilities.py`"

    def test_the_export_is_deterministic(self):
        exporter = _exporter()
        assert exporter.render() == exporter.render()

    def test_capabilities_are_sorted_by_id_and_ids_are_unique(self):
        ids = [c["id"] for c in _contract()["capabilities"]]
        assert ids == sorted(ids) and len(ids) == len(set(ids))

    def test_it_holds_every_capability_the_code_declares(self):
        assert {c["id"] for c in _contract()["capabilities"]} == {c.id for c in catalogue.CAPABILITIES}

    def test_a_surface_is_available_or_says_which_kind_of_gap_and_why(self):
        for cap in _contract()["capabilities"]:
            assert set(cap["surfaces"]) == {"cli", "api", "mcp"}, cap["id"]
            for surface, cell in cap["surfaces"].items():
                if cell["status"] == "available":
                    assert cell["names"], (cap["id"], surface)
                    assert "reason" not in cell
                else:
                    assert cell["status"] in ("by_design", "planned"), (cap["id"], surface, cell)
                    assert cell["reason"].strip(), (cap["id"], surface)
                    assert "names" not in cell

    def test_the_file_carries_no_clock(self):
        text = CONTRACT.read_text(encoding="utf-8")
        assert not re.search(r"\b20\d\d-\d\d-\d\d\b|generated_at|timestamp", text)

    def test_the_counts_are_the_surfaces_the_code_discovers(self):
        found = catalogue.discover(app)
        counts = _contract()["counts"]
        assert counts["cli_commands"] == len(found["cli"])
        assert counts["api_routes"] == len(found["api"])
        assert counts["mcp_tools"] == len(found["mcp"]) == len(_contract()["mcp_tools"])
        assert counts["capabilities"] == len(catalogue.CAPABILITIES)
        assert counts["cli_domains"] == len({c.split()[0] for c in found["cli"]}) == len(_contract()["cli_domains"])
        for surface in ("cli", "api", "mcp"):
            cells = [c["surfaces"][surface]["status"] for c in _contract()["capabilities"]]
            expected = {k: cells.count(k) for k in ("available", "by_design", "planned")}
            assert counts["surfaces"][surface] == expected, surface


# ---------------------------------------------------------------------------
# every capability id the site shows exists
# ---------------------------------------------------------------------------
class TestCapabilityIdsOnTheSiteExist:
    ID = re.compile(r"""['"`]([a-z0-9_]+\.[a-z0-9_]+)['"`]""")

    def test_every_id_in_the_site_data_is_in_the_catalogue(self):
        ids = {c["id"] for c in _contract()["capabilities"]}
        shown = set(self.ID.findall(_text("app/lib/siteCapabilities.ts")))
        assert shown, "app/lib/siteCapabilities.ts names no capability: the featured list is empty"
        unknown = sorted(shown - ids)
        assert not unknown, f"capability ids on the site that the catalogue does not have: {unknown}"

    def test_every_featured_group_names_at_least_one_capability_and_says_something(self):
        source = _text("app/lib/siteCapabilities.ts")
        featured = source[source.index("export const FEATURED"):]
        groups = re.findall(r"title: '([^']+)',\s*note:\s*'([^']{40,})',\s*ids: \[([^\]]+)\]", featured, re.S)
        assert len(groups) >= 5
        for title, _note, ids in groups:
            assert self.ID.findall(ids), title

    def test_an_anchor_into_the_capabilities_page_points_at_a_service_or_a_capability(self):
        contract = _contract()
        ids = {c["id"] for c in contract["capabilities"]}
        services = {c["service"] for c in contract["capabilities"]}
        for path in [*_app_sources(), ROOT / "public" / "llms.txt"]:
            for frag in re.findall(r"/docs/capabilities#([A-Za-z0-9_.-]+)", path.read_text(encoding="utf-8")):
                kind, _, name = frag.partition("-")
                assert (kind == "service" and name in services) or (kind == "cap" and name in ids), \
                    f"{path.relative_to(ROOT)}: #{frag} is not a service or capability anchor"

    def test_every_service_has_a_title_on_the_page(self):
        source = _text("app/lib/siteCapabilities.ts")
        block = source[source.index("SERVICE_TITLE"):source.index("export interface FeaturedGroup")]
        titled = set(re.findall(r"^\s+(\w+): '", block, re.M))
        assert titled == {c["service"] for c in _contract()["capabilities"]}

    def test_the_page_labels_are_exactly_the_three_the_contract_uses(self):
        source = _text("app/lib/siteCapabilities.ts")
        block = source[source.index("export const STATUS_LABEL"):]
        block = block[:block.index("};")]
        assert set(re.findall(r"^\s+(\w+): '", block, re.M)) == {"available", "planned", "by_design"}

    def test_the_page_renders_the_json_and_types_no_row_of_its_own(self):
        page = _text("app/docs/capabilities/page.tsx")
        assert "siteCapabilities" in page and "CAPABILITIES.filter" in page
        assert "../../public/capabilities.json" in _text("app/lib/siteCapabilities.ts")
        assert "method: '" not in page, "a route row typed into the page instead of read from the contract"


# ---------------------------------------------------------------------------
# lists and counts the site states are the contract's
# ---------------------------------------------------------------------------
class TestSiteListsAreDerivedFromTheContract:
    def test_the_cli_page_lists_every_domain_and_verb_the_cli_has(self):
        ts = _text("app/lib/routes.ts")
        site: dict[str, list[str]] = {}
        for domain, verbs in re.findall(r"\{ domain: '([\w-]+)', verbs: \[([^\]]*)\]", ts):
            site[domain] = re.findall(r"'([\w-]+)'", verbs)
        assert {d: sorted(v) for d, v in site.items()} == _contract()["cli_domains"]

    def test_the_mcp_page_lists_every_tool_the_server_registers(self):
        page = _text("app/connectors/mcp/page.tsx")
        assert sorted(re.findall(r"name: '(\w+)', route", page)) == _contract()["mcp_tools"]

    def test_the_developers_table_lists_every_route_except_the_account_plane(self):
        listed = {(m.upper(), _norm(p)) for m, p in
                  re.findall(r"\{ method: '(\w+)', path: '([^']+)'", _text("app/lib/routes.ts"))}
        account = {(n.split()[0], _norm(n.split()[1])) for c in catalogue.CAPABILITIES
                   if c.service == "account" for n in c.api}
        served = {(k.split()[0], _norm(k.split()[1])) for k in catalogue.discover(app)["api"]}
        missing = sorted(f"{m} {p}" for m, p in served - listed - account)
        assert not missing, f"served routes missing from app/lib/routes.ts: {missing}"

    def test_the_committed_openapi_has_the_routes_the_contract_counts(self):
        openapi = json.loads(_text("public/openapi.json"))
        routes = sum(1 for path, item in openapi["paths"].items() if path.startswith("/v1/")
                     for m in item if m in METHODS)
        assert routes == _contract()["counts"]["api_routes"]
        assert "path.startsWith('/v1/')" in _text("app/developers/page.tsx")

    def test_a_route_with_no_mcp_tool_is_labelled_from_the_catalogue(self):
        page = _text("app/connectors/mcp/page.tsx")
        assert "mcpCellForRoute" in page and "Not yet a tool" not in page

    # A count typed next to its noun is allowed only if it is a number the contract holds.
    NOUN = re.compile(
        r"\b(\d[\d,]*|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|"
        r"fifteen|sixteen|seventeen|eighteen|nineteen|twenty)\s+(?:(?:HTTP|MCP|CLI|read-only)\s+)*"
        r"(tools|routes|domains|commands|capabilities)\b", re.I)

    def test_no_count_of_tools_routes_domains_commands_or_capabilities_is_typed_wrongly(self):
        counts = _contract()["counts"]
        allowed = {"tools": counts["mcp_tools"], "routes": counts["api_routes"],
                   "domains": counts["cli_domains"], "commands": counts["cli_commands"],
                   "capabilities": counts["capabilities"]}
        files = [*_app_sources(), ROOT / "public" / "llms.txt", ROOT / "docs" / "assurance" / "index.md"]
        bad = []
        for path in files:
            for number, noun in self.NOUN.findall(path.read_text(encoding="utf-8")):
                if not number.isdigit() or int(number.replace(",", "")) != allowed[noun.lower()]:
                    bad.append(f"{path.relative_to(ROOT)}: {number} {noun} (the contract has {allowed[noun.lower()]})")
        assert not bad, "\n".join(bad)

    def test_llms_txt_states_the_contract_counts(self):
        counts = _contract()["counts"]
        text = " ".join(_text("public/llms.txt").split())
        for phrase in (f"{counts['capabilities']} capabilities", f"{counts['api_routes']} HTTP routes",
                       f"{counts['cli_commands']} CLI commands", f"{counts['cli_domains']} domains",
                       f"{counts['mcp_tools']} MCP tools"):
            assert phrase in text, phrase

    def test_the_four_intel_tools_are_four(self):
        intel = [t for t in _contract()["mcp_tools"] if t.startswith("intel_")]
        assert len(intel) == 4
        assert "four `intel_*` MCP tools" in " ".join(_text("public/llms.txt").split())


# ---------------------------------------------------------------------------
# what the site says about the intel layer and the new capabilities
# ---------------------------------------------------------------------------
class TestWhatTheSiteSaysAboutIntel:
    @pytest.mark.parametrize("relative", [
        "app/docs/capabilities/page.tsx", "app/developers/page.tsx", "app/connectors/mcp/page.tsx",
        "app/cli/page.tsx", "app/status/page.tsx", "public/llms.txt", "README.md",
        "app/lib/siteCapabilities.ts",
    ])
    def test_the_unconfigured_store_is_a_503_and_fetching_is_an_operator_act(self, relative):
        text = " ".join(_text(relative).split())
        assert "ASSURANCE_INTEL_STORE" in text and "503" in text, relative

    @pytest.mark.parametrize("relative", [
        "app/docs/capabilities/page.tsx", "app/cli/page.tsx", "public/llms.txt", "README.md",
        "app/lib/siteCapabilities.ts",
    ])
    def test_fetching_a_feed_is_said_to_be_an_operator_act(self, relative):
        text = " ".join(_text(relative).split()).lower()
        assert "operator" in text and ("refresh --live" in text or "fetching" in text), relative

    def test_the_intel_capabilities_in_the_catalogue_say_the_same(self):
        by_id = {c["id"]: c for c in _contract()["capabilities"]}
        for cid in ("intel.ingest", "intel.refresh"):
            for surface in ("api", "mcp"):
                assert by_id[cid]["surfaces"][surface]["status"] == "by_design", (cid, surface)
        for cid in ("intel.history", "intel.show", "intel.candidates"):
            assert by_id[cid]["surfaces"]["cli"]["status"] == "available"
            assert by_id[cid]["surfaces"]["api"]["status"] == "available"
            assert by_id[cid]["surfaces"]["mcp"]["status"] == "available"

    def test_enrolment_and_the_case_decisions_have_no_mcp_tool_by_design(self):
        by_id = {c["id"]: c for c in _contract()["capabilities"]}
        for cid in ("machinery.enrol", "machinery.amend_enrolment", "change.decide", "change.resume",
                    "watch.open_case", "art14.awareness"):
            assert by_id[cid]["surfaces"]["mcp"]["status"] == "by_design", cid

    def test_the_new_pages_claim_none_of_the_things_this_repository_cannot_support(self):
        banned = re.compile(
            r"\b(customers?|pilots?|revenue|valuation|market (?:leader|share|position|size)|dominan\w*|"
            r"industry[- ]leading|world[- ]class|best[- ]in[- ]class|certified|certification|"
            r"guarantee[sd]?|trusted by|compliant with)\b", re.I)
        for relative in ("app/docs/capabilities/page.tsx", "app/lib/siteCapabilities.ts",
                         "app/components/DocsSidebar.tsx", "docs/assurance/index.md"):
            hit = banned.search(_text(relative))
            assert hit is None, f"{relative}: {hit.group(0)!r}"

    def test_the_status_page_still_says_nothing_is_deployed_and_the_key_ceremony_is_not_done(self):
        text = " ".join(_text("app/status/page.tsx").split())
        assert "Prepared, not performed" in text
        assert "No production key exists" in text
        assert "done: true" not in text


# ---------------------------------------------------------------------------
# docs: the new engine guides render, and every internal link resolves
# ---------------------------------------------------------------------------
class TestDocsPagesAndLinks:
    def test_the_new_engine_guides_are_registered(self):
        docs = _text("app/lib/docs.ts")
        for source in ("CHANGE.md", "INTEL.md", "PIPELINE.md", "KEY-CEREMONY.md", "TRUST-RUNBOOK.md"):
            assert f"deploy/assurance/{source}" in docs, source
            assert (ROOT / "deploy" / "assurance" / source).exists()

    def test_every_declared_source_exists_so_no_nav_link_answers_not_found(self):
        docs = _text("app/lib/docs.ts")
        sources = re.findall(r"source: '([^']+)'", docs)
        assert len(sources) >= 15
        assert [s for s in sources if not (ROOT / s).exists()] == []

    def test_every_docs_nav_entry_is_a_rendered_page(self):
        out = _node("""
          const m = await import('./app/lib/docs.ts');
          const rendered = new Set(m.listDocSlugs().map(({ slug }) => '/docs/' + slug.join('/')));
          const hrefs = m.DOCS_NAV.flatMap((i) => [i.href, ...(i.children ?? []).map((c) => c.href)]);
          process.stdout.write(JSON.stringify({ hrefs, rendered: [...rendered] }));
        """, stub_marked=True)
        # /docs is the landing and /docs/capabilities is its own route (app/docs/capabilities/page.tsx)
        own = {"/docs", "/docs/capabilities"}
        missing = [h for h in out["hrefs"] if h not in own and h not in out["rendered"]]
        assert missing == [], f"DOCS_NAV links that would answer not-found: {missing}"
        assert "/docs/capabilities" in out["hrefs"]
        assert (ROOT / "app" / "docs" / "capabilities" / "page.tsx").exists()

    def test_the_sitemap_and_the_search_index_list_the_capabilities_page(self):
        assert "/docs/capabilities" in _text("app/sitemap.ts")
        assert "href: '/docs/capabilities'" in _text("app/lib/search-index.ts")
        assert "https://neuralbridge.io/docs/capabilities" in _text("public/llms.txt")
        assert "https://neuralbridge.io/capabilities.json" in _text("public/llms.txt")

    def test_no_rendered_guide_keeps_a_relative_markdown_link_that_was_not_rewritten(self):
        out = _node("""
          import fs from 'node:fs';
          const m = await import('./app/lib/docs.ts');
          const left = [];
          for (const { slug } of m.listDocSlugs()) {
            const d = m.loadDoc(slug);
            const raw = fs.readFileSync(d.editPath, 'utf-8');
            for (const link of m.rewriteLinks(raw).matchAll(/\\]\\(([^)\\s]+)\\)/g)) {
              const target = link[1];
              if (/^(https?:|mailto:|#|\\/)/.test(target)) continue;
              left.push(slug.join('/') + ' -> ' + target);
            }
          }
          process.stdout.write(JSON.stringify(left));
        """, stub_marked=True)
        assert out == [], f"relative links that resolve to nothing on the site: {out}"

    def test_the_link_rewrites_cover_every_guide_by_both_names(self):
        out = _node("""
          const m = await import('./app/lib/docs.ts');
          process.stdout.write(JSON.stringify([
            m.rewriteLinks('[a](KEY-CEREMONY.md)'), m.rewriteLinks('[b](key-ceremony.md)'),
            m.rewriteLinks('[c](assurance/pipeline.md)'), m.rewriteLinks('[d](assurance/deploy.md)'),
          ]));
        """, stub_marked=True)
        assert out == ["[a](/docs/assurance/key-ceremony)", "[b](/docs/assurance/key-ceremony)",
                       "[c](/docs/assurance/pipeline)", "[d](/docs/assurance/deploy)"]

    def test_the_mkdocs_includes_point_at_files_that_exist(self):
        for page in (ROOT / "docs" / "assurance").glob("*.md"):
            for target in re.findall(r'--8<-- "([^"]+)"', page.read_text(encoding="utf-8")):
                assert (ROOT / target).exists(), f"{page.relative_to(ROOT)} includes missing {target}"


class TestDescriptionsSkipDiagrams:
    def test_an_arrow_chain_in_capitals_is_not_a_description_but_prose_with_an_arrow_still_is(self):
        sample = ("# Title\n\nA -> B -> C IN CAPITALS ONLY.\n\n"
                  "Move a case from OPEN -> IN_REVIEW by claiming it, which names an owner and an actor.\n")
        out = _node("const m = await import('./app/lib/docDescription.ts');"
                    f"process.stdout.write(JSON.stringify(m.firstParagraph({json.dumps(sample)})));")
        assert out.startswith("Move a case from OPEN") or out == ""
        assert "CAPITALS" not in out

    def test_change_md_gets_a_description_from_its_prose(self):
        out = _node("""
          const m = await import('./app/lib/docs.ts');
          process.stdout.write(JSON.stringify(m.loadDoc(['assurance', 'change']).description));
        """, stub_marked=True)
        assert out and ">" not in out and not out.startswith("OBSERVATION")
