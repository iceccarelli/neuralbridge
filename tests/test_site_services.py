"""The services catalogue, the trust page and the get-started path say only what the code and docs hold.

``app/lib/services.ts`` is data with no imports, so this module runs it under Node (type stripping) and checks
the words against the capability contract (``public/capabilities.json``) and the code the trust page cites.
The rules that matter most are negative: the catalogue offers no capacity, SLA, certification or price, and
every product capability it calls available is one the contract lists as available.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "public" / "capabilities.json").read_text(encoding="utf-8"))
CAPS = {c["id"]: c for c in CONTRACT["capabilities"]}


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _node(script: str) -> object:
    node = shutil.which("node")
    assert node, "node is not installed; this module reads app/lib/services.ts with it"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is a constant in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def catalogue() -> dict:
    return _node(
        "const m = await import('./app/lib/services.ts');"
        "process.stdout.write(JSON.stringify({services: m.SERVICES, disclaimer: m.SERVICES_DISCLAIMER}));"
    )


@pytest.fixture(scope="module")
def services(catalogue) -> list[dict]:
    return catalogue["services"]


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


FIELDS = ["customer", "problem", "inputs", "deliverables", "exclusions", "prerequisites",
          "responsibilities", "evidence", "automated", "review", "support", "verifiable", "today", "gap"]
EXPECTED = ["Industrial software and machine-evidence baseline", "Machine enrolment and assurance implementation",
            "CRA Article 14 workflow configuration", "Machinery Regulation Annex III evidence workflow",
            "Supplier advisory and fleet-impact integration", "NeuralBridge platform and API integration",
            "Operator onboarding and training", "Ongoing assurance and evidence operations"]


class TestCatalogueShape:
    def test_exactly_the_eight_services_in_order(self, services):
        assert [s["name"] for s in services] == EXPECTED
        assert len({s["id"] for s in services}) == len(services)

    def test_every_service_answers_every_question(self, services):
        for s in services:
            for field in FIELDS:
                value = s[field]
                assert value and all(isinstance(x, str) and len(x) > 20 for x in ([value] if isinstance(value, str) else value)), (
                    s["id"], field)

    def test_every_service_names_what_is_excluded_and_what_needs_building(self, services):
        for s in services:
            assert len(s["exclusions"]) >= 2, s["id"]
            assert s["availability"] in {"available", "partial", "gap"}

    def test_no_package_price_hours_or_team_is_implied(self, services):
        for text in _strings(services):
            assert not re.search(r"\b\d+\s*(?:hours?|days?|weeks?|person-days?)\b|\bour (?:team|engineers|consultants)\b|\bpackage\b", text, re.I), text

    def test_the_annex_iii_entry_states_the_regulatory_date_and_denies_compliance(self, services):
        (annex,) = [s for s in services if s["id"] == "machinery-annex-iii"]
        text = " ".join(_strings(annex))
        assert "20 January 2027" in text and "2023/1230" in text
        assert re.search(r"No statement that a machine is compliant, certified or safe", text)

    def test_the_disclaimer_denies_capacity_sla_certification_price_and_separates_entitlements(self, catalogue):
        text = " ".join(catalogue["disclaimer"])
        for word in ("delivery team", "capacity", "SLA", "certification", "price"):
            assert word in text, word
        assert re.search(r"entitlements .* are separate from services", text)

    def test_the_page_renders_the_disclaimer_before_the_first_service(self):
        page = _text("app/services/page.tsx")
        assert page.index("SERVICES_DISCLAIMER") < page.index("SERVICES.map((service)")


class TestNothingIsPromised:
    def test_no_price_currency_or_rate(self, services):
        for text in _strings(services):
            assert not re.search(r"[€$£]|\bEUR\b|\bper (?:day|hour|month)\b|/mo\b|\bfree trial\b", text, re.I), text

    def test_no_time_commitment_or_guarantee(self, services):
        for text in _strings(services):
            assert not re.search(r"\bwithin \d+|\b\d+[- ](?:hour|day|week)s? (?:response|turnaround|delivery|support|SLA)|guarantee|ensure[sd]? compliance|\bwill be compliant", text, re.I), text

    def test_sla_certification_and_compliance_appear_only_in_denials(self, services):
        for text in _strings(services):
            for word, flags in ((r"\bSLAs?\b", 0), ("certif", re.I), ("compliant", re.I), (r"\bsafe\b", re.I)):
                for match in re.finditer(word, text, flags):
                    sentence = text[max(0, text.rfind(".", 0, match.start()) + 1): text.find(".", match.end()) + 1 or None]
                    assert re.search(r"\b(no|not|never|cannot|without|nor)\b", sentence, re.I), (word, text)

    def test_no_customer_or_result_claims(self, services):
        banned = re.compile(r"trusted by|customers include|case stud|testimonial|award|saved \d|reduced \w+ by|\d+\s?%", re.I)
        for text in _strings(services):
            assert not banned.search(text), text

    def test_the_page_has_one_call_to_action_and_it_is_the_general_contact_route(self):
        page = _text("app/services/page.tsx")
        assert page.count("{SALES}") == 1
        assert not re.search(r"btn-primary|mailto:|calendly|book a|schedule a|checkout|buy", page, re.I)


class TestCapabilityClaimsAreTrue:
    def test_every_backticked_command_is_in_the_contract(self, services):
        domains = CONTRACT["cli_domains"]
        for text in _strings([s["today"] + s["verifiable"] + s["deliverables"] + s["prerequisites"] for s in services]):
            for span in re.findall(r"`([^`]+)`", text):
                head = span.split()
                if head and head[0] in domains and len(head) > 1 and not head[1].startswith("-"):
                    assert head[1] in domains[head[0]], span

    @pytest.mark.parametrize("cap", ["kit.init", "kit.check", "kit.run", "machinery.enrol", "machinery.import_inventory",
                                     "machinery.diff", "machinery.coverage", "fleet.advisory", "fleet.import_csaf",
                                     "watch.run", "machinery.passport", "machinery.passport_check", "machinery.manifest", "machinery.intervention", "machine.verify", "change.reverify", "ops.cycle", "ops.status", "ops.check", "tenant.export",
                                     "collect.check_plan", "change.replay", "evidence.verify"])
    def test_a_capability_called_available_exists_on_the_cli(self, cap):
        assert CAPS[cap]["surfaces"]["cli"]["status"] == "available", cap

    @pytest.mark.parametrize("cap", ["change.decide", "change.waive_reverification", "supplier.trust_pin"])
    def test_decisions_and_trust_changes_have_no_mcp_tool_by_design(self, cap):
        assert CAPS[cap]["surfaces"]["mcp"]["status"] == "by_design", cap

    def test_services_say_the_hosted_api_is_not_deployed_and_it_is_not(self, services):
        text = " ".join(_strings(services))
        assert "none is public today" in text or "not deployed publicly" in text or "none is deployed publicly" in text
        go_live = _text("docs/GO-LIVE.md")
        assert "Do not start the post-secrets half" in go_live  # the deployment half has not been done
        assert "price_not_configured" in _text("scripts/site_static/agent.json.tmpl")

    def test_the_ops_guide_really_is_prepared_not_performed(self):
        assert "prepared, not performed" in _text("deploy/assurance/OPS.md")

    def test_no_training_curriculum_exists_in_the_repository(self):
        # the service says none exists; if one is added this test fails and the entry must change
        names = [p.name.lower() for p in (ROOT / "docs").rglob("*") if p.is_file()]
        assert not any("curriculum" in n or "training" in n for n in names)


class TestTrustPage:
    def test_provenance_classes_and_ceilings_match_the_code(self):
        code = _text("src/assurance/machinery/manifest.py")
        ceilings = dict(re.findall(r"if self is HashSource\.(\w+):\s*return AssuranceTier\.(\w+)", code))
        assert ceilings == {"READ_FROM_MACHINE": "VALIDATED", "SUPPLIED_BY_VENDOR": "COMMUNITY"}  # DECLARED falls through to PROFILE
        assert "return AssuranceTier.PROFILE" in code
        page = _text("app/trust/page.tsx")
        for cls, tier in (("read_from_machine", "validated"), ("supplied_by_vendor", "community"), ("declared", "profile")):
            row = re.search(rf"<code>{cls}</code>.*?<td>{tier}</td>", page, re.S)
            assert row, (cls, tier)

    def test_no_class_reaches_certified(self):
        ceiling = _text("src/assurance/machinery/manifest.py").split("def tier_ceiling")[1].split("def describes_this_unit")[0]
        assert "CERTIFIED" not in ceiling
        page = _text("app/trust/page.tsx")
        assert "No class reaches <em>certified</em>" in re.sub(r"\s+", " ", page)

    def test_the_page_claims_no_certification_audit_uptime_or_customer(self):
        page = _text("app/trust/page.tsx")
        assert "No security certification" in page and "No uptime" in page and "No customer" in page
        text = re.sub(r"<[^>]+>", " ", page)
        assert not re.search(r"SOC ?2|ISO ?27001|pen(?:etration)?[- ]test(?:ed)?|trusted by|\b99\.\d+%", text, re.I)

    def test_decider_rules_are_the_ones_the_change_guide_states(self):
        guide = _text("deploy/assurance/CHANGE.md")
        for needle in ("actor_mismatch", "operator_required", "`decider` role"):
            assert needle in guide, needle
        page = _text("app/trust/page.tsx")
        assert "<code>decider</code>" in page


class TestPathAndBrand:
    def test_every_new_page_is_in_the_sitemap_and_the_search_index(self):
        sitemap, index = _text("app/sitemap.ts"), _text("app/lib/search-index.ts")
        for path in ("/start", "/services", "/trust"):
            assert f"${{SITE_URL}}{path}`" in sitemap, path
            assert f"href: '{path}'" in index, path

    def test_static_agent_files_list_the_new_pages(self):
        llms = _text("scripts/site_static/llms.txt.tmpl")
        agent = _text("scripts/site_static/agent.json.tmpl")
        for path in ("/start", "/trust", "/services"):
            assert f"https://neuralbridge.io{path}" in llms and f"https://neuralbridge.io{path}" in agent, path
        assert "NeuralBridge is the company and platform" in llms
        assert "Industrial Autonomous Assurance is its flagship product" in llms

    def test_the_header_names_the_company_first_and_the_product_second(self):
        header = _text("app/Header.tsx")
        assert re.search(r'brand-name">NeuralBridge<.*?brand-product">Industrial Autonomous Assurance<', header, re.S)
        assert 'className="brand-lockup" href="/"' in header  # not "#top": that went nowhere from any other page

    def test_the_home_hero_states_the_relationship(self):
        page = _text("app/page.tsx")
        assert "NeuralBridge is the company and platform; Industrial Autonomous Assurance is its flagship product." in page
        assert page.count("<h1") == 1

    def test_the_journey_prices_are_the_published_unvalidated_list_prices(self):
        journey = _text("app/lib/journey.ts")
        assert sorted(set(re.findall(r"€[\d,]+", journey))) == ["€1,290", "€390"]
        assert "unvalidated list prices, not quotes" in journey
        assert "price_not_configured" in journey

    def test_no_journey_step_promises_a_response_time_or_self_serve_checkout(self):
        journey = _text("app/lib/journey.ts")
        assert "Nothing here promises a response time." in journey
        assert not re.search(r"within \d+|instantly|in minutes|sign up now|start your free trial", journey, re.I)
