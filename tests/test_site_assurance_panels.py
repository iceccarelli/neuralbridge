"""The /assurance workspace panels "Enrol a machine" and "Public intelligence lookup".

Source-level checks on the TSX/TS (the repo's pattern for the site: read ``app/**``, and run the
pure helpers in ``app/lib/assuranceApi.ts`` with node type stripping). They pin that each panel
calls exactly the documented route, renders the server's own not-established text, never says a
machine is verified/compliant/safe, and never draws an unknown or unavailable answer as a good
or zero one. The browser behaviour is ``tests-e2e/assurance-panels.spec.ts``.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMP = ROOT / "app" / "components" / "assurance"
ENROL = COMP / "EnrolPanel.tsx"
ENROL_VIEW = COMP / "EnrolReceiptView.tsx"
INTEL = COMP / "IntelPanel.tsx"
INTEL_VIEW = COMP / "IntelReportView.tsx"
PANELS = (ENROL, ENROL_VIEW, INTEL, INTEL_VIEW)


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def code(path: Path) -> str:
    """Source without comments, so an explanation may use any word."""
    src = re.sub(r"/\*.*?\*/", "", text(path), flags=re.S)
    return "\n".join(line for line in src.splitlines() if not line.strip().startswith("//"))


def _node(script: str) -> object:
    node = shutil.which("node")
    assert node, "node is not installed"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is built in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


OPENAPI = json.loads((ROOT / "public" / "openapi.json").read_text(encoding="utf-8"))


class TestThePanelsExistAndAreMounted:
    def test_the_files_exist(self):
        for path in PANELS:
            assert path.is_file(), path

    def test_the_workspace_mounts_both_panels_in_the_keyed_page(self):
        ws = text(ROOT / "app" / "components" / "AssuranceWorkspace.tsx")
        assert "<EnrolPanel" in ws and "<IntelPanel" in ws
        # They get the key the workspace holds (the shared per-tab key), nothing else is stored.
        assert re.search(r"<IntelPanel apiKey=\{key\}", ws)
        assert re.search(r"<EnrolPanel[^>]*apiKey=\{key\}", ws, re.S)

    def test_the_page_is_still_noindex(self):
        assert "index: false" in text(ROOT / "app" / "assurance" / "page.tsx")

    def test_the_panels_store_nothing_and_the_key_goes_only_through_call(self):
        for path in PANELS:
            src = code(path)
            assert not re.search(r"localStorage|sessionStorage|document\.cookie|console\.", src), path.name
            assert "fetch(" not in src, f"{path.name} must go through call(), which sends the key as a header"
            assert not re.search(r"[?&]key=|api_key=|apiKey\s*\}?\s*(`|\+)", src), path.name
        for path in (ENROL, INTEL):
            assert "API_BASE" in code(path)


class TestTheRoutesAreTheDocumentedOnes:
    def test_the_enrol_panel_posts_exactly_to_the_documented_route(self):
        src = code(ENROL)
        assert re.findall(r"""['"`](/v1/[^'"`]*)""", src) == ["/v1/machinery/enrol"]
        assert "method: 'POST'" in src
        assert "post" in OPENAPI["paths"]["/v1/machinery/enrol"]

    def test_the_enrol_body_uses_the_documented_fields_and_no_others(self):
        schema_ref = OPENAPI["paths"]["/v1/machinery/enrol"]["post"]["requestBody"]["content"][
            "application/json"]["schema"]["$ref"]
        schema = OPENAPI["components"]["schemas"][schema_ref.rsplit("/", 1)[1]]
        sent = set(re.findall(r"^\s+(manifest|actor|site|owner|role)\b",
                              code(ENROL).split("body: {", 1)[1].split("});", 1)[0], re.M))
        assert sent and sent <= set(schema["properties"]), (sent, set(schema["properties"]))
        assert {"manifest", "actor"} <= sent and set(schema["required"]) == {"manifest", "actor"}

    def test_the_intel_panel_gets_exactly_the_documented_route(self):
        src = code(INTEL)
        assert re.findall(r"""['"`](/v1/[^'"`$]*)""", src.replace("{'GET /v1/intel/cve/{cve_id}'}", "")) \
            == ["/v1/intel/cve/"]
        assert "/v1/intel/cve/${id}" in src and "method:" not in src.split("call<IntelCve>")[1].split(";")[0]
        assert "get" in OPENAPI["paths"]["/v1/intel/cve/{cve_id}"]

    def test_neither_panel_names_a_route_the_api_does_not_have(self):
        paths = {re.sub(r"\{[^}]+\}", "{}", p) for p in OPENAPI["paths"]}
        for path in PANELS:
            for route in re.findall(r"(?:GET|POST) (/v1/[\w/{}.-]+)", code(path)) + \
                    re.findall(r"""['"`](/v1/[\w/.-]+)""", code(path)):
                assert re.sub(r"\{[^}]+\}", "{}", route).rstrip("/") in paths or route.endswith("/"), route


class TestTheServersOwnWordsAreRendered:
    @pytest.mark.parametrize("key", [
        "does_not_establish", "next_steps", "pointer", "uncomparable_items", "uncomparable_note",
        "tier_ceiling", "tier_ceiling_note", "undemonstrable_functions", "coverage", "machine",
        "configuration_hash", "written", "conflicts", "status",
    ])
    def test_every_receipt_field_the_panel_shows_is_one_the_server_sends(self, key):
        enrol = text(ROOT / "src" / "assurance" / "machinery" / "enrol.py")
        assert f'"{key}"' in enrol, key
        assert re.search(rf"\b{key}\b", text(ENROL_VIEW)), f"EnrolReceiptView does not render {key}"

    def test_the_not_established_list_and_the_pointer_are_shown_unedited(self):
        view = code(ENROL_VIEW)
        assert re.search(r"List items=\{receipt\.does_not_establish\}", view)
        assert re.search(r"\{receipt\.pointer\}", view)
        assert re.search(r"List items=\{receipt\.next_steps\}", view)
        # the 409 message (the pointer text the API returns) is shown with the refusal
        assert re.search(r"\{out\.message\}", code(ENROL))

    def test_the_ceiling_is_labelled_as_a_ceiling_not_a_result(self):
        assert "a ceiling, not a result" in code(ENROL_VIEW)

    @pytest.mark.parametrize("snippet", [
        "kev.not_established", "kev.note", "epss.note", "epss.reason", "epss.score_date",
        "report.not_established", "report.summary.reason", "c.nvd.citation", "c.csaf.citation",
        "o.sha256", "o.retrieved_at", "o.seq", "o.source", "report.conflicts",
        "sources_without_an_accepted_observation", "c.observation_seq",
    ])
    def test_the_intel_view_renders_the_citation_and_not_established_fields(self, snippet):
        assert snippet in code(INTEL_VIEW)

    def test_those_fields_are_ones_the_server_sends(self):
        view = text(ROOT / "src" / "assurance" / "intel" / "view.py")
        routes = text(ROOT / "src" / "assurance" / "api" / "intel_routes.py")
        for key in ("not_established", "note", "reason", "score_date", "observation_seq", "retrieved_at",
                    "sha256", "resolution"):
            assert f'"{key}"' in view or f'"{key}"' in text(ROOT / "src" / "assurance" / "intel" / "store.py"), key
        for key in ("sources_consulted", "not_established", "summary", "unreadable_observations"):
            assert f'"{key}"' in routes, key
        assert "sources_without_an_accepted_observation" in routes

    def test_the_store_503_codes_are_the_servers_and_say_what_the_operator_does(self):
        routes = text(ROOT / "src" / "assurance" / "api" / "intel_routes.py")
        api = text(ROOT / "app" / "lib" / "assuranceApi.ts")
        for codename in ("no_intel_store_configured", "intel_store_unreadable"):
            assert f'"{codename}"' in routes and f"'{codename}'" in api, codename
        assert "Operator action:" in api
        assert "data-testid=\"intel-store-banner\"" in code(INTEL)
        assert "not an empty result" in code(INTEL)


class TestTheWordsThePanelsMayNotUse:
    BANNED = re.compile(r"\b(verified|compliant|compliance|safe|certified|approved|passed|passes)\b", re.I)

    def test_no_sentence_calls_a_machine_verified_compliant_or_safe(self):
        for path in PANELS:
            # `never_verified` is the server's coverage value, shown as spelled; \b does not split it.
            src = code(path).replace("never_verified", "")
            hits = [m.group(0) for m in self.BANNED.finditer(src)]
            # "does NOT establish" lists come from the server at run time; none is written here.
            assert not hits, (path.name, hits)

    def test_no_invented_claims(self):
        for path in PANELS:
            assert not re.search(r"\b(customer|pilot|revenue|production deployment)s?\b", code(path), re.I), path.name
            assert "github.com" not in text(path)


class TestUnknownAndUnavailableAreNeverDrawnAsGoodOrZero:
    def test_the_epss_unavailable_branch_renders_no_number(self):
        view = code(INTEL_VIEW)
        branch = view.split("function Epss", 1)[1].split("function Nvd", 1)[0]
        unavailable = branch.split("if (epss.status === 'available')", 1)[1].split("return (\n      <Row", 1)[1]
        unavailable = unavailable.split("</Row>", 1)[1]            # past the available row
        assert "unavailable" in unavailable
        assert not re.search(r"epss\.score|\b0\b|0\.0|toFixed|\?\?\s*0|\|\|\s*0|Number\(", unavailable), unavailable

    def test_no_missing_value_is_defaulted_to_zero_anywhere_in_the_intel_view(self):
        for path in (INTEL_VIEW, INTEL):
            assert not re.search(r"\?\?\s*0\b|\|\|\s*0\b|:\s*0\b(?!\.)", code(path)), path.name
        # the one score shown is the server's, printed as the string it sent
        assert "String(epss.score)" in code(INTEL_VIEW)

    def test_an_unknown_summary_is_styled_apart_from_a_recorded_one_and_never_green(self):
        view = code(INTEL_VIEW)
        assert "report.summary.status !== 'recorded'" in view
        assert "unknown ? 'unknown' : 'recorded'" in view
        css = text(ROOT / "app" / "globals.css")
        rules = re.findall(r"^\.aw-(?:intel|receipt|store)[^{]*\{[^}]*\}", css, re.M)
        assert any('data-state="unknown"' in r for r in rules)
        for rule in rules:
            assert not re.search(r"--success|green|#0[0-9a-f]{2}[0-9a-f]{3}\b|#06", rule, re.I), rule
        unknown_rule = next(r for r in rules if r.startswith(".aw-intel-summary[data-state=\"unknown\"]"))
        recorded_rule = next(r for r in rules if r.startswith(".aw-intel-summary {"))
        assert unknown_rule != recorded_rule and "dashed" in unknown_rule

    def test_unchecked_kev_and_unknown_nvd_keep_their_own_words(self):
        view = code(INTEL_VIEW)
        for word in ("unchecked", "not_listed_in_kev", "listed", "unavailable", "unknown", "rejected"):
            assert f"<code>{word}</code>" in view or f"state=\"{word}\"" in view or f"=== '{word}'" in view, word


class TestTheClientSideChecksMatchTheServer:
    def test_cve_ids_are_validated_with_the_servers_pattern_and_upper_cased(self):
        routes = text(ROOT / "src" / "assurance" / "api" / "intel_routes.py")
        assert 're.compile(r"CVE-[0-9]{4}-[0-9]{4,19}")' in routes
        out = _node(
            "const m = await import('./app/lib/assuranceApi.ts');"
            "const ins=['cve-2021-44228',' CVE-2021-44228 ','CVE-2021-123','CVE-21-44228','CVE-2021-44228; DROP',"
            "'CVE-2026-' + '1'.repeat(19),'CVE-2026-' + '1'.repeat(20),'','../x','CVE-２０２１-44228'];"
            "process.stdout.write(JSON.stringify({pattern: m.CVE_ID_PATTERN.source,"
            " r: ins.map(i => m.parseCveId(i))}));")
        assert out["pattern"] == r"^CVE-\d{4}-\d{4,19}$"
        ok = [r["id"] for r in out["r"]]
        assert ok == ["CVE-2021-44228", "CVE-2021-44228", "", "", "", "CVE-2026-" + "1" * 19, "", "", "", ""]
        assert all(r["problem"] for r in out["r"] if not r["id"])

    def test_an_empty_or_automation_looking_actor_is_refused_client_side(self):
        names = ["", "   ", "​", "---", "automation", "Watch", "AI Agent", "system bot", "service 42",
                 "Ada Lovelace", "m.tech", "Operator Maria", "Jörg Müller"]
        out = _node(
            "const m = await import('./app/lib/assuranceApi.ts');"
            f"process.stdout.write(JSON.stringify({json.dumps(names)}.map(n => m.actorProblem(n))));")
        refused = {n for n, p in zip(names, out, strict=True) if p}
        assert refused == {"", "   ", "​", "---", "automation", "Watch", "AI Agent", "system bot", "service 42"}

    def test_the_client_list_of_automation_names_is_the_servers(self):
        enrol = text(ROOT / "src" / "assurance" / "machinery" / "enrol.py")
        server = set(re.search(r"_RESERVED_NAMES = frozenset\(\{(.*?)\}\)", enrol, re.S).group(1)
                     .replace('"', "").replace("\n", "").replace(" ", "").strip(",").split(","))
        client = set(re.search(r"AUTOMATION_NAMES = new Set\(\[(.*?)\]\)", text(ROOT / "app" / "lib" / "assuranceApi.ts"))
                     .group(1).replace("'", "").replace(" ", "").split(","))
        assert client == server

    def test_the_enrol_panel_checks_the_actor_before_it_sends_anything(self):
        src = code(ENROL)
        assert src.index("actorProblem(actor)") < src.index("await call<EnrolReceipt>")

    def test_a_409_receipt_is_kept_by_the_client(self):
        out = _node(
            "const m = await import('./app/lib/assuranceApi.ts');"
            "const o = m.classify(409, {detail:{error:'configuration_differs', detail:'POINTER TEXT',"
            " receipt:{status:'configuration_differs', machine:'a/b#1', coverage:{f1:'never_verified'}}}});"
            "process.stdout.write(JSON.stringify({kind:o.kind, msg:o.message, r:m.receiptOf(o.receipt)}));")
        assert out["kind"] == "conflict" and out["msg"] == "POINTER TEXT"
        assert out["r"]["status"] == "configuration_differs" and out["r"]["coverage"] == {"f1": "never_verified"}

    def test_a_503_store_refusal_names_the_operator_action_and_is_not_empty(self):
        out = _node(
            "const m = await import('./app/lib/assuranceApi.ts');"
            "const o = m.classify(503, {detail:{error:'no_intel_store_configured', detail:'ASSURANCE_INTEL_STORE is not set.',"
            " remedy:'The operator sets ASSURANCE_INTEL_STORE.', not_established:'No store means nothing is known.'}});"
            "process.stdout.write(JSON.stringify(m.describeOutcome(o)));")
        assert "not configured" in out["heading"] and out["remedy"].startswith("Operator action:")
        assert "nothing is known" in out["text"].lower()
