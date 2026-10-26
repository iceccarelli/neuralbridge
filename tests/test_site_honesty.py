"""The marketing site and the docs say what the code does, and each claim is held by a test.

An independent read-only audit of ``origin/main`` found copy that outran the code:
sample CLI output that no longer matched the CLI, an adapter table typed by hand in four
places that disagreed with the README, a privacy page that omitted what the code stores,
pricing cards that hid enforced limits behind ``slice()``, structured data that priced a
monthly plan with no period, an agent descriptor that said "self serve" for a checkout that
answers 503, and so on. Every test here parses the real artefact (TSX, Markdown, JSON,
CSS, or the running CLI/API) and compares structure, not a substring that happens to be
there. Each was written to fail on that audited tree.
"""

from __future__ import annotations

import html
import importlib
import inspect
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from assurance.billing.accounts import AccountStore
from assurance.billing.plans import METERED_SCOPES, PLANS, public_catalogue

from .test_assurance_plans_parity import _fallback_plans

ROOT = Path(__file__).resolve().parents[1]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def page_text(source: str) -> str:
    """The words a visitor reads in a TSX/MD/TXT source: tags and code fences dropped, entities decoded."""
    text = re.sub(r"</?(?:code|strong|em|a|span|b|i)\b[^>]*>", "", source)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = text.replace("’", "'").replace("`", "")
    return re.sub(r"\s+", " ", text).strip()


def ts_strings(source: str) -> str:
    """Plain text of string literals in TS data files (so ``’`` and ``'`` compare equal)."""
    text = html.unescape(source).replace("’", "'").replace("\\'", "'").replace("`", "")
    return re.sub(r"\s+", " ", text)


def _env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASSURANCE_LEDGER", str(tmp_path / "art14.db"))
    monkeypatch.setenv("ASSURANCE_ACCOUNTS", str(tmp_path / "accounts.db"))
    for name in ("ASSURANCE_API_KEYS", "ASSURANCE_ALLOW_UNAUTHENTICATED", "STRIPE_SECRET_KEY",
                 "ASSURANCE_PRICE_REGISTER", "ASSURANCE_PRICE_CELL"):
        monkeypatch.delenv(name, raising=False)
    from assurance.api import deps

    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    service = importlib.import_module("assurance.api.service")
    with TestClient(service.create_app()) as c:
        yield c


# ---------------------------------------------------------------------------
# 1. the sample outputs on the homepage are what the shipped command printed
# ---------------------------------------------------------------------------
INTENT_TSX = "app/components/IntentModule.tsx"
OMITTED = "…"  # a line that is only this marks lines left out of an excerpt


def _intents() -> dict[str, dict]:
    source = read(INTENT_TSX)
    found: dict[str, dict] = {}
    for m in re.finditer(r"\n  \{\n    key: '([\w-]+)',(.*?)\n  \},", source, re.S):
        body = m.group(2)
        cmds = re.search(r"commands: \[(.*?)\],\n", body, re.S)
        out = re.search(r"output: (`(?:[^`\\]|\\.)*`|\w+\(\)),?\s*$", body, re.S)
        assert cmds and out, f"intent {m.group(1)!r} needs `commands` and `output`"
        found[m.group(1)] = {
            "commands": [c.replace("\\'", "'") for c in re.findall(r"'((?:[^'\\]|\\.)*)'", cmds.group(1))],
            "output": out.group(1),
        }
    return found


def _block(expr: str) -> str:
    assert expr.startswith("`"), f"{expr} is computed, not typed"
    assert "${" not in expr and "\\" not in expr, "a sample output block must be plain text"
    return expr[1:-1]


def _lines(text: str) -> list[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


MORE = re.compile(r"^\u2026 (\d+) more not shown$")


def _sections(real: str) -> list[tuple[str, list[str]]]:
    """The ``not checked:`` / ``provenance:`` sections of a real output: header and bullet lines."""
    raw = [line.strip() for line in real.splitlines()]
    found, i = [], 0
    while i < len(raw):
        if re.fullmatch(r"(not checked|provenance):", raw[i]):
            j = i + 1
            while j < len(raw) and raw[j].startswith("- "):
                j += 1
            found.append((raw[i], raw[i + 1:j]))
            i = j
        else:
            i += 1
    return found


def _assert_excerpt(block: str, real: str) -> None:
    """Every line shown is a whole line of the real output, in order; nothing is re-wrapped.

    An excerpt may not hide what the command says it did NOT establish: the first line of every
    ``not checked`` / ``provenance`` section is shown, a provenance caveat line is shown, and bullets
    left out are announced by a ``... N more not shown`` line whose N is checked against the output.
    """
    real_lines, pos = _lines(real), 0
    shown = _lines(block)
    assert shown, "empty sample block"
    assert shown[0] == real_lines[0], f"the first line must be the verdict line {real_lines[0]!r}"
    for line in shown:
        if line == OMITTED or MORE.match(line):
            continue
        try:
            pos = real_lines.index(line, pos) + 1
        except ValueError:
            pytest.fail(f"homepage shows {line!r}, which the command does not print there")
    # An excerpt may not hide a failing or never-run line: those are the point of the output.
    must_show = [ln for ln in real_lines if re.match(r"(\[(?!ok|n/a)|!!)", ln)]
    assert must_show, "the reference output has no failing lines: pick a command that shows them"
    hidden = [ln for ln in must_show if ln not in shown]
    assert not hidden, f"the homepage block hides lines the command printed: {hidden}"

    sections = _sections(real)
    assert sections, "the reference output has no not-checked section: pick a command that shows one"
    announced = 0
    for header, bullets in sections:
        assert header in shown, f"the {header!r} section is not shown"
        assert bullets[0] in shown, f"the first line under {header!r} is hidden: {bullets[0]!r}"
        left_out = [b for b in bullets if b not in shown]
        if left_out:
            last = max(shown.index(b) for b in bullets if b in shown)
            marker = MORE.match(shown[last + 1]) if last + 1 < len(shown) else None
            assert marker, f"{len(left_out)} lines under {header!r} are left out and the block does not say so"
            assert int(marker.group(1)) == len(left_out), (marker.group(0), len(left_out))
            announced += 1
    assert sum(1 for ln in shown if MORE.match(ln)) == announced, "a 'more not shown' line with nothing behind it"
    caveats = [ln for ln in real_lines if re.search(r"provenance", ln, re.I)
               and not ln.startswith("- ") and not ln.endswith(":")]
    assert not [c for c in caveats if c not in shown], "a provenance caveat the command printed is hidden"


def _run_cli(command: str, ledger: Path) -> subprocess.CompletedProcess:
    argv = shlex.split(command)
    assert argv[0] == "assurance", command
    argv = [str(ledger) if a == "register.db" else a for a in argv[1:]]
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "COLUMNS": "400"}
    return subprocess.run(  # noqa: S603
        [sys.executable, "-m", "assurance", *argv],
        capture_output=True, text=True, check=False, cwd=ROOT, env=env, timeout=120,
    )


CLI_INTENTS = ["manufacturing", "robotics", "insurance"]


class TestHomepageSampleOutputIsTheRealOutput:
    def test_the_intents_are_parsed(self):
        assert set(_intents()) == {"manufacturing", "robotics", "compliance", "insurance", "ai-ops"}

    @pytest.mark.parametrize("key", CLI_INTENTS)
    def test_each_cli_block_is_an_excerpt_of_the_command_it_names(self, key, tmp_path):
        intent = _intents()[key]
        ledger = tmp_path / "register.db"
        *setup, shown = intent["commands"]
        for command in setup:
            done = _run_cli(command, ledger)
            assert done.returncode == 0, f"{command}: {done.stderr or done.stdout}"
        done = _run_cli(shown, ledger)
        assert done.returncode in (0, 1), done.stderr  # 1 means findings, which these examples have
        _assert_excerpt(_block(intent["output"]), done.stdout)

    def test_the_machine_verify_block_shows_the_figures_the_cli_prints(self, tmp_path):
        """The audited block said worst margin 0.0 mm/s and omitted the fourth failing check."""
        intent = _intents()["robotics"]
        assert intent["commands"][-1].startswith("assurance machine verify ")
        assert "examples/machine/envelope.json" in intent["commands"][-1]
        block = _block(intent["output"])
        real = _run_cli(intent["commands"][-1], tmp_path / "register.db").stdout
        for figure in re.findall(r"\d+(?:\.\d+)?(?: mm/s| mm)?", block):
            assert figure in real, f"{figure!r} is on the homepage and not in the command's output"
        assert block.count("[FAIL]") == real.count("[FAIL]") == 3
        assert "worst shortfall 1050.0 mm/s" in block and "worst shortfall 1281.0 mm" in block
        assert re.search(r"\[FAIL\] stop_characterisation", block)

    def test_the_validate_block_is_an_excerpt_of_the_real_response(self, client):
        intent = _intents()["compliance"]
        (command,) = intent["commands"]
        verb, path, body = command.split(" ", 2)
        assert (verb, path) == ("POST", "/v1/spec/validate")
        real = client.post(path, json=json.loads(body)).json()
        block = _block(intent["output"])
        assert re.search(r'"submittable":\s*false', block) and real["submittable"] is False
        shown = re.findall(
            r'"field_number":\s*"([^"]+)",\s*"field_name":\s*"([^"]+)",\s*"message":\s*"([^"]*)"', block)
        assert shown
        by_field = {(i["field_number"], i["field_name"]): re.sub(r"\s+", " ", i["message"])
                    for i in real["issues"]}
        for number, name, message in shown:
            assert (number, name) in by_field, f"{number}/{name} is not an issue the service returns"
            assert by_field[(number, name)].startswith(re.sub(r"\s+", " ", message)), message
        hidden = len(real["issues"]) - len(shown)
        if hidden:
            assert re.search(rf"{OMITTED}\s*and {hidden} more", block), \
                f"{hidden} issues are not shown and the block does not say so"

    def test_the_validate_request_shown_is_the_playground_payload(self):
        (command,) = _intents()["compliance"]["commands"]
        shown = json.loads(command.split(" ", 2)[2])
        sample = re.search(r"SAMPLE_PAYLOAD = `(.*?)`;", read("app/components/ValidatorPlayground.tsx"), re.S)
        assert sample and json.loads(sample.group(1)) == shown

    def test_the_section_says_excerpt_and_names_the_test(self):
        text = page_text(read("app/page.tsx"))
        sentence = re.search(r"[^.]*shipped command[^.]*\.[^.]*\.", text)
        assert sentence, "the section no longer describes where the sample output comes from"
        assert re.search(r"excerpt", sentence.group(0), re.I), sentence.group(0)
        assert "tests/test_site_honesty.py" in text


# ---------------------------------------------------------------------------
# 2. adapter / platform status: one table, taken from the README
# ---------------------------------------------------------------------------
def _md_status_rows(markdown: str, heading: str | None = None) -> list[tuple[str, str]]:
    if heading:
        markdown = markdown[markdown.index(heading):]
    rows = []
    for line in markdown.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.startswith("|") else []
        if len(cells) == 2 and not set(cells[0]) <= {"-", ":", " "} and cells[0] not in ("Capability", "Area"):
            rows.append((cells[0], cells[1].replace("**", "")))
        elif rows and not line.startswith("|"):
            break
    return rows


def _site_status_rows() -> list[dict[str, str]]:
    source = read("app/lib/platformStatus.ts")
    rows = []
    for m in re.finditer(r"\{\s*area: '((?:[^'\\]|\\.)*)',\s*status: '((?:[^'\\]|\\.)*)',\s*pill: '(\w[\w-]*)'"
                         r"(?:,\s*note:\s*'((?:[^'\\]|\\.)*)')?,?\s*\}", source):
        rows.append({"area": m.group(1).replace("\\'", "'"), "status": m.group(2).replace("\\'", "'"),
                     "pill": m.group(3), "note": (m.group(4) or "").replace("\\'", "'")})
    return rows


class TestPlatformStatusIsTheReadmeTable:
    def test_the_readme_table_parses(self):
        rows = _md_status_rows(read("README.md"), "## Current Supported Scope")
        assert ("Small set of working adapters", "Intended supported scope") in rows
        assert len(rows) >= 10

    def test_the_site_table_is_the_readme_table_verbatim(self):
        readme = _md_status_rows(read("README.md"), "## Current Supported Scope")
        site = [(r["area"], r["status"]) for r in _site_status_rows()]
        assert site == readme

    def test_docs_platform_is_the_readme_table_verbatim(self):
        readme = _md_status_rows(read("README.md"), "## Current Supported Scope")
        docs = _md_status_rows(read("docs/platform.md"))
        assert docs == readme

    def test_the_intent_block_shows_that_same_table(self):
        intent = _intents()["ai-ops"]
        assert intent["output"] == "platformStatusText()"
        assert "README.md" in intent["commands"][0]
        assert "from '../lib/platformStatus'" in read(INTENT_TSX)
        assert "'GET /v1/plans" not in read(INTENT_TSX), "GET /v1/plans does not return this table"

    def test_the_homepage_renders_the_shared_table_not_a_private_copy(self):
        source = read("app/page.tsx")
        assert "PLATFORM_STATUS" in source and "from './lib/platformStatus'" in source
        assert "const platformStatus" not in source

    def test_the_pill_is_not_green_for_anything_the_readme_does_not_call_supported(self):
        for row in _site_status_rows():
            expected = ("supported" if row["status"] == "Supported"
                        else "not-claimed" if row["status"].startswith(("Not part", "Too broad"))
                        else "evolving")
            assert row["pill"] == expected, row
        assert ".status-pill.not-claimed" in read("app/globals.css")

    def test_adapters_row_says_what_was_exercised_and_the_code_agrees(self):
        rows = {r["area"]: r for r in _site_status_rows()}
        note = rows["Small set of working adapters"]["note"]
        assert "PostgreSQL" in note and "real server" in note and "/ai" in note
        assert "REST" in note and "canned" in note and "no HTTP request" in note
        # PostgreSQL is exercised against a real server only by the /ai and MCP integration tests ...
        owners = sorted(p.name for p in (ROOT / "tests").glob("test_*.py")
                        if "NEURALBRIDGE_AI_PG_HOST" in p.read_text(encoding="utf-8"))
        assert all(n.startswith(("test_ai", "test_neuralbridge_mcp", "test_site_honesty")) for n in owners), owners
        # ... and the REST adapter sends no request: its calls are commented out behind canned data.
        rest = read("src/neuralbridge/adapters/apis/rest.py")
        assert not re.search(r"^\s*(?:response = )?await self\._client\.(get|post|put|patch|delete|head)\(", rest, re.M)
        assert rest.count("MOCK:") >= 2 and '"mock_data"' in rest

    def test_docs_platform_carries_the_same_adapter_note(self):
        text = page_text(read("docs/platform.md"))
        assert "real server" in text and "canned" in text and "no HTTP request" in text

    def test_no_copy_claims_to_be_generated_from_the_readme(self):
        for relative in ("app/lib/solutions.ts", INTENT_TSX, "app/page.tsx", "docs/platform.md"):
            text = ts_strings(read(relative))
            assert not re.search(r"generated from (?:the )?(?:same )?README", text, re.I), relative
            assert not re.search(r"README.s own status table", text), relative

    def test_adapter_wording_elsewhere_does_not_call_them_supported(self):
        for relative in ("app/lib/solutions.ts", "app/page.tsx", "docs/platform.md"):
            text = ts_strings(read(relative))
            assert not re.search(r"small (?:set of )?(?:\w+ )?supported adapter", text, re.I), relative


# ---------------------------------------------------------------------------
# 3. privacy: every browser-storage mechanism and every server-side counter is disclosed
# ---------------------------------------------------------------------------
PRIVACY = "app/privacy/page.tsx"


def _storage_map() -> dict[str, set[str]]:
    """key -> mechanisms, for every key passed to get/set/removeItem anywhere under ``app/``."""
    files = {p: p.read_text(encoding="utf-8") for p in (ROOT / "app").rglob("*.ts*")}
    constants = {}
    for source in files.values():
        constants.update(re.findall(r"\bconst\s+(\w+)\s*=\s*'((?:nb|iaa)-[a-z-]+)'", source))
    legacy = set()
    for source in files.values():
        for body in re.findall(r"LEGACY_KEYS\s*=\s*\[([^\]]*)\]", source):
            legacy.update(re.findall(r"'([^']+)'", body))
    found: dict[str, set[str]] = {}
    for source in files.values():
        for name in ("localStorage", "sessionStorage"):
            for arg in re.findall(rf"window\.{name}\.(?:get|set|remove)Item\(\s*([\w']+)", source):
                if arg.startswith("'"):
                    keys = {arg.strip("'")}
                elif arg in constants:
                    keys = {constants[arg]}
                elif arg == "legacy":
                    keys = set(legacy)
                else:
                    pytest.fail(f"storage key {arg!r} is not a constant this test can resolve")
                for key in keys:
                    found.setdefault(key, set()).add(name)
        if re.search(r"document\.cookie\s*=", source):
            found.setdefault("<cookie>", set()).add("cookie")
    return found


def _browser_storage() -> tuple[set[str], set[str]]:
    found = _storage_map()
    return ({m for ms in found.values() for m in ms},
            {k for k in found if k != "<cookie>"})


class TestPrivacyDisclosesWhatTheCodeStores:
    def test_the_code_scan_finds_what_is_known_to_be_there(self):
        mechanisms, keys = _browser_storage()
        assert {"localStorage", "sessionStorage"} <= mechanisms
        assert {"nb-api-key", "iaa-cookie-choice", "nb-ai-actor", "nb-ai-session",
                "nb-assurance-decision-credential", "nb-console-api-key", "nb-ai-api-key"} <= keys

    def test_every_storage_mechanism_and_key_in_use_is_named_on_the_page(self):
        mechanisms, keys = _browser_storage()
        text = page_text(read(PRIVACY))
        missing = sorted(m for m in mechanisms | keys if m not in text)
        assert not missing, f"app/privacy/page.tsx does not mention: {missing}"

    def test_the_page_no_longer_says_a_single_flag_is_all_that_is_stored(self):
        text = page_text(read(PRIVACY))
        assert not re.search(r"one thing stored in your browser", text, re.I)

    def test_the_api_key_is_said_to_be_kept_in_the_tab_and_sent_only_to_the_api(self):
        text = page_text(read(PRIVACY))
        assert re.search(r"sessionStorage[^.]*(tab|session)", text)
        assert re.search(r"/console", text) and re.search(r"/ai\b", text) and re.search(r"/assurance", text)

    def test_the_page_does_not_claim_free_endpoints_record_nothing_server_side(self):
        text = page_text(read(PRIVACY))
        assert not re.search(r"record nothing server-side", text, re.I)

    def test_the_retention_the_page_states_is_the_one_in_the_store(self):
        source = read("src/assurance/billing/accounts.py")
        days = int(re.search(r"cutoff = \(utc_now\(\)\.date\(\) - timedelta\(days=(\d+)\)\)", source).group(1))
        text = page_text(read(PRIVACY))
        assert re.search(rf"\b{days} days\b", text), f"the store drops counters after {days} days"
        assert "ip:" in text and "usage_events" in text and "address" in text

    @staticmethod
    def _items() -> list[str]:
        return [page_text(m) for m in re.findall(r"<li>(.*?)</li>", read(PRIVACY), re.S)]

    def _item(self, needle: str) -> str:
        hits = [i for i in self._items() if needle in i]
        assert hits, f"no list item on the privacy page mentions {needle!r}"
        return hits[0]

    def test_each_key_is_filed_under_the_mechanism_the_code_uses_with_its_lifetime(self):
        for key, mechanisms in _storage_map().items():
            if key.startswith(("nb-console-api-key", "nb-ai-api-key")):
                continue  # the legacy keys are read-only; named inside the nb-api-key item
            (mechanism,) = mechanisms
            item = self._item(key)
            assert mechanism in item, (key, mechanism)
            other = ({"localStorage", "sessionStorage"} - {mechanism}).pop()
            assert other not in item.replace("nb-api-key", ""), (key, "names the wrong mechanism")
            if mechanism == "sessionStorage":
                assert re.search(r"gone when the tab closes", item), key
            else:
                assert re.search(r"until you clear site data", item), key

    def test_the_legacy_keys_are_named_and_said_to_be_read_not_written(self):
        item = self._item("nb-api-key")
        for legacy in ("nb-console-api-key", "nb-ai-api-key"):
            assert legacy in item
            writes = [p for p in (ROOT / "app").rglob("*.ts*") if re.search(rf"setItem\(\s*'{legacy}'", p.read_text(encoding="utf-8"))]
            assert not writes
        assert "never writes to them" in item

    def test_the_api_key_item_states_who_can_read_it_and_where_it_goes(self):
        item = self._item("nb-api-key")
        for phrase in ("any script running on this origin", "browser extensions", "X-API-Key header", "API host this build is configured with"):
            assert phrase in item, phrase

    def test_the_site_sets_no_cookies_and_sends_storage_only_to_the_api(self):
        assert "<cookie>" not in _storage_map()
        assert not [p for p in (ROOT / "app").rglob("*.ts*")
                    if re.search(r"navigator\.sendBeacon|new XMLHttpRequest|new WebSocket|new EventSource", p.read_text(encoding="utf-8"))]
        for path in (ROOT / "app").rglob("*.ts*"):
            for call in re.findall(r"\bfetch\(\s*([^,)]*)", path.read_text(encoding="utf-8")):
                if call.startswith("`$"):
                    assert re.match(r"`\$\{(API_BASE|apiBase)\}", call), f"{path.name}: fetch({call})"
        text = page_text(read(PRIVACY))
        assert "It sets no cookies." in text
        assert "None of it is sent anywhere except, where stated, to the API you configured." in text

    def test_the_address_is_described_as_the_ipv4_address_or_ipv6_prefix_the_code_stores(self):
        from assurance.api.deps import _bucket

        assert _bucket("2001:db8:1:2:3:4:5:6") == "2001:db8:1:2::/64" and _bucket("203.0.113.9") == "203.0.113.9"
        item = self._item("ip:")
        assert "IPv4 address, or the IPv6 /64 prefix" in item and "full address" not in item

    def test_the_metered_families_are_listed_as_metered_and_the_rest_as_writing_nothing(self):
        metered = self._item("carry a daily allowance")
        assert "write that counter" in metered
        for family in ("POST /v1/spec/validate", "separation calculator", "manifest diff", "advisory check",
                       "POST /v1/evidence/verify"):
            assert family in metered, family
        assert set(METERED_SCOPES) == {"validate", "separation", "machinery_diff", "advisory_check"}
        unmetered = self._item("not metered and write nothing")
        for family in ("Declaration", "evidence-bundle", "passport", "attestation"):
            assert family in unmetered, family

    def test_ai_reads_are_disclosed_with_the_limit_and_the_attribution_headers_the_code_uses(self):
        assert 'spend(principal, "ai_reads", principal.plan.ai_reads_per_day, accounts)' in read(
            "src/neuralbridge/ai/entitlements.py")
        limit = PLANS["free"].ai_reads_per_day
        item = self._item("ai_reads")
        assert f"{limit} a day per address" in item and "/ai" in item
        assert "X-NB-Actor" in item and "X-NB-Session" in item
        assert "'X-NB-Actor': actorId" in read("app/components/AiWorkspace.tsx")

    def test_the_request_fingerprint_is_disclosed_as_a_hash_stored_only_with_an_idempotency_key(self):
        deps = read("src/assurance/api/deps.py")
        assert 'if idempotency_key is not None else ""' in deps and "hashlib.sha256()" in deps
        item = self._item("has a fingerprint")
        assert "SHA-256" in item and "Idempotency-Key" in item and "not the body" in item

    def test_usage_event_retention_is_the_one_in_the_store(self):
        source = read("src/assurance/billing/accounts.py")
        days = int(re.search(r"_INCLUDED_RETENTION = timedelta\(days=(\d+)\)", source).group(1))
        assert "billed_state='included' AND occurred_at <" in source
        item = self._item("Usage events inside the free allowance")
        assert f"{days} days" in item and "billable" in item and "kept" in item

    def test_the_app_server_access_log_is_disclosed_as_on_by_default(self):
        docker = read("deploy/assurance/Dockerfile")
        cmd = re.search(r'^CMD \[(.*)\]', docker, re.M).group(1)
        assert '"uvicorn"' in cmd and "--no-access-log" not in cmd
        item = self._item("access log")
        for phrase in ("uvicorn", "access line", "peer address", "by default"):
            assert phrase in item, phrase

    def test_headings_do_not_skip_a_level(self):
        for relative in ("app/privacy/page.tsx", "app/contact/page.tsx"):
            levels = [int(n) for n in re.findall(r"<h([1-6])\b", read(relative))]
            assert levels[0] == 1, relative
            assert all(b - a <= 1 for a, b in zip(levels, levels[1:], strict=False)), (relative, levels)

    def test_an_anonymous_call_leaves_a_counter_keyed_by_address_and_nothing_else(self, client, tmp_path):
        done = client.post(
            "/v1/spec/validate",
            json={"track": "actively_exploited_vulnerability", "stage": "early_warning", "payload": {}},
        )
        assert done.status_code == 200
        db = sqlite3.connect(tmp_path / "accounts.db")
        rows = db.execute("SELECT subject, scope, count FROM usage").fetchall()
        events = db.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0]
        assert rows == [("ip:testclient", "validate", 1)]  # the peer address, keyed "ip:<address>"
        assert events == 0, "an anonymous caller must not write a usage event"

    def test_a_counter_older_than_the_retention_is_dropped_on_the_next_first_spend(self, tmp_path):
        store = AccountStore(str(tmp_path / "accounts.db"))
        db = sqlite3.connect(tmp_path / "accounts.db")
        from assurance.billing.accounts import utc_now

        old = (utc_now().date() - timedelta(days=8)).isoformat()
        recent = (utc_now().date() - timedelta(days=5)).isoformat()
        db.execute("INSERT INTO usage VALUES ('ip:198.51.100.1','validate',?,3)", (old,))
        db.execute("INSERT INTO usage VALUES ('ip:198.51.100.2','validate',?,3)", (recent,))
        db.commit()
        store.consume("ip:198.51.100.3", "validate", 20)
        days = {row[0] for row in db.execute("SELECT day FROM usage")}
        assert old not in days and recent in days


# ---------------------------------------------------------------------------
# 4. pricing cards: no feature is sliced away
# ---------------------------------------------------------------------------
PRICING_TSX = "app/components/PricingPlans.tsx"


class TestPricingCardsShowEveryEnforcedFeature:
    def test_no_card_slices_its_feature_list(self):
        source = read(PRICING_TSX)
        assert not re.search(r"\.includes\s*\.slice\(", source)
        assert not re.search(r"\bslice\(\s*0\s*,", source)

    def test_each_standing_card_maps_over_all_of_its_includes(self):
        source = read(PRICING_TSX)
        for variable in ("validator", "register", "cell"):
            assert re.search(rf"{variable}\.includes\.map\(\(item\)", source), variable

    def test_the_cell_card_can_show_the_change_assurance_waiver_caveat(self):
        cell = next(p for p in _fallback_plans() if p["tier"] == "cell")
        (line,) = [i for i in cell["includes"] if i.startswith("Change-assurance cases")]
        assert "waiver" in line and "validated" in line
        assert re.search(r"cell\.includes\.map\(\(item\)", read(PRICING_TSX))

    def test_the_validator_card_can_show_the_enforced_per_address_limits(self):
        validator = next(p for p in _fallback_plans() if p["tier"] == "free")
        limit = [i for i in validator["includes"] if "per day, per address" in i]
        assert limit == [f"{PLANS['free'].validations_per_day} validations and "
                         f"{PLANS['free'].separations_per_day} separation calculations per day, per address"]
        assert len(validator["includes"]) > 8, "the old slice was 8; the whole list must be rendered"
        assert re.search(r"validator\.includes\.map\(\(item\)", read(PRICING_TSX))


# ---------------------------------------------------------------------------
# 5. structured data: monthly price specification, home page only
# ---------------------------------------------------------------------------
OFFERS = "app/lib/structured-offers.json"


def _digits(price_label: str) -> str:
    return re.sub(r"[^\d]", "", price_label.split("/")[0])


class TestStructuredDataPricesAreMonthlyAndHomeOnly:
    def test_the_offer_data_is_a_json_module(self):
        data = json.loads(read(OFFERS))
        assert {"listPriceNote", "softwareApplication", "products"} <= set(data)

    def test_no_offer_claims_availability(self):
        assert "availability" not in read(OFFERS).lower()

    def test_a_paid_offer_has_no_bare_price(self):
        data = json.loads(read(OFFERS))
        paid = [o for o in data["softwareApplication"]["offers"] if o["name"] != "Validator"]
        paid += [p["offers"] for p in data["products"]]
        assert len(paid) == 4
        for offer in paid:
            assert "price" not in offer, "a bare price has no billing period: use priceSpecification"
            assert offer["priceSpecification"]["@type"] == "UnitPriceSpecification"

    def test_the_free_offer_is_zero_with_no_invented_period(self):
        data = json.loads(read(OFFERS))
        (free,) = [o for o in data["softwareApplication"]["offers"] if o["name"] == "Validator"]
        assert free["priceSpecification"]["price"] == "0"
        assert "unitText" not in free["priceSpecification"]

    def test_the_list_price_note_still_says_unvalidated_and_not_a_quote(self):
        note = json.loads(read(OFFERS))["listPriceNote"]
        assert "unvalidated" in note.lower() and "not a quote" in note.lower()

    def test_the_layout_emits_no_offer_or_product_so_noindex_pages_carry_none(self):
        layout = read("app/layout.tsx")
        assert "structured-offers" not in layout
        assert layout.count("application/ld+json") == 1  # Organization only
        for token in ("'Offer'", "'Product'", "priceCurrency", "SoftwareApplication"):
            assert token not in layout, token

    def test_the_home_page_is_what_emits_them(self):
        page = read("app/page.tsx")
        assert "structured-offers.json" in page
        assert page.count("application/ld+json") == 1  # one script per block, mapped over the JSON's blocks
        assert "structuredOffers.softwareApplication" in page and "...structuredOffers.products" in page
        assert len(json.loads(read(OFFERS))["products"]) == 2  # Register + Cell


# ---------------------------------------------------------------------------
# 6. agent.json says what checkout does
# ---------------------------------------------------------------------------
class TestAgentDescriptorMatchesCheckout:
    def test_checkout_answers_503_when_no_price_is_configured(self, client):
        done = client.post("/v1/checkout", json={"tier": "register", "email": "a@example.de"})
        assert done.status_code == 503
        assert done.json()["detail"]["error"] == "price_not_configured"

    def test_no_plan_is_purchasable_without_configured_prices(self, client):
        assert [p["purchasable"] for p in public_catalogue()] == [False, False, False]

    def test_paid_tiers_are_not_self_serve_and_say_they_cannot_be_bought_now(self):
        data = json.loads(read("public/.well-known/agent.json"))
        tiers = {t["name"]: t for t in data["pricing"]["tiers"]}
        for name in ("Register", "Cell"):
            assert tiers[name]["self_serve"] is False, name
            assert tiers[name]["purchasable_now"] is False, name
        assert tiers["Validator"]["price"] == 0 and tiers["Validator"]["self_serve"] is True
        assert data["honesty_note"].startswith("Purchase is inactive today.")
        assert "503 price_not_configured" in data["honesty_note"]

    def test_the_descriptor_agrees_with_the_catalogue_flag(self, client):
        data = json.loads(read("public/.well-known/agent.json"))
        catalogue = {p["name"]: p["purchasable"] for p in public_catalogue()}
        for tier in data["pricing"]["tiers"]:
            if tier["name"] in catalogue and tier["price"]:
                assert tier["purchasable_now"] is catalogue[tier["name"]]


# ---------------------------------------------------------------------------
# 7 + 8. "live, purchasable" and the tier-floor rule are not pricing claims
# ---------------------------------------------------------------------------
class TestPricingProseIsHonest:
    @pytest.mark.parametrize("relative", ["docs/pricing.md", "docs/index.md"])
    def test_the_docs_do_not_call_the_pricing_page_purchasable(self, relative):
        text = page_text(read(relative))
        assert not re.search(r"live,? purchasable", text, re.I)
        assert re.search(r"purchase only works on a deployment with Stripe prices configured \(none today\)", text)

    def test_that_statement_is_true_of_the_code(self, client):
        assert client.post("/v1/checkout", json={"tier": "cell", "email": "a@example.de"}).status_code == 503

    def test_nothing_the_site_serves_calls_the_pricing_table_live_purchasable(self):
        pattern = re.compile(r"live,? purchasable", re.I)
        files = [p for r in (ROOT / "app", ROOT / "docs", ROOT / "public") for p in r.rglob("*")
                 if p.is_file() and p.suffix in {".ts", ".tsx", ".md", ".json", ".txt"}] + [ROOT / "README.md"]
        offenders = [str(p.relative_to(ROOT)) for p in files
                     if pattern.search(ts_strings(p.read_text(encoding="utf-8", errors="ignore")))]
        assert not offenders, offenders

    @pytest.mark.parametrize("relative", ["app/page.tsx", "docs/pricing.md", "docs/index.md", "public/llms.txt"])
    def test_the_verification_tier_rule_is_not_in_pricing_copy(self, relative):
        assert not re.search(r"tiers are computed from the weakest input", page_text(read(relative)), re.I)

    def test_the_rule_is_still_stated_where_it_is_true(self):
        assert "computed from the weakest input" in read("README.md")
        assert "weakest input" in read("src/assurance/machine/verify.py")


# ---------------------------------------------------------------------------
# 9. re-check wording, derived from the metering registry and the routes
# ---------------------------------------------------------------------------
UNMETERED = ["/v1/fleet/declaration/check", "/v1/machine/bundle/check",
             "/v1/machinery/passport/check", "/v1/ledger/attest/verify"]


def _allowance_sentences() -> tuple[str, str]:
    free = PLANS["free"]
    verifier = free.validations_per_day
    diff = getattr(free, METERED_SCOPES["machinery_diff"])
    no_account = "Re-checking someone else's evidence needs no account."
    allowances = (
        "Declaration, evidence-bundle, passport and attestation checks are not metered. "
        f"The file verifier (POST /v1/evidence/verify, and /verify on this site) allows {verifier} a day per address; "
        f"manifest diff allows {diff} a day. Register and Cell have no daily cap on either."
    )
    return no_account, allowances


class TestRecheckWordingIsUniformAndTrue:
    def test_the_numbers_come_from_the_registry(self):
        assert PLANS["free"].validations_per_day == 20 and PLANS["free"].diffs_per_day == 10
        assert METERED_SCOPES["machinery_diff"] == "diffs_per_day"
        assert "evidence_verify" not in METERED_SCOPES  # a daily guard, not a billed scope
        assert PLANS["register"].diffs_per_day is None and PLANS["cell"].diffs_per_day is None
        assert PLANS["register"].validations_per_day is None and PLANS["cell"].validations_per_day is None

    @pytest.mark.parametrize("path", UNMETERED)
    def test_the_routes_the_copy_calls_unmetered_take_no_meter(self, path):
        from .test_assurance_entitlements import _v1

        app = importlib.import_module("assurance.api.service").create_app()
        (route,) = [r for (m, p), r in _v1(app).items() if p == path]
        assert "MeterTicket" not in str(inspect.signature(route.endpoint)), path
        body = inspect.getsource(route.endpoint)
        assert "spend(" not in body and "_meter(" not in body and ".consume(" not in body, path
        assert "Metered(" not in body

    def test_the_file_verifier_stops_at_the_free_allowance_and_the_diff_takes_a_meter(self, client):
        from .test_assurance_entitlements import _v1

        limit = PLANS["free"].validations_per_day
        codes = [client.post("/v1/evidence/verify", content=b"{}",
                             headers={"Content-Type": "application/json"}).status_code
                 for _ in range(limit + 1)]
        assert 429 not in codes[:limit] and codes[limit] == 429
        refusal = client.post("/v1/evidence/verify", content=b"{}",
                              headers={"Content-Type": "application/json"}).json()["detail"]
        assert refusal["scope"] == "evidence_verify" and refusal["limit"] == limit
        by_path = {p: r for (m, p), r in _v1(client.app).items()}
        assert "MeterTicket" in str(inspect.signature(by_path["/v1/machinery/diff"].endpoint))

    @pytest.mark.parametrize("relative", [
        "app/page.tsx", "app/solutions/[slug]/page.tsx", "app/lib/solutions.ts",
        "docs/pricing.md", "docs/index.md", "README.md", "public/llms.txt",
    ])
    def test_the_full_allowance_sentence_is_in_the_pages_that_discuss_the_limits(self, relative):
        _, allowances = _allowance_sentences()
        normal = ts_strings(read(relative)) if relative.endswith(".ts") else page_text(read(relative))
        assert allowances in normal, f"{relative} must state: {allowances}"

    @pytest.mark.parametrize("relative", [
        "app/page.tsx", "app/layout.tsx", "app/solutions/[slug]/page.tsx", "app/lib/solutions.ts",
        "docs/pricing.md", "docs/index.md", "README.md", "public/llms.txt", "public/.well-known/agent.json",
    ])
    def test_no_copy_generalises_the_allowance_or_the_unmetered_claim(self, relative):
        text = ts_strings(read(relative)) if relative.endswith(".ts") else page_text(read(relative))
        for pattern in (r"not gated in code at any tier", r"never call the meter", r"Every re-check route",
                        r"needs no account[:(] ?(?:\()?\d+ a day per address",
                        r"re-checks? (?:is|are) (?:allowed|limited)[^.]*\d+ a day per address without an account"):
            assert not re.search(pattern, text, re.I), f"{relative}: {pattern}"
        # an "N a day per address" figure is only ever about the file verifier or the validator
        for m in re.finditer(r"[^.;]*\b\d+ a day per address", text):
            assert re.search(r"file verifier|validator|validation|evidence re-checks|separation", m.group(0), re.I), \
                f"{relative}: {m.group(0)!r} attaches a per-address cap to something unspecific"

    def test_the_layout_footer_states_the_account_rule_and_both_allowances(self):
        no_account, _ = _allowance_sentences()
        free = PLANS["free"]
        diff = getattr(free, METERED_SCOPES["machinery_diff"])
        text = page_text(read("app/layout.tsx"))
        assert no_account in text
        sentence = (f"The file verifier allows {free.validations_per_day} a day per address and manifest diff {diff}; "
                    "declaration, bundle, passport and attestation checks are not metered.")
        assert sentence in text, f"the footer must say: {sentence}"
        assert not re.search(r"other re-checks are not metered|every re-check is unmetered", text, re.I)

    def test_the_file_verifier_has_the_validators_limit_but_its_own_counter(self, client):
        limit = PLANS["free"].validations_per_day
        assert PLANS["free"].validations_per_day == limit  # the same number ...
        body = {"track": "actively_exploited_vulnerability", "stage": "early_warning", "payload": {}}
        assert [client.post("/v1/spec/validate", json=body).status_code for _ in range(limit)] == [200] * limit
        assert client.post("/v1/spec/validate", json=body).status_code == 429
        # ... counted separately: the verifier still answers from the same address.
        assert client.post("/v1/evidence/verify", content=b"{}",
                           headers={"Content-Type": "application/json"}).status_code != 429
        assert "evidence_verify" not in METERED_SCOPES and "validate" in METERED_SCOPES

    @pytest.mark.parametrize("relative", ["README.md", "docs/pricing.md", "docs/index.md", "docs/claims-registry.md"])
    def test_no_copy_says_the_verifier_shares_the_validators_allowance(self, relative):
        text = page_text(read(relative))
        assert not re.search(r"same daily allowance|same allowance as|spends a unit of the same|shared? (?:the )?counter",
                             text, re.I), relative

    def test_the_readme_says_same_limit_counted_separately(self):
        text = page_text(read("README.md"))
        assert re.search(r"same limit as the Article 14 validator, counted separately", text)


# ---------------------------------------------------------------------------
# 10. /ai: the demo connection is a demo
# ---------------------------------------------------------------------------
class TestAiPageIsHonestAboutTheDemoConnection:
    def test_no_file_says_the_control_plane_or_platform_is_a_real_connection_not_a_demo(self):
        pattern = re.compile(r"not a demo|real connection(?! wizard)|real integration layer", re.I)
        offenders = []
        roots = [ROOT / "app", ROOT / "docs"]
        files = [p for r in roots for p in r.rglob("*") if p.is_file() and p.suffix in {".ts", ".tsx", ".md", ".json"}]
        files += [p for p in (ROOT / "public").rglob("*") if p.is_file() and p.suffix in {".txt", ".json"}]
        files += [ROOT / "README.md"]
        for path in files:
            text = ts_strings(path.read_text(encoding="utf-8", errors="ignore"))
            if pattern.search(text):
                offenders.append(str(path.relative_to(ROOT)))
        assert not offenders, offenders

    def test_the_ai_ops_solution_is_described_without_overclaiming(self):
        text = ts_strings(read("app/lib/solutions.ts"))
        headline = re.search(r"slug: 'ai-ops'.*?headline: '([^']+)'", text, re.S).group(1)
        assert "demo" not in headline.lower() and "real" not in headline.lower(), headline
        assert re.search(r"integration layer", headline)

    def test_llms_txt_and_the_page_both_say_the_demo_connection_is_read_only(self):
        for relative in ("app/ai/page.tsx", "public/llms.txt"):
            text = page_text(read(relative))
            assert "shared demo connection" in text and "read-only" in text, relative

    def test_the_page_says_what_is_read_only_and_for_whom(self):
        text = page_text(read("app/ai/page.tsx"))
        assert "demo connection" in text and "read-only" in text
        assert re.search(r"Register or Cell", text) and re.search(r"bind", text)

    def test_that_is_what_the_code_enforces(self):
        orchestrator = read("src/neuralbridge/ai/orchestrator.py")
        assert "The shared demo connection is read-only" in orchestrator
        tenancy = read("src/neuralbridge/ai/tenancy.py")
        assert "demo_writable_by_paid" in tenancy and 'DEMO_WRITABLE_ENV = "NEURALBRIDGE_AI_DEMO_WRITABLE_BY_PAID"' in tenancy
        plans = {p["tier"]: p for p in _fallback_plans()}
        assert any("demo connection" in i and "writes need Register or Cell" in i for i in plans["free"]["includes"])


# ---------------------------------------------------------------------------
# 11. SECURITY.md promises no response time
# ---------------------------------------------------------------------------
class TestSecurityPolicyPromisesNoResponseTime:
    def test_no_hours_figure(self):
        text = read("SECURITY.md")
        assert not re.search(r"\b\d+\s*(?:hours|business days|days)\b", text, re.I)
        assert re.search(r"no response[- ]time (?:commitment|guarantee|SLA)|does not promise a response time",
                         text, re.I)

    def test_the_reporting_address_is_not_changed_by_this_slice(self):
        assert "security@neuralbridge.ai" in read("SECURITY.md")  # a founder decision: left as it was


# ---------------------------------------------------------------------------
# 12. unreproducible "prior run" claim
# ---------------------------------------------------------------------------
class TestNoUnreproduciblePriorRunClaim:
    @pytest.mark.parametrize("relative", ["app/page.tsx", "public/llms.txt", "README.md", "docs/index.md"])
    def test_absent(self, relative):
        assert not re.search(r"prior run|previous run against", page_text(read(relative)), re.I)


# ---------------------------------------------------------------------------
# 13. generated imagery is disclosed on every page that shows it
# ---------------------------------------------------------------------------
def _local_imports(path: Path) -> list[Path]:
    found = []
    for spec in re.findall(r"from '(\.[^']*)'", path.read_text(encoding="utf-8")):
        base = (path.parent / spec).resolve()
        for candidate in (base.with_suffix(".tsx"), base.with_suffix(".ts"), base / "index.tsx", base / "index.ts"):
            if candidate.exists():
                found.append(candidate)
                break
    return found


def _reaches(path: Path, target: str, seen: set[Path] | None = None) -> bool:
    seen = seen if seen is not None else set()
    if path in seen:
        return False
    seen.add(path)
    return any(dep.name == target or _reaches(dep, target, seen) for dep in _local_imports(path))


class TestGeneratedImageryIsDisclosed:
    CAPTION = "Illustrative images, not photographs of a customer site. The images are generated."

    def test_pages_that_show_rotating_imagery_are_found(self):
        pages = [p for p in (ROOT / "app").rglob("page.tsx") if _reaches(p, "RotatingImage.tsx")]
        names = {str(p.relative_to(ROOT / "app")) for p in pages}
        assert {"page.tsx", "developers/page.tsx", "solutions/[slug]/page.tsx"} <= names

    def test_each_of_them_renders_the_caption_component(self):
        missing = [str(p.relative_to(ROOT)) for p in (ROOT / "app").rglob("page.tsx")
                   if _reaches(p, "RotatingImage.tsx") and "<ImageryNote" not in p.read_text(encoding="utf-8")]
        assert not missing, f"generated imagery is shown without a disclosure on: {missing}"

    def test_the_caption_is_visible_text_not_alt_text_or_a_title(self):
        component = page_text(read("app/components/ImageryNote.tsx"))
        assert self.CAPTION in component
        source = read("app/components/ImageryNote.tsx")
        assert "aria-hidden" not in source and "sr-only" not in source and "display: 'none'" not in source
        css = read("app/globals.css")
        rule = re.search(r"\.imagery-note\s*\{([^}]*)\}", css)
        assert rule and "display: none" not in rule.group(1)
        size = re.search(r"font-size:\s*([\d.]+)rem", rule.group(1))
        assert size and 0.7 <= float(size.group(1)) <= 0.9, "small, but not unreadably so"

    def test_the_images_really_are_generated_so_the_caption_is_true(self):
        images = read("app/lib/images.ts")
        assert re.search(r"independently generated photoreal frames", images)


# ---------------------------------------------------------------------------
# 14. /status is a static checklist
# ---------------------------------------------------------------------------
class TestStatusPageIsDescribedAsAStaticChecklist:
    def test_title_and_description_do_not_pose_as_live_status(self):
        source = read("app/status/page.tsx")
        title = re.search(r"title: '([^']+)'", source).group(1)
        description = re.search(r"description:\s*'([^']+)'", source).group(1)
        assert "checklist" in title.lower()
        assert re.search(r"\bstatic\b", description) and "does not" in description
        assert "checked at build time" not in description
        assert "index: false" in source

    def test_the_footer_and_llms_txt_call_it_a_checklist(self):
        assert "Deploy status" not in read("app/layout.tsx")
        assert "Deploy status" not in read("public/llms.txt")
        assert "Deploy checklist" in read("app/layout.tsx")


# ---------------------------------------------------------------------------
# 15. smaller items
# ---------------------------------------------------------------------------
class TestSmallerItems:
    def test_the_orphan_llm_txt_is_gone_and_nothing_points_at_it(self):
        assert not (ROOT / "public" / "llm.txt").exists()
        offenders = []
        for top in ("app", "public", "docs", "tests", "tests-e2e", "scripts", "deploy", ".github"):
            for path in (ROOT / top).rglob("*") if (ROOT / top).exists() else []:
                if path.is_file() and path.suffix in {".ts", ".tsx", ".py", ".md", ".txt", ".json", ".yml", ".sh", ".toml"}:
                    if path.name in ("test_site_honesty.py", "site-honesty.spec.ts"):
                        continue
                    if re.search(r"(?<!\w)llm\.txt", path.read_text(encoding="utf-8", errors="ignore")):
                        offenders.append(str(path.relative_to(ROOT)))
        assert not offenders, offenders

    def test_the_sitemap_does_not_invent_a_modification_date(self):
        source = read("app/sitemap.ts")
        assert "new Date(" not in source and "lastModified" not in source

    def test_the_search_index_does_not_call_hand_typed_docs_generated(self):
        source = read("app/lib/search-index.ts")
        entry = re.search(r"title: 'Pricing \(docs\)'[^}]*blurb: '([^']*)'", source)
        assert entry and not re.search(r"generated", entry.group(1), re.I)

    def test_every_static_sitemap_route_is_in_the_search_index(self):
        routes = set(re.findall(r"\$\{SITE_URL\}(/[a-z/-]*)`", read("app/sitemap.ts")))
        routes = {r for r in routes if not r.endswith("/")}
        assert {"/ai", "/privacy", "/contact", "/verify", "/roadmap"} <= routes
        index = read("app/lib/search-index.ts")
        hrefs = set(re.findall(r"href: '([^']+)'", index)) | {"/docs"}
        missing = sorted(r for r in routes if r not in ("/", "/docs") and r not in hrefs)
        assert not missing, f"indexable pages missing from the search index: {missing}"

    def test_privacy_and_contact_lead_with_an_h1(self):
        for relative in ("app/privacy/page.tsx", "app/contact/page.tsx"):
            source = read(relative)
            assert len(re.findall(r"<h1\b", source)) == 1, relative
            assert source.index("<h1") < (source.index("<h2") if "<h2" in source else len(source)), relative
        css = read("app/globals.css")
        assert re.search(r"\.section-head h1", css), "the section-head heading style must cover h1 too"

    def test_docs_pages_get_a_description_from_their_first_paragraph(self):
        page = read("app/docs/[[...slug]]/page.tsx")
        assert re.search(r"description:\s*\w+", page)
        docs = read("app/lib/docs.ts")
        assert "export function firstParagraph" in docs or "description" in docs

    def test_a_docs_page_renders_one_h1_even_when_the_source_has_several(self):
        docs = read("app/lib/docs.ts")
        assert "export function singleH1" in docs
        assert docs.count("singleH1(marked.parse(") == 2  # loadDoc and loadRootDoc
        assert read("deploy/assurance/WATCH.md").count("\n# ") >= 2  # the case that needs it

    def test_the_search_input_keeps_a_visible_focus_style(self):
        css = read("app/globals.css")
        rule = re.search(r"\.search-input\s*\{([^}]*)\}", css).group(1)
        removed = re.search(r"outline:\s*(none|0)\b", rule)
        if removed:
            assert re.search(r"\.search-input-row:focus-within\s*\{[^}]*(outline|box-shadow|border-color)", css), \
                "outline is removed from .search-input and nothing shows focus instead"
        assert not removed, "outline: none on the search input; show focus on the row instead"
        assert re.search(r"\.search-input-row:focus-within\s*\{[^}]*outline:\s*[^;]*solid", css)


# ---------------------------------------------------------------------------
# docs descriptions are built by the real function, on the real documents
# ---------------------------------------------------------------------------
def _node(script: str) -> object:
    import shutil

    node = shutil.which("node")
    assert node, "node is not installed; the docs.ts checks need it"
    version = subprocess.run([node, "--version"], capture_output=True, text=True, check=True).stdout  # noqa: S603
    assert int(version.strip().lstrip("v").split(".")[0]) >= 22, "node >= 22 runs docs.ts directly"
    done = subprocess.run(  # noqa: S603 - fixed argv; the script is a constant in this file
        [node, "--experimental-strip-types", "--no-warnings", "--input-type=module", "-e", script],
        capture_output=True, text=True, check=False, cwd=ROOT, timeout=120,
    )
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


class TestDocsDescriptions:
    def test_first_paragraph_keeps_identifiers_and_drops_markup(self):
        sample = ("# Title\n\n<!-- note -->\n\nCall `verify_chain` on [the ledger](ledger.md) with **care**, "
                  "_not_ haste; snake_case_word and 2*3 stay. More words follow so that the paragraph is long enough.\n")
        out = _node("const m = await import('./app/lib/docs.ts');"
                    f"process.stdout.write(JSON.stringify(m.firstParagraph({json.dumps(sample)})));")
        assert out.startswith("Call verify_chain on the ledger with care, not haste; snake_case_word and 2*3 stay.")
        assert "](" not in out and "`" not in out and "**" not in out

    def test_a_long_paragraph_is_cut_at_a_word_boundary_within_200_characters(self):
        sample = "word " * 80
        out = _node("const m = await import('./app/lib/docs.ts');"
                    f"process.stdout.write(JSON.stringify(m.firstParagraph({json.dumps(sample)})));")
        assert len(out) <= 201 and out.endswith("\u2026") and "wor\u2026" not in out

    def test_every_real_docs_description_is_made_of_words_that_are_in_its_source(self):
        docs = _node("""
          const m = await import('./app/lib/docs.ts');
          const out = [];
          for (const { slug } of m.listDocSlugs()) {
            const d = m.loadDoc(slug.length ? slug : undefined);
            out.push({ slug: slug.join('/'), description: d.description, file: d.editPath });
          }
          process.stdout.write(JSON.stringify(out));
        """)
        assert len(docs) >= 14
        for doc in docs:
            source = read(doc["file"])
            description = doc["description"]
            assert description, doc["slug"]
            for token in re.findall(r"[A-Za-z0-9_]+(?:[./-][A-Za-z0-9_]+)*", description.rstrip("\u2026")):
                assert token in source, f"{doc['slug']}: {token!r} is not in {doc['file']} (markup stripped too eagerly?)"
            assert not re.search(r"[`<>]|\]\(|\*\*", description), doc["slug"]
            assert not re.search(r"\(\d[\d,]* tests?\)|\b\d[\d,]* tests\b", description), \
                f"{doc['slug']}: a test count in metadata goes stale: {description!r}"

    def test_the_stale_test_count_is_out_of_the_docs_source(self):
        assert not re.search(r"\(\d+ tests\)", read("docs/assurance/index.md"))


# ---------------------------------------------------------------------------
# README: one adapter vocabulary, taken from its own status table
# ---------------------------------------------------------------------------
class TestReadmeAdapterWordingIsConsistent:
    def test_nothing_in_the_readme_calls_the_adapters_supported(self):
        text = read("README.md")
        assert not re.search(r"supported[- ]adapter|Supported Adapter", text, re.I)
        assert not re.search(r"small set of supported", text, re.I)

    def test_the_readme_carries_the_same_adapter_note_as_the_site_and_docs(self):
        note = ts_strings(next(r["note"] for r in _site_status_rows() if r["area"] == "Small set of working adapters"))
        assert note in page_text(read("README.md"))
        assert note in page_text(read("docs/platform.md"))


# ---------------------------------------------------------------------------
# tidiness
# ---------------------------------------------------------------------------
class TestSourceTidiness:
    @pytest.mark.parametrize("relative", ["app/sitemap.ts", "app/components/IntentModule.tsx", "app/lib/platformStatus.ts"])
    def test_no_whitespace_only_or_trailing_space_lines(self, relative):
        bad = [n for n, line in enumerate(read(relative).splitlines(), 1) if line != line.rstrip()]
        assert not bad, f"{relative}: trailing whitespace on lines {bad}"

    def test_the_intent_header_comment_says_each_thing_once(self):
        head = read("app/components/IntentModule.tsx").split("const INTENTS")[0]
        assert head.count("tests/test_site_honesty.py") == 1
        assert head.count("sealed as") == 1
        assert not re.search(r"fails\s+// if|and fails if a line shown is not\s+// there", head)
