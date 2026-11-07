"""docs/integrations.md is generated from the adapter source and is registered on the site.

The directory is the answer to "which integrations work?". It must not drift from the code (adapter added,
reclassified, or removed) and must not say more than tests/test_adapter_fail_closed.py enforces.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "docs" / "integrations.md").read_text(encoding="utf-8")


def _generator():
    spec = importlib.util.spec_from_file_location("export_integrations", ROOT / "scripts" / "export_integrations.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_committed_page_equals_generator_output():
    assert PAGE == _generator().render(), "run: python scripts/export_integrations.py"


def test_every_adapter_has_a_row_and_the_counts_are_stated():
    inv = _generator().inventory()
    assert len(inv) == 22
    for row in inv:
        assert f"| `{row['type']}` |" in PAGE
    assert "22 adapters: 2 supported with limits, 3 with a real client path" in PAGE and "17 canned" in PAGE


def test_only_postgres_and_rest_are_called_supported():
    rows = [ln for ln in PAGE.splitlines() if ln.startswith("| `") and "Supported, with limits" in ln]
    assert sorted(ln.split("|")[1].strip() for ln in rows) == ["`postgres`", "`rest`"]


def test_page_discloses_what_is_not_claimed():
    assert "No adapter other than PostgreSQL and REST is exercised" in PAGE
    assert "local HTTP server" in PAGE and "no third-party API" in PAGE and "DNS rebinding" in PAGE
    assert "sends no HTTP request" not in PAGE
    assert "cannot even be imported" in PAGE
    assert "NEURALBRIDGE_ALLOW_MOCK_ADAPTERS" in PAGE


def test_page_is_registered_on_the_site_and_in_mkdocs():
    docs = (ROOT / "app" / "lib" / "docs.ts").read_text(encoding="utf-8")
    assert "href: '/docs/integrations'" in docs and "slug: ['integrations']" in docs
    assert "file: 'docs/integrations.md'" in docs
    assert "'/docs/integrations'" in (ROOT / "app" / "lib" / "search-index.ts").read_text(encoding="utf-8")
    assert re.search(r"Integrations: integrations\.md", (ROOT / "mkdocs.yml").read_text(encoding="utf-8"))


def test_readme_adapter_table_matches_the_code():
    """The README states exactly one of Supported / Evolving / Not implemented for every adapter, from `backend`."""
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    section = readme.split("## Adapter Status", 1)[1].split("\n## ", 1)[0]
    stated = {m.group(1): m.group(2) for m in re.finditer(r"^\| `(\w+)` \| (Supported|Evolving|Not implemented) \|", section, re.M)}
    word = {"real": "Supported", "partial": "Evolving", "mock": "Not implemented"}
    expected = {str(r["type"]): word[str(r["backend"])] for r in _generator().inventory()}
    assert stated == expected
