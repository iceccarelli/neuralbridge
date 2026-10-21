"""The MCP connector page lists the tools ``assurance-mcp`` really has.

The page once said "six tools - two free, four paid" and marked the change-queue
tools "Not yet a tool" while ``server.py`` carried ten, and quoted a line count
the file had outgrown. The page now renders from one ``MCP_TOOLS`` array; this
pins that array to the ``@mcp.tool()`` functions, and to the route each one's
docstring says it calls, by reading both sources as text.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGE = (ROOT / "app" / "connectors" / "mcp" / "page.tsx").read_text(encoding="utf-8")
SERVER = (ROOT / "src" / "assurance" / "mcp" / "server.py").read_text(encoding="utf-8")
ROUTES_TS = (ROOT / "app" / "lib" / "routes.ts").read_text(encoding="utf-8")


def _server_tools() -> dict[str, str]:
    """``{tool name: "METHOD /path"}`` from the first line of each tool's docstring."""
    found: dict[str, str] = {}
    pattern = re.compile(
        r"@mcp\.tool\(\)\s*async def (\w+)\([^)]*\)[^:]*:\s*\"\"\"\s*"
        r"((?:GET|POST|PUT|PATCH|DELETE) \S+)", re.S)
    for name, route in pattern.findall(SERVER):
        found[name] = route
    return found


def _page_tools() -> dict[str, tuple[str, str, bool]]:
    block = PAGE[PAGE.index("const MCP_TOOLS: McpTool[] = ["):]
    block = block[:block.index("];")]
    return {
        m.group(1): (m.group(2), m.group(3), m.group(4) == "true")
        for m in re.finditer(
            r"name: '(\w+)', route: '([^']+)', tier: '(\w+)', agentWrite: (true|false)", block)
    }


def test_the_page_lists_exactly_the_tools_server_py_registers():
    registered = len(re.findall(r"^@mcp\.tool\(\)", SERVER, re.M))
    assert registered >= 10
    assert set(_server_tools()) == set(_page_tools())
    assert len(_server_tools()) == registered, "a tool's docstring no longer starts with its route"


def test_each_tool_names_the_route_its_docstring_calls():
    server = _server_tools()
    for name, (route, _tier, _write) in _page_tools().items():
        assert route == server[name], name


def test_every_tool_route_is_a_row_of_the_route_table():
    rows = {f"{m} {p}" for m, p in re.findall(r"\{ method: '(\w+)', path: '([^']+)'", ROUTES_TS)}
    for name, (route, _tier, _write) in _page_tools().items():
        assert route in rows, f"{name}: {route} is not in app/lib/routes.ts"


def test_the_tier_shown_for_a_tool_is_the_tier_of_its_route():
    tiers = {f"{m} {p}": t for m, p, t in
             re.findall(r"\{ method: '(\w+)', path: '([^']+)', tier: '(\w+)'", ROUTES_TS)}
    for name, (route, tier, _write) in _page_tools().items():
        assert tiers[route] == tier, name


def test_the_agent_write_tools_are_exactly_the_post_tools_that_are_not_verification():
    tools = _page_tools()
    writers = {n for n, (_r, _t, w) in tools.items() if w}
    assert writers == {"change_claim", "change_advance", "change_reverify"}
    # a human-only decision has no tool, and the page says so
    for name in tools:
        assert not any(w in name for w in ("decide", "close", "reject", "defer", "resume", "resolve", "waive"))
    assert "human-only" in PAGE.lower()
    assert "asserted by the caller" in PAGE


def test_the_page_makes_none_of_its_old_claims():
    for stale in ("six tools", "Six tools", "two free, four paid", "under 150 lines"):
        assert stale not in PAGE, stale
    # counts come from the array, not from typed numbers
    assert "{TOOL_COUNT} tools" in PAGE
