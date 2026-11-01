#!/usr/bin/env python
"""Export the capability catalogue to public/capabilities.json, the website's contract.

``src/assurance/capabilities.py`` is the one place that says what this product can do and on which
of the command line, the HTTP API and the MCP server. The website renders this file (see
``/docs/capabilities``) instead of a hand-typed list, and ``tests/test_site_capabilities_contract.py``
fails when the committed file is not what this script would write now.

Regenerate after any change to the CLI parsers, the API routes, the MCP tools or the catalogue:

    python scripts/export_capabilities.py

The output is deterministic: no timestamp, capabilities sorted by id, keys sorted. A surface a
capability does not have says which of two things that is: ``by_design`` (a decision, with its
reason) or ``planned`` (a known gap, with its reason). Nothing here says a surface is deployed,
sold or behaves identically to another; ``available`` means the command, route or tool exists in
this build.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

OUT = Path(__file__).resolve().parent.parent / "public" / "capabilities.json"

SCHEMA = "neuralbridge.site-capabilities/1"
SURFACES = ("cli", "api", "mcp")
#: The catalogue's word for a surface that exists, and the word this contract uses for it.
AVAILABLE = "available"


def _surface(entry: dict[str, Any]) -> dict[str, Any]:
    if entry["status"] == "present":
        return {"status": AVAILABLE, "names": sorted(entry["names"])}
    if entry["status"] in ("by_design", "planned"):
        return {"status": entry["status"], "reason": entry["reason"]}
    # "declared_but_missing" can only come from a stale declaration; refuse to publish it.
    raise ValueError(f"unpublishable surface status {entry['status']!r}")


def build() -> dict[str, Any]:
    """The contract, computed from the live catalogue and the live surfaces."""
    from assurance import capabilities
    from assurance.api.service import app

    cat = capabilities.catalogue(app)
    found = capabilities.discover(app)
    caps = sorted(
        (
            {
                "id": c["id"],
                "service": c["service"],
                "title": c["summary"],
                "surfaces": {s: _surface(c[s]) for s in SURFACES},
            }
            for c in cat["capabilities"]
        ),
        key=lambda c: c["id"],
    )

    cli_domains: dict[str, list[str]] = {}
    for command in sorted(found["cli"]):
        domain, _, rest = command.partition(" ")
        verbs = cli_domains.setdefault(domain, [])
        verb = rest.split(" ", 1)[0]
        if verb and verb not in verbs:
            verbs.append(verb)

    return {
        "schema": SCHEMA,
        "generated_by": "scripts/export_capabilities.py, from src/assurance/capabilities.py",
        "meaning": (
            "available: the command, route or tool exists in this build. It does not say the "
            "surfaces behave identically, that anything is deployed, or what a plan includes. "
            "by_design: the surface is absent on purpose, for the reason given. planned: a "
            "known gap, listed so it is not hidden."
        ),
        "counts": {
            "capabilities": len(caps),
            "cli_commands": len(found["cli"]),
            "cli_domains": len(cli_domains),
            "api_routes": len(found["api"]),
            "mcp_tools": len(found["mcp"]),
            "surfaces": {
                s: {
                    "available": cat["counts"][s]["present"],
                    "by_design": cat["counts"][s]["by_design"],
                    "planned": cat["counts"][s]["planned"],
                }
                for s in SURFACES
            },
        },
        "cli_domains": cli_domains,
        "mcp_tools": sorted(found["mcp"]),
        "capabilities": caps,
    }


def render() -> str:
    return json.dumps(build(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    OUT.write_text(render(), encoding="utf-8")
    data = json.loads(OUT.read_text(encoding="utf-8"))
    print(f"wrote {OUT} ({data['counts']['capabilities']} capabilities)")  # noqa: T201
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
