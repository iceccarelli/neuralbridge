#!/usr/bin/env python
"""Export the assurance API's real OpenAPI 3 schema to public/openapi.json.

This is the single source of truth the marketing site's /developers page
links to, and what an agent (Cursor, a CI bot, another Claude session)
should fetch to discover the actual routes, request/response shapes, and
auth scheme — never a hand-typed summary that can drift into fiction.

Regenerate after any change to src/assurance/api/*_routes.py:

    python scripts/export_openapi.py
"""

from __future__ import annotations

import json
from pathlib import Path

from assurance.api.service import app

OUT = Path(__file__).resolve().parent.parent / "public" / "openapi.json"


def main() -> int:
    spec = app.openapi()
    OUT.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n")
    print(f"wrote {OUT} ({len(spec['paths'])} paths)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
