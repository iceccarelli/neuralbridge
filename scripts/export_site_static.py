#!/usr/bin/env python
"""Render public/llms.txt and public/.well-known/agent.json from scripts/site_static/*.tmpl.

The repository is private and the code proprietary, so the site must not point visitors at it. The
templates are the committed files plus the lines that name the repository, each prefixed ``@repo ``.
With the repository private (the default) those lines are dropped; with it public they are kept
with the prefix removed. The same switch drives the Next.js site (``app/lib/links.ts``)::

    NEXT_PUBLIC_REPO_PUBLIC=true python scripts/export_site_static.py   # public release
    python scripts/export_site_static.py                               # default: no repo links
    python scripts/export_site_static.py --check                       # exit 1 if public/ is stale

Only the exact string ``true`` turns the flag on. ``tests/test_site_repo_links.py`` fails when the
committed files are not what this script writes with the flag off.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "scripts" / "site_static"
MARK = "@repo "

#: template name -> published path under public/
OUTPUTS = {
    "llms.txt.tmpl": ROOT / "public" / "llms.txt",
    "agent.json.tmpl": ROOT / "public" / ".well-known" / "agent.json",
}


def repo_public_from_env() -> bool:
    return os.environ.get("NEXT_PUBLIC_REPO_PUBLIC") == "true"


def render(template: str, repo_public: bool) -> str:
    """The template with its ``@repo `` lines kept (prefix removed) or dropped."""
    out: list[str] = []
    for line in (TEMPLATES / template).read_text(encoding="utf-8").split("\n"):
        if line.startswith(MARK):
            if repo_public:
                out.append(line[len(MARK):])
        else:
            out.append(line)
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--check", action="store_true", help="do not write; exit 1 if a file is stale")
    ap.add_argument("--repo-public", action="store_true", help="override the environment: repo links on")
    args = ap.parse_args(argv)
    public = args.repo_public or repo_public_from_env()

    stale = False
    for template, target in OUTPUTS.items():
        text = render(template, public)
        current = target.read_text(encoding="utf-8") if target.exists() else None
        if args.check:
            if current != text:
                print(f"stale: {target.relative_to(ROOT)} (repo_public={public})")
                stale = True
        elif current != text:
            target.write_text(text, encoding="utf-8")
            print(f"wrote {target.relative_to(ROOT)} (repo_public={public})")
    return 1 if stale else 0


if __name__ == "__main__":
    sys.exit(main())
