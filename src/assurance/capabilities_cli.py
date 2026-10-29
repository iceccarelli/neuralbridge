"""``assurance capabilities``: the catalogue of what this product does and where.

    assurance capabilities                 # a readable table
    assurance capabilities --json          # the same as one document
    assurance capabilities --gaps          # only what is missing on some surface, with reasons
    assurance capabilities --check         # exit 1 if the catalogue and the real surfaces disagree

Exit codes: 0 fine (``--check``: the catalogue matches the code); 1 ``--check`` found a
disagreement; 2 the catalogue could not be built.
"""

from __future__ import annotations

import argparse
import json
import sys

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance capabilities", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--json", action="store_true", help="print the catalogue as JSON")
    p.add_argument("--gaps", action="store_true",
                   help="show only capabilities missing on some surface, with the reason")
    p.add_argument("--check", action="store_true",
                   help="exit 1 if the declared catalogue disagrees with the real surfaces")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        from assurance.api.service import create_app
        from assurance.capabilities import catalogue, problems

        app = create_app()
        if args.check:
            found = problems(app)
            for line in found:
                print(f"PROBLEM  {line}")
            print("the catalogue matches the code." if not found
                  else f"{len(found)} disagreement(s) between the catalogue and the code.")
            return 1 if found else 0
        data = catalogue(app)
    except Exception as exc:  # noqa: BLE001 - report, never traceback at a user
        print(f"error: could not build the catalogue ({exc.__class__.__name__}: {exc})",
              file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(data, indent=2))
        return 0
    rows = data["capabilities"]
    if args.gaps:
        rows = [r for r in rows if any(r[s]["status"] != "present" for s in ("cli", "api", "mcp"))]
    width = max(len(r["id"]) for r in rows) if rows else 10
    print(f"{'capability':<{width}}  cli      api      mcp")
    for r in rows:
        cells = []
        for s in ("cli", "api", "mcp"):
            st = r[s]["status"]
            cells.append({"present": "yes", "by_design": "no*", "planned": "PLAN",
                          "declared_but_missing": "MISS"}[st])
        print(f"{r['id']:<{width}}  {cells[0]:<7}  {cells[1]:<7}  {cells[2]:<7}")
        if args.gaps:
            for s in ("cli", "api", "mcp"):
                if r[s]["status"] in ("by_design", "planned"):
                    print(f"    {s}: {r[s]['status']} - {r[s]['reason']}")
    c = data["counts"]
    print(f"\n{len(data['capabilities'])} capabilities. no* = absent by design, PLAN = a known gap.")
    for s in ("cli", "api", "mcp"):
        print(f"  {s}: {c[s]['present']} present, {c[s]['by_design']} by design, "
              f"{c[s]['planned']} planned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
