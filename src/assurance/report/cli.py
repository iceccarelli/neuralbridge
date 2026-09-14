"""``assurance report`` — the page a plant manager reads, and a demo to fill it.

    demo    build a complete worked fleet from nothing and report on it
    build   render a report from a ledger you already have

``assurance report demo --out demo/`` is the thirty-second answer to "what does
this actually do". It writes a real ledger — real collection through real
normalisation rules, real verification, real intervention records — and an HTML
report over it. Nothing is stubbed; the data is invented and the page says so.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import ComponentAdvisory
from assurance.fleet.declaration import DeclarationOfConformity
from assurance.report.demo import DEMO_NOTICE, build_demo
from assurance.report.render import ReportInput, render_report

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance report",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    dm = verbs.add_parser("demo", help="build a worked fleet and report on it")
    dm.add_argument("--out", required=True, type=Path,
                    help="directory to build the demo in")
    dm.add_argument("--organisation", default="Demonstration")

    bd = verbs.add_parser("build", help="render a report from a ledger")
    bd.add_argument("--ledger", required=True, type=Path)
    bd.add_argument("--out", required=True, type=Path, help="the .html to write")
    bd.add_argument("--organisation", default="")
    bd.add_argument("--prepared-by", default="")
    bd.add_argument("--advisory", type=Path, default=None,
                    help="fan this advisory across the fleet in the report")
    bd.add_argument("--declaration", type=Path, action="append", default=[],
                    help="repeatable: check these declarations against the machines")
    bd.add_argument("--notice", default="")

    return p


def _cmd_demo(args: argparse.Namespace) -> int:
    out = Path(args.out)
    fleet = build_demo(out)
    html = render_report(ReportInput(
        ledger=EvidenceLedger(fleet.ledger_path),
        organisation=args.organisation,
        prepared_by="assurance report demo",
        advisory=fleet.advisory,
        declarations=fleet.declarations,
        notice=DEMO_NOTICE,
    ))
    page = out / "report.html"
    page.write_text(html, encoding="utf-8")

    print(f"built a worked fleet in {out}")
    print(f"  ledger     {fleet.ledger_path}  ({fleet.entries} sealed records)")
    print(f"  exports    {fleet.exports_root}")
    print(f"  plan       {out / 'plan.json'}")
    print(f"  advisory   {out / 'advisory.json'}")
    print(f"  REPORT     {page}")
    print()
    print("  Open the report in a browser. Nothing is stubbed: the collection ran")
    print("  against those export files through the normalisation rules in the")
    print("  plan, and every finding came out of the same engines a customer runs.")
    print()
    print("  Then try:")
    print(f"    python -m assurance fleet list --ledger {fleet.ledger_path}")
    print(f"    python -m assurance fleet advisory {out / 'advisory.json'} "
          f"--ledger {fleet.ledger_path}")
    print(f"    python -m assurance collect check-plan {out / 'plan.json'}")
    return 0


def _cmd_build(args: argparse.Namespace) -> int:
    advisory = (ComponentAdvisory.from_json(args.advisory)
                if args.advisory else None)
    declarations = tuple(DeclarationOfConformity.from_json(p)
                         for p in args.declaration)
    html = render_report(ReportInput(
        ledger=EvidenceLedger(args.ledger),
        organisation=args.organisation,
        prepared_by=args.prepared_by,
        advisory=advisory,
        declarations=declarations,
        notice=args.notice,
    ))
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"report written to {args.out}")
    print("  Self-contained: no network, no scripts. It opens on a laptop in a "
          "plant with no internet, and it prints.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {"demo": _cmd_demo, "build": _cmd_build}
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
