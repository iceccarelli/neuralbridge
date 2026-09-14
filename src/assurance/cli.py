"""Top-level command line: ``python -m assurance <domain> ...``."""

from __future__ import annotations

import sys

_DOMAINS = {
    "report": "assurance.report.cli",
    "collect": "assurance.collect.cli",
    "art14": "assurance.security.art14.cli",
    "machine": "assurance.machine.cli",
    "machinery": "assurance.machinery.cli",
    "fleet": "assurance.fleet.cli",
    "bridge": "assurance.bridge.cli",
    "watch": "assurance.watch.cli",
    "attest": "assurance.attest.cli",
    "kit": "assurance.kit.cli",
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"-h", "--help"}:
        print(__doc__)
        print("domains:")
        for name in _DOMAINS:
            print(f"  {name}")
        print("\ntry: python -m assurance art14 --help")
        print("     python -m assurance report demo --out demo/")
        return 0
    domain, rest = argv[0], argv[1:]
    if domain not in _DOMAINS:
        print(f"unknown domain {domain!r}; known: {', '.join(_DOMAINS)}", file=sys.stderr)
        return 2
    from importlib import import_module

    return int(import_module(_DOMAINS[domain]).main(rest))


if __name__ == "__main__":
    raise SystemExit(main())
