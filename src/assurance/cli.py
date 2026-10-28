"""Top-level command line: ``python -m assurance <domain> ...``."""

from __future__ import annotations

import os
import sys

#: What a shell reports for a process whose reader went away: 128 + SIGPIPE.
EXIT_BROKEN_PIPE = 141

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
    "supplier": "assurance.supplier.cli",
    "change": "assurance.change.cli",
    "evidence": "assurance.evidence.cli",
    "value": "assurance.value.cli",
    "billing": "assurance.billing.cli",
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

    try:
        return int(import_module(_DOMAINS[domain]).main(rest))
    except BrokenPipeError:
        # `assurance ... | head`: the reader left while we were printing. Whatever the
        # command seals (a ledger entry, a case) is sealed before it prints, so there
        # is nothing to repair and nothing to say. Point stdout at /dev/null so the
        # interpreter's own flush at exit does not raise the same error again.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return EXIT_BROKEN_PIPE


if __name__ == "__main__":
    raise SystemExit(main())
