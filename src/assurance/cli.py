"""Top-level command line: ``python -m assurance <domain> ...``.

If the reader of the output goes away (``... | head``), the command ends quietly with exit
141 (128 + SIGPIPE, as a shell reports it) and no traceback. Whatever it seals (a ledger
entry, a case) is sealed before it prints, so the records are complete; the exit code is not
the command's verdict. The one thing that is NOT recoverable from the ledger is a secret
printed once, so ``billing grant`` and ``billing issue-key`` handle a closed output
themselves (they revoke the key they could not deliver and say so on stderr) instead of
leaving it to this handler.
"""

from __future__ import annotations

import os
import sqlite3
import sys

from assurance.core.errors import AssuranceError

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


#: "Could not do that": the same code every verb already uses for an unreadable input.
EXIT_COULD_NOT_RUN = 2

_OPERATOR_ERRORS = (
    AssuranceError, OSError, sqlite3.Error, ValueError, LookupError, TypeError, AttributeError,
    RecursionError,
)


def _operator_message(exc: BaseException) -> str:
    if isinstance(exc, sqlite3.DatabaseError) and "not a database" in str(exc):
        return ("error: that file is not a ledger (it is not a SQLite database). Check the path "
                "you gave for --ledger, or ASSURANCE_LEDGER.")
    if isinstance(exc, AssuranceError | OSError | ValueError):
        return f"error: {exc}"
    return (f"error: could not complete ({type(exc).__name__}: {exc}). The input may have the "
            "wrong shape (for example a list where an object is expected). Set "
            "ASSURANCE_DEBUG=1 to see the traceback.")


def silence_stdout() -> None:
    """Point stdout at /dev/null so the interpreter's own flush at exit cannot fail again."""
    try:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    except (OSError, ValueError):
        pass


def _run(argv: list[str]) -> int:
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


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        code = _run(args)
        # Output is block-buffered on a pipe: a reader that left early fails here, not in
        # the print that produced the text. Flush inside the guard so both cases end alike.
        sys.stdout.flush()
        return code
    except BrokenPipeError:
        # `assurance ... | head`: the reader left while we were printing. Whatever the
        # command seals (a ledger entry, a case) is sealed before it prints, so there
        # is nothing to repair and nothing to say. Point stdout at /dev/null so the
        # interpreter's own flush at exit does not raise the same error again.
        silence_stdout()
        return EXIT_BROKEN_PIPE
    except _OPERATOR_ERRORS as exc:
        # The person at the keyboard gave a verb a file it cannot use: a directory, a JSON
        # array where it wants an object, a ledger path that is not a database. That is "could
        # not do that" (2), not an uncaught exception, which a shell reports as 1: the code
        # several verbs use for a finding. ASSURANCE_DEBUG=1 brings the traceback back.
        if os.environ.get("ASSURANCE_DEBUG"):
            raise
        print(_operator_message(exc), file=sys.stderr)
        return EXIT_COULD_NOT_RUN


if __name__ == "__main__":
    raise SystemExit(main())
