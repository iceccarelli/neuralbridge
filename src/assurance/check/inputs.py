"""Reading a JSON object a command was handed: a path, or ``-`` for standard input.

The stateless verbs (``check``, ``fleet advisory-check``) take their inputs as files so a
person can pipe one machine's manifest straight in. Anything unreadable, empty, not JSON or not
an object stops the command with a message and exit 2; there is no partial reading and no
default, because a check run on a guess is a verdict nobody should rely on.

Standard input can be read once, so at most one input of a command may be ``-``
(:func:`one_stdin`).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError

__all__ = ["InputError", "one_stdin", "read_json_object"]


class InputError(AssuranceError):
    """An input the command cannot use. The command ends with exit 2 and says why."""


def one_stdin(**inputs: str | Path | None) -> None:
    """Refuse a command line that asks for standard input twice."""
    asked = [name for name, spec in inputs.items() if spec is not None and str(spec) == "-"]
    if len(asked) > 1:
        raise InputError(
            f"{' and '.join(asked)} were both given as '-'; standard input can be read once. "
            "Give one of them as a file.")


def read_json_object(spec: str | Path, what: str) -> dict[str, Any]:
    """The JSON object in the file ``spec``, or on standard input when ``spec`` is ``-``."""
    try:
        if str(spec) == "-":
            text = sys.stdin.read()
        else:
            text = Path(spec).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        reason = getattr(exc, "strerror", None) or "not readable as UTF-8 text"
        raise InputError(f"cannot read the {what} ({spec}): {reason}") from exc
    if not text.strip():
        raise InputError(f"the {what} ({spec}) is empty. Nothing was checked.")
    try:
        doc = json.loads(text)
    except ValueError as exc:
        raise InputError(f"the {what} ({spec}) is not valid JSON ({exc}). "
                         "Nothing was checked.") from exc
    if not isinstance(doc, dict):
        raise InputError(f"the {what} ({spec}) must be a JSON object, not "
                         f"{type(doc).__name__}. Nothing was checked.")
    return doc
