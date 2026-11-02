"""One definition of what a caller-typed person name or declared role may contain.

Several surfaces (HTTP, CLI, MCP, library) seal a name a caller typed into a record whose
other fields the server writes in a small grammar: ``attribution=<basis>``,
``operator=<id> (<role>)``, ``key=<prefix>``, ``;`` between clauses, parentheses around a
role suffix. A reader scanning a sealed record for ``attribution=authenticated_operator``
must be able to believe the token came from the server. A typed name or role must therefore
be unable to contain that grammar.

This module **refuses**; it never silently rewrites. A caller who typed ``a=b`` is told so
and nothing is recorded. (``api.declared_actor.sanitise_declared_role`` is the older,
lenient reducer for roles on routes that must accept free text.)

The rules, applied to the NFKC-normalised text so that full-width ``＝`` / ``；`` / ``（``
are the characters they imitate:

* none of ``=``  ``;``  ``(``  ``)`` (the attribution grammar);
* no Unicode control, format, line/paragraph separator, surrogate, private-use or
  unassigned code point (zero-width joiners, bidi overrides, NUL, newline, tab ...), and
  none of the blank "filler" letters; no space-like character other than one plain space;
* no leading or trailing whitespace, and no run of two spaces;
* at most :data:`MAX_NAME_LENGTH` characters;
* a letter or digit somewhere; and not what automation is called (``bot``, ``system``,
  ``automation`` ... also in look-alike letters), the rule the change workflow already had.

Apostrophes (ASCII and U+2019), hyphens, dots, accented letters and other scripts remain
valid: ``Zoë O’Brien``, ``Jean-Luc Picard``, ``A. N. Other``.

Imports only ``core``, so the machinery layer can use it without importing the change
workflow.
"""

from __future__ import annotations

import re
import unicodedata

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor

__all__ = [
    "ActorNameError",
    "MAX_NAME_LENGTH",
    "MAX_ROLE_LENGTH",
    "actor_grammar_problem",
    "actor_name_problem",
    "checked_person",
    "declared_role_problem",
]

MAX_NAME_LENGTH = 120
MAX_ROLE_LENGTH = 200

#: Characters the server's attribution grammar is made of.
GRAMMAR_CHARACTERS = frozenset("=;()")

#: What the change workflow calls an automated actor: what it is, not who it is.
RESERVED_NAMES = frozenset({
    "automation", "watch", "agent", "service", "system", "bot", "assistant",
    "operator", "ai",
})
#: Code points that render as nothing (or a blank) but are not control/format characters.
_FILLERS = frozenset("ᅟᅠㅤﾠ⠀")
_INVISIBLE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs", "Co", "Cn"})
#: Letters from other scripts that read as Latin ones. A short list of the common ones, not
#: Unicode's confusables table: it closes the obvious disguises of a reserved word.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
    "һ": "h", "ԁ": "d", "ѵ": "v", "к": "k", "м": "m",
    "т": "t", "н": "h",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i",
    "κ": "k", "τ": "t", "υ": "u", "χ": "x", "ε": "e",
    "η": "n", "ς": "s",
    "ɡ": "g", "ı": "i", "ȷ": "j",
})


def _skeleton(name: str) -> str:
    """The name as it would read in Latin letters: NFKC, accents dropped, look-alike
    letters mapped, case folded."""
    norm = unicodedata.normalize("NFKD", unicodedata.normalize("NFKC", name))
    stripped = "".join(c for c in norm if not unicodedata.combining(c))
    return stripped.casefold().translate(_CONFUSABLES)


def _hidden(norm: str) -> str:
    for ch in norm:
        if ch in _FILLERS or unicodedata.category(ch) in _INVISIBLE_CATEGORIES:
            return f"it contains an invisible or control character (U+{ord(ch):04X})"
    return ""


def actor_grammar_problem(name: str) -> str:
    """Why ``name`` could forge or disturb the server's attribution grammar, or ``""``.

    The check every sealing path needs, whatever kind of actor it records: it does not
    judge whether the name could be a *person's* (see :func:`actor_name_problem`).
    """
    if not isinstance(name, str):
        return "the name is not text"
    norm = unicodedata.normalize("NFKC", name)
    hidden = _hidden(norm)
    if hidden:
        return hidden
    for ch in norm:
        if ch in GRAMMAR_CHARACTERS:
            return (f"it contains {ch!r}, which the record's attribution grammar uses "
                    "(= ; and parentheses are not allowed in a name)")
        if ch != " " and (ch.isspace() or unicodedata.category(ch) == "Zs"):
            return f"it contains a space-like character (U+{ord(ch):04X}) other than a space"
    if norm != norm.strip():
        return "it has leading or trailing whitespace"
    if "  " in norm:
        return "it has a run of spaces"
    if len(norm) > MAX_NAME_LENGTH or len(name) > MAX_NAME_LENGTH:
        return f"it is longer than {MAX_NAME_LENGTH} characters"
    return ""


def actor_name_problem(name: str) -> str:
    """Why ``name`` cannot be the name of a person who may be recorded, or ``""``."""
    if not isinstance(name, str) or not name.strip():
        return "no name was given"
    problem = actor_grammar_problem(name)
    if problem:
        return problem
    norm = unicodedata.normalize("NFKC", name)
    if not any(ch.isalnum() for ch in norm):
        return "it has no letter or digit in it"
    # Reserved if every word in it that is not a number is a reserved word: "agent.",
    # "system:", "bot-7", "automation bot", and the same in look-alike letters.
    # "Agent Smith" and "Botticelli" are somebody's name and pass.
    words = [w for w in re.findall(r"[^\W_]+", _skeleton(name)) if not w.isdigit()]
    if words and all(w in RESERVED_NAMES for w in words):
        return f"{name.strip()!r} is what an automated actor is called, not who it is"
    return ""


def declared_role_problem(role: str, *, required: bool = False) -> str:
    """Why ``role`` cannot be sealed as a person's declared role, or ``""``.

    A role is free text, so parentheses are allowed; ``=`` and ``;`` (and their full-width
    forms), invisible characters and absurd lengths are not.
    """
    if not isinstance(role, str):
        return "the role is not text"
    if required and not role.strip():
        return "the person's role is required"
    norm = unicodedata.normalize("NFKC", role)
    if "=" in norm or ";" in norm:
        return "the role is free text and may not contain '=' or ';'"
    hidden = _hidden(norm)
    if hidden:
        return f"the role is free text without invisible characters ({hidden})"
    if len(norm) > MAX_ROLE_LENGTH or len(role) > MAX_ROLE_LENGTH:
        return f"the role is longer than {MAX_ROLE_LENGTH} characters"
    return ""


class ActorNameError(AssuranceError, ValueError):
    """A typed actor name or role cannot be recorded. Nothing was written."""


def checked_person(name: str, role: str = "") -> Actor:
    """An ``Actor`` of kind person from caller-typed words, or :class:`ActorNameError`.

    For command lines and library callers that build the actor themselves. Applies the
    grammar rule to the name and the role rule to the role; whether the name could be a
    person's (not ``bot``) is the decision functions' own refusal.
    """
    problem = actor_grammar_problem(name) or declared_role_problem(role)
    if problem:
        raise ActorNameError(
            f"actor {name[:60]!r} cannot be recorded: {problem}. Nothing was recorded.")
    return Actor(identifier=name, role=role, kind="person")
