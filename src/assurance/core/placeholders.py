"""One definition of "this is a template value, not data", for every path that takes input.

Three paths used to disagree: the kit refused ``tbd`` and ``change me`` but enrolled the serial
``000000``; SBOM review refused ``tbd`` and accepted ``000000``; inventory import accepted
``TBD``, ``000000`` and an all-zero SHA-256. A person who learns one path's rules and meets
another's is told "fine" about a value that is not data, and it is then sealed as real.

:func:`placeholder_problem` answers for a single field and never echoes the value, so a caller
whose rule is "a reason never contains a cell value" (inventory import) can use it as is.
"""

from __future__ import annotations

import unicodedata

__all__ = ["PLACEHOLDER_WORDS", "KIT_STARTER_VALUES", "placeholder_problem", "starter_values"]

#: Compared after normalisation (see :func:`_key`): case, spaces, invisible characters and
#: punctuation do not matter, so ``N/A``, ``n.a.`` and ``n a`` are one entry.
PLACEHOLDER_WORDS = frozenset({
    # what the kit's starter files ship with
    "change me", "changeme", "your company gmbh", "your company",
    "your.name@yourcompany.example", "yourcompany",
    # what people type when they do not know yet
    "tbd", "tbc", "tba", "to be determined", "to be confirmed", "to be advised", "todo",
    "to do", "xxx", "n/a", "na", "not applicable", "none", "null", "nil", "unknown",
    "unknown serial", "no serial", "no serial number", "not known", "not given",
    "not provided", "unspecified", "not supplied", "not available", "placeholder",
    "example", "sample", "test", "dummy", "serial", "serial number",
})

#: The values ``kit init`` writes for fields that are legitimate values in their own right
#: (a plant can be called "Plant 1" and be in Germany). They are not placeholders, so
#: :func:`placeholder_problem` does not refuse them; the kit names them as "still the starter
#: value" so that nobody seals them by not noticing them.
KIT_STARTER_VALUES = {
    "site": "Plant 1", "country": "DE", "year": "2025", "serial": "CELL-0412",
}


def _key(text: str) -> str:
    """*text* reduced to what a person typed: no invisible, space or punctuation characters,
    folded to lower case. ``n.a.``, ``N/A`` and ``n a`` all become ``na``."""
    return "".join(
        ch for ch in text.casefold()
        if unicodedata.category(ch) not in ("Cf", "Zs", "Zl", "Zp", "Pd", "Po", "Pc", "Cc"))


_WORDS = frozenset(_key(w) for w in PLACEHOLDER_WORDS)

#: A run of one repeated character is a placeholder only when it is this long: "1111" and
#: "AAAA" are serials somebody was given; "000000" and "xxxxxx" are not.
_MIN_REPEAT = 6


def placeholder_problem(field: str, value: object) -> str | None:
    """Why *value* is not real data for *field*, or ``None``. Empty is not judged here.

    The reason never contains the value. A value made only of invisible or punctuation
    characters (``—``, ``???``, a zero-width space) is a placeholder: nothing was typed.
    """
    if not isinstance(value, str) or not value:
        return None
    core = _key(value)
    if not core:
        return f"{field} has no letters or digits in it"
    if core in _WORDS:
        return f"{field} is a placeholder word, not data"
    if len(core) >= _MIN_REPEAT and set(core) == {"0"}:
        # Also the null digest: 64 zeros is what an uncomputed hash is written as.
        return f"{field} is all zeros"
    # Not applied to 64-hex digests: a run of one repeated hex digit is how this repository's own
    # fixtures write a stand-in hash ("1" * 64), and a manifest reader cannot tell it from a
    # computed one. An all-zero digest, which is the null hash, is refused above.
    if _MIN_REPEAT <= len(core) < 64 and len(set(core)) == 1:
        return f"{field} is one character repeated"
    return None


def starter_values(**fields: str) -> dict[str, str]:
    """The fields (``site``, ``country``, ``year``, ``serial``) still holding the kit's starter value."""
    return {k: v for k, v in fields.items()
            if KIT_STARTER_VALUES.get(k) is not None
            and " ".join(str(v).split()).casefold() == KIT_STARTER_VALUES[k].casefold()}
