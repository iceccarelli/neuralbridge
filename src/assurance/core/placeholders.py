"""One definition of "this is a template value, not data", for every path that takes input.

Three paths used to disagree: the kit refused ``tbd`` and ``change me`` but enrolled the serial
``000000``; SBOM review refused ``tbd`` and accepted ``000000``; inventory import accepted
``TBD``, ``000000`` and an all-zero SHA-256. A person who learns one path's rules and meets
another's is told "fine" about a value that is not data, and it is then sealed as real.

:func:`placeholder_problem` answers for a single field and never echoes the value, so a caller
whose rule is "a reason never contains a cell value" (inventory import) can use it as is.
"""

from __future__ import annotations

__all__ = ["PLACEHOLDER_WORDS", "KIT_STARTER_VALUES", "placeholder_problem", "starter_values"]

#: Compared case-insensitively after trimming and collapsing runs of spaces.
PLACEHOLDER_WORDS = frozenset({
    # what the kit's starter files ship with
    "change me", "changeme", "your company gmbh", "your company",
    "your.name@yourcompany.example", "yourcompany",
    # what people type when they do not know yet
    "tbd", "to be determined", "todo", "to do", "xxx", "n/a", "na", "none", "null", "nil",
    "unknown", "unspecified", "not supplied", "not available", "placeholder", "example",
    "sample", "test", "dummy", "serial", "serial number", "-", "--", "?", "??",
})

#: The values ``kit init`` writes for fields that are legitimate values in their own right
#: (a plant can be called "Plant 1" and be in Germany). They are not placeholders, so
#: :func:`placeholder_problem` does not refuse them; the kit names them as "still the starter
#: value" so that nobody seals them by not noticing them.
KIT_STARTER_VALUES = {
    "site": "Plant 1", "country": "DE", "year": "2025", "serial": "CELL-0412",
}


def placeholder_problem(field: str, value: object) -> str | None:
    """Why *value* is not real data for *field*, or ``None``. Empty is not judged here.

    The reason never contains the value.
    """
    if not isinstance(value, str):
        return None
    text = " ".join(value.split())
    if not text:
        return None
    if text.casefold() in PLACEHOLDER_WORDS:
        return f"{field} is a placeholder word, not data"
    stripped = text.replace(" ", "")
    if len(stripped) >= 3 and set(stripped) == {"0"}:
        # Also the null digest: 64 zeros is what an uncomputed hash is written as.
        return f"{field} is all zeros"
    # Not applied to 64-hex digests: a run of one repeated hex digit is how this repository's own
    # fixtures write a stand-in hash ("1" * 64), and a manifest reader cannot tell it from a
    # computed one. An all-zero digest, which is the null hash, is refused above.
    if 4 <= len(stripped) < 64 and len(set(stripped.casefold())) == 1:
        return f"{field} is one character repeated"
    return None


def starter_values(**fields: str) -> dict[str, str]:
    """The fields (``site``, ``country``, ``year``, ``serial``) still holding the kit's starter value."""
    return {k: v for k, v in fields.items()
            if KIT_STARTER_VALUES.get(k) is not None
            and " ".join(str(v).split()).casefold() == KIT_STARTER_VALUES[k].casefold()}
