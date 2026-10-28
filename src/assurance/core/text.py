"""Text that came from somebody else, on its way to a person's terminal or a comparison.

An advisory is third-party content. Its title is printed under a "CLEAR" or "EXPOSED" line;
its product names decide whether a machine matches. Two failures follow from taking either at
face value, and both look like an ordinary working tool:

* a title carrying a terminal escape (``ESC[2J``), a carriage return or a bidirectional
  override can rewrite what the person reading the screen sees;
* a zero-width space inside a product name makes two names that read identically compare
  as different, so an affected machine silently fails to match.

:func:`neutralise` answers the first (for anything *printed*): every character that is not
safe to render is replaced by a visible ``\\uXXXX`` escape, never dropped, so the reader can see
that something was there. :func:`invisible_characters` answers the second (for anything
*compared*): it reports the characters so the caller can refuse the value, naming them.
"""

from __future__ import annotations

import unicodedata

__all__ = ["invisible_characters", "neutralise", "strip_invisible"]

#: General categories that render as nothing, as a control, or not at all.
_UNSAFE = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})
#: Characters that render as a blank without being a control or format character.
_FILLERS = frozenset("ᅟᅠㅤﾠ⠀᠎")


def _unsafe(char: str) -> bool:
    return unicodedata.category(char) in _UNSAFE or char in _FILLERS


def _escape(char: str) -> str:
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 \
        else f"\\U{code:08x}"


def neutralise(text: object, *, multiline: bool = False) -> str:
    """``text`` made safe to print: unsafe characters become visible escapes.

    With ``multiline`` a newline and a tab survive (a detail paragraph); otherwise they are
    escaped too, so a single-line field cannot start a fake line of its own.
    """
    out: list[str] = []
    for char in str(text):
        if multiline and char in "\n\t":
            out.append(char)
        elif _unsafe(char):
            out.append(_escape(char))
        else:
            out.append(char)
    return "".join(out)


def invisible_characters(text: str) -> list[str]:
    """Each distinct unsafe character in ``text`` as ``U+XXXX``, in order of appearance."""
    found: list[str] = []
    for char in text:
        if _unsafe(char):
            label = f"U+{ord(char):04X}"
            if label not in found:
                found.append(label)
    return found


def strip_invisible(text: str) -> tuple[str, list[str]]:
    """``text`` with every unsafe character removed, and the characters that were."""
    removed = invisible_characters(text)
    kept = "".join(" " if char in "\n\r\t" else char
                   for char in text if not _unsafe(char) or char in "\n\r\t")
    return " ".join(kept.split()), removed
