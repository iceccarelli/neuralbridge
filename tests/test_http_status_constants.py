"""Starlette renamed status constants, and neither spelling works over the declared range.

``pyproject.toml`` allows ``fastapi>=0.110`` and so Starlette back to 0.36. In Starlette 0.48
``HTTP_422_UNPROCESSABLE_ENTITY`` became ``HTTP_422_UNPROCESSABLE_CONTENT`` (and the 413, 414
and 416 constants were renamed the same way): the old name is deprecated and warns on every
access (8 of the warnings in the hosted 3.13 run), the new name does not exist before 0.48
(``AttributeError`` on a supported install).

For the renamed codes the source therefore writes the integer, as the rest of ``src/`` already
does for 400/401/402/403/409/422. Any ``status.HTTP_*`` that remains must exist, without
warning, in the installed Starlette.
"""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

from starlette import status

SRC = Path(__file__).resolve().parent.parent / "src"

#: Constants whose name differs between the lower and upper end of the declared Starlette range.
RENAMED = {
    "HTTP_413_REQUEST_ENTITY_TOO_LARGE", "HTTP_413_CONTENT_TOO_LARGE",
    "HTTP_414_REQUEST_URI_TOO_LONG", "HTTP_414_URI_TOO_LONG",
    "HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE", "HTTP_416_RANGE_NOT_SATISFIABLE",
    "HTTP_422_UNPROCESSABLE_ENTITY", "HTTP_422_UNPROCESSABLE_CONTENT",
}


def _status_constants() -> dict[str, list[str]]:
    used: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Attribute) and node.attr.startswith("HTTP_")
                    and isinstance(node.value, ast.Name) and node.value.id == "status"):
                used.setdefault(node.attr, []).append(f"{path.relative_to(SRC)}:{node.lineno}")
    return used


def test_source_does_not_use_a_status_constant_that_was_renamed_across_starlette_versions() -> None:
    bad = {name: where for name, where in _status_constants().items() if name in RENAMED}
    assert not bad, (
        f"{bad}: use the integer (e.g. status_code=422); the named constant is deprecated on "
        "new Starlette and missing on the oldest one the package declares"
    )


def test_every_remaining_status_constant_exists_without_a_deprecation_warning() -> None:
    for name in _status_constants():
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert isinstance(getattr(status, name), int), name
