"""Two ways of writing SQLite code leak a connection that is never closed.

* ``with sqlite3.connect(path) as db:`` ends a *transaction* (commit, or rollback on error) when
  the block exits. It does not close the connection. Python's documentation says so, and
  CPython 3.13 reports every one as ``ResourceWarning: unclosed database``.
* ``sqlite3.connect(path).execute(...)`` keeps the connection alive only as long as the cursor
  it returned, then drops it unclosed.

A hosted run of the suite on 3.13 counted about 176 of these warnings. Warnings are not
silenced for them; the code is fixed, and this static check keeps the two spellings out of
``src/`` and ``tests/`` on every Python version (the warning itself exists only on 3.13+).
Use ``contextlib.closing(sqlite3.connect(...))``, ``try/finally: db.close()`` or, in tests,
``tests.support_sqlite.connect`` / ``rows`` / ``scalar``.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {ROOT / "tests" / "support_sqlite.py", ROOT / "tests" / "test_sqlite_connection_hygiene.py"}


def _is_connect(node: ast.AST) -> bool:
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
            and isinstance(node.func.value, ast.Name) and node.func.value.id == "sqlite3")


def offences(source: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if _is_connect(item.context_expr):
                    found.append((node.lineno, "`with sqlite3.connect(...)` does not close"))
        if isinstance(node, ast.Attribute) and _is_connect(node.value):
            found.append((node.lineno, f"`sqlite3.connect(...).{node.attr}` drops the "
                                       "connection unclosed"))
    return found


def _is_name(node: ast.AST, name: str) -> bool:
    """``name`` itself, or a tuple/list holding it: the connection, not something derived from it."""
    if isinstance(node, ast.Name):
        return node.id == name
    if isinstance(node, (ast.Tuple, ast.List)):
        return any(_is_name(e, name) for e in node.elts)
    return False


def _escapes(func: ast.AST, name: str) -> bool:
    """Is ``name`` closed, returned, yielded, stored on an object or handed to a callable?

    Any of those means the function is not the one that has to close it (a factory, a fixture,
    a context-manager helper) or that it does close it.
    """
    for node in ast.walk(func):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "close" and isinstance(node.func.value, ast.Name)
                and node.func.value.id == name):
            return True
        if isinstance(node, ast.For) and any(isinstance(n, ast.Name) and n.id == name
                                             for n in ast.walk(node.iter)):
            if any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                   and n.func.attr == "close" for b in node.body for n in ast.walk(b)):
                return True   # for c in (db, other): c.close()
        if isinstance(node, (ast.Return, ast.Yield, ast.YieldFrom)) and node.value is not None:
            if _is_name(node.value, name):
                return True
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Attribute) for t in node.targets):
            if _is_name(node.value, name):
                return True
        if isinstance(node, ast.Call) and any(isinstance(a, ast.Name) and a.id == name
                                              for a in (*node.args, *(k.value for k in node.keywords))):
            return True   # e.g. closing(db), stack.enter_context(db), helper(db)
    return False


def unclosed_assignments(source: str) -> list[tuple[int, str]]:
    """``db = sqlite3.connect(...)`` in a function that never closes, returns or hands off ``db``."""
    found: list[tuple[int, str]] = []
    tree = ast.parse(source)
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(func):
            if (isinstance(node, ast.Assign) and _is_connect(node.value) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name)
                    and not _escapes(func, node.targets[0].id)):
                found.append((node.lineno, f"`{node.targets[0].id} = sqlite3.connect(...)` is "
                                           "never closed in this function"))
    return found


def _python_files() -> list[Path]:
    return [p for base in ("src", "tests") for p in sorted((ROOT / base).rglob("*.py"))
            if p not in ALLOWED]


def test_no_source_or_test_file_uses_a_leaking_sqlite_pattern() -> None:
    bad = {str(p.relative_to(ROOT)): hits for p in _python_files()
           if (hits := offences(p.read_text(encoding="utf-8"))
               + unclosed_assignments(p.read_text(encoding="utf-8")))}
    assert not bad, (
        "these leak a SQLite connection (use contextlib.closing / try-finally / "
        f"tests.support_sqlite): {bad}"
    )


def test_the_detector_sees_both_leaking_spellings_and_accepts_the_closing_ones() -> None:
    assert offences("import sqlite3\nwith sqlite3.connect('x') as db:\n    pass\n")
    assert offences("import sqlite3\nrows = sqlite3.connect('x').execute('select 1').fetchall()\n")
    assert offences("import sqlite3\nasync def f():\n    async with sqlite3.connect('x') as d:\n"
                    "        pass\n")
    assert not offences("import sqlite3, contextlib\n"
                        "with contextlib.closing(sqlite3.connect('x')) as db:\n    db.execute('s')\n")
    assert not offences("import sqlite3\ndb = sqlite3.connect('x')\ntry:\n    db.execute('s')\n"
                        "finally:\n    db.close()\n")


def test_an_assigned_connection_that_is_never_closed_is_found() -> None:
    leaky = "import sqlite3\ndef f():\n    db = sqlite3.connect('x')\n    return db.execute('s')\n"
    assert unclosed_assignments(leaky)
    closed = "import sqlite3\ndef f():\n    db = sqlite3.connect('x')\n    try:\n        db.execute('s')\n    finally:\n        db.close()\n"
    factory = "import sqlite3\ndef f():\n    db = sqlite3.connect('x')\n    db.row_factory = None\n    return db\n"
    handed = "import sqlite3, contextlib\ndef f():\n    db = sqlite3.connect('x')\n    with contextlib.closing(db):\n        pass\n"
    assert not unclosed_assignments(closed)
    assert not unclosed_assignments(factory)
    assert not unclosed_assignments(handed)
