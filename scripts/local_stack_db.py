#!/usr/bin/env python3
"""Create or drop the throwaway PostgreSQL database used by scripts/local-stack.sh.

    local_stack_db.py create NAME [--seed deploy/ai/seed.sql]
    local_stack_db.py drop   NAME

Connects with NEURALBRIDGE_AI_PG_{HOST,PORT,USER,PASSWORD} (the same variables the /ai backend and
the tests use) to the maintenance database ``postgres``. It only ever creates or drops a database
whose name starts with ``nb_local_``, so it cannot touch a database it did not make by name. The
password is read from the environment and is never printed.

Exit: 0 done | 1 the database operation failed | 2 bad arguments or no connection settings.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path

NAME_RE = re.compile(r"^nb_local_[a-z0-9_]{1,40}$")


def _settings() -> dict[str, object]:
    missing = [v for v in ("HOST", "USER", "PASSWORD") if not os.environ.get(f"NEURALBRIDGE_AI_PG_{v}")]
    if missing:
        print("set NEURALBRIDGE_AI_PG_" + ", NEURALBRIDGE_AI_PG_".join(missing), file=sys.stderr)
        raise SystemExit(2)
    return {
        "host": os.environ["NEURALBRIDGE_AI_PG_HOST"],
        "port": int(os.environ.get("NEURALBRIDGE_AI_PG_PORT", "5432")),
        "user": os.environ["NEURALBRIDGE_AI_PG_USER"],
        "password": os.environ["NEURALBRIDGE_AI_PG_PASSWORD"],
    }


async def _create(name: str, seed: Path | None) -> None:
    import asyncpg

    s = _settings()
    admin = await asyncpg.connect(database="postgres", **s)  # type: ignore[arg-type]
    try:
        if await admin.fetchval("SELECT 1 FROM pg_database WHERE datname = $1", name):
            raise SystemExit(f"database {name} already exists; refusing to reuse it")
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    if seed is not None:
        conn = await asyncpg.connect(database=name, **s)  # type: ignore[arg-type]
        try:
            await conn.execute(seed.read_text(encoding="utf-8"))
        finally:
            await conn.close()


async def _drop(name: str) -> None:
    import asyncpg

    s = _settings()
    admin = await asyncpg.connect(database="postgres", **s)  # type: ignore[arg-type]
    try:
        await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    finally:
        await admin.close()


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] not in ("create", "drop") or not NAME_RE.match(argv[1]):
        print(__doc__, file=sys.stderr)
        print("NAME must match nb_local_[a-z0-9_]+", file=sys.stderr)
        return 2
    cmd, name = argv[0], argv[1]
    seed: Path | None = None
    if cmd == "create" and len(argv) >= 4 and argv[2] == "--seed":
        seed = Path(argv[3])
        if not seed.is_file():
            print(f"seed file not found: {seed}", file=sys.stderr)
            return 2
    try:
        asyncio.run(_create(name, seed) if cmd == "create" else _drop(name))
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - report the type only: a driver message can echo a DSN
        print(f"{cmd} {name} failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(f"{cmd} {name}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
