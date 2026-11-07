"""Seed the /ai browser journey: real customer accounts, a real customer database role, real tables.

Uses the same mechanisms production and tests/test_ai_tenancy.py use, no bypass flags:

* entitlements: ``assurance.billing.accounts.AccountStore`` (``ASSURANCE_ACCOUNTS``), the one store the
  platform API and the assurance API both read. A Register account A and B, a Cell account, and a
  Validator (free) account that holds a real key but no control-plane entitlement.
* the customer's database: a throwaway PostgreSQL role with a RANDOM password and grants on two tables
  only. Paid callers bind it through ``POST /api/v1/ai/connections`` (the product's own route); its
  password is the "credential" the specs hunt for in the DOM, network bodies and browser storage.
* the shared demo database the free caller may read: ``demo_customers`` from ``deploy/ai/seed.sql``.

    NEURALBRIDGE_AI_PG_{HOST,PORT,USER,PASSWORD,DATABASE}=... ASSURANCE_ACCOUNTS=... \\
        python scripts/e2e_seed_ai.py seed OUT.json
    ... python scripts/e2e_seed_ai.py count  OUT.json MARKER   # rows in e2e_runs carrying MARKER
    ... python scripts/e2e_seed_ai.py teardown OUT.json        # drop the role and tables

The PG_USER given must be allowed to create roles (a throwaway cluster's owner). Local test credentials for a
throwaway database only: never run against a deployed service.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src")]

import asyncpg  # noqa: E402


def _admin() -> dict:
    need = ("HOST", "USER", "PASSWORD", "DATABASE")
    missing = [f"NEURALBRIDGE_AI_PG_{n}" for n in need if not os.environ.get(f"NEURALBRIDGE_AI_PG_{n}")]
    if missing:
        sys.exit(f"e2e_seed_ai: set {', '.join(missing)} (a throwaway PostgreSQL; see docs/ai-local-setup.md)")
    e = os.environ
    return {
        "host": e["NEURALBRIDGE_AI_PG_HOST"], "port": int(e.get("NEURALBRIDGE_AI_PG_PORT", "5432")),
        "user": e["NEURALBRIDGE_AI_PG_USER"], "password": e["NEURALBRIDGE_AI_PG_PASSWORD"],
        "database": e["NEURALBRIDGE_AI_PG_DATABASE"],
    }


async def _seed(out: str) -> None:
    from assurance.billing.accounts import AccountStore

    admin = _admin()
    role = "e2e_cust_" + secrets.token_hex(4)
    password = secrets.token_urlsafe(24)
    conn = await asyncpg.connect(**admin)
    try:
        for stmt in (
            "DROP TABLE IF EXISTS e2e_runs",
            "CREATE TABLE e2e_runs (id serial PRIMARY KEY, note text NOT NULL)",
            f"CREATE ROLE {role} LOGIN PASSWORD '{password}' NOSUPERUSER NOCREATEDB NOCREATEROLE",
            f"GRANT CONNECT ON DATABASE \"{admin['database']}\" TO {role}",
            f"GRANT SELECT, INSERT ON e2e_runs TO {role}",
            f"GRANT USAGE ON SEQUENCE e2e_runs_id_seq TO {role}",
        ):
            await conn.execute(stmt)
        # The shared demo table (deploy/ai/seed.sql) the free caller reads through the seeded connection.
        await conn.execute((ROOT / "deploy" / "ai" / "seed.sql").read_text())
    finally:
        await conn.close()

    store = AccountStore(os.environ["ASSURANCE_ACCOUNTS"])

    def account(name: str, tier: str) -> str:
        acct = store.upsert_account(email=f"{name}@e2e.invalid", tier=tier, company=f"e2e-{name}")
        return store.issue_key(acct.id, label="e2e-ai")

    seed = {
        "register_a": account("ai-register-a", "register"),
        "register_b": account("ai-register-b", "register"),
        "cell": account("ai-cell", "cell"),
        "free_account": account("ai-free", "free"),
        "invalid_key": "nb-not-a-real-key-" + secrets.token_hex(8),
        "customer_db": {
            "host": admin["host"], "port": admin["port"], "user": role, "password": password,
            "database": admin["database"],
        },
    }
    Path(out).write_text(json.dumps(seed))


async def _count(out: str, marker: str) -> int:
    conn = await asyncpg.connect(**_admin())
    try:
        return await conn.fetchval("SELECT count(*) FROM e2e_runs WHERE note = $1", marker)
    finally:
        await conn.close()


async def _teardown(out: str) -> None:
    role = json.loads(Path(out).read_text())["customer_db"]["user"]
    conn = await asyncpg.connect(**_admin())
    try:
        await conn.execute("DROP TABLE IF EXISTS e2e_runs")
        if await conn.fetchval("SELECT 1 FROM pg_roles WHERE rolname = $1", role):
            await conn.execute(f"DROP OWNED BY {role}")  # its CONNECT grant, so the role can go
            await conn.execute(f"DROP ROLE {role}")
    finally:
        await conn.close()


def main(argv: list[str]) -> None:
    if len(argv) >= 3 and argv[1] == "seed":
        asyncio.run(_seed(argv[2]))
    elif len(argv) == 4 and argv[1] == "count":
        sys.stdout.write(f"{asyncio.run(_count(argv[2], argv[3]))}\n")
    elif len(argv) == 3 and argv[1] == "teardown":
        asyncio.run(_teardown(argv[2]))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
