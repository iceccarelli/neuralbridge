# Phase 5 — optional-dependency honesty (Agent E)

Scope: make every genuinely-optional third-party adapter SDK installable as
its own extra, and confirm CI does not hard-fail when it is absent — the
same honesty pattern Phase 3 established for `google-cloud-bigquery` (then
generalized to `mongodb`'s SDK) in `tests/test_ai.py`'s
`TestGolden011SafeDiscoveryAllowlistSanity`.

## What was found

Grepping `src/` for module-level vendor-SDK imports inside
`neuralbridge/adapters/**` turned up three adapters (all marked
"Experimental/evolving" in `reports/NEURALBRIDGE-AI-CAPABILITY-MATRIX.md`)
that hard-import a third-party SDK nothing else in the repo requires:

| Adapter | File | SDK imported | Was in an extras group? |
| --- | --- | --- | --- |
| BigQuery | `src/neuralbridge/adapters/databases/bigquery.py` | `google.api_core`, `google.cloud.bigquery` | No |
| MongoDB | `src/neuralbridge/adapters/databases/mongodb.py` | `bson`, `motor.motor_asyncio` | No |
| MySQL | `src/neuralbridge/adapters/databases/mysql.py` | `aiomysql`, `pymysql` | No |

`mcp` (used by `src/assurance/mcp/server.py` and
`src/neuralbridge/mcp/server.py`) was already correctly extras'd
(`assurance-mcp`, `neuralbridge-ai-mcp`) and is additionally installed
unconditionally by `requirements/base.txt` for CI's own test job — no
change needed there.

Other adapters that look database/cloud-flavored (`aws_s3`, `gcs`,
`azure_blob`, `snowflake`, `postgres`) either have no vendor SDK import at
module level (they're stub/mock per the capability matrix) or use a
dependency already in core (`asyncpg` for Postgres) — left untouched.

## Fix

`pyproject.toml` `[project.optional-dependencies]`: added three new extras
groups, following the existing per-component naming/commenting style:

```
bigquery = ["google-cloud-bigquery>=3.11.0"]
mongodb  = ["motor>=3.3.0"]
mysql    = ["aiomysql>=0.2.0", "pymysql>=1.1.0"]
```

No change to `dependencies` (core) — none of these are runtime-required
outside their own adapter.

## Test-time cascade check (item 5 of the brief)

Verified nothing outside `neuralbridge/adapters/databases/{bigquery,mongodb,mysql}.py`
themselves imports those adapter classes at module scope (`main.py`,
`api/service.py`, `core/router.py`, `core/gateway.py` all resolve adapters
by string/dynamic lookup, not eager import) — so a missing SDK cannot
cascade into route registration or app startup. The only place in `tests/`
that reaches these imports is `test_ai.py`'s allow-list sanity test, and
it already guards each adapter's import individually
(`importlib.import_module` inside a `try/except ModuleNotFoundError:
continue`, per-adapter, added in Phase 3 commits `08ae0e6` /
`a5c797b`) rather than skipping the whole test — that pattern was kept
as-is rather than replaced, per the brief's "match the existing pattern"
instruction. No lazy-import fix was needed in adapter source: no
unconditional import there reaches app startup.

## Verification

Built a clean venv mirroring CI's own test job exactly
(`pip install -r requirements/test.txt -e .`, i.e. no
`google-cloud-bigquery`, no `motor`/`bson`, no `aiomysql`/`pymysql`
installed; `mcp` present, matching `requirements/base.txt`):

```
$ pip list | grep -iE "mcp|bigquery|pymongo|motor|bson|aiomysql|pymysql"
mcp                                   2.2.0
mcp-types                             2.2.0
neuralbridge-middleware               0.1.1  (editable)
```

```
$ python -m pytest tests/ -q --no-cov -rs
797 passed, 5 warnings in 25.57s
```

```
$ ruff check src/
All checks passed!
```

No collection errors, no hard failures from the missing optional SDKs.
Entitlement/tier-gating tests (`test_assurance_billing.py`,
`test_assurance_mcp.py::test_machine_verify_surfaces_a_real_402_not_a_fake_success`,
`test_assurance_api.py`, `tests/test_ai_buyer_journey.py`'s Cell/Register
golden path) all ran and passed — none of them touch bigquery/mongodb/mysql
and none were skipped.
