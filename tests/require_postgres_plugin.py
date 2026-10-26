"""``NEURALBRIDGE_REQUIRE_POSTGRES``: turn a Postgres skip into a failure, on request.

A skip is a gate that did not run. The Postgres-backed tests skip honestly when no server
is reachable, which is right on a laptop and wrong in CI, where the workflow provides the
service. With ``NEURALBRIDGE_REQUIRE_POSTGRES`` set to ``1``, ``true`` or ``yes`` (any
case), a skip whose reason names PostgreSQL is reported as a failure carrying the same
reason. Unset, or any other value, nothing changes. Skips for other reasons are never
touched, and an expected failure (xfail) is not a skip.

Free of heavy imports on purpose: ``tests/test_require_postgres_hook.py`` loads this
module by name into a throwaway pytest run (``-p tests.require_postgres_plugin``).
"""

from __future__ import annotations

import os
import re

import pytest

ENV = "NEURALBRIDGE_REQUIRE_POSTGRES"
_TRUE = {"1", "true", "yes"}
_POSTGRES = re.compile(r"postgres", re.IGNORECASE)


def postgres_required() -> bool:
    return os.environ.get(ENV, "").strip().lower() in _TRUE


def _reason(report: pytest.TestReport) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):  # type: ignore[type-arg]
    outcome = yield
    report = outcome.get_result()
    if not report.skipped or hasattr(report, "wasxfail") or not postgres_required():
        return
    reason = _reason(report)
    if _POSTGRES.search(reason):
        report.outcome = "failed"
        report.longrepr = (f"{ENV} is set, so a skipped Postgres test is a failure "
                           f"(the gate did not run): {reason}")
