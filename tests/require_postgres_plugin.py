"""``NEURALBRIDGE_REQUIRE_POSTGRES``: turn a Postgres skip into a failure, on request.

A skip is a gate that did not run. The Postgres-backed tests skip honestly when no server
is reachable, which is right on a laptop and wrong in CI, where the workflow provides the
service. With ``NEURALBRIDGE_REQUIRE_POSTGRES`` set to ``1``, ``true`` or ``yes`` (any
case), a skip whose reason names PostgreSQL is reported as a failure carrying the same
reason. Unset, or any other value, nothing changes. Skips for other reasons are never
touched, and an expected failure (xfail) is not a skip.

The same hook also serves ``NEURALBRIDGE_REQUIRE_NODE``: with it set, a skip whose reason says
``node_modules`` or ``node`` is missing is a failure. The Site CI job (which runs the
node-dependent tests/test_site_{seo,product_pages,repo_links}.py after ``npm ci``) sets it, so
a site gate that could not run turns the job red instead of green. It is one hook because
pytest allows one ``pytest_runtest_makereport`` per conftest namespace.

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

NODE_ENV = "NEURALBRIDGE_REQUIRE_NODE"
_NODE = re.compile(r"node_modules|node is not installed", re.IGNORECASE)


def postgres_required() -> bool:
    return os.environ.get(ENV, "").strip().lower() in _TRUE


def node_required() -> bool:
    return os.environ.get(NODE_ENV, "").strip().lower() in _TRUE


def _reason(report: pytest.TestReport) -> str:
    longrepr = report.longrepr
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo):  # type: ignore[type-arg]
    outcome = yield
    report = outcome.get_result()
    if not report.skipped or hasattr(report, "wasxfail"):
        return
    reason = _reason(report)
    for env, required, pattern in ((ENV, postgres_required(), _POSTGRES),
                                   (NODE_ENV, node_required(), _NODE)):
        if required and pattern.search(reason):
            report.outcome = "failed"
            report.longrepr = (f"{env} is set, so a skipped test of this kind is a failure "
                               f"(the gate did not run): {reason}")
            return
