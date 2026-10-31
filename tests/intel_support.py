"""Shared helpers for the ``intel`` tests.

Everything that stands in for the network is a CONTRACT FIXTURE: a recorded or hand-written
payload served by an in-memory transport. It proves how the code handles a response of that
shape. It is NOT live integration and nothing here claims it is. The payload files live in
``tests/fixtures/intel/`` and each says in its ``_fixture`` key whether it was minimized from
a public source or is synthetic.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from assurance.intel.transport import TransportError

FIXTURES = Path(__file__).parent / "fixtures" / "intel"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_json(name: str) -> dict:
    return json.loads(fixture_bytes(name))


def dump(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True).encode()


class Clock:
    """A deterministic UTC clock that ticks one minute per call."""

    def __init__(self) -> None:
        self.now = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        self.now += timedelta(minutes=1)
        return self.now


class ContractFixtureTransport:
    """CONTRACT FIXTURE transport: answers from a table; records every call it receives."""

    label = "contract-fixture (not live integration)"

    def __init__(self, responses: Mapping[str, tuple[int, bytes] | Exception]) -> None:
        self.responses = dict(responses)
        self.calls: list[tuple[str, Mapping[str, str], float]] = []

    def get(self, url: str, headers: Mapping[str, str], timeout: float) -> tuple[int, bytes]:
        self.calls.append((url, headers, timeout))
        out = self.responses.get(url)
        if out is None:
            raise TransportError("no recorded response for this URL")
        if isinstance(out, Exception):
            raise out
        return out


def kev_doc(*cves: str, version: str = "2026.10.30") -> dict:
    rows = [{"cveID": c, "vendorProject": "Example", "product": "Widget",
             "vulnerabilityName": "SYNTHETIC", "dateAdded": "2026-10-01",
             "shortDescription": "SYNTHETIC", "requiredAction": "n/a", "dueDate": "2026-10-22",
             "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []} for c in cves]
    return {"title": "SYNTHETIC KEV", "catalogVersion": version,
            "dateReleased": "2026-10-30T00:00:00Z", "count": len(rows), "vulnerabilities": rows}


def epss_doc(*rows: tuple[str, str, str, str]) -> dict:
    return {"status": "OK", "status-code": 200, "version": "1.0", "total": len(rows),
            "offset": 0, "limit": 100,
            "data": [{"cve": c, "epss": e, "percentile": p, "date": d} for c, e, p, d in rows]}


def nvd_doc(*cves: dict) -> dict:
    return {"resultsPerPage": len(cves), "startIndex": 0, "totalResults": len(cves),
            "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-10-31T00:00:00.000",
            "vulnerabilities": [{"cve": copy.deepcopy(c)} for c in cves]}
