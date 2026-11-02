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


CSAF_HOST = "csaf.example.invalid"
CSAF_META_URL = f"https://{CSAF_HOST}/.well-known/csaf/provider-metadata.json"
CSAF_DIR = f"https://{CSAF_HOST}/csaf/white"


def csaf_doc(tracking_id: str, *, version: str = "1", current: str = "2026-10-02T08:30:00Z",
             extra: str | None = None) -> dict:
    """A SYNTHETIC CSAF 2.0 advisory (names no real product), accepted by the repo importer."""
    doc = copy.deepcopy(fixture_json("csaf_synthetic.json"))
    doc.pop("_fixture", None)
    t = doc["document"]["tracking"]
    t.update(id=tracking_id, version=version, current_release_date=current)
    doc["document"]["title"] = f"SYNTHETIC {tracking_id} v{version}"
    if extra is not None:
        doc["document"]["notes"].append({"category": "general", "text": extra})
    return doc


def provider_metadata(directory: str = CSAF_DIR) -> dict:
    """SYNTHETIC provider-metadata.json in the CSAF 2.0 shape."""
    return {"canonical_url": CSAF_META_URL, "last_updated": "2026-10-31T00:00:00Z",
            "list_on_CSAF_aggregators": False, "metadata_version": "2.0",
            "mirror_on_CSAF_aggregators": False, "public_openpgp_keys": [],
            "publisher": {"category": "vendor", "name": "Example Controls GmbH",
                          "namespace": "https://example.invalid"},
            "role": "csaf_trusted_provider",
            "distributions": [{"directory_url": directory}]}


def changes_csv(*rows: tuple[str, str]) -> bytes:
    return "".join(f'"{p}","{t}"\n' for p, t in rows).encode()


def nvd_doc(*cves: dict) -> dict:
    return {"resultsPerPage": len(cves), "startIndex": 0, "totalResults": len(cves),
            "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-10-31T00:00:00.000",
            "vulnerabilities": [{"cve": copy.deepcopy(c)} for c in cves]}


def csaf_doc_with_status(tracking_id: str, status: str, **kw: str) -> dict:
    """A SYNTHETIC CSAF advisory whose tracking.status is ``status`` (verbatim)."""
    doc = csaf_doc(tracking_id, **kw)
    doc["document"]["tracking"]["status"] = status
    return doc
