"""Public-source intelligence layer: KEV, NVD, EPSS and CSAF observations, with provenance.

Offline by construction: nothing in this package's parsing, storage or view code imports a
network client. The network is an injected :class:`~assurance.intel.transport.Transport`; the
single real one lives in :mod:`assurance.intel.transport_urllib` and is imported only by
``assurance intel refresh --live``.

``unchecked`` / ``unavailable`` / ``unknown`` are first-class outcomes here: a missing EPSS
score is not 0.0, an absent KEV listing is not "not exploited", an absent NVD record is not
"no CVE". See :mod:`assurance.intel.view` for how observations reach the fleet pipeline.
"""

from assurance.intel.fetch import fetch, ingest_bytes, ingest_file
from assurance.intel.store import IntelStore, Observation
from assurance.intel.transport import Transport
from assurance.intel.view import Candidate, Enrichment, IntelReport, build_report

__all__ = ["Candidate", "Enrichment", "IntelReport", "IntelStore", "Observation", "Transport",
           "build_report", "fetch", "ingest_bytes", "ingest_file"]
