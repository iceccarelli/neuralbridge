"""The four public sources, and the exact places they may be fetched from."""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = ["CVE_ID", "DEFAULT_HOSTS", "SOURCES", "SOURCE_ALIASES", "Source", "epss_url",
           "nvd_url", "resolve_source"]

CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,19}$")


@dataclass(frozen=True)
class Source:
    id: str
    label: str
    #: Canonical URL (or URL prefix) the observations of this source claim to come from.
    url: str
    #: The one host a live fetch may use. ``None`` for CSAF: a vendor host must be named by
    #: the operator, never defaulted.
    host: str | None
    max_bytes: int


MIB = 1024 * 1024
SOURCES: dict[str, Source] = {
    "cisa_kev": Source(
        "cisa_kev", "CISA Known Exploited Vulnerabilities catalogue",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "www.cisa.gov", 16 * MIB),
    "nvd_cve_api": Source(
        "nvd_cve_api", "NVD CVE API 2.0",
        "https://services.nvd.nist.gov/rest/json/cves/2.0", "services.nvd.nist.gov", 16 * MIB),
    "first_epss": Source(
        "first_epss", "FIRST EPSS", "https://api.first.org/data/v1/epss", "api.first.org",
        8 * MIB),
    "csaf": Source("csaf", "CSAF 2.0 vendor advisory", "", None, 8 * MIB),
}
SOURCE_ALIASES = {"kev": "cisa_kev", "nvd": "nvd_cve_api", "epss": "first_epss",
                  "csaf": "csaf"}
#: The exact hosts for the three fixed sources. A CSAF vendor host is added by the operator.
DEFAULT_HOSTS = frozenset(s.host for s in SOURCES.values() if s.host)


def resolve_source(name: str) -> Source:
    key = SOURCE_ALIASES.get(name, name)
    if key not in SOURCES:
        raise ValueError(f"unknown source {name!r}; known: {', '.join(sorted(SOURCE_ALIASES))}")
    return SOURCES[key]


def _cves(ids: list[str] | tuple[str, ...]) -> list[str]:
    if not ids:
        raise ValueError("at least one CVE id is needed")
    bad = [i for i in ids if not CVE_ID.match(i)]
    if bad:
        raise ValueError(f"not a CVE id: {bad[0]!r}")
    return list(ids)


def nvd_url(cve_id: str) -> str:
    """One focused request per CVE, as the stress lab's source list prescribes."""
    return f"{SOURCES['nvd_cve_api'].url}?cveId={_cves([cve_id])[0]}"


def epss_url(cve_ids: list[str] | tuple[str, ...]) -> str:
    return f"{SOURCES['first_epss'].url}?cve={','.join(_cves(cve_ids))}"
