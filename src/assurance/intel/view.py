"""From recorded observations to what the fleet pipeline can use.

Two outputs, and nothing in between:

``candidates``
    :class:`~assurance.fleet.advisory.ComponentAdvisory` objects, produced **only** where the
    existing model can say it without inventing anything. The matcher compares supplier, name
    and version labels by equality (``fleet/advisory.py``); it has no range arithmetic and this
    package adds none. So:

    * a CSAF document the repo's own importer accepts becomes its advisory, unchanged
      (``import_record`` and all);
    * an NVD record contributes an affected artefact only for a CPE match that names one exact
      version (``cpe:2.3:o:vendor:product:V2.001:...`` with no version bounds). A bounded range
      (``versionEndExcluding`` ...) is **not** turned into a list of versions; it is kept as
      text in the artefact's ``version_note`` (which the matcher treats as "a person must
      read this") and in ``not_representable``;
    * KEV carries no versions, so it never yields an advisory.

``enrichments``
    One record per CVE id, attaching what each source said, with a citation (observation
    sequence, URL, sha256, retrieval time) for every statement:

    ==============  ==============================================================
    kev             ``listed`` | ``not_listed_in_kev`` | ``unchecked`` (no KEV
                    observation exists). ``not_listed_in_kev`` is explicitly NOT
                    "not exploited": it carries ``not_established``.
    epss            ``available`` (score, percentile, score_date: time-sensitive)
                    | ``unavailable``. Never 0.0 for a missing score.
    nvd             ``present`` | ``rejected`` | ``unknown`` (no record).
    cvss            every metric NVD published, as published, unranked.
    conflicts       NVD and a vendor CSAF disagreeing, with both citations.
    ==============  ==============================================================

Conflicts are surfaced, never resolved. Two rules, both string equality on folded labels:
a CSAF *fixed* version that NVD lists as affected (``fixed_listed_as_affected``), and a CSAF
fixed version that is not any of NVD's ``versionEndExcluding`` boundaries for the same CVE
(``fixed_boundary_differs``). Which source is right is a human's call.

No severity is derived from CVSS, EPSS or KEV: candidates default to ``safety_relevant``
exactly as the CSAF importer does, because a public feed does not say whether a safety
function is affected. Software here drafts; people decide.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from assurance.core.identity import parse_utc
from assurance.fleet.advisory import (
    AdvisoryError,
    AdvisorySeverity,
    AffectedArtefact,
    ComponentAdvisory,
    fold_text,
)
from assurance.fleet.csaf import advisory_from_csaf, is_plain_version_token
from assurance.intel.parsers import ParsedFeed, parser_for
from assurance.intel.sources import SOURCES
from assurance.intel.store import IntelStore, Observation

__all__ = ["Candidate", "Enrichment", "IntelReport", "build_report"]

TRUST_UNSIGNED_PUBLIC = "unsigned_public_feed"
KEV_NOT_ESTABLISHED = ("absence from the KEV catalogue does not establish that the "
                       "vulnerability is not exploited, only that CISA has not listed it")
EPSS_UNAVAILABLE_NOTE = "no EPSS score is not a score of 0.0; the probability is unknown"
_BOUNDS = ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding",
           "versionEndExcluding")
_CPE_SPLIT = re.compile(r"(?<!\\):")


@dataclass(frozen=True)
class Candidate:
    advisory: ComponentAdvisory
    source: str
    trust: str
    citation: dict[str, Any]
    notes: tuple[str, ...] = ()
    #: Statements the source made that the advisory model cannot hold, as text.
    not_representable: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"advisory": self.advisory.to_dict(), "advisory_content_hash":
                self.advisory.content_hash(), "source": self.source, "trust": self.trust,
                "citation": self.citation, "notes": list(self.notes),
                "not_representable": list(self.not_representable)}


@dataclass(frozen=True)
class Enrichment:
    cve_id: str
    kev: dict[str, Any]
    epss: dict[str, Any]
    nvd: dict[str, Any]
    cvss: tuple[dict[str, Any], ...]
    conflicts: tuple[dict[str, Any], ...]
    not_representable: tuple[str, ...] = ()
    csaf_advisories: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"cve_id": self.cve_id, "kev": self.kev, "epss": self.epss, "nvd": self.nvd,
                "cvss": list(self.cvss), "conflicts": list(self.conflicts),
                "not_representable": list(self.not_representable),
                "csaf_advisories": list(self.csaf_advisories)}


@dataclass(frozen=True)
class IntelReport:
    candidates: tuple[Candidate, ...]
    enrichments: tuple[Enrichment, ...]
    conflicts: tuple[dict[str, Any], ...]
    #: Accepted observations whose payload could not be re-read (should be empty).
    unreadable: tuple[int, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)


# --------------------------------------------------------------------------- loading
def _reparse(store: IntelStore, obs: Observation) -> ParsedFeed | None:
    body = store.body(obs.sha256)
    if body is None:
        return None
    try:
        return parser_for(obs.source)(body, SOURCES[obs.source].max_bytes)
    except Exception:  # noqa: BLE001 - an unreadable payload is reported, not guessed at
        return None


def _parse_cpe(criteria: str) -> tuple[str, str, str, str, str] | None:
    parts = _CPE_SPLIT.split(criteria)
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    un = [re.sub(r"\\(.)", r"\1", p) for p in parts]
    return un[2], un[3], un[4], un[5], un[6]       # part, vendor, product, version, update


def _key(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", fold_text(text))


@dataclass
class _Nvd:
    exact: dict[tuple[str, str], list[str]] = field(default_factory=dict)
    bounded: list[tuple[str, str, dict[str, str]]] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _walk_nvd(cve: dict[str, Any]) -> _Nvd:
    out = _Nvd()
    for cfg in cve.get("configurations") or []:
        if not isinstance(cfg, dict):
            continue
        combined = str(cfg.get("operator", "")).upper() == "AND"
        for node in cfg.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            matches = [m for m in node.get("cpeMatch") or [] if isinstance(m, dict)
                       and m.get("vulnerable") is True]
            if node.get("negate") is True:
                out.other += [f"negated node: {m.get('criteria', '?')}" for m in matches]
                continue
            for m in matches:
                criteria = str(m.get("criteria", ""))
                cpe = _parse_cpe(criteria)
                bounds = {k: str(m[k]) for k in _BOUNDS if m.get(k)}
                if cpe is None:
                    out.other += [f"unparseable criteria: {criteria[:80]}"]
                    continue
                part, vendor, product, version, update = cpe
                if bounds:
                    out.bounded.append((vendor, product, bounds))
                    continue
                if (part not in ("a", "o", "h") or version in ("*", "-", "")
                        or update not in ("*", "-", "") or "?" in vendor + product + version
                        or "*" in vendor + product + version):
                    out.other.append(f"not one exact version: {criteria}")
                    continue
                versions = out.exact.setdefault((vendor, product), [])
                if version not in versions:
                    versions.append(version)
                if combined:
                    note = ("listed inside an AND configuration; the conditions on the other "
                            "components are not evaluated")
                    if note not in out.notes:
                        out.notes.append(note)
    return out


def _range_text(vendor: str, product: str, bounds: dict[str, str]) -> str:
    return f"{vendor}:{product} " + " ".join(f"{k}={v}" for k, v in sorted(bounds.items()))


def _csaf_products(doc: dict[str, Any]) -> dict[str, tuple[str, str, str]]:
    """product_id -> (vendor, product name, version label), from the branch path."""
    found: dict[str, tuple[str, str, str]] = {}

    def walk(branches: Any, vendor: str, name: str, depth: int) -> None:
        if not isinstance(branches, list) or depth > 32:
            return
        for b in branches:
            if not isinstance(b, dict):
                continue
            cat, label = b.get("category"), str(b.get("name", ""))
            v, n = (label, name) if cat == "vendor" else (vendor, label if cat == "product_name"
                                                          else name)
            prod = b.get("product")
            if isinstance(prod, dict) and isinstance(prod.get("product_id"), str):
                found[prod["product_id"]] = (v, n, label if cat == "product_version" else "")
            walk(b.get("branches"), v, n, depth + 1)

    tree = doc.get("product_tree")
    if isinstance(tree, dict):
        walk(tree.get("branches"), "", "", 0)
    return found


def _csaf_fixed(doc: dict[str, Any]) -> dict[str, list[tuple[str, str, str]]]:
    """CVE -> [(vendor, product, plain fixed version label)]."""
    products = _csaf_products(doc)
    out: dict[str, list[tuple[str, str, str]]] = {}
    for vuln in doc.get("vulnerabilities") or []:
        if not isinstance(vuln, dict) or not isinstance(vuln.get("cve"), str):
            continue
        status = vuln.get("product_status")
        if not isinstance(status, dict):
            continue
        for key in ("fixed", "first_fixed"):
            for pid in status.get(key) or []:
                vendor, product, label = products.get(pid, ("", "", ""))
                if label and is_plain_version_token(label):
                    out.setdefault(vuln["cve"].strip(), []).append((vendor, product, label))
    return out


def _linked(nvd_vendor: str, nvd_product: str, vendor: str, product: str) -> str:
    nv, np_, v, p = _key(nvd_vendor), _key(nvd_product), _key(vendor), _key(product)
    if v and p and (nv in v or v in nv) and (np_.startswith(p) or p.startswith(np_)):
        return "name_match"
    return "cve_only"


# --------------------------------------------------------------------------- the report
def build_report(store: IntelStore, *, cve_ids: list[str] | None = None) -> IntelReport:
    latest = store.latest_accepted()
    unreadable: list[int] = []
    kev_obs: Observation | None = None
    kev: dict[str, Any] = {}
    epss: dict[str, tuple[Observation, dict[str, Any]]] = {}
    nvd: dict[str, tuple[Observation, dict[str, Any]]] = {}
    csaf: list[tuple[Observation, dict[str, Any], list[str]]] = []

    for obs in latest:                              # oldest first: a newer series wins
        feed = _reparse(store, obs)
        if feed is None:
            unreadable.append(obs.seq)
            continue
        if obs.source == "cisa_kev":
            kev_obs, kev = obs, feed.records
        elif obs.source == "first_epss":
            epss.update({k: (obs, v) for k, v in feed.records.items()})
        elif obs.source == "nvd_cve_api":
            nvd.update({k: (obs, v) for k, v in feed.records.items()})
        elif obs.source == "csaf":
            csaf.append((obs, next(iter(feed.records.values())), list(feed.meta["cves"])))

    candidates: list[Candidate] = []
    conflicts_by_cve: dict[str, list[dict[str, Any]]] = {}
    unrep_by_cve: dict[str, list[str]] = {}
    nvd_walk = {cid: _walk_nvd(rec) for cid, (_, rec) in nvd.items()}

    for obs, doc, _cves in csaf:
        try:
            imported = advisory_from_csaf(doc)
        except AdvisoryError:
            unreadable.append(obs.seq)
            continue
        candidates.append(Candidate(
            imported.advisory, "csaf", "unsigned_inspect_only",
            obs.citation(imported.advisory.advisory_id), imported.notes,
            tuple(d.product_id + ": " + d.reason for d in
                  (imported.advisory.import_record.dropped if imported.advisory.import_record
                   else ()))))

    for cid, (obs, rec) in sorted(nvd.items()):
        walked = nvd_walk[cid]
        unrep = [_range_text(v, p, b) for v, p, b in walked.bounded] + walked.other
        if unrep:
            unrep_by_cve[cid] = unrep
        if rec.get("vulnStatus") == "Rejected" or not walked.exact:
            continue
        stamp = rec.get("lastModified") or rec.get("published") or ""
        try:
            issued = _nvd_time(stamp)
        except ValueError:
            unrep_by_cve.setdefault(cid, []).append("no usable lastModified/published time")
            continue
        affected = []
        for (vendor, product), versions in sorted(walked.exact.items()):
            ranges = [_range_text(v, p, b) for v, p, b in walked.bounded
                      if (v, p) == (vendor, product)]
            affected.append(AffectedArtefact(
                supplier=vendor, name=product, versions=tuple(versions),
                version_note=("NVD also lists, for this component: " + "; ".join(ranges))
                if ranges else ""))
        desc = next((d.get("value", "") for d in rec.get("descriptions") or []
                     if isinstance(d, dict) and d.get("lang") == "en"), "")
        try:
            advisory = ComponentAdvisory(
                advisory_id=f"nvd:{cid}", issued_by="NVD (NIST), unsigned public feed",
                issued_at=issued, title=f"{cid} (NVD record)",
                summary=("UNSIGNED public NVD record, fit for inspection only. " + desc)[:2000],
                severity=AdvisorySeverity.SAFETY_RELEVANT, affected=tuple(affected),
                reference=f"https://nvd.nist.gov/vuln/detail/{cid}")
        except AdvisoryError:
            unrep_by_cve.setdefault(cid, []).append("the advisory model refused this record")
            continue
        candidates.append(Candidate(
            advisory, "nvd_cve_api", TRUST_UNSIGNED_PUBLIC, obs.citation(cid),
            ("Severity defaulted to safety_relevant: NVD does not say whether a safety "
             "function is affected.",
             "supplier and name are NVD CPE identifiers, not display names; they match a "
             "manifest only if it uses the same strings.", *walked.notes),
            tuple(unrep_by_cve.get(cid, ()))))

    # conflicts: NVD against each vendor CSAF, per CVE
    for obs, doc, _cves in csaf:
        adv_id = str(doc.get("document", {}).get("tracking", {}).get("id", "")).strip()
        for cid, fixed in _csaf_fixed(doc).items():
            if cid not in nvd:
                continue
            nvd_obs = nvd[cid][0]
            walked = nvd_walk[cid]
            labels = {fold_text(v): (vd, pr, v) for vd, pr, v in fixed}
            for (nv, np_), versions in sorted(walked.exact.items()):
                for ver in versions:
                    if fold_text(ver) in labels:
                        vd, pr, fx = labels[fold_text(ver)]
                        conflicts_by_cve.setdefault(cid, []).append(_conflict(
                            cid, "fixed_listed_as_affected", _linked(nv, np_, vd, pr),
                            f"NVD lists {nv}:{np_} version {ver} as affected",
                            nvd_obs.citation(cid),
                            f"{adv_id} lists {vd} {pr} {fx} as fixed", obs.citation(adv_id)))
            for nv, np_, bounds in walked.bounded:
                for key in ("versionEndIncluding", "versionStartIncluding"):
                    if key in bounds and fold_text(bounds[key]) in labels:
                        vd, pr, fx = labels[fold_text(bounds[key])]
                        conflicts_by_cve.setdefault(cid, []).append(_conflict(
                            cid, "fixed_listed_as_affected", _linked(nv, np_, vd, pr),
                            f"NVD: {_range_text(nv, np_, bounds)}", nvd_obs.citation(cid),
                            f"{adv_id} lists {vd} {pr} {fx} as fixed", obs.citation(adv_id)))
            ends = {fold_text(b["versionEndExcluding"]): (nv, np_, b["versionEndExcluding"])
                    for nv, np_, b in walked.bounded if "versionEndExcluding" in b}
            if ends and not set(ends) & set(labels):
                nv, np_, end = next(iter(ends.values()))
                vd, pr, fx = fixed[0]
                conflicts_by_cve.setdefault(cid, []).append(_conflict(
                    cid, "fixed_boundary_differs", _linked(nv, np_, vd, pr),
                    "NVD affected up to (excluding): "
                    + ", ".join(sorted(e[2] for e in ends.values())), nvd_obs.citation(cid),
                    "vendor fixed in: " + ", ".join(sorted({f[2] for f in fixed})),
                    obs.citation(adv_id)))

    all_cves = set(cve_ids or ())
    if not cve_ids:
        all_cves |= set(nvd) | set(kev) | set(epss) | set(conflicts_by_cve)
        for _, _, cves in csaf:
            all_cves |= set(cves)
    csaf_by_cve: dict[str, list[str]] = {}
    for _obs, doc, cves in csaf:
        for c in cves:
            csaf_by_cve.setdefault(c, []).append(
                str(doc["document"]["tracking"]["id"]).strip())

    enrichments = tuple(
        _enrich(cid, kev_obs, kev, epss, nvd, conflicts_by_cve, unrep_by_cve, csaf_by_cve)
        for cid in sorted(all_cves))
    flat = tuple(c for cid in sorted(conflicts_by_cve) for c in conflicts_by_cve[cid])
    return IntelReport(tuple(candidates), enrichments, flat, tuple(unreadable))


def _nvd_time(stamp: str) -> datetime:
    """NVD timestamps carry no zone; its documentation defines them as UTC."""
    return parse_utc(stamp if stamp.endswith("Z") or "+" in stamp[10:] else stamp + "Z")


def _conflict(cve: str, kind: str, link: str, nvd_says: str, nvd_cite: dict[str, Any],
              csaf_says: str, csaf_cite: dict[str, Any]) -> dict[str, Any]:
    return {"cve_id": cve, "status": "conflict", "kind": kind, "component_link": link,
            "nvd": {"says": nvd_says, "citation": nvd_cite},
            "csaf": {"says": csaf_says, "citation": csaf_cite},
            "resolution": "none: both statements are carried; no version arithmetic is done "
                          "and neither source is preferred"}


def _enrich(cid: str, kev_obs: Observation | None, kev: dict[str, Any],
            epss: dict[str, tuple[Observation, dict[str, Any]]],
            nvd: dict[str, tuple[Observation, dict[str, Any]]],
            conflicts: dict[str, list[dict[str, Any]]], unrep: dict[str, list[str]],
            csaf_by_cve: dict[str, list[str]]) -> Enrichment:
    if kev_obs is None:
        kev_s: dict[str, Any] = {"status": "unchecked",
                                 "note": "no KEV catalogue has been recorded"}
    elif cid in kev:
        e = kev[cid]
        kev_s = {"status": "listed", "vendor_project": e.get("vendorProject"),
                 "product": e.get("product"), "date_added": e.get("dateAdded"),
                 "due_date": e.get("dueDate"),
                 "known_ransomware_campaign_use": e.get("knownRansomwareCampaignUse"),
                 "citation": kev_obs.citation(cid)}
    else:
        kev_s = {"status": "not_listed_in_kev", "not_established": KEV_NOT_ESTABLISHED,
                 "citation": kev_obs.citation()}
    if cid in epss:
        o, r = epss[cid]
        epss_s: dict[str, Any] = {"status": "available", "score": r["epss"],
                                  "percentile": r["percentile"], "score_date": r["date"],
                                  "note": "time-sensitive: the score is as of score_date",
                                  "citation": o.citation(cid)}
    else:
        epss_s = {"status": "unavailable", "score": None, "note": EPSS_UNAVAILABLE_NOTE,
                  "reason": "no EPSS observation covers this CVE"}
    cvss: list[dict[str, Any]] = []
    if cid in nvd:
        o, rec = nvd[cid]
        status = "rejected" if rec.get("vulnStatus") == "Rejected" else "present"
        nvd_s: dict[str, Any] = {"status": status, "vuln_status": rec.get("vulnStatus"),
                                 "last_modified": rec.get("lastModified"),
                                 "citation": o.citation(cid)}
        for family, metrics in sorted((rec.get("metrics") or {}).items()):
            if not str(family).startswith("cvssMetric") or not isinstance(metrics, list):
                continue
            for m in metrics:
                data = m.get("cvssData") if isinstance(m, dict) else None
                if isinstance(data, dict):
                    cvss.append({"family": family, "version": data.get("version"),
                                 "base_score": data.get("baseScore"),
                                 "base_severity": data.get("baseSeverity") or m.get("baseSeverity"),
                                 "vector": data.get("vectorString"),
                                 "metric_source": m.get("source"), "type": m.get("type"),
                                 "citation": o.citation(cid)})
    else:
        nvd_s = {"status": "unknown", "note": "no NVD record for this CVE has been recorded"}
    return Enrichment(cid, kev_s, epss_s, nvd_s, tuple(cvss), tuple(conflicts.get(cid, ())),
                      tuple(unrep.get(cid, ())), tuple(csaf_by_cve.get(cid, ())))
