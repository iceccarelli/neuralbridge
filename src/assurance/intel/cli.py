"""``assurance intel``: public-source vulnerability intelligence, offline first.

    ingest  --store DB [--kev FILE] [--nvd FILE] [--epss FILE] [--csaf FILE]
        parse local files and record one observation per file. Opens no socket.
    refresh --source kev|nvd|epss --store DB --live [--cve ID ...] [--api-key-env NAME]
        fetch from the official host. Refuses to touch the network without --live.
    refresh --source csaf --store DB --live --allow-host HOST [--allow-host ...]
            (--url DOC_URL ... | --provider-metadata-url URL [--max-documents N]
             [--max-total-bytes N])
        fetch CSAF advisories from a provider the operator names. --allow-host is required
        and exact; a provider-metadata run fetches only documents new or changed since the
        last run and says how many it did not fetch. Imports stay unsigned (inspect-only).
    history --store DB [--source S] [--limit N] [--json]
    show    --store DB SEQ | --cve CVE-ID  [--json]
    candidates --store DB [--out DIR] [--json]
        advisories the existing model can represent, plus per-CVE enrichment.

Exit codes: 0 done (an ``unchanged`` re-observation is done); 1 an input was REJECTED (it is
recorded as a rejected observation and changed nothing else); 2 could not run (usage, an
unreadable file, no ``--live``).

The NVD key is read from the environment variable whose NAME you pass; it is sent as a header
and never printed, logged or stored.
"""

# ruff: noqa: T201 - a command line writes to stdout
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from assurance.intel.fetch import build_headers, fetch, ingest_file
from assurance.intel.sources import SOURCES, epss_url, nvd_url, resolve_source
from assurance.intel.store import IntelStore, Observation
from assurance.intel.view import build_report

__all__ = ["build_parser", "main"]

EXIT_REJECTED = 1
EXIT_COULD_NOT_RUN = 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance intel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="record local feed files as observations (offline)")
    ing.add_argument("--store", required=True, type=Path)
    for flag in ("kev", "nvd", "epss", "csaf"):
        ing.add_argument(f"--{flag}", type=Path, action="append", default=[],
                         metavar="FILE")

    ref = sub.add_parser("refresh", help="fetch one source from its official host (--live)")
    ref.add_argument("--source", required=True, choices=["kev", "nvd", "epss", "csaf"])
    ref.add_argument("--store", required=True, type=Path)
    ref.add_argument("--live", action="store_true",
                     help="required: without it nothing touches the network")
    ref.add_argument("--cve", action="append", default=[], metavar="CVE-ID",
                     help="nvd and epss are asked about named CVEs only")
    ref.add_argument("--api-key-env", metavar="NAME", default=None,
                     help="NAME of the environment variable holding the NVD API key")
    ref.add_argument("--timeout", type=float, default=30.0)
    ref.add_argument("--allow-host", action="append", default=[], metavar="HOST",
                     help="csaf only, required: an exact host the run may contact (repeat)")
    ref.add_argument("--url", action="append", default=[], metavar="HTTPS_URL",
                     help="csaf only: one CSAF document URL (repeatable)")
    ref.add_argument("--provider-metadata-url", metavar="HTTPS_URL", default=None,
                     help="csaf only: a provider-metadata.json; only new/changed documents")
    ref.add_argument("--max-documents", type=int, default=None, metavar="N",
                     help="csaf provider mode: fetch at most N documents per run (default 50)")
    ref.add_argument("--max-total-bytes", type=int, default=None, metavar="N",
                     help="csaf: stop fetching once N bytes were read (default 64 MiB)")

    hist = sub.add_parser("history", help="list observations, oldest first")
    hist.add_argument("--store", required=True, type=Path)
    hist.add_argument("--source", choices=["kev", "nvd", "epss", "csaf"])
    hist.add_argument("--limit", type=int, default=None)
    hist.add_argument("--json", action="store_true")

    show = sub.add_parser("show", help="one observation, or everything known about a CVE")
    show.add_argument("--store", required=True, type=Path)
    which = show.add_mutually_exclusive_group(required=True)
    which.add_argument("seq", nargs="?", type=int)
    which.add_argument("--cve", metavar="CVE-ID")
    show.add_argument("--json", action="store_true")

    cand = sub.add_parser("candidates", help="advisory candidates and enrichment")
    cand.add_argument("--store", required=True, type=Path)
    cand.add_argument("--out", type=Path, default=None,
                      help="write each candidate advisory as JSON into this directory")
    cand.add_argument("--json", action="store_true")
    return p


def _line(o: Observation) -> str:
    status = "-" if o.http_status is None else str(o.http_status)
    tail = f"  {o.reason}" if o.reason else ""
    return (f"{o.seq:>4}  {o.retrieved_at}  {o.source:<12} {o.disposition:<9} "
            f"http={status:<4} bytes={o.byte_length:<9} sha256={o.sha256[:12]}{tail}")


def _make_transport(source_id: str, allowed_hosts: frozenset[str] | None = None) -> Any:
    """The only place the real network client is constructed (lazy: offline verbs never).

    CSAF gets exactly the hosts the operator named, never the three fixed source hosts.
    """
    from assurance.intel.transport_urllib import UrllibTransport

    if allowed_hosts is not None:
        return UrllibTransport(allowed_hosts=allowed_hosts,
                               max_bytes=SOURCES[source_id].max_bytes)
    return UrllibTransport(max_bytes=SOURCES[source_id].max_bytes)


def _report(observations: list[Observation]) -> int:
    for o in observations:
        print(_line(o))
    return EXIT_REJECTED if any(o.disposition == "rejected" for o in observations) else 0


def _ingest(args: argparse.Namespace) -> int:
    jobs = [(sid, path) for flag, sid in (("kev", "cisa_kev"), ("nvd", "nvd_cve_api"),
                                          ("epss", "first_epss"), ("csaf", "csaf"))
            for path in getattr(args, flag)]
    if not jobs:
        print("error: give at least one of --kev, --nvd, --epss, --csaf", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    for _, path in jobs:
        if not path.is_file():
            print(f"error: {path} is not a readable file", file=sys.stderr)
            return EXIT_COULD_NOT_RUN
    store = IntelStore(args.store)
    return _report([ingest_file(store, sid, path) for sid, path in jobs])


def _refresh_csaf(args: argparse.Namespace) -> int:
    from assurance.intel.csaf_live import (
        DEFAULT_MAX_DOCUMENTS,
        DEFAULT_MAX_TOTAL_BYTES,
        CsafRefusal,
        normalise_allow_hosts,
        refresh_documents,
        refresh_provider,
    )

    if bool(args.url) == bool(args.provider_metadata_url):
        print("error: csaf takes either --url (one or more documents) or "
              "--provider-metadata-url, not both and not neither", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    if args.api_key_env:
        print("error: csaf takes no API key; credentials are never sent to a vendor host",
              file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    try:
        hosts = normalise_allow_hosts(args.allow_host)
        if args.max_total_bytes is not None and args.max_total_bytes < 1:
            raise CsafRefusal("--max-total-bytes must be positive")
        total = args.max_total_bytes or DEFAULT_MAX_TOTAL_BYTES
        store = IntelStore(args.store)
        transport = _make_transport("csaf", hosts)
        if args.url:
            report = refresh_documents(store, args.url, transport, allowed_hosts=hosts,
                                       timeout=args.timeout, max_total_bytes=total)
        else:
            report = refresh_provider(
                store, args.provider_metadata_url, transport, allowed_hosts=hosts,
                max_documents=(DEFAULT_MAX_DOCUMENTS if args.max_documents is None
                               else args.max_documents),
                max_total_bytes=total, timeout=args.timeout)
    except CsafRefusal as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    for what, info in report.index_status.items():
        print(f"index {what}: http={info['http_status']} bytes={info['bytes']} {info['url']}")
    for o in report.observations:
        print(_line(o))
    c = report.counts()
    print(f"csaf {report.provider}: listed {report.listed} ({report.index_kind or 'direct'}), "
          f"already up to date {report.up_to_date}, fetched {len(report.observations)} "
          f"(first {c['first']}, changed {c['changed']}, unchanged {c['unchanged']}, "
          f"rejected {c['rejected']}), bytes {report.bytes_fetched}")
    if report.not_fetched:
        print(f"{report.not_fetched} more not fetched ({report.stopped}); run again to "
              "continue")
    elif report.stopped:
        print(f"note: {report.stopped}")
    if report.skipped_rows:
        print(f"{report.skipped_rows} index rows skipped (unusable path or time)")
    for label in report.refused:
        print(f"refused (host not allowed): {label}")
    return EXIT_REJECTED if report.rejected else 0


def _refresh(args: argparse.Namespace) -> int:
    if not args.live:
        print("error: refresh fetches from the network and does nothing without --live. "
              "Use `intel ingest` to record files you already have.", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    src = resolve_source(args.source)
    if src.id == "csaf":
        return _refresh_csaf(args)
    if args.allow_host or args.url or args.provider_metadata_url:
        print("error: --allow-host, --url and --provider-metadata-url are for "
              "--source csaf only", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    if src.id == "cisa_kev":
        urls = [src.url]
    elif not args.cve:
        print(f"error: {args.source} is asked about named CVEs: pass --cve CVE-ID",
              file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    elif src.id == "nvd_cve_api":
        urls = [nvd_url(c) for c in args.cve]
    else:
        urls = [epss_url(args.cve)]
    headers = build_headers(src, api_key_env=args.api_key_env)
    if args.api_key_env and "apiKey" not in headers:
        print(f"note: ${args.api_key_env} is not set; the request is unauthenticated",
              file=sys.stderr)
    store = IntelStore(args.store)
    transport = _make_transport(src.id)
    return _report([fetch(store, src.id, u, transport, headers=headers, timeout=args.timeout)
                    for u in urls])


def _tracking_text(prov: dict[str, Any] | None) -> str:
    t = (prov or {}).get("tracking")
    if not t or prov is None:
        return ""
    return (f"\n      csaf id={t['id']} v{t['version']} initial={t['initial_release_date']} "
            f"current={t['current_release_date']} provider={prov['provider']}")


def _history(args: argparse.Namespace) -> int:
    source = resolve_source(args.source).id if args.source else None
    store = IntelStore(args.store)
    rows = store.observations(source=source, limit=args.limit)
    if args.json:
        out = []
        for o in rows:
            d = o.to_dict()
            prov = store.provenance(o.seq) if o.source == "csaf" else None
            if prov:
                d["provenance"] = prov
            out.append(d)
        print(json.dumps(out, indent=1))
    else:
        for o in rows:
            prov = store.provenance(o.seq) if o.source == "csaf" else None
            print(_line(o) + _tracking_text(prov))
        if not rows:
            print("no observations")
    return 0


def _show(args: argparse.Namespace) -> int:
    store = IntelStore(args.store)
    if args.cve:
        report = build_report(store, cve_ids=[args.cve])
        data: Any = report.enrichments[0].to_dict()
        print(json.dumps(data, indent=1) if args.json else _cve_text(data))
        return 0
    obs = store.get(args.seq)
    if args.json:
        print(json.dumps(obs.to_dict(), indent=1))
    else:
        print(_line(obs))
        print(f"  url={obs.url}\n  locator={obs.locator}  parser={obs.parser_version}  "
              f"records={obs.record_count}  feed_stamp={obs.feed_stamp or '-'}")
        if obs.diff:
            d = obs.diff
            print(f"  diff: +{d['added_total']} -{d['removed_total']} ~{d['modified_total']}")
            for key in ("added", "removed", "modified"):
                if d[key]:
                    print(f"    {key}: {', '.join(d[key][:20])}")
    return 0


def _cve_text(e: dict[str, Any]) -> str:
    lines = [e["cve_id"]]
    k, ep, n = e["kev"], e["epss"], e["nvd"]
    lines.append(f"  kev:  {k['status']}" + (f" -- {k['not_established']}"
                                              if "not_established" in k else ""))
    lines.append(f"  epss: {ep['status']}" + (f" {ep['score']} as of {ep['score_date']}"
                                              if ep["status"] == "available" else
                                              f" -- {ep['note']}"))
    lines.append(f"  nvd:  {n['status']}")
    for m in e["cvss"]:
        lines.append(f"  cvss: {m['version']} {m['base_score']} {m['base_severity']} "
                     f"({m['metric_source']})")
    for c in e["conflicts"]:
        lines.append(f"  CONFLICT {c['kind']}: {c['nvd']['says']} | {c['csaf']['says']}")
    for u in e["not_representable"]:
        lines.append(f"  not representable as an advisory: {u}")
    return "\n".join(lines)


def _candidates(args: argparse.Namespace) -> int:
    report = build_report(IntelStore(args.store))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for c in report.candidates:
            name = c.advisory.advisory_id.replace(":", "_").replace("/", "_")
            (args.out / f"{name}.json").write_text(
                json.dumps(c.advisory.to_dict(), indent=1, sort_keys=True) + "\n",
                encoding="utf-8")
    if args.json:
        print(json.dumps({"candidates": [c.to_dict() for c in report.candidates],
                          "enrichments": [e.to_dict() for e in report.enrichments],
                          "conflicts": list(report.conflicts),
                          "unreadable_observations": list(report.unreadable)}, indent=1))
    else:
        print(f"{len(report.candidates)} candidate advisories, {len(report.enrichments)} CVEs "
              f"enriched, {len(report.conflicts)} conflicts")
        for c in report.candidates:
            print(f"  {c.advisory.advisory_id}  [{c.trust}]  {c.source}")
        for c in report.conflicts:
            print(f"  CONFLICT {c['cve_id']} {c['kind']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return {"ingest": _ingest, "refresh": _refresh, "history": _history, "show": _show,
            "candidates": _candidates}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
