"""``assurance intel``: public-source vulnerability intelligence, offline first.

    ingest  --store DB [--kev FILE] [--nvd FILE] [--epss FILE] [--csaf FILE]
        parse local files and record one observation per file. Opens no socket.
    refresh --source kev|nvd|epss --store DB --live [--cve ID ...] [--api-key-env NAME]
        fetch from the official host. Refuses to touch the network without --live.
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
    ref.add_argument("--source", required=True, choices=["kev", "nvd", "epss"])
    ref.add_argument("--store", required=True, type=Path)
    ref.add_argument("--live", action="store_true",
                     help="required: without it nothing touches the network")
    ref.add_argument("--cve", action="append", default=[], metavar="CVE-ID",
                     help="nvd and epss are asked about named CVEs only")
    ref.add_argument("--api-key-env", metavar="NAME", default=None,
                     help="NAME of the environment variable holding the NVD API key")
    ref.add_argument("--timeout", type=float, default=30.0)

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


def _make_transport(source_id: str) -> Any:
    """The only place the real network client is constructed (lazy: offline verbs never)."""
    from assurance.intel.transport_urllib import UrllibTransport

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


def _refresh(args: argparse.Namespace) -> int:
    if not args.live:
        print("error: refresh fetches from the network and does nothing without --live. "
              "Use `intel ingest` to record files you already have.", file=sys.stderr)
        return EXIT_COULD_NOT_RUN
    src = resolve_source(args.source)
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


def _history(args: argparse.Namespace) -> int:
    source = resolve_source(args.source).id if args.source else None
    rows = IntelStore(args.store).observations(source=source, limit=args.limit)
    if args.json:
        print(json.dumps([o.to_dict() for o in rows], indent=1))
    else:
        for o in rows:
            print(_line(o))
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
