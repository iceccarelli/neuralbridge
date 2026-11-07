"""``assurance ingest`` — third-party SBOMs and advisories, as drafts and supplier statements.

    sbom-import   read a CycloneDX SBOM (JSON 1.4/1.5/1.6) into a DRAFT inventory in a ledger
    sbom-list     the drafts in a ledger and whether each has been reviewed
    sbom-show     one draft in full (``--review-template`` prints a blank review request)
    sbom-review   a NAMED PERSON approves (and enrols) or rejects a draft
    csaf-import   read a CSAF 2.0 advisory into a recorded supplier advisory
    csaf-list     the supplier advisories in a ledger
    csaf-show     one recorded advisory in full
    csaf-impact   what the advisory says about each enrolled machine, in the ledger

These call the same domain functions as ``POST /v1/ingest/...`` and the MCP tools; this command
works on a local ledger file and opens no socket.

Exit codes: ``sbom-import``/``csaf-import``/``sbom-review``: 0 done (an ``already_imported`` is
done), 2 refused or could not run. ``csaf-impact``: 0 every machine is fixed, not_affected or not
named by the advisory and nothing is incomplete; 1 at least one machine is affected; 3 nothing is
affected but the answer is NOT a clear (a machine is under_investigation or unknown, the advisory
is partial, the fleet is empty or the ledger chain does not verify); 2 could not run.
"""

# ruff: noqa: T201  (a command line writes to stdout; that is its interface)
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from assurance.core.actor_names import ActorNameError, checked_person
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.text import neutralise
from assurance.evidence.ledger import EvidenceLedger
from assurance.ingest import csaf, sbom_store
from assurance.ingest.common import (
    MAX_DOCUMENT_BYTES,
    IngestError,
    make_source,
    parse_json_document,
)

__all__ = ["build_parser", "main"]

SERVICE_ACTOR = Actor(identifier="assurance-ingest", role="importer", kind="automation")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="assurance ingest", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    verbs = p.add_subparsers(dest="command", required=True)

    def source_args(v: argparse.ArgumentParser) -> None:
        v.add_argument("document", type=Path, help="the document, as JSON")
        v.add_argument("--name", default=None,
                       help="the source name to record, as supplied (default: none; the file "
                            "name is not guessed)")
        v.add_argument("--supplied-at", default=None,
                       help="when the document was produced or fetched, ISO-8601 with a timezone, "
                            "recorded as supplied and not verified")
        v.add_argument("--url", default=None,
                       help="where it came from (recorded as supplied; never fetched)")
        v.add_argument("--source-sha256", default=None,
                       help="the SHA-256 you were told the document has; refused if it differs "
                            "from the bytes read")
        v.add_argument("--actor", default=None,
                       help="who is running the import (recorded; default: the importer service)")
        v.add_argument("--role", default="")
        v.add_argument("--ledger", type=Path, default=None)
        v.add_argument("--dry-run", action="store_true",
                       help="validate and show; write nothing (no ledger needed)")
        v.add_argument("--json", action="store_true")

    sb = verbs.add_parser("sbom-import", help="read a CycloneDX SBOM into a DRAFT inventory")
    source_args(sb)
    cs = verbs.add_parser("csaf-import", help="read a CSAF 2.0 advisory into a supplier advisory")
    source_args(cs)
    cs.add_argument("--allow-draft", action="store_true",
                    help="accept a draft or interim document (recorded as partial; it can state "
                         "no 'fixed' or 'not_affected')")

    for name, helptext in (("sbom-list", "drafts in a ledger"),
                           ("csaf-list", "supplier advisories in a ledger")):
        v = verbs.add_parser(name, help=helptext)
        v.add_argument("--ledger", required=True, type=Path)
        v.add_argument("--json", action="store_true")

    ss = verbs.add_parser("sbom-show", help="one draft in full")
    ss.add_argument("draft_id")
    ss.add_argument("--ledger", required=True, type=Path)
    ss.add_argument("--review-template", action="store_true",
                    help="print a blank review request (every decision null)")
    ss.add_argument("--json", action="store_true")

    sr = verbs.add_parser("sbom-review",
                          help="a NAMED PERSON approves (and enrols) or rejects a draft")
    sr.add_argument("draft_id")
    sr.add_argument("request", type=Path,
                    help="the review request as JSON (see `sbom-show --review-template`)")
    sr.add_argument("--actor", required=True, help="the reviewer: a named person")
    sr.add_argument("--role", default="")
    sr.add_argument("--ledger", required=True, type=Path)
    sr.add_argument("--json", action="store_true")

    for name, helptext in (("csaf-show", "one recorded advisory in full"),
                           ("csaf-impact", "what the advisory says about each machine")):
        v = verbs.add_parser(name, help=helptext)
        v.add_argument("advisory_ref")
        v.add_argument("--ledger", required=True, type=Path)
        v.add_argument("--json", action="store_true")
    return p


def _read(path: Path) -> bytes:
    if not path.is_file():
        raise IngestError(f"{path} is not a regular file.", code="invalid_source")
    size = path.stat().st_size
    if size > MAX_DOCUMENT_BYTES:
        raise IngestError(f"{path} is {size:,} bytes, over the {MAX_DOCUMENT_BYTES:,} read; it "
                          "is refused rather than truncated.", code="too_large")
    with path.open("rb") as handle:
        return handle.read(MAX_DOCUMENT_BYTES + 1)


def _actor(args: argparse.Namespace) -> Actor:
    if args.actor is None:
        return SERVICE_ACTOR
    return checked_person(args.actor, args.role)


def _emit(args: argparse.Namespace, payload: dict[str, Any]) -> bool:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return True
    return False


def _t(value: object) -> str:
    return neutralise(value)


def _cmd_sbom_import(args: argparse.Namespace) -> int:
    raw = _read(args.document)
    source = make_source(raw, name=args.name, supplied_at=args.supplied_at, url=args.url,
                         claimed_sha256=args.source_sha256)
    actor = _actor(args)
    if args.dry_run:
        receipt = sbom_store.import_sbom(None, raw, source=source, actor=actor, dry_run=True)
    else:
        path = _need_ledger(args)
        # validate before a ledger file is created: a refused document leaves nothing behind
        sbom_store.import_sbom(None, raw, source=source, actor=actor, dry_run=True)
        receipt = sbom_store.import_sbom(EvidenceLedger(path), raw, source=source, actor=actor)
    if _emit(args, receipt):
        return 0
    c = receipt["counts"]
    print(f"{receipt['status']}: {receipt['draft_id']} (CycloneDX; {c['components']} component(s))")
    print(f"  source sha256  {receipt['source']['sha256']} (of the bytes as read)")
    print(f"  review state   {receipt['review_state']}")
    print(f"  unknown        {c['without_version']} without version, {c['without_purl']} without "
          f"purl, {c['without_supplier']} without supplier, {c['without_sha256']} without SHA-256")
    for w in receipt["warnings"]:
        print(f"  note           {_t(w)}")
    print("  decisions a named person must make:")
    for d in receipt["decisions_required"]:
        print(f"    - {d}")
    print("  this import does NOT establish:")
    for n in receipt["does_not_establish"]:
        print(f"    - {n}")
    print("  next: `assurance ingest sbom-show --review-template`, then `sbom-review`")
    return 0


def _need_ledger(args: argparse.Namespace) -> Path:
    if args.ledger is None:
        raise IngestError("--ledger is required unless --dry-run is given.",
                          code="invalid_request")
    return Path(args.ledger)


def _cmd_sbom_list(args: argparse.Namespace) -> int:
    out = sbom_store.list_sbom_drafts(EvidenceLedger.open_existing(args.ledger))
    if _emit(args, out):
        return 0
    for d in out["drafts"]:
        print(f"{d['draft_id']}  {d['review_state']:<22} {d['components']:>4} component(s)  "
              f"{_t(d['source_name']) or '(unnamed)'}  sha256 {d['source_sha256'][:12]}")
    if not out["drafts"]:
        print("no SBOM drafts in this ledger")
    if out["damaged_entries"]:
        print(f"!! {len(out['damaged_entries'])} draft record(s) are damaged: "
              f"{out['damaged_entries']}", file=sys.stderr)
    return 0


def _cmd_sbom_show(args: argparse.Namespace) -> int:
    out = sbom_store.get_sbom_draft(EvidenceLedger.open_existing(args.ledger), args.draft_id)
    if args.review_template:
        if out["review_template"] is None:
            raise IngestError("this draft has already been reviewed; there is no template.",
                              code="already_reviewed")
        print(json.dumps(out["review_template"], indent=2))
        return 0
    if _emit(args, out):
        return 0
    draft = out["draft"]
    print(f"{out['draft_id']}  {out['review_state']}  (CycloneDX {draft['bom']['spec_version']})")
    print(f"  source sha256 {draft['source']['sha256']}; name as supplied "
          f"{_t(draft['source']['name_as_supplied']) or '(none)'}")
    ident = draft["proposed_identity"]
    for key in ("manufacturer", "model"):
        print(f"  {key} candidates: " + (", ".join(
            f"{_t(c['value'])} ({c['from']})" for c in ident[key]) or "none"))
    print("  serial: never taken from an SBOM; the reviewer enters it")
    for c in draft["components"]:
        print(f"  {c['ref']} {_t(c['type']):<16} {_t(c['name'])} "
              f"{_t(c['version']) if c['version'] else '(version unknown)'}"
              f"  kind proposal: {c['kind_proposal'] or 'none'}  safety relevance: "
              f"{c['safety_relevance']}  [{c['review']}]")
    for w in draft["warnings"]:
        print(f"  note: {_t(w)}")
    return 0


def _cmd_sbom_review(args: argparse.Namespace) -> int:
    request = parse_json_document(_read(args.request), "review request")
    if not isinstance(request, dict):
        raise IngestError("the review request must be a JSON object.", code="invalid_review")
    ledger = EvidenceLedger.open_existing(args.ledger, writable=True)
    out = sbom_store.review_sbom_draft(ledger, args.draft_id, request,
                                       reviewer=checked_person(args.actor, args.role))
    if _emit(args, out):
        return 0
    print(f"{out['status']}: {out['draft_id']} reviewed by {_t(args.actor)}")
    if out["machine"]:
        print(f"  machine        {_t(out['machine'])}")
        print(f"  configuration  {out['configuration_hash'][:16]}")
        print(f"  tier ceiling   {out['tier_ceiling']} (every item is declared; nothing was read "
              "from the machine)")
        print(f"  enrolment      {out['enrolment']['status']}")
    print("  next: verify the machine (`machine verify --configuration-hash ...`), then coverage")
    return 0


def _cmd_csaf_import(args: argparse.Namespace) -> int:
    raw = _read(args.document)
    source = make_source(raw, name=args.name, supplied_at=args.supplied_at, url=args.url,
                         claimed_sha256=args.source_sha256)
    actor = _actor(args)
    if args.dry_run:
        receipt = csaf.import_csaf(None, raw, source=source, actor=actor,
                                   allow_draft=args.allow_draft, dry_run=True)
    else:
        path = _need_ledger(args)
        csaf.import_csaf(None, raw, source=source, actor=actor, allow_draft=args.allow_draft,
                         dry_run=True)
        receipt = csaf.import_csaf(EvidenceLedger(path), raw, source=source, actor=actor,
                                   allow_draft=args.allow_draft)
    if _emit(args, receipt):
        return 0
    pub, trk = receipt["publisher"], receipt["tracking"]
    print(f"{receipt['status']}: {receipt['advisory_ref']}")
    print(f"  {_t(trk['id'])} v{_t(trk['version'])} ({trk['status']}), released "
          f"{trk['current_release_date']}")
    print(f"  publisher  {_t(pub['name'])} [{pub['category']}] {_t(pub['namespace'])}")
    print(f"  document sha256 {receipt['source']['sha256']} (of the bytes as read)")
    print(f"  {receipt['vulnerabilities']} vulnerabilit(ies), {receipt['products']} product(s) "
          "this importer can match")
    if receipt["partial"]:
        print("  PARTIAL: " + "; ".join(_t(r) for r in receipt["partial_reasons"]))
    if receipt.get("sibling_note"):
        print(f"  note: {_t(receipt['sibling_note'])}")
    print("  unsigned third-party content: inspect-only.")
    print("  next: `assurance ingest csaf-impact` against your ledger")
    return 0


def _cmd_csaf_list(args: argparse.Namespace) -> int:
    out = csaf.list_csaf_advisories(EvidenceLedger.open_existing(args.ledger))
    if _emit(args, out):
        return 0
    for a in out["advisories"]:
        print(f"{a['advisory_ref']}  {_t(a['tracking_id'])} v{_t(a['tracking_version'])} "
              f"({a['tracking_status']})  {_t(a['publisher_name'])}"
              f"{'  PARTIAL' if a['partial'] else ''}")
    if not out["advisories"]:
        print("no supplier advisories in this ledger")
    return 0


def _cmd_csaf_show(args: argparse.Namespace) -> int:
    out = csaf.get_csaf_advisory(EvidenceLedger.open_existing(args.ledger), args.advisory_ref)
    if _emit(args, out):
        return 0
    rec = out["record"]
    print(f"{out['advisory_ref']}  {_t(rec['document']['title'])}")
    print(f"  publisher {_t(out['publisher_name'])} [{out['publisher_category']}] "
          f"{_t(out['publisher_namespace'])}")
    print(f"  tracking {_t(out['tracking_id'])} v{_t(out['tracking_version'])} "
          f"({out['tracking_status']}); document sha256 {out['source_sha256']}")
    for v in rec["vulnerabilities"]:
        statuses = ", ".join(f"{k}: {len(ids)}" for k, ids in v["product_status"].items())
        print(f"  {_t(v['cve']) or '(no CVE)'}  {statuses or 'no product_status'}")
    return 0


_EXIT_AFFECTED = 1
_EXIT_NOT_CLEAR = 3


def _cmd_csaf_impact(args: argparse.Namespace) -> int:
    ledger = EvidenceLedger.open_existing(args.ledger)
    out = csaf.csaf_impact(ledger, args.advisory_ref)
    if _emit(args, out):
        pass
    else:
        prov = out["provenance"]
        print(f"{out['advisory_ref']}: {_t(prov['tracking']['id'])} v{_t(prov['tracking']['version'])} "
              f"({prov['tracking']['status']}) by {_t(prov['publisher']['name'])}")
        print("  unsigned third-party content: inspect-only; nothing here decides safety")
        c = out["counts"]
        print(f"  {out['machines_in_fleet']} machine(s): {c['affected']} affected, "
              f"{c['under_investigation']} under_investigation, {c['unknown']} unknown "
              f"({out['not_named']} not named by the advisory), {c['fixed']} fixed, "
              f"{c['not_affected']} not_affected")
        for m in out["machines"]:
            if not m["named_by_advisory"]:
                continue
            print(f"  {_t(m['machine'])}  {m['state'].upper()}"
                  + (f"  [{', '.join(m['reason_codes'])}]" if m["reason_codes"] else ""))
            for it in m["items"]:
                print(f"      {_t(it['item_name'])} {_t(it['item_version'])}: {it['state']}"
                      + (f" [{', '.join(it['reason_codes'])}]" if it["reason_codes"] else ""))
            for caveat in m["caveats"]:
                print(f"      ! {_t(caveat)}")
        print(f"  {_t(out['complete_note'])}")
    if not out["ledger_chain_verified"]:
        return _EXIT_NOT_CLEAR
    if out["counts"]["affected"]:
        return _EXIT_AFFECTED
    return 0 if out["complete"] else _EXIT_NOT_CLEAR


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "sbom-import": _cmd_sbom_import, "sbom-list": _cmd_sbom_list,
        "sbom-show": _cmd_sbom_show, "sbom-review": _cmd_sbom_review,
        "csaf-import": _cmd_csaf_import, "csaf-list": _cmd_csaf_list,
        "csaf-show": _cmd_csaf_show, "csaf-impact": _cmd_csaf_impact,
    }
    try:
        return handlers[args.command](args)
    except IngestError as exc:
        print(f"error: {_t(exc)}", file=sys.stderr)
        for line in exc.violations[:50]:
            print(f"  - {_t(line)}", file=sys.stderr)
        return 2
    except (ActorNameError, AssuranceError, ValueError, OSError) as exc:
        print(f"error: {_t(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
