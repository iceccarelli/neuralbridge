"""``assurance fleet`` — every machine at once, and what an advisory means for them.

    list        every machine in the ledger, worst coverage first
    advisory    fan a component advisory out across the fleet
    import-csaf translate a CSAF 2.0 advisory into this product's advisory format
    declare     bind a Declaration of Conformity to the configuration in front of you
    declaration check a declaration against what the machine runs today

``advisory`` and ``declaration`` exit non-zero on a finding, so both belong in
whatever runs when a supplier bulletin lands or before a machine ships.

Exit codes: 0 nothing found (and, for ``declaration``, the evidence was assessed and
stands); 1 a finding (for ``advisory`` a match, or a ledger whose chain does not verify:
nothing was cleared); 2 could not vouch (the command could not run, an error, ``list`` or
``declaration`` on a ledger that does not verify, or a ``declaration`` check whose evidence
was NOT assessed: only the configuration was compared, which is not a pass); 3 INCOMPLETE,
not a pass: for ``advisory``, nothing matched but at least one advisory is a partial
translation of its source (``import-csaf`` dropped an affected product), so "nothing
matched" is not "nothing is affected"; for ``list`` and ``declaration``, no gaps, but the
cover rests only on evidence below ``validated``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assurance.core.errors import AssuranceError
from assurance.core.identity import parse_utc, utc_now
from assurance.core.text import neutralise
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.advisory import AdvisorySeverity, ComponentAdvisory
from assurance.fleet.csaf import advisory_from_csaf, load_csaf_document
from assurance.fleet.declaration import (
    DeclarationOfConformity,
    check_declaration,
)
from assurance.fleet.impact import assess_impact
from assurance.fleet.registry import Fleet
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import interventions_from_ledger
from assurance.machinery.staleness import VerificationRecord, assess_coverage

__all__ = ["build_parser", "main"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="assurance fleet",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    verbs = p.add_subparsers(dest="command", required=True)

    ls = verbs.add_parser("list", help="every machine, worst coverage first")
    ls.add_argument("--ledger", required=True, type=Path)
    ls.add_argument("--json", action="store_true")

    ad = verbs.add_parser("advisory", help="which machines does this advisory touch")
    ad.add_argument("advisory", type=Path, nargs="?", default=None,
                    help="an advisory as JSON. Prefer --feed, which is signed")
    ad.add_argument("--feed", type=Path, default=None,
                    help="a signed supplier feed; every standing advisory in it "
                         "is fanned out")
    ad.add_argument("--supplier-key", type=Path, default=None,
                    help="the supplier's public key, obtained by a route that is "
                         "not this feed")
    ad.add_argument("--expect-supplier", default="")
    ad.add_argument("--unsigned-anyway", action="store_true",
                    help="act on an advisory that did not meet the trust policy. "
                         "Needs --override-actor: the override is recorded in the "
                         "ledger against that name. A record whose signature FAILED "
                         "is never admitted this way")
    ad.add_argument("--override-actor", default="",
                    help="who is accepting the risk (recorded in the ledger)")
    ad.add_argument("--override-reason", default="",
                    help="why (recorded in the ledger)")
    ad.add_argument("--ledger", required=True, type=Path)
    ad.add_argument("--json", action="store_true")

    ic = verbs.add_parser(
        "import-csaf",
        help="translate a CSAF 2.0 advisory (unsigned, inspect-only) into our advisory JSON")
    ic.add_argument("csaf", type=Path, help="a CSAF 2.0 document as JSON")
    ic.add_argument("--out", type=Path, default=None,
                    help="write the advisory here instead of standard output")
    ic.add_argument("--severity", default=None,
                    choices=[s.value for s in AdvisorySeverity],
                    help="CSAF does not say. Without this the advisory is imported as "
                         "safety_relevant (over-report rather than clear) and the file "
                         "records that the importer chose it; with it, the file records "
                         "that you did")
    ic.add_argument("--allow-draft", action="store_true",
                    help="import a document whose tracking status is draft or interim "
                         "(refused otherwise); the result is marked partial")

    dc = verbs.add_parser("declare",
                          help="bind a declaration to a manifest's configuration")
    dc.add_argument("manifest", type=Path)
    dc.add_argument("--doc-id", required=True)
    dc.add_argument("--issued-by", required=True)
    dc.add_argument("--legislation", required=True, action="append",
                    help="repeatable, e.g. --legislation 'Regulation (EU) 2023/1230'")
    dc.add_argument("--standard", action="append", default=[])
    dc.add_argument("--notified-body", default="")
    dc.add_argument("--notified-body-number", default="")
    dc.add_argument("--signatory", default="")
    dc.add_argument("--place", default="")
    dc.add_argument("--issued-at", default="",
                    help="ISO timestamp; defaults to now")
    dc.add_argument("--out", type=Path, default=None)

    ck = verbs.add_parser("declaration",
                          help="does the declaration still describe the machine")
    ck.add_argument("declaration", type=Path)
    ck.add_argument("--manifest", required=True, type=Path)
    ck.add_argument("--ledger", type=Path, default=None,
                    help="also assess whether the safety evidence still stands")
    ck.add_argument("--json", action="store_true")

    return p


def _cmd_list(args: argparse.Namespace) -> int:
    fleet = Fleet.from_ledger(EvidenceLedger.open_existing(args.ledger))
    if args.json:
        print(json.dumps(fleet.to_dict(), indent=2))
    else:
        print(fleet.table())
    if not fleet.chain_verified:
        return 2          # could not vouch for the ledger; not 'quiet', not 'gaps'
    if fleet.with_gaps():
        return 1
    # 3: nothing is uncovered, but some machine is covered only on evidence below
    # 'validated' (a declared provenance): standing, not demonstrated. Not a pass.
    return 3 if fleet.covered_at_community() else 0


#: Said once, loudly, wherever an unverified advisory is acted on. The point of
#: this whole mechanism is that a forged advisory is a physical safety attack:
#: it induces somebody to modify the safety system of a machine people stand
#: next to. A tool that treats signed and unsigned as equivalent has not closed
#: anything.
_UNSIGNED_WARNING = (
    "This advisory is not signed, or its signature was not checked. It arrived "
    "as a file. Acting on it means changing a safety system on the authority of "
    "something anyone could have written — which is the attack this mechanism "
    "exists to prevent. Ask the supplier to publish a signed feed; it costs them "
    "one command."
)


def _advisories_from_feed(
    args: argparse.Namespace,
) -> tuple[list, list[str], dict[str, dict], dict]:
    """Every standing advisory in a feed that may be assessed, with its provenance.

    Returns ``(advisories, notes, provenance_by_advisory_id, feed_trust)``. A feed
    is trusted when its signatures verify under a key PINNED for that supplier in
    the ledger's trust store; a key handed over with ``--supplier-key`` is
    reported as exactly that (signature valid, key not pinned). Anything else is
    refused unless ``--unsigned-anyway`` carries a named actor, and even then a
    record whose signature FAILED is excluded.
    """
    from assurance.attest.keys import VerifyingKey
    from assurance.supplier.publish import AdvisoryFeed, verify_feed
    from assurance.supplier.trust import (
        TRUST_STATEMENT,
        SupplierTrustError,
        SupplierTrustStore,
        evaluate_feed,
    )

    records = AdvisoryFeed(args.feed).read()
    if not records:
        raise AssuranceError(f"{args.feed} holds no records.")

    store = SupplierTrustStore(EvidenceLedger(args.ledger))
    key = VerifyingKey.from_file(args.supplier_key) if args.supplier_key else None
    trust = evaluate_feed(records, store, expect_supplier=args.expect_supplier,
                          candidate_key=key)
    by_id = {}
    for r in records:
        if not r.is_withdrawal:
            by_id.setdefault(r.advisory_id, r)

    if trust.policy_satisfied:
        return ([by_id[a["advisory_id"]].component() for a in trust.advisories],
                [TRUST_STATEMENT],
                {a["advisory_id"]: trust.provenance_for(a["advisory_id"])
                 for a in trust.advisories},
                trust.to_dict())

    if key is not None:
        verdict = verify_feed(records, key, expect_supplier=args.expect_supplier)
        if verdict.ok:
            prov = {
                "source": "supplier_feed", "trust_state": "key_supplied_not_pinned",
                "trust_basis": "operator_supplied_key",
                "signature_state": "all_valid", "key_trust_state": "not_pinned",
                "chain_valid": True, "automated_consequences_permitted": False,
                "inspect_only": False, "override": None,
                "implications_reviewed": False, "problems": [],
                "trust_statement": TRUST_STATEMENT,
            }
            notes = list(verdict.checks_skipped) + [
                f"key {key.fingerprint} was supplied on the command line and is NOT "
                "pinned for this supplier in the ledger's trust store; signatures "
                "verify under it, which proves who signed the bytes only if that "
                "key really is the supplier's. `assurance supplier trust pin` "
                "records the decision."]
            return ([r.component() for r in verdict.live], notes,
                    {r.advisory_id: prov for r in verdict.live}, trust.to_dict())

    if not args.unsigned_anyway:
        why = ("\n  ".join(trust.problems) if trust.problems
               else "it was not checked against a pinned or supplied key")
        unchecked = ("" if key is not None else
                     f"{args.feed} was not checked against a key (pass --supplier-key) "
                     "and no key pinned in the ledger covers it.\n")
        raise AssuranceError(
            unchecked + f"refusing to act on {args.feed} (trust state "
            f"{trust.trust_state}):\n  "
            + why
            + "\n\nPin the supplier's key (`assurance supplier trust pin`, with the "
              "fingerprint you obtained by a route that is not this feed), pass "
              "--supplier-key, or use --unsigned-anyway with --override-actor if you "
              "have decided, deliberately, to proceed."
        )
    if not args.override_actor.strip():
        raise AssuranceError(
            "--unsigned-anyway needs --override-actor: an override of the trust "
            "policy is recorded in the ledger against a name, and an anonymous one "
            "is not accepted.")

    admitted: list = []
    provenance: dict[str, dict] = {}
    notes = [_UNSIGNED_WARNING, "PROCEEDED UNDER MANUAL OVERRIDE by "
             f"{args.override_actor.strip()} on a feed in trust state {trust.trust_state}: "
             + "; ".join(trust.problems[:5])]
    for row in trust.advisories:
        try:
            store.override(trust, row["advisory_id"], actor=args.override_actor,
                           reason=args.override_reason or "no reason given")
        except SupplierTrustError as exc:
            notes.append(f"EXCLUDED {row['advisory_id']}: {exc}")
            continue
    final = evaluate_feed(records, store, expect_supplier=args.expect_supplier,
                          candidate_key=key)
    for row in final.advisories:
        if row["automated_consequences_permitted"]:
            admitted.append(by_id[row["advisory_id"]].component())
            provenance[row["advisory_id"]] = final.provenance_for(row["advisory_id"])
    return admitted, notes, provenance, final.to_dict()


def _cmd_advisory(args: argparse.Namespace) -> int:
    if args.feed and args.advisory:
        print("error: give an advisory file or --feed, not both.", file=sys.stderr)
        return 2
    if not args.feed and not args.advisory:
        print("error: give an advisory file or --feed.", file=sys.stderr)
        return 2

    feed_trust: dict = {}
    provenance: dict[str, dict] = {}
    if args.feed:
        advisories, notes, provenance, feed_trust = _advisories_from_feed(args)
    else:
        advisories = [ComponentAdvisory.from_json(args.advisory)]
        notes = [_UNSIGNED_WARNING]
        provenance = {a.advisory_id: {
            "source": "bare_file", "trust_state": "unauthenticated_file",
            "trust_basis": "none", "signature_state": "none",
            "automated_consequences_permitted": False, "inspect_only": True,
            "override": None, "implications_reviewed": False,
        } for a in advisories}

    fleet = Fleet.from_ledger(EvidenceLedger.open_existing(args.ledger))
    reports = [assess_impact(a, fleet, provenance=provenance.get(a.advisory_id))
               for a in advisories]
    for a in advisories:
        if a.import_record is not None:
            notes = [*notes, f"{neutralise(a.advisory_id)} is an unsigned CSAF import "
                             f"({a.import_record.trust}); it was assessed for inspection "
                             "only."]

    if args.json:
        print(json.dumps({
            "advisories": [r.to_dict() for r in reports],
            "provenance_notes": notes,
            "feed_trust": feed_trust,
        }, indent=2))
    else:
        for advisory, report in zip(advisories, reports, strict=True):
            print(f"{neutralise(advisory.advisory_id)} — {neutralise(advisory.title)}")
            print(report.summary())
            if report.checks_skipped:
                print("\n  not checked:")
                for c in report.checks_skipped:
                    print(f"    - {neutralise(c)}")
            print()
        print("  provenance:")
        for note in notes:
            print(f"    - {neutralise(note)}")
    if all(r.verdict == "clear" for r in reports):
        return 0
    if all(r.verdict == "clear" or (r.incomplete and not r.exposures and r.chain_verified)
           for r in reports):
        return 3      # nothing matched, but the translation was partial: not clear
    return 1


def _cmd_import_csaf(args: argparse.Namespace) -> int:
    if args.out is not None:
        try:
            same = args.out.exists() and args.csaf.exists() and args.out.samefile(args.csaf)
        except OSError:
            same = False
        if same or args.out.absolute() == args.csaf.absolute():
            print(f"error: --out {args.out} is the input file; the source document is "
                  "never overwritten.", file=sys.stderr)
            return 2
    document = load_csaf_document(args.csaf)
    result = advisory_from_csaf(
        document, severity=AdvisorySeverity(args.severity) if args.severity else None,
        allow_draft=args.allow_draft)
    advisory = result.advisory
    record = advisory.import_record
    text = json.dumps(advisory.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    for note in result.notes:
        print(f"note: {neutralise(note)}", file=sys.stderr)
    if record is not None:
        print(f"severity: {advisory.severity.value} "
              f"({record.severity_source.replace('_', ' ')})", file=sys.stderr)
        if record.partial:
            print("PARTIAL: the advisory written is NOT the whole document; "
                  + ("not imported: " + ", ".join(neutralise(i) for i in record.dropped_ids)
                     if record.dropped else "; ".join(neutralise(r)
                                                       for r in record.partial_reasons))
                  + ". It is marked partial and no consumer will report it as clear.",
                  file=sys.stderr)
    print(f"imported {neutralise(advisory.advisory_id)} ({len(advisory.affected)} affected "
          f"component(s)); run `assurance fleet advisory <file> --ledger ...` to see which "
          "machines it touches.", file=sys.stderr)
    return 0


def _cmd_declare(args: argparse.Namespace) -> int:
    manifest = SafetyManifest.from_json(args.manifest)
    issued = parse_utc(args.issued_at) if args.issued_at else utc_now()
    declaration = DeclarationOfConformity.bind(
        manifest, doc_id=args.doc_id, issued_by=args.issued_by, issued_at=issued,
        legislation=tuple(args.legislation), standards=tuple(args.standard),
        notified_body=args.notified_body,
        notified_body_number=args.notified_body_number,
        signatory=args.signatory, place=args.place,
    )
    payload = json.dumps(declaration.to_dict(), indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(payload, encoding="utf-8")
        print(f"declaration {declaration.doc_id} written to {args.out}")
        print(f"  machine        {declaration.machine_key}")
        print(f"  configuration  {declaration.configuration_hash[:16]}")
        print(f"  identity       {declaration.content_hash()[:16]}")
        print("  This declaration is now checkable: any later manifest of this "
              "machine either matches that configuration or does not.")
    else:
        print(payload, end="")
    return 0


def _cmd_declaration(args: argparse.Namespace) -> int:
    declaration = DeclarationOfConformity.from_json(args.declaration)
    manifest = SafetyManifest.from_json(args.manifest)

    coverage = None
    chain_ok = True
    if args.ledger:
        ledger = EvidenceLedger(args.ledger)
        chain_ok = ledger.verify_chain()[0]
        key = manifest.machine.key
        coverage = assess_coverage(
            manifest,
            VerificationRecord.from_ledger(ledger, subject=key),
            interventions_from_ledger(ledger, key),
        )

    status = check_declaration(declaration, manifest, coverage)
    if args.json:
        print(json.dumps({**status.to_dict(), "ledger_chain_verified": chain_ok}, indent=2))
    else:
        if not chain_ok:
            print("THE LEDGER CHAIN DOES NOT VERIFY — the evidence below is drawn from a "
                  "store whose integrity is in question.\n")
        print(status.summary())
        if status.checks_skipped:
            print("\n  not checked:")
            for c in status.checks_skipped:
                print(f"    - {c}")
        if not status.evidence_assessed:
            print("\n  The evidence was NOT assessed. Supply --ledger (and a manifest that "
                  "declares safety functions) to check the evidence as well as the "
                  "configuration.")
    if not chain_ok:
        return 2        # could not vouch: not a pass, whatever the evidence reads
    if status.is_sound:
        return 0
    # 2: could not vouch (the evidence was never looked at), as for an unverifiable ledger.
    # 3: the evidence stands, but only below 'validated' (as for `machinery coverage`).
    # 1: a finding (changed configuration, wrong machine, lapsed evidence).
    if status.verdict.is_unassessed:
        return 2
    return 3 if status.verdict.is_below_validated else 1


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "list": _cmd_list,
        "advisory": _cmd_advisory,
        "import-csaf": _cmd_import_csaf,
        "declare": _cmd_declare,
        "declaration": _cmd_declaration,
    }
    try:
        return handlers[args.command](args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (AssuranceError, ValueError, OSError) as exc:
        print(f"error: {neutralise(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
