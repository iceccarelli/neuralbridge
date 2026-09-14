"""Command line for the Article 14 register.

Designed for the hour it will actually be used in: something has happened, the
clock is running, and the person at the keyboard needs to record a fact and be
told what is due next. Every command that changes something prints what is now
outstanding, because the next question is always "and now what".

    assurance art14 signal      CASE-001 --at ... --channel customer --by ... --description ...
    assurance art14 awareness   CASE-001 --at ... --started ... --completed ... --by ... --because ...
    assurance art14 triage      CASE-001 --answer reliable_evidence=yes ... --by ...
    assurance art14 availability CASE-001 --from product.json --by ...
    assurance art14 measure     CASE-001 --at ... --description ... --by ...
    assurance art14 file        CASE-001 --stage early_warning --at ... --payload draft.json --by ...
    assurance art14 validate    --track vulnerability --stage early_warning --payload draft.json
    assurance art14 fields      --track vulnerability --stage early_warning
    assurance art14 case        CASE-001
    assurance art14 register
    assurance art14 verify
    assurance art14 export      [--case CASE-001] [-o bundle.json]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from ...core.evidence import Actor
from ...core.identity import format_utc, parse_utc, utc_now
from ...evidence.ledger import EvidenceLedger
from .engine import Art14Register
from .model import Awareness, ProductVersion, Signal, SignalChannel, Stage, Track
from .report import case_report, readiness_json, register_report
from .srp import fields_for, validate_payload
from .triage import Answer, Question

DEFAULT_LEDGER = "art14-register.db"


def _register(args: argparse.Namespace) -> Art14Register:
    path = args.ledger or os.environ.get("ASSURANCE_LEDGER", DEFAULT_LEDGER)
    return Art14Register(EvidenceLedger(path))


def _actor(args: argparse.Namespace) -> Actor:
    if not getattr(args, "by", None):
        raise SystemExit(
            "error: --by is required. An unattributed record is not evidence; the person who "
            "made the call is part of the fact."
        )
    identifier, _, role = args.by.partition(":")
    return Actor(identifier=identifier.strip(), role=role.strip())


def _load_json(path: str) -> dict[str, Any]:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"error: {path} does not exist") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"error: {path} is not valid JSON — {exc}") from exc


def _show_outstanding(register: Art14Register, case_id: str) -> None:
    case = register.case(case_id)
    items = case.outstanding()
    print(f"\ncase {case_id} — state: {case.state}")
    if not items:
        print("  nothing outstanding")
        return
    print("  outstanding:")
    for item in items:
        print(f"    • {item}")


# -- commands -------------------------------------------------------------
def cmd_signal(args: argparse.Namespace) -> int:
    register = _register(args)
    signal = Signal(
        received_at=parse_utc(args.at) if args.at else utc_now(),
        channel=SignalChannel(args.channel),
        received_by=args.received_by or _actor(args).identifier,
        description=args.description,
        product_name=args.product or "",
        version=args.version or "",
        reference=args.reference or "",
    )
    evidence = register.record_signal(args.case_id, signal, _actor(args))
    print(f"recorded signal  {evidence.content_hash[:16]}  at {format_utc(signal.received_at)}")
    print(
        "  no deadline is running yet. The clock starts at awareness, which is a separate, "
        "reasoned record — Art. 14 and guidance C(2026) 5252 §213."
    )
    _show_outstanding(register, args.case_id)
    return 0


def cmd_awareness(args: argparse.Namespace) -> int:
    register = _register(args)
    awareness = Awareness(
        established_at=parse_utc(args.at),
        assessment_started_at=parse_utc(args.started),
        assessment_completed_at=parse_utc(args.completed),
        determined_by=args.determined_by or _actor(args).identifier,
        reasoning=args.because,
    )
    evidence = register.record_awareness(
        args.case_id, awareness, Track(args.track), _actor(args)
    )
    print(f"recorded awareness  {evidence.content_hash[:16]}")
    case = register.case(args.case_id)
    deadlines = case.deadlines
    if deadlines:
        print("\ndeadlines now running:")
        for d in deadlines.all():
            print(f"  {d.stage.label:26s} {format_utc(d.due_at)}   {d.provision}")
        for gap in deadlines.pending_facts():
            print(f"  not computable: {gap}")
    _show_outstanding(register, args.case_id)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    register = _register(args)
    answers: dict[Question | str, Answer | str] = {}
    for pair in args.answer or []:
        key, _, value = pair.partition("=")
        answers[key.strip()] = Answer(value.strip())
    evidence, result = register.record_triage(
        args.case_id, answers, _actor(args), args.because or "", reopen_trigger=args.reopen_if or ""
    )
    print(result.summary())
    print(f"\nrecorded  {evidence.content_hash[:16]}")
    _show_outstanding(register, args.case_id)
    return 0


def cmd_availability(args: argparse.Namespace) -> int:
    register = _register(args)
    product = ProductVersion.from_dict(_load_json(args.source))
    evidence = register.record_availability(args.case_id, product, _actor(args))
    gaps = product.gaps()
    print(f"recorded availability  {evidence.content_hash[:16]}")
    for gap in gaps:
        print(f"  gap: {gap}")
    _show_outstanding(register, args.case_id)
    return 0


def cmd_measure(args: argparse.Namespace) -> int:
    register = _register(args)
    evidence = register.record_measure_available(
        args.case_id, parse_utc(args.at), args.description, _actor(args)
    )
    print(f"recorded measure  {evidence.content_hash[:16]}")
    case = register.case(args.case_id)
    deadlines = case.deadlines
    if deadlines and deadlines.final:
        print(
            f"  the 14-day final-report clock now runs to "
            f"{format_utc(deadlines.final.due_at)} ({deadlines.final.provision})"
        )
    _show_outstanding(register, args.case_id)
    return 0


def cmd_file(args: argparse.Namespace) -> int:
    register = _register(args)
    payload = _load_json(args.payload)
    evidence, validation = register.record_filing(
        args.case_id,
        Stage(args.stage),
        parse_utc(args.at) if args.at else utc_now(),
        payload,
        _actor(args),
        args.reference or "",
    )
    print(validation.summary())
    print(f"\nrecorded filing  {evidence.content_hash[:16]}")
    _show_outstanding(register, args.case_id)
    return 0 if validation.submittable else 2


def cmd_notify_users(args: argparse.Namespace) -> int:
    register = _register(args)
    evidence = register.record_user_notification(
        args.case_id,
        parse_utc(args.at) if args.at else utc_now(),
        args.scope,
        args.content,
        _actor(args),
        public=args.public,
    )
    print(f"recorded user notification  {evidence.content_hash[:16]}")
    if args.public:
        print(
            "  note: Art. 14(8) does not require public disclosure. Guidance §§219-221: "
            "it may be limited to the users concerned, particularly where publishing technical "
            "detail would itself increase risk."
        )
    _show_outstanding(register, args.case_id)
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    validation = validate_payload(_load_json(args.payload), Track(args.track), Stage(args.stage))
    print(validation.summary())
    return 0 if validation.submittable else 2


def cmd_fields(args: argparse.Namespace) -> int:
    specs = fields_for(Track(args.track), Stage(args.stage))
    if args.json:
        print(json.dumps([s.to_dict() for s in specs], indent=2, ensure_ascii=False))
        return 0
    print(f"{Track(args.track).label} — {Stage(args.stage).label}: {len(specs)} fields")
    for spec in specs:
        requirement = spec.requirement_at(Stage(args.stage))
        limit = f"  max {spec.max_length}" if spec.max_length else ""
        print(f"  {spec.number:5s} {requirement.value:22s} {spec.name}{limit}")
        if spec.platform_gap:
            print(f"        platform gap: {spec.platform_gap}")
    return 0


def cmd_case(args: argparse.Namespace) -> int:
    register = _register(args)
    case = register.case(args.case_id)
    if args.json:
        print(json.dumps(case.to_dict(), indent=2, ensure_ascii=False))
        return 0
    print(case_report(case))
    return 0


def cmd_register_cmd(args: argparse.Namespace) -> int:
    register = _register(args)
    if args.json:
        print(readiness_json(register))
        return 0
    print(register_report(register))
    return 1 if register.breaches() else 0


def cmd_verify(args: argparse.Namespace) -> int:
    register = _register(args)
    ok, problems = register.ledger.verify_chain()
    if ok:
        attestation = register.ledger.head_attestation()
        print(f"chain verified: {attestation['length']} records")
        print(f"  head link hash  {attestation['head_link_hash']}")
        print(
            "  sign or publish this value to make a silent rewind detectable; a self-"
            "recomputable chain detects accident, not a determined insider."
        )
        return 0
    print("CHAIN VERIFICATION FAILED", file=sys.stderr)
    for problem in problems:
        print(f"  • {problem}", file=sys.stderr)
    return 1


def cmd_export(args: argparse.Namespace) -> int:
    register = _register(args)
    bundle = register.ledger.export(subject=args.case_id)
    text = json.dumps(bundle, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"exported {len(bundle['entries'])} records to {args.output}")
    else:
        print(text)
    return 0


# -- parser ---------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="assurance art14",
        description=(
            "EU Cyber Resilience Act, Article 14 reporting register. "
            "Applicable since 2026-09-11 and, by Art. 69(3), applicable to products placed "
            "on the market before 2027-12-11."
        ),
    )
    parser.add_argument("--ledger", help=f"ledger path (default: ${{ASSURANCE_LEDGER}} or {DEFAULT_LEDGER})")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_case(p: argparse.ArgumentParser) -> argparse.ArgumentParser:
        p.add_argument("case_id")
        p.add_argument("--by", help="who is recording this, as 'identifier:role'")
        return p

    s = with_case(sub.add_parser("signal", help="record an incoming signal"))
    s.add_argument("--at", help="UTC ISO-8601; defaults to now")
    s.add_argument("--channel", default="other", choices=[c.value for c in SignalChannel])
    s.add_argument("--received-by")
    s.add_argument("--description", required=True)
    s.add_argument("--product")
    s.add_argument("--version")
    s.add_argument("--reference")
    s.set_defaults(func=cmd_signal)

    a = with_case(sub.add_parser("awareness", help="establish the moment deadlines run from"))
    a.add_argument("--at", required=True, help="when reasonable certainty was reached (UTC)")
    a.add_argument("--started", required=True, help="when the initial assessment started")
    a.add_argument("--completed", required=True, help="when the initial assessment completed")
    a.add_argument("--track", required=True, choices=[t.value for t in Track])
    a.add_argument("--determined-by")
    a.add_argument("--because", required=True, help="the reasoning; required, not decorative")
    a.set_defaults(func=cmd_awareness)

    t = with_case(sub.add_parser("triage", help="work the reportability decision path"))
    t.add_argument("--answer", action="append", metavar="question=yes|no|undetermined")
    t.add_argument("--because")
    t.add_argument("--reopen-if", help="mandatory for grounds that can stop being true")
    t.set_defaults(func=cmd_triage)

    av = with_case(sub.add_parser("availability", help="attach the product and Member State record"))
    av.add_argument("--from", dest="source", required=True, help="JSON file")
    av.set_defaults(func=cmd_availability)

    m = with_case(sub.add_parser("measure", help="record a corrective or mitigating measure"))
    m.add_argument("--at", required=True)
    m.add_argument("--description", required=True)
    m.set_defaults(func=cmd_measure)

    f = with_case(sub.add_parser("file", help="record a submission"))
    f.add_argument("--stage", required=True, choices=[s.value for s in Stage])
    f.add_argument("--at")
    f.add_argument("--payload", required=True, help="JSON file keyed by field name")
    f.add_argument("--reference", help="platform reference")
    f.set_defaults(func=cmd_file)

    n = with_case(sub.add_parser("notify-users", help="record the Art. 14(8) notification"))
    n.add_argument("--at")
    n.add_argument("--scope", required=True, help="e.g. 'impacted users' or 'all users'")
    n.add_argument("--content", required=True)
    n.add_argument("--public", action="store_true")
    n.set_defaults(func=cmd_notify_users)

    v = sub.add_parser("validate", help="check a draft payload without recording it")
    v.add_argument("--track", required=True, choices=[t.value for t in Track])
    v.add_argument("--stage", required=True, choices=[s.value for s in Stage])
    v.add_argument("--payload", required=True)
    v.set_defaults(func=cmd_validate)

    fl = sub.add_parser("fields", help="print the platform field specification")
    fl.add_argument("--track", required=True, choices=[t.value for t in Track])
    fl.add_argument("--stage", required=True, choices=[s.value for s in Stage])
    fl.add_argument("--json", action="store_true")
    fl.set_defaults(func=cmd_fields)

    c = sub.add_parser("case", help="show one case")
    c.add_argument("case_id")
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_case)

    r = sub.add_parser("register", help="show every case, worst first")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_register_cmd)

    ve = sub.add_parser("verify", help="verify the evidence chain")
    ve.set_defaults(func=cmd_verify)

    e = sub.add_parser("export", help="export a verifiable bundle")
    e.add_argument("--case", dest="case_id", default=None)
    e.add_argument("-o", "--output")
    e.set_defaults(func=cmd_export)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
