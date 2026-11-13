"""Reports.

Two audiences, one source. The register renders what the ledger holds; nothing
here computes a fact that is not already recorded, so a report and an audit
export cannot disagree.

The house style is deliberate. Every report leads with what is missing or late,
states what was *not* checked, and cites the provision behind each statement. A
report whose most prominent element is a score is a report that will be quoted
back at the company by someone who read only the first page.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from ...core.identity import format_utc, utc_now
from .clock import OPEN_LEGAL_QUESTIONS, RULE_VERSION, Deadline
from .engine import Art14Register, Case
from .srp import GLOSSARY_DATE, GLOSSARY_VERSION

__all__ = ["basis_lines", "case_report", "readiness_report", "register_report"]

_RULE = "─" * 78


def _lines(*parts: str) -> str:
    return "\n".join(parts)


def basis_lines(deadline: Deadline, indent: str = "    ") -> list[str]:
    """The provenance of one deadline in words: the same facts as ``Deadline.to_dict()['basis']``."""
    b = deadline.basis()
    sf = b["starts_from"]
    where = (
        f"ledger seq {sf['ledger_seq']} {str(sf['ledger_hash'])[:16]}, recorded by "
        f"{sf['recorded_by']} [{sf['actor_kind'] or 'kind not recorded'}]"
        if sf["ledger_seq"] is not None
        else "ledger position not carried; see the audit history"
    )
    out = [
        f'{indent}basis: {b["citation"]}' + (f': "{b["wording"]}"' if b["wording"] else ""),
        f'{indent}counting {b["counting"]} · rule version {b["rule_version"]} · starts from '
        f'{sf["fact"]} at {sf["at"]} ({where})',
    ]
    if b["also_required"]:
        out.append(f'{indent}also required: {b["also_required"]}')
    out.extend(f"{indent}not modelled: {n}" for n in b["not_modelled"])
    if b["residual"]:
        out.append(f'{indent}residual: {b["residual"]}')
    for r in b["other_readings"]:
        out.append(
            f'{indent}other reading, information only, {r["status"]}: {r["id"]} would end '
            f'{r["would_end_at"]}; it does not replace the due time above'
        )
    w = b["weekend_holiday_rule"]
    out.append(f"{indent}weekend/holiday rule ({w['id']}): NOT applied. {w['note']}")
    if b["status_note"]:
        out.append(f'{indent}NOTE: {b["status_note"]}')
    return out


def case_report(case: Case, *, now: datetime | None = None) -> str:
    """A single case, as an auditor would want to read it."""
    reference = now or utc_now()
    out: list[str] = [
        _RULE,
        f"ARTICLE 14 CASE {case.case_id}   —   state: {case.state}",
        _RULE,
    ]

    if case.signal:
        out += [
            "",
            "SIGNAL",
            f"  received      {format_utc(case.signal.received_at)}  via {case.signal.channel.value}",
            f"  received by   {case.signal.received_by}",
            f"  reference     {case.signal.reference or '(none)'}",
            f"  description   {case.signal.description}",
        ]

    if case.awareness:
        out += [
            "",
            "AWARENESS  —  the fact every deadline runs from",
            f"  established   {format_utc(case.awareness.established_at)}",
            (
                f"  assessment    {format_utc(case.awareness.assessment_started_at)} "
                f"→ {format_utc(case.awareness.assessment_completed_at)} "
                f"({case.awareness.assessment_hours} h)"
            ),
            f"  determined by {case.awareness.determined_by}",
            f"  basis         {case.awareness.basis}",
            f"  reasoning     {case.awareness.reasoning}",
        ]
        if case.signal:
            out.append(
                f"  signal → awareness: {case.awareness.lag_hours_from(case.signal)} h"
            )

    if len(case.awareness_history) > 1:
        out += ["", "AWARENESS HISTORY  —  earlier records are kept, never edited"]
        for h in case.awareness_history:
            tag = "IN FORCE " if h["status"] == "in_force" else "SUPERSEDED"
            out.append(
                f"  {tag} seq {h['ledger_seq']:<4} {h['content_hash'][:16]}  established "
                f"{h['established_at']}  recorded {h['recorded_at']} by {h['recorded_by']}"
            )
            if h["supersedes"]:
                out.append(
                    f"             supersedes {h['supersedes'][:16]}; reason: "
                    f"{h['supersession_reason']}"
                )
        for x in case.deadline_shifts:
            out.append(
                f"  deadline recomputed: {x['stage_label']} from {x['from_due_at']} to "
                f"{x['to_due_at']} by {x['by']}, reason: {x['reason']}"
            )

    if case.triage_result:
        t = case.triage_result
        out += ["", f"TRIAGE  —  {t.status}"]
        for question, answer in t.answered.items():
            out.append(f"  {answer:13s} {question}")
        if t.ground:
            out += [
                f"  ground        {t.ground.value}",
                f"  authority     {t.authority}",
            ]
        if case.reopen_trigger:
            out.append(f"  reopen if     {case.reopen_trigger}")
        if t.reasoning:
            out.append(f"  reasoning     {t.reasoning}")

    deadlines = case.deadlines
    if deadlines:
        out += ["", "DEADLINES"]
        for d in deadlines.all():
            mark = {
                "filed_on_time": "recorded as filed, on time",
                "filed_late": "RECORDED AS FILED LATE",
                "recorded_incomplete": "RECORDED, CONTENT INCOMPLETE (not counted as met)",
                "open": "open",
            }[d.status]
            detail = ""
            if d.submitted_at is None:
                hours = d.hours_remaining(reference)
                detail = (
                    f"  ({abs(hours):.1f} h overdue)" if hours < 0 else f"  ({hours:.1f} h left)"
                )
            else:
                detail = (
                    f"  (declared {format_utc(d.submitted_at)}, {d.submission_evidence}; "
                    "not verified by the platform"
                    + ("" if d.content_complete else "; content incomplete")
                    + ")"
                )
            out.append(
                f"  {d.stage.label:26s} due {format_utc(d.due_at)}  {mark}{detail}"
            )
            out.append(f"  {'':26s} runs from {d.runs_from_fact} · {d.provision}")
            out.extend(basis_lines(d, "      "))
        for gap in deadlines.pending_facts():
            out.append(f"  not computable: {gap}")
        out += ["", "OPEN LEGAL QUESTIONS  —  not answered by this software; a qualified lawyer must decide"]
        out.extend(f"  {q['id']}: {q['question']}" for q in OPEN_LEGAL_QUESTIONS)

        platform = deadlines.to_dict(reference).get("platform_counter")
        if platform and not platform["agrees"]:
            out += [
                "",
                "PLATFORM COUNTER DISAGREES WITH THE LEGAL DEADLINE",
                f"  platform shows  {platform['displayed_notification_due']}",
                f"  legal deadline  {platform['legal_notification_due']}",
                f"  {platform['note']}",
            ]

    out += ["", "OUTSTANDING"]
    outstanding = case.outstanding(reference)
    out.extend(f"  • {item}" for item in outstanding) if outstanding else out.append(
        "  nothing outstanding"
    )
    out += ["", "AUDIT HISTORY  —  every ledger record of this case, oldest first"]
    for h in case.history:
        out.append(f"  seq {h['ledger_seq']:<4} {h['recorded_at']}  {h['recorded_by']}")
        out.append(f"      {h['summary']}")
    out += ["", _RULE]
    return _lines(*out)


def register_report(register: Art14Register, *, now: datetime | None = None) -> str:
    """Every case, worst first."""
    reference = now or utc_now()
    cases, unreadable = register.survey(reference)
    breaches = register.breaches(reference)
    ok, problems = register.ledger.verify_chain()

    out = [
        _RULE,
        "ARTICLE 14 REGISTER",
        f"generated {format_utc(reference)}",
        _RULE,
        "",
        f"  cases                {len(cases)}",
        f"  ledger records       {len(register.ledger)}",
        f"  chain verified       {'yes' if ok else 'NO — SEE BELOW'}",
        f"  deadline breaches    {len(breaches)}",
        f"  unreadable cases     {len(unreadable)}",
        f"  field spec           ENISA CRA SRP Glossary v{GLOSSARY_VERSION} ({GLOSSARY_DATE})",
        f"  clock rule version   {RULE_VERSION}",
    ]

    if not ok:
        out += ["", "LEDGER INTEGRITY FAILURE"]
        out.extend(f"  • {p}" for p in problems)

    if breaches:
        out += ["", "BREACHES"]
        for b in breaches:
            out.append(
                f"  {b['case_id']:14s} {b['stage'] or '-':16s} {b['status']:28s} "
                f"due {b['due_at'] or '-'}  {b['provision'] or ''}"
            )

    if unreadable:
        out += ["", "CASES THAT COULD NOT BE READ (not part of the totals below)"]
        out.extend(f"  {u['case_id']:14s} {u['error']}" for u in unreadable)

    out += ["", "CASES"]
    for case in cases:
        items = case.outstanding(reference)
        out.append(f"  {case.case_id:14s} {case.state:22s} {len(items)} outstanding")
        for item in items[:3]:
            out.append(f"      • {item}")
        if len(items) > 3:
            out.append(f"      … and {len(items) - 3} more")

    out += ["", _RULE]
    return _lines(*out)


def readiness_report(register: Art14Register, *, now: datetime | None = None) -> dict[str, Any]:
    """The machine-readable version, for a dashboard or a customer hand-back."""
    reference = now or utc_now()
    ok, problems = register.ledger.verify_chain()
    cases, unreadable = register.survey(reference)
    return {
        "generated_at": format_utc(reference),
        "regulation": "Regulation (EU) 2024/2847, Article 14",
        "applicable_since": "2026-09-11",
        "legacy_products_in_scope": True,
        "legacy_basis": "Art. 69(3)",
        "clock_rule_version": RULE_VERSION,
        "open_legal_questions": [dict(q) for q in OPEN_LEGAL_QUESTIONS],
        "field_spec": {"source": "ENISA CRA SRP Glossary", "version": GLOSSARY_VERSION,
                       "dated": GLOSSARY_DATE},
        "ledger": {
            "records": len(register.ledger),
            "chain_verified": ok,
            "problems": problems,
            "attestation": register.ledger.head_attestation(),
        },
        "cases": [c.to_dict(reference) for c in cases],
        "unreadable_cases": unreadable,
        "breaches": register.breaches(reference),
        "checks_skipped": [
            (
                "this register reflects what was recorded in it; events never recorded are "
                "invisible to it and to any report derived from it"
            ),
            (
                "the Commission guidance relied on for the awareness test (C(2026) 5252) is "
                "expressly non-binding"
            ),
            (
                "'sensitive or important data or functions' (Art. 14(5)(a)) is undefined in "
                "the Regulation and unelaborated in the FAQ and guidance"
            ),
            (
                "no implementing act under Art. 14(10) specifying notification format has "
                "been identified; the ENISA Glossary is operational guidance and can change "
                "without legislative process"
            ),
        ],
    }


def readiness_json(register: Art14Register, *, now: datetime | None = None) -> str:
    return json.dumps(readiness_report(register, now=now), indent=2, ensure_ascii=False)
