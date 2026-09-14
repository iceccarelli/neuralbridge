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
from .engine import Art14Register, Case
from .srp import GLOSSARY_DATE, GLOSSARY_VERSION

__all__ = ["case_report", "readiness_report", "register_report"]

_RULE = "─" * 78


def _lines(*parts: str) -> str:
    return "\n".join(parts)


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
                "filed_on_time": "filed, on time",
                "filed_late": "FILED LATE",
                "open": "open",
            }[d.status]
            detail = ""
            if d.submitted_at is None:
                hours = d.hours_remaining(reference)
                detail = (
                    f"  ({abs(hours):.1f} h overdue)" if hours < 0 else f"  ({hours:.1f} h left)"
                )
            out.append(
                f"  {d.stage.label:26s} due {format_utc(d.due_at)}  {mark}{detail}"
            )
            out.append(f"  {'':26s} runs from {d.runs_from_fact} · {d.provision}")
        for gap in deadlines.pending_facts():
            out.append(f"  not computable: {gap}")

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
    out += ["", _RULE]
    return _lines(*out)


def register_report(register: Art14Register, *, now: datetime | None = None) -> str:
    """Every case, worst first."""
    reference = now or utc_now()
    cases = register.cases()
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
        f"  field spec           ENISA CRA SRP Glossary v{GLOSSARY_VERSION} ({GLOSSARY_DATE})",
    ]

    if not ok:
        out += ["", "LEDGER INTEGRITY FAILURE"]
        out.extend(f"  • {p}" for p in problems)

    if breaches:
        out += ["", "BREACHES"]
        for b in breaches:
            out.append(
                f"  {b['case_id']:14s} {b['stage']:16s} {b['status']:18s} "
                f"due {b['due_at']}  {b['provision']}"
            )

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
    cases = register.cases()
    return {
        "generated_at": format_utc(reference),
        "regulation": "Regulation (EU) 2024/2847, Article 14",
        "applicable_since": "2026-09-11",
        "legacy_products_in_scope": True,
        "legacy_basis": "Art. 69(3)",
        "field_spec": {"source": "ENISA CRA SRP Glossary", "version": GLOSSARY_VERSION,
                       "dated": GLOSSARY_DATE},
        "ledger": {
            "records": len(register.ledger),
            "chain_verified": ok,
            "problems": problems,
            "attestation": register.ledger.head_attestation(),
        },
        "cases": [c.to_dict(reference) for c in cases],
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
