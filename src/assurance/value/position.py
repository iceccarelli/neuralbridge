"""What the customer's own verified ledger says about where their assurance stands.

A read-only, deterministic analysis. Nothing is estimated: no savings, no risk
percentages, no score. Every line is one of

* ``fact`` — read from sealed records, with the ledger entry it came from;
* ``unknown`` — the ledger cannot say (never observed, never verified, not read
  off the unit); an unknown is never presented as fine;
* ``assumption`` — a statement that rests on something the ledger does not hold;
* ``recommendation`` — ranked work whose order is a fixed rule (below), not a
  prediction. The rule is printed with the result.

The chain is verified first and the result says so; on a chain that does not
verify, nothing derived from it is offered as fact.

Reuses :mod:`assurance.machinery` (manifests, coverage), :mod:`assurance.change`
(cases) and :mod:`assurance.watch.observations` (look freshness). It adds no
second source of truth.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from assurance.change.store import CaseStore
from assurance.core.identity import format_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.recorder_attestation import RecorderTrust
from assurance.machinery.manifest import HashSource
from assurance.machinery.record import (
    MANIFEST_KIND,
    interventions_from_ledger,
    manifests_from_ledger,
)
from assurance.machinery.staleness import Coverage, VerificationRecord, assess_coverage
from assurance.watch.observations import fleet_observations

__all__ = ["POSITION_SCHEMA", "assess_position", "render_text"]

POSITION_SCHEMA = "assurance.position/1"

#: Fixed order of recommended work, most consequential first. The order is a rule
#: of this package (a decision a person owes outranks evidence owed, which
#: outranks evidence that has gone stale, which outranks not having looked, which
#: outranks never having verified, which outranks an incomplete inventory). It is
#: not derived from any probability or cost.
_PRIORITY = (
    ("decision_owed", "A person owes a decision on an open case"),
    ("reverification_owed", "Re-verification evidence is owed on an open case"),
    ("function_failing", "A safety function's latest verification did not pass"),
    ("function_stale", "A safety function's verification was invalidated by a later change"),
    ("machine_unobserved", "The machine has no recent successful observation"),
    ("function_unchecked", "A safety function's latest verification left its checks unchecked"),
    ("function_incomplete", "A safety function's latest verification checked only part of it"),
    ("function_never_verified", "A safety function has never been verified"),
    ("inventory_not_read", "Safety items were not read off the unit"),
)
_RANK = {k: i + 1 for i, (k, _) in enumerate(_PRIORITY)}

_NOT_ASSESSED = [
    "whether any machine behaves as its manifest says: the ledger holds what was "
    "collected and what was verified, not the machine",
    "whether verification evidence was produced on the machine it is filed under; "
    "the trace's origin is declared by whoever filed it",
    "supplier advisories not yet ingested into this ledger, and the correctness of "
    "those that were",
    "any machine, item or function not in a manifest sealed in this ledger",
    "regulatory classification or deadlines; those are human determinations",
]


def assess_position(ledger: EvidenceLedger, *, now: datetime | None = None,
                    recorder_trust: RecorderTrust | None = None) -> dict[str, Any]:
    as_of = now or utc_now()
    problems, head_seq, head_link = ledger.verify_full()
    out: dict[str, Any] = {
        "schema": POSITION_SCHEMA,
        "as_of": format_utc(as_of),
        "ledger": {"entries": head_seq, "head_link_hash": head_link,
                   "chain_verified": not problems, "chain_problems": problems[:5]},
        "measurement_basis": [
            "read-only analysis of the sealed records in this ledger",
            "evidence whose own seal does not verify is ignored by the readers used here",
            "ordering of recommended work is a fixed rule, printed below; no score, "
            "probability or monetary estimate is produced",
        ],
        "priority_rule": [{"kind": k, "meaning": m} for k, m in _PRIORITY],
        "not_assessed": list(_NOT_ASSESSED),
    }
    if problems:
        out.update(machines=[], totals={}, findings=[], next_work=[], withheld=(
            "the ledger's hash chain does not verify, so nothing derived from it is "
            "offered. Repair or restore the ledger before relying on any figure."))
        return out

    observations = {m["machine"]: m for m in fleet_observations(ledger, now=as_of)["machines"]}
    keys = sorted({e.subject for e in ledger.entries(kind=MANIFEST_KIND)
                   if e.subject} | set(observations))
    cases = CaseStore(ledger).list()
    open_by_machine: dict[str, list[Any]] = {}
    for c in cases:
        if c.is_open:
            for m in c.machines:
                open_by_machine.setdefault(m, []).append(c)

    machines: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    work: list[dict[str, Any]] = []

    def fact(kind: str, machine: str, statement: str, refs: list[dict[str, Any]] | None = None,
             *, work_kind: str = "", action: str = "") -> None:
        findings.append({"kind": kind, "machine": machine, "statement": statement,
                         "refs": refs or []})
        if work_kind:
            work.append({"work": work_kind, "rank": _RANK[work_kind], "machine": machine,
                         "kind": "recommendation", "action": action,
                         "because": statement, "refs": refs or []})

    for key in keys:
        history = manifests_from_ledger(ledger, key)
        obs = observations.get(key, {})
        rec: dict[str, Any] = {"machine": key, "manifest": None, "inventory": None,
                               "coverage": None, "observation": {
                                   k: obs.get(k) for k in (
                                       "reported", "last_successful_observation_at",
                                       "last_attempt_at", "last_attempt_status", "stale",
                                       "stale_reason", "age_hours", "cadence_hours",
                                       "consecutive_failed_attempts")},
                               "open_case_ids": sorted(c.case_id for c in open_by_machine.get(key, []))}
        entries = list(ledger.entries(kind=MANIFEST_KIND, subject=key))
        if not history:
            fact("unknown", key, f"{key}: no sealed manifest, so what is installed is unknown.")
            machines.append(rec)
            continue
        m = history[-1]
        ref = [{"seq": entries[-1].seq, "content_hash": entries[-1].content_hash}] if entries else []
        read = [i for i in m.items if i.hash_source is HashSource.READ_FROM_MACHINE]
        vendor = [i for i in m.items if i.hash_source is HashSource.SUPPLIED_BY_VENDOR]
        declared = [i for i in m.items if i.hash_source is HashSource.DECLARED]
        incomplete = "[collection incomplete" in (m.notes or "")
        age_days = round((as_of - m.taken_at).total_seconds() / 86400, 1)
        rec["manifest"] = {"manifest_id": m.manifest_id, "taken_at": format_utc(m.taken_at),
                           "age_days": age_days, "source": m.source.value,
                           "collection_incomplete": incomplete,
                           "configuration_hash": m.configuration_hash()}
        rec["inventory"] = {"items": len(m.items), "read_from_machine": len(read),
                            "supplied_by_vendor": len(vendor), "declared_only": len(declared)}
        fact("fact", key, f"{key}: manifest {m.manifest_id} taken {format_utc(m.taken_at)} "
             f"lists {len(m.items)} item(s): {len(read)} hashed off the unit, {len(vendor)} "
             f"hashed from a vendor file, {len(declared)} declared with no hash.", ref)
        if incomplete:
            fact("unknown", key, f"{key}: the newest manifest records that its collection was "
                 "incomplete; items the plan names but could not read are unknown.", ref,
                 work_kind="inventory_not_read",
                 action=f"Re-collect {key} until every planned item is read.")
        elif vendor or declared:
            fact("assumption", key, f"{key}: {len(vendor) + len(declared)} item(s) rest on a "
                 "vendor file or a typed version, not on a hash taken from the unit; "
                 "they say what should be there, not what is.", ref,
                 work_kind="inventory_not_read",
                 action=f"Read the {len(vendor) + len(declared)} unverified item(s) off {key}.")

        cov = assess_coverage(
            m, VerificationRecord.from_ledger(ledger, subject=key,
                                              recorder_trust=recorder_trust),
            interventions_from_ledger(ledger, key))
        counts: dict[str, int] = {c.value: 0 for c in Coverage}
        for f in cov.functions:
            counts[f.coverage.value] += 1
        rec["coverage"] = {"functions": len(cov.functions), **counts}
        for f in cov.functions:
            refs = ([{"content_hash": f.last_verified_hash}] if f.last_verified_hash else [])
            if f.coverage is Coverage.CURRENT:
                continue
            label = {"failing": "function_failing", "stale": "function_stale",
                     "unchecked": "function_unchecked", "incomplete": "function_incomplete",
                     "never_verified": "function_never_verified"}.get(f.coverage.value)
            kind = "unknown" if f.coverage in (
                Coverage.NEVER_VERIFIED, Coverage.NOT_DEMONSTRABLE, Coverage.UNCHECKED,
                Coverage.INCOMPLETE) else "fact"
            fact(kind, key, f"{key}/{f.function_id}: evidence is {f.coverage.value}"
                 + (f" (invalidated by {f.invalidated_by})" if f.invalidated_by else "") + ".",
                 refs, work_kind=label or "", action=(
                     f"Verify {f.function_id} on {key} after the current configuration."
                     if label else ""))

        # Observations are client-reported; say so with the finding.
        if obs.get("stale"):
            fact("unknown", key, f"{key}: no recent successful observation "
                 f"({obs.get('stale_reason')}); last successful look "
                 f"{obs.get('last_successful_observation_at')}. A missing report is not "
                 "evidence the machine is unchanged.", [],
                 work_kind="machine_unobserved",
                 action=f"Run the watch against {key} and push or seal the result.")

        for c in open_by_machine.get(key, []):
            ref_c = [{"case_id": c.case_id}]
            if c.human_decisions_required or c.status.value in ("ready_to_close", "awaiting_action"):
                fact("fact", key, f"case {c.case_id} ({c.status.value}) awaits a human decision.",
                     ref_c, work_kind="decision_owed",
                     action=f"A decider operator should answer: {c.next_action}")
            if c.required_reverifications:
                fact("fact", key, f"case {c.case_id} awaits re-verification of "
                     f"{', '.join(c.required_reverifications)}.", ref_c,
                     work_kind="reverification_owed",
                     action=f"Supply post-change verification evidence for "
                            f"{', '.join(c.required_reverifications)}.")
        machines.append(rec)

    seen_cases: set[tuple[str, str]] = set()
    uniq = []
    for w in sorted(work, key=lambda w: (w["rank"], w["machine"], w["action"])):
        sig = (w["work"], w["because"])
        if sig in seen_cases:
            continue
        seen_cases.add(sig)
        uniq.append(w)
    for i, w in enumerate(uniq, 1):
        w["order"] = i

    out.update(
        machines=machines,
        totals={
            "machines": len(machines),
            "machines_with_inventory_fully_read_off_the_unit": sum(
                1 for r in machines if r["inventory"] and r["inventory"]["items"]
                and r["inventory"]["read_from_machine"] == r["inventory"]["items"]
                and not r["manifest"]["collection_incomplete"]),
            "machines_without_a_manifest": sum(1 for r in machines if r["manifest"] is None),
            "machines_stale_or_unobserved": sum(
                1 for r in machines if r["observation"].get("stale")),
            "functions_current": sum((r["coverage"] or {}).get("current", 0) for r in machines),
            "functions_not_current": sum(
                (r["coverage"] or {}).get("functions", 0) - (r["coverage"] or {}).get("current", 0)
                for r in machines),
            "open_cases": sum(1 for c in cases if c.is_open),
        },
        findings=findings, next_work=uniq,
        observation_limits=("Observation dates are client-reported by the customer's own "
                            "watch; a submitted observation is not independent telemetry."),
    )
    return out


def render_text(result: dict[str, Any]) -> str:
    lines = [f"Assurance position as of {result['as_of']}",
             f"  ledger: {result['ledger']['entries']} entries, chain "
             f"{'verified' if result['ledger']['chain_verified'] else 'DOES NOT VERIFY'}"]
    if result.get("withheld"):
        return "\n".join([*lines, "", result["withheld"]])
    t = result["totals"]
    lines += ["", "Totals (each is a count of sealed records, not a score):"]
    lines += [f"  {k.replace('_', ' ')}: {v}" for k, v in t.items()]
    lines += ["", "Findings:"]
    for f in result["findings"]:
        lines.append(f"  [{f['kind']:<10}] {f['statement']}")
    lines += ["", "Next work (fixed priority rule, not a prediction):"]
    for w in result["next_work"]:
        lines.append(f"  {w['order']}. [{w['kind']}] {w['action']}  — {w['because']}")
    if not result["next_work"]:
        lines.append("  none recorded; that does not mean nothing is wrong (see not assessed).")
    lines += ["", "Not assessed:"] + [f"  - {x}" for x in result["not_assessed"]]
    lines += ["", result["observation_limits"]]
    return "\n".join(lines)

