"""``assurance watch open-case`` — a NAMED PERSON opens a case from an intel finding.

The watch never opens a case from public intelligence: those findings are inspect-only.
This is the one step that does, and it is a person's act. It does exactly this and no more:

* re-derives the finding from the local intel store with the SAME function the runner's
  matching rests on (:func:`~assurance.watch.intel_source.impact_for_case` ->
  :func:`~assurance.fleet.impact.assess_impact`); no matching is duplicated here;
* refuses an automation/service actor or an empty / reserved name (the change service's own
  check), and a CSAF-derived candidate without ``--accept-unsigned`` and a reason (the
  change service's own unsigned-import rule): both enforced by
  :func:`~assurance.change.service.assess_advisory`, which is the only writer;
* refuses when the id is not a current finding (not in the store, or matching no machine);
* never closes, decides, defers, waives or advances anything, and does not touch a case that
  is already settled or deferred.

It reads the intel store from disk and opens no socket.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from assurance.change.service import (
    advisory_case_id,
    assess_advisory,
    named_person_problem,
)
from assurance.change.store import CaseStore
from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor
from assurance.core.identity import utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.fleet.impact import ImpactReport
from assurance.fleet.registry import Fleet
from assurance.watch.config import IntelSubscription, WatchConfig
from assurance.watch.intel_source import INTEL_TRUST_STATE, impact_for_case, store_ages

__all__ = ["OpenCaseRefusedError", "OpenCaseResult", "NOT_ESTABLISHED", "NEXT_STEPS", "open_case",
           "open_case_from_report", "role_problem"]


class OpenCaseRefusedError(AssuranceError):
    """Nothing was opened, and the reason says why."""


NOT_ESTABLISHED = (
    "that the advisory is genuine: it comes from an unauthenticated public source and no "
    "signature or publisher key was checked",
    "that any listed machine is actually affected: the match is on recorded manifest labels, "
    "and NVD ranges / conditions the model cannot represent were not matched",
    "that a machine NOT listed is unaffected",
    "that anything has been verified, fixed or accepted: the case opens with every "
    "re-verification outstanding",
)

NEXT_STEPS = (
    "read the advisory against the publisher's own page (and key, where there is one)",
    "claim the case:  assurance change claim CASE_ID --ledger LEDGER --actor NAME",
    "supply fresh verification evidence per machine/function, or record a named decision "
    "(resolve a question, waive an entry with a reason): these are human acts",
    "close or reject the case only when a person decides; this command never does",
)


@dataclass(frozen=True)
class OpenCaseResult:
    case_id: str
    #: ``opened`` | ``already_open``
    outcome: str
    status: str
    trust_state: str
    recorded_trust: str
    machines: tuple[str, ...]
    accepted_by: str
    checks_skipped: tuple[str, ...]
    #: One line per selected source of the store this finding was read from that is older
    #: than the subscription's ``max_age_hours`` (or has no accepted observation). Empty when
    #: fresh or when age is not checked. A warning, never a refusal: a person may knowingly
    #: open a case from older data.
    intel_age_warnings: tuple[str, ...] = ()


def _age_warnings(sub: IntelSubscription, now: datetime) -> tuple[str, ...]:
    ages = store_ages(sub, now)
    out = []
    for a in ages.ages:
        if a.ok:
            continue
        if a.state == "stale":
            out.append(
                f"the intel store is STALE: source '{a.source}' was last accepted at "
                f"{a.retrieved_at}, {a.age_hours:.1f} h ago; the limit is {a.limit_hours:g} h. "
                "The case was opened from data that old.")
        else:
            out.append(a.message.replace("STALE: ", "the intel store is STALE: ", 1)
                       + " The case was opened from data of unknown age.")
    return tuple(out)


def role_problem(role: str) -> str:
    """Why ``role`` cannot be recorded as a person's declared role, or ``""``."""
    if not role.strip():
        return "opening a case needs the person's role"
    if "=" in role or ";" in role:
        # The change service reads `attribution=...` tokens out of the role string; a
        # caller-typed role must not be able to imitate one.
        return "the role is free text and may not contain '=' or ';'"
    return ""


def _actor(name: str, role: str) -> Actor:
    """The person, as the change service will judge them. Always kind ``person``: a command
    line cannot be anything else, and the service refuses the names automation goes by."""
    problem = named_person_problem(name)
    if problem:
        raise OpenCaseRefusedError(
            f"opening a case needs a named person; {name!r} is not one ({problem}). "
            "Nothing was opened.")
    if not role.strip():
        raise OpenCaseRefusedError("opening a case needs the person's role (--role). "
                              "Nothing was opened.")
    if role_problem(role):
        raise OpenCaseRefusedError("the role is free text and may not contain '=' or ';'. "
                              "Nothing was opened.")
    return Actor(identifier=name.strip(), role=role.strip(), kind="person")


def open_case(
    config: WatchConfig, ledger: EvidenceLedger, advisory_id: str, *,
    actor_name: str, role: str, accept_unsigned: bool = False, reason: str = "",
    now: datetime | None = None,
) -> OpenCaseResult:
    # `now` is for the age WARNING only (library callers / tests); the CLI never sets it,
    # because this command writes a case and its record must not carry a forged clock.
    now = now or utc_now()
    actor = _actor(actor_name, role)
    fleet = Fleet.from_ledger(ledger)
    report = None
    used = None
    last: AssuranceError | None = None
    for sub in config.intel:
        try:
            report = impact_for_case(sub, advisory_id, fleet)
            used = sub
            break
        except AssuranceError as exc:
            last = exc
    if report is None:
        why = str(last) if last else "this watch has no intel subscription"
        raise OpenCaseRefusedError(
            f"{advisory_id!r} is not a current finding of this watch's intel store(s): "
            f"{why}. Nothing was opened.")
    return open_case_from_report(
        ledger, report, actor, accept_unsigned=accept_unsigned, reason=reason,
        age_warnings=_age_warnings(used, now) if used is not None else ())


def open_case_from_report(
    ledger: EvidenceLedger, report: ImpactReport, actor: Actor, *,
    accept_unsigned: bool = False, reason: str = "",
    age_warnings: tuple[str, ...] = (),
) -> OpenCaseResult:
    """Open (or return) the case for an already-derived inspect-only report.

    The one domain step behind the CLI and ``POST /v1/change/assess/advisory/intel``: refuses
    a report that touches no machine, never reopens or alters a settled case, never
    re-attributes a case someone else already accepted, and otherwise lets
    :func:`assess_advisory` (the only writer) apply the named-person / unsigned-import rules.
    """
    if report.verdict == "clear":
        raise OpenCaseRefusedError(
            f"{report.advisory_id!r} matches no machine in this ledger's fleet (verdict "
            f"{report.verdict!r}), so it is not a current finding; a case is opened only for "
            "an advisory that touches the fleet. Nothing was opened.")
    store = CaseStore(ledger)
    case_id = advisory_case_id(report)
    existing = store.get(case_id)
    if existing is not None and existing.status.is_settled:
        raise OpenCaseRefusedError(
            f"case {case_id} already exists and is {existing.status.value}; that is a "
            "person's decision and this command does not reopen or alter it. Nothing "
            "was written.")
    accepted = str(existing.provenance.get("advisory_accepted_by", "")) if existing else ""
    if existing is not None and accepted and accepted != actor.identifier:
        # Someone else already took responsibility for opening it. Do not rewrite who
        # accepted the advisory; the case is returned as it stands.
        case = existing
    else:
        case = assess_advisory(store, report, actor=actor, accept_unsigned=accept_unsigned,
                               reason=reason)
    if case is None:       # defensive: 'clear' was refused above
        raise OpenCaseRefusedError("no case applies to this advisory. Nothing was opened.")
    return OpenCaseResult(
        intel_age_warnings=age_warnings,
        case_id=case.case_id, outcome="already_open" if existing is not None else "opened",
        status=case.status.value, trust_state=INTEL_TRUST_STATE,
        recorded_trust=str(case.provenance.get("advisory_trust", "")),
        machines=tuple(case.machines),
        accepted_by=str(case.provenance.get("advisory_accepted_by", "")),
        checks_skipped=tuple(case.checks_skipped))
