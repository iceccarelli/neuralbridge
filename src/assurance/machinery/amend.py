"""Amend a machine's declared enrolment attributes, without rewriting anything.

Enrolment (:mod:`assurance.machinery.enrol`) records an identity as declared: site, owner,
year, country. That record is sealed and is never edited. A site changes (the machine is
moved) and an owner changes (it is sold); :func:`amend_enrolment` is the path for that, and
it is a **new** record:

* one ``machinery.enrolment_amendment`` entry under the machine key, naming the enrolment
  entry it amends and the amendment before it, so each machine has one amendment chain;
* the effective identity is the enrolment followed by its amendments in order
  (:func:`effective_identity`). Every reader that shows a site or owner shows the effective
  value *and* that it was amended: who, when, why, from -> to;
* the enrolment record, and every earlier amendment, stay in the ledger byte for byte.

Rules:

* only a named person amends (same rule as enrolment), and a reason is required;
* the machine must already be enrolled;
* only the declared attributes ``site`` and ``owner`` are amendable. Year and country are
  not, and the machine key (manufacturer / model / serial) or its configuration is not an
  attribute at all: a different key is a different machine (enrol it), a different
  configuration is drift (``machinery diff`` / ``change assess drift``);
* an amendment that changes nothing writes nothing;
* concurrent amendments are serialised by the ledger's compare-and-swap on the subject
  head: both are recorded in one order, or one is refused. The chain never forks.

An amendment does not authenticate the identity to a physical unit, does not make the earlier
value disappear, and runs no verification; the configuration hash and coverage are untouched.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from assurance.core.errors import LedgerConflictError
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    Origin,
    ValidationState,
)
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.enrol import (
    ENROLMENT_KIND,
    IDENTITY_BASIS,
    EnrolmentError,
    enrolment_of,
    require_person,
)

__all__ = [
    "AMENDABLE",
    "AMENDMENT_KIND",
    "AMENDMENT_SCHEMA",
    "Amendment",
    "AmendmentError",
    "AmendmentReceipt",
    "EffectiveIdentity",
    "amend_enrolment",
    "effective_identity",
]

AMENDMENT_KIND = "machinery.enrolment_amendment"
AMENDMENT_SCHEMA = "assurance.machinery.enrolment_amendment/1"

#: The declared attributes a named person may amend. Year and country are declared at
#: enrolment and are not amendable here.
AMENDABLE = ("site", "owner")

#: Names that are the machine's key or configuration, not attributes of it.
_KEY_FIELDS = frozenset({
    "key", "machine", "machine_key", "manufacturer", "model", "serial", "identity",
    "configuration", "configuration_hash", "manifest", "manifest_id", "items", "functions",
    "firmware", "software",
})

AMENDED = "amended"
NO_CHANGE = "no_change"
NOT_ENROLLED = "not_enrolled"
UNKNOWN_ATTRIBUTE = "unknown_attribute"
KEY_CHANGE_REFUSED = "key_change_refused"

MAX_VALUE = 200
MAX_REASON = 1000

NOT_ESTABLISHED = (
    "identity is still as declared by the person named here, not authenticated to a physical "
    "unit: nothing shows the new value is true of the machine",
    "the previous value is not erased: it stays in the ledger, in the enrolment record and in "
    "this amendment, and is shown beside the new one",
    "the reason is the amender's statement and was not checked",
    "no verification was run: the configuration, the manifest and every function's coverage "
    "are as they were before",
)

_POINTER_KEY = (
    "the machine key and its configuration are not attributes that can be amended. A "
    "different manufacturer / model / serial is a different machine: enrol it "
    "(`machinery enrol`). A changed configuration is drift: grade it with `machinery diff` "
    "or `change assess drift`.")


class AmendmentError(EnrolmentError):
    """The amendment request cannot be read, or cannot be made by this caller.

    Nothing was written.
    """


def _text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _clean(label: str, value: Any, limit: int) -> str:
    if not isinstance(value, str):
        raise AmendmentError(f"{label} must be text.")
    text = _text(value)
    if any(unicodedata.category(c) in ("Cf", "Cc", "Zl", "Zp") for c in value
           if c not in " \t\n\r"):
        raise AmendmentError(f"{label} contains invisible or control characters.")
    if len(text) > limit:
        raise AmendmentError(f"{label} is longer than {limit} characters.")
    return text


# -- reading back ----------------------------------------------------------


@dataclass(frozen=True)
class Amendment:
    """One recorded amendment, as read back from the ledger."""

    sequence: int
    entry: int
    content_hash: str
    previous_hash: str
    at: str
    by: str
    reason: str
    changes: dict[str, dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence, "entry": self.entry,
            "content_hash": self.content_hash,
            "previous_amendment_hash": self.previous_hash,
            "at": self.at, "by": self.by, "reason": self.reason,
            "changes": {k: dict(v) for k, v in self.changes.items()},
        }


@dataclass(frozen=True)
class EffectiveIdentity:
    """The enrolment followed by its amendments, in order.

    ``effective`` is what readers show; ``original`` is what was declared at enrolment.
    ``problems`` lists amendment records that could not be applied (damaged, edited, not
    linked to the enrolment or to the amendment before, or whose ``from`` is not the value
    in force); application stops at the first one, and nothing after it is shown as in force.
    """

    machine_key: str
    enrolment_entry: int
    enrolment_content_hash: str
    original: dict[str, str]
    effective: dict[str, str]
    amendments: tuple[Amendment, ...] = ()
    problems: tuple[str, ...] = ()

    @property
    def amended(self) -> bool:
        return bool(self.amendments)

    @property
    def head_entry(self) -> int:
        return self.amendments[-1].entry if self.amendments else self.enrolment_entry

    @property
    def head_hash(self) -> str:
        return self.amendments[-1].content_hash if self.amendments else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "machine": self.machine_key,
            "enrolment_entry": self.enrolment_entry,
            "enrolment_content_hash": self.enrolment_content_hash,
            "effective": dict(self.effective),
            "original": dict(self.original),
            "amended": self.amended,
            "amendments": [a.to_dict() for a in self.amendments],
            "problems": list(self.problems),
            "identity_basis": IDENTITY_BASIS,
        }


def effective_identity(
    ledger: EvidenceLedger, machine_key: str,
    enrolment: tuple[Any, dict[str, Any]] | None = None,
) -> EffectiveIdentity | None:
    """The identity in force for ``machine_key``, or ``None`` when it is not enrolled.

    Raises :class:`~assurance.core.errors.AssuranceError` (via :func:`enrolment_of`) when the
    enrolment record itself is damaged. A damaged or inconsistent *amendment* is reported in
    ``problems`` rather than raised, so a reader can still show the identity up to it.
    """
    found = enrolment if enrolment is not None else enrolment_of(ledger, machine_key)
    if found is None:
        return None
    entry, body = found
    original = {k: _text(v) for k, v in dict(body.get("declared", {})).items()}
    effective = dict(original)
    applied: list[Amendment] = []
    problems: list[str] = []

    readable, damaged, _ = ledger.read_subject(machine_key, AMENDMENT_KIND)
    for d in damaged:
        problems.append(f"amendment record at entry {d.seq} cannot be read: {d.why}")
    previous = ""
    for e in readable:
        if problems:
            break
        evidence = e.evidence()
        if not evidence.verify():
            problems.append(f"amendment at entry {e.seq} no longer matches its own seal")
            break
        b = evidence.body
        if b.get("enrolment_content_hash") != entry.content_hash:
            problems.append(f"amendment at entry {e.seq} does not reference this enrolment")
            break
        if b.get("previous_amendment_hash", "") != previous:
            problems.append(f"amendment at entry {e.seq} does not follow the amendment "
                            "before it")
            break
        if b.get("sequence") != len(applied) + 1:
            problems.append(f"amendment at entry {e.seq} is out of sequence")
            break
        changes = b.get("changes")
        ok = isinstance(changes, dict) and bool(changes)
        parsed: dict[str, dict[str, str]] = {}
        if ok:
            for attr, ft in changes.items():
                if (attr not in AMENDABLE or not isinstance(ft, dict)
                        or _text(ft.get("from")) != effective.get(attr, "")
                        or not _text(ft.get("to"))):
                    ok = False
                    break
                parsed[attr] = {"from": _text(ft["from"]), "to": _text(ft["to"])}
        if not ok:
            problems.append(f"amendment at entry {e.seq} does not apply to the identity in "
                            "force when it was written")
            break
        for attr, ft in parsed.items():
            effective[attr] = ft["to"]
        am = Amendment(
            sequence=len(applied) + 1, entry=e.seq, content_hash=e.content_hash,
            previous_hash=previous, at=e.at, by=e.actor,
            reason=str(b.get("reason", "")), changes=parsed)
        applied.append(am)
        previous = e.content_hash
    return EffectiveIdentity(
        machine_key=machine_key, enrolment_entry=entry.seq,
        enrolment_content_hash=entry.content_hash, original=original,
        effective=effective, amendments=tuple(applied), problems=tuple(problems))


# -- the receipt -----------------------------------------------------------


@dataclass(frozen=True)
class AmendmentReceipt:
    """What an amendment attempt did, and what it does not mean.

    ``status`` is ``amended`` | ``no_change`` | ``not_enrolled`` | ``unknown_attribute`` |
    ``key_change_refused``. The last three are refusals; ``written`` is ``False`` for them
    and for ``no_change``, and the ledger is untouched.
    """

    status: str
    written: bool
    machine_key: str
    changes: dict[str, dict[str, str]] = field(default_factory=dict)
    effective: dict[str, str] = field(default_factory=dict)
    original: dict[str, str] = field(default_factory=dict)
    reason: str = ""
    amended_by: str = ""
    amended_at: str = ""
    sequence: int = 0
    amendment_entry: int = 0
    amendment_content_hash: str = ""
    previous_amendment_hash: str = ""
    enrolment_entry: int = 0
    enrolment_content_hash: str = ""
    rejected: tuple[str, ...] = ()
    pointer: str = ""

    @property
    def refused(self) -> bool:
        return self.status in (NOT_ENROLLED, UNKNOWN_ATTRIBUTE, KEY_CHANGE_REFUSED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": AMENDMENT_SCHEMA,
            "status": self.status,
            "written": self.written,
            "machine": self.machine_key,
            "changes": {k: dict(v) for k, v in self.changes.items()},
            "effective": dict(self.effective),
            "original": dict(self.original),
            "reason": self.reason,
            "amended_by": self.amended_by,
            "amended_at": self.amended_at,
            "sequence": self.sequence,
            "amendment_entry": self.amendment_entry,
            "amendment_content_hash": self.amendment_content_hash,
            "previous_amendment_hash": self.previous_amendment_hash,
            "enrolment_entry": self.enrolment_entry,
            "enrolment_content_hash": self.enrolment_content_hash,
            "rejected": list(self.rejected),
            "pointer": self.pointer,
            "identity_basis": IDENTITY_BASIS,
            "does_not_establish": list(NOT_ESTABLISHED),
        }

    def summary(self) -> str:
        head = {
            AMENDED: f"amended the enrolment of {self.machine_key}",
            NO_CHANGE: f"no change for {self.machine_key}; nothing written",
            NOT_ENROLLED: f"REFUSED: {self.machine_key} is not enrolled; nothing written",
            UNKNOWN_ATTRIBUTE: "REFUSED: not an amendable attribute; nothing written",
            KEY_CHANGE_REFUSED: ("REFUSED: the machine key or configuration is not an "
                                 "amendment; nothing written"),
        }[self.status]
        lines = [head]
        for attr, ft in self.changes.items():
            lines.append(f"  {attr:<8}      {ft['from'] or '(not declared)'!r} -> {ft['to']!r}")
        if self.reason:
            lines.append(f"  reason        {self.reason}")
        if self.written:
            lines.append(f"  amendment     {self.amendment_content_hash[:16]} (entry "
                         f"{self.amendment_entry}, number {self.sequence}, by "
                         f"{self.amended_by}, {self.amended_at})")
            lines.append(f"  amends        enrolment {self.enrolment_content_hash[:16]} "
                         f"(entry {self.enrolment_entry}), unchanged")
        shown = {k: v for k, v in self.effective.items() if v}
        if shown:
            lines.append("  now in force  " + ", ".join(f"{k}={v}" for k, v in shown.items()))
        for name in self.rejected:
            lines.append(f"  rejected      {name}")
        if self.pointer:
            lines.append(f"  next          {self.pointer}")
        lines.append("  an amendment does NOT establish:")
        lines.extend(f"    - {n}" for n in NOT_ESTABLISHED)
        return "\n".join(lines)


# -- the domain function ---------------------------------------------------


def amend_enrolment(
    ledger: EvidenceLedger,
    machine_key: str,
    *,
    actor: Actor | None,
    changes: Mapping[str, Any],
    reason: str,
) -> AmendmentReceipt:
    """Amend the declared ``site`` / ``owner`` of an enrolled machine, as a new record.

    Raises :class:`AmendmentError` (an :class:`~assurance.machinery.enrol.EnrolmentError`)
    when the actor is not a named person, the reason is empty, there is nothing to amend, a
    value is empty or malformed, the ledger chain does not verify, or the machine's existing
    amendment records are inconsistent. Everything else is a receipt: refusals
    (``not_enrolled``, ``unknown_attribute``, ``key_change_refused``) and ``no_change``
    write nothing.
    """
    try:
        who = require_person(actor, "amendment")
    except AmendmentError:
        raise
    except EnrolmentError as exc:
        raise AmendmentError(str(exc)) from exc
    why = _clean("the reason", reason or "", MAX_REASON)
    if not why:
        raise AmendmentError(
            "an amendment needs a reason (--reason / reason): who changed what is on the "
            "record, and the record must also say why. Nothing was written.")
    key = _text(machine_key)
    if not key:
        raise AmendmentError("an amendment needs the machine key. Nothing was written.")
    if not isinstance(changes, Mapping) or not changes:
        raise AmendmentError(
            f"nothing to amend: name at least one of {', '.join(AMENDABLE)}. "
            "Nothing was written.")

    ok, problems = ledger.verify_chain()
    if not ok:
        raise AmendmentError(
            "the ledger chain does not verify, so nothing was amended: "
            + "; ".join(problems[:3]))

    names = [str(n) for n in changes]
    key_like = tuple(n for n in names if n.strip().lower() in _KEY_FIELDS)
    unknown = tuple(n for n in names if n not in AMENDABLE and n not in key_like)
    wanted: dict[str, str] = {}
    if not key_like and not unknown:
        for attr in AMENDABLE:
            if attr in changes:
                value = _clean(f"the new {attr}", changes[attr], MAX_VALUE)
                if not value:
                    raise AmendmentError(
                        f"the new {attr} is empty. An amendment replaces a value with "
                        "another; clearing one is not an amendment. Nothing was written.")
                wanted[attr] = value

    for _ in range(6):
        ident = effective_identity(ledger, key)
        if ident is None:
            return AmendmentReceipt(
                status=NOT_ENROLLED, written=False, machine_key=key, reason=why,
                pointer="the machine is not enrolled in this ledger: enrol it first "
                        "(`machinery enrol`). An amendment needs an enrolment to amend.")
        common: dict[str, Any] = {
            "machine_key": key, "reason": why, "original": dict(ident.original),
            "effective": dict(ident.effective),
            "enrolment_entry": ident.enrolment_entry,
            "enrolment_content_hash": ident.enrolment_content_hash,
        }
        if key_like:
            return AmendmentReceipt(
                status=KEY_CHANGE_REFUSED, written=False, rejected=key_like,
                pointer=_POINTER_KEY, **common)
        if unknown:
            return AmendmentReceipt(
                status=UNKNOWN_ATTRIBUTE, written=False, rejected=unknown,
                pointer=f"only {', '.join(AMENDABLE)} can be amended; year and country "
                        "stay as declared at enrolment.", **common)
        if ident.problems:
            raise AmendmentError(
                "the amendment records for this machine are inconsistent, so nothing was "
                "written: " + "; ".join(ident.problems[:3]))

        delta = {a: {"from": ident.effective.get(a, ""), "to": v}
                 for a, v in wanted.items() if ident.effective.get(a, "") != v}
        if not delta:
            return AmendmentReceipt(status=NO_CHANGE, written=False, **common)

        sequence = len(ident.amendments) + 1
        body = {
            "schema": AMENDMENT_SCHEMA,
            "machine": key,
            "enrolment_entry": ident.enrolment_entry,
            "enrolment_content_hash": ident.enrolment_content_hash,
            "previous_amendment_hash": ident.head_hash,
            "sequence": sequence,
            "changes": delta,
            "reason": why,
            "amended_by": who.identifier,
            "identity_basis": IDENTITY_BASIS,
            "previous_values_remain": "the enrolment record and every earlier amendment are "
                                      "unchanged in the ledger",
            "does_not_establish": list(NOT_ESTABLISHED),
        }
        evidence = Evidence(
            kind=AMENDMENT_KIND,
            body=body,
            actor=who,
            origin=Origin(
                system="assurance.machinery",
                reference=f"{key} / amendment {sequence}",
                method="enrolment amendment declared by a named person; identity as declared",
            ),
            validation_state=ValidationState.UNVERIFIED,
            confidence=Confidence.LOW,
            checks_skipped=NOT_ESTABLISHED,
        ).seal()
        try:
            appended = ledger.append(
                evidence, subject=key,
                expect_subject_head=ident.head_entry,
                expect_kinds=(ENROLMENT_KIND, AMENDMENT_KIND),
            )
        except LedgerConflictError:
            continue   # another amendment landed between the read and the write: read again
        effective = dict(ident.effective)
        effective.update({a: ft["to"] for a, ft in delta.items()})
        common["effective"] = effective
        return AmendmentReceipt(
            status=AMENDED, written=True, changes=delta, amended_by=who.identifier,
            amended_at=appended.at, sequence=sequence, amendment_entry=appended.seq,
            amendment_content_hash=evidence.content_hash,
            previous_amendment_hash=ident.head_hash, **common)
    raise AmendmentError(f"{key!r} is being amended concurrently; nothing was written. "
                         "Try again.")

