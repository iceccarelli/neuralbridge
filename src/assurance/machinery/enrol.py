"""The front door of the lifecycle: enrol one machine.

Machine -> Configuration -> Software -> Evidence -> Change -> Verification -> Finding ->
Intervention -> Attestation. Everything after the first arrow was reachable only by
somebody who already knew to seal a manifest. :func:`enrol_machine` is the one step that
says "this unit is now one this ledger keeps a record of", and it says exactly that and
no more.

What enrolment does:

* seals the manifest with :func:`~assurance.machinery.record.record_manifest` (or, when
  that exact manifest is already sealed for this key, points at the entry that holds it);
* seals one ``machinery.enrolment`` record under the machine key: the identity as declared
  (manufacturer, model, serial, year, site, country, owner), the configuration hash the
  machine was enrolled with, and what the record does not establish;
* returns a receipt that repeats the same limits.

What it refuses to do, and why:

* **Re-enrol the same configuration**: nothing is written; the receipt says
  ``already_enrolled``.
* **Re-enrol a changed configuration**: that is not an enrolment, it is drift. Nothing is
  written; the receipt says ``configuration_differs`` and points at ``machinery diff`` /
  ``change assess drift``, which are the paths that grade a change.
* **Claim an enrolled key with different declared attributes**: ``identity_conflict``.
  Nothing is written. Two records of one key that disagree about the site or the owner are
  a question for a person, not a merge.

Enrolment is a person's declaration. The actor must be a named person; the identity is as
declared and is **not authenticated to a physical unit** (nothing here proves the serial on
the manifest is the serial on the machine). It runs no verification, so every demonstrable
function reads ``never_verified`` afterwards, and it does not show the manifest is
complete. Software drafts the receipt; a named human makes the declaration.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from assurance.core.errors import AssuranceError, LedgerConflictError
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    Origin,
    ValidationState,
)
from assurance.evidence.ledger import EvidenceLedger
from assurance.machinery.manifest import SafetyManifest
from assurance.machinery.record import (
    MANIFEST_KIND,
    interventions_from_ledger,
    record_manifest,
)
from assurance.machinery.staleness import VerificationRecord, assess_coverage

__all__ = [
    "ENROLMENT_KIND",
    "ENROLMENT_SCHEMA",
    "EnrolmentError",
    "EnrolmentReceipt",
    "enrol_machine",
    "enrolment_of",
    "require_person",
]

ENROLMENT_KIND = "machinery.enrolment"
ENROLMENT_SCHEMA = "assurance.machinery.enrolment/1"

#: Receipt statuses. ``enrolled`` and ``already_enrolled`` are the two that leave the
#: machine enrolled; the other two are refusals and write nothing.
ENROLLED = "enrolled"
ALREADY_ENROLLED = "already_enrolled"
CONFIGURATION_DIFFERS = "configuration_differs"
IDENTITY_CONFLICT = "identity_conflict"

#: Declared attributes compared when a key is claimed a second time. The key itself
#: (manufacturer / model / serial) is what makes it the same machine.
_ATTRIBUTES = ("site", "owner", "year", "country")

IDENTITY_BASIS = (
    "as declared by the person named in the record; not authenticated to a physical unit"
)

NOT_ESTABLISHED = (
    "not verified safe: enrolment runs no verification and states no safety conclusion",
    "no verification has been run yet: every safety function reads never_verified until a "
    "verification is recorded",
    "manifest completeness is not shown: an item nobody listed is absent from every later "
    "comparison",
    "identity is as declared, not authenticated to a physical unit: the serial on the "
    "manifest is a claim by the person who enrolled it",
)

NEXT_STEPS = (
    "verify: run `machine verify` for each declared safety function against its envelope",
    "record the baseline verification into this ledger (`machine verify --ledger ... "
    "--subject <machine key>`), then run `machinery coverage`",
)

_RESERVED_NAMES = frozenset({
    "automation", "watch", "agent", "service", "system", "bot", "assistant", "operator", "ai",
})


class EnrolmentError(AssuranceError):
    """The enrolment request cannot be read or cannot be made by this caller."""


def require_person(actor: Actor | None, act: str = "enrolment") -> Actor:
    """Enrolment is a declaration, and only a named person makes one.

    ``act`` names the declaration in the refusal (``amendment`` for an amended identity).

    Mirrors the rule the change workflow applies to human decisions (``Actor.kind`` must be
    ``person``; the name must be one a person could have), without importing that package.
    """
    if actor is None or not actor.identifier.strip():
        raise EnrolmentError(
            f"{act} is a declaration and needs a named person (--actor / actor). "
            f"An unattributed {act} is not recorded.")
    if actor.kind != "person":
        raise EnrolmentError(
            f"{act} needs a named person; actor {actor.identifier!r} is kind "
            f"{actor.kind!r}. Automation can collect and seal a manifest, but cannot declare "
            "that a unit is enrolled or what its identity is.")
    norm = unicodedata.normalize("NFKC", actor.identifier)
    if any(unicodedata.category(c) in ("Cf", "Cc", "Zl", "Zp") for c in norm) \
            or not any(c.isalnum() for c in norm):
        raise EnrolmentError(
            f"actor {actor.identifier!r} is not a name a person could have "
            "(invisible characters or no letter or digit).")
    words = [w for w in re.findall(r"[^\W_]+", norm.casefold()) if not w.isdigit()]
    if words and all(w in _RESERVED_NAMES for w in words):
        raise EnrolmentError(
            f"actor {actor.identifier!r} is what an automated actor is called, not who it "
            f"is; {act} needs a named person.")
    return actor


def _text(value: str | None) -> str:
    return " ".join((value or "").split())


@dataclass(frozen=True)
class EnrolmentReceipt:
    """What an enrolment attempt did, and what it does not mean.

    ``status`` is ``enrolled`` | ``already_enrolled`` | ``configuration_differs`` |
    ``identity_conflict``. The last two are refusals: ``written`` is ``False`` and the
    ledger is untouched.
    """

    status: str
    written: bool
    machine_key: str
    configuration_hash: str
    declared: dict[str, str]
    #: The configuration hash the machine was enrolled with, when it was enrolled earlier.
    enrolled_configuration_hash: str = ""
    manifest_id: str = ""
    manifest_content_hash: str = ""
    manifest_entry: int = 0
    enrolment_content_hash: str = ""
    enrolment_entry: int = 0
    enrolled_by: str = ""
    items_total: int = 0
    uncomparable_items: tuple[str, ...] = ()
    #: A ceiling on what any claim from this manifest could be worth. Not a result.
    tier_ceiling: str = ""
    undemonstrable_functions: tuple[str, ...] = ()
    #: ``function_id -> coverage`` read back from the ledger after the enrolment.
    coverage: dict[str, str] = field(default_factory=dict)
    conflicts: tuple[dict[str, str], ...] = ()
    notes: tuple[str, ...] = ()
    pointer: str = ""
    #: ``declared`` is the identity in force. When a named person has amended it since
    #: enrolment, these say so: what was declared at enrolment, and each amendment (who,
    #: when, why, from -> to), oldest first.
    original_declared: dict[str, str] = field(default_factory=dict)
    amendments: tuple[dict[str, Any], ...] = ()

    @property
    def refused(self) -> bool:
        return self.status in (CONFIGURATION_DIFFERS, IDENTITY_CONFLICT)

    @property
    def enrolled(self) -> bool:
        return self.status in (ENROLLED, ALREADY_ENROLLED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": ENROLMENT_SCHEMA,
            "status": self.status,
            "written": self.written,
            "machine": self.machine_key,
            "configuration_hash": self.configuration_hash,
            "enrolled_configuration_hash": self.enrolled_configuration_hash,
            "declared": dict(self.declared),
            "identity_amended": bool(self.amendments),
            "original_declared": dict(self.original_declared),
            "amendments": [dict(a) for a in self.amendments],
            "identity_basis": IDENTITY_BASIS,
            "manifest_id": self.manifest_id,
            "manifest_content_hash": self.manifest_content_hash,
            "manifest_entry": self.manifest_entry,
            "enrolment_content_hash": self.enrolment_content_hash,
            "enrolment_entry": self.enrolment_entry,
            "enrolled_by": self.enrolled_by,
            "items": self.items_total,
            "uncomparable_items": list(self.uncomparable_items),
            "uncomparable_note": (
                "these items carry no hash: a change to them would not be detectable"
                if self.uncomparable_items else ""),
            "tier_ceiling": self.tier_ceiling,
            "tier_ceiling_note": (
                "a ceiling on what any claim from this manifest could be worth, not a result"
                if self.tier_ceiling else ""),
            "undemonstrable_functions": list(self.undemonstrable_functions),
            "coverage": dict(self.coverage),
            "conflicts": [dict(c) for c in self.conflicts],
            "notes": list(self.notes),
            "pointer": self.pointer,
            "does_not_establish": list(NOT_ESTABLISHED),
            "next_steps": list(NEXT_STEPS) if self.enrolled else [],
        }

    def summary(self) -> str:
        head = {
            ENROLLED: f"enrolled {self.machine_key}",
            ALREADY_ENROLLED: f"already enrolled {self.machine_key}; nothing written",
            CONFIGURATION_DIFFERS: (
                f"REFUSED: {self.machine_key} is already enrolled and its configuration "
                "differs; nothing written"),
            IDENTITY_CONFLICT: (
                f"REFUSED: {self.machine_key} is already enrolled with different declared "
                "attributes; nothing written"),
        }[self.status]
        lines = [head]
        lines.append(f"  configuration {self.configuration_hash[:16]}")
        if self.enrolled_configuration_hash:
            lines.append(f"  enrolled with {self.enrolled_configuration_hash[:16]}")
        if self.manifest_content_hash:
            lines.append(f"  manifest      {self.manifest_content_hash[:16]} "
                         f"(entry {self.manifest_entry})")
        if self.enrolment_content_hash:
            lines.append(f"  enrolment     {self.enrolment_content_hash[:16]} "
                         f"(entry {self.enrolment_entry}, by {self.enrolled_by})")
        shown = {k: v for k, v in self.declared.items() if v}
        if shown:
            lines.append("  declared      " + ", ".join(f"{k}={v}" for k, v in shown.items()))
        for a in self.amendments:
            for attr, ft in a["changes"].items():
                lines.append(
                    f"  amended       {attr}: {ft['from'] or '(not declared)'!r} -> "
                    f"{ft['to']!r} by {a['by']} at {a['at']} (entry {a['entry']}): "
                    f"{a['reason']}")
        if self.items_total:
            lines.append(f"  items         {self.items_total} "
                         f"({len(self.uncomparable_items)} carry no hash)")
        for item in self.uncomparable_items:
            lines.append(f"    uncomparable: {item}")
        if self.tier_ceiling:
            lines.append(f"  tier ceiling  {self.tier_ceiling} (a ceiling, not a result)")
        for fid in self.undemonstrable_functions:
            lines.append(f"  !! {fid} declares no verification check")
        for fid, cov in self.coverage.items():
            lines.append(f"  coverage      {fid}: {cov}")
        for c in self.conflicts:
            lines.append(f"  conflict      {c['attribute']}: enrolled as "
                         f"{c['enrolled'] or '(not declared)'!r}, claimed {c['claimed']!r}")
        for n in self.notes:
            lines.append(f"  note          {n}")
        if self.pointer:
            lines.append(f"  next          {self.pointer}")
        lines.append("  enrolment does NOT establish:")
        lines.extend(f"    - {n}" for n in NOT_ESTABLISHED)
        if self.enrolled:
            lines.append("  next steps:")
            lines.extend(f"    - {s}" for s in NEXT_STEPS)
        return "\n".join(lines)


# -- reading back ----------------------------------------------------------


def enrolment_of(ledger: EvidenceLedger, machine_key: str) -> tuple[Any, dict[str, Any]] | None:
    """The first valid enrolment record for a key as ``(entry, body)``, or ``None``.

    A record of this kind that cannot be read, or no longer matches its seal, is not
    skipped: enrolling "again" beside a damaged record would hide that it was damaged.
    """
    entries, damaged, _ = ledger.read_subject(machine_key, ENROLMENT_KIND)
    if damaged:
        raise EnrolmentError(
            f"an enrolment record for {machine_key!r} (entry {damaged[0].seq}) cannot be "
            f"read: {damaged[0].why}. Nothing was written.")
    for entry in entries:
        evidence = entry.evidence()
        if not evidence.verify():
            raise EnrolmentError(
                f"the enrolment record for {machine_key!r} (entry {entry.seq}) no longer "
                "matches its own seal; it was edited. Nothing was written.")
        return entry, evidence.body
    return None


def _sealed_copy(
    ledger: EvidenceLedger, manifest: SafetyManifest,
) -> tuple[int, str] | None:
    """The entry holding exactly this manifest (same id, time, taker, content), if sealed."""
    key = manifest.machine.key
    want = manifest.content_hash()
    for entry in ledger.entries(kind=MANIFEST_KIND, subject=key):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        try:
            held = SafetyManifest.from_dict(evidence.body["manifest"])
        except (AssuranceError, KeyError, ValueError, TypeError):
            continue
        if held.content_hash() == want:
            return entry.seq, entry.content_hash
    return None


def _declared(manifest: SafetyManifest, site: str | None, owner: str | None) -> dict[str, str]:
    m = manifest.machine
    given_site = _text(site)
    if given_site and m.site and _text(m.site) != given_site:
        raise EnrolmentError(
            f"site {given_site!r} disagrees with the site {m.site!r} written in the "
            "manifest. The manifest's site is part of its configuration hash; correct one "
            "of them rather than enrolling two answers.")
    return {
        "site": given_site or _text(m.site),
        "owner": _text(owner),
        "year": _text(m.year),
        "country": _text(m.country).upper(),
    }


def _conflicts(enrolled: dict[str, Any], claimed: dict[str, str]) -> list[dict[str, str]]:
    """Attributes the new claim states that the enrolment states differently.

    An attribute the claim leaves out is not stated, so it cannot contradict.
    """
    held = enrolled.get("declared", {})
    out: list[dict[str, str]] = []
    for attr in _ATTRIBUTES:
        want = claimed.get(attr, "")
        have = _text(held.get(attr, ""))
        if want and have and want != have:
            out.append({"attribute": attr, "enrolled": have, "claimed": want})
    return out


def _coverage_after(ledger: EvidenceLedger, manifest: SafetyManifest) -> dict[str, str]:
    key = manifest.machine.key
    report = assess_coverage(
        manifest,
        VerificationRecord.from_ledger(ledger, subject=key),
        interventions_from_ledger(ledger, key),
    )
    return {f.function_id: f.coverage.value for f in report.functions}


# -- the domain function ---------------------------------------------------


def enrol_machine(
    ledger: EvidenceLedger,
    manifest: SafetyManifest,
    *,
    actor: Actor | None,
    site: str | None = None,
    owner: str | None = None,
) -> EnrolmentReceipt:
    """Enrol one machine into ``ledger`` and return an honest receipt.

    Raises :class:`EnrolmentError` when the actor is not a named person, when the
    ledger chain does not verify, when an existing enrolment record is damaged, or when
    ``site`` contradicts the manifest. Everything else is a receipt: refusals
    (``configuration_differs``, ``identity_conflict``) write nothing.
    """
    who = require_person(actor)
    key = manifest.machine.key
    declared = _declared(manifest, site, owner)
    config = manifest.configuration_hash()

    ok, problems = ledger.verify_chain()
    if not ok:
        raise EnrolmentError(
            "the ledger chain does not verify, so nothing was enrolled: "
            + "; ".join(problems[:3]))

    for _ in range(2):
        existing = enrolment_of(ledger, key)
        if existing is not None:
            return _against_existing(ledger, manifest, declared, config, *existing)
        try:
            return _first_enrolment(ledger, manifest, declared, config, who)
        except LedgerConflictError:
            continue   # somebody enrolled it between the read and the write: read again
    raise EnrolmentError(f"{key!r} is being enrolled concurrently; nothing was written. "
                         "Try again.")


def _shape(manifest: SafetyManifest) -> dict[str, Any]:
    return {
        "items_total": len(manifest.items),
        "uncomparable_items": tuple(i.item_id for i in manifest.uncomparable_items),
        "tier_ceiling": manifest.tier_ceiling.value,
        "undemonstrable_functions": tuple(f.function_id
                                          for f in manifest.undemonstrable_functions),
    }


def _against_existing(
    ledger: EvidenceLedger, manifest: SafetyManifest, declared: dict[str, str],
    config: str, entry: Any, body: dict[str, Any],
) -> EnrolmentReceipt:
    from assurance.machinery.amend import effective_identity  # amend builds on this module

    key = manifest.machine.key
    enrolled_config = str(body.get("configuration_hash", ""))
    # The identity in force is the enrolment plus its amendments, in order; the claim is
    # compared with that, not with the first declaration alone.
    ident = effective_identity(ledger, key, (entry, body))
    in_force = dict(ident.effective) if ident else dict(body.get("declared", declared))
    amended: dict[str, Any] = {}
    if ident is not None and ident.amended:
        amended = {"original_declared": dict(ident.original),
                   "amendments": tuple(a.to_dict() for a in ident.amendments)}
    common: dict[str, Any] = {
        "machine_key": key,
        "configuration_hash": config,
        "enrolled_configuration_hash": enrolled_config,
        "declared": in_force,
        **amended,
        "manifest_id": manifest.manifest_id,
        "manifest_content_hash": str(body.get("manifest_content_hash", "")),
        "manifest_entry": int(body.get("manifest_entry", 0)),
        "enrolment_content_hash": entry.content_hash,
        "enrolment_entry": entry.seq,
        "enrolled_by": entry.actor,
        "written": False,
        **_shape(manifest),
    }
    conflicts = _conflicts({"declared": in_force}, declared)
    if conflicts:
        return EnrolmentReceipt(
            status=IDENTITY_CONFLICT, conflicts=tuple(conflicts),
            pointer=("a person must decide which declaration stands; nothing was merged. "
                     "Correct the claim, or ask whoever enrolled it to correct theirs."),
            **common)
    if config != enrolled_config:
        return EnrolmentReceipt(
            status=CONFIGURATION_DIFFERS,
            pointer=("already enrolled, configuration differs. A changed configuration is "
                     "drift, not an enrolment: grade it with `machinery diff --baseline "
                     "<enrolled manifest> --observed <this manifest>` or `change assess "
                     "drift` (POST /v1/machinery/diff, POST /v1/change/assess/drift)."),
            **common)
    notes = [f"amendment record problem, not applied: {p}"
             for p in (ident.problems if ident else ())]
    held = in_force
    for attr in _ATTRIBUTES:
        if declared.get(attr) and not _text(held.get(attr, "")):
            notes.append(f"{attr} {declared[attr]!r} was not declared at enrolment and was "
                         "not added by enrolling again; a named person adds it with "
                         "`machinery amend-enrolment`")
    return EnrolmentReceipt(
        status=ALREADY_ENROLLED, notes=tuple(notes),
        coverage=_coverage_after(ledger, manifest), **common)


def _first_enrolment(
    ledger: EvidenceLedger, manifest: SafetyManifest, declared: dict[str, str],
    config: str, who: Actor,
) -> EnrolmentReceipt:
    key = manifest.machine.key
    notes: list[str] = []
    prior = ledger.entries(kind=MANIFEST_KIND, subject=key)
    held = _sealed_copy(ledger, manifest)
    if held is not None:
        manifest_entry, manifest_hash = held
        notes.append("this exact manifest was already sealed in this ledger; it was "
                     "referenced, not sealed twice")
    else:
        if prior:
            notes.append(
                f"{len(prior)} manifest(s) were already sealed for this key before it was "
                "enrolled; enrolment takes this one as its baseline and does not reconcile "
                "them. Compare with `machinery diff` if they differ.")
        sealed = record_manifest(ledger, manifest, actor=who)
        manifest_hash = sealed.content_hash
        found = ledger.get(manifest_hash)
        manifest_entry = found.seq if found else 0

    shape = _shape(manifest)
    body = {
        "schema": ENROLMENT_SCHEMA,
        "machine": key,
        "identity": manifest.machine.to_dict(),
        "declared": declared,
        "identity_basis": IDENTITY_BASIS,
        "configuration_hash": config,
        "manifest_id": manifest.manifest_id,
        "manifest_content_hash": manifest_hash,
        "manifest_entry": manifest_entry,
        "tier_ceiling": shape["tier_ceiling"],
        "uncomparable_items": list(shape["uncomparable_items"]),
        "undemonstrable_functions": list(shape["undemonstrable_functions"]),
        "functions": [f.function_id for f in manifest.functions],
        "does_not_establish": list(NOT_ESTABLISHED),
    }
    head = ledger.entries(kind=ENROLMENT_KIND, subject=key)
    evidence = Evidence(
        kind=ENROLMENT_KIND,
        body=body,
        actor=who,
        origin=Origin(
            system="assurance.machinery",
            reference=f"{key} / {manifest.manifest_id}",
            method="enrolment declared by a named person; identity as declared",
        ),
        # An enrolment is a declaration, not a verification of anything.
        validation_state=ValidationState.UNVERIFIED,
        confidence=Confidence.LOW,
        checks_skipped=NOT_ESTABLISHED,
    ).seal()
    appended = ledger.append(
        evidence, subject=key,
        expect_subject_head=head[-1].seq if head else 0,
        expect_kinds=(ENROLMENT_KIND,),
    )
    return EnrolmentReceipt(
        status=ENROLLED, written=True, machine_key=key, configuration_hash=config,
        enrolled_configuration_hash=config, declared=declared,
        manifest_id=manifest.manifest_id, manifest_content_hash=manifest_hash,
        manifest_entry=manifest_entry, enrolment_content_hash=evidence.content_hash,
        enrolment_entry=appended.seq, enrolled_by=who.identifier,
        coverage=_coverage_after(ledger, manifest), notes=tuple(notes), **shape,
    )
