"""Sealing manifests and interventions into the ledger, and the machine passport.

A manifest in a file is a document. A manifest in the hash-chained ledger is a
dated, attributed, tamper-evident record of what was on the machine on the day
somebody looked — and the chain, not our word, is what makes a later
"the baseline always said that" checkable.

The passport is the deliverable a customer actually receives: the machine's
identity, its current configuration, its change history, and the coverage
position for every declared safety function, sealed as one object that anybody
can re-check against the ledger it came from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import (
    Actor,
    Confidence,
    Evidence,
    EvidenceRef,
    Origin,
    ValidationState,
)
from assurance.core.identity import content_hash_of, format_utc, parse_utc, utc_now
from assurance.evidence.ledger import EvidenceLedger
from assurance.machine.recorder_attestation import RecorderTrust
from assurance.machine.trace import MAX_FILE_BYTES
from assurance.machinery.divergence import ChangeKind, Divergence, Severity, compare
from assurance.machinery.intervention import (
    IMPLIED_PREFIX,
    UNREADABLE_PREFIX,
    ImpliedIntervention,
    Intervention,
    InterventionKind,
    UnreadableIntervention,
)
from assurance.machinery.manifest import ManifestSource, SafetyManifest, normalised_digest
from assurance.machinery.staleness import (
    CoverageReport,
    VerificationRecord,
    assess_coverage,
    tier_reaches_validated,
)

__all__ = [
    "DIVERGENCE_KIND",
    "INTERVENTION_KIND",
    "MANIFEST_KIND",
    "PASSPORT_KIND",
    "PASSPORT_SCHEMA",
    "MachinePassport",
    "PassportError",
    "build_passport",
    "InterventionRefusedError",
    "UnknownFunctionError",
    "UnknownMachineError",
    "check_intervention",
    "implied_interventions",
    "interventions_from_ledger",
    "manifests_from_ledger",
    "record_divergence",
    "record_intervention",
    "record_manifest",
    "verify_passport",
]

MANIFEST_KIND = "machinery.safety_manifest"
INTERVENTION_KIND = "machinery.intervention"
DIVERGENCE_KIND = "machinery.divergence"
PASSPORT_KIND = "machinery.passport"
PASSPORT_SCHEMA = "assurance.machinery.passport/1"


class PassportError(AssuranceError):
    """A passport is malformed, or does not match the ledger it names."""


# -- sealing ---------------------------------------------------------------


def record_manifest(
    ledger: EvidenceLedger, manifest: SafetyManifest, *, actor: Actor | None = None,
) -> Evidence:
    """Seal a manifest into the ledger under the machine's key.

    The actor defaults to whoever the manifest says took it, because a manifest
    that arrives with no taker is refused at seal time rather than filed to a
    placeholder.
    """
    who = actor or manifest.taken_by
    evidence = Evidence(
        kind=MANIFEST_KIND,
        body={
            "manifest": manifest.to_dict(),
            "configuration_hash": manifest.configuration_hash(),
            "tier_ceiling": manifest.tier_ceiling.value,
        },
        actor=who,
        origin=Origin(
            system="assurance.machinery",
            reference=f"{manifest.machine.key} / {manifest.manifest_id}",
            method=manifest.method or f"manifest recorded as {manifest.source.value}",
        ),
        validation_state=ValidationState.UNVERIFIED,
        confidence=(
            Confidence.HIGH if manifest.tier_ceiling.may_claim_physical_behaviour
            else Confidence.LOW
        ),
        checks_skipped=tuple(
            [f"{i.item_id} carries no hash ({i.hash_source.value}); a change to it "
             "would not be detectable." for i in manifest.uncomparable_items]
            + [f"{i.item_id} is safety-bearing and modifiable on site."
               for i in manifest.field_modifiable_safety_items]
            + ["this records what was collected. It does not establish that the "
               "collection was complete: an item nobody listed is absent from every "
               "comparison made from this manifest."]
        ),
    ).seal()
    ledger.append(evidence, subject=manifest.machine.key)
    return evidence


def record_intervention(
    ledger: EvidenceLedger, intervention: Intervention, *, actor: Actor | None = None,
) -> Evidence:
    """Seal an intervention record. Findings are carried, not suppressed.

    An intervention with no authorisation and no revalidation is still recorded —
    and its own ``findings`` become the evidence object's ``checks_skipped``, so
    the gap travels with the record instead of being lost between systems.
    """
    findings = intervention.findings
    evidence = Evidence(
        kind=INTERVENTION_KIND,
        body={"intervention": intervention.to_dict(),
              "findings": list(findings)},
        actor=actor or intervention.performed_by,
        origin=Origin(
            system="assurance.machinery",
            reference=f"{intervention.machine_key} / {intervention.intervention_id}",
            method=f"{intervention.kind.value} recorded against {intervention.item_id}",
        ),
        validation_state=(
            ValidationState.VERIFIED if intervention.is_revalidated
            else ValidationState.INDETERMINATE
        ),
        confidence=Confidence.HIGH if intervention.kind.is_contemporaneous
        else Confidence.LOW,
        checks_skipped=findings,
        relations=tuple(
            [EvidenceRef(relation="supersedes", content_hash=intervention.from_hash,
                         note=f"the {intervention.item_id} artefact this replaced")]
            if intervention.from_hash else []
        ) + tuple(
            [EvidenceRef(
                relation="supports",
                content_hash=intervention.revalidation.evidence_hash,
                note="the verification re-run after this change")]
            if intervention.revalidation and intervention.revalidation.is_evidenced
            else []
        ),
    ).seal()
    ledger.append(evidence, subject=intervention.machine_key)
    return evidence


def record_divergence(
    ledger: EvidenceLedger, divergence: Divergence, *, actor: Actor,
) -> Evidence:
    """Seal a divergence report."""
    evidence = Evidence(
        kind=DIVERGENCE_KIND,
        body=divergence.to_dict(),
        actor=actor,
        origin=Origin(
            system="assurance.machinery",
            reference=f"{divergence.machine_key} / {divergence.observed_id}",
            method=f"baseline {divergence.baseline_id} compared against observed "
                   f"{divergence.observed_id}",
        ),
        # "unverifiable" is neither: nothing that could be seen moved, and some of
        # it could not be seen. Sealing that as refuted would be as wrong as
        # sealing it as verified.
        validation_state={
            "matches": ValidationState.VERIFIED,
            "unverifiable": ValidationState.INDETERMINATE,
        }.get(divergence.verdict, ValidationState.REFUTED),
        confidence=Confidence.HIGH if divergence.tier.may_claim_physical_behaviour
        else Confidence.MEDIUM,
        checks_skipped=divergence.checks_skipped,
        relations=(
            EvidenceRef(relation="concerns", content_hash=divergence.baseline_hash,
                        note="the as-declared baseline manifest"),
            EvidenceRef(relation="derived_from", content_hash=divergence.observed_hash,
                        note="the as-found manifest"),
        ),
    ).seal()
    ledger.append(evidence, subject=divergence.machine_key)
    return evidence


# -- reading back ----------------------------------------------------------


def manifests_from_ledger(
    ledger: EvidenceLedger, machine_key: str,
) -> list[SafetyManifest]:
    """Every sealed manifest for a machine, oldest first, tampered ones dropped."""
    out: list[SafetyManifest] = []
    for entry in ledger.entries(kind=MANIFEST_KIND, subject=machine_key):
        evidence = entry.evidence()
        if not evidence.verify():
            continue
        out.append(SafetyManifest.from_dict(evidence.body["manifest"]))
    return out


#: What the watch writes into a manifest's notes when it could not read every item its plan
#: names (``change.service.INCOMPLETE_COLLECTION_MARK``; a test pins the two together,
#: because this module cannot import the change package). Such a look is not a
#: configuration the machine was in.
_PARTIAL_LOOK_MARK = "[collection incomplete"

_READER = Actor(identifier="assurance.ledger-reader", role="derived, not recorded",
                kind="automation")


def _unreadable(machine_key: str, *, seq: int, at: datetime, why: str) -> UnreadableIntervention:
    return UnreadableIntervention(
        intervention_id=f"{UNREADABLE_PREFIX}seq-{seq}" if seq else f"{UNREADABLE_PREFIX}ledger",
        machine_key=machine_key, item_id="(unreadable)", kind=InterventionKind.RECONSTRUCTED,
        occurred_at=at, performed_by=_READER,
        reason=f"a change record that cannot be read: {why}",
        notes="derived by the reader; nobody sealed this", ledger_seq=seq, why=why,
    )


def _read_interventions(
    ledger: EvidenceLedger, machine_key: str,
) -> list[Intervention]:
    """Every intervention filed under the key: the ones that read, and a stand-in for each
    one that does not. A record is dropped from the list only by being a different kind."""
    out: list[Intervention] = []
    try:
        entries = ledger.entries(kind=INTERVENTION_KIND, subject=machine_key)
    except ValueError as exc:     # a stored row that is not JSON: we cannot even tell which
        return [_unreadable(machine_key, seq=0, at=utc_now(),
                            why=f"the intervention rows could not be read: {exc}")]
    for entry in entries:
        try:
            filed = parse_utc(entry.at)
        except (ValueError, TypeError):
            filed = utc_now()
        try:
            evidence = entry.evidence()
            if not evidence.verify():
                raise ValueError("it no longer matches its own seal; the body was edited")
            found = Intervention.from_dict(evidence.body["intervention"])
            if found.machine_key != entry.subject:
                raise ValueError(f"it is filed under {entry.subject!r} but names "
                                 f"{found.machine_key!r}")
        except (AssuranceError, KeyError, ValueError, TypeError, AttributeError) as exc:
            out.append(_unreadable(machine_key, seq=entry.seq, at=filed, why=str(exc)[:200]))
            continue
        out.append(found)
    return out


def _sealed_manifests(
    ledger: EvidenceLedger, machine_key: str,
) -> list[tuple[datetime, int, SafetyManifest]]:
    """Readable manifests for a machine with the ledger's filing time and position,
    oldest first."""
    out: list[tuple[datetime, int, SafetyManifest]] = []
    for entry in ledger.entries(kind=MANIFEST_KIND, subject=machine_key):
        try:
            evidence = entry.evidence()
            if not evidence.verify():
                continue
            out.append((parse_utc(entry.at), entry.seq,
                        SafetyManifest.from_dict(evidence.body["manifest"])))
        except (AssuranceError, KeyError, ValueError, TypeError, AttributeError):
            continue
    return out


def _explains(
    i: Intervention, change: Any, *, was: str, found: str, after: datetime, until: datetime,
) -> bool:
    """Does recorded intervention ``i`` account for this manifest ``change``?

    Same item; dated after the earlier look and no later than the filing of the manifest
    that showed the change (a record cannot explain what had not been seen yet). A changed
    hash is explained only by a record whose ``to_hash`` is the hash now found (and whose
    ``from_hash``, when given, is the one before), so a record of some other update or of
    an older one does not cover this. An item that appeared or vanished is explained by a
    record of that kind of event; a version moving on an item with no hash, by any record
    of the item.
    """
    if i.item_id != change.item_id or not after < i.occurred_at <= until:
        return False
    if change.kind is ChangeKind.CONTENT_CHANGED:
        now_hash = normalised_digest(found)
        return bool(now_hash) and normalised_digest(i.to_hash) == now_hash and (
            not i.from_hash or normalised_digest(i.from_hash) == normalised_digest(was))
    if change.kind is ChangeKind.ADDED:
        return i.kind in (InterventionKind.INSTALL, InterventionKind.UPDATE,
                          InterventionKind.RESTORE, InterventionKind.RECONSTRUCTED)
    if change.kind is ChangeKind.REMOVED:
        return i.kind in (InterventionKind.REMOVAL, InterventionKind.RECONSTRUCTED)
    return True


def implied_interventions(
    ledger: EvidenceLedger, machine_key: str, recorded: list[Intervention],
) -> list[ImpliedIntervention]:
    """Changes the ledger's own manifests show that no intervention record explains.

    Walk the readable manifests in the order they were filed. Each ``as_found`` manifest
    is compared with the latest earlier one that was a look or a declaration (a plan,
    ``as_intended``, says nothing about the machine; a look the watch marked incomplete is
    not a configuration, so it is never the earlier side and items it did not collect are
    not read as removed). A safety-bearing item whose hash
    differs, or that appeared or vanished, is a change; so is a version moving on a
    safety-bearing item that carries no hash to compare (the only sign there is).

    A change is *explained* when an intervention for the same item, dated after the
    earlier look and no later than the filing of the manifest that showed it, accounts
    for it (see :func:`_explains`): for a changed hash its ``to_hash`` must be the hash
    now found. An explained change is the intervention's, with its own date. An
    unexplained one becomes an :class:`ImpliedIntervention` dated when the manifest that
    showed it was filed, not the manifest's own ``taken_at``.

    What counts is the smallest sound rule, not the whole truth: only items that
    implement a declared safety function; only changes visible between two manifests of
    the same unit (a first look has nothing to differ from); an item with no hash and an
    unchanged version is invisible, as everywhere (see ``Manifest.uncomparable_items``).
    The conservative direction is stale: a verification that began before the change was
    filed is read as no longer describing the machine until one is run after it.
    """
    out: list[ImpliedIntervention] = []
    prior: tuple[datetime, SafetyManifest] | None = None
    explicit = [i for i in recorded if not isinstance(i, UnreadableIntervention)]
    for filed, seq, manifest in _sealed_manifests(ledger, machine_key):
        if manifest.machine.key != machine_key:
            continue
        if manifest.source is ManifestSource.AS_INTENDED:
            continue
        partial = _PARTIAL_LOOK_MARK in manifest.notes
        if prior is not None and manifest.source is ManifestSource.AS_FOUND:
            prior_filed, before = prior
            divergence = compare(before, manifest)
            for change in divergence.changes:
                if partial and change.kind is ChangeKind.REMOVED:
                    continue    # not collected is not gone
                moved = change.severity is Severity.SAFETY_RELEVANT or (
                    change.kind is ChangeKind.VERSION_RELABELLED
                    and change.severity is Severity.NOTABLE and bool(change.functions))
                if not moved:
                    continue
                found = (change.after or {}).get("content_hash", "")
                was = (change.before or {}).get("content_hash", "")
                if any(_explains(i, change, was=was, found=found,
                                 after=before.taken_at, until=filed) for i in explicit):
                    continue
                out.append(ImpliedIntervention(
                    intervention_id=f"{IMPLIED_PREFIX}{manifest.content_hash()[:12]}:"
                                    f"{change.item_id}",
                    machine_key=machine_key, item_id=change.item_id,
                    kind=InterventionKind.RECONSTRUCTED, occurred_at=filed,
                    performed_by=_READER,
                    reason=f"the ledger's manifests show {change.item_id} changed "
                           f"({change.kind.value}) and no intervention record explains it",
                    from_hash=was, ledger_seq=seq,
                    to_hash=found, affects_functions=tuple(change.functions),
                    notes="derived by comparing sealed manifests; nobody recorded this "
                          f"change. {change.detail}",
                ))
        if not partial:
            prior = (filed, manifest)
    return out


def interventions_from_ledger(
    ledger: EvidenceLedger, machine_key: str, *, include_implied: bool = True,
) -> list[Intervention]:
    """Every change to a machine the ledger can account for, in the order they occurred.

    The sealed interventions, plus two kinds of record nobody wrote and every consumer
    must treat as changes:

    * an :class:`UnreadableIntervention` for each record filed as an intervention that
      cannot be used (its seal fails, it is not an intervention, or its row is not JSON).
      The one input whose absence only ever makes evidence look *fresher* is never
      silently dropped; and
    * with ``include_implied`` (the default), an :class:`ImpliedIntervention` for each
      safety-bearing change the ledger's own manifests show with no record explaining it
      (see :func:`implied_interventions`).

    ``include_implied=False`` is for a caller that wants only what was recorded.
    """
    recorded = _read_interventions(ledger, machine_key)
    if include_implied:
        recorded = [*recorded, *implied_interventions(ledger, machine_key, recorded)]
    return sorted(recorded, key=lambda i: i.occurred_at)


class InterventionRefusedError(AssuranceError):
    """An intervention that cannot be filed against what the ledger holds."""

    #: Machine-readable reason: ``unknown_machine`` | ``unknown_function``.
    code = "refused"
    unknown: tuple[str, ...] = ()


class UnknownMachineError(InterventionRefusedError):
    code = "unknown_machine"


class UnknownFunctionError(InterventionRefusedError):
    code = "unknown_function"


def check_intervention(
    ledger: EvidenceLedger, intervention: Intervention,
) -> tuple[Intervention, SafetyManifest]:
    """Read an intervention against the manifest sealed for the unit it names.

    Returns the intervention with its function ids written as the manifest spells them,
    and that manifest. Raises :class:`UnknownMachineError` when no manifest is sealed
    under exactly this unit key (a different case, a serial with a digit missing, another
    unit of the same model, a product line: each is a different unit, and a change filed
    under it would be about nothing the coverage assessment reads), and
    :class:`UnknownFunctionError` when it names a safety function the manifest does not
    declare. Nothing is written by this function.
    """
    sealed = _sealed_manifests(ledger, intervention.machine_key)
    if not sealed:
        raise UnknownMachineError(
            f"no manifest is sealed in this ledger under the unit key "
            f"{intervention.machine_key!r}. A unit key is maker/model#serial, exactly as "
            "sealed (a different case or serial is a different unit). Seal the unit's "
            "manifest first, or correct the key.")
    manifest = sealed[-1][2]
    resolved, unknown = manifest.resolve_function_ids(intervention.affects_functions)
    if unknown:
        declared = ", ".join(f.function_id for f in manifest.functions) or "none declared"
        exc = UnknownFunctionError(
            f"{', '.join(unknown)} matches no safety function declared by the manifest "
            f"sealed for {intervention.machine_key!r} ({declared}). "
            "A change filed against a function nobody declared disturbs nothing.")
        exc.unknown = unknown
        raise exc
    return replace(intervention, affects_functions=resolved), manifest


# -- the passport ----------------------------------------------------------


@dataclass(frozen=True)
class MachinePassport:
    """What the customer receives: identity, configuration, history, coverage."""

    evidence: Evidence
    manifest: SafetyManifest
    coverage: CoverageReport
    interventions: tuple[Intervention, ...]

    @property
    def content_hash(self) -> str:
        return self.evidence.content_hash

    @property
    def verdict(self) -> str:
        return self.coverage.verdict

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": PASSPORT_SCHEMA,
            "evidence": self.evidence.to_dict(),
            "manifest": self.manifest.to_dict(),
            "coverage": self.coverage.to_dict(),
            "interventions": [i.to_dict() for i in self.interventions],
        }

    def write(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_text(json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
                     encoding="utf-8")
        return p

    def summary(self) -> str:
        return (f"{self.coverage.summary()}\n"
                f"  {len(self.interventions)} recorded intervention(s)\n"
                f"  sealed as {self.content_hash[:16]}")


def build_passport(
    ledger: EvidenceLedger,
    manifest: SafetyManifest,
    *,
    actor: Actor,
    interventions: list[Intervention] | None = None,
    verifications: list[VerificationRecord] | None = None,
    seal: bool = True,
    recorder_trust: RecorderTrust | None = None,
) -> MachinePassport:
    """Assemble and seal the machine's current evidence position.

    Interventions and verifications are read out of the ledger when not supplied,
    which is the normal path: the passport is a view over what has been recorded,
    not a document somebody assembles by hand.

    ``recorder_trust`` is the reader's own recorder trust list, applied to the
    verifications read from the ledger: a ``validated`` tier whose recorder key the
    reader has revoked or removed is read as ``community``, and the passport's state and
    confidence follow that tier floor. A hosted reader always passes one.
    """
    key = manifest.machine.key
    ivs = (interventions if interventions is not None
           else interventions_from_ledger(ledger, key))
    vfs = (verifications if verifications is not None
           else VerificationRecord.from_ledger(ledger, subject=key,
                                               recorder_trust=recorder_trust))

    coverage = assess_coverage(manifest, vfs, ivs)
    chain_ok, chain_problems = ledger.verify_chain()

    skipped = list(coverage.checks_skipped)
    if not chain_ok:
        skipped.insert(0, "THE LEDGER CHAIN DOES NOT VERIFY: "
                          + "; ".join(chain_problems[:3])
                          + ". Every statement below is drawn from a store whose "
                            "integrity is in question.")
    floor = coverage.evidence_tier_floor
    covered = coverage.verdict == "covered"
    # A cover that rests on evidence under 'validated' is about a recorded file, not a
    # demonstration on the machine, so the passport does not read VERIFIED / HIGH on it
    # (see the engine's cap on declared provenance). It is capped at the tier floor.
    capped = covered and not tier_reaches_validated(floor)
    if capped:
        skipped.append(
            f"every function reads current, but only on evidence at tier {floor!r}, below "
            "'validated'. A trace's declared provenance is capped at 'community'; "
            "'validated' needs a recorder attestation accepted under a recorder trust "
            "list the verifier holds, so this passport is INDETERMINATE "
            "with low confidence, not verified: the behaviour was not demonstrated on "
            "the machine.")
    if not vfs:
        skipped.append(
            f"no machine verification in this ledger is filed under {key!r}. A "
            "verification sealed under a product line rather than this unit will not "
            "be found here — seal it with subject=<machine key> to link the two.")

    evidence = Evidence(
        kind=PASSPORT_KIND,
        body={
            "schema": PASSPORT_SCHEMA,
            "machine": manifest.machine.to_dict(),
            "manifest_id": manifest.manifest_id,
            "manifest_hash": manifest.content_hash(),
            "configuration_hash": manifest.configuration_hash(),
            "verdict": coverage.verdict,
            "evidence_tier_floor": floor,
            "functions": [f.to_dict() for f in coverage.functions],
            "intervention_ids": [i.intervention_id for i in ivs],
            "verification_hashes": [v.content_hash for v in vfs],
            "ledger_chain_verified": chain_ok,
            "ledger_head": ledger.head_attestation() if chain_ok else {},
            "assessed_at": format_utc(utc_now()),
        },
        actor=actor,
        origin=Origin(
            system="assurance.machinery",
            reference=key,
            method="coverage assessed by joining verification bundles to "
                   "intervention records through declared safety functions",
        ),
        validation_state=(
            ValidationState.VERIFIED if covered and not capped
            else ValidationState.INDETERMINATE
        ),
        confidence=Confidence.HIGH if (chain_ok and covered and not capped)
        else Confidence.LOW,
        checks_skipped=tuple(dict.fromkeys(skipped)),
        relations=(
            EvidenceRef(relation="concerns", content_hash=manifest.content_hash(),
                        note="the manifest this position is assessed against"),
        ) + tuple(
            EvidenceRef(relation="derived_from", content_hash=v.content_hash,
                        note=f"verification {v.product_version}")
            for v in vfs
        ),
    ).seal()

    if seal:
        ledger.append(evidence, subject=key)

    return MachinePassport(
        evidence=evidence, manifest=manifest, coverage=coverage,
        interventions=tuple(ivs),
    )


_COVERAGE_STATES = ("current", "stale", "failing", "never_verified", "not_demonstrable")


def _passport_coherence(
    evidence: Evidence, raw: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Whether the passport hangs together without the ledger, and whether the
    blocks printed beside the seal are the ones the seal covers.

    As with a verification bundle, the seal is a content hash and covers the
    evidence object only; the manifest, coverage and intervention list printed in
    the same file are what a reader looks at, and each must repeat the sealed body.
    Returns ``(problems, limitations)``.
    """
    problems: list[str] = []
    limits: list[str] = []
    body = evidence.body

    if evidence.kind != PASSPORT_KIND:
        problems.append(f"the sealed evidence is of kind {evidence.kind!r}, not "
                        f"{PASSPORT_KIND!r}; this is not a machine passport.")

    functions = body.get("functions")
    if not isinstance(functions, list) or not all(isinstance(f, dict) for f in functions):
        problems.append("the sealed function list is not a list of objects.")
        functions = []
    uncovered = 0
    for f in functions:
        state = f.get("coverage")
        if state not in _COVERAGE_STATES:
            problems.append(f"function {f.get('function_id')!r} has coverage {state!r}, "
                            f"which is not one of {', '.join(_COVERAGE_STATES)}.")
            uncovered += 1
            continue
        if state != "current":
            uncovered += 1
        elif not f.get("last_verified_hash"):
            problems.append(f"function {f.get('function_id')!r} is recorded as current "
                            "but names no verification that made it so.")
        if state == "stale" and not f.get("invalidated_by"):
            problems.append(f"function {f.get('function_id')!r} is recorded as stale "
                            "but names no intervention that made it so.")
    implied = ("no_functions_declared" if not functions
               else "covered" if not uncovered else "gaps")
    if body.get("verdict") != implied:
        problems.append(
            f"the passport records verdict {body.get('verdict')!r} but its own "
            f"function list implies {implied!r} ({uncovered} not current).")

    floor = body.get("evidence_tier_floor")
    if floor is None:
        if body.get("verdict") == "covered":
            limits.append(
                "NOT CHECKED: the passport records no evidence tier floor (it predates "
                "the cap on declared provenance), so whether its 'verified' state rests "
                "on evidence below 'validated' cannot be told from the file.")
        capped = False
    elif not isinstance(floor, str):
        problems.append("the sealed evidence tier floor is not a string.")
        capped = True
    else:
        capped = body.get("verdict") == "covered" and not tier_reaches_validated(floor)
    want_state = ("verified" if body.get("verdict") == "covered" and not capped
                  else "indeterminate")
    if evidence.validation_state.value != want_state:
        problems.append(
            f"the sealed validation state is {evidence.validation_state.value!r} but "
            f"the verdict {body.get('verdict')!r} requires {want_state!r}.")
    if evidence.confidence.value in ("high", "established") and not (
            body.get("verdict") == "covered" and body.get("ledger_chain_verified") is True
            and not capped):
        problems.append(
            f"the sealed confidence is {evidence.confidence.value!r}, which a passport "
            "earns only when it is covered, the ledger chain verified and the evidence "
            "it rests on reaches 'validated'.")

    # -- the half of the file the seal does not cover -------------------------
    printed_cov = raw.get("coverage")
    if printed_cov is None:
        limits.append("NOT CHECKED: the file carries no coverage block beside the seal.")
    elif not isinstance(printed_cov, dict):
        problems.append("the printed coverage block is not an object.")
    else:
        if printed_cov.get("verdict") != body.get("verdict"):
            problems.append(
                f"the printed coverage says {printed_cov.get('verdict')!r}; the sealed "
                f"evidence says {body.get('verdict')!r}. The coverage block was edited.")
        if content_hash_of(printed_cov.get("functions")) != content_hash_of(functions):
            problems.append("the printed coverage's functions differ from the sealed "
                            "evidence's. The coverage block was edited.")

    printed_man = raw.get("manifest")
    if printed_man is None:
        limits.append("NOT CHECKED: the file carries no manifest beside the seal.")
    else:
        try:
            m = SafetyManifest.from_dict(printed_man)
        except (AssuranceError, KeyError, TypeError, ValueError, AttributeError) as exc:
            problems.append(f"the printed manifest cannot be read: {exc}")
        else:
            if m.content_hash() != body.get("manifest_hash") \
                    or m.configuration_hash() != body.get("configuration_hash"):
                problems.append(
                    "the printed manifest is not the one the sealed evidence names "
                    f"(printed {m.content_hash()[:12]}, sealed "
                    f"{str(body.get('manifest_hash'))[:12]}). It was edited.")

    printed_ivs = raw.get("interventions")
    if printed_ivs is None:
        limits.append("NOT CHECKED: the file carries no intervention list beside the "
                      "seal.")
    elif not isinstance(printed_ivs, list) or not all(
            isinstance(i, dict) for i in printed_ivs):
        problems.append("the printed intervention list is not a list of objects.")
    else:
        printed_ids = [i.get("intervention_id") for i in printed_ivs]
        if printed_ids != list(body.get("intervention_ids") or []):
            problems.append(
                "the printed intervention list is not the one the sealed evidence "
                f"names (printed {printed_ids}, sealed "
                f"{list(body.get('intervention_ids') or [])}). An intervention was "
                "added or removed.")
    return problems, limits


def verify_passport(
    passport_path: str | Path, *, ledger: EvidenceLedger | None = None,
) -> tuple[bool, list[str]]:
    """Re-check a passport without trusting whoever produced it.

    Returns ``(ok, problems)``. As with a verification bundle, the seal proves the
    file was not edited and a seal anyone can recompute proves nothing about
    whether the claim hangs together, so the sealed claim is checked for coherence
    and the manifest, coverage and intervention list printed beside it are checked
    against the sealed body. Supplying nothing to check against yields ``ok``
    *with* a stated limitation rather than a clean pass. A file that cannot be
    read is a problem, not an exception.
    """
    problems: list[str] = []
    limitations: list[str] = []
    path = Path(passport_path)
    if path.stat().st_size > MAX_FILE_BYTES:
        return False, [f"{path.name} is larger than the {MAX_FILE_BYTES} bytes this "
                       "checker will read."]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        return False, [f"the file is not readable JSON: {exc}"]
    if not isinstance(raw, dict):
        return False, [f"the file holds a JSON {type(raw).__name__}, not a passport."]

    if raw.get("schema") != PASSPORT_SCHEMA:
        return False, [f"schema is {raw.get('schema')!r}, expected {PASSPORT_SCHEMA!r}."]

    try:
        evidence = Evidence.from_dict(raw["evidence"])
    except Exception as exc:  # noqa: BLE001 - a verifier reports, it does not raise
        return False, [f"the sealed evidence could not be read: {exc!r}"]
    if not isinstance(evidence.body, dict):
        return False, ["the sealed evidence body is not an object."]

    if not evidence.verify():
        problems.append(
            f"the evidence does not hash to the value it carries "
            f"({evidence.content_hash[:16]}). The passport was edited after sealing.")

    body = evidence.body
    coherence, coherence_limits = _passport_coherence(evidence, raw)
    problems.extend(coherence)
    limitations.extend(coherence_limits)

    if body.get("ledger_chain_verified") is False:
        problems.append(
            "the passport itself records that the ledger chain did not verify when it "
            "was produced.")

    if ledger is not None:
        entry = ledger.get(evidence.content_hash)
        if entry is None:
            problems.append(
                "this passport is not in the ledger supplied. Either it came from a "
                "different ledger, or it was never sealed into one.")
        ok, chain_problems = ledger.verify_chain()
        if not ok:
            problems.append("the supplied ledger's chain does not verify: "
                            + "; ".join(chain_problems[:3]))
        for h in body.get("verification_hashes") or []:
            if ledger.get(h) is None:
                problems.append(
                    f"verification {str(h)[:12]} is named by this passport and is not "
                    "in the supplied ledger.")
    else:
        limitations.insert(0, (
            "NOT CHECKED: no ledger was supplied, so only the passport's internal "
            "integrity was confirmed. Nothing here shows the records it names exist."))

    return not problems, problems + limitations
