"""From a supplier advisory to a CRA Article 14 intake, in one command.

This is the join between the two halves of the company, and it exists because
of one field.

A manufacturer who becomes aware of an actively exploited vulnerability in
their product has **24 hours** to file an early warning. Article 14(2)(a)
requires that warning to indicate the Member States in whose territory the
manufacturer is aware the product has been made available. Everything else on
the form can be written under pressure. That list cannot: it is an inventory
question, the answer lives in four spreadsheets and somebody's memory, and the
clock does not stop while it is assembled.

The fleet already knows. Every enrolled machine carries a serial, a model, and
— since this module needed it — the territory it was made available in. When
:mod:`assurance.fleet` matches an advisory to eleven machines, the product
versions and the Member States are a query, not a scramble.

**What this refuses to do is the judgement.** It does not set a track, because
a watchdog defect is not an actively exploited vulnerability and only a person
can say which this is. It does not set an awareness timestamp, because
awareness is a determination made after an assessment, not the moment an email
arrived. It produces an *intake*: the signal, the products, the territories,
and an explicit list of everything a human still has to decide. The Article 14
register then enforces the rest in the order the Regulation requires.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from assurance.core.errors import AssuranceError
from assurance.core.evidence import Actor, Evidence
from assurance.fleet.advisory import ComponentAdvisory, MatchBasis
from assurance.fleet.impact import ImpactReport
from assurance.fleet.registry import Fleet
from assurance.security.art14.engine import Art14Register
from assurance.security.art14.model import ProductVersion, Signal, SignalChannel
from assurance.security.art14.srp import EU_MEMBER_STATES

__all__ = ["BridgeError", "CaseDraft", "draft_from_advisory", "open_case"]


class BridgeError(AssuranceError):
    """The bridge cannot produce an intake from what it was given."""


@dataclass(frozen=True)
class CaseDraft:
    """A pre-filled Article 14 intake. Not a filing, and not a decision."""

    case_id: str
    signal: Signal
    products: tuple[ProductVersion, ...]
    #: Every EU Member State the affected machines were made available in.
    member_states: tuple[str, ...]
    #: Non-EU territories. They matter for Article 14(8) duties to users; they
    #: are not what field 5 asks for, and mixing them in would put a wrong
    #: answer on a regulatory form.
    other_markets: tuple[str, ...]
    #: Serials the list was built from. This is the evidence for field 5.
    machines: tuple[str, ...]
    #: Machines that matched and had no country recorded, so contributed nothing.
    machines_without_country: tuple[str, ...]
    #: Matches that are neither confirmed affected nor confirmed clear.
    machines_needing_a_human: tuple[str, ...]
    #: What a person must still decide before anything can be filed.
    decisions_required: tuple[str, ...]
    checks_skipped: tuple[str, ...]
    advisory_id: str = ""
    advisory_hash: str = ""

    @property
    def can_complete_field_5(self) -> bool:
        """Whether the Member State list is complete for every affected machine."""
        return bool(self.member_states) and not self.machines_without_country

    def srp_prefill(self) -> dict[str, Any]:
        """The platform fields this can honestly fill, and only those.

        Deliberately partial. ``notification_type`` is absent because the track
        is a decision; ``awareness_datetime`` is absent because awareness is a
        determination. A prefill that guessed either would put a manufacturer's
        name on a statement nobody made.
        """
        first = self.products[0] if self.products else None
        return {
            "title": self.signal.description[:200],
            "summary": self.signal.description,
            "member_states_available": list(self.member_states),
            "product_name": first.product_name if first else "",
            "product_version": first.version_range if first else "",
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "advisory_id": self.advisory_id,
            "advisory_hash": self.advisory_hash,
            "signal": self.signal.to_dict(),
            "products": [p.to_dict() for p in self.products],
            "member_states": list(self.member_states),
            "other_markets": list(self.other_markets),
            "machines": list(self.machines),
            "machines_without_country": list(self.machines_without_country),
            "machines_needing_a_human": list(self.machines_needing_a_human),
            "can_complete_field_5": self.can_complete_field_5,
            "decisions_required": list(self.decisions_required),
            "srp_prefill": self.srp_prefill(),
            "checks_skipped": list(self.checks_skipped),
        }

    def summary(self) -> str:
        lines = [
            f"{self.case_id} — intake drafted from {self.advisory_id}",
            f"  {len(self.machines)} affected machine(s) in "
            f"{len(self.member_states)} Member State(s): "
            + (", ".join(self.member_states) or "—"),
        ]
        if self.other_markets:
            lines.append(f"  outside the EU: {', '.join(self.other_markets)} "
                         "(Article 14(8) may apply; field 5 does not)")
        for p in self.products:
            lines.append(f"  product  {p.product_name} {p.version_range}  "
                         f"({p.units_in_field} unit(s))")
        if self.machines_without_country:
            lines.append(f"  !! {len(self.machines_without_country)} affected "
                         "machine(s) have no country recorded: field 5 CANNOT be "
                         "completed from the fleet alone.")
        if self.machines_needing_a_human:
            lines.append(f"  !! {len(self.machines_needing_a_human)} machine(s) are "
                         "neither confirmed affected nor confirmed clear.")
        lines.append("")
        lines.append("  still to be decided by a person:")
        for d in self.decisions_required:
            lines.append(f"    - {d}")
        return "\n".join(lines)


def draft_from_advisory(
    advisory: ComponentAdvisory,
    impact: ImpactReport,
    fleet: Fleet,
    *,
    case_id: str = "",
    received_by: str,
    product_name: str = "",
) -> CaseDraft:
    """Assemble the intake an advisory implies, and nothing more.

    ``received_by`` is required: a signal nobody received is not a signal, and
    the interval from receipt to awareness is the number a market surveillance
    authority asks about.
    """
    if not received_by:
        raise BridgeError(
            "received_by is required. The interval between a signal arriving and "
            "awareness being established is evidence, and it cannot be "
            "reconstructed from an unattributed record."
        )

    affected: list[Any] = []
    needing_a_human: list[str] = []
    for exposure in impact.exposures:
        if exposure.basis is MatchBasis.HASH:
            affected.append(exposure)
        else:
            needing_a_human.append(exposure.machine_key)

    if not affected and not needing_a_human:
        raise BridgeError(
            f"advisory {advisory.advisory_id} matches no machine in this fleet. "
            "There is nothing to open a case about from here."
        )

    states: set[str] = set()
    other: set[str] = set()
    machines: list[str] = []
    without_country: list[str] = []
    models: dict[str, dict[str, Any]] = {}

    for exposure in affected:
        record = fleet.record(exposure.machine_key)
        if record is None:  # pragma: no cover - fleet and impact share a source
            continue
        machine = record.manifest.machine
        machines.append(machine.serial)
        if not machine.country:
            without_country.append(machine.serial)
        elif machine.country in EU_MEMBER_STATES:
            states.add(machine.country)
        else:
            other.add(machine.country)

        key = product_name or f"{machine.manufacturer} {machine.model}"
        bucket = models.setdefault(key, {"versions": set(), "units": 0,
                                         "states": set(), "other": set()})
        bucket["units"] += 1
        if exposure.item_version:
            bucket["versions"].add(exposure.item_version)
        if machine.country in EU_MEMBER_STATES:
            bucket["states"].add(machine.country)
        elif machine.country:
            bucket["other"].add(machine.country)

    products = tuple(
        ProductVersion(
            product_name=name,
            version_range=", ".join(sorted(b["versions"])) or "(not recorded)",
            member_states=tuple(sorted(b["states"])),
            other_markets=tuple(sorted(b["other"])),
            units_in_field=b["units"],
            components=tuple(f"{a.supplier} {a.name}" for a in advisory.affected),
            evidence_source=f"fleet manifests, advisory {advisory.advisory_id} "
                            f"({impact.advisory_hash[:12]})",
            owner=received_by,
        )
        for name, b in sorted(models.items())
    )

    decisions: list[str] = [
        "Whether this is an actively exploited vulnerability, a severe incident, "
        "or neither. An advisory naming a defect is not by itself either, and the "
        "track decides which clock runs.",
        "Whether and when awareness was established, per C(2026) 5252 Annex §213: "
        "a reasonable degree of certainty after an initial assessment. The "
        "advisory's publication time is when a document arrived, not when anyone "
        "understood it.",
        "Whether the affected component is part of the product as placed on the "
        "market, or was integrated by somebody else downstream.",
    ]
    if needing_a_human:
        decisions.append(
            f"What is actually running on {', '.join(sorted(needing_a_human))}: the "
            "version label and the artefact disagree, so those machines are in "
            "neither column and are excluded from the counts above."
        )
    if without_country:
        decisions.append(
            f"Which territories {', '.join(without_country)} were made available "
            "in. They are affected and contribute nothing to field 5."
        )

    caveats = [
        "this is an intake, not a filing. No track has been set and no awareness "
        "timestamp has been established; the Article 14 register will refuse a "
        "filing until a person records both.",
        "the Member State list is built from the countries recorded against "
        "enrolled machines. A unit that was never enrolled, or one whose country "
        "was not recorded, is absent from it — and Article 14(2)(a) asks what the "
        "manufacturer is aware of, which is not the same as what is in this ledger.",
        f"only machines matched by artefact hash are counted as affected. "
        f"{len(needing_a_human)} match(es) rest on something weaker and are "
        "listed separately.",
        *impact.checks_skipped,
    ]

    return CaseDraft(
        case_id=case_id or f"CASE-{advisory.advisory_id}",
        signal=Signal(
            received_at=advisory.issued_at,
            channel=SignalChannel.SUPPLIER_ADVISORY,
            received_by=received_by,
            description=f"{advisory.issued_by} advisory {advisory.advisory_id}: "
                        f"{advisory.title}. {advisory.summary}",
            product_name=products[0].product_name if products else "",
            version=products[0].version_range if products else "",
            reference=advisory.reference,
        ),
        products=products,
        member_states=tuple(sorted(states)),
        other_markets=tuple(sorted(other)),
        machines=tuple(sorted(machines)),
        machines_without_country=tuple(sorted(without_country)),
        machines_needing_a_human=tuple(sorted(needing_a_human)),
        decisions_required=tuple(decisions),
        checks_skipped=tuple(dict.fromkeys(caveats)),
        advisory_id=advisory.advisory_id,
        advisory_hash=impact.advisory_hash,
    )


def open_case(
    register: Art14Register, draft: CaseDraft, actor: Actor,
) -> tuple[str, list[Evidence]]:
    """Record the intake in the Article 14 register.

    Records the signal and the product availability — the two things the fleet
    can evidence. It does not record awareness or a track: those are decisions,
    and the register refuses a filing until a person has made them.
    """
    sealed: list[Evidence] = [
        register.record_signal(draft.case_id, draft.signal, actor)
    ]
    for product in draft.products:
        sealed.append(register.record_availability(draft.case_id, product, actor))
    return draft.case_id, sealed
