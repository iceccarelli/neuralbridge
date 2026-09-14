"""The domain of an Article 14 case.

Regulation (EU) 2024/2847, Article 14 — applicable since 11 September 2026,
and by Article 69(3) applicable to every in-scope product placed on the market
before 11 December 2027. There is no grandfathering for reporting, and per the
Commission's guidance the duty outlives a product's support period.

Everything modelled here exists because a filing needs it or because a defence
needs it. Nothing is modelled because it would be tidy.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from ...core.identity import format_utc, parse_utc

__all__ = [
    "CASE_KIND",
    "Awareness",
    "NonReportGround",
    "ProductVersion",
    "Signal",
    "SignalChannel",
    "Stage",
    "Track",
]

#: Evidence kinds written to the ledger by this module.
CASE_KIND = {
    "signal": "art14.signal",
    "awareness": "art14.awareness",
    "triage": "art14.triage",
    "non_report": "art14.non_report",
    "filing": "art14.filing",
    "user_notice": "art14.user_notice",
}


class Track(StrEnum):
    """Which limb of Article 14 applies.

    The tracks differ in required content *and* in what the final-report clock
    runs from, which is the single most commonly misread part of the Article.
    """

    #: Article 14(1)-(2). Art. 3(42): reliable evidence that a malicious actor
    #: has exploited it in a system without the owner's permission.
    VULNERABILITY = "actively_exploited_vulnerability"
    #: Article 14(3)-(4), severity per Article 14(5).
    INCIDENT = "severe_incident"

    @property
    def label(self) -> str:
        return {
            "actively_exploited_vulnerability": "Actively exploited vulnerability",
            "severe_incident": "Severe incident",
        }[self.value]


class Stage(StrEnum):
    """The three filings."""

    EARLY_WARNING = "early_warning"      # 24 h
    NOTIFICATION = "notification"        # 72 h
    FINAL = "final"                      # 14 d (vuln) / 1 month (incident)
    INTERMEDIATE = "intermediate"        # Art. 14(6), on CSIRT request

    @property
    def label(self) -> str:
        return {
            "early_warning": "Early warning (24 h)",
            "notification": "Notification (72 h)",
            "final": "Final report",
            "intermediate": "Intermediate report (on request)",
        }[self.value]


class SignalChannel(StrEnum):
    """How a potential event reached us.

    The Commission FAQ is explicit that the CRA does not require a manufacturer
    to go looking through any of these; what it requires is that the duty binds
    once the manufacturer does become aware. Recording the channel matters
    because it is the start of the interval a regulator will ask about.
    """

    CVD_INBOX = "cvd_inbox"
    CUSTOMER = "customer_or_integrator"
    DISTRIBUTOR = "distributor"
    CSIRT = "national_csirt"
    SUPPLIER_ADVISORY = "component_supplier_advisory"
    INTERNAL_TELEMETRY = "internal_telemetry"
    RESEARCHER = "security_researcher"
    PUBLIC_REPORTING = "public_reporting"
    PENETRATION_TEST = "penetration_test"
    OTHER = "other"


@dataclass(frozen=True)
class ProductVersion:
    """A product and the versions of it that are in the field.

    ``member_states`` is the field that decides whether a 24-hour filing can be
    completed at all. Article 14(2)(a) and 14(4)(a) require the early warning to
    indicate, where applicable, the Member States in whose territory the
    manufacturer is aware the product has been made available. For a legacy
    portfolio it is the answer that cannot be assembled under time pressure, so
    it is assembled in advance and kept here.

    ``end_of_support`` does not remove the product from scope. It is carried
    because the platform asks for it, and because a support period that has
    ended changes which *other* obligations apply, not this one.
    """

    product_name: str
    version_range: str
    #: ISO 3166-1 alpha-2, EU/EEA only. Non-Member-State markets belong in
    #: ``other_markets``: they matter for the duty to inform users under
    #: Article 14(8), but they are not what field 5 asks for.
    member_states: tuple[str, ...] = ()
    other_markets: tuple[str, ...] = ()
    placed_on_market_from: str = ""
    placed_on_market_to: str = ""
    end_of_support: bool = False
    units_in_field: int | None = None
    product_type: str = ""       # Default | Important Class I | Important Class II | Critical
    annex_category: str = ""
    components: tuple[str, ...] = ()
    evidence_source: str = ""    # where the Member State list came from
    owner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "product_name": self.product_name,
            "version_range": self.version_range,
            "member_states": list(self.member_states),
            "other_markets": list(self.other_markets),
            "placed_on_market_from": self.placed_on_market_from,
            "placed_on_market_to": self.placed_on_market_to,
            "end_of_support": self.end_of_support,
            "units_in_field": self.units_in_field,
            "product_type": self.product_type,
            "annex_category": self.annex_category,
            "components": list(self.components),
            "evidence_source": self.evidence_source,
            "owner": self.owner,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ProductVersion:
        return cls(
            product_name=str(d["product_name"]),
            version_range=str(d.get("version_range", "")),
            member_states=tuple(d.get("member_states", ())),
            other_markets=tuple(d.get("other_markets", ())),
            placed_on_market_from=str(d.get("placed_on_market_from", "")),
            placed_on_market_to=str(d.get("placed_on_market_to", "")),
            end_of_support=bool(d.get("end_of_support", False)),
            units_in_field=d.get("units_in_field"),
            product_type=str(d.get("product_type", "")),
            annex_category=str(d.get("annex_category", "")),
            components=tuple(d.get("components", ())),
            evidence_source=str(d.get("evidence_source", "")),
            owner=str(d.get("owner", "")),
        )

    def gaps(self) -> list[str]:
        """What this record cannot answer for a 24-hour filing."""
        missing = []
        if not self.member_states:
            missing.append(
                "member_states is empty — SRP field 5 cannot be completed, and it is the "
                "only substantive content Art. 14(2)(a) requires at 24 hours"
            )
        if not self.version_range:
            missing.append("version_range is empty — SRP field 7 cannot be completed")
        if not self.evidence_source:
            missing.append(
                "evidence_source is empty — the Member State list cannot be substantiated "
                "if challenged"
            )
        return missing


@dataclass(frozen=True)
class Signal:
    """A report or observation that might turn out to be reportable.

    Recorded *before* anyone knows whether it matters. The interval between
    ``received_at`` and the awareness moment is the number a market surveillance
    authority asks about, and it cannot be reconstructed after the fact.
    """

    received_at: datetime
    channel: SignalChannel
    received_by: str
    description: str
    product_name: str = ""
    version: str = ""
    reference: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "received_at": format_utc(self.received_at),
            "channel": self.channel.value,
            "received_by": self.received_by,
            "description": self.description,
            "product_name": self.product_name,
            "version": self.version,
            "reference": self.reference,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Signal:
        return cls(
            received_at=parse_utc(d["received_at"]),
            channel=SignalChannel(d.get("channel", "other")),
            received_by=str(d.get("received_by", "")),
            description=str(d.get("description", "")),
            product_name=str(d.get("product_name", "")),
            version=str(d.get("version", "")),
            reference=str(d.get("reference", "")),
        )


@dataclass(frozen=True)
class Awareness:
    """The moment every deadline runs from, and the reasoning behind it.

    The Regulation does not define "becoming aware". The Commission's guidance
    (Communication C(2026) 5252, Annex, §213) does: a manufacturer is to be
    regarded as having become aware when, after an initial assessment, it has a
    reasonable degree of certainty that a vulnerability in its product is being
    actively exploited, or that a severe incident has occurred. §214 adds
    that the emphasis is on prompt action to carry out that assessment — a
    slow assessment is not a lawful way to postpone a deadline.

    This record exists because the reporting platform does not yet capture the
    fact. The field for a vulnerability awareness timestamp is documented as
    arriving in a future release, and the incident field currently records
    *detection*, which is a different moment. Until that changes, this is the
    only evidence of the fact every deadline is computed from.
    """

    established_at: datetime
    assessment_started_at: datetime
    assessment_completed_at: datetime
    determined_by: str
    reasoning: str
    basis: str = "C(2026) 5252 Annex §213 — reasonable degree of certainty after initial assessment"

    def __post_init__(self) -> None:
        if self.assessment_completed_at < self.assessment_started_at:
            raise ValueError("assessment completed before it started")

    @property
    def assessment_hours(self) -> float:
        delta = self.assessment_completed_at - self.assessment_started_at
        return round(delta.total_seconds() / 3600.0, 2)

    def lag_hours_from(self, signal: Signal) -> float:
        """Hours from the first signal to the awareness moment."""
        return round((self.established_at - signal.received_at).total_seconds() / 3600.0, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "established_at": format_utc(self.established_at),
            "assessment_started_at": format_utc(self.assessment_started_at),
            "assessment_completed_at": format_utc(self.assessment_completed_at),
            "assessment_hours": self.assessment_hours,
            "determined_by": self.determined_by,
            "reasoning": self.reasoning,
            "basis": self.basis,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Awareness:
        return cls(
            established_at=parse_utc(d["established_at"]),
            assessment_started_at=parse_utc(d["assessment_started_at"]),
            assessment_completed_at=parse_utc(d["assessment_completed_at"]),
            determined_by=str(d.get("determined_by", "")),
            reasoning=str(d.get("reasoning", "")),
            basis=str(d.get("basis", "")),
        )


class NonReportGround(StrEnum):
    """Why an event was assessed as not reportable.

    A conclusion with no ground is not a decision record. Each member names the
    provision or the guidance paragraph it rests on, so the record cites its own
    authority.
    """

    NO_RELIABLE_EVIDENCE = "no_reliable_evidence_of_malicious_exploitation"
    NOT_REACHABLE = "third_party_component_not_reachable_in_our_product"
    NOT_EXPLOITED_IN_PRODUCT = "third_party_component_not_exploited_in_our_product"
    NO_PRODUCT_SECURITY_IMPACT = "incident_does_not_affect_security_of_the_product"
    NOT_SEVERE = "incident_not_severe_under_article_14_5"
    CORPORATE_IT_ONLY = "incident_affected_corporate_it_only"
    PRE_CUTOFF_AWARENESS = "awareness_of_active_exploitation_predates_2026_09_11"
    OUT_OF_SCOPE = "product_outside_cra_scope"

    @property
    def authority(self) -> str:
        return {
            "no_reliable_evidence_of_malicious_exploitation":
                "Art. 3(42); Recital 68; Commission FAQ 5.2",
            "third_party_component_not_reachable_in_our_product":
                "Commission guidance C(2026) 5252 Annex §218(i)",
            "third_party_component_not_exploited_in_our_product":
                "Commission guidance C(2026) 5252 Annex §218(ii)",
            "incident_does_not_affect_security_of_the_product": "Art. 3(44)",
            "incident_not_severe_under_article_14_5": "Art. 14(5)(a) and (b)",
            "incident_affected_corporate_it_only": "Art. 3(44); Art. 14(5)",
            "awareness_of_active_exploitation_predates_2026_09_11":
                "Commission guidance C(2026) 5252 Annex §217",
            "product_outside_cra_scope": "Art. 2",
        }[self.value]

    @property
    def requires_reopen_trigger(self) -> bool:
        """Grounds that can stop being true without any action by us.

        §217 is the sharpest: awareness of a vulnerability before the cutoff
        does not exempt it if active exploitation occurs, or comes to our
        attention, afterwards. Closing on that ground without a reopen trigger
        converts a live obligation into a forgotten one.
        """
        return self in {
            NonReportGround.NO_RELIABLE_EVIDENCE,
            NonReportGround.NOT_REACHABLE,
            NonReportGround.NOT_EXPLOITED_IN_PRODUCT,
            NonReportGround.PRE_CUTOFF_AWARENESS,
            NonReportGround.NOT_SEVERE,
        }

    @property
    def leaves_upstream_duty(self) -> bool:
        """Whether Art. 13(6) upstream reporting still applies."""
        return self in {NonReportGround.NOT_REACHABLE, NonReportGround.NOT_EXPLOITED_IN_PRODUCT}
