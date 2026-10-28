"""A placeholder is not a hash: it must never make two manifests compare as unchanged.

Regression: ``is_comparable`` was ``bool(content_hash)``, so ``n/a`` on both sides, claimed
as read from the machine, produced an identical, VALIDATED-tier divergence report with no
caveat. The same string in two manifests said nothing about the machine.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.core.evidence import Actor
from assurance.core.tiers import AssuranceTier
from assurance.machinery.divergence import ChangeKind, compare
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyFunction,
    SafetyItem,
    SafetyManifest,
    normalised_digest,
)

H1 = "a" * 64
H2 = "b" * 64


def item(h, version="1.0"):
    return SafetyItem("fw", ItemKind.FIRMWARE, "controller firmware", version, h,
                      HashSource.READ_FROM_MACHINE, implements=("SF-1",))


def manifest(it):
    return SafetyManifest(
        manifest_id="m", machine=MachineIdentity("Acme", "AR-7", "0412"),
        source=ManifestSource.AS_FOUND, taken_at=datetime(2026, 1, 1, tzinfo=UTC),
        taken_by=Actor("tech", "technician"), items=(it,),
        functions=(SafetyFunction("SF-1", "safe stop", verified_by=("stop_time",)),),
    )


@pytest.mark.parametrize("text", ["n/a", "unknown", "0", "   ", "TBD", "sha256:", "a" * 63,
                                  "a" * 65, "g" * 64])
def test_a_non_digest_is_not_a_hash(text):
    assert normalised_digest(text) == ""
    assert item(text).is_comparable is False


@pytest.mark.parametrize("text", [H1, H1.upper(), f" {H1} ", f"sha256:{H1}", f"SHA256:{H1.upper()}"])
def test_a_digest_is_recognised_in_any_dress(text):
    assert normalised_digest(text) == H1
    assert item(text).is_comparable is True


@pytest.mark.parametrize("placeholder", ["n/a", "unknown", "0", "   "])
def test_two_placeholders_are_not_an_unchanged_artefact(placeholder):
    d = compare(manifest(item(placeholder)), manifest(item(placeholder)))
    assert d.uncompared == ("fw",)
    assert any("carries no hash" in c for c in d.checks_skipped)


def test_a_placeholder_lowers_the_tier_as_a_declared_item_would():
    assert manifest(item("n/a")).tier_ceiling < AssuranceTier.VALIDATED
    assert manifest(item(H1)).tier_ceiling is AssuranceTier.VALIDATED
    assert item("n/a").effective_hash_source is HashSource.DECLARED


def test_the_same_digest_in_different_dress_is_not_a_change():
    d = compare(manifest(item(H1)), manifest(item(f"sha256:{H1.upper()}")))
    assert d.changes == () and d.equivalent
    assert d.verdict == "matches"


def test_a_real_change_is_still_the_finding():
    d = compare(manifest(item(H1)), manifest(item(H2)))
    assert [c.kind for c in d.changes] == [ChangeKind.CONTENT_CHANGED]
    assert d.changes[0].severity.value == "safety_relevant"
