"""One definition of "template value", enforced the same on every path that takes input.

The kit, SBOM review and inventory import used to keep three different lists: the kit refused
``tbd`` and enrolled ``000000``, SBOM review refused ``tbd`` and accepted ``000000``, inventory
import accepted ``TBD``, ``000000`` and an all-zero SHA-256. A value must be judged the same
wherever it is typed.
"""

from __future__ import annotations

import json

import pytest

from assurance.core.placeholders import placeholder_problem, starter_values
from assurance.ingest import sbom_store
from assurance.kit.enrol import KitConfig, KitError
from assurance.machinery import inventory as inv
from assurance.machinery.manifest import (
    HashSource,
    ItemKind,
    MachineIdentity,
    ManifestSource,
    SafetyItem,
    SafetyManifest,
    not_a_look,
)

PLACEHOLDER_SERIALS = [
    "TBD", "tbd", "TODO", "CHANGE ME", "changeme", "xxx", "XXXXXX", "n/a", "N/A", "none",
    "null", "placeholder", "example", "000000", "AAAAAA", "xxxxxx", "-----",
    "TBC", "tba", "unknown", "unknown serial", "not applicable", "n.a.", "N A", "—", "???",
    "---", "\u200b", "\u00a0", "T-B-D",
]
REAL_SERIALS = ["0412", "AR7-1001", "2023/00123", "7", "SN 88 21", "1234567", "111",
                "1111", "0000", "7777", "AAAA", "000123", "1111-A", "NA-100", "00-12"]


def _sbom_problems(serial: str) -> list[str]:
    bad: list[str] = []
    sbom_store._identity(
        {"identity": {"manufacturer": "Acme", "model": "AR-7", "serial": serial}},
        {"bom": {}}, bad)
    return bad


def _inventory_rejects(serial: str) -> str:
    raw = {"manufacturer": "Acme", "model": "AR-7", "serial": serial,
           "items": [{"name": "fw", "version": "1"}]}
    try:
        inv.canonical_row(raw, 1)
    except inv.RowRejected as exc:
        return str(exc)
    return ""


def _kit_rejects(tmp_path, serial: str) -> str:
    body = {"kit_id": "k", "organisation": "Acme GmbH", "prepared_by": "Jane Doe",
            "site": "Hamburg Works", "machines": [
                {"serial": serial, "plan": "p.json", "exports": "e"}]}
    path = tmp_path / "kit.json"
    path.write_text(json.dumps(body))
    try:
        KitConfig.from_json(path)
    except KitError as exc:
        return str(exc)
    return ""


@pytest.mark.parametrize("serial", PLACEHOLDER_SERIALS)
def test_a_placeholder_serial_is_refused_on_all_three_paths(tmp_path, serial):
    assert placeholder_problem("serial", serial), serial
    assert _sbom_problems(serial), f"SBOM review accepted {serial!r}"
    assert _inventory_rejects(serial), f"inventory import accepted {serial!r}"
    assert _kit_rejects(tmp_path, serial), f"the kit accepted {serial!r}"


@pytest.mark.parametrize("serial", REAL_SERIALS)
def test_a_real_serial_is_accepted_on_all_three_paths(tmp_path, serial):
    assert placeholder_problem("serial", serial) is None
    assert not _sbom_problems(serial)
    assert not _inventory_rejects(serial)
    assert "serial" not in _kit_rejects(tmp_path, serial).split("export")[0]


def test_the_reason_never_contains_the_value():
    """Inventory import's rule: a rejection reason carries no cell value."""
    assert "SECRETPLACEHOLDER" not in (placeholder_problem("serial", "000000") or "")
    assert "TBD" not in _inventory_rejects("TBD")


def test_an_all_zero_digest_is_refused_by_inventory_import():
    raw = {"manufacturer": "Acme", "model": "AR-7", "serial": "0412",
           "items": [{"name": "fw", "version": "1", "sha256": "0" * 64}]}
    with pytest.raises(inv.RowRejected, match="all zeros"):
        inv.canonical_row(raw, 1)
    raw["items"][0]["sha256"] = "ab" * 32
    assert inv.canonical_row(raw, 1).items[0].sha256 == "ab" * 32


def test_the_starter_values_are_named_not_refused():
    """Plant 1, DE and 2025 can all be true; they are reported, never treated as junk."""
    assert starter_values(site="Plant 1", country="DE", year="2025", serial="CELL-0412") == {
        "site": "Plant 1", "country": "DE", "year": "2025", "serial": "CELL-0412"}
    assert starter_values(site="Hamburg Works", country="IT") == {}
    assert placeholder_problem("country", "DE") is None


# -- F9: the digest label is the effective one --------------------------------
def _manifest(digest: str, source: HashSource = HashSource.READ_FROM_MACHINE):
    from assurance.core.evidence import Actor
    from assurance.core.identity import utc_now

    item = SafetyItem(item_id="ITM-FW", kind=ItemKind.FIRMWARE, name="fw", version="1",
                      content_hash=digest, hash_source=source)
    return SafetyManifest(
        manifest_id="m", machine=MachineIdentity("Acme", "AR-7", "0412"),
        source=ManifestSource.AS_FOUND, taken_at=utc_now(),
        taken_by=Actor(identifier="Jane Doe", role="x", kind="person"), items=(item,))


@pytest.mark.parametrize("digest", ["n/a", "0" * 64, "unknown"])
def test_a_label_of_read_from_machine_beside_no_real_digest_is_not_a_look(digest):
    m = _manifest(digest)
    assert m.tier_ceiling.value == "profile"
    assert not_a_look(m), f"{digest!r} labelled read_from_machine passed as a look"


def test_a_real_digest_labelled_read_from_machine_is_still_a_look():
    m = _manifest("ab" * 32)
    assert not_a_look(m) == ""
    assert m.tier_ceiling.value == "validated"


def test_a_real_sha256_still_passes_and_the_null_digest_does_not():
    assert placeholder_problem("sha256", "ab" * 32) is None
    assert placeholder_problem("sha256", "1" * 64) is None        # fixtures' stand-in, tolerated
    assert placeholder_problem("sha256", "0" * 64)
    assert placeholder_problem("item 1 sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is None
