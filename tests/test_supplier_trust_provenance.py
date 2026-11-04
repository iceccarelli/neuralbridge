"""A pin whose stated provenance is the feed itself is refused (the feed is signed by the key)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from assurance.attest.keys import SigningKey
from assurance.evidence.ledger import EvidenceLedger
from assurance.supplier.cli import main as supplier_main
from assurance.supplier.trust import SupplierTrustError, SupplierTrustStore

FEED_ONLY = [
    "from the feed", "the feed", "feed", "Feed itself", "  FROM   THE  FEED  ", "the feed's own key",
    "the feed’s own key", "same feed", "from the feed.", "via the supplier feed",
    "feeds", "copied from the hosted feed", "from-the-feed", "the feed itself, fingerprint printed inside",
]
INDEPENDENT = [
    "supplier contract, clause 7", "signed email, verified by phone to the PSIRT desk",
    "vendor portal over a separate channel", "phone call", "feed team lead read it out over the phone",
]


def _store(tmp_path):
    return SupplierTrustStore(EvidenceLedger(tmp_path / "t.db"))


def _public_pem():
    return SigningKey.generate().verifying.pem()


@pytest.mark.parametrize("via", FEED_ONLY)
def test_pin_naming_the_feed_is_refused_and_nothing_is_recorded(tmp_path, via):
    store = _store(tmp_path)
    with pytest.raises(SupplierTrustError) as e:
        store.pin("ctrl", _public_pem(), actor="alice", obtained_via=via)
    msg = str(e.value)
    assert "independent channel" in msg and "contract" in msg and "phone" in msg
    assert "portal" in msg
    assert store.pins() == []


@pytest.mark.parametrize("via", INDEPENDENT)
def test_independent_provenance_is_accepted(tmp_path, via):
    pin = _store(tmp_path).pin("ctrl", _public_pem(), actor="alice", obtained_via=via)
    assert pin.obtained_via == via


@pytest.mark.parametrize("via", FEED_ONLY[:4])
def test_rotation_naming_the_feed_is_refused(tmp_path, via):
    store = _store(tmp_path)
    old = store.pin("ctrl", _public_pem(), actor="alice", obtained_via="contract")
    with pytest.raises(SupplierTrustError) as e:
        store.rotate("ctrl", _public_pem(), retire_fingerprint=old.fingerprint,
                     effective_at=datetime(2030, 1, 1, tzinfo=UTC), actor="alice",
                     obtained_via=via)
    assert "independent channel" in str(e.value)


def test_cli_refuses_and_says_why(tmp_path, capsys):
    key = SigningKey.generate()
    pub = tmp_path / "s.pub"
    pub.write_text(_public_pem())
    ledger = tmp_path / "l.db"
    EvidenceLedger(ledger)
    rc = supplier_main(["trust", "pin", "--ledger", str(ledger), "--supplier-id", "ctrl",
                        "--public-key", str(pub), "--obtained-via", "from the feed",
                        "--actor", "alice"])
    assert rc == 1
    assert "independent channel" in capsys.readouterr().err
    del key
