"""scripts/rehearse-local.sh runs the whole buyer path locally, with no real credential.

The rehearsal starts REAL uvicorn processes on loopback (see scripts/rehearse_local.py). This
test runs it as a user would and checks the record: every step passed, the record carries the
"not a hosted staging proof" label, no secret is in it, and credentials that happen to be in the
caller's environment (a Stripe test key, a price id) never reach the service it starts.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "rehearse-local.sh"

pytestmark = pytest.mark.skipif(not sys.platform.startswith("linux"),
                                reason="loopback servers")


def _run(tmp_path: Path, extra_env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("STRIPE_", "ASSURANCE_", "NEURALBRIDGE_"))}
    env.update(extra_env)
    env["PYTHON"] = sys.executable
    return subprocess.run(  # noqa: S603 - fixed argv, test-owned paths
        ["bash", str(SCRIPT), "--record-dir", str(tmp_path / "rec")],  # noqa: S607
        env=env, capture_output=True, text=True, timeout=240, cwd=ROOT, check=False)


def test_the_complete_buyer_path_passes_and_the_record_is_honest(tmp_path: Path) -> None:
    # A Stripe TEST key and a price id in the caller's environment must NOT reach the service:
    # if they did, checkout would stop refusing and try to call Stripe.
    r = _run(tmp_path, {"STRIPE_SECRET_KEY": "sk_test_" + "x" * 24,
                        "ASSURANCE_PRICE_REGISTER": "price_should_not_leak"})
    assert r.returncode == 0, r.stderr[-3000:]
    path = tmp_path / "rec" / "local-rehearsal.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    text = path.read_text()
    doc = json.loads(text)
    assert doc["label"] == "local rehearsal, not a hosted staging proof"
    assert doc["result"] == "PASS"
    assert [s for s in doc["steps"] if s["status"] != "PASS"] == []
    done = {s["step"] for s in doc["steps"]}
    for needed in (
        "checkout.register_refused_honestly", "webhook.reject_stale_timestamp",
        "webhook.accept_valid_checkout", "webhook.replay_is_a_noop", "webhook.out_of_order_held",
        "webhook.stale_event_ignored", "claim.collected_once_with_token",
        "claim.second_collection_410", "entitlement.no_key_401",
        "entitlement.register_key_on_cell_route_402", "lifecycle.renewal_applied",
        "lifecycle.past_due_flagged_but_entitled", "lifecycle.recovery_from_past_due",
        "lifecycle.cancelled_writes_402", "lifecycle.cancelled_can_still_read_verify_export",
        "lifecycle.key_revocation_is_immediate", "restore.backup_verifies",
        "restore.ledger_chain_verifies", "restore.restored_volume_serves_same_entitlements",
    ):
        assert needed in done, needed
    assert doc["not_established"], "the record must say what it does not show"
    # nothing secret-shaped in the record or in what the script printed
    for blob in (text, r.stdout, r.stderr):
        assert not re.search(r"whsec_local_[0-9a-f]{8}|op-local-\S{8}|nb_[A-Za-z0-9_-]{20}", blob)
        assert "price_should_not_leak" not in blob and "sk_test_" not in blob


def test_it_refuses_to_run_when_the_environment_holds_live_credentials(tmp_path: Path) -> None:
    r = _run(tmp_path, {"STRIPE_SECRET_KEY": "sk_live_" + "x" * 24})
    assert r.returncode == 2
    assert "live" in r.stderr
    assert not (tmp_path / "rec").exists()
