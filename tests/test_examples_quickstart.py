"""examples/quickstart.py is the first thing a developer runs on the adapter platform. It crashed on step 2
(`register("postgres", adapter)` against `register(adapter, key=None)`) and on `AuditLogger()` (storage is
required), so it had never run for anyone. It must run, say its data is canned, and show the default refusal."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_quickstart_runs_and_is_honest_about_canned_data():
    done = subprocess.run(  # noqa: S603
        [sys.executable, str(ROOT / "examples" / "quickstart.py")],
        capture_output=True, text=True, timeout=120, cwd=ROOT,
        env={"PATH": "", "PYTHONPATH": str(ROOT / "src")},
    )
    out = done.stdout
    assert done.returncode == 0, done.stderr[-800:]
    assert "CANNED" in out and "Salesforce query ->" in out and "Slack send_message ->" in out
    assert "refused: Adapter 'slack' (mock) would answer from canned data" in out
    assert "2 audit events recorded" in out
    assert "NeuralBridge is ready" not in out  # nothing here starts a server
