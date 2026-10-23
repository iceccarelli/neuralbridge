"""Test-only: make a subprocess behave as if a recorder attestation had been verified.

Loaded by Python at start-up when this directory is on ``PYTHONPATH``. See
``tests/support_recorder_attestation.py``. Never on any production path.
"""

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_support_recorder_attestation",
    Path(__file__).resolve().parents[1] / "support_recorder_attestation.py")
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    _mod.install()
