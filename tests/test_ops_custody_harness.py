"""Every harness that starts the platform API gives it credential custody, or binding answers 503.

Credential custody fails closed: with no key and no journal, ``POST /ai/connections`` answers 503
``credential_custody_unconfigured``. PR #113's browser job failed on exactly that (five specs per
project) because ``scripts/e2e-local.sh`` started the platform without either. The two scripts that
start a throwaway platform must set both, per run, with the journal outside the store's directory,
and without the key ever reaching a command line.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ["scripts/e2e-local.sh", "scripts/local-stack.sh"]


@pytest.mark.parametrize("script", SCRIPTS)
def test_the_script_configures_a_per_run_key_and_a_journal_before_starting_the_platform(script: str) -> None:
    text = (ROOT / script).read_text(encoding="utf-8")
    start = text.index("-m uvicorn neuralbridge.main:app")
    before = text[:start]
    assert "NEURALBRIDGE_CREDENTIAL_KEYS" in before, "no custody key before the platform starts"
    assert "NEURALBRIDGE_CREDENTIAL_JOURNAL" in before, "no custody journal before the platform starts"
    assert "os.urandom(32)" in before, "the key must be random per run"


@pytest.mark.parametrize("script", SCRIPTS)
def test_the_key_is_never_printed_or_placed_on_a_command_line(script: str) -> None:
    text = (ROOT / script).read_text(encoding="utf-8")
    for line in text.splitlines():
        code = line.split("#", 1)[0]
        if "CREDENTIAL_KEYS" in code:
            assert not re.search(r"\b(echo|printf|cat)\b", code), line
            assert "--" not in code.replace("--port", ""), f"key near an option: {line}"
    assert "set -x" not in text and "set -o xtrace" not in text


def test_the_journal_is_outside_the_store_directory() -> None:
    e2e = (ROOT / "scripts/e2e-local.sh").read_text(encoding="utf-8")
    assert 'NEURALBRIDGE_CREDENTIAL_JOURNAL="$WORK/custody/journal"' in e2e   # store is $WORK/<proj>/
    stack = (ROOT / "scripts/local-stack.sh").read_text(encoding="utf-8")
    assert 'NEURALBRIDGE_CREDENTIAL_JOURNAL="$DIR.custody/journal"' in stack  # store is $DIR/
    assert 'rm -rf "$DIR" "$DIR.custody"' in stack, "down must remove the custody directory too"


def test_the_demo_compose_file_refuses_to_start_without_a_key() -> None:
    text = (ROOT / "docker-compose.demo.yml").read_text(encoding="utf-8")
    assert "NEURALBRIDGE_CREDENTIAL_KEYS: ${NEURALBRIDGE_CREDENTIAL_KEYS:?" in text
    assert "NEURALBRIDGE_CREDENTIAL_JOURNAL: /custody/journal" in text
    assert "demo_custody:/custody" in text
