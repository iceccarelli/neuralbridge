"""The cycle record: one JSON object per line, appended, never rewritten.

What it holds: times from the real clock, each step's command-equivalent, exit code, duration,
status, a few counts, and the human actions the findings call for. What it never holds: key
material, a passphrase, an API key, ledger contents or a step's raw output. The structural
guarantee is that raw output is never stored; :func:`scrub` is a second, independent filter over
every string (configured secrets by value, PEM markers, long base64-looking runs) so that an
exception message or a path that happens to carry one cannot reach the file.

The record is not signed or chained. Whoever can write the file can rewrite it, so it is an
operator's log and not evidence (``OPS.md``, "not established").
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["FORMAT", "ReadResult", "append", "read", "scrub", "secrets_for"]

FORMAT = "neuralbridge-ops-cycle/1"
REDACTED = "[redacted]"
_PEM = re.compile(r"-----(?:BEGIN|END)[^-\n]{0,40}-----")
_LONG_B64 = re.compile(r"[A-Za-z0-9+]{40,}={0,2}")
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def secrets_for(env_names: Iterable[str], key_files: Iterable[Path]) -> list[str]:
    """The secret strings this cycle could meet, to be removed by value from anything stored.

    Held in memory for the length of the cycle and never written. A key file contributes each
    non-marker line (the base64 body), so a pasted fragment is caught even without its header.
    """
    found: set[str] = set()
    for name in env_names:
        value = os.environ.get(name, "")
        if len(value) >= 4:
            found.add(value)
    for path in key_files:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if len(line) >= 8 and not line.startswith("-----"):
                found.add(line)
    return sorted(found, key=len, reverse=True)


def _clean_text(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    text = _PEM.sub(REDACTED, text)

    def run(m: re.Match[str]) -> str:
        return m.group(0) if _HEX.match(m.group(0).rstrip("=")) else REDACTED

    return _LONG_B64.sub(run, text)


def scrub(value: Any, secrets: list[str]) -> Any:
    """``value`` with every string cleaned; dict keys are cleaned too."""
    if isinstance(value, str):
        return _clean_text(value, secrets)
    if isinstance(value, dict):
        return {_clean_text(str(k), secrets): scrub(v, secrets) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [scrub(v, secrets) for v in value]
    return value


def append(path: Path, record: dict[str, Any]) -> None:
    """Append one line. Earlier bytes are never touched.

    A final line without a newline (a crash mid-write) gets its newline first, so the next
    record starts on its own line instead of being glued onto the fragment.
    """
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        size = os.fstat(fd).st_size
        if size and os.pread(fd, 1, size - 1) != b"\n":
            os.write(fd, b"\n")
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class ReadResult:
    cycles: list[dict[str, Any]]
    unreadable_lines: list[int]
    exists: bool


def read(path: Path) -> ReadResult:
    if not path.is_file():
        return ReadResult([], [], False)
    cycles: list[dict[str, Any]] = []
    bad: list[int] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                bad.append(n)
                continue
            if (isinstance(doc, dict) and doc.get("format") == FORMAT
                    and isinstance(doc.get("finished_at"), str)
                    and doc.get("status") in ("ok", "flagged", "degraded")):
                cycles.append(doc)
            else:
                bad.append(n)
    return ReadResult(cycles, bad, True)
