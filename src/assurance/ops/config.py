"""``ops.json``: what one cycle looks at, and where it writes.

Strict on purpose: an unknown key, a wrong type or a value that looks like a pasted secret is an
error (exit 2, nothing written), because a typo in a field that switches a step off would read
exactly like a step that ran. Relative paths are resolved against the config file's directory.
Errors never echo a value back: a key pasted into the wrong field must not reach a terminal.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from assurance.core.errors import AssuranceError

__all__ = ["OpsConfig", "OpsConfigError", "SCHEMA", "load_config"]

SCHEMA = "neuralbridge-ops/1"
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SOURCES = ("kev", "nvd", "epss")
_TOP = {"schema", "ops_id", "data_dir", "record", "lock", "backup_dir", "max_cycle_age_hours",
        "min_free_disk_mb", "intel", "watch", "attest"}


class OpsConfigError(AssuranceError):
    """The ops config is unusable. Nothing was run and nothing was written."""


@dataclass(frozen=True)
class IntelSource:
    source: str
    cves: tuple[str, ...] = ()
    api_key_env: str | None = None


@dataclass(frozen=True)
class IntelCfg:
    live: bool
    store: Path
    sources: tuple[IntelSource, ...]
    timeout_s: float = 30.0


@dataclass(frozen=True)
class WatchCfg:
    config: Path
    ledger: Path


@dataclass(frozen=True)
class AttestCfg:
    key: Path
    passphrase_env: str | None = None
    max_age_hours: float = 24.0


@dataclass(frozen=True)
class OpsConfig:
    path: Path
    ops_id: str
    data_dir: Path
    record: Path
    lock: Path
    backup_dir: Path
    max_cycle_age_hours: float = 26.0
    min_free_disk_mb: float = 1024.0
    intel: IntelCfg | None = None
    watch: tuple[WatchCfg, ...] = field(default_factory=tuple)
    attest: AttestCfg | None = None

    def secret_env_names(self) -> list[str]:
        names = [s.api_key_env for s in (self.intel.sources if self.intel else ())
                 if s.api_key_env]
        if self.attest and self.attest.passphrase_env:
            names.append(self.attest.passphrase_env)
        return names


def _fail(msg: str) -> OpsConfigError:
    return OpsConfigError(f"ops config: {msg}. Nothing was run and nothing was written.")


def _obj(value: Any, where: str, allowed: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(f"{where} must be an object")
    extra = sorted(set(value) - allowed)
    if extra:
        # key NAMES are shown (they are the operator's typo); values never are
        raise _fail(f"{where} has unknown key(s) {', '.join(map(str, extra))} (allowed: "
                    f"{', '.join(sorted(allowed))})")
    return value


def _path(value: Any, where: str, base: Path) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise _fail(f"{where} must be a non-empty path string")
    p = Path(value).expanduser()
    return p if p.is_absolute() else base / p


def _env_name(value: Any, where: str) -> str:
    # Only the NAME of a variable is ever configured. A value that is not shaped like a name is
    # refused without being shown: it may be the secret itself.
    if not isinstance(value, str) or not _ENV_NAME.fullmatch(value):
        raise _fail(f"{where} must be the NAME of an environment variable (letters, digits, "
                    "underscore); the value was not shown. Never put a key or passphrase here")
    return value


def _number(value: Any, where: str, *, minimum: float) -> float:
    if (isinstance(value, bool) or not isinstance(value, int | float)
            or value != value or value < minimum):
        raise _fail(f"{where} must be a number >= {minimum:g}")
    return float(value)


def load_config(path: str | Path) -> OpsConfig:
    p = Path(path)
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise _fail("the config file does not exist") from None
    except (OSError, UnicodeDecodeError):
        raise _fail("the config file could not be read") from None
    except json.JSONDecodeError as exc:
        raise _fail(f"the config file is not valid JSON (line {exc.lineno}, column "
                    f"{exc.colno})") from None
    base = p.resolve().parent
    top = _obj(raw, "the file", _TOP)
    if top.get("schema", SCHEMA) != SCHEMA:
        raise _fail(f"schema must be {SCHEMA!r}")
    for key in ("ops_id", "data_dir", "record", "backup_dir"):
        if key not in top:
            raise _fail(f"{key!r} is required")
    ops_id = top["ops_id"]
    if not isinstance(ops_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", ops_id):
        raise _fail("ops_id must be 1-64 characters of letters, digits, '.', '_' or '-'")
    record = _path(top["record"], "record", base)
    lock = _path(top["lock"], "lock", base) if "lock" in top else Path(f"{record}.lock")

    intel: IntelCfg | None = None
    if "intel" in top:
        d = _obj(top["intel"], "intel", {"live", "store", "sources", "timeout_s"})
        if not isinstance(d.get("live", False), bool):
            raise _fail("intel.live must be true or false")
        raw_sources = d.get("sources", [])
        if not isinstance(raw_sources, list):
            raise _fail("intel.sources must be a list")
        sources: list[IntelSource] = []
        for i, item in enumerate(raw_sources):
            s = _obj(item, f"intel.sources[{i}]", {"source", "cves", "api_key_env"})
            if s.get("source") not in _SOURCES:
                raise _fail(f"intel.sources[{i}].source must be one of {', '.join(_SOURCES)}")
            cves = s.get("cves", [])
            if not isinstance(cves, list) or not all(
                    isinstance(c, str) and _CVE.fullmatch(c) for c in cves):
                raise _fail(f"intel.sources[{i}].cves must be a list of CVE ids")
            if s["source"] != "kev" and not cves:
                raise _fail(f"intel.sources[{i}]: {s['source']} is asked about named CVEs; "
                            "give cves")
            if s["source"] == "kev" and cves:
                raise _fail(f"intel.sources[{i}]: kev is the whole catalogue; cves do not apply")
            env = _env_name(s["api_key_env"], f"intel.sources[{i}].api_key_env") \
                if s.get("api_key_env") is not None else None
            sources.append(IntelSource(s["source"], tuple(cves), env))
        if sources and "store" not in d:
            raise _fail("intel.store is required when intel.sources is not empty")
        intel = IntelCfg(
            live=d.get("live", False),
            store=_path(d["store"], "intel.store", base) if "store" in d else base / "intel.db",
            sources=tuple(sources),
            timeout_s=_number(d.get("timeout_s", 30), "intel.timeout_s", minimum=1))

    watches: list[WatchCfg] = []
    raw_watch = top.get("watch", [])
    if not isinstance(raw_watch, list):
        raise _fail("watch must be a list")
    for i, item in enumerate(raw_watch):
        w = _obj(item, f"watch[{i}]", {"config", "ledger"})
        if "config" not in w or "ledger" not in w:
            raise _fail(f"watch[{i}] needs 'config' and 'ledger'")
        watches.append(WatchCfg(_path(w["config"], f"watch[{i}].config", base),
                                _path(w["ledger"], f"watch[{i}].ledger", base)))

    attest: AttestCfg | None = None
    if "attest" in top:
        a = _obj(top["attest"], "attest", {"key", "passphrase_env", "max_age_hours"})
        if "key" not in a:
            raise _fail("attest.key (a path to the key FILE) is required when attest is given")
        attest = AttestCfg(
            key=_path(a["key"], "attest.key", base),
            passphrase_env=_env_name(a["passphrase_env"], "attest.passphrase_env")
            if a.get("passphrase_env") is not None else None,
            max_age_hours=_number(a.get("max_age_hours", 24), "attest.max_age_hours",
                                  minimum=0))

    return OpsConfig(
        path=p, ops_id=ops_id, data_dir=_path(top["data_dir"], "data_dir", base),
        record=record, lock=lock, backup_dir=_path(top["backup_dir"], "backup_dir", base),
        max_cycle_age_hours=_number(top.get("max_cycle_age_hours", 26), "max_cycle_age_hours",
                                    minimum=0.01),
        min_free_disk_mb=_number(top.get("min_free_disk_mb", 1024), "min_free_disk_mb",
                                 minimum=0),
        intel=intel, watch=tuple(watches), attest=attest)
