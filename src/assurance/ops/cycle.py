"""One cycle: the unattended, non-human steps of the pipeline, in a fixed order.

    1. intel refresh      per configured source; ONLY if config ``live: true`` AND ``--live``
    2. watch run          per configured watch config
    3. ledger.verify      every ledger under the data directory (read-only chain walk)
    4. attest anchor-all  only if a key is configured, and only if step 3 passed
    5. backup             into a new timestamped directory, then
    6. backup.verify      ``restore_check verify`` on it; a backup that does not verify fails

Each step calls the existing entry point in-process (``main(argv)``) and is isolated: an
exception or a non-zero exit is recorded and the rest still run, except where a step is a
PRECONDITION of another (a broken chain means no anchor is written over it: the anchor would
vouch for a ledger already known to be wrong). A skipped step says why.

Step statuses: ``ok`` | ``flagged`` (something for a person to read: not a failure) |
``degraded`` (the step could not rely on its inputs) | ``skipped`` | ``failed``.
Cycle exit code mirrors ``watch run``: 0 every step ok or skipped, 1 something is flagged for a
person, 2 anything degraded or failed. Nothing here opens a case, closes anything or decides.
"""

from __future__ import annotations

import contextlib
import io
import json
import re
import shlex
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from assurance.core.identity import format_utc, utc_now
from assurance.core.text import neutralise
from assurance.ops import record as rec
from assurance.ops.config import OpsConfig

__all__ = ["EXIT_BY_STATUS", "plan", "run_cycle"]

EXIT_BY_STATUS = {"ok": 0, "flagged": 1, "degraded": 2}
_TENANT = re.compile(r"^acc_[0-9a-f]{16}\.db$")
_OPERATOR_LEDGER = "art14-register.db"
_MAX_DETAIL = 240
#: Recorded as a step's exit code when its entry point RAISED instead of returning (sysexits
#: EX_SOFTWARE), so a crash is told apart from the verb's own "exit 2".
EXIT_RAISED = 70


def _short(text: object) -> str:
    return neutralise(text)[:_MAX_DETAIL]


def _call(main: Callable[[list[str]], int], argv: list[str]) -> tuple[int, str, str]:
    """Run ``main(argv)`` in-process with its output captured; never raises."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 2
        except Exception as exc:  # noqa: BLE001 - one step's failure must not stop the cycle
            err.write(f"{type(exc).__name__}: {exc}")
            code = EXIT_RAISED
    return int(code), out.getvalue(), err.getvalue()


def _step(name: str, command: str, status: str, exit_code: int | None, started: float,
          detail: str, **info: Any) -> dict[str, Any]:
    return {"name": name, "command": command, "status": status, "exit_code": exit_code,
            "duration_s": round(time.monotonic() - started, 3), "detail": detail,
            **({"info": info} if info else {})}


def _skipped(name: str, command: str, why: str) -> dict[str, Any]:
    return {"name": name, "command": command, "status": "skipped", "exit_code": None,
            "duration_s": 0.0, "detail": why}


def _cmd(*argv: object) -> str:
    return "assurance " + shlex.join(map(str, argv))


def _json(text: str) -> dict[str, Any]:
    try:
        doc = json.loads(text)
    except ValueError:
        return {}
    return doc if isinstance(doc, dict) else {}


def _action(step: str, ref: str, text: str) -> dict[str, str]:
    return {"step": step, "ref": _short(ref), "action": text}


def _ledgers(data_dir: Path) -> list[Path]:
    found: list[Path] = []
    tenants = data_dir / "tenants"
    if tenants.is_dir():
        found += [p for p in sorted(tenants.iterdir())
                  if _TENANT.fullmatch(p.name) and p.is_file() and not p.is_symlink()]
    if (data_dir / _OPERATOR_LEDGER).is_file():
        found.append(data_dir / _OPERATOR_LEDGER)
    return found


# --------------------------------------------------------------------------------------------
# the plan: what a cycle would do, decided without running anything
# --------------------------------------------------------------------------------------------
def _intel_skip_reason(cfg: OpsConfig, live: bool) -> str | None:
    if cfg.intel is None or not cfg.intel.sources:
        return "not refreshed: no intel sources are configured"
    if not cfg.intel.live:
        return "not refreshed: the config says live: false"
    if not live:
        return "not refreshed: --live was not passed"
    return None


def _intel_argv(cfg: OpsConfig, src: Any) -> list[str]:
    assert cfg.intel is not None
    argv = ["intel", "refresh", "--source", src.source, "--store", str(cfg.intel.store),
            "--live", "--timeout", f"{cfg.intel.timeout_s:g}"]
    for cve in src.cves:
        argv += ["--cve", cve]
    if src.api_key_env:
        argv += ["--api-key-env", src.api_key_env]
    return argv


def _watch_argv(w: Any) -> list[str]:
    return ["watch", "run", str(w.config), "--ledger", str(w.ledger), "--json"]


def _anchor_argv(cfg: OpsConfig, *, redact_key: bool) -> list[str]:
    assert cfg.attest is not None
    argv = ["attest", "anchor-all", "--data-dir", str(cfg.data_dir), "--key",
            "<configured key file>" if redact_key else str(cfg.attest.key),
            "--max-age", f"{cfg.attest.max_age_hours:g}", "--json"]
    if cfg.attest.passphrase_env:
        argv += ["--passphrase-env", cfg.attest.passphrase_env]
    return argv


def plan(cfg: OpsConfig, *, live: bool) -> list[dict[str, Any]]:
    """What ``cycle`` would do, in order. Runs nothing, reads nothing, writes nothing."""
    steps: list[dict[str, Any]] = []
    why = _intel_skip_reason(cfg, live)
    if cfg.intel is None or not cfg.intel.sources:
        steps.append(_skipped("intel.refresh", _cmd("intel", "refresh", "..."), why or ""))
    else:
        for src in cfg.intel.sources:
            argv = _intel_argv(cfg, src)
            steps.append(_skipped(f"intel.refresh:{src.source}", _cmd(*argv), why)
                         if why else
                         {"name": f"intel.refresh:{src.source}", "command": _cmd(*argv),
                          "status": "planned", "exit_code": None, "duration_s": 0.0,
                          "detail": "would fetch from the official host"})
    for w in cfg.watch:
        steps.append({"name": f"watch.run:{w.config.name}", "command": _cmd(*_watch_argv(w)),
                      "status": "planned", "exit_code": None, "duration_s": 0.0,
                      "detail": "would run and seal into the configured ledger"})
    steps.append({"name": "ledger.verify",
                  "command": _cmd("art14", "--ledger", "<each ledger>", "verify"),
                  "status": "planned", "exit_code": None, "duration_s": 0.0,
                  "detail": "read-only chain walk of every ledger under the data directory"})
    if cfg.attest is None:
        steps.append(_skipped("attest.anchor_all", _cmd("attest", "anchor-all", "..."),
                              "not anchored: no attest key path is configured"))
    else:
        steps.append({"name": "attest.anchor_all",
                      "command": _cmd(*_anchor_argv(cfg, redact_key=True)),
                      "status": "planned", "exit_code": None, "duration_s": 0.0,
                      "detail": "would anchor if ledger.verify passes"})
    stamp = "<UTC timestamp>"
    steps.append({"name": "backup",
                  "command": f"python -m assurance.evidence.restore_check backup "
                             f"{cfg.data_dir} {cfg.backup_dir / stamp}",
                  "status": "planned", "exit_code": None, "duration_s": 0.0,
                  "detail": "would snapshot into a new directory"})
    steps.append({"name": "backup.verify",
                  "command": f"python -m assurance.evidence.restore_check verify "
                             f"{cfg.backup_dir / stamp}",
                  "status": "planned", "exit_code": None, "duration_s": 0.0,
                  "detail": "would verify that snapshot; failing fails the cycle"})
    return steps


# --------------------------------------------------------------------------------------------
# the steps
# --------------------------------------------------------------------------------------------
def _intel_steps(cfg: OpsConfig, live: bool) -> list[dict[str, Any]]:
    why = _intel_skip_reason(cfg, live)
    if cfg.intel is None or not cfg.intel.sources:
        return [_skipped("intel.refresh", _cmd("intel", "refresh", "..."), why or "")]
    out: list[dict[str, Any]] = []
    from assurance.intel import cli as intel_cli  # lazy: no network client is loaded here

    for src in cfg.intel.sources:
        argv = _intel_argv(cfg, src)
        name = f"intel.refresh:{src.source}"
        if why:
            out.append(_skipped(name, _cmd(*argv), why))
            continue
        t0 = time.monotonic()
        code, stdout, stderr = _call(intel_cli.main, argv[1:])
        rows = [ln.split() for ln in stdout.splitlines() if ln.strip()]
        dispositions: dict[str, int] = {}
        for row in rows:
            for word in row:
                if word in ("first", "changed", "unchanged", "rejected"):
                    dispositions[word] = dispositions.get(word, 0) + 1
        if code == 0:
            out.append(_step(name, _cmd(*argv), "ok", 0, t0,
                             "refreshed: " + (", ".join(f"{k} {v}" for k, v in
                                                        sorted(dispositions.items()))
                                              or "no observations printed"),
                             observations=dispositions))
        elif code == 1:
            out.append(_step(name, _cmd(*argv), "flagged", 1, t0,
                             "an input was rejected and recorded as a rejected observation",
                             observations=dispositions))
        else:
            out.append(_step(name, _cmd(*argv), "failed", code, t0,
                             "could not refresh: " + _short(stderr.strip().splitlines()[-1]
                                                            if stderr.strip() else "no message")))
    return out


def _watch_actions(step: str, doc: dict[str, Any]) -> list[dict[str, str]]:
    actions: list[dict[str, str]] = []
    watch_id = _short(doc.get("watch_id", ""))
    adv = doc.get("advisories") if isinstance(doc.get("advisories"), dict) else {}
    for f in adv.get("findings", []) if isinstance(adv.get("findings"), list) else []:
        if not isinstance(f, dict):
            continue
        ident = str(f.get("advisory_id", ""))
        stops = f.get("severity") == "stop_use" and bool(f.get("machines"))
        if stops:
            actions.append(_action(step, ident, (
                f"STOP-USE advisory {_short(ident)} matched machine(s) in watch {watch_id}: a "
                "named person decides what stops; software has decided nothing")))
        elif f.get("state") in ("new", "updated", "withdrawn", "not_assessed"):
            actions.append(_action(step, ident, (
                f"read {f.get('state')} finding {_short(ident)} (watch {watch_id}); if it "
                "concerns the fleet a named person opens a case with `assurance watch "
                "open-case`. Nothing was opened")))
    for o in doc.get("outcomes", []) if isinstance(doc.get("outcomes"), list) else []:
        if isinstance(o, dict) and o.get("status") in ("changed", "uncollectable"):
            actions.append(_action(step, str(o.get("serial", "")), (
                f"machine {_short(o.get('serial', ''))} is {o.get('status')} in watch "
                f"{watch_id}: review the drift or the collection gap")))
    filings = doc.get("filings") if isinstance(doc.get("filings"), dict) else {}
    for p in filings.get("prompts", []) if isinstance(filings.get("prompts"), list) else []:
        if isinstance(p, dict) and p.get("state") in ("unassessed", "drafted"):
            actions.append(_action(step, str(p.get("advisory_id", "")), (
                f"advisory {_short(p.get('advisory_id', ''))} has no awareness decision "
                f"({p.get('state')}): a person establishes awareness; the Article 14 clock "
                "runs from awareness, not from this report")))
    return actions


def _watch_steps(cfg: OpsConfig) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    steps: list[dict[str, Any]] = []
    actions: list[dict[str, str]] = []
    if not cfg.watch:
        return [_skipped("watch.run", _cmd("watch", "run", "..."),
                         "no watch config is configured")], actions
    from assurance.watch import cli as watch_cli

    for w in cfg.watch:
        argv = _watch_argv(w)
        name = f"watch.run:{w.config.name}"
        t0 = time.monotonic()
        code, stdout, stderr = _call(watch_cli.main, argv[1:])
        doc = _json(stdout)
        verdict = {0: "ok", 1: "flagged", 2: "degraded"}.get(code, "failed")
        if code == 0:
            steps.append(_step(name, _cmd(*argv), "ok", 0, t0, "quiet: nothing moved"))
            continue
        if code in (1, 2) and doc:
            found = _watch_actions(name, doc)
            actions += found
            detail = (f"verdict {_short(doc.get('verdict', '?'))}; "
                      f"{len(found)} action(s) for a person")
            steps.append(_step(name, _cmd(*argv), verdict, code, t0, detail,
                               verdict=_short(doc.get("verdict", ""))))
            if code == 2 and not found:
                actions.append(_action(name, w.config.name, (
                    "the watch was DEGRADED (a source or store could not be relied on, "
                    "including a stale one): read `assurance watch run … --json`, fix it, "
                    "and do not read a quiet result until it passes")))
            elif code == 1 and not found:
                actions.append(_action(name, w.config.name, (
                    "the watch flagged something new or changed: read "
                    "`assurance watch run … --dry-run`")))
            continue
        why = _short(stderr.strip().splitlines()[-1] if stderr.strip() else "no message")
        steps.append(_step(name, _cmd(*argv), "failed" if code not in (1, 2) else verdict,
                           code, t0, f"exit {code}: {why}"))
        actions.append(_action(name, w.config.name,
                               f"watch run could not complete (exit {code}): {why}"))
    return steps, actions


def _chain_step(cfg: OpsConfig) -> dict[str, Any]:
    from assurance.evidence.ledger import EvidenceLedger

    cmd = _cmd("art14", "--ledger", "<each ledger>", "verify")
    t0 = time.monotonic()
    ledgers = _ledgers(cfg.data_dir)
    if not ledgers:
        return _skipped("ledger.verify", cmd, "no ledger under the data directory to verify")
    bad: list[str] = []
    errors: list[str] = []
    for path in ledgers:
        try:
            ok, problems = EvidenceLedger(path, mint_id=False).verify_chain()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{path.name}: {type(exc).__name__}")
            continue
        if not ok:
            bad.append(f"{path.name}: {len(problems)} problem(s)")
    if bad or errors:
        return _step("ledger.verify", cmd, "failed", 1 if bad else 2, t0,
                     f"{len(bad)} ledger(s) failed the chain walk, {len(errors)} could not be "
                     "read", failing=bad[:20], unreadable=errors[:20], checked=len(ledgers))
    return _step("ledger.verify", cmd, "ok", 0, t0,
                 f"{len(ledgers)} ledger chain(s) verify", checked=len(ledgers))


def _anchor_step(cfg: OpsConfig, chain: dict[str, Any]
                 ) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if cfg.attest is None:
        return _skipped("attest.anchor_all", _cmd("attest", "anchor-all", "..."),
                        "not anchored: no attest key path is configured"), []
    shown = _cmd(*_anchor_argv(cfg, redact_key=True))
    if chain["status"] == "failed":
        return _skipped("attest.anchor_all", shown, (
            "not anchored: precondition ledger.verify failed. An anchor over a chain already "
            "known to be broken would vouch for it")), []
    if chain["status"] == "skipped":
        return _skipped("attest.anchor_all", shown, (
            "not anchored: precondition ledger.verify had nothing to verify")), []
    from assurance.attest import cli as attest_cli

    t0 = time.monotonic()
    code, stdout, stderr = _call(attest_cli.main, _anchor_argv(cfg, redact_key=False)[1:])
    doc = _json(stdout)
    summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
    counts = {str(k): v for k, v in summary.items() if isinstance(v, int)}
    if code == 0:
        return _step("attest.anchor_all", shown, "ok", 0, t0,
                     "anchors current: " + (", ".join(f"{k} {v}" for k, v in
                                                      sorted(counts.items())) or "none"),
                     summary=counts, key_fingerprint=_short(doc.get("key_fingerprint", ""))), []
    if code == 1:
        return _step("attest.anchor_all", shown, "flagged", 1, t0,
                     "a ledger was refused or showed an anomaly", summary=counts), [
            _action("attest.anchor_all", "anchor-all", (
                "anchor-all refused a ledger or reported an anomaly: run "
                "`assurance attest anchor-all --data-dir … --key … --dry-run` and read the "
                "rows"))]
    why = _short(stderr.strip().splitlines()[-1] if stderr.strip() else "no message")
    return _step("attest.anchor_all", shown, "failed", code, t0,
                 f"could not anchor (exit {code}): {why}"), [
        _action("attest.anchor_all", "anchor-all",
                f"anchoring failed (exit {code}): {why}. Check the key file and its mode with "
                "`ops check`")]


def _backup_steps(cfg: OpsConfig, chain: dict[str, Any], now: datetime
                  ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    from assurance.evidence import restore_check

    actions: list[dict[str, str]] = []
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    target = cfg.backup_dir / stamp
    n = 1
    while target.exists():
        n += 1
        target = cfg.backup_dir / f"{stamp}-{n}"
    cmd_b = f"python -m assurance.evidence.restore_check backup {cfg.data_dir} {target}"
    cmd_v = f"python -m assurance.evidence.restore_check verify {target}"
    t0 = time.monotonic()
    try:
        cfg.backup_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return [_step("backup", cmd_b, "failed", 2, t0, f"backup directory: {type(exc).__name__}"),
                _skipped("backup.verify", cmd_v, "no backup was taken")], [
            _action("backup", str(cfg.backup_dir), "no backup was taken this cycle: the backup "
                    "directory cannot be created")]
    code, stdout, stderr = _call(restore_check.main, ["backup", str(cfg.data_dir), str(target)])
    doc = _json(stdout)
    manifest_sha = _short(doc.get("manifest_sha256", ""))
    if code == 2 or (code not in (0, 1)):
        why = _short(stderr.strip().splitlines()[-1] if stderr.strip() else "no message")
        steps = [_step("backup", cmd_b, "failed", code, t0, f"no backup taken: {why}"),
                 _skipped("backup.verify", cmd_v, "no backup was taken")]
        return steps, [_action("backup", str(target), f"no backup was taken this cycle: {why}")]
    degraded = code == 1
    backup = _step(
        "backup", cmd_b, "flagged" if degraded else "ok", code, t0,
        ("snapshot kept, but the SOURCE already fails a check (degraded: true)" if degraded
         else "snapshot taken"),
        directory=str(target), manifest_sha256=manifest_sha,
        files=len(doc.get("backed_up", [])) if isinstance(doc.get("backed_up"), list) else 0)
    if degraded:
        actions.append(_action("backup", str(target), (
            "the backup was taken from a source that already fails a check: investigate the "
            "ledger before relying on any backup of it (OPS.md, incidents)")))
    t1 = time.monotonic()
    vcode, vout, verr = _call(restore_check.main, ["verify", str(target)])
    vdoc = _json(vout)
    problems = vdoc.get("problems") if isinstance(vdoc.get("problems"), list) else []
    if vcode == 0:
        verify = _step("backup.verify", cmd_v, "ok", 0, t1,
                       f"backup verifies ({vdoc.get('checked', '?')} check(s))",
                       directory=str(target), manifest_sha256=manifest_sha)
    else:
        explained = degraded and chain["status"] == "failed" and vcode == 1
        text = (f"verify exit {vcode}: " + (f"{len(problems)} problem(s); first: "
                                            f"{_short(problems[0])}" if problems else
                                            _short(verr.strip() or "unchecked")))
        verify = _step("backup.verify", cmd_v, "flagged" if explained else "failed", vcode, t1,
                       text + (" (expected: the source chain failed, see ledger.verify)"
                               if explained else ""),
                       directory=str(target), problems=len(problems))
        if not explained:
            actions.append(_action("backup.verify", str(target), (
                "the backup just taken does NOT verify: treat this backup as unusable and "
                "investigate before the next cycle (a backup that does not verify is not a "
                "backup)")))
    return [backup, verify], actions


# --------------------------------------------------------------------------------------------
def _overall(steps: list[dict[str, Any]]) -> str:
    statuses = {s["status"] for s in steps}
    if statuses & {"failed", "degraded"}:
        return "degraded"
    return "flagged" if "flagged" in statuses else "ok"


def run_cycle(cfg: OpsConfig, *, live: bool) -> dict[str, Any]:
    """Run one cycle and return its record (not yet written). Never raises for a step."""
    started = utc_now()
    t_all = time.monotonic()
    secrets = rec.secrets_for(cfg.secret_env_names(),
                              [cfg.attest.key] if cfg.attest else [])
    steps: list[dict[str, Any]] = []
    actions: list[dict[str, str]] = []

    steps += _intel_steps(cfg, live)
    w_steps, w_actions = _watch_steps(cfg)
    steps += w_steps
    actions += w_actions
    chain = _chain_step(cfg)
    steps.append(chain)
    if chain["status"] == "failed":
        actions.append(_action("ledger.verify", "chain", (
            "a ledger chain does NOT verify or could not be read: do not anchor or rely on it; "
            "follow OPS.md, incident 'chain verify fails'")))
    anchor, a_actions = _anchor_step(cfg, chain)
    steps.append(anchor)
    actions += a_actions
    b_steps, b_actions = _backup_steps(cfg, chain, started)
    steps += b_steps
    actions += b_actions

    for s in steps:
        if s["status"] in ("failed", "degraded") and not any(a["step"] == s["name"]
                                                             for a in actions):
            actions.append(_action(s["name"], s["name"], (
                f"{s['name']} {s['status']}: {s['detail']}")))

    status = _overall(steps)
    finished = utc_now()
    record = {
        "format": rec.FORMAT, "ops_id": cfg.ops_id,
        "started_at": format_utc(started), "finished_at": format_utc(finished),
        "duration_s": round(time.monotonic() - t_all, 3),
        "live_requested": live, "status": status, "exit_code": EXIT_BY_STATUS[status],
        "steps": steps, "human_actions": actions,
        "not_established": ("This record is an operator log: it is not signed or chained. A "
                            "skipped step did not run; ok means the step's own exit code was 0, "
                            "not that the machine is safe."),
    }
    return rec.scrub(record, secrets)
