#!/usr/bin/env python3
"""Scale benchmark for the assurance ledger and fleet paths.

Measures wall time, peak RSS and database size for the operations a fleet customer runs, at
several fleet sizes (N machines) and ledger sizes (entries), on THIS machine, with SYNTHETIC
data, no network and throwaway temp directories. It prints a table and writes JSON.

    PYTHONPATH=src python scripts/bench_scale.py --out /var/tmp/scale/baseline.json
    PYTHONPATH=src python scripts/bench_scale.py --sizes 100,500 --ledger-sizes 1000 --only fleet_reads

What this is: a measurement of one run on one machine. What it is not: a capacity guarantee, a
concurrency test, a network-latency test, or a claim about any other hardware. Every case runs
in a fresh child process so that its peak RSS (read from ``wait4``'s rusage) is its own.
Peak RSS includes the case's own fixture set-up (copying a database file, opening it), not
the building of the fixture, which is cached from an earlier case.

stdlib only for the harness; the cases import the product from ``PYTHONPATH``. Nothing here opens
a socket (the API cases use an in-process ASGI test client).
"""
# ruff: noqa: T201, S603  (a benchmark prints, and runs this interpreter on itself)
from __future__ import annotations

import argparse
import contextlib
import csv
import io
import json
import math
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MAPPING = {
    "source_system": "bench-synthetic", "export_date": "2026-10-15",
    "columns": {"manufacturer": "Hersteller", "model": "Typ", "serial": "Seriennr",
                "site": "Standort", "owner": "Eigentuemer", "year": "Baujahr", "country": "Land"},
    "items": [
        {"name_column": "SPS Firmware", "version_column": "SPS Version",
         "sha256_column": "SPS SHA256", "supplier": "ControlCo", "kind": "firmware",
         "implements": ["SF-01"]},
        {"name": "Safety scanner zone set", "version_column": "Scanner Version",
         "kind": "safety_configuration", "implements": ["SF-01"]}],
    "functions": [{"function_id": "SF-01", "description": "Protective stop on zone intrusion",
                   "required_performance": "PL d",
                   "verified_by": ["ssm_separation", "stop_characterisation"]}],
}
HEADER = ["Hersteller", "Typ", "Seriennr", "Standort", "Eigentuemer", "Baujahr", "Land",
          "SPS Firmware", "SPS Version", "SPS SHA256", "Scanner Version"]
SHA = "1" * 64
ACTOR = "a.integrator"


# ---------------------------------------------------------------------------------- data

def inventory_rows(n: int, start: int = 0) -> list[list[str]]:
    return [["Grimaldi", "AR-7", f"S{i:06d}", f"Plant {i % 20}", "Example GmbH", "2021", "DE",
             "Safety controller firmware", "3.8.2", SHA, "r4"] for i in range(start, start + n)]


def canonical_rows(n: int, start: int = 0) -> list[dict[str, Any]]:
    return [{"manufacturer": "Grimaldi", "model": "AR-7", "serial": f"S{i:06d}",
             "site": f"Plant {i % 20}", "owner": "Example GmbH", "year": "2021", "country": "DE",
             "items": [{"name": "Safety controller firmware", "version": "3.8.2", "sha256": SHA,
                        "supplier": "ControlCo", "implements": ["SF-01"]},
                       {"name": "Scanner zones", "version": "r4", "kind": "safety_configuration",
                        "implements": ["SF-01"]}]} for i in range(start, start + n)]


def write_inventory(dirpath: Path, n: int) -> tuple[Path, Path]:
    f, m = dirpath / f"inv_{n}.csv", dirpath / "mapping.json"
    with f.open("w", newline="", encoding="utf-8") as h:
        w = csv.writer(h, lineterminator="\r\n")
        w.writerow(HEADER)
        w.writerows(inventory_rows(n))
    m.write_text(json.dumps(MAPPING), "utf-8")
    return f, m


def copy_db(src: Path, dst: Path) -> Path:
    shutil.copyfile(src, dst)
    for sfx in ("-wal", "-shm"):
        side = src.with_name(src.name + sfx)
        if side.is_file():
            shutil.copyfile(side, dst.with_name(dst.name + sfx))
    return dst


def db_bytes(p: Path) -> int:
    return sum(q.stat().st_size for q in (p, p.with_name(p.name + "-wal")) if q.is_file())


def checkpoint(p: Path) -> None:
    import sqlite3
    db = sqlite3.connect(p)
    try:
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        db.close()
    for sfx in ("-wal", "-shm"):
        with contextlib.suppress(OSError):
            p.with_name(p.name + sfx).unlink()


def cli(argv: list[str]) -> tuple[int, float]:
    """Run ``python -m assurance <argv>`` in this process, output discarded. (code, seconds)."""
    from assurance.cli import main
    buf_out, buf_err = io.StringIO(), io.StringIO()
    t = time.perf_counter()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        try:
            code = main(argv)
        except SystemExit as exc:
            code = int(exc.code or 0) if isinstance(exc.code, int) or exc.code is None else 1
    return int(code or 0), time.perf_counter() - t


def timed(fn):
    t = time.perf_counter()
    out = fn()
    return out, time.perf_counter() - t


# ---------------------------------------------------------------------------------- cases
# Each case: (work: Path, params: dict) -> {"metrics": {name: seconds}, "notes": {...}}.
# Fixtures cached in `work`:  ledger_<n>.db (n synthetic entries), fleet_<N>.db (N machines).

def case_ledger(work: Path, p: dict) -> dict:
    from assurance.core.evidence import Actor, Evidence, Origin
    from assurance.evidence.ledger import EvidenceLedger
    n = p["entries"]
    path = work / f"ledger_{n}.db"
    path.unlink(missing_ok=True)
    led = EvidenceLedger(path)
    actor, origin = Actor("bench.writer", "benchmark"), Origin("bench")
    t = time.perf_counter()
    for i in range(n):
        ev = Evidence(kind="bench.record", body={"n": i, "pad": "x" * 120}, actor=actor,
                      origin=origin).seal()
        led.append(ev, subject=f"SUBJ-{i % 100}")
    append_s = time.perf_counter() - t
    m = {"append_total_s": append_s}
    (ok, _), m["verify_chain_s"] = timed(led.verify_chain)
    _, m["export_s"] = timed(led.export)
    _, m["verify_report_s"] = timed(led.verify_report)
    _, m["entries_all_s"] = timed(led.entries)
    notes = {"appends_per_s": n / append_s, "chain_ok": ok}
    checkpoint(path)
    notes["db_bytes"] = db_bytes(path)
    return {"metrics": m, "notes": notes}


def _enrol_manifest(serial: str):
    from assurance.core.evidence import Actor
    from assurance.machinery import inventory as inv
    row = inv.canonical_row(canonical_rows(1, 0)[0] | {"serial": serial}, 1,
                            frozenset({"SF-01"}))
    fns = (inv.FunctionDecl("SF-01", "Protective stop", "PL d", ("ssm_separation",)),)
    return inv._manifest_for(row, actor=Actor(ACTOR, "engineer", "person"),
                             source_system="bench", export_date=None, file_sha256="",
                             functions=fns)


def case_enrol_at(work: Path, p: dict) -> dict:
    from assurance.core.evidence import Actor
    from assurance.evidence.ledger import EvidenceLedger
    from assurance.machinery.enrol import enrol_machine
    n = p["entries"]
    src = work / f"ledger_{n}.db"
    led = EvidenceLedger(copy_db(src, work / f"enrol_{n}.db"))
    who = Actor(ACTOR, "engineer", "person")
    times = []
    for k in range(3):
        mf = _enrol_manifest(f"E{k:05d}")
        r, dt = timed(lambda mf=mf: enrol_machine(led, mf, actor=who))
        assert r.status == "enrolled", r.status
        times.append(dt)
    _, again = timed(lambda: enrol_machine(led, _enrol_manifest("E00000"), actor=who))
    return {"metrics": {"enrol_one_s": sum(times) / len(times), "enrol_again_s": again},
            "notes": {"db_bytes": db_bytes(led.path)}}


def case_import_cli(work: Path, p: dict) -> dict:
    n = p["machines"]
    d = work / f"imp_cli_{n}"
    d.mkdir(exist_ok=True)
    f, m = write_inventory(d, n)
    led = work / f"fleet_{n}.db"
    led.unlink(missing_ok=True)
    code, dt = cli(["machinery", "import-inventory", str(f), "--mapping", str(m),
                    "--ledger", str(led), "--actor", ACTOR, "--max-rows", str(n)])
    assert code == 0, code
    checkpoint(led)
    return {"metrics": {"import_cli_s": dt}, "notes": {"db_bytes": db_bytes(led), "exit": code}}


def _api_env(tmp: Path, ledger: Path | None):
    from fastapi.testclient import TestClient
    os.environ["ASSURANCE_LEDGER"] = str(tmp / "l.db")
    os.environ["ASSURANCE_ACCOUNTS"] = str(tmp / "a.db")
    os.environ.pop("ASSURANCE_API_KEYS", None)
    os.environ.pop("ASSURANCE_ALLOW_UNAUTHENTICATED", None)
    os.environ.pop("ASSURANCE_TENANT_LEDGERS", None)
    from assurance.api import deps
    from assurance.api.service import create_app
    deps._register_for.cache_clear()
    deps._accounts_for.cache_clear()
    client = TestClient(create_app())
    client.__enter__()
    store = deps.get_accounts()
    acct = store.upsert_account(email="bench@example.invalid", tier="cell")
    tenant = tmp / "tenants" / f"{acct.id}.db"      # a customer account has its own ledger file
    tenant.parent.mkdir(parents=True, exist_ok=True)
    if ledger is not None:
        copy_db(ledger, tenant)
    return client, {"X-API-Key": store.issue_key(acct.id)}, tenant


def case_import_api(work: Path, p: dict) -> dict:
    n = p["machines"]
    tmp = work / f"api_imp_{n}"
    tmp.mkdir(exist_ok=True)
    client, h, tenant = _api_env(tmp, None)
    body = {"source_system": "bench", "actor": ACTOR, "export_date": "2026-10-15",
            "functions": MAPPING["functions"]}
    t = time.perf_counter()
    done = reqs = 0
    while done < n:
        k = min(200, n - done)
        r = client.post("/v1/machinery/enrol/batch", headers=h,
                        json={**body, "rows": canonical_rows(k, done)})
        assert r.status_code == 200, r.text[:200]
        assert r.json()["counts"]["enrolled"] == k, r.json()["counts"]
        done += k
        reqs += 1
    dt = time.perf_counter() - t
    return {"metrics": {"import_api_s": dt}, "notes": {"requests": reqs,
            "db_bytes": db_bytes(tenant)}}


def case_fleet_reads(work: Path, p: dict) -> dict:
    n = p["machines"]
    src = work / f"fleet_{n}.db"
    d = work / f"reads_{n}"
    d.mkdir(exist_ok=True)
    led = copy_db(src, d / "f.db")
    m: dict[str, float] = {}
    # one machine's manifest, for `machinery coverage`
    manifest = _enrol_manifest(f"S{n // 2:06d}")
    mf = d / "m.json"
    mf.write_text(json.dumps(manifest.to_dict()), "utf-8")
    for name, argv in (
        ("fleet_list_cli_s", ["fleet", "list", "--ledger", str(led), "--json"]),
        ("fleet_report_cli_s", ["report", "build", "--ledger", str(led), "--out",
                                str(d / "r.html")]),
        ("coverage_one_cli_s", ["machinery", "coverage", str(mf), "--ledger", str(led),
                                "--json"]),
        ("change_list_cli_s", ["change", "list", "--ledger", str(led), "--json"]),
    ):
        _, m[name] = cli(argv)
    client, h, _ = _api_env(d, src)
    for name, url in (("fleet_list_api_s", "/v1/fleet/machines"),
                      ("fleet_report_api_s", "/v1/fleet/report"),
                      ("change_list_api_s", "/v1/change/cases")):
        r, m[name] = timed(lambda url=url: client.get(url, headers=h))
        assert r.status_code == 200, (url, r.status_code, r.text[:200])
    return {"metrics": m, "notes": {"db_bytes": db_bytes(src)}}


def case_watch(work: Path, p: dict) -> dict:
    sys.path.insert(0, str(ROOT))
    from tests.support import plan_dict, write_export
    n = p["machines"]
    d = work / f"watch_{n}"
    shutil.rmtree(d, ignore_errors=True)
    d.mkdir()
    (d / "plan.json").write_text(json.dumps(plan_dict()))
    write_export(d / "tmpl", stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    targets = []
    for i in range(n):
        shutil.copytree(d / "tmpl", d / f"x{i}")
        targets.append({"serial": f"W{i:05d}", "plan": "plan.json", "root": f"x{i}",
                        "site": f"Plant {i % 20}", "country": "DE", "read_from_machine": True})
    (d / "watch.json").write_text(json.dumps(
        {"watch_id": "WATCH-BENCH", "max_age_hours": 168, "targets": targets}))
    led = d / "ev.db"
    code, dt = cli(["watch", "run", str(d / "watch.json"), "--ledger", str(led), "--dry-run",
                    "--json"])
    return {"metrics": {"watch_run_dry_s": dt}, "notes": {"exit": code, "targets": n}}


def case_intel(work: Path, p: dict) -> dict:
    fx = ROOT / "tests" / "fixtures" / "intel"
    store = work / f"intel_{p['reps']}.db"
    store.unlink(missing_ok=True)
    args = ["intel", "ingest", "--store", str(store), "--allow-interim"]
    for flag, name in (("--nvd", "nvd_synthetic.json"), ("--kev", "kev_min.json"),
                       ("--epss", "epss_min.json"), ("--csaf", "csaf_synthetic.json")):
        args += [flag, str(fx / name)]
    t = time.perf_counter()
    for _ in range(p["reps"]):
        code, _ = cli(args)
    ingest_s = time.perf_counter() - t
    from assurance.intel.store import IntelStore
    nobs = len(IntelStore(store).observations())
    _, cand = cli(["intel", "candidates", "--store", str(store), "--json"])
    _, hist = cli(["intel", "history", "--store", str(store), "--json"])
    return {"metrics": {"intel_ingest_total_s": ingest_s, "intel_candidates_s": cand,
                        "intel_history_s": hist},
            "notes": {"observations": nobs, "ingest_exit": code, "db_bytes": db_bytes(store)}}


def case_ops(work: Path, p: dict) -> dict:
    from assurance.attest import SigningKey
    from assurance.billing.accounts import AccountStore
    n = p["machines"]
    d = work / f"ops_{n}"
    shutil.rmtree(d, ignore_errors=True)
    (d / "data" / "tenants").mkdir(parents=True)
    store = AccountStore(d / "data" / "accounts.db")
    acct = store.upsert_account(email="ops@example.invalid", tier="cell",
                                stripe_customer_id="cus_bench").id
    copy_db(work / f"fleet_{n}.db", d / "data" / "tenants" / f"{acct}.db")
    from assurance.evidence.ledger import EvidenceLedger
    EvidenceLedger(d / "data" / "art14-register.db")
    key = d / "service.pem"
    SigningKey.generate().save(key)
    cfg = {"ops_id": "bench-ops", "data_dir": "data", "record": "ops/cycles.jsonl",
           "backup_dir": "backups", "min_free_disk_mb": 0, "attest": {"key": str(key)}}
    (d / "ops.json").write_text(json.dumps(cfg))
    code, dt = cli(["ops", "cycle", "--config", str(d / "ops.json"), "--json"])
    return {"metrics": {"ops_cycle_s": dt}, "notes": {"exit": code}}


def case_tenant_export(work: Path, p: dict) -> dict:
    from assurance.billing.accounts import AccountStore
    n = p["entries"]
    d = work / f"tenant_{n}"
    shutil.rmtree(d, ignore_errors=True)
    (d / "data" / "tenants").mkdir(parents=True)
    store = AccountStore(d / "data" / "accounts.db")
    acct = store.upsert_account(email="t@example.invalid", tier="cell",
                                stripe_customer_id="cus_bench").id
    copy_db(work / f"ledger_{n}.db", d / "data" / "tenants" / f"{acct}.db")
    code, dt = cli(["tenant", "export", "--data-dir", str(d / "data"), "--account", acct,
                    "--out", str(d / "out"), "--actor", ACTOR])
    size = sum(f.stat().st_size for f in (d / "out").rglob("*") if f.is_file()) \
        if (d / "out").is_dir() else 0
    return {"metrics": {"tenant_export_s": dt}, "notes": {"exit": code, "export_bytes": size}}


CASES = {"ledger": case_ledger, "enrol_at": case_enrol_at, "import_cli": case_import_cli,
         "import_api": case_import_api, "fleet_reads": case_fleet_reads, "watch": case_watch,
         "intel": case_intel, "ops": case_ops, "tenant_export": case_tenant_export}


# ---------------------------------------------------------------------------------- driver

def run_child(case: str, params: dict, work: Path, timeout: float) -> dict:
    out = work / f"result_{case}_{abs(hash(json.dumps(params, sort_keys=True)))}.json"
    argv = [sys.executable, "-B", str(Path(__file__).resolve()), "--child", case,
            "--params", json.dumps(params), "--workdir", str(work), "--result", str(out)]
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    env.setdefault("PYTHONPATH", str(ROOT / "src"))
    t0 = time.perf_counter()
    proc = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        _, status, ru = os.wait4(proc.pid, 0)
    except KeyboardInterrupt:
        proc.kill()
        raise
    proc.returncode = os.waitstatus_to_exitcode(status)
    err = proc.stderr.read().decode("utf-8", "replace")[-600:] if proc.stderr else ""
    wall = time.perf_counter() - t0
    if proc.returncode != 0 or not out.is_file():
        return {"case": case, "params": params, "error": f"exit {proc.returncode}: {err}",
                "wall_s": wall}
    res = json.loads(out.read_text("utf-8"))
    out.unlink()
    res.update(case=case, params=params, peak_rss_mb=ru.ru_maxrss / 1024.0, wall_s=wall,
               cpu_s=ru.ru_utime + ru.ru_stime,
               load1=os.getloadavg()[0])
    return res


def fit_exponent(xs: list[float], ys: list[float]) -> float | None:
    pts = [(math.log(x), math.log(y)) for x, y in zip(xs, ys, strict=False) if x > 0 and y > 0]
    if len(pts) < 2:
        return None
    mx = sum(a for a, _ in pts) / len(pts)
    my = sum(b for _, b in pts) / len(pts)
    den = sum((a - mx) ** 2 for a, _ in pts)
    return sum((a - mx) * (b - my) for a, b in pts) / den if den else None


def machine_model() -> dict[str, Any]:
    model = ""
    with contextlib.suppress(OSError):
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    mem = ""
    with contextlib.suppress(OSError):
        mem = Path("/proc/meminfo").read_text().splitlines()[0].split(":", 1)[1].strip()
    return {"cpu_count": os.cpu_count(), "cpu_model": model, "mem_total": mem,
            "python": platform.python_version(), "platform": platform.platform(),
            "disk_type": "unknown (not probed)", "date": time.strftime("%Y-%m-%d")}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", type=Path, help="write the JSON result here")
    ap.add_argument("--sizes", default="100,500,2000", help="fleet sizes N (machines)")
    ap.add_argument("--ledger-sizes", default="1000,10000,50000", help="ledger entry counts")
    ap.add_argument("--only", default="", help="comma list of cases to run: " + ",".join(CASES))
    ap.add_argument("--workdir", type=Path, default=None,
                    help="throwaway directory (default: a fresh temp dir, removed afterwards)")
    ap.add_argument("--timeout", type=float, default=3600.0)
    ap.add_argument("--intel-reps", type=int, default=750)
    ap.add_argument("--child"), ap.add_argument("--params"), ap.add_argument("--result")
    a = ap.parse_args()

    if a.child:
        work = a.workdir
        res = CASES[a.child](work, json.loads(a.params))
        Path(a.result).write_text(json.dumps(res), "utf-8")
        return 0

    sizes = [int(s) for s in a.sizes.split(",") if s]
    lsizes = [int(s) for s in a.ledger_sizes.split(",") if s]
    only = {s for s in a.only.split(",") if s}
    want = lambda c: not only or c in only  # noqa: E731
    cleanup = a.workdir is None
    work = a.workdir or Path(tempfile.mkdtemp(prefix="nb-scale-"))   # honours $TMPDIR
    work.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []

    def go(case: str, **params: Any) -> None:
        print(f"  running {case} {params} ...", flush=True)
        r = run_child(case, params, work, a.timeout)
        results.append(r)
        if "error" in r:
            print(f"    FAILED: {r['error']}", flush=True)

    try:
        # fixtures first, in dependency order
        for n in lsizes:
            if want("ledger") or want("enrol_at") or want("tenant_export"):
                go("ledger", entries=n)
        for n in lsizes:
            if want("enrol_at"):
                go("enrol_at", entries=n)
        for n in sizes:
            if any(want(c) for c in ("import_cli", "fleet_reads", "ops")):
                go("import_cli", machines=n)
        for n in sizes:
            if want("import_api"):
                go("import_api", machines=n)
        for n in sizes:
            if want("fleet_reads"):
                go("fleet_reads", machines=n)
        for n in sizes:
            if want("watch"):
                go("watch", machines=n)
        for n in sizes:
            if want("ops"):
                go("ops", machines=n)
        if want("intel"):
            go("intel", reps=a.intel_reps)
        if want("tenant_export") and 10000 in lsizes:
            go("tenant_export", entries=10000)

        doc = {"machine": machine_model(), "sizes": sizes, "ledger_sizes": lsizes,
               "results": results, "exponents": {}}
        series: dict[str, list[tuple[int, float]]] = {}
        for r in results:
            if "error" in r:
                continue
            x = r["params"].get("machines") or r["params"].get("entries")
            if not x:
                continue
            for k, v in r["metrics"].items():
                series.setdefault(k, []).append((x, v))
        for k, pts in sorted(series.items()):
            if len(pts) >= 3:
                pts.sort()
                doc["exponents"][k] = fit_exponent([x for x, _ in pts], [y for _, y in pts])
        print_table(doc)
        if a.out:
            a.out.parent.mkdir(parents=True, exist_ok=True)
            a.out.write_text(json.dumps(doc, indent=2, sort_keys=True), "utf-8")
            print(f"\nwrote {a.out}")
        return 0 if all("error" not in r for r in results) else 1
    finally:
        if cleanup:
            shutil.rmtree(work, ignore_errors=True)


def print_table(doc: dict) -> None:
    mm = doc["machine"]
    print(f"\nmachine: {mm['cpu_count']} cpu ({mm['cpu_model']}), {mm['mem_total']} mem, "
          f"python {mm['python']}, disk {mm['disk_type']}")
    print("(other processes share this machine; load1 is the 1-minute load average when each "
          "case ended; case cpu s is user+sys of the whole case process, set-up included)")
    print(f"{'metric':<26} {'size':>7} {'seconds':>10} {'peak MB':>9} {'db MB':>8} {'load1':>6} "
          f"{'case cpu s':>10}")
    print("-" * 82)
    for r in doc["results"]:
        x = r["params"].get("machines") or r["params"].get("entries") or r["params"].get("reps")
        if "error" in r:
            print(f"{r['case']:<26} {x!s:>7} FAILED {r['error'][:60]}")
            continue
        dbm = r["notes"].get("db_bytes")
        for k, v in r["metrics"].items():
            print(f"{k:<26} {x!s:>7} {v:>10.3f} {r['peak_rss_mb']:>9.0f} "
                  f"{(dbm / 1e6 if dbm else 0):>8.1f} {r.get('load1', 0):>6.1f} "
                  f"{r.get('cpu_s', 0):>10.1f}")
    print("\nlog-log slope of time against size, where three sizes were run "
          "(1.0 = linear, 2.0 = quadratic):")
    for k, e in doc["exponents"].items():
        print(f"  {k:<26} {e:>6.2f}" if e is not None else f"  {k:<26}    n/a")


if __name__ == "__main__":
    sys.exit(main())
