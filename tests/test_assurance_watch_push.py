"""``assurance watch push``: opt-in, explicit, honest, and separate from the offline path.

Runs the real Watch over synthetic vendor exports into a *local* plant ledger,
then pushes the sealed result to a real in-process API (the same app, accounts
and per-account ledgers the production routes use). The properties pinned:

* the offline kit and ``watch run`` do not import the push module or any HTTP
  client, and ``watch run`` leaves it unloaded at run time;
* nothing is sent without an explicit ``--api-url`` and a key in an environment
  variable; ``--dry-run`` opens no socket and shows exactly what would go;
* raw files, local paths and failure reasons never leave;
* a machine that could not be collected arrives as exactly that;
* a timeout after the server processed the report is retried and duplicates
  nothing; a redirect is never followed.
"""

from __future__ import annotations

import ast
import json
import shutil
import socket
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from assurance.change import CaseStore
from assurance.evidence.ledger import EvidenceLedger
from assurance.watch import push
from assurance.watch.cli import main as watch_main
from assurance.watch.config import WatchConfig
from assurance.watch.runner import run_watch

from .support import plan_dict, write_export
from .test_assurance_watch_report import (  # noqa: F401  (fixtures: env, client, accounts, cell)
    KEY_0412,
    KEY_0501,
    _accounts,
    _cell,
    _client,
    _env,
    account,
    ledger_of,
    machine_row,
    observations,
)

SRC = Path(__file__).resolve().parents[1] / "src"
SERIALS = ("0412", "0501", "0602")
SECRET_MARK = "radius_mm"          # a string that exists only inside a raw export file


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


# -- the local plant -------------------------------------------------------------

@pytest.fixture(name="plant")
def _plant(tmp_path):
    root = tmp_path / "plant"
    root.mkdir()
    (root / "plan.json").write_text(json.dumps(plan_dict()))
    for serial in SERIALS:
        write_export(root / serial, stamp="2026-09-14T06:00:00Z", operator="m.tech", seq="4181")
    (root / "watch.json").write_text(json.dumps({
        "watch_id": "WATCH-PUSH", "max_age_hours": 168,
        "targets": [{"serial": s, "plan": "plan.json", "root": s, "site": "Plant 2",
                     "country": "DE"} for s in SERIALS],
    }))
    return root


@pytest.fixture(name="config")
def _config(plant):
    return WatchConfig.from_json(plant / "watch.json")


@pytest.fixture(name="local")
def _local(plant):
    return EvidenceLedger(plant / "register.db")


def reflash(plant, serial):
    shutil.rmtree(plant / serial)
    write_export(plant / serial, stamp="2026-10-18T06:12:41Z", operator="a.integrator",
                 seq="4199", fw=b"firmware 3.9.0")


class Recorder:
    """Stands in for httpx.Client: records every request, forwards to the real app."""

    def __init__(self, inner, *, fail=None):
        self.inner, self.requests, self.fail = inner, [], fail
        self.calls = 0

    def post(self, url, content, headers):
        self.requests.append((url, content, dict(headers)))
        self.calls += 1
        if self.fail:
            outcome = self.fail(self.calls, lambda: self.inner.post(url, content=content,
                                                                   headers=headers))
            if outcome is not None:
                return outcome
        return self.inner.post(url, content=content, headers=headers)


@pytest.fixture()
def hosted_key(cell, monkeypatch):
    key = cell[1]["X-API-Key"]
    monkeypatch.setenv("NB_ASSURANCE_KEY", key)
    return key


def cli(capsys, plant, key, *extra, api_url="http://127.0.0.1:18080", env_name="NB_ASSURANCE_KEY"):
    argv = ["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
            "--api-url", api_url, "--key-env", env_name, "--retry-wait", "0", *extra]
    code = watch_main(argv)
    out, err = capsys.readouterr()
    # Whatever happened, the key is nowhere in what the operator saw.
    assert key not in out and key not in err
    return code, out, err


def use(monkeypatch, recorder):
    monkeypatch.setattr(push, "make_client", lambda timeout: recorder)
    return recorder


# =====================================================================
# the offline path stays offline
# =====================================================================

OFFLINE_ROOTS = ("assurance.kit", "assurance.collect", "assurance.watch.runner",
                 "assurance.watch.config", "assurance.watch.advisories",
                 "assurance.watch.filings", "assurance.watch.observations")


def _module_file(name: str) -> Path | None:
    path = SRC / Path(*name.split("."))
    if path.with_suffix(".py").is_file():
        return path.with_suffix(".py")
    if (path / "__init__.py").is_file():
        return path / "__init__.py"
    return None


def _imports(path: Path, *, top_level_only: bool) -> set[str]:
    """Every module a file imports. ``top_level_only`` skips imports inside functions."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    pkg = path.relative_to(SRC).with_suffix("").parts[:-1] if SRC in path.parents else ()
    found: set[str] = set()

    def walk(node: ast.AST, in_function: bool) -> None:
        for child in ast.iter_child_nodes(node):
            inside = in_function or isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda))
            if not (top_level_only and in_function):
                if isinstance(child, ast.Import):
                    found.update(a.name for a in child.names)
                elif isinstance(child, ast.ImportFrom):
                    base = child.module or ""
                    if child.level:
                        anchor = list(pkg[: len(pkg) - (child.level - 1)])
                        base = ".".join([*anchor, *([base] if base else [])])
                    found.add(base)
                    found.update(f"{base}.{a.name}" for a in child.names)
            walk(child, inside)

    walk(tree, False)
    return found


def _closure(roots, *, top_level_only: bool) -> set[str]:
    seen: set[str] = set()
    todo = []
    for root in roots:
        # every module under a root package
        path = SRC / Path(*root.split("."))
        files = sorted(path.rglob("*.py")) if path.is_dir() else [path.with_suffix(".py")]
        todo.extend(f for f in files if f.is_file())
    done: set[Path] = set()
    while todo:
        file = todo.pop()
        if file in done:
            continue
        done.add(file)
        for name in _imports(file, top_level_only=top_level_only):
            seen.add(name)
            if name.startswith("assurance"):
                target = _module_file(name)
                if target is not None:
                    todo.append(target)
                    # importing a.b.c also runs a/__init__ and a/b/__init__
                    parts = name.split(".")
                    for i in range(1, len(parts)):
                        init = _module_file(".".join(parts[:i]))
                        if init is not None:
                            todo.append(init)
    return seen


class TestTheOfflinePathStaysOffline:
    def test_the_push_module_exists_and_is_reachable_from_no_offline_module(self):
        assert (SRC / "assurance/watch/push.py").is_file()
        reachable = _closure(OFFLINE_ROOTS, top_level_only=False)
        assert "assurance.watch.push" not in reachable
        assert not any(name.startswith("assurance.watch.push") for name in reachable)
        # And not the ingest/api side either: nothing offline needs the server's code.
        assert "assurance.watch.ingest" not in reachable
        assert not any(n.startswith("assurance.api") for n in reachable)

    def test_no_http_client_is_imported_at_module_level_by_the_offline_path(self):
        reachable = _closure(OFFLINE_ROOTS, top_level_only=True)
        leaked = sorted(n for n in reachable
                        if n.split(".")[0] in {"httpx", "requests", "urllib3", "aiohttp"}
                        or n in {"http.client", "urllib.request"})
        assert leaked == []

    def test_the_push_module_itself_imports_httpx_lazily(self):
        assert not any(n.split(".")[0] == "httpx"
                       for n in _imports(SRC / "assurance/watch/push.py", top_level_only=True))

    def test_the_import_graph_walker_would_notice_a_leak(self, tmp_path):
        """The check above is only worth something if it can fail."""
        leaky = tmp_path / "leaky.py"
        leaky.write_text("def run():\n    from assurance.watch.push import main_push\n"
                         "import httpx\n")
        assert "assurance.watch.push" in _imports(leaky, top_level_only=False)
        assert "httpx" in _imports(leaky, top_level_only=True)

    def test_watch_run_leaves_the_push_module_and_every_http_client_unloaded(self, plant):
        code = (
            "import sys\n"
            "from assurance.watch.cli import main\n"
            f"rc = main(['run', {str(plant / 'watch.json')!r}, '--ledger', "
            f"{str(plant / 'register.db')!r}])\n"
            "bad = [m for m in ('assurance.watch.push', 'assurance.watch.ingest', "
            "'assurance.api', 'httpx', 'requests', 'urllib3', 'http.client') if m in sys.modules]\n"
            "print('RC', rc, 'LOADED', bad)\n"
        )
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,  # noqa: S603
                             env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
                             check=False)
        assert "LOADED []" in out.stdout, out.stdout + out.stderr

    def test_the_kit_runs_with_the_push_module_unloaded(self, tmp_path):
        code = (
            "import sys\n"
            "import assurance.kit, assurance.kit.cli, assurance.kit.enrol\n"
            "bad = [m for m in ('assurance.watch.push', 'httpx', 'requests', 'urllib3', "
            "'http.client') if m in sys.modules]\n"
            "print('LOADED', bad)\n"
        )
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,  # noqa: S603
                             env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
                             check=False)
        assert "LOADED []" in out.stdout, out.stdout + out.stderr


# =====================================================================
# explicit opt-in
# =====================================================================

class TestNothingLeavesWithoutAnExplicitRequest:
    def test_there_is_no_way_to_pass_the_key_on_the_command_line(self, plant, local, config,
                                                                 capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        # Includes the abbreviation `--key` for `--key-env`, which argparse would
        # otherwise accept and then treat the secret as the variable's name.
        for flag in ("--key", "--api-key", "--ke", "--key=asr_secret_value"):
            argv = ["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
                    "--api-url", "https://api.example.com", flag]
            if "=" not in flag:
                argv.append("asr_secret_value")
            with pytest.raises(SystemExit) as excinfo:
                watch_main(argv)
            assert excinfo.value.code == 2
            captured = capsys.readouterr()
            assert "asr_secret_value" not in captured.err + captured.out

    @pytest.mark.parametrize("missing", ["--api-url", "--key-env"])
    def test_api_url_and_key_env_are_both_required(self, plant, missing, capsys):
        argv = ["push", str(plant / "watch.json"), "--ledger", str(plant / "register.db"),
                "--api-url", "https://api.example.com", "--key-env", "K"]
        i = argv.index(missing)
        del argv[i:i + 2]
        with pytest.raises(SystemExit) as excinfo:
            watch_main(argv)
        assert excinfo.value.code == 2

    def test_a_missing_key_variable_stops_before_anything_is_built_or_sent(
            self, plant, local, config, client, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        monkeypatch.delenv("NB_ASSURANCE_KEY", raising=False)
        rec = use(monkeypatch, Recorder(client))
        code, out, err = cli(capsys, plant, "asr_never_set")
        assert code == 2 and "NB_ASSURANCE_KEY" in err
        assert rec.requests == []

    def test_the_key_env_must_be_a_name_not_a_key(self, plant, local, config, client,
                                                  monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        rec = use(monkeypatch, Recorder(client))
        secret = "asr_this_is_actually_the_key"
        code, out, err = cli(capsys, plant, secret, env_name=secret)
        assert code == 2 and rec.requests == []

    def test_plain_http_to_a_remote_host_is_refused_before_any_request(
            self, plant, local, config, client, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        rec = use(monkeypatch, Recorder(client))
        code, out, err = cli(capsys, plant, hosted_key, api_url="http://api.example.com")
        assert code == 2 and "plain http" in err and rec.requests == []

    @pytest.mark.parametrize("url", ["ftp://example.com", "https://user:pw@example.com",
                                     "https://example.com/?x=1", "example.com", ""])
    def test_malformed_api_urls_are_refused(self, plant, local, config, client, hosted_key,
                                            monkeypatch, capsys, url):
        run_watch(config, local, now=now() - timedelta(hours=1))
        rec = use(monkeypatch, Recorder(client))
        code, _, err = cli(capsys, plant, hosted_key, api_url=url)
        assert code == 2 and rec.requests == []
        assert "pw" not in err

    def test_a_ledger_that_never_ran_has_nothing_to_report(self, plant, local, config, client,
                                                           hosted_key, monkeypatch, capsys):
        rec = use(monkeypatch, Recorder(client))
        code, out, err = cli(capsys, plant, hosted_key)
        assert code == 2 and "never run" in err and rec.requests == []

    def test_a_ledger_path_that_does_not_exist_is_not_created(self, plant, hosted_key, capsys):
        code = watch_main(["push", str(plant / "watch.json"), "--ledger",
                           str(plant / "nowhere.db"), "--api-url", "https://api.example.com",
                           "--key-env", "NB_ASSURANCE_KEY"])
        assert code == 2 and not (plant / "nowhere.db").exists()


class TestDryRun:
    def test_dry_run_opens_no_socket_builds_no_client_and_prints_the_bodies(
            self, plant, local, config, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))

        def no_network(*a, **k):
            raise AssertionError("a socket operation was attempted during --dry-run")

        monkeypatch.setattr(socket.socket, "connect", no_network)
        monkeypatch.setattr(socket.socket, "connect_ex", no_network)
        monkeypatch.setattr(socket, "create_connection", no_network)
        monkeypatch.setattr(socket, "getaddrinfo", no_network)
        monkeypatch.setattr(push, "make_client", no_network)

        code, out, err = cli(capsys, plant, hosted_key, "--dry-run",
                             api_url="https://api.example.com")
        assert code == 0
        assert "DRY RUN" in out and "nothing was sent" in out
        assert "api.example.com" in out and "NB_ASSURANCE_KEY" in out
        body = json.JSONDecoder().raw_decode(out[out.index("{"):])[0]
        assert body["watch_id"] == "WATCH-PUSH" and len(body["machines"]) == 3
        assert {m["serial"] for m in body["machines"]} == set(SERIALS)

    def test_dry_run_prints_exactly_the_body_a_real_push_sends(
            self, plant, local, config, client, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        _, dry, _ = cli(capsys, plant, hosted_key, "--dry-run")
        shown = json.JSONDecoder().raw_decode(dry[dry.index("{"):])[0]
        rec = use(monkeypatch, Recorder(client))
        code, *_ = cli(capsys, plant, hosted_key)
        assert code == 0
        assert len(rec.requests) == 1
        assert json.loads(rec.requests[0][1]) == shown

    def test_dry_run_needs_neither_the_key_nor_httpx(self, plant, local, config, monkeypatch,
                                                     capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        monkeypatch.delenv("NB_ASSURANCE_KEY", raising=False)
        monkeypatch.setitem(sys.modules, "httpx", None)      # import httpx -> ImportError
        code, out, err = cli(capsys, plant, "asr_none", "--dry-run")
        assert code == 0 and "is NOT set" in out

    def test_dry_run_writes_nothing_to_the_ledger_or_the_hosted_side(
            self, plant, local, config, client, cell, hosted_key, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        before = len(local)
        cli(capsys, plant, hosted_key, "--dry-run")
        assert len(local) == before and len(ledger_of(cell[0])) == 0


class TestNothingPrivateLeaves:
    def test_no_raw_file_no_local_path_and_no_failure_reason_is_in_the_bodies(
            self, plant, local, config, client, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(days=2))
        shutil.rmtree(plant / "0501")
        run_watch(config, local, now=now() - timedelta(hours=1))
        rec = use(monkeypatch, Recorder(client))
        code, *_ = cli(capsys, plant, hosted_key)
        assert code == 0
        sent = b"".join(c for _, c, _ in rec.requests).decode()
        assert str(plant) not in sent and str(plant.parent) not in sent
        assert SECRET_MARK not in sent and "PROGRAM Main" not in sent
        assert "firmware 3.8.2" not in sent
        assert "No such file" not in sent and "is not a directory" not in sent
        bodies = [json.loads(c) for _, c, _ in rec.requests]
        blind = next(m for b in bodies for m in b["machines"]
                     if m["serial"] == "0501" and m["status"] == "uncollectable")
        assert blind["status"] == "uncollectable" and blind["manifest"] is None
        assert blind["detail"] == "could not be collected; the reason is in the local ledger"
        # What is sent for a collected machine is its manifest: ids, hashes, versions.
        ok = next(m for b in bodies for m in b["machines"] if m["serial"] == "0412")
        assert {i["item_id"] for i in ok["manifest"]["items"]} == {
            "ITM-ZONES", "ITM-PARAMS", "ITM-PLC", "ITM-FW"}
        assert all(len(i["content_hash"]) == 64 for i in ok["manifest"]["items"])

    def test_the_key_travels_only_in_the_header(self, plant, local, config, client, hosted_key,
                                                monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        rec = use(monkeypatch, Recorder(client))
        cli(capsys, plant, hosted_key)
        url, content, headers = rec.requests[0]
        assert headers["X-API-Key"] == hosted_key
        assert hosted_key not in url and hosted_key.encode() not in content


# =====================================================================
# what the hosted workspace ends up knowing
# =====================================================================

class TestWhatArrives:
    def test_a_healthy_fleet_arrives_as_baselines_and_is_not_stale(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0 and "3 recorded" in out
        data = observations(client, cell[1])
        assert all(m["cadence_hours"] == 168 and m["cadence_declared"] is True
                   for m in data["machines"])
        assert [m["stale"] for m in data["machines"]] == [False, False, False]
        assert all(m["last_attempt_succeeded"] for m in data["machines"])
        assert client.get("/v1/change/cases", headers=cell[1]).json()["cases"] == []

    def test_a_machine_that_could_not_be_collected_arrives_as_failed_and_stale_never_current(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(days=10))
        shutil.rmtree(plant / "0501")
        run_watch(config, local, now=now() - timedelta(hours=1))
        use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0
        assert "[FAILED  ] 0501" in out and "NOT observed" in out
        row = machine_row(client, cell[1], KEY_0501)
        assert row["last_attempt_status"] == "uncollectable"
        assert row["last_attempt_succeeded"] is False
        assert row["stale"] is True and row["stale_reason"] == "older_than_cadence"
        assert row["age_hours"] == pytest.approx(240, abs=1)       # blind for ten days
        assert row["consecutive_failed_attempts"] == 1
        good = machine_row(client, cell[1], KEY_0412)
        assert good["stale"] is False and good["last_attempt_succeeded"] is True

    def test_a_first_push_of_a_configuration_older_than_the_window_sends_the_look_that_sealed_it(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        """manifest_relayed is honoured only for a manifest the account already holds, so the
        local look at which the manifest was sealed travels beside the relayed re-confirmation."""
        run_watch(config, local, now=now() - timedelta(days=30))
        run_watch(config, local, now=now() - timedelta(hours=1))
        plan = push.build_plan(config, local)
        entries = [m for b in plan.bodies for m in b["machines"] if m["serial"] == "0412"]
        assert [(e["manifest_relayed"], e["status"]) for e in entries] == [
            (False, "changed"), (True, "unchanged")]
        assert entries[0]["manifest"] == entries[1]["manifest"]
        assert entries[0]["observed_at"] < entries[1]["observed_at"]
        rec = use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0
        row = machine_row(client, cell[1], KEY_0412)
        assert row["stale"] is False and row["last_successful_manifest_relayed"] is True
        # pushing again records nothing new: the anchor is already held
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0
        again = json.loads(rec.requests[-1][1])
        assert {m["serial"] for m in again["machines"]} == set(SERIALS)

    def test_a_relayed_entry_with_no_local_look_to_anchor_it_is_not_made_current(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(days=30))
        run_watch(config, local, now=now() - timedelta(hours=1))
        monkeypatch.setattr(push, "_anchor_entry", lambda *a, **k: None)
        use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 1 and "relayed_manifest_not_held" in out
        assert KEY_0412 not in [m["machine"] for m in observations(client, cell[1])["machines"]]

    def test_a_machine_blind_from_its_first_run_is_refused_and_says_why_not_shown_as_a_ghost(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        shutil.rmtree(plant / "0602")
        run_watch(config, local, now=now() - timedelta(hours=1))
        use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        # The hosted ledger has never seen a manifest for it: a failure alone cannot create it.
        assert code == 1 and "unenrolled_machine" in out
        assert [m["machine"] for m in observations(client, cell[1])["machines"]] == [
            KEY_0412, KEY_0501]

    def test_a_drift_opens_exactly_one_case_and_pushing_again_opens_none(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(days=3))
        use(monkeypatch, Recorder(client))
        assert cli(capsys, plant, hosted_key)[0] == 0
        reflash(plant, "0412")
        run_watch(config, local, now=now() - timedelta(hours=1))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0 and "cases opened: case-" in out
        cases = client.get("/v1/change/cases", headers=cell[1]).json()["cases"]
        assert len(cases) == 1 and cases[0]["machines"] == [KEY_0412]
        length = len(ledger_of(cell[0]))

        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0 and "already recorded" in out and "cases opened" not in out
        assert len(ledger_of(cell[0])) == length
        assert len(client.get("/v1/change/cases", headers=cell[1]).json()["cases"]) == 1

    def test_the_hosted_case_is_the_case_the_local_watch_opened(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(days=3))
        use(monkeypatch, Recorder(client))
        cli(capsys, plant, hosted_key)
        reflash(plant, "0412")
        run = run_watch(config, local, now=now() - timedelta(hours=1))
        local_case = next(o for o in run.outcomes if o.case_id)
        cli(capsys, plant, hosted_key)
        hosted = client.get("/v1/change/cases", headers=cell[1]).json()["cases"]
        # Same trigger, same pure function of it: the hosted case IS the local case's id,
        # and its content is what assess_drift made of the same two manifests.
        assert [c["case_id"] for c in hosted] == [local_case.case_id]
        local_case_body = CaseStore(local).get(local_case.case_id)
        hosted_case = client.get(f"/v1/change/cases/{local_case.case_id}",
                                 headers=cell[1]).json()
        assert hosted_case["changed_items"] == [dict(c) for c in local_case_body.changed_items]
        assert hosted_case["affected_functions"] == list(local_case_body.affected_functions)


# =====================================================================
# retries, redirects and refusals
# =====================================================================

class TestSafeToRetry:
    def test_a_timeout_after_the_server_processed_the_report_duplicates_nothing(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        import httpx

        run_watch(config, local, now=now() - timedelta(days=3))
        use(monkeypatch, Recorder(client))
        cli(capsys, plant, hosted_key)
        reflash(plant, "0412")
        run_watch(config, local, now=now() - timedelta(hours=1))

        def timeout_after_processing(call, forward):
            if call == 1:
                forward()                       # the server did the work ...
                raise httpx.ReadTimeout("slow")  # ... and the answer never arrived
            return None

        rec = use(monkeypatch, Recorder(client, fail=timeout_after_processing))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0 and rec.calls == 2
        assert "already recorded" in out
        assert len(client.get("/v1/change/cases", headers=cell[1]).json()["cases"]) == 1
        observed = ledger_of(cell[0]).entries(kind="watch.observation")
        assert len(observed) == 3 + 3                       # two runs' worth, once each
        assert ledger_of(cell[0]).verify_chain()[0] is True

    def test_a_5xx_is_retried_and_then_succeeds(self, plant, local, config, client, hosted_key,
                                                monkeypatch, capsys):
        import httpx

        run_watch(config, local, now=now() - timedelta(hours=1))

        def flaky(call, forward):
            return httpx.Response(503, json={"detail": "busy"}) if call < 3 else None

        rec = use(monkeypatch, Recorder(client, fail=flaky))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 0 and rec.calls == 3 and "3 recorded" in out

    def test_giving_up_is_exit_2_and_says_it_is_safe_to_run_again(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        import httpx

        run_watch(config, local, now=now() - timedelta(hours=1))

        def down(call, forward):
            raise httpx.ConnectError("refused")

        rec = use(monkeypatch, Recorder(client, fail=down))
        code, out, err = cli(capsys, plant, hosted_key, "--retries", "2")
        assert code == 2 and rec.calls == 3
        assert "running the same command again is safe" in out
        assert len(ledger_of(cell[0])) == 0

    def test_a_redirect_is_never_followed_and_the_key_goes_nowhere_else(
            self, plant, local, config, hosted_key, monkeypatch, capsys):
        import httpx

        run_watch(config, local, now=now() - timedelta(hours=1))
        seen: list[str] = []

        def handler(request):
            seen.append(str(request.url.host))
            return httpx.Response(307, headers={"location": "https://evil.example/steal"})

        real = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
        monkeypatch.setattr(push, "make_client", lambda timeout: real)
        code, out, err = cli(capsys, plant, hosted_key)
        assert code == 2 and seen == ["127.0.0.1"]
        assert "Redirects are never followed" in out and "evil.example" in out

    def test_make_client_never_follows_redirects(self):
        client = push.make_client(5.0)
        try:
            assert client.follow_redirects is False
        finally:
            client.close()

    def test_a_register_plan_key_is_refused_with_the_plans_own_words(
            self, plant, local, config, client, accounts, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        _, headers = account(accounts, "register", "reg@example.de")
        key = headers["X-API-Key"]
        monkeypatch.setenv("NB_ASSURANCE_KEY", key)
        rec = use(monkeypatch, Recorder(client))
        code, out, err = cli(capsys, plant, key)
        assert code == 1 and rec.calls == 1                   # a 402 is not retried
        assert "HTTP 402" in out and "REFUSED" in out

    def test_a_wrong_key_is_refused_and_not_echoed(self, plant, local, config, client,
                                                   monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        monkeypatch.setenv("NB_ASSURANCE_KEY", "asr_definitely_not_valid")
        use(monkeypatch, Recorder(client))
        code, out, err = cli(capsys, plant, "asr_definitely_not_valid")
        assert code == 1 and "HTTP 401" in out

    def test_a_server_that_refuses_part_of_the_report_is_exit_1(
            self, plant, local, config, client, hosted_key, monkeypatch, capsys):
        # A run stamped in the future is refused by the server: the clock is not ours to lie to.
        run_watch(config, local, now=now() + timedelta(days=2))
        use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        assert code == 1 and "REFUSED" in out

    def test_an_older_look_the_server_already_has_newer_than_is_ignored_not_a_failure(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        from .test_assurance_watch_report import good, make_manifest, post, report

        run_watch(config, local, now=now() - timedelta(days=10))
        shutil.rmtree(plant / "0501")
        run_watch(config, local, now=now() - timedelta(hours=1))
        # The hosted ledger already has a *newer* success for 0501 from somewhere else.
        fresh = now() - timedelta(minutes=30)
        post(client, cell[1], report(good(make_manifest(plant.parent, "0501"), at=fresh)))
        use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key)
        # The failed attempt (1h ago) is older than the recorded success (30m ago), and so is
        # the ten-day-old success: both are ignored as older, neither is a refusal of the push.
        assert code == 0 and "ignored" in out


class TestBatching:
    def test_a_report_larger_than_one_request_is_split_and_says_so(
            self, plant, local, config, client, cell, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        plan = push.build_plan(config, local)
        one = max(len(push.wire_bytes({**plan.bodies[0], "machines": [m]}))
                  for m in plan.bodies[0]["machines"])
        rec = use(monkeypatch, Recorder(client))
        code, out, _ = cli(capsys, plant, hosted_key, "--max-body-bytes", str(one + 200))
        assert code == 0
        assert rec.calls == 3 and "sent as 3 requests" in out
        bodies = [json.loads(c) for _, c, _ in rec.requests]
        assert [(b["batch_index"], b["batch_count"]) for b in bodies] == [(1, 3), (2, 3), (3, 3)]
        assert all(len(c) <= one + 200 for _, c, _ in rec.requests)
        assert len(observations(client, cell[1])["machines"]) == 3

    def test_every_batch_of_a_big_fleet_fits_the_servers_real_cap(self, plant, local, config):
        run_watch(config, local, now=now() - timedelta(hours=1))
        plan = push.build_plan(config, local, max_body_bytes=push.DEFAULT_MAX_BODY_BYTES)
        assert all(len(push.wire_bytes(b)) < 1024 * 1024 for b in plan.bodies)
        assert not plan.batched                      # three machines are one request

    def test_machines_too_large_for_any_request_are_named_not_dropped_silently(
            self, plant, local, config, client, hosted_key, monkeypatch, capsys):
        run_watch(config, local, now=now() - timedelta(hours=1))
        rec = use(monkeypatch, Recorder(client))
        code, out, err = cli(capsys, plant, hosted_key, "--max-body-bytes", "700")
        assert code == 2 and rec.requests == []
        assert "alone is larger than the 700-byte request limit" in err
