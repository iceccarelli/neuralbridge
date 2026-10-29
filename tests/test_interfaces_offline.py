"""The offline path opens no sockets and loads no HTTP client; ``watch push`` is the
one networked command.

Existing tests cover pieces: the kit's airgap guard on a real HTTP client
(``test_assurance_kit.py``), the import graph (``test_assurance_watch_push.py``)
and ``--dry-run`` (same file). They leave three gaps this file closes:

* nothing *ran* the report, collect, evidence-verify, change or machine commands
  in a fresh interpreter with the socket layer watched from outside the code
  under test (a Python audit hook cannot be bypassed by a C extension or a
  re-imported ``socket``, unlike the kit's own monkeypatch guard);
* the kit and watch tests check imports, not a whole run;
* nothing pinned *which* modules may import a network client at all, so a new
  one could appear without any test noticing.

A positive control proves the hook can fail: ``watch push`` against a closed port
is seen connecting.
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path

import pytest

from .interfaces_scenario import KEY, Plant, cli_env
from .interfaces_support import envelope_dict, trace_dict

SRC = Path(__file__).resolve().parents[1] / "src"

#: The only modules in the package that import anything able to reach a network.
NETWORKED_MODULES = {
    "assurance/watch/push.py",           # `watch push`, opt-in, lazy import
    "assurance/supplier/publish.py",     # `supplier publish --api-url`, lazy import
    "assurance/billing/stripe_gateway.py",   # the hosted service talking to Stripe
    "assurance/mcp/server.py",           # the MCP relay to a deployment
    "assurance/kit/airgap.py",           # imports socket to REFUSE connections
}
_NETWORK_ROOTS = {"httpx", "requests", "urllib3", "aiohttp", "http", "urllib", "socket",
                  "smtplib", "ftplib", "stripe", "websockets", "ssl", "xmlrpc", "telnetlib"}

_CHILD = textwrap.dedent('''
    import json, os, sys

    NET = {"socket.__new__", "socket.connect", "socket.getaddrinfo", "socket.gethostbyname",
           "socket.gethostbyname_ex", "socket.gethostbyaddr", "socket.getnameinfo",
           "socket.bind", "socket.sendto", "socket.sendmsg",
           "urllib.Request", "http.client.connect", "http.client.send",
           "smtplib.connect", "ftplib.connect"}
    events = []

    def hook(event, args):
        if event in NET:
            events.append([event, repr(args)[:160]])

    sys.addaudithook(hook)

    from assurance.cli import main

    commands = json.loads(open(sys.argv[1]).read())
    results = []
    for argv in commands:
        if argv[0] == "!firmware":
            with open(argv[1], "wb") as f:
                f.write(b"\\x7fELF" + b"firmware 3.9.0" * 20)
            continue
        rc = main([str(a) for a in argv])
        results.append([argv[:2], rc])
    watched = ["httpx", "requests", "urllib3", "aiohttp", "http.client", "urllib.request",
               "smtplib", "ftplib", "stripe", "assurance.watch.push", "assurance.api",
               "assurance.mcp", "assurance.billing", "fastapi", "uvicorn"]
    loaded = [m for m in watched if m in sys.modules]
    print("RESULT " + json.dumps({"events": events, "loaded": loaded, "results": results}))
''')


def run_child(tmp: Path, cwd: Path, commands: list, **env: str) -> dict:
    script = tmp / "child.py"
    script.write_text(_CHILD, encoding="utf-8")
    cmds = tmp / "commands.json"
    cmds.write_text(json.dumps(commands), encoding="utf-8")
    r = subprocess.run(  # noqa: S603
        [sys.executable, str(script), str(cmds)], cwd=cwd, capture_output=True, text=True,
        env=cli_env(**env), check=False, timeout=300)
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line, r.stdout + r.stderr
    return json.loads(line[len("RESULT "):])


@pytest.fixture
def plant(tmp_path):
    p = Plant(tmp_path / "plant")
    (p.root / "envelope.json").write_text(json.dumps(envelope_dict()), encoding="utf-8")
    (p.root / "trace.json").write_text(
        json.dumps(trace_dict(datetime.now(UTC))), encoding="utf-8")   # not future-dated: the engine refuses that
    return p


def offline_commands(cid: str) -> list:
    led = "out/evidence.db"
    return [
        ["kit", "check", "kit.json"],
        ["kit", "run", "kit.json", "--out", "out"],
        ["collect", "check-plan", "plans/cell.json"],
        ["collect", "run", "plans/cell.json", "--root", "exports/0412", "--serial", "0412",
         "--actor", "m.keller", "--ledger", led],
        ["watch", "run", "watch.json", "--ledger", led],
        ["!firmware", "exports/0501/controller-fw.bin"],
        ["watch", "run", "watch.json", "--ledger", led],
        ["watch", "status", "watch.json", "--ledger", led],
        ["machine", "verify", "--envelope", "envelope.json", "--trace", "trace.json",
         "--actor", "v.grimaldi", "--ledger", led, "--subject", KEY],
        ["fleet", "list", "--ledger", led],
        ["change", "list", "--ledger", led, "--json"],
        ["change", "show", cid, "--ledger", led],
        ["change", "claim", cid, "--ledger", led, "--owner", "v.grimaldi",
         "--actor", "v.grimaldi"],
        ["change", "replay", cid, "--ledger", led],
        ["change", "export", cid, "--ledger", led, "--out", "export.json"],
        ["evidence", "verify", "export.json"],
        ["report", "build", "--ledger", led, "--out", "report.html"],
        ["report", "demo", "--out", "demo"],
    ]


class TestRunningTheOfflinePathOpensNoSocket:
    def test_a_whole_offline_session_in_a_fresh_interpreter(self, plant, tmp_path):
        # The case id is derived from the observed configuration; compute it from the
        # same files in a twin, so the child can export and verify the real case.
        twin = Plant(tmp_path / "twin")
        twin.enrol_and_change("lib")
        commands = offline_commands(twin.expected_drift_case_id())

        out = run_child(tmp_path, plant.root, commands, PLANT_API_KEY="unused")

        assert out["events"] == [], out["events"]
        assert out["loaded"] == [], out["loaded"]
        rcs = {" ".join(map(str, argv)): rc for argv, rc in out["results"]}
        # Each command ran for real and did not fail to run (exit 2 = could not run).
        assert rcs["kit run"] == 0
        assert rcs["change export"] == 0
        assert rcs["evidence verify"] == 0
        assert rcs["report build"] == 0 and rcs["report demo"] == 0
        assert rcs["machine verify"] == 0
        assert all(rc in (0, 1) for rc in rcs.values()), rcs      # nothing exited 2
        assert (plant.root / "report.html").is_file()


class TestRecorderAttestationNeedsNoNetwork:
    """Signing a recording and verifying under a trust list are offline operations."""

    def test_sign_trust_verify_and_check_in_a_fresh_interpreter_open_no_socket(
            self, plant, tmp_path):
        env = json.loads((plant.root / "envelope.json").read_text(encoding="utf-8"))
        commands = [
            ["attest", "keygen", "--out", "rec.pem"],
            ["machine", "recorder-sign", "--key", "rec.pem", "--trace", "trace.json",
             "--product", env["product"], "--product-version", env["product_version"],
             "--recorder-id", "REC-OFFLINE", "--out", "att.json"],
            ["machine", "recorder-trust", "--trust", "rtrust.json",
             "--public-key", "rec.pem.pub", "--label", "offline recorder",
             "--provenance", "field"],
            ["machine", "verify", "--envelope", "envelope.json", "--trace", "trace.json",
             "--actor", "v.grimaldi", "--recorder-attestation", "att.json",
             "--recorder-trust", "rtrust.json", "--out", "signed-bundle.json"],
            ["machine", "check", "signed-bundle.json", "--envelope", "envelope.json",
             "--trace", "trace.json", "--recorder-trust", "rtrust.json"],
            ["machine", "check", "signed-bundle.json", "--envelope", "envelope.json",
             "--trace", "trace.json"],
        ]
        out = run_child(tmp_path, plant.root, commands, PLANT_API_KEY="unused")

        assert out["events"] == [], out["events"]
        assert out["loaded"] == [], out["loaded"]
        assert [rc for _, rc in out["results"]] == [0] * len(commands), out["results"]
        bundle = json.loads((plant.root / "signed-bundle.json").read_text(encoding="utf-8"))
        assert bundle["evidence"]["body"]["provenance_basis"] == "recorder_attested"
        assert bundle["evidence"]["body"]["tier"] == "validated"
        assert "PRIVATE" not in json.dumps(bundle).upper()
        assert "PRIVATE" not in (plant.root / "att.json").read_text(encoding="utf-8").upper()


class TestWatchPushIsTheOnlyNetworkedPath:
    def test_dry_run_opens_no_socket_and_loads_no_client(self, plant, tmp_path):
        plant.kit_run("cli")
        out = run_child(tmp_path, plant.root, [
            ["watch", "run", "watch.json", "--ledger", "out/evidence.db"],
            ["watch", "push", "watch.json", "--ledger", "out/evidence.db",
             "--api-url", "http://127.0.0.1:18499", "--key-env", "PLANT_API_KEY", "--dry-run"],
        ], PLANT_API_KEY="unused")
        assert out["events"] == []
        assert out["loaded"] == ["assurance.watch.push"]      # the verb, and no client

    def test_a_real_push_is_seen_connecting_so_the_hook_can_fail(self, plant, tmp_path):
        """Positive control. Port 18499 is ours and has nothing listening."""
        plant.kit_run("cli")
        out = run_child(tmp_path, plant.root, [
            ["watch", "run", "watch.json", "--ledger", "out/evidence.db"],
            ["watch", "push", "watch.json", "--ledger", "out/evidence.db",
             "--api-url", "http://127.0.0.1:18499", "--key-env", "PLANT_API_KEY",
             "--retries", "0", "--timeout", "2"],
        ], PLANT_API_KEY="asr_not_a_real_key_0000000000000000000000")
        assert any(e[0] == "socket.connect" for e in out["events"]), out["events"]
        assert "httpx" in out["loaded"] and "assurance.watch.push" in out["loaded"]
        push_rc = out["results"][-1][1]
        assert push_rc == 2          # could not reach the server: safe to run again

    def test_no_key_on_the_command_line_and_no_network_without_an_explicit_url(self, plant):
        """`watch push` requires both --api-url and --key-env; with neither it does not run."""
        from assurance.watch.cli import build_parser

        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["push", "watch.json", "--ledger", "l.db"])


def _network_imports(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            found.add(node.module.split(".")[0])
    return found & _NETWORK_ROOTS


class TestNoOtherModuleCanReachTheNetwork:
    def test_the_set_of_modules_that_import_a_network_client_is_pinned(self):
        found = {str(p.relative_to(SRC)) for p in (SRC / "assurance").rglob("*.py")
                 if _network_imports(p)}
        assert found == NETWORKED_MODULES, (
            "a module started (or stopped) importing a network client. If it is new, it "
            "needs a reason in the module docstring, a place in this set, and a test that "
            f"it is not reachable from the offline kit: {sorted(found ^ NETWORKED_MODULES)}")

    def test_the_scan_would_notice_one(self, tmp_path):
        leaky = tmp_path / "leaky.py"
        leaky.write_text("def f():\n    import urllib.request\n")
        assert _network_imports(leaky) == {"urllib"}

    def test_push_is_imported_only_from_the_push_verb(self):
        users = []
        for p in (SRC / "assurance").rglob("*.py"):
            for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
                names = []
                if isinstance(node, ast.Import):
                    names = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [f"{node.module}.{a.name}" for a in node.names]
                    names.append(node.module or "")
                if any(n.startswith("assurance.watch.push") for n in names):
                    users.append(str(p.relative_to(SRC)))
        assert sorted(set(users)) == ["assurance/watch/cli.py"]
