"""The offline kit's "opens no sockets, spawns nothing" claim has to be enforced, not asserted.

An independent review found:

* the guard patched five functions of the ``socket`` module and left the rest of the
  resolution and send paths (``gethostbyname``, ``getnameinfo``, ``sendmsg``, the
  ``_socket`` base class) open and unrecorded;
* "spawns nothing ... enforced separately" had no test: a subprocess and a UDP datagram
  injected into the kit left every kit test green;
* CI ran the kit with no network namespace and read back the guard's own verdict.

So the guard now has a second layer (a Python audit hook, which sees ``_socket`` calls and
cannot be removed), it refuses and records process creation, the kit's import closure and a
real run are checked from outside, and the kit runs under ``unshare -rn`` where the OS allows
it. ``NEURALBRIDGE_REQUIRE_NETNS=1`` turns "the OS does not allow it" into a failure (CI).
"""

from __future__ import annotations

import _posixsubprocess
import _socket
import ast
import json
import multiprocessing
import multiprocessing.util
import os
import shutil
import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from assurance.kit.airgap import AIRGAP_LIMITS, AirgapError, no_network

from .support import plan_dict, write_export

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src"
UNREACHABLE = ("192.0.2.1", 9)  # TEST-NET-1: never routed


# ---------------------------------------------------------------------------
# every way out of the process that is not connect()
# ---------------------------------------------------------------------------
def _udp_sendmsg():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendmsg([b"x"], [], 0, UNREACHABLE)


def _udp_sendto():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"x", UNREACHABLE)


def _raw_socket_connect():
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    s.settimeout(0.2)
    s.connect(UNREACHABLE)


def _raw_socket_sendto():
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.sendto(b"x", UNREACHABLE)


def _base_class_connect():
    s = socket.socket()
    s.settimeout(0.2)
    _socket.socket.connect(s, UNREACHABLE)


def _socket_subclass_connect():
    class Mine(socket.socket):
        pass

    s = Mine()
    s.settimeout(0.2)
    s.connect(UNREACHABLE)


def _listen():
    s = socket.socket()
    s.bind(("0.0.0.0", 0))


def _raw_sendmsg():
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    s.sendmsg([b"x"], [], 0, UNREACHABLE)


PROBES = {
    "gethostbyname": lambda: socket.gethostbyname("telemetry.example.invalid"),
    "gethostbyname_ex": lambda: socket.gethostbyname_ex("telemetry.example.invalid"),
    "gethostbyaddr": lambda: socket.gethostbyaddr("192.0.2.1"),
    "getnameinfo": lambda: socket.getnameinfo(("192.0.2.1", 443), 0),
    "udp sendmsg": _udp_sendmsg,
    "udp sendto": _udp_sendto,
    "_socket connect": _raw_socket_connect,
    "_socket sendto": _raw_socket_sendto,
    "_socket sendmsg": _raw_sendmsg,
    "_socket gethostbyname": lambda: _socket.gethostbyname("telemetry.example.invalid"),
    "_socket getaddrinfo": lambda: _socket.getaddrinfo("telemetry.example.invalid", 443),
    "_socket gethostbyaddr": lambda: _socket.gethostbyaddr("192.0.2.1"),
    "_socket getnameinfo": lambda: _socket.getnameinfo(("192.0.2.1", 443), 0),
    "_socket base-class connect": _base_class_connect,
    "socket subclass connect": _socket_subclass_connect,
    "bind a listening port": _listen,
}


@pytest.mark.parametrize("name", sorted(PROBES))
def test_every_way_out_is_refused_and_recorded(name):
    with no_network() as result:
        with pytest.raises(AirgapError):
            PROBES[name]()
    assert not result.held, f"{name}: refused but not recorded"
    assert result.attempts, name
    assert "test_assurance_airgap_enforcement.py" in result.attempts[0].caller


def test_creating_an_ip_socket_is_itself_refused():
    with no_network() as result:
        with pytest.raises(AirgapError):
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    assert [a.api for a in result.attempts] == ["socket.__new__"]


def test_a_local_socketpair_is_allowed_and_recorded_as_observed():
    with no_network() as result:
        a, b = socket.socketpair()
        a.close()
        b.close()
    assert result.held
    assert any(o["event"] == "socket.__new__" and o["outcome"] == "allowed"
               for o in result.to_dict()["observed"])


# ---------------------------------------------------------------------------
# "spawns nothing"
# ---------------------------------------------------------------------------
def test_starting_a_process_is_refused_and_recorded():
    with no_network() as result:
        with pytest.raises(AirgapError):
            subprocess.run(["true"], check=False)  # noqa: S603, S607
    assert not result.held
    assert result.attempts[0].api == "subprocess.Popen"


def test_os_system_is_refused_and_recorded():
    with no_network() as result:
        with pytest.raises(AirgapError):
            os.system("true")  # noqa: S605, S607
    assert result.attempts[0].api == "os.system"


@pytest.mark.parametrize("event", ["os.exec", "os.posix_spawn", "os.spawn", "os.fork",
                                   "os.forkpty"])
def test_the_other_process_creating_events_are_refused(event):
    # Raised through the interpreter's audit machinery so that nothing is really exec'd.
    with no_network() as result:
        with pytest.raises(AirgapError):
            sys.audit(event, "/bin/true", ["true"], None)
    assert result.attempts[0].api == event


def _marker_child(marker: Path) -> bytes:
    return f"echo ran > {marker}".encode()


def test_multiprocessing_spawn_of_a_process_is_refused_and_recorded(tmp_path):
    """multiprocessing's spawn and forkserver start children with ``_posixsubprocess.fork_exec``,
    for which CPython emits no audit event: the guard wraps it for the run."""
    marker = tmp_path / "child-ran"
    with no_network() as result:
        with pytest.raises(AirgapError):
            multiprocessing.util.spawnv_passfds(
                b"/bin/sh", [b"sh", b"-c", _marker_child(marker)], [])
    assert not marker.exists()
    assert not result.held
    assert result.attempts[0].api == "_posixsubprocess.fork_exec"
    assert "test_assurance_airgap_enforcement.py" in result.attempts[0].caller \
        or "multiprocessing" in result.attempts[0].caller


def test_a_spawn_process_pool_is_refused_and_recorded():
    import concurrent.futures as cf

    pool = cf.ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.get_context("spawn"))
    try:
        with no_network() as result:
            with pytest.raises(AirgapError):
                pool.submit(os.getpid).result(timeout=20)
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    assert [a.api for a in result.attempts] == ["_posixsubprocess.fork_exec"]


def test_a_multiprocessing_spawn_context_process_is_refused(tmp_path):
    ctx = multiprocessing.get_context("spawn")
    proc = ctx.Process(target=print)
    with no_network() as result:
        with pytest.raises(AirgapError):
            proc.start()
    assert not result.held and result.attempts[0].api == "_posixsubprocess.fork_exec"


def test_fork_exec_is_restored_and_a_stale_binding_is_inert_after_the_block(tmp_path):
    real = _posixsubprocess.fork_exec
    with no_network():
        wrapped = _posixsubprocess.fork_exec
        assert wrapped is not real
    assert _posixsubprocess.fork_exec is real
    # a module that bound the wrapper while the block ran (``from _posixsubprocess import
    # fork_exec``) must not keep refusing after release
    marker = tmp_path / "ran-after-release"
    _posixsubprocess.fork_exec = wrapped
    try:
        pid = multiprocessing.util.spawnv_passfds(
            b"/bin/sh", [b"sh", b"-c", _marker_child(marker)], [])
        os.waitpid(pid, 0)
    finally:
        _posixsubprocess.fork_exec = real
    assert marker.exists()


def test_leaving_the_block_restores_everything_even_if_the_guard_list_was_cleared():
    from assurance.kit import airgap

    real_connect = socket.socket.connect
    real_fork_exec = _posixsubprocess.fork_exec
    with no_network():
        airgap._ACTIVE.clear()          # evasion from inside the process: documented
    assert socket.socket.connect is real_connect
    assert _posixsubprocess.fork_exec is real_fork_exec
    assert socket.gethostbyname("localhost")


def test_sendmsg_to_a_non_loopback_address_is_refused_by_the_audit_layer_alone():
    """Through ``_socket`` directly, layer 1 (the patched ``socket.socket``) is not involved."""
    with no_network(allow_loopback=True) as result:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        with pytest.raises(AirgapError):
            s.sendmsg([b"x"], [], 0, UNREACHABLE)
        s.close()
    assert [a.api for a in result.attempts] == ["socket.sendmsg"]


def test_bind_is_refused_by_the_audit_layer_unless_the_address_is_loopback():
    with no_network(allow_loopback=True) as result:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        with pytest.raises(AirgapError):
            s.bind(("0.0.0.0", 0))  # noqa: S104 - the point of the test
        s.close()
        assert [a.api for a in result.attempts] == ["socket.bind"]
        ok = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        ok.bind(("127.0.0.1", 0))
        ok.close()
    assert result.loopback_used and len(result.attempts) == 1


def test_the_limits_say_what_is_not_seen():
    text = " ".join(AIRGAP_LIMITS)
    assert "multiprocessing" in text and "fork_exec" in text
    assert "ctypes" in text and "already" in text       # pre-existing connected sockets


def test_the_kit_readme_does_not_claim_a_subprocess_is_covered_or_absent_without_basis():
    from assurance.kit import cli

    assert "spawns none" not in cli._README
    assert "refuses" in cli._README and "ctypes" in cli._README


def test_process_creation_is_not_exempted_by_allow_loopback():
    with no_network(allow_loopback=True) as result:
        with pytest.raises(AirgapError):
            subprocess.run(["true"], check=False)  # noqa: S603, S607
    assert not result.held


# ---------------------------------------------------------------------------
# the guard is released, and its record says what it saw and what it cannot
# ---------------------------------------------------------------------------
def test_nothing_is_left_blocked_after_the_block():
    with pytest.raises(AirgapError):
        with no_network():
            socket.gethostbyname("telemetry.example.invalid")
    assert socket.gethostbyname("localhost")
    assert subprocess.run(["true"], check=False).returncode == 0  # noqa: S603, S607
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.close()


def test_the_guard_can_be_armed_again_after_a_release():
    for _ in range(3):
        with no_network() as result:
            with pytest.raises(AirgapError):
                socket.gethostbyname("telemetry.example.invalid")
        assert len(result.attempts) == 1


def test_the_record_names_its_layers_and_limits():
    with no_network() as result:
        pass
    body = result.to_dict()
    assert body["held"] is True
    assert "sys.addaudithook" in body["layers"]
    text = " ".join(AIRGAP_LIMITS)
    assert "audit hook" in text
    assert "network namespace" in text or "unshare" in text
    assert "process" in text and "spawn" in text


# ---------------------------------------------------------------------------
# from the outside: the import closure of a real kit run, and a real run
# ---------------------------------------------------------------------------
FORBIDDEN_IMPORTS = {"subprocess", "ssl", "http", "urllib", "ctypes", "multiprocessing", "pty",
                     "socketserver", "smtplib", "ftplib", "telnetlib", "xmlrpc", "asyncio",
                     "httpx", "requests", "urllib3", "aiohttp", "stripe", "websockets",
                     # the C modules under socket and subprocess: no audit event for fork_exec
                     "_posixsubprocess", "_socket"}
FORBIDDEN_CALLS = {("os", n) for n in (
    "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "execv", "execve",
    "execl", "execle", "execlp", "execlpe", "execvp", "execvpe", "spawnl", "spawnle",
    "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe", "startfile")}
#: The one module of the kit's closure that may name these: it imports them to refuse them.
MAY_IMPORT = {"assurance/kit/airgap.py": {"socket", "_posixsubprocess"}}


def make_kit(root: Path) -> Path:
    """The shipped sample: what ``kit init`` writes, filled in the way the README says."""
    base = root / "plant"
    subprocess.run([sys.executable, "-m", "assurance", "kit", "init", str(base)],  # noqa: S603
                   check=True, capture_output=True, env=_env())
    for n, serial in enumerate(("CELL-0412", "CELL-0501")):
        write_export(base / "exports" / serial, stamp="2026-09-14T06:02:11Z",
                     operator="ci", seq=f"004{n}")
    (base / "exports" / "CELL-0412" / "PUT-EXPORTS-HERE.txt").unlink(missing_ok=True)
    plan = json.loads((base / "plans" / "cell.json").read_text())
    plan.update(manufacturer="CI", model="AR-7")
    assert plan_dict()  # the shared helper still builds; the shipped plan is what runs
    (base / "plans" / "cell.json").write_text(json.dumps(plan))
    cfg = json.loads((base / "kit.json").read_text())
    cfg.update(organisation="CI Run", site="Runner", country="IT", prepared_by="ci@example.com")
    cfg["machines"] = [{"serial": s, "plan": "plans/cell.json", "exports": f"exports/{s}"}
                       for s in ("CELL-0412", "CELL-0501")]
    (base / "kit.json").write_text(json.dumps(cfg))
    return base


def _env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().endswith("_PROXY")}
    env["PYTHONPATH"] = str(SRC) + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("NEURALBRIDGE_REQUIRE_POSTGRES", None)
    return env


_CHILD = textwrap.dedent('''
    import json, sys
    WATCH = ("socket.", "subprocess.", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
             "os.fork", "os.forkpty", "pty.", "urllib.", "http.client.", "smtplib.", "ftplib.",
             "ctypes.dlopen", "ctypes.call_function")
    events = []
    def hook(event, args):
        if event.startswith(WATCH):
            events.append([event, repr(args)[:120]])
    sys.addaudithook(hook)
    from assurance.cli import main
    rc = main(["kit", "run", sys.argv[1], "--out", sys.argv[2]])
    loaded = sorted(m.__file__ for m in list(sys.modules.values())
                    if getattr(m, "__name__", "").startswith("assurance")
                    and getattr(m, "__file__", None))
    print("RESULT " + json.dumps({"rc": rc, "events": events, "loaded": loaded}))
''')


@pytest.fixture(scope="module")
def observed_run(tmp_path_factory):
    root = tmp_path_factory.mktemp("kit")
    base = make_kit(root)
    child = root / "child.py"
    child.write_text(_CHILD, encoding="utf-8")
    r = subprocess.run(  # noqa: S603
        [sys.executable, str(child), str(base / "kit.json"), str(base / "out")],
        capture_output=True, text=True, env=_env(), check=False, timeout=300)
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("RESULT ")), None)
    assert line, r.stdout + r.stderr
    return base, json.loads(line[len("RESULT "):])


def test_a_real_kit_run_makes_no_socket_or_process_call_that_the_process_can_see(observed_run):
    _, out = observed_run
    assert out["rc"] == 0
    # the guard's own permitted, observed local socketpair (if any) is the only event allowed
    stray = [e for e in out["events"] if e[0] != "socket.__new__"]
    assert stray == [], stray


def test_a_real_kit_run_says_what_it_observed(observed_run):
    base, _ = observed_run
    run = json.loads((base / "out" / "run.json").read_text())
    assert run["verdict"] == "complete"
    assert run["airgap"]["held"] is True
    assert "sys.addaudithook" in run["airgap"]["layers"]
    assert "observed" in run["airgap"]


def test_the_kit_import_closure_names_no_network_client_and_starts_no_process(observed_run):
    _, out = observed_run
    offenders: list[str] = []
    for file in out["loaded"]:
        rel = Path(file).resolve().relative_to(SRC.resolve()).as_posix()
        tree = ast.parse(Path(file).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for name in names:
                root = name.split(".")[0]
                if (root in FORBIDDEN_IMPORTS or root == "socket") \
                        and root not in MAY_IMPORT.get(rel, set()):
                    offenders.append(f"{rel}:{node.lineno} imports {name}")
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                    and (node.value.id, node.attr) in FORBIDDEN_CALLS:
                offenders.append(f"{rel}:{node.lineno} uses {node.value.id}.{node.attr}")
    assert offenders == [], offenders
    assert any(f.endswith("kit/enrol.py") for f in out["loaded"])  # the scan did cover the kit


# ---------------------------------------------------------------------------
# the OS-level control: a network namespace with no interface
# ---------------------------------------------------------------------------
NETNS_RUN = REPO / ".github" / "scripts" / "netns-run.sh"


def _netns_available() -> bool:
    """Whether this machine can create a network namespace with no interface (CI's script)."""
    probe = subprocess.run([str(NETNS_RUN), "true"], capture_output=True,  # noqa: S603
                           check=False)
    return probe.returncode == 0


def test_the_kit_runs_with_no_network_namespace_interface(tmp_path):
    if not _netns_available():
        if os.environ.get("NEURALBRIDGE_REQUIRE_NETNS") == "1":
            pytest.fail("NEURALBRIDGE_REQUIRE_NETNS=1 but no network namespace can be created "
                        "here (.github/scripts/netns-run.sh exits non-zero)")
        pytest.skip("no network namespace can be created here (set "
                    "NEURALBRIDGE_REQUIRE_NETNS=1 to make this a failure; CI sets it)")
    base = make_kit(tmp_path)
    control = subprocess.run(  # noqa: S603
        [str(NETNS_RUN), sys.executable, "-c",
         "import socket,sys\n"
         "try:\n socket.create_connection(('192.0.2.1', 9), timeout=1)\n"
         "except OSError as e:\n print('ISOLATED', e.errno)\n sys.exit(0)\n"
         "sys.exit(1)"], capture_output=True, text=True, check=False, env=_env())
    assert control.returncode == 0 and "ISOLATED" in control.stdout, control.stdout + control.stderr
    r = subprocess.run(  # noqa: S603
        [str(NETNS_RUN), sys.executable, "-m", "assurance", "kit", "run",
         str(base / "kit.json"), "--out", str(base / "out")],
        capture_output=True, text=True, check=False, env=_env(), timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    run = json.loads((base / "out" / "run.json").read_text())
    assert run["verdict"] == "complete" and run["airgap"]["held"] is True


def test_the_cold_start_job_runs_the_kit_in_a_namespace_and_does_not_skip_when_it_cannot():
    workflow = (REPO / ".github" / "workflows" / "assurance.yml").read_text(encoding="utf-8")
    assert "netns-run.sh python -m assurance kit run" in workflow
    assert "netns-run.sh python -m assurance kit check" in workflow
    assert "fail closed" in workflow
    script = NETNS_RUN.read_text(encoding="utf-8")
    assert "exit 97" in script and "exec unshare -rn" in script
    assert os.access(NETNS_RUN, os.X_OK)
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert 'NEURALBRIDGE_REQUIRE_NETNS: "1"' in ci


def test_the_script_fails_closed_when_it_cannot_make_a_namespace(tmp_path):
    # With `unshare` and `sudo` hidden from PATH the script must refuse (97), not run the command.
    marker = tmp_path / "ran"
    bare = tmp_path / "bin"
    bare.mkdir()
    for tool in ("bash", "true", "touch", "env", "id", "command"):
        found = shutil.which(tool)
        if found:
            (bare / tool).symlink_to(found)
    r = subprocess.run(  # noqa: S603
        [str(bare / "bash"), str(NETNS_RUN), "touch", str(marker)],
        capture_output=True, text=True, check=False, env={"PATH": str(bare)})
    assert r.returncode == 97, r.stdout + r.stderr
    assert not marker.exists()


# ---------------------------------------------------------------------------
# the kit itself, with a spawn injected where the review put one
# ---------------------------------------------------------------------------
def test_a_process_started_inside_the_kit_run_stops_it_and_is_named(tmp_path, monkeypatch):
    from assurance.kit import enrol
    from assurance.kit.enrol import KitConfig

    base = make_kit(tmp_path)
    real = enrol._enrol_one

    def spawning(*args, **kwargs):
        subprocess.run(["true"], check=False)  # noqa: S603, S607
        return real(*args, **kwargs)

    monkeypatch.setattr(enrol, "_enrol_one", spawning)
    with pytest.raises(AirgapError, match="subprocess.Popen"):
        enrol.run_kit(KitConfig.from_json(base / "kit.json"), tmp_path / "out")
