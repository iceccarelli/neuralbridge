"""Proving a tool did not phone home, rather than promising it.

Every vendor selling software that runs inside a plant says the same sentence:
"it works offline, nothing leaves your network". Plant IT has heard it before,
cannot check it, and therefore treats it as worth nothing — which is the correct
response to an unverifiable claim, and the reason a pilot takes eleven weeks to
get through a security review instead of an afternoon.

This module makes the sentence checkable. It arms a guard over the socket layer
for the duration of a run, refuses every outbound connection, records any
attempt with the line of code that made it, and produces a result that is sealed
into the customer's own evidence ledger alongside the work. Afterwards the
question "did this tool send anything anywhere" has an answer with a hash on it,
in a file the customer holds, which is a different kind of object from a bullet
point on a datasheet.

The rule this repository runs on — *if it is not gated in code, it is not on the
pricing page* — applied to the claim that sells the kit.

Two layers, because one is not enough:

1. **The socket module.** For the run, the functions a Python program uses to
   reach a network (``connect``, ``connect_ex``, ``create_connection``,
   ``sendto``, ``sendmsg``, ``getaddrinfo``, ``gethostbyname``/``_ex``/``addr``,
   ``getnameinfo``) are replaced by ones that refuse and record. This gives a
   named API and the calling line.
2. **A Python audit hook** (:func:`sys.addaudithook`). The interpreter itself
   announces every socket creation, connection, send, bind and name lookup, every
   subprocess and every ``exec``/``spawn``/``fork``, whichever module asked —
   including the ``_socket`` base class that layer 1 cannot patch. The hook
   cannot be removed once installed; it is inert outside an armed block.

What the guard covers, stated precisely because a security reviewer will ask and
a vague answer is worse than a narrow one:

* **Network.** Outbound connections, datagrams, name resolution and the creation
  of IP sockets by **this Python process**, by any route CPython announces.
  Everything in the Python ecosystem that speaks TCP, UDP or TLS goes through it.
* **Processes.** Creating a process from this one (``subprocess``,
  ``os.system``, ``os.exec*``, ``os.spawn*``, ``os.posix_spawn``, ``os.fork``) is
  refused and recorded. A command that already existed, or is started by
  something else, is outside it.
* **What was seen but allowed** (a local ``socketpair``, loopback when the caller
  asked for it) is listed in the record, so "held" never hides what the process
  did.
* It does **not** cover native code that reaches the kernel without going through
  CPython — a C extension calling ``socket(2)``, ``ctypes``/FFI, a loaded library.
* It is a **proof of intent, not a containment boundary**. The guard lives in the
  process it watches: code in that process determined to evade it (by flipping the
  module's own state) could. The real control is the operating system — run the kit
  in a network namespace with no interface (``unshare -rn``), or behind the plant's
  firewall. CI runs it that way. What this answers is whether the tool *tried*.

Those sentences travel with the evidence. A claim whose limits are printed next
to it is worth more to a reviewer than a broader claim with none.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import AssuranceError
from ..core.identity import format_utc, utc_now

__all__ = [
    "AIRGAP_LAYERS",
    "AIRGAP_LIMITS",
    "AirgapResult",
    "AirgapError",
    "NetworkAttempt",
    "no_network",
]

#: The two layers a record is produced under, named in the record itself.
AIRGAP_LAYERS: tuple[str, ...] = ("socket module functions", "sys.addaudithook")

#: Carried verbatim into every record this guard produces, and from there into
#: the report. The limits are part of the claim, not a footnote to it.
AIRGAP_LIMITS: tuple[str, ...] = (
    "The guard covers outbound connections, datagrams, name resolution and the "
    "creation of IP sockets made by this Python process: the functions of the "
    "socket module are replaced for the run (connect, connect_ex, "
    "create_connection, sendto, sendmsg, getaddrinfo, gethostbyname, "
    "gethostbyaddr, getnameinfo), and a Python audit hook refuses the same "
    "operations as the interpreter announces them, including calls made on the "
    "_socket module directly. Every Python HTTP and TLS client goes through "
    "that layer.",
    "It refuses and records creating a process from this one (subprocess, "
    "os.system, os.exec*, os.spawn*, os.posix_spawn, os.fork). A subprocess "
    "started some other way, or one that already existed, has its own socket "
    "layer which this guard cannot see. This run's record lists what was "
    "observed; anything refused makes it not hold.",
    "It does not cover native code that reaches the kernel without going "
    "through CPython: a C extension calling socket(2) itself, ctypes or FFI "
    "calls, a loaded library.",
    "It records intent, it does not enforce containment. The guard and the audit "
    "hook live in the process they watch, so code in that process determined to "
    "evade them could, and the audit hook cannot defend against a hostile "
    "process. Containment is the operating system's job: run the kit in a "
    "network namespace with no interface (unshare -rn) or behind the plant's "
    "firewall. This answers whether the tool tried.",
)

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "127.0.1.1"})

#: Audit events that create a process. Never allowed, loopback or not.
_PROCESS_EVENTS = frozenset({
    "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
    "os.fork", "os.forkpty", "pty.spawn",
})
#: Audit events that reach, or ask about, a network address (args: see _audit_target).
_NETWORK_EVENTS = frozenset({
    "socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind",
    "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
    "socket.getnameinfo",
})
#: Seen and listed, never refused on their own: the operation that matters follows
#: through one of the events above.
_OBSERVED_EVENTS = frozenset({
    "socket.getservbyname", "socket.getservbyport", "urllib.Request",
    "http.client.connect", "http.client.send", "smtplib.connect", "ftplib.connect",
    "ctypes.dlopen", "ctypes.call_function",
})
_WATCHED = _PROCESS_EVENTS | _NETWORK_EVENTS | _OBSERVED_EVENTS | {"socket.__new__"}
#: Address families whose sockets reach a network. AF_UNIX (1) is local IPC.
_IP_FAMILIES = frozenset({2, 10})  # AF_INET, AF_INET6

#: How many allowed-but-observed events one record keeps; the rest are counted.
MAX_OBSERVED = 200


class AirgapError(AssuranceError):
    """Something in this process tried to open a connection. It did not succeed.

    Raised at the point of the attempt so the traceback names the line, rather
    than being collected quietly and reported later — a caller that swallows
    this and carries on has produced a run whose airgap record is a lie.

    Deliberately **not** an :class:`OSError`. Every HTTP client in existence
    catches ``OSError`` and treats it as a transient network failure: it would
    retry three times, turning one refusal into three records of the same
    mistake, or fall back to a cached path and carry on as though nothing had
    happened. A refusal by this guard is not a network problem and must not be
    mistakable for one, so it travels up through every library's error handling
    untouched and stops the run.
    """


@dataclass(frozen=True)
class NetworkAttempt:
    """One refused connection (or process), with enough context to find the line."""

    at: str
    api: str
    target: str
    caller: str

    def to_dict(self) -> dict[str, Any]:
        return {"at": self.at, "api": self.api, "target": self.target,
                "caller": self.caller}


@dataclass
class AirgapResult:
    """What the guard saw between arming and release."""

    armed_at: str
    released_at: str = ""
    attempts: list[NetworkAttempt] = field(default_factory=list)
    loopback_allowed: bool = False
    loopback_used: bool = False
    #: Operations the guard saw and allowed (a local socketpair, loopback when asked for).
    observed: list[dict[str, str]] = field(default_factory=list)
    observed_dropped: int = 0

    @property
    def held(self) -> bool:
        """True only if nothing in this process tried to reach the network or start a process."""
        return not self.attempts

    def summary(self) -> str:
        if self.held:
            return (
                f"No outbound connection was attempted between {self.armed_at} "
                f"and {self.released_at}."
            )
        return (
            f"{len(self.attempts)} outbound connection or process attempt(s) were refused "
            f"between {self.armed_at} and {self.released_at}."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "armed_at": self.armed_at,
            "released_at": self.released_at,
            "held": self.held,
            "attempts": [a.to_dict() for a in self.attempts],
            "loopback_allowed": self.loopback_allowed,
            "loopback_used": self.loopback_used,
            "layers": list(AIRGAP_LAYERS),
            "observed": list(self.observed),
            "observed_dropped": self.observed_dropped,
            "summary": self.summary(),
            "limits": list(AIRGAP_LIMITS),
        }


def _target_of(address: Any) -> str:
    if isinstance(address, (tuple, list)) and address:
        host = str(address[0])
        port = address[1] if len(address) > 1 else ""
        return f"{host}:{port}" if port != "" else host
    return str(address)


def _host_of(address: Any) -> str:
    if isinstance(address, (tuple, list)) and address:
        return str(address[0])
    return str(address)


_STDLIB_DIR = os.path.dirname(os.__file__)
_PLUMBING = frozenset({"socket.py", "subprocess.py", "os.py", "pty.py"})


def _caller() -> str:
    """The first frame outside this module (and the standard library's own plumbing for
    the call). Where the attempt came from."""
    for frame in reversed(traceback.extract_stack()[:-2]):
        if frame.filename.endswith("airgap.py"):
            continue
        if os.path.dirname(frame.filename) == _STDLIB_DIR \
                and os.path.basename(frame.filename) in _PLUMBING:
            continue
        return f"{frame.filename}:{frame.lineno} in {frame.name}"
    return "unknown"


class _Guard:
    """One armed block: its result and the policy it applies."""

    def __init__(self, result: AirgapResult, allow_loopback: bool) -> None:
        self.result = result
        self.allow_loopback = allow_loopback

    def refuse(self, api: str, address: Any, *, network: bool = True) -> None:
        """Record and raise, unless the address is loopback and the caller allowed it."""
        host = _host_of(address)
        if network and self.allow_loopback and host in _LOOPBACK:
            self.result.loopback_used = True
            return
        attempt = NetworkAttempt(
            at=format_utc(utc_now()), api=api,
            target=_target_of(address), caller=_caller())
        self.result.attempts.append(attempt)
        raise AirgapError(
            f"refused {api} to {attempt.target} from {attempt.caller}. This run "
            "is under an airgap guard: nothing here may reach the network or start "
            "a process. If this call is legitimate, it belongs outside the guarded "
            "block, where the customer can see it."
        )

    def observe(self, event: str, detail: str) -> None:
        if len(self.result.observed) >= MAX_OBSERVED:
            self.result.observed_dropped += 1
            return
        self.result.observed.append({
            "at": format_utc(utc_now()), "event": event, "detail": detail[:160],
            "outcome": "allowed", "caller": _caller()})


_ACTIVE: list[_Guard] = []
_STATE_LOCK = threading.Lock()
_HOOK_INSTALLED = False


def _audit(event: str, args: tuple[Any, ...]) -> None:
    """The audit hook. Inert unless a guard is armed; raises only :class:`AirgapError`."""
    if not _ACTIVE or event not in _WATCHED:
        return
    for guard in tuple(_ACTIVE):
        if event in _PROCESS_EVENTS:
            guard.refuse(event, args[0] if args else event, network=False)
        elif event == "socket.__new__":
            family = args[1] if len(args) > 1 else None
            if int(family) in _IP_FAMILIES if isinstance(family, int) else False:
                # Making an IP socket is not yet reaching anything; with loopback allowed the
                # connect that follows is judged on its address. Without it, no IP socket.
                if not guard.allow_loopback:
                    guard.refuse(event, "IP socket", network=False)
                guard.observe(event, "IP socket (loopback allowed)")
            else:
                guard.observe(event, f"family={family!r}")
        elif event in _NETWORK_EVENTS:
            guard.refuse(event, _audit_target(event, args))
        else:
            guard.observe(event, repr(args))


def _audit_target(event: str, args: tuple[Any, ...]) -> Any:
    """The address an audit event is about. ``socket.*`` events lead with the socket
    object, except name lookups, which lead with the name."""
    if event in ("socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind"):
        return args[1] if len(args) > 1 else ""
    if event == "socket.getaddrinfo":
        return (args[0] if args else "", args[1] if len(args) > 1 else "")
    if event == "socket.getnameinfo":
        return args[0] if args else ""
    return args[0] if args else ""


def _install_hook() -> None:
    global _HOOK_INSTALLED
    with _STATE_LOCK:
        if not _HOOK_INSTALLED:
            sys.addaudithook(_audit)
            _HOOK_INSTALLED = True


@contextmanager
def no_network(*, allow_loopback: bool = False) -> Iterator[AirgapResult]:
    """Refuse every outbound connection and process creation for the duration of the block.

    Yields the :class:`AirgapResult` being filled in; it is complete once the
    block exits. ``allow_loopback`` permits connections to this machine only —
    needed if something in the run talks to a local service, recorded either
    way so that "offline" never quietly means "offline except one thing".
    Creating a process is refused whatever ``allow_loopback`` says.

    The guard restores the original functions on the way out, including when
    the block raises, because a process left unable to open a socket after a
    library call is a far worse bug than the one being prevented. The audit
    hook cannot be uninstalled (the interpreter offers no way); it does nothing
    once the block has exited.
    """
    result = AirgapResult(
        armed_at=format_utc(utc_now()), loopback_allowed=allow_loopback)
    guard = _Guard(result, allow_loopback)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo
    real_sendto = socket.socket.sendto
    real_sendmsg = socket.socket.sendmsg
    real_gethostbyname = socket.gethostbyname
    real_gethostbyname_ex = socket.gethostbyname_ex
    real_gethostbyaddr = socket.gethostbyaddr
    real_getnameinfo = socket.getnameinfo

    def guarded_connect(self: Any, address: Any) -> Any:
        guard.refuse("socket.connect", address)
        return real_connect(self, address)

    def guarded_connect_ex(self: Any, address: Any) -> Any:
        guard.refuse("socket.connect_ex", address)
        return real_connect_ex(self, address)

    def guarded_create(address: Any, *args: Any, **kwargs: Any) -> Any:
        guard.refuse("socket.create_connection", address)
        return real_create(address, *args, **kwargs)

    def guarded_sendto(self: Any, data: Any, *args: Any) -> Any:
        # sendto's address is the last positional argument; with flags it is
        # (data, flags, address), without it is (data, address).
        guard.refuse("socket.sendto", args[-1] if args else "")
        return real_sendto(self, data, *args)

    def guarded_sendmsg(self: Any, buffers: Any, *args: Any) -> Any:
        # (buffers, ancdata, flags, address): the address is optional on a connected socket.
        guard.refuse("socket.sendmsg", args[2] if len(args) > 2 else "")
        return real_sendmsg(self, buffers, *args)

    def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        # Resolution is refused too. A tool that resolves a name has already
        # told a DNS server something, which is exactly what a plant's network
        # team is asking about.
        guard.refuse("socket.getaddrinfo", (host, port))
        return real_getaddrinfo(host, port, *args, **kwargs)

    def guarded_gethostbyname(name: Any) -> Any:
        guard.refuse("socket.gethostbyname", name)
        return real_gethostbyname(name)

    def guarded_gethostbyname_ex(name: Any) -> Any:
        guard.refuse("socket.gethostbyname_ex", name)
        return real_gethostbyname_ex(name)

    def guarded_gethostbyaddr(address: Any) -> Any:
        guard.refuse("socket.gethostbyaddr", address)
        return real_gethostbyaddr(address)

    def guarded_getnameinfo(sockaddr: Any, flags: Any) -> Any:
        guard.refuse("socket.getnameinfo", sockaddr)
        return real_getnameinfo(sockaddr, flags)

    _install_hook()
    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = guarded_sendto  # type: ignore[method-assign]
    socket.socket.sendmsg = guarded_sendmsg  # type: ignore[method-assign]
    socket.create_connection = guarded_create
    socket.getaddrinfo = guarded_getaddrinfo
    socket.gethostbyname = guarded_gethostbyname
    socket.gethostbyname_ex = guarded_gethostbyname_ex
    socket.gethostbyaddr = guarded_gethostbyaddr
    socket.getnameinfo = guarded_getnameinfo
    with _STATE_LOCK:
        _ACTIVE.append(guard)
    try:
        yield result
    finally:
        with _STATE_LOCK:
            _ACTIVE.remove(guard)
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex  # type: ignore[method-assign]
        socket.socket.sendto = real_sendto  # type: ignore[method-assign]
        socket.socket.sendmsg = real_sendmsg  # type: ignore[method-assign]
        socket.create_connection = real_create
        socket.getaddrinfo = real_getaddrinfo
        socket.gethostbyname = real_gethostbyname
        socket.gethostbyname_ex = real_gethostbyname_ex
        socket.gethostbyaddr = real_gethostbyaddr
        socket.getnameinfo = real_getnameinfo
        result.released_at = format_utc(utc_now())
