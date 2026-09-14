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

What the guard actually covers, stated precisely because a security reviewer
will ask and a vague answer is worse than a narrow one:

* It covers outbound connections made by **this Python process** through the
  ``socket`` module: ``connect``, ``connect_ex``, ``create_connection``,
  ``sendto``, and name resolution via ``getaddrinfo``. Everything in the Python
  ecosystem that speaks TCP or TLS — ``httpx``, ``requests``, ``urllib``,
  ``ssl``, every HTTP client worth naming — goes through that layer.
* It does **not** cover a subprocess. If this process spawns a command, that
  command has its own socket layer and this guard cannot see it. The kit
  spawns nothing, and that is enforced separately.
* It does **not** cover a C extension that opens a file descriptor itself
  without going through the ``socket`` module.
* It is a **proof of intent, not a containment boundary**. Code that wanted to
  evade it could. Containment is a firewall's job, and a firewall is what a
  plant already has. What this answers is whether the tool *tried*.

Those four sentences travel with the evidence. A claim whose limits are printed
next to it is worth more to a reviewer than a broader claim with none.
"""

from __future__ import annotations

import socket
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from ..core.errors import AssuranceError
from ..core.identity import format_utc, utc_now

__all__ = [
    "AIRGAP_LIMITS",
    "AirgapResult",
    "AirgapError",
    "NetworkAttempt",
    "no_network",
]

#: Carried verbatim into every record this guard produces, and from there into
#: the report. The limits are part of the claim, not a footnote to it.
AIRGAP_LIMITS: tuple[str, ...] = (
    "The guard covers outbound connections made by this Python process through "
    "the socket module (connect, connect_ex, create_connection, sendto, and "
    "getaddrinfo). Every Python HTTP and TLS client goes through that layer.",
    "It does not cover a subprocess, which has its own socket layer. This run "
    "spawned none.",
    "It does not cover a C extension that opens a socket file descriptor "
    "without going through the socket module.",
    "It records intent, it does not enforce containment. Code determined to "
    "evade it could. Containment is a firewall's job; this answers whether the "
    "tool tried.",
)

_LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "127.0.1.1"})


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
    """One refused connection, with enough context to find the line."""

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

    @property
    def held(self) -> bool:
        """True only if nothing in this process tried to reach the network."""
        return not self.attempts

    def summary(self) -> str:
        if self.held:
            return (
                f"No outbound connection was attempted between {self.armed_at} "
                f"and {self.released_at}."
            )
        return (
            f"{len(self.attempts)} outbound connection attempt(s) were refused "
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


def _caller() -> str:
    """The first frame outside this module. Where the attempt came from."""
    for frame in reversed(traceback.extract_stack()[:-2]):
        if not frame.filename.endswith("airgap.py"):
            return f"{frame.filename}:{frame.lineno} in {frame.name}"
    return "unknown"


@contextmanager
def no_network(*, allow_loopback: bool = False) -> Iterator[AirgapResult]:
    """Refuse every outbound connection for the duration of the block.

    Yields the :class:`AirgapResult` being filled in; it is complete once the
    block exits. ``allow_loopback`` permits connections to this machine only —
    needed if something in the run talks to a local service, recorded either
    way so that "offline" never quietly means "offline except one thing".

    The guard restores the original functions on the way out, including when
    the block raises, because a process left unable to open a socket after a
    library call is a far worse bug than the one being prevented.
    """
    result = AirgapResult(
        armed_at=format_utc(utc_now()), loopback_allowed=allow_loopback)

    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex
    real_create = socket.create_connection
    real_getaddrinfo = socket.getaddrinfo
    real_sendto = socket.socket.sendto

    def refuse(api: str, address: Any) -> None:
        host = _host_of(address)
        if allow_loopback and host in _LOOPBACK:
            result.loopback_used = True
            return
        attempt = NetworkAttempt(
            at=format_utc(utc_now()), api=api,
            target=_target_of(address), caller=_caller())
        result.attempts.append(attempt)
        raise AirgapError(
            f"refused {api} to {attempt.target} from {attempt.caller}. This run "
            "is under an airgap guard: nothing here may reach the network. If "
            "this call is legitimate, it belongs outside the guarded block, "
            "where the customer can see it."
        )

    def guarded_connect(self: Any, address: Any) -> Any:
        refuse("socket.connect", address)
        return real_connect(self, address)

    def guarded_connect_ex(self: Any, address: Any) -> Any:
        refuse("socket.connect_ex", address)
        return real_connect_ex(self, address)

    def guarded_create(address: Any, *args: Any, **kwargs: Any) -> Any:
        refuse("socket.create_connection", address)
        return real_create(address, *args, **kwargs)

    def guarded_sendto(self: Any, data: Any, *args: Any) -> Any:
        # sendto's address is the last positional argument; with flags it is
        # (data, flags, address), without it is (data, address).
        refuse("socket.sendto", args[-1] if args else "")
        return real_sendto(self, data, *args)

    def guarded_getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> Any:
        # Resolution is refused too. A tool that resolves a name has already
        # told a DNS server something, which is exactly what a plant's network
        # team is asking about.
        refuse("socket.getaddrinfo", (host, port))
        return real_getaddrinfo(host, port, *args, **kwargs)

    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = guarded_connect_ex  # type: ignore[method-assign]
    socket.socket.sendto = guarded_sendto  # type: ignore[method-assign]
    socket.create_connection = guarded_create
    socket.getaddrinfo = guarded_getaddrinfo
    try:
        yield result
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = real_connect_ex  # type: ignore[method-assign]
        socket.socket.sendto = real_sendto  # type: ignore[method-assign]
        socket.create_connection = real_create
        socket.getaddrinfo = real_getaddrinfo
        result.released_at = format_utc(utc_now())
