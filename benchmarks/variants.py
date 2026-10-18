"""
Experimental changes to the proxy, applied by the launcher inside the benchmark's proxy process only, so an
optimization candidate can be measured before anyone implements it. The proxy's code is never modified.

A variant spec joins names with "+", e.g. "recv_into+buf=1048576". Available:

    buf=N        relay reads of N bytes throughout, instead of 64 KiB growing to 256 KiB
    recv_into    each direction of a relay recv_into() a buffer reused for its life, instead of recv() allocating each
                 chunk
    splice       each direction of a relay moves data with os.splice() through a pipe, never copying it into Python
                 (Linux)
    stack=N      a thread stack of N bytes instead of THREAD_STACK_SIZE
    no_makefile  the connection handler without StreamRequestHandler's buffered rfile and wfile, which it never uses

These are sketches good enough to measure, not reviewed implementations. recv_into and splice replace only how
TCPRelay._move copies a chunk; the relay's threads, half-close, counting and timeouts stay its own.
"""

import contextlib
import fcntl
import os
import socket
from collections.abc import Callable

from simple_socks5 import main
from simple_socks5.relays import tcp_relay
from simple_socks5.relays.tcp_relay import TCPRelay
from simple_socks5.server import TCPProxyServer


def apply(spec: str) -> None:
    for part in filter(None, spec.split("+")):
        name, _, value = part.partition("=")
        if name not in _VARIANTS:
            raise ValueError(f"unknown variant {name!r}; choose from {', '.join(_VARIANTS)}")
        _VARIANTS[name](value)


def _patch(owner: object, name: str, value: object) -> None:
    if not hasattr(owner, name):
        raise AttributeError(f"{owner!r} has no {name}: the variant no longer matches the proxy's code")
    setattr(owner, name, value)


def _buffer_size() -> int:
    return int(vars(tcp_relay)["RELAY_BUFFER_SIZE"])  # read at call time, so buf=N applies


def _buf(value: str) -> None:
    for name in ("RELAY_INITIAL_BUFFER_SIZE", "RELAY_BUFFER_SIZE"):
        _patch(tcp_relay, name, int(value))


def _stack(value: str) -> None:
    _patch(main, "THREAD_STACK_SIZE", int(value))  # main() sets it before the server starts


def _no_makefile(_: str) -> None:
    def setup(self: TCPProxyServer) -> None:
        # What StreamRequestHandler.setup() does, minus makefile() and the timeout it leaves unset
        self.connection = self.request

    _patch(TCPProxyServer, "setup", setup)


def _per_direction(relay: TCPRelay, name: str, src: socket.socket, make: Callable[[], object]) -> object:
    """What a variant keeps for one direction of a relay, made on first use. Each direction has one thread."""
    kept: dict[socket.socket, object] = relay.__dict__.setdefault(name, {})
    if src not in kept:
        kept[src] = make()
    return kept[src]


def _recv_into(_: str) -> None:
    def move(self: TCPRelay, src: socket.socket, dst: socket.socket, size: int) -> int:
        buf = _per_direction(self, "_buffers", src, lambda: memoryview(bytearray(_buffer_size())))
        assert isinstance(buf, memoryview)
        n = src.recv_into(buf, size)
        if n:
            self._send_all(dst, buf[:n])
        return n

    _patch(TCPRelay, "_move", move)


def _pipe(size: int) -> tuple[int, int]:
    read_end, write_end = os.pipe()
    with contextlib.suppress(OSError):  # a smaller pipe only means more splice() calls
        fcntl.fcntl(write_end, fcntl.F_SETPIPE_SZ, size)  # type: ignore[attr-defined,unused-ignore]  # Linux
    return read_end, write_end


def _splice(_: str) -> None:
    if not hasattr(os, "splice"):
        raise ValueError("the splice variant needs Linux")
    cleanup = TCPRelay._cleanup

    def move(self: TCPRelay, src: socket.socket, dst: socket.socket, size: int) -> int:
        pipe = _per_direction(self, "_pipes", src, lambda: _pipe(_buffer_size()))
        assert isinstance(pipe, tuple)
        read_end, write_end = pipe
        n: int = os.splice(src.fileno(), write_end, size)  # type: ignore[attr-defined,unused-ignore]  # Linux
        left = n
        try:
            while left:
                left -= os.splice(read_end, dst.fileno(), left)  # type: ignore[attr-defined,unused-ignore]  # Linux
        except BlockingIOError as e:  # SO_SNDTIMEO, not the read side's idle check
            raise tcp_relay._WriteTimeoutError from e
        return n

    def cleanup_pipes(self: TCPRelay) -> None:
        cleanup(self)
        for read_end, write_end in self.__dict__.get("_pipes", {}).values():
            os.close(read_end)
            os.close(write_end)

    _patch(TCPRelay, "_move", move)
    _patch(TCPRelay, "_cleanup", cleanup_pipes)


_VARIANTS: dict[str, Callable[[str], None]] = {
    "buf": _buf,
    "recv_into": _recv_into,
    "splice": _splice,
    "stack": _stack,
    "no_makefile": _no_makefile,
}
