"""
Experimental changes to the proxy, applied by the launcher inside the benchmark's proxy process only, so an
optimization candidate can be measured before anyone implements it. The proxy's code is never modified.

A variant spec joins names with "+", e.g. "pumps+buf=1048576". Available:

    buf=N        relay reads of N bytes throughout, instead of 64 KiB growing to 256 KiB
    recv_into    recv_into() a buffer reused for the life of the relay, instead of recv() allocating each chunk
    blocking     blocking sockets with the write timeout as the kernel's SO_SNDTIMEO. A socket with a Python
                 timeout poll()s before every recv() and send(), on top of the selector's select()
    pumps        two threads, one per direction, blocking in recv() instead of a selector loop; implies blocking
    splice       pumps that move data with os.splice() through a pipe, never copying it into Python (Linux)
    stack=N      threading.stack_size(N) for every thread the proxy starts
    no_makefile  the connection handler without StreamRequestHandler's buffered rfile and wfile, which it never uses

These are sketches good enough to measure, not reviewed implementations.
"""

import contextlib
import fcntl
import os
import socket
import struct
import threading
from collections.abc import Callable

from simple_socks5.constants import RELAY_WRITE_TIMEOUT, TCP_SELECTOR_TIMEOUT
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


def _kernel_write_timeout(sock: socket.socket) -> None:
    sock.settimeout(None)
    seconds = int(RELAY_WRITE_TIMEOUT)
    # struct timeval is two longs on Linux, and a long and a padded int on macOS: with tv_usec 0 both read the same
    timeval = struct.pack("@ll", seconds, 0)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDTIMEO, timeval)


def _blocking(_: str) -> None:
    prepare = TCPRelay._prepare_sockets

    def prepare_blocking(self: TCPRelay) -> None:
        prepare(self)
        for sock in (self.client_connection, self.proxy_connection):
            _kernel_write_timeout(sock)

    _patch(TCPRelay, "_prepare_sockets", prepare_blocking)


def _buf(value: str) -> None:
    for name in ("RELAY_INITIAL_BUFFER_SIZE", "RELAY_BUFFER_SIZE"):
        _patch(tcp_relay, name, int(value))


def _stack(value: str) -> None:
    threading.stack_size(int(value))


def _no_makefile(_: str) -> None:
    def setup(self: TCPProxyServer) -> None:
        # What StreamRequestHandler.setup() does, minus makefile() and the timeout it leaves unset
        self.connection = self.request

    _patch(TCPProxyServer, "setup", setup)


def _recv_into(_: str) -> None:
    def listen_and_relay(self: TCPRelay) -> None:
        # The selector loop of TCPRelay.listen_and_relay, reading into a buffer per direction
        size = _buffer_size()
        buffers = {
            self.client_connection: memoryview(bytearray(size)),
            self.proxy_connection: memoryview(bytearray(size)),
        }
        open_readers = {self.client_connection, self.proxy_connection}
        try:
            self._prepare_sockets()
            while open_readers:
                events = self.selector.select(timeout=TCP_SELECTOR_TIMEOUT)
                if not events and (self.client_connection.fileno() == -1 or self.proxy_connection.fileno() == -1):
                    break
                for key, _ in events:
                    sock, other_sock = self._direction(key.fileobj)
                    buf = buffers[sock]
                    n = sock.recv_into(buf)
                    if not n:
                        self._half_close(sock, other_sock)
                        open_readers.discard(sock)
                        continue
                    other_sock.sendall(buf[:n])
                    if sock is self.client_connection:
                        self.bytes_up += n
                    else:
                        self.bytes_down += n
        except TimeoutError:
            tcp_relay.logger.warning("Relay write timed out after %s seconds", RELAY_WRITE_TIMEOUT)
        except OSError as e:
            tcp_relay.logger.debug("Relay ended: %s", e)
        finally:
            self._cleanup()

    _patch(TCPRelay, "listen_and_relay", listen_and_relay)


Pump = Callable[[socket.socket, socket.socket], int]


def _copy_pump(src: socket.socket, dst: socket.socket) -> int:
    buf = memoryview(bytearray(_buffer_size()))
    total = 0
    while n := src.recv_into(buf):
        dst.sendall(buf[:n])
        total += n
    return total


def _splice_pump(src: socket.socket, dst: socket.socket) -> int:
    size = _buffer_size()
    read_end, write_end = os.pipe()
    try:
        with contextlib.suppress(OSError):  # a smaller pipe only means more splice() calls
            fcntl.fcntl(write_end, fcntl.F_SETPIPE_SZ, size)  # type: ignore[attr-defined,unused-ignore]  # Linux
        total = 0
        while n := os.splice(src.fileno(), write_end, size):  # type: ignore[attr-defined,unused-ignore]  # Linux
            total += n
            while n:
                n -= os.splice(read_end, dst.fileno(), n)  # type: ignore[attr-defined,unused-ignore]  # Linux
        return total
    finally:
        os.close(read_end)
        os.close(write_end)


def _pumps_with(pump: Pump) -> None:
    def listen_and_relay(self: TCPRelay) -> None:
        def run(src: socket.socket, dst: socket.socket, upstream: bool) -> None:
            try:
                n = pump(src, dst)
                if upstream:
                    self.bytes_up += n
                else:
                    self.bytes_down += n
                dst.shutdown(socket.SHUT_WR)
            except OSError as e:
                tcp_relay.logger.debug("Relay ended: %s", e)
                for sock in (src, dst):  # wakes the other pump
                    with contextlib.suppress(OSError):
                        sock.shutdown(socket.SHUT_RDWR)

        try:
            self._prepare_sockets()
            for sock in (self.client_connection, self.proxy_connection):
                _kernel_write_timeout(sock)
            up = threading.Thread(target=run, args=(self.client_connection, self.proxy_connection, True), daemon=True)
            up.start()
            run(self.proxy_connection, self.client_connection, False)
            up.join()
        finally:
            self._cleanup()

    _patch(TCPRelay, "listen_and_relay", listen_and_relay)


def _pumps(_: str) -> None:
    _pumps_with(_copy_pump)


def _splice(_: str) -> None:
    if not hasattr(os, "splice"):
        raise ValueError("the splice variant needs Linux")
    _pumps_with(_splice_pump)


_VARIANTS: dict[str, Callable[[str], None]] = {
    "buf": _buf,
    "recv_into": _recv_into,
    "blocking": _blocking,
    "pumps": _pumps,
    "splice": _splice,
    "stack": _stack,
    "no_makefile": _no_makefile,
}
