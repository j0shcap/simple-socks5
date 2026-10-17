"""
End-to-end fixtures: the real proxy (simple_socks5.server) and local origins, all in-process on loopback.

Every e2e test gets a fresh proxy and fresh origins on port 0; nothing is shared between tests.
Use tests/e2e/socks_client.py to talk to the proxy.

Fixtures (stable public API; regression tests build on them)
    make_proxy(*, auth_required=False, allow_loopback=True) -> ProxyHandle
        Sets SOCKS5_AUTH_REQUIRED / SOCKS5_USERNAME / SOCKS5_PASSWORD / SOCKS5_ALLOW_LOOPBACK with
        monkeypatch, then starts the server. The origins listen on loopback, so the destination
        policy is off unless allow_loopback=False. Credentials are E2E_USERNAME / E2E_PASSWORD.
        These are all read per connection, so a test may change them with monkeypatch.setenv(...)
        at any time.
        SOCKS5_MAX_CONNECTIONS is read when the server is constructed, so set it before calling.
    proxy                   make_proxy()
    auth_proxy              make_proxy(auth_required=True)
    echo_origin             Origin: echoes bytes until EOF
    echo_origin_v6          Origin on ::1 (skips when IPv6 loopback is unavailable)
    half_close_origin       Origin: reads until EOF, then replies b"GOT <n> BYTES"
    trickle_origin          Origin: sends 1 KiB every 100 ms until the peer goes away
    reply_then_read_origin  RecordingOrigin: sends b"BANNER" + FIN, then reports the sha256 of what it reads
    streaming_origin        RecordingOrigin: streams until a send fails, then reports time.monotonic()
    reset_origin            RecordingOrigin: sends 1 MiB, sends RST, then reports time.monotonic()
    http_origin             Origin: GET /bytes/<n> serves origins.deterministic_payload(n)
    udp_echo_origin         Origin: echoes each UDP datagram

RecordingOrigin(host, port, results)
    .results                queue.Queue the origin's handlers report into; use .get(timeout=...)

ProxyHandle(server, address)
    .connect() -> socket    raw TCP connection to the proxy; no SOCKS bytes sent

_e2e_leak_guard (autouse) fails a test that leaves behind a thread it started (after a 3 s grace
period) or that triggers a ResourceWarning in any thread at any point from setup to teardown.

update_loggers() is deliberately never called: the package logger keeps its NullHandler and
propagates, so records reach caplog and nothing is written to the console or SOCKS5_LOG_FILE.
"""

import gc
import queue
import socket
import socketserver
import threading
import time
import warnings
from collections.abc import Iterator
from contextlib import ExitStack
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar

import pytest

from simple_socks5.server import TCPProxyServer, ThreadingTCPServer
from tests.e2e.origins import (
    EchoHandler,
    HalfCloseHandler,
    Origin,
    OriginTCPServer,
    OriginTCPServerV6,
    PayloadHTTPHandler,
    RecordingOriginTCPServer,
    ReplyThenReadHandler,
    ResetMidTransferHandler,
    SplitReplyHandler,
    StreamUntilClosedHandler,
    TrickleHandler,
    UDPEchoHandler,
    serve_in_thread,
)
from tests.e2e.socks_client import TIMEOUT

E2E_USERNAME = "e2e-user"
E2E_PASSWORD = "e2e-pass"
THREAD_EXIT_GRACE = 3.0

ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class RecordingOrigin(Origin, Generic[ResultT]):
    results: queue.Queue[ResultT]


@dataclass(frozen=True)
class ProxyHandle:
    server: ThreadingTCPServer
    address: tuple[str, int]

    def connect(self) -> socket.socket:
        return socket.create_connection(self.address, timeout=TIMEOUT)


class MakeProxy(Protocol):
    def __call__(self, *, auth_required: bool = False, allow_loopback: bool = True) -> ProxyHandle: ...


def _bound_address(server: socketserver.TCPServer | socketserver.UDPServer) -> tuple[str, int]:
    address: tuple[str, int] = server.socket.getsockname()[:2]
    return address


@pytest.fixture(autouse=True)
def _e2e_leak_guard() -> Iterator[None]:
    threads_before = set(threading.enumerate())
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ResourceWarning)
        yield
        deadline = time.monotonic() + THREAD_EXIT_GRACE
        leftover = [t for t in threading.enumerate() if t not in threads_before]
        while leftover and time.monotonic() < deadline:
            time.sleep(0.01)
            leftover = [t for t in leftover if t.is_alive()]
        gc.collect()

    assert not leftover, f"threads still running after teardown: {[t.name for t in leftover]}"
    resource_warnings = [str(w.message) for w in caught if issubclass(w.category, ResourceWarning)]
    assert not resource_warnings, f"ResourceWarning during test: {resource_warnings}"


@pytest.fixture
def make_proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[MakeProxy]:
    with ExitStack() as stack:

        def _make_proxy(*, auth_required: bool = False, allow_loopback: bool = True) -> ProxyHandle:
            monkeypatch.setenv("SOCKS5_AUTH_REQUIRED", "true" if auth_required else "false")
            monkeypatch.setenv("SOCKS5_ALLOW_LOOPBACK", "true" if allow_loopback else "false")
            monkeypatch.setenv("SOCKS5_USERNAME", E2E_USERNAME)
            monkeypatch.setenv("SOCKS5_PASSWORD", E2E_PASSWORD)
            server = stack.enter_context(serve_in_thread(ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer)))
            return ProxyHandle(server, _bound_address(server))

        yield _make_proxy


@pytest.fixture
def proxy(make_proxy: MakeProxy) -> ProxyHandle:
    return make_proxy()


@pytest.fixture
def auth_proxy(make_proxy: MakeProxy) -> ProxyHandle:
    return make_proxy(auth_required=True)


def _serve_origin(server: socketserver.TCPServer | socketserver.UDPServer) -> Iterator[Origin]:
    with serve_in_thread(server):
        yield Origin(*_bound_address(server))


@pytest.fixture
def echo_origin() -> Iterator[Origin]:
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), EchoHandler))


@pytest.fixture
def echo_origin_v6() -> Iterator[Origin]:
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    try:
        server = OriginTCPServerV6(("::1", 0), EchoHandler)
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    yield from _serve_origin(server)


@pytest.fixture
def half_close_origin() -> Iterator[Origin]:
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), HalfCloseHandler))


def _serve_recording_origin(server: RecordingOriginTCPServer[ResultT]) -> Iterator[RecordingOrigin[ResultT]]:
    for origin in _serve_origin(server):
        yield RecordingOrigin(origin.host, origin.port, server.results)


@pytest.fixture
def reply_then_read_origin() -> Iterator[RecordingOrigin[str]]:
    yield from _serve_recording_origin(RecordingOriginTCPServer[str](("127.0.0.1", 0), ReplyThenReadHandler))


@pytest.fixture
def streaming_origin() -> Iterator[RecordingOrigin[float]]:
    yield from _serve_recording_origin(RecordingOriginTCPServer[float](("127.0.0.1", 0), StreamUntilClosedHandler))


@pytest.fixture
def reset_origin() -> Iterator[RecordingOrigin[float]]:
    yield from _serve_recording_origin(RecordingOriginTCPServer[float](("127.0.0.1", 0), ResetMidTransferHandler))


@pytest.fixture
def trickle_origin() -> Iterator[Origin]:
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), TrickleHandler))


@pytest.fixture
def split_reply_origin() -> Iterator[Origin]:
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), SplitReplyHandler))


@pytest.fixture
def http_origin() -> Iterator[Origin]:
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), PayloadHTTPHandler))


@pytest.fixture
def udp_echo_origin() -> Iterator[Origin]:
    yield from _serve_origin(socketserver.UDPServer(("127.0.0.1", 0), UDPEchoHandler))
