"""
End-to-end fixtures: the real proxy (src.server) and local origins, all in-process on loopback.

Every e2e test gets a fresh proxy and fresh origins on port 0; nothing is shared between tests.
Use tests/e2e/socks_client.py to talk to the proxy.

Fixtures (stable public API; regression tests build on them)
    make_proxy(*, auth_required=False) -> ProxyHandle
        Sets SOCKS5_AUTH_REQUIRED / SOCKS5_USERNAME / SOCKS5_PASSWORD with monkeypatch, patches
        the import-time credentials in src.handlers.tcp, then starts the server. Env is set
        before start, so a test may monkeypatch.setenv(...) its own variables and then call it.
        Credentials are E2E_USERNAME / E2E_PASSWORD.
    proxy                   make_proxy()
    auth_proxy              make_proxy(auth_required=True)
    echo_origin             Origin: echoes bytes until EOF
    echo_origin_v6          Origin on ::1 (skips when IPv6 loopback is unavailable)
    half_close_origin       Origin: reads until EOF, then replies b"GOT <n> BYTES"
    trickle_origin          Origin: sends 1 KiB every 100 ms until the peer goes away
    http_origin             Origin: GET /bytes/<n> serves origins.deterministic_payload(n)
    udp_echo_origin         Origin: echoes each UDP datagram

ProxyHandle(server, address)
    .connect() -> socket    raw TCP connection to the proxy; no SOCKS bytes sent

_e2e_leak_guard (autouse) fails a test that leaves behind a thread it started (after a 3 s grace
period) or that triggers a ResourceWarning in any thread at any point from setup to teardown.

ProxyConfiguration is deliberately left uninitialised: loggers then get a NullHandler (records
still reach caplog) instead of writing errors.log into the working directory.
"""

import gc
import socket
import socketserver
import threading
import time
import warnings
from contextlib import ExitStack
from dataclasses import dataclass

import pytest

from src.server import TCPProxyServer, ThreadingTCPServer
from tests.e2e.origins import (
    EchoHandler,
    HalfCloseHandler,
    Origin,
    OriginTCPServer,
    OriginTCPServerV6,
    PayloadHTTPHandler,
    TrickleHandler,
    UDPEchoHandler,
    serve_in_thread,
)
from tests.e2e.socks_client import TIMEOUT

E2E_USERNAME = "e2e-user"
E2E_PASSWORD = "e2e-pass"
THREAD_EXIT_GRACE = 3.0


@dataclass(frozen=True)
class ProxyHandle:
    server: ThreadingTCPServer
    address: tuple[str, int]

    def connect(self) -> socket.socket:
        return socket.create_connection(self.address, timeout=TIMEOUT)


@pytest.fixture(autouse=True)
def _e2e_leak_guard():
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
def make_proxy(monkeypatch):
    with ExitStack() as stack:
        def _make_proxy(*, auth_required: bool = False) -> ProxyHandle:
            monkeypatch.setenv("SOCKS5_AUTH_REQUIRED", "true" if auth_required else "false")
            monkeypatch.setenv("SOCKS5_USERNAME", E2E_USERNAME)
            monkeypatch.setenv("SOCKS5_PASSWORD", E2E_PASSWORD)
            # Credentials are read at import time today; raising=False survives their removal.
            monkeypatch.setattr("src.handlers.tcp.USERNAME", E2E_USERNAME, raising=False)
            monkeypatch.setattr("src.handlers.tcp.PASSWORD", E2E_PASSWORD, raising=False)
            server = stack.enter_context(serve_in_thread(ThreadingTCPServer(("127.0.0.1", 0), TCPProxyServer)))
            return ProxyHandle(server, server.server_address)

        yield _make_proxy


@pytest.fixture
def proxy(make_proxy) -> ProxyHandle:
    return make_proxy()


@pytest.fixture
def auth_proxy(make_proxy) -> ProxyHandle:
    return make_proxy(auth_required=True)


def _serve_origin(server: socketserver.BaseServer):
    with serve_in_thread(server):
        host, port = server.server_address[:2]
        yield Origin(host, port)


@pytest.fixture
def echo_origin():
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), EchoHandler))


@pytest.fixture
def echo_origin_v6():
    if not socket.has_ipv6:
        pytest.skip("IPv6 unavailable")
    try:
        server = OriginTCPServerV6(("::1", 0), EchoHandler)
    except OSError:
        pytest.skip("IPv6 loopback unavailable")
    yield from _serve_origin(server)


@pytest.fixture
def half_close_origin():
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), HalfCloseHandler))


@pytest.fixture
def trickle_origin():
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), TrickleHandler))


@pytest.fixture
def http_origin():
    yield from _serve_origin(OriginTCPServer(("127.0.0.1", 0), PayloadHTTPHandler))


@pytest.fixture
def udp_echo_origin():
    yield from _serve_origin(socketserver.UDPServer(("127.0.0.1", 0), UDPEchoHandler))
