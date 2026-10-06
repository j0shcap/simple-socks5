"""
Handshake deadline (SOCKS5_HANDSHAKE_TIMEOUT) and outbound connect timeout (SOCKS5_CONNECT_TIMEOUT).

Both are read per connection, so each test sets a short value before talking to the proxy.
"""
import select
import socket
import time
from contextlib import ExitStack, contextmanager

import pytest

from src.constants import DEFAULT_MAX_CONNECTIONS
from tests.e2e import socks_client as sc
from tests.e2e.conftest import E2E_PASSWORD, E2E_USERNAME

TOLERANCE = 1.0  # seconds allowed past a timeout
BLACKHOLE = ("10.255.255.1", 80)


def _seconds_until_closed(sock: socket.socket, started: float) -> float:
    sc.assert_closed(sock)
    return time.monotonic() - started


@contextmanager
def _fd_limit_at_least(wanted: int):
    resource = pytest.importorskip("resource")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft >= wanted:
        yield
        return
    if hard != resource.RLIM_INFINITY and hard < wanted:
        pytest.skip(f"RLIMIT_NOFILE hard limit {hard} is below {wanted}")
    resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_idle_connection_closed(monkeypatch, proxy):
    monkeypatch.setenv("SOCKS5_HANDSHAKE_TIMEOUT", "0.5")
    with proxy.connect() as sock:
        elapsed = _seconds_until_closed(sock, time.monotonic())
    assert 0.4 <= elapsed <= 0.5 + TOLERANCE


def test_flood_slots_freed(monkeypatch, proxy, echo_origin):
    monkeypatch.setenv("SOCKS5_HANDSHAKE_TIMEOUT", "1.0")
    # Client and server ends of every idle connection share this process's fd table
    with _fd_limit_at_least(4 * DEFAULT_MAX_CONNECTIONS + 256), ExitStack() as stack:
        started = time.monotonic()
        idle = [stack.enter_context(proxy.connect()) for _ in range(DEFAULT_MAX_CONNECTIONS)]
        with proxy.connect() as rejected:
            sc.assert_closed(rejected)

        while True:
            try:
                with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
                    tunnel.sendall(b"ping")
                    assert sc.recv_exact(tunnel, 4) == b"ping"
                break
            except (sc.Socks5Error, EOFError, ConnectionError):
                assert time.monotonic() - started <= 1.0 + TOLERANCE, "slots not freed by the deadline"
                time.sleep(0.05)
        assert time.monotonic() - started <= 1.0 + TOLERANCE
        for sock in idle:
            sc.assert_closed(sock)


def test_drip_feed_greeting_closed_at_deadline(monkeypatch, proxy):
    monkeypatch.setenv("SOCKS5_HANDSHAKE_TIMEOUT", "1.0")
    greeting = sc.build_greeting(range(1, 256))  # 257 bytes: far more than fit before the deadline
    with proxy.connect() as sock:
        started = time.monotonic()
        for byte in greeting:
            try:
                sock.sendall(bytes([byte]))
            except ConnectionError:
                break
            readable, _, _ = select.select([sock], [], [], 0.6)
            if readable:
                break
        elapsed = _seconds_until_closed(sock, started)
    assert elapsed <= 1.0 + TOLERANCE


def test_auth_handshake_succeeds_under_deadline(monkeypatch, auth_proxy, echo_origin):
    monkeypatch.setenv("SOCKS5_HANDSHAKE_TIMEOUT", "1.0")
    credentials = (E2E_USERNAME, E2E_PASSWORD)
    with sc.open_tunnel(auth_proxy.address, "127.0.0.1", echo_origin.port, credentials=credentials) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"


def test_mid_auth_timeout_sends_nothing(monkeypatch, auth_proxy):
    monkeypatch.setenv("SOCKS5_HANDSHAKE_TIMEOUT", "0.5")
    with auth_proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS
        sock.sendall(b"\x01\x05e2e")  # ULEN says 5, only 3 bytes follow

        assert sc.recv_until_eof(sock) == b""


def test_relay_outlives_handshake_deadline(monkeypatch, proxy, echo_origin):
    monkeypatch.setenv("SOCKS5_HANDSHAKE_TIMEOUT", "0.5")
    with sc.open_tunnel(proxy.address, "127.0.0.1", echo_origin.port) as tunnel:
        time.sleep(1.0)
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"


def _blackhole_times_out() -> bool:
    with socket.socket() as probe:
        probe.settimeout(0.3)
        try:
            probe.connect(BLACKHOLE)
        except TimeoutError:
            return True
        except OSError:
            return False
    return False


def test_blackhole_connect_replies_host_unreachable(monkeypatch, proxy):
    if not _blackhole_times_out():
        pytest.skip(f"{BLACKHOLE[0]} is not a blackhole on this network (connect fails or succeeds fast)")
    monkeypatch.setenv("SOCKS5_CONNECT_TIMEOUT", "0.5")
    with proxy.connect() as sock:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        started = time.monotonic()
        sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, *BLACKHOLE)

        assert sc.read_reply(sock).rep == sc.REP_HOST_UNREACHABLE
        assert time.monotonic() - started <= 0.5 + TOLERANCE
        sc.assert_closed(sock)
