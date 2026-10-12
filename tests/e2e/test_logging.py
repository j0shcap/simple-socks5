"""
What the proxy logs: one CONNECTION and one CLOSED line per connection, nothing above DEBUG for a client that
hangs up mid-handshake (the healthcheck included), each failure at its level (client errors at DEBUG, destination
failures at INFO, policy and login warnings at WARNING, only bugs at ERROR), and at process level no colour off a TTY
and no errors.log.
"""

import logging
import re
import signal
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple, NoReturn

import pytest

from simple_socks5 import healthcheck
from simple_socks5.server import TCPProxyServer
from tests.e2e import socks_client as sc
from tests.e2e.app_process import run_app
from tests.e2e.conftest import E2E_PASSWORD, E2E_USERNAME, MakeProxy, ProxyHandle
from tests.e2e.origins import Origin
from tests.e2e.test_timeouts import BLACKHOLE, blackhole_times_out

DOWNLOAD_SIZE = 10 * 1024 * 1024
REQUEST = b"GET /bytes/%d HTTP/1.0\r\n\r\n" % DOWNLOAD_SIZE


def _wait_for_closed_line(caplog: pytest.LogCaptureFixture, proxy: ProxyHandle) -> None:
    """CLOSED is logged on the handler thread after the client has already read EOF."""
    deadline = time.monotonic() + 5
    while not any(r.getMessage().startswith("CLOSED |") for r in caplog.records):
        assert time.monotonic() < deadline, "no CLOSED line within 5 s"
        time.sleep(0.01)
    assert proxy.server.wait_for_connections(5)


def _download(proxy: ProxyHandle, http_origin: Origin) -> bytes:
    with sc.open_tunnel(proxy.address, "127.0.0.1", http_origin.port) as tunnel:
        tunnel.sendall(REQUEST)
        return sc.recv_until_eof(tunnel)


def test_10mb_download_logs_one_connection_and_one_closed_line(
    proxy: ProxyHandle, http_origin: Origin, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="simple_socks5")

    response = _download(proxy, http_origin)
    _wait_for_closed_line(caplog, proxy)

    messages = [r.getMessage() for r in caplog.records if r.name.startswith("simple_socks5")]
    assert [m.split(" |")[0] for m in messages] == ["CONNECTION", "CLOSED"]
    counts = re.search(r"up=(\d+) B down=(\d+) B", messages[1])
    assert counts is not None, messages[1]
    up, down = map(int, counts.groups())
    assert up == len(REQUEST)
    assert down == len(response) > DOWNLOAD_SIZE


def test_auth_connect_logs_only_connection_and_closed_at_info(
    auth_proxy: ProxyHandle, echo_origin: Origin, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger="simple_socks5")

    credentials = (E2E_USERNAME, E2E_PASSWORD)
    with sc.open_tunnel(auth_proxy.address, "127.0.0.1", echo_origin.port, credentials=credentials) as tunnel:
        tunnel.sendall(b"ping")
        assert sc.recv_exact(tunnel, 4) == b"ping"
    _wait_for_closed_line(caplog, auth_proxy)

    messages = [r.getMessage() for r in caplog.records if r.name.startswith("simple_socks5")]
    assert [m.split(" |")[0] for m in messages] == ["CONNECTION", "CLOSED"]


@pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO])
def test_no_per_chunk_lines_at_any_level(
    proxy: ProxyHandle, http_origin: Origin, caplog: pytest.LogCaptureFixture, level: int
) -> None:
    caplog.set_level(level, logger="simple_socks5")

    _download(proxy, http_origin)
    _wait_for_closed_line(caplog, proxy)

    records = [r for r in caplog.records if r.name.startswith("simple_socks5")]
    assert not [r for r in records if "RELAY" in r.getMessage()]
    # A 10 MiB download is 160+ relay buffers; a handful of lines means none of them was logged
    assert len(records) < 10


@pytest.fixture
def wait_handled(monkeypatch: pytest.MonkeyPatch) -> Callable[[ProxyHandle], None]:
    """Returns wait(proxy): blocks until the proxy has finished with one connection and logged everything for it."""
    finished = threading.Semaphore(0)
    original_finish = TCPProxyServer.finish

    def finish(self: TCPProxyServer) -> None:
        try:
            original_finish(self)
        finally:
            finished.release()

    monkeypatch.setattr(TCPProxyServer, "finish", finish)

    def wait(proxy: ProxyHandle) -> None:
        assert finished.acquire(timeout=5), "the proxy never finished the connection"
        # handle_error() and untracking run after finish()
        assert proxy.server.wait_for_connections(5)

    return wait


def _reset_on_close(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def _greet_then_reset(sock: socket.socket) -> None:
    sc.greet(sock, [sc.METHOD_NO_AUTH])
    _reset_on_close(sock)


def _greet_then_partial_auth(sock: socket.socket) -> None:
    sc.greet(sock, [sc.METHOD_USERPASS])
    sock.sendall(b"\x01\x05us")


def _partial_request_then_reset(sock: socket.socket) -> None:
    sc.greet(sock, [sc.METHOD_NO_AUTH])
    sock.sendall(b"\x05\x01\x00\x01\x7f")
    _reset_on_close(sock)


MID_HANDSHAKE_CASES: dict[str, tuple[bool, Callable[[socket.socket], object]]] = {
    "after connect": (False, lambda _sock: None),
    "partial greeting": (False, lambda sock: sock.sendall(b"\x05")),
    "after method reply": (False, lambda sock: sc.greet(sock, [sc.METHOD_NO_AUTH])),
    "after method reply, RST": (False, _greet_then_reset),
    "no acceptable method, auth required": (True, lambda sock: sc.greet(sock, [sc.METHOD_NO_AUTH])),
    "mid auth": (True, _greet_then_partial_auth),
    "mid request, RST": (False, _partial_request_then_reset),
}


@pytest.mark.parametrize("case", MID_HANDSHAKE_CASES)
def test_client_closing_mid_handshake_logs_nothing_above_debug(
    make_proxy: MakeProxy, wait_handled: Callable[[ProxyHandle], None], caplog: pytest.LogCaptureFixture, case: str
) -> None:
    auth_required, client_steps = MID_HANDSHAKE_CASES[case]
    proxy = make_proxy(auth_required=auth_required)
    caplog.set_level(logging.DEBUG, logger="simple_socks5")

    with proxy.connect() as sock:
        client_steps(sock)
    wait_handled(proxy)

    problems = [r for r in caplog.records if r.levelno > logging.DEBUG or r.exc_info]
    assert problems == []


def _closed_port() -> int:
    with socket.socket() as placeholder:
        placeholder.bind(("127.0.0.1", 0))
        port: int = placeholder.getsockname()[1]
    return port


def _request(cmd: int, atyp: int, addr: sc.Address, port: int = 80) -> Callable[[socket.socket], int]:
    def steps(sock: socket.socket) -> int:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sc.send_request(sock, cmd, atyp, addr, port)
        return sc.read_reply(sock).rep

    return steps


def _raw_request(header: bytes) -> Callable[[socket.socket], int]:
    def steps(sock: socket.socket) -> int:
        assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
        sock.sendall(header)
        return sc.read_reply(sock).rep

    return steps


def _login(username: str, password: str, *, ver: int = sc.AUTH_VERSION) -> Callable[[socket.socket], int]:
    def steps(sock: socket.socket) -> int:
        assert sc.greet(sock, [sc.METHOD_USERPASS]) == sc.METHOD_USERPASS
        return sc.authenticate(sock, username, password, ver=ver)

    return steps


def _socks4_greeting(sock: socket.socket) -> None:
    sock.sendall(b"\x04\x01")
    sc.assert_closed(sock)


def _connect_to_closed_port(sock: socket.socket) -> int:
    return _request(sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", _closed_port())(sock)


class Scenario(NamedTuple):
    steps: Callable[[socket.socket], int | None]
    reply: int | None  # REP, or the RFC 1929 STATUS for a login
    level: int  # of the line that explains the failure
    message: str  # part of that line
    auth_required: bool = False
    allow_loopback: bool = True


SCENARIOS: dict[str, Scenario] = {
    "empty domain": Scenario(
        _request(sc.CMD_CONNECT, sc.ATYP_DOMAIN, b"\x00"), sc.REP_HOST_UNREACHABLE, logging.DEBUG, "b''"
    ),
    "bad ATYP": Scenario(
        _raw_request(b"\x05\x01\x00\x07"), sc.REP_ATYP_NOT_SUPPORTED, logging.DEBUG, "Invalid request: 7"
    ),
    "unknown CMD": Scenario(
        _request(0x09, sc.ATYP_IPV4, "127.0.0.1"), sc.REP_COMMAND_NOT_SUPPORTED, logging.DEBUG, "Unsupported command"
    ),
    "BIND": Scenario(
        _request(sc.CMD_BIND, sc.ATYP_IPV4, "127.0.0.1"), sc.REP_COMMAND_NOT_SUPPORTED, logging.DEBUG, "BIND"
    ),
    "SOCKS4 greeting": Scenario(_socks4_greeting, None, logging.DEBUG, "Version not supported: 4"),
    "bad sub-negotiation version": Scenario(
        _login(E2E_USERNAME, E2E_PASSWORD, ver=0x02),
        sc.AUTH_FAILURE,
        logging.DEBUG,
        "subnegotiation version",
        auth_required=True,
    ),
    "wrong credentials": Scenario(
        _login(E2E_USERNAME, "wrong"),
        sc.AUTH_FAILURE,
        logging.WARNING,
        "Authentication failed for client 127.0.0.1",
        auth_required=True,
    ),
    "refused destination": Scenario(
        _connect_to_closed_port, sc.REP_CONNECTION_REFUSED, logging.INFO, "CONNECTION_REFUSED for 127.0.0.1:"
    ),
    "denied destination": Scenario(
        _request(sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1"),
        sc.REP_NOT_ALLOWED,
        logging.WARNING,
        "Denied",
        allow_loopback=False,
    ),
}


def _assert_explained_at(records: list[logging.LogRecord], level: int, message: str) -> None:
    assert [r for r in records if r.levelno == level and message in r.getMessage()], [
        (r.levelname, r.getMessage()) for r in records
    ]
    # The CONNECTION line is logged once the request is read, before the command runs
    others = [r for r in records if not r.getMessage().startswith("CONNECTION |")]
    assert [r.getMessage() for r in others if r.levelno > level] == []
    assert not [r for r in records if r.exc_info]


@pytest.mark.parametrize("case", SCENARIOS)
def test_failure_logged_at_its_level(
    make_proxy: MakeProxy, wait_handled: Callable[[ProxyHandle], None], caplog: pytest.LogCaptureFixture, case: str
) -> None:
    scenario = SCENARIOS[case]
    proxy = make_proxy(auth_required=scenario.auth_required, allow_loopback=scenario.allow_loopback)
    caplog.set_level(logging.DEBUG, logger="simple_socks5")

    with proxy.connect() as sock:
        assert scenario.steps(sock) == scenario.reply
    wait_handled(proxy)

    _assert_explained_at(caplog.records, scenario.level, scenario.message)


def test_repeated_wrong_credentials_warn_once(
    auth_proxy: ProxyHandle, wait_handled: Callable[[ProxyHandle], None], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="simple_socks5")
    for _ in range(2):
        with auth_proxy.connect() as sock:
            assert _login(E2E_USERNAME, "wrong")(sock) == sc.AUTH_FAILURE
        wait_handled(auth_proxy)

    failures = [r for r in caplog.records if "Authentication failed" in r.getMessage()]
    assert [r.levelno for r in failures] == [logging.WARNING, logging.DEBUG]


def test_timed_out_destination_logged_at_info(
    monkeypatch: pytest.MonkeyPatch,
    proxy: ProxyHandle,
    wait_handled: Callable[[ProxyHandle], None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    if not blackhole_times_out():
        pytest.skip(f"{BLACKHOLE[0]} is not a blackhole on this network (connect fails or succeeds fast)")
    monkeypatch.setenv("SOCKS5_CONNECT_TIMEOUT", "0.3")
    caplog.set_level(logging.DEBUG, logger="simple_socks5")

    with proxy.connect() as sock:
        assert _request(sc.CMD_CONNECT, sc.ATYP_IPV4, BLACKHOLE[0], BLACKHOLE[1])(sock) == sc.REP_HOST_UNREACHABLE
    wait_handled(proxy)

    _assert_explained_at(caplog.records, logging.INFO, f"HOST_UNREACHABLE for {BLACKHOLE[0]}:{BLACKHOLE[1]}")


def test_unexpected_exception_logged_at_error_with_traceback(
    monkeypatch: pytest.MonkeyPatch,
    proxy: ProxyHandle,
    wait_handled: Callable[[ProxyHandle], None],
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken_relay(*_args: object) -> NoReturn:
        raise RuntimeError("bug")

    monkeypatch.setattr("simple_socks5.server.TCPRelay", broken_relay)
    caplog.set_level(logging.DEBUG, logger="simple_socks5")

    with proxy.connect() as sock:
        assert _request(sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1")(sock) == sc.REP_GENERAL_FAILURE
    wait_handled(proxy)

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1
    assert errors[0].exc_info is not None
    assert isinstance(errors[0].exc_info[1], RuntimeError)


def _stop(proc: subprocess.Popen[str]) -> tuple[str, str]:
    proc.send_signal(signal.SIGTERM)
    stdout, stderr = proc.communicate(timeout=10)
    assert proc.returncode == 0, stderr
    return stdout, stderr


def _probe_healthcheck(monkeypatch: pytest.MonkeyPatch, address: tuple[str, int], times: int) -> None:
    monkeypatch.setenv("SOCKS5_HEALTHCHECK_PORT", str(address[1]))
    assert [healthcheck.main() for _ in range(times)] == [0] * times


def test_info_process_healthchecks_silent_no_ansi_no_errors_log(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = {"SOCKS5_USERNAME": "process-user", "SOCKS5_PASSWORD": "process-password"}
    with run_app(tmp_path, logging_level="info", env=env) as (proc, address):
        _probe_healthcheck(monkeypatch, address, 10)
        stdout, stderr = _stop(proc)

    assert stdout == ""
    messages = [line.split(" - ", 2)[2] for line in stderr.splitlines()]
    assert messages == [
        f"Server started on {address[0]}:{address[1]}",
        "Server shutting down...",
        "Server terminated.",
    ]
    assert "\x1b[" not in stderr
    assert list(tmp_path.iterdir()) == []


def test_disabled_process_prints_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, echo_origin: Origin) -> None:
    with run_app(tmp_path, logging_level="disabled") as (proc, address):
        _probe_healthcheck(monkeypatch, address, 3)
        with sc.open_tunnel(address, "127.0.0.1", echo_origin.port) as tunnel:
            tunnel.sendall(b"ping")
            assert sc.recv_exact(tunnel, 4) == b"ping"
        stdout, stderr = _stop(proc)

    assert (stdout, stderr) == ("", "")
    assert list(tmp_path.iterdir()) == []


def test_log_file_omits_client_errors(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "proxy.log"
    log_path.parent.mkdir()
    with run_app(tmp_path, logging_level="debug", env={"SOCKS5_LOG_FILE": str(log_path)}) as (proc, address):
        with socket.create_connection(address, timeout=sc.TIMEOUT) as sock:
            assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
            sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", 80, ver=4)
            assert sc.read_reply(sock).rep == sc.REP_GENERAL_FAILURE
        _, stderr = _stop(proc)

    assert "[DEBUG] - Failed to parse SOCKS5 request: Version not supported: 4" in stderr
    assert "[ERROR]" not in stderr
    assert log_path.read_text() == ""
