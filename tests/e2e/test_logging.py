"""
What the proxy logs: one CONNECTION and one CLOSED line per connection, nothing above DEBUG for a client that
hangs up mid-handshake (the healthcheck included), and at process level no colour off a TTY and no errors.log.
"""
import logging
import re
import signal
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from simple_socks5 import healthcheck
from simple_socks5.server import TCPProxyServer
from tests.e2e import socks_client as sc
from tests.e2e.app_process import run_app

DOWNLOAD_SIZE = 10 * 1024 * 1024
REQUEST = b"GET /bytes/%d HTTP/1.0\r\n\r\n" % DOWNLOAD_SIZE


def _wait_for_closed_line(caplog, proxy) -> None:
    """CLOSED is logged on the handler thread after the client has already read EOF."""
    deadline = time.monotonic() + 5
    while not any(r.getMessage().startswith("CLOSED |") for r in caplog.records):
        assert time.monotonic() < deadline, "no CLOSED line within 5 s"
        time.sleep(0.01)
    assert proxy.server.wait_for_connections(5)


def _download(proxy, http_origin) -> bytes:
    with sc.open_tunnel(proxy.address, "127.0.0.1", http_origin.port) as tunnel:
        tunnel.sendall(REQUEST)
        return sc.recv_until_eof(tunnel)


def test_10mb_download_logs_one_connection_and_one_closed_line(proxy, http_origin, caplog):
    caplog.set_level(logging.INFO, logger="simple_socks5")

    response = _download(proxy, http_origin)
    _wait_for_closed_line(caplog, proxy)

    messages = [r.getMessage() for r in caplog.records if r.name.startswith("simple_socks5")]
    assert [m.split(" |")[0] for m in messages] == ["CONNECTION", "CLOSED"]
    up, down = map(int, re.search(r"up=(\d+) B down=(\d+) B", messages[1]).groups())
    assert up == len(REQUEST)
    assert down == len(response) > DOWNLOAD_SIZE


@pytest.mark.parametrize("level", [logging.DEBUG, logging.INFO])
def test_no_per_chunk_lines_at_any_level(proxy, http_origin, caplog, level):
    caplog.set_level(level, logger="simple_socks5")

    _download(proxy, http_origin)
    _wait_for_closed_line(caplog, proxy)

    records = [r for r in caplog.records if r.name.startswith("simple_socks5")]
    assert not [r for r in records if "RELAY" in r.getMessage()]
    # A 10 MiB download is 160+ relay buffers; a handful of lines means none of them was logged
    assert len(records) < 10


@pytest.fixture
def handled(monkeypatch):
    """wait(): blocks until the proxy has finished with one connection and logged everything for it."""
    finished = threading.Semaphore(0)
    original_finish = TCPProxyServer.finish

    def finish(self):
        try:
            original_finish(self)
        finally:
            finished.release()

    monkeypatch.setattr(TCPProxyServer, "finish", finish)

    def wait(proxy) -> None:
        assert finished.acquire(timeout=5), "the proxy never finished the connection"
        # handle_error() and untracking run after finish()
        assert proxy.server.wait_for_connections(5)

    return SimpleNamespace(wait=wait)


def _reset_on_close(sock: socket.socket) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


MID_HANDSHAKE_CASES = {
    "after connect": (False, lambda sock: None),
    "partial greeting": (False, lambda sock: sock.sendall(b"\x05")),
    "after method reply": (False, lambda sock: sc.greet(sock, [sc.METHOD_NO_AUTH])),
    "after method reply, RST": (False, lambda sock: (sc.greet(sock, [sc.METHOD_NO_AUTH]), _reset_on_close(sock))),
    "no acceptable method, auth required": (True, lambda sock: sc.greet(sock, [sc.METHOD_NO_AUTH])),
    "mid auth": (True, lambda sock: (sc.greet(sock, [sc.METHOD_USERPASS]), sock.sendall(b"\x01\x05us"))),
    "mid request, RST": (
        False,
        lambda sock: (
            sc.greet(sock, [sc.METHOD_NO_AUTH]),
            sock.sendall(b"\x05\x01\x00\x01\x7f"),
            _reset_on_close(sock),
        ),
    ),
}


@pytest.mark.parametrize("case", MID_HANDSHAKE_CASES)
def test_client_closing_mid_handshake_logs_nothing_above_debug(make_proxy, handled, caplog, case):
    auth_required, client_steps = MID_HANDSHAKE_CASES[case]
    proxy = make_proxy(auth_required=auth_required)
    caplog.set_level(logging.DEBUG, logger="simple_socks5")

    with proxy.connect() as sock:
        client_steps(sock)
    handled.wait(proxy)

    problems = [r for r in caplog.records if r.levelno > logging.DEBUG or r.exc_info]
    assert problems == []


def _stop(proc) -> tuple[str, str]:
    proc.send_signal(signal.SIGTERM)
    stdout, stderr = proc.communicate(timeout=10)
    assert proc.returncode == 0, stderr
    return stdout, stderr


def _probe_healthcheck(monkeypatch, address, times: int) -> None:
    monkeypatch.setenv("SOCKS5_HEALTHCHECK_PORT", str(address[1]))
    assert [healthcheck.main() for _ in range(times)] == [0] * times


def test_info_process_healthchecks_silent_no_ansi_no_errors_log(tmp_path, monkeypatch):
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


def test_disabled_process_prints_nothing(tmp_path, monkeypatch, echo_origin):
    with run_app(tmp_path, logging_level="disabled") as (proc, address):
        _probe_healthcheck(monkeypatch, address, 3)
        with sc.open_tunnel(address, "127.0.0.1", echo_origin.port) as tunnel:
            tunnel.sendall(b"ping")
            assert sc.recv_exact(tunnel, 4) == b"ping"
        stdout, stderr = _stop(proc)

    assert (stdout, stderr) == ("", "")
    assert list(tmp_path.iterdir()) == []


def test_log_file_receives_errors(tmp_path):
    log_path = tmp_path / "logs" / "proxy.log"
    log_path.parent.mkdir()
    with run_app(tmp_path, env={"SOCKS5_LOG_FILE": str(log_path)}) as (proc, address):
        with socket.create_connection(address, timeout=sc.TIMEOUT) as sock:
            assert sc.greet(sock, [sc.METHOD_NO_AUTH]) == sc.METHOD_NO_AUTH
            sc.send_request(sock, sc.CMD_CONNECT, sc.ATYP_IPV4, "127.0.0.1", 80, ver=4)
            assert sc.read_reply(sock).rep == sc.REP_GENERAL_FAILURE
        _, stderr = _stop(proc)

    assert "[ERROR] - Failed to parse SOCKS5 request: Version not supported: 4" in stderr
    contents = log_path.read_text()
    assert "[simple_socks5.server] - [ERROR] - [Failed to parse SOCKS5 request: Version not supported: 4]" in contents
    assert "Server started" not in contents
